//! The sing-box module as the server uses it: the fragments an operator wrote,
//! the configuration assembled from them, and the process running it.
//!
//! File and process operations run on the blocking pool. Release fetching is
//! asynchronous; one in-memory cache shared by the releases route and install
//! preflight keeps concurrent requests from hitting the upstream separately.
//! The process itself outlives any single request.
//!
//! **The order a start keeps.** The fragments are read, assembled, checked
//! against the schema of the version that will run them, written out, and only
//! then is a process started. A configuration that does not hold up is refused
//! with the field it is about, and a core that is already serving is never
//! touched by one — which is what makes "restart" safe to offer.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use suba_singbox::assemble::{self, Assembled, Tag};
use suba_singbox::core::{self, Asset, Dirs, Metadata, Release, Version};
use suba_singbox::install::{self, Generate};
use suba_singbox::run::{self, Runner, Status};
use suba_singbox::schema::{Schema, Verdict};
use tokio::sync::Mutex as AsyncMutex;

use crate::{error::Error, fs};

/// The directory the operator's fragments live in, under the config directory.
const FRAGMENTS: &str = "sing-box";

/// What a fragment's file name ends in.
const EXTENSION: &str = "json";

/// The assembled configuration, named as the core is pointed at it.
pub(crate) const CONFIG: &str = "config.json";

/// Where sing-box's releases are listed.
///
/// The dialect crate knows the shape of what this API answers; where that API
/// lives is this instance's choice, which is why the address is here and not
/// there.
const RELEASES: &str = "https://api.github.com/repos/SagerNet/sing-box/releases?per_page=30";

/// A short-lived listing shared by the releases route and installation preflight.
const RELEASES_TTL: Duration = Duration::from_secs(5 * 60);

/// An expired listing remains useful while the release API refuses requests.
const RELEASES_RETRY: Duration = Duration::from_secs(60);

struct ReleasesCache {
    fetched_at: Instant,
    retry_after: Instant,
    values: Vec<Release>,
}

/// A schema, as it was read: which version's, which bytes, and their hash.
pub(crate) struct SchemaBytes {
    pub version: Version,
    pub sha256: String,
    pub body: Vec<u8>,
}

/// An installation in flight, or its last failure until retried.
#[derive(Clone, Copy)]
pub(crate) enum InstallationTask {
    Downloading { downloaded: u64, total: Option<u64> },
    Failed { error: &'static str },
}

#[derive(Clone, Copy)]
pub(crate) enum RuntimePhase {
    Starting,
    Stopping,
    Failed { error: &'static str },
}

fn installation_failure(error: &Error) -> &'static str {
    match error {
        Error::Singbox(core::Error::Refused { .. }) => "the release server refused the download",
        Error::Singbox(core::Error::Network { .. }) => "the download could not be completed",
        Error::Singbox(core::Error::Hash { .. }) => "the downloaded asset failed its checksum",
        Error::Singbox(core::Error::Archive { .. })
        | Error::Singbox(core::Error::Member { .. })
        | Error::Singbox(core::Error::MemberMissing { .. })
        | Error::Singbox(core::Error::MemberTooLarge { .. }) => {
            "the release archive could not be installed"
        }
        Error::Singbox(core::Error::Run { .. }) => {
            "the installed binary could not generate its schema"
        }
        _ => "the installation could not be completed",
    }
}

fn runtime_failure(error: &Error) -> &'static str {
    match error {
        Error::Document(_) => "the configuration did not pass validation",
        Error::Schema(_) => "the installed schema could not be read",
        Error::Singbox(core::Error::Run { .. }) => {
            "the core process could not be started or stopped"
        }
        Error::Io(_) => "a runtime file could not be read or written",
        _ => "the core could not be started or stopped",
    }
}

/// The sing-box module.
pub(crate) struct SingboxStore {
    /// `<config>/sing-box`: one file per section, which this server writes but
    /// never rewrites on its own.
    fragment_dir: PathBuf,
    /// The module's own directories under the data directory.
    dirs: Dirs,
    /// The instance's HTTP client, which fetching a release goes through.
    http: reqwest::Client,
    /// Held across a cache miss so concurrent requests make one upstream call.
    releases: AsyncMutex<Option<ReleasesCache>>,
    /// The process, which outlives any request that touched it.
    runner: Arc<Runner>,
    /// Which version was started, while that process is the one in the runner.
    started: Mutex<Option<Version>>,
    /// The last schema read, with the hash it was read at.
    ///
    /// A schema is addressed by its bytes (I3), so holding one costs nothing but
    /// memory and saves parsing 445 KB on every form save and every start.
    schemas: Mutex<Option<(String, Arc<Schema>)>>,
    installs: Mutex<HashMap<Version, InstallationTask>>,
    selection: Mutex<()>,
    phase: Mutex<Option<RuntimePhase>>,
    failed_version: Mutex<Option<Version>>,
}

impl SingboxStore {
    pub(crate) fn new(config_dir: &Path, data_dir: &Path, http: reqwest::Client) -> Self {
        Self {
            fragment_dir: config_dir.join(FRAGMENTS),
            dirs: Dirs::new(data_dir),
            http,
            releases: AsyncMutex::new(None),
            runner: Arc::new(Runner::new()),
            started: Mutex::new(None),
            schemas: Mutex::new(None),
            installs: Mutex::new(HashMap::new()),
            selection: Mutex::new(()),
            phase: Mutex::new(None),
            failed_version: Mutex::new(None),
        }
    }

    pub(crate) fn installation_task(&self, version: &Version) -> Option<InstallationTask> {
        self.installs
            .lock()
            .expect("install tasks")
            .get(version)
            .copied()
    }

    /// Reserve a version before spawning work; a second request sees this task.
    pub(crate) fn begin_install(&self, version: &Version) -> Result<bool, Error> {
        if version < &Version::from_tag(core::MIN_VERSION) {
            return Err(suba_singbox::core::Error::TooOld {
                version: version.clone(),
                floor: core::MIN_VERSION,
            }
            .into());
        }
        if self.installed_record(version)?.is_some() {
            self.select_if_empty(version)?;
            return Ok(false);
        }
        let mut installs = self.installs.lock().expect("install tasks");
        if matches!(
            installs.get(version),
            Some(InstallationTask::Downloading { .. })
        ) {
            return Ok(false);
        }
        installs.insert(
            version.clone(),
            InstallationTask::Downloading {
                downloaded: 0,
                total: None,
            },
        );
        Ok(true)
    }

    pub(crate) fn finish_install(&self, version: &Version, result: &Result<Metadata, Error>) {
        let mut installs = self.installs.lock().expect("install tasks");
        match result {
            Ok(_) => {
                installs.remove(version);
            }
            Err(error) => {
                installs.insert(
                    version.clone(),
                    InstallationTask::Failed {
                        error: installation_failure(error),
                    },
                );
            }
        }
    }

    /// Make the first installed version current, without replacing a choice.
    fn select_if_empty(&self, version: &Version) -> Result<(), Error> {
        let _selection = self.selection.lock().expect("current selection");
        if self.current()?.is_none() {
            self.write_current(version)?;
        }
        Ok(())
    }

    pub(crate) fn runtime_phase(&self) -> Option<RuntimePhase> {
        *self.phase.lock().expect("runtime phase")
    }

    pub(crate) fn last_started_version(&self) -> Option<Version> {
        self.started.lock().expect("the started version").clone()
    }

    pub(crate) fn failed_version(&self) -> Option<Version> {
        self.failed_version.lock().expect("failed version").clone()
    }

    /// The fragments the operator wrote, one per section.
    ///
    /// A name that is not a section is refused rather than politely skipped: a
    /// file put here to matter, which silently does not, is the failure mode
    /// this whole module is written against. A name starting with a dot is this
    /// server's own half-written file and is not the operator's business.
    pub(crate) fn fragments(&self) -> Result<BTreeMap<String, Vec<u8>>, Error> {
        let listing = match std::fs::read_dir(&self.fragment_dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new())
            }
            Err(error) => {
                return Err(Error::Io(error));
            }
        };

        let mut fragments = BTreeMap::new();
        for entry in listing {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }

            let Some(section) = name.strip_suffix(&format!(".{EXTENSION}")) else {
                return Err(Error::Fragment {
                    name,
                    reason: "a fragment is one section, named <section>.json",
                });
            };

            let Some(text) = fs::read_to_string(&self.fragment_dir, &name)? else {
                continue;
            };

            fragments.insert(section.to_string(), text.into_bytes());
        }

        Ok(fragments)
    }

    /// One section's fragment, as it is on disk.
    pub(crate) fn fragment(&self, section: &str) -> Result<Option<Value>, Error> {
        let name = fragment_name(section)?;

        match fs::read_to_string(&self.fragment_dir, &name)? {
            Some(text) => Ok(Some(serde_json::from_str(&text)?)),
            None => Ok(None),
        }
    }

    /// Write one section's fragment, once the schema has taken it.
    ///
    /// The document is checked as if it were the whole configuration with this
    /// one section in it, which is what it would be: an unknown section, a wrong
    /// type or a field this version does not have is refused here, with the
    /// field path, instead of becoming a core that will not start.
    pub(crate) fn write_fragment(&self, section: &str, value: &Value) -> Result<Verdict, Error> {
        let (schema, _) = self.parsed_schema()?;

        // As if it were the whole configuration with this one section in it,
        // which is what it would be.
        let mut document = serde_json::Map::new();
        document.insert(section.to_string(), value.clone());
        let document = Value::Object(document);

        match schema.validate(&document) {
            Verdict::Failed(fault) => {
                Err(Error::Document(format!("{}: {}", fault.path, fault.reason)))
            }
            verdict => {
                let name = fragment_name(section)?;
                fs::ensure_dir(&self.fragment_dir)?;
                let body = serde_json::to_vec_pretty(value)?;
                fs::write_atomic(&self.fragment_dir, &name, body)?;

                Ok(verdict)
            }
        }
    }

    /// The version in use, when there is one.
    pub(crate) fn current(&self) -> Result<Option<Version>, Error> {
        Ok(suba_singbox::install::current(&self.dirs)?)
    }

    /// The versions this machine has.
    pub(crate) fn versions(&self) -> Result<Vec<Metadata>, Error> {
        Ok(install::installed(&self.dirs)?)
    }

    /// A version's record, when it is installed.
    pub(crate) fn installed_record(&self, version: &Version) -> Result<Option<Metadata>, Error> {
        Ok(self
            .versions()?
            .into_iter()
            .find(|metadata| &metadata.version == version))
    }

    /// Which version the running process is, when one is running.
    pub(crate) fn running_version(&self) -> Option<Version> {
        let started = self.started.lock().expect("the started version");

        match self.runner.status().running {
            true => started.clone(),
            false => None,
        }
    }

    /// What the release server lists.
    pub(crate) async fn releases(&self) -> Result<Vec<Release>, Error> {
        self.releases_from(RELEASES).await
    }

    async fn releases_from(&self, url: &str) -> Result<Vec<Release>, Error> {
        let mut cached = self.releases.lock().await;
        if let Some(cache) = cached.as_ref() {
            if cache.fetched_at.elapsed() < RELEASES_TTL || Instant::now() < cache.retry_after {
                return Ok(cache.values.clone());
            }
        }

        match install::releases(&self.http, url).await {
            Ok(releases) => {
                *cached = Some(ReleasesCache {
                    fetched_at: Instant::now(),
                    retry_after: Instant::now(),
                    values: releases.clone(),
                });
                Ok(releases)
            }
            Err(error) => match cached.as_mut() {
                Some(cache) => {
                    cache.retry_after = Instant::now() + RELEASES_RETRY;
                    Ok(cache.values.clone())
                }
                None => Err(error.into()),
            },
        }
    }

    /// Resolve an installable asset before claiming an installation task.
    pub(crate) async fn install_asset(&self, version: &Version) -> Result<(Asset, String), Error> {
        if version < &Version::from_tag(core::MIN_VERSION) {
            return Err(suba_singbox::core::Error::TooOld {
                version: version.clone(),
                floor: core::MIN_VERSION,
            }
            .into());
        }
        let platform = core::platform()?;
        let releases = self.releases().await?;
        Ok(Self::asset_in(&releases, version, platform)?)
    }

    /// Find an asset before creating a task; an absent release is not queued.
    fn asset_in(
        releases: &[Release],
        version: &Version,
        platform: &str,
    ) -> Result<(Asset, String), suba_singbox::core::Error> {
        let release = releases
            .iter()
            .find(|release| &release.version == version)
            .ok_or_else(|| suba_singbox::core::Error::Unpublished {
                version: version.clone(),
            })?;
        Ok((release.asset_for(platform)?.clone(), platform.to_string()))
    }

    /// Download and install an asset already confirmed to exist by the caller.
    pub(crate) async fn install(
        &self,
        version: &Version,
        asset: Asset,
        platform: String,
    ) -> Result<Metadata, Error> {
        let expected_size = (asset.size > 0).then_some(asset.size);
        let archive =
            install::download_with_progress(&self.http, &asset.url, |downloaded, total| {
                let mut installs = self.installs.lock().expect("install tasks");
                if let Some(task @ InstallationTask::Downloading { .. }) = installs.get_mut(version)
                {
                    *task = InstallationTask::Downloading {
                        downloaded,
                        total: total.or(expected_size),
                    };
                }
            })
            .await?;

        let dirs = self.dirs.clone();
        let version = version.clone();
        let name = asset.name.clone();
        let expected = asset.sha256.clone();
        let now = chrono::Utc::now().timestamp();

        let metadata = tokio::task::spawn_blocking(move || {
            install::install(
                &dirs,
                &version,
                &platform,
                &name,
                &archive,
                expected.as_deref(),
                now,
            )
        })
        .await??;

        // Selecting the first installed version and an explicit switch must
        // serialize, otherwise a late download could overwrite the user's pick.
        self.select_if_empty(&metadata.version)?;

        Ok(metadata)
    }

    /// Remove an installed version.
    pub(crate) fn uninstall(&self, version: &Version) -> Result<(), Error> {
        if self.running_version().as_ref() == Some(version) {
            return Err(Error::Singbox(suba_singbox::core::Error::RunningVersion {
                version: version.clone(),
            }));
        }

        Ok(install::uninstall(&self.dirs, version)?)
    }

    /// Make an installed version the one in use.
    pub(crate) fn set_current(&self, version: &Version) -> Result<(), Error> {
        let _selection = self.selection.lock().expect("current selection");
        self.write_current(version)
    }

    fn write_current(&self, version: &Version) -> Result<(), Error> {
        Ok(install::set_current(&self.dirs, version)?)
    }

    /// Ask the version in use for something it generates.
    pub(crate) fn generate(&self, kind: Generate, argument: Option<&str>) -> Result<String, Error> {
        let version = self.current()?.ok_or(Error::NoVersion)?;

        Ok(install::generate(&self.dirs, &version, kind, argument)?)
    }

    /// The schema of the version in use, as it is on disk.
    pub(crate) fn schema_bytes(&self) -> Result<SchemaBytes, Error> {
        let version = self.current()?.ok_or(Error::NoVersion)?;
        let body = std::fs::read(self.dirs.schema(&version))?;
        let sha256 = core::sha256_hex(&body);

        let record = self.record(&version)?;
        if record.schema_sha256 != sha256 {
            return Err(Error::Singbox(suba_singbox::core::Error::Hash {
                expected: record.schema_sha256,
                found: sha256,
            }));
        }

        Ok(SchemaBytes {
            version,
            sha256,
            body,
        })
    }

    /// The tags a form can offer as references.
    ///
    /// Read from the document the fragments make, without requiring it to hold
    /// up: the operator is still writing it, and the tags that exist so far are
    /// exactly what the next field needs.
    pub(crate) fn references(&self, generated: &[Value]) -> Result<Vec<Tag>, Error> {
        let document = assemble::document(&self.fragments()?, generated)
            .map_err(|unfit| Error::Document(unfit.to_string()))?;

        assemble::tags(&document).map_err(|unfit| Error::Document(unfit.to_string()))
    }

    /// The schema of the version in use, parsed, with the bytes it came from.
    ///
    /// Held by the hash it was read at: a schema is addressed by its bytes (I3),
    /// so every caller after the first pays nothing to have it.
    pub(crate) fn parsed_schema(&self) -> Result<(Arc<Schema>, Vec<u8>), Error> {
        let file = self.schema_bytes()?;

        let mut held = self.schemas.lock().expect("the schema");
        if let Some((hash, schema)) = held.as_ref() {
            if hash == &file.sha256 {
                return Ok((Arc::clone(schema), file.body));
            }
        }

        let schema = Arc::new(
            Schema::read(&file.body).map_err(|unreadable| Error::Schema(unreadable.to_string()))?,
        );
        *held = Some((file.sha256, Arc::clone(&schema)));

        Ok((schema, file.body))
    }

    /// The configuration the core would run: the fragments, and whatever a
    /// collection contributed.
    pub(crate) fn assemble(&self, generated: &[Value]) -> Result<Assembled, Error> {
        assemble::assemble(&self.fragments()?, generated)
            .map_err(|unfit| Error::Document(unfit.to_string()))
    }

    /// Write the assembled configuration where the core is pointed at it.
    pub(crate) fn write_product(&self, config: &Value) -> Result<(), Error> {
        fs::ensure_dir(self.dirs.config())?;
        let body = serde_json::to_vec_pretty(config)?;

        Ok(fs::write_atomic(&self.dirs.config(), CONFIG, body)?)
    }

    /// Whether an assembled configuration is there.
    pub(crate) fn assembled(&self) -> bool {
        self.dirs.config().join(CONFIG).is_file()
    }

    /// Whether the version in use has its binary where it should be.
    pub(crate) fn binary_in_place(&self) -> Result<bool, Error> {
        Ok(self
            .current()?
            .is_some_and(|version| self.dirs.binary(&version).is_file()))
    }

    /// Assemble the configuration, check it, write it, and run it.
    ///
    /// `generated` is the outbound half a collection contributes; a build
    /// without one passes nothing. Nothing is started until the document has
    /// been assembled, checked and written.
    pub(crate) fn start(&self, generated: &[Value]) -> Result<u32, Error> {
        let attempted = self.current().ok().flatten();
        *self.phase.lock().expect("runtime phase") = Some(RuntimePhase::Starting);
        let result = self.start_checked(generated);
        *self.phase.lock().expect("runtime phase") = match &result {
            Ok(_) => None,
            Err(error) => Some(RuntimePhase::Failed {
                error: runtime_failure(error),
            }),
        };
        *self.failed_version.lock().expect("failed version") = result.as_ref().err().and(attempted);
        result
    }

    fn start_checked(&self, generated: &[Value]) -> Result<u32, Error> {
        let version = self.current()?.ok_or(Error::NoVersion)?;

        let assembled = self.assemble(generated)?;
        let (schema, _) = self.parsed_schema()?;
        if let Verdict::Failed(fault) = schema.validate(&assembled.config) {
            return Err(Error::Document(format!("{}: {}", fault.path, fault.reason)));
        }

        // The core's own working directory, which its cache lives in.
        fs::ensure_dir(self.dirs.work())?;
        self.write_product(&assembled.config)?;

        let binary = std::fs::canonicalize(self.dirs.binary(&version))?;
        let config = std::fs::canonicalize(self.dirs.config().join(CONFIG))?;
        let work = std::fs::canonicalize(self.dirs.work())?;

        let pid = self.runner.spawn(run::command(&binary, &config, &work))?;
        *self.started.lock().expect("the started version") = Some(version);
        Ok(pid)
    }

    /// Ask the core to stop.
    pub(crate) fn stop(&self, patience: std::time::Duration) -> Result<(), Error> {
        *self.phase.lock().expect("runtime phase") = Some(RuntimePhase::Stopping);
        let result = self.runner.stop(patience).map_err(Error::from);
        *self.phase.lock().expect("runtime phase") = match &result {
            Ok(()) => None,
            Err(error) => Some(RuntimePhase::Failed {
                error: runtime_failure(error),
            }),
        };
        result
    }

    /// What the process is doing.
    pub(crate) fn status(&self) -> Status {
        self.runner.status()
    }

    /// The last `tail` lines the core printed.
    pub(crate) fn log(&self, tail: usize) -> Vec<String> {
        self.runner.log(tail)
    }

    /// A version's record, as it was written when it was installed.
    fn record(&self, version: &Version) -> Result<Metadata, Error> {
        self.installed_record(version)?.ok_or_else(|| {
            Error::Singbox(suba_singbox::core::Error::NotInstalled {
                version: version.clone(),
            })
        })
    }
}

/// The file name a section's fragment has, refusing a name that is not one.
fn fragment_name(section: &str) -> Result<String, Error> {
    let usable = !section.is_empty()
        && !section.contains(['/', '\\', '\0'])
        && section != "."
        && section != "..";

    if !usable {
        return Err(Error::Fragment {
            name: section.to_string(),
            reason: "a section is named by a plain word",
        });
    }

    Ok(format!("{section}.{EXTENSION}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn release_server() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/releases", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0; 1024];
                if stream.read(&mut request).await.unwrap() == 0 {
                    continue;
                }
                let call = observed.fetch_add(1, Ordering::SeqCst);
                let body = r#"[{"tag_name":"v1.14.2","assets":[]}]"#;
                // Each connection is answered once and dropped, so the client
                // must not pool it: a reused dead connection is a failed fetch.
                let response = if call == 2 {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_string()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (url, calls)
    }

    #[tokio::test]
    async fn releases_share_a_fetch_until_expired_and_keep_the_last_good_listing() {
        use std::sync::atomic::Ordering;

        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );
        let (url, calls) = release_server().await;

        let (first, second) = tokio::join!(store.releases_from(&url), store.releases_from(&url));
        assert_eq!(first.unwrap()[0].version.as_str(), "1.14.2");
        assert_eq!(second.unwrap()[0].version.as_str(), "1.14.2");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one fetch for concurrent callers"
        );
        assert_eq!(store.releases_from(&url).await.unwrap().len(), 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fresh hit does not call upstream"
        );

        store.releases.lock().await.as_mut().unwrap().fetched_at = Instant::now() - RELEASES_TTL;
        assert_eq!(store.releases_from(&url).await.unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "expiry fetches again");

        store.releases.lock().await.as_mut().unwrap().fetched_at = Instant::now() - RELEASES_TTL;
        assert_eq!(store.releases_from(&url).await.unwrap().len(), 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a failed refresh is retried"
        );
        assert_eq!(store.releases_from(&url).await.unwrap().len(), 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "a failed refresh backs off"
        );
        store.releases.lock().await.as_mut().unwrap().retry_after = Instant::now();
        assert_eq!(store.releases_from(&url).await.unwrap().len(), 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            4,
            "refresh resumes after backoff"
        );
    }

    #[tokio::test]
    async fn failed_first_release_fetch_is_not_cached() {
        use std::sync::atomic::Ordering;

        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );
        let (url, calls) = release_server().await;
        let failed = format!("{url}/missing");

        // A malformed path is still answered by this local server, so explicitly
        // test a fresh upstream refusal by letting its third response be the
        // first response for another store.
        store.releases_from(&url).await.unwrap();
        store.releases.lock().await.take();
        store.releases_from(&url).await.unwrap();
        assert!(store.releases.lock().await.take().is_some());
        assert!(store.releases_from(&failed).await.is_err());
        assert!(store.releases.lock().await.is_none());
        assert_eq!(store.releases_from(&url).await.unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    /// A fake release archive: a binary that writes a schema when asked and runs
    /// until it is asked to stop, and a minimal schema that accepts one section.
    fn archive() -> Vec<u8> {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "log": { "type": "object", "properties": { "level": { "type": "string" } } }
            },
            "additionalProperties": false,
            "$defs": {
                "Inbound": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "socks" } } }
                ] },
                "Outbound": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "direct" } } }
                ] }
            }
        });

        let binary = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = schema ]; then\n\
             \tprintf '%s' '{}' > \"$3\"\n\
             \texit 0\n\
             fi\n\
             cd \"$2\" || exit 1\n\
             if [ ! -f \"$4\" ]; then echo 'config not found' >&2; exit 1; fi\n\
             echo started\n\
             trap 'exit 0' TERM\n\
             while :; do sleep 1; done\n",
            schema
        );

        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::fast(),
        ));
        for (name, bytes) in [
            ("release/sing-box", binary.as_bytes()),
            ("release/LICENSE", b"a licence"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, std::io::Cursor::new(bytes))
                .expect("a member");
        }

        builder
            .into_inner()
            .expect("the encoder")
            .finish()
            .expect("gzip")
    }

    /// A store over a scratch directory, with one version installed and current.
    fn store() -> (Scratch, SingboxStore) {
        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );

        let version = Version::from_tag("v1.14.2");
        suba_singbox::install::install(
            &store.dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(),
            None,
            1_700_000_000,
        )
        .expect("an install");
        suba_singbox::install::set_current(&store.dirs, &version).expect("a current version");

        (scratch, store)
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static COUNTER: AtomicUsize = AtomicUsize::new(0);

            let path = std::env::temp_dir().join(format!(
                "suba-server-singbox-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).expect("a temporary directory");

            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn first_install_becomes_current_without_replacing_a_later_choice() {
        let (_scratch, store) = store();
        let original = Version::from_tag("1.14.2");
        let next = Version::from_tag("1.14.3");
        suba_singbox::install::install(
            &store.dirs,
            &next,
            "linux-amd64",
            "sing-box-1.14.3-linux-amd64.tar.gz",
            &archive(),
            None,
            1_700_000_000,
        )
        .expect("a second install");

        store.select_if_empty(&next).unwrap();
        assert_eq!(store.current().unwrap(), Some(original));
    }

    #[test]
    fn first_install_selects_itself_when_there_is_no_current_version() {
        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );
        let version = Version::from_tag("1.14.2");
        suba_singbox::install::install(
            &store.dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(),
            None,
            1_700_000_000,
        )
        .expect("an install");

        store.select_if_empty(&version).unwrap();
        assert_eq!(store.current().unwrap(), Some(version));
    }

    #[test]
    fn retrying_an_installed_version_repairs_a_missing_current_selection() {
        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );
        let version = Version::from_tag("1.14.2");
        suba_singbox::install::install(
            &store.dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(),
            None,
            1_700_000_000,
        )
        .expect("a completed install without a current selection");

        assert!(
            !store.begin_install(&version).unwrap(),
            "nothing is downloaded again"
        );
        assert_eq!(store.current().unwrap(), Some(version));
    }

    #[test]
    fn a_fragment_that_is_not_a_section_is_refused() {
        let (_scratch, store) = store();
        std::fs::create_dir_all(&store.fragment_dir).expect("the fragments directory");
        std::fs::write(store.fragment_dir.join("notes.txt"), "hello").expect("a file");

        assert!(matches!(
            store.fragments(),
            Err(Error::Fragment { name, reason })
                if name == "notes.txt" && reason == "a fragment is one section, named <section>.json"
        ));
    }

    #[test]
    fn a_fragment_is_checked_before_it_is_written() {
        let (_scratch, store) = store();

        let refused = store.write_fragment("bogus", &serde_json::json!({}));

        assert!(
            matches!(
                &refused,
                Err(Error::Document(message))
                    if message == "bogus: is not one of the fields this place takes"
            ),
            "{refused:?}"
        );
        assert!(!store.fragment_dir.join("bogus.json").exists());

        let verdict = store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");
        assert_eq!(verdict, Verdict::Ok);

        assert_eq!(
            store.fragment("log").expect("a fragment"),
            Some(serde_json::json!({ "level": "info" }))
        );
    }

    #[test]
    fn the_assembled_configuration_lands_where_the_core_is_pointed() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "warn" }))
            .expect("a fragment");

        let generated = vec![serde_json::json!({ "type": "direct", "tag": "node 1" })];
        let assembled = store.assemble(&generated).expect("an assembly");
        store.write_product(&assembled.config).expect("a product");

        assert!(store.assembled());

        let written: Value = serde_json::from_slice(
            &std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration"),
        )
        .expect("a readable configuration");

        assert_eq!(written["log"], serde_json::json!({ "level": "warn" }));
        assert_eq!(written["outbounds"][0]["tag"], "node 1");
    }

    /// Below the floor there is nothing to install, and that is said before
    /// anything is fetched or downloaded.
    #[tokio::test]
    async fn a_version_below_the_floor_is_refused_by_name() {
        let (_scratch, store) = store();

        assert!(matches!(
            store.install_asset(&Version::from_tag("1.13.0")).await,
            Err(Error::Singbox(suba_singbox::core::Error::TooOld { .. }))
        ));
    }

    #[test]
    fn an_unpublished_version_is_not_an_installation_task() {
        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );
        let version = Version::from_tag("9.99.9");
        let release = Release::from_json(&serde_json::json!({
            "tag_name": "v1.14.2",
            "assets": [],
        }))
        .unwrap();

        assert!(matches!(
            SingboxStore::asset_in(&[release], &version, "darwin-arm64"),
            Err(suba_singbox::core::Error::Unpublished { .. })
        ));
        assert!(store.installation_task(&version).is_none());
    }

    #[test]
    fn starting_without_a_version_is_refused() {
        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
        );

        assert!(matches!(store.start(&[]), Err(Error::NoVersion)));
        assert!(!store.assembled());
    }

    #[test]
    fn a_broken_fragment_stops_a_start_and_leaves_the_product_alone() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");
        store.assemble(&[]).expect("an assembly");
        let assembled = store.assemble(&[]).expect("an assembly");
        store.write_product(&assembled.config).expect("a product");
        let before = std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration");

        // A fragment the schema refuses, written by hand: the one way to get one
        // past `write_fragment`, and what a start has to survive.
        std::fs::write(store.fragment_dir.join("log.json"), r#"{"level": 7}"#)
            .expect("a broken fragment");

        let refused = store.start(&[]);

        assert!(matches!(refused, Err(Error::Document(_))), "{refused:?}");
        assert_eq!(
            std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration"),
            before
        );
    }

    /// Wait until the core has said something.
    ///
    /// A stop can reach a process before it has printed its first line, which is
    /// a real thing a core can see — so a test that means to look at what it said
    /// has to wait for it to say it.
    fn wait_for(store: &SingboxStore, line: &str) {
        for _ in 0..200 {
            if store.log(run::LOG_LINES).iter().any(|said| said == line) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        panic!(
            "the core never said {line:?}: {:?}",
            store.log(run::LOG_LINES)
        );
    }

    /// Acceptance 7: a configuration that does not hold up leaves a running core
    /// running. A start that would reload a broken configuration is refused, and
    /// the process that is serving keeps serving.
    #[test]
    fn a_broken_fragment_leaves_the_running_core_alone() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");

        let pid = store.start(&[]).expect("a start");
        wait_for(&store, "started");

        // The one way to get a broken fragment past `write_fragment`.
        std::fs::write(store.fragment_dir.join("log.json"), r#"{"level": 7}"#)
            .expect("a broken fragment");

        let refused = store.start(&[]);

        assert!(matches!(&refused, Err(Error::Document(_))), "{refused:?}");

        let status = store.status();
        assert!(status.running, "the core that was serving is still serving");
        assert_eq!(status.pid, Some(pid));
        assert_eq!(status.exits.len(), 0);

        store.stop(Duration::from_secs(2)).expect("a stop");
    }

    #[test]
    fn the_core_runs_and_stops_one_at_a_time() {
        let (_scratch, store) = store();
        store
            .write_fragment("log", &serde_json::json!({ "level": "info" }))
            .expect("a fragment");

        let pid = store.start(&[]).expect("a start");
        assert!(pid > 0);
        assert!(store.status().running);
        wait_for(&store, "started");

        let refused = store.start(&[]);
        assert!(
            matches!(
                refused,
                Err(Error::Singbox(suba_singbox::core::Error::Running { .. }))
            ),
            "{refused:?}"
        );

        store.stop(Duration::from_secs(2)).expect("a stop");

        let status = store.status();
        assert!(!status.running);
        assert_eq!(status.exits.len(), 1);
        assert!(
            store
                .log(run::LOG_LINES)
                .iter()
                .any(|line| line == "started"),
            "what the core said: {:?}",
            store.log(run::LOG_LINES)
        );
    }

    #[test]
    fn a_relative_data_directory_still_points_the_core_at_its_config() {
        let scratch = Scratch::new();
        let relative =
            PathBuf::from("target").join(format!("suba-relative-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&relative).expect("a relative scratch directory");
        let store = SingboxStore::new(&scratch.0.join("config"), &relative, reqwest::Client::new());
        let version = Version::from_tag("1.14.2");
        suba_singbox::install::install(
            &store.dirs,
            &version,
            "linux-amd64",
            "sing-box-1.14.2-linux-amd64.tar.gz",
            &archive(),
            None,
            1_700_000_000,
        )
        .expect("an installed core");
        store.set_current(&version).expect("a current version");

        store.start(&[]).expect("a start");
        wait_for(&store, "started");
        assert!(store.status().running, "the config was found after -D");
        store.stop(Duration::from_secs(2)).expect("a stop");
        std::fs::remove_dir_all(relative).expect("remove the relative scratch directory");
    }
}
