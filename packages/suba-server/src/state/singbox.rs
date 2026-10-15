//! The sing-box module as the server uses it: the operator's settings and
//! configurations, the configuration assembled from them, and the process
//! running it.
//!
//! Three documents, three owners. `config/sing-box.<ext>` is the module's
//! settings (which version runs, which configuration, which collections
//! contribute outbounds); `config/sing-box/<name>.json` is one of the
//! configurations the operator wrote, each edited whole or a section or an
//! entry at a time, of which the settings name the one in use; and
//! `data/sing-box/config/config.json` is what a start assembled from it, which
//! is ours to overwrite.
//!
//! File and process operations run on the blocking pool. Release fetching is
//! asynchronous; one in-memory cache shared by the releases route and install
//! preflight keeps concurrent requests from hitting the upstream separately.
//! The process itself outlives any single request.
//!
//! **The order a start keeps.** The document is read, assembled, checked
//! against the schema of the version that will run them, written out, and only
//! then is a process started. A configuration that does not hold up is refused
//! with the field it is about, and a core that is already serving is never
//! touched by one — which is what makes "restart" safe to offer.

use std::collections::HashMap;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use suba_singbox::assemble::{self, Assembled, Tag};
use suba_singbox::core::{self, Asset, Dirs, Metadata, Release, Version};
use suba_singbox::install::{self, Generate};
use suba_singbox::run::{self, Runner, Status};
use suba_singbox::schema::{Schema, Skipped, Verdict};
use tokio::sync::Mutex as AsyncMutex;

use crate::{error::Error, fs, identity::Identity};

/// The directory the operator's configurations live in, under the config
/// directory.
const DOCUMENT_DIR: &str = "sing-box";

/// The configuration a module that has not chosen one runs.
pub(crate) const DEFAULT_CONFIG: &str = "default";

/// The longest a configuration name may be.
const CONFIG_NAME_MAX: usize = 64;

/// The file a configuration is kept in.
fn document_file(name: &str) -> String {
    format!("{name}.json")
}

/// Refuse a configuration name that could not be told apart in a URL, a file
/// name or a log line.
pub(crate) fn config_name(name: &str) -> Result<(), Error> {
    let usable = !name.is_empty()
        && name.len() <= CONFIG_NAME_MAX
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !name.starts_with('.');

    match usable {
        true => Ok(()),
        false => Err(Error::ConfigName {
            reason:
                "a name is 1 to 64 letters, digits, '.', '_' or '-', and does not start with '.'",
        }),
    }
}

/// What the operator chose for the module.
///
/// Kept out of the server's `config` document because it is changed through
/// the API at any time and only exists in a build that runs a core, and out of
/// the sing-box configuration because the core refuses a field it does not know.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct Settings {
    /// The version that runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    /// The configuration that runs; the default one when none is chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    /// Whether the core runs with the privileges this instance has.
    #[serde(default, skip_serializing_if = "is_operator")]
    pub privilege: Privilege,
    /// The collections whose nodes become outbounds, in this order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<String>,
}

/// How a started core runs, which is not something that can be inferred from a
/// configuration: a `tun` inbound needs a privilege, and whether this instance
/// has one to give is the operator's to say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Privilege {
    /// Dropped to the user whose files these are: what a configuration without
    /// a `tun`, `tproxy` or `redirect` inbound needs.
    #[default]
    Operator,
    /// Started as this instance is, which is root when it was started as root.
    Root,
}

fn is_operator(privilege: &Privilege) -> bool {
    *privilege == Privilege::Operator
}

/// The operator's configuration, and the tag it is addressed by.
pub(crate) struct Document {
    pub value: Value,
    /// The sha256 of the bytes on disk: what `If-Match` has to name.
    pub etag: String,
}

/// The module's settings, beside the server's own in the config directory.
pub(crate) const SETTINGS_BASENAME: &str = "sing-box";

/// What a write left behind.
#[derive(Debug, Serialize)]
pub(crate) struct Saved {
    #[serde(skip)]
    pub etag: String,
    /// What the schema could not check.
    pub unchecked: Vec<Skipped>,
    /// References that do not resolve yet: saved anyway, refused at start.
    pub warnings: Vec<String>,
}

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
    /// The config directory, which the settings live in.
    config_dir: PathBuf,
    /// `<config>/sing-box`, which the operator's configuration lives in.
    document_dir: PathBuf,
    /// The module's own directories under the data directory.
    dirs: Dirs,
    /// The instance's HTTP client, which fetching a release goes through.
    http: reqwest::Client,
    /// Who this process is, for the one decision that depends on it: whether a
    /// started core inherits its privileges or is dropped to the operator.
    identity: Identity,
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
    /// Held across read, check and write, so an `If-Match` answers for the
    /// document it is compared with.
    writing: Mutex<()>,
    phase: Mutex<Option<RuntimePhase>>,
    failed_version: Mutex<Option<Version>>,
}

impl SingboxStore {
    pub(crate) fn new(
        config_dir: &Path,
        data_dir: &Path,
        http: reqwest::Client,
        identity: Identity,
    ) -> Self {
        Self {
            config_dir: config_dir.to_path_buf(),
            document_dir: config_dir.join(DOCUMENT_DIR),
            dirs: Dirs::new(data_dir),
            http,
            identity,
            releases: AsyncMutex::new(None),
            runner: Arc::new(Runner::new()),
            started: Mutex::new(None),
            schemas: Mutex::new(None),
            installs: Mutex::new(HashMap::new()),
            selection: Mutex::new(()),
            writing: Mutex::new(()),
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
        let mut settings = self.settings()?;
        if settings.version.is_none() {
            settings.version = Some(version.clone());
            self.write_settings(&settings)?;
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

    /// The configurations this instance has, by name.
    ///
    /// A file that is not `<name>.json` is not a configuration, and a name that
    /// begins with `.` is one of our own half-written temp files rather than
    /// something the operator made.
    pub(crate) fn configs(&self) -> Result<Vec<String>, Error> {
        Ok(fs::list(&self.document_dir)?
            .into_iter()
            .filter(|file| !file.starts_with('.'))
            .filter_map(|file| file.strip_suffix(".json").map(str::to_string))
            .collect())
    }

    /// The configuration the module runs: the one the settings name, or the
    /// default one.
    pub(crate) fn config(&self) -> Result<String, Error> {
        Ok(self
            .settings()?
            .config
            .unwrap_or_else(|| DEFAULT_CONFIG.to_string()))
    }

    /// One configuration, as it is on disk; an empty one when none has been
    /// written.
    pub(crate) fn config_document(&self, name: &str) -> Result<Document, Error> {
        config_name(name)?;

        let text = fs::read_to_string(&self.document_dir, &document_file(name))?;
        let value = match &text {
            Some(text) => serde_json::from_str(text).map_err(|error| {
                Error::Document(format!(
                    "{}/{name}: not JSON (line {}, column {})",
                    DOCUMENT_DIR,
                    error.line(),
                    error.column()
                ))
            })?,
            None => Value::Object(Map::new()),
        };

        Ok(Document {
            value,
            etag: core::sha256_hex(text.unwrap_or_default().as_bytes()),
        })
    }

    /// Make a configuration exist, from a copy of another or empty.
    ///
    /// A name that is taken is refused rather than replaced: the caller meant to
    /// make a new one, and overwriting a document somebody wrote by hand is not
    /// a thing to do behind their back.
    pub(crate) fn create_config(&self, name: &str, copy: Option<&str>) -> Result<(), Error> {
        config_name(name)?;
        if self.configs()?.iter().any(|held| held == name) {
            return Err(Error::ConfigExists {
                name: name.to_string(),
            });
        }

        let value = match copy {
            Some(source) => {
                if !self.configs()?.iter().any(|held| held == source) {
                    return Err(Error::NoConfig {
                        name: source.to_string(),
                    });
                }
                self.config_document(source)?.value
            }
            None => Value::Object(Map::new()),
        };

        let body = serde_json::to_vec_pretty(&value)?;
        fs::ensure_dir(&self.document_dir)?;

        Ok(fs::write_atomic(
            &self.document_dir,
            &document_file(name),
            body,
        )?)
    }

    /// Forget a configuration. The one in use is refused: it is what the
    /// running core was started from, and switching is a step of its own.
    pub(crate) fn remove_config(&self, name: &str) -> Result<(), Error> {
        config_name(name)?;
        if self.config()? == name {
            return Err(Error::ConfigInUse {
                name: name.to_string(),
            });
        }
        if !self.configs()?.iter().any(|held| held == name) {
            return Err(Error::NoConfig {
                name: name.to_string(),
            });
        }

        Ok(fs::remove(&self.document_dir, &document_file(name))?)
    }

    /// One section of a configuration.
    pub(crate) fn section(&self, name: &str, section: &str) -> Result<(Value, String), Error> {
        let Document { value, etag } = self.config_document(name)?;

        match value.get(section) {
            Some(found) => Ok((found.clone(), etag)),
            None => Err(Error::NoSection {
                section: section.to_string(),
            }),
        }
    }

    /// One entry of an array section, by its tag.
    pub(crate) fn entry(
        &self,
        name: &str,
        section: &str,
        tag: &str,
    ) -> Result<(Value, String), Error> {
        let Document { value, etag } = self.config_document(name)?;

        value
            .get(section)
            .and_then(Value::as_array)
            .and_then(|entries| entries.iter().find(|entry| tag_of(entry) == Some(tag)))
            .map(|found| (found.clone(), etag))
            .ok_or_else(|| Error::NoEntry {
                section: section.to_string(),
                tag: tag.to_string(),
            })
    }

    /// Replace the whole configuration.
    pub(crate) fn write_document(
        &self,
        name: &str,
        value: Value,
        if_match: Option<&str>,
        generated: &[Value],
    ) -> Result<Saved, Error> {
        self.edit(name, if_match, generated, |sections| {
            let Value::Object(replacement) = value else {
                return Err(Error::Document("a configuration is an object".to_string()));
            };
            *sections = replacement;

            Ok(())
        })
    }

    /// Replace one section.
    pub(crate) fn write_section(
        &self,
        name: &str,
        section: &str,
        value: Value,
        if_match: Option<&str>,
        generated: &[Value],
    ) -> Result<Saved, Error> {
        self.edit(name, if_match, generated, |sections| {
            sections.insert(section.to_string(), value);

            Ok(())
        })
    }

    /// Remove one section.
    pub(crate) fn remove_section(
        &self,
        name: &str,
        section: &str,
        if_match: Option<&str>,
        generated: &[Value],
    ) -> Result<Saved, Error> {
        self.edit(name, if_match, generated, |sections| {
            sections
                .remove(section)
                .map(drop)
                .ok_or_else(|| Error::NoSection {
                    section: section.to_string(),
                })
        })
    }

    /// Put one entry of an array section, replacing the one with its tag.
    ///
    /// The tag is the entry's address, so an entry that spells a different one
    /// is refused rather than moved: renaming is a removal and a write.
    pub(crate) fn write_entry(
        &self,
        name: &str,
        section: &str,
        tag: &str,
        value: Value,
        if_match: Option<&str>,
        generated: &[Value],
    ) -> Result<Saved, Error> {
        let Value::Object(mut entry) = value else {
            return Err(Error::Document(format!(
                "{section}.{tag}: an entry is an object"
            )));
        };
        match entry.get("tag") {
            None => {
                entry.insert("tag".to_string(), Value::String(tag.to_string()));
            }
            Some(written) if written.as_str() == Some(tag) => {}
            Some(_) => {
                return Err(Error::Document(format!(
                    "{section}.{tag}: the entry's tag is the one in its path"
                )))
            }
        }
        let entry = Value::Object(entry);

        self.edit(name, if_match, generated, |sections| {
            let entries = sections
                .entry(section.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            let Value::Array(entries) = entries else {
                return Err(Error::Document(format!(
                    "{section}: the section is an array of entries"
                )));
            };

            match entries.iter().position(|held| tag_of(held) == Some(tag)) {
                Some(index) => entries[index] = entry,
                None => entries.push(entry),
            }

            Ok(())
        })
    }

    /// Remove one entry of an array section.
    pub(crate) fn remove_entry(
        &self,
        name: &str,
        section: &str,
        tag: &str,
        if_match: Option<&str>,
        generated: &[Value],
    ) -> Result<Saved, Error> {
        self.edit(name, if_match, generated, |sections| {
            let index = sections
                .get(section)
                .and_then(Value::as_array)
                .and_then(|entries| entries.iter().position(|held| tag_of(held) == Some(tag)));

            match (index, sections.get_mut(section)) {
                (Some(index), Some(Value::Array(entries))) => {
                    entries.remove(index);

                    Ok(())
                }
                _ => Err(Error::NoEntry {
                    section: section.to_string(),
                    tag: tag.to_string(),
                }),
            }
        })
    }

    /// Read, change, check the whole document, write it once.
    ///
    /// The whole document is checked, not the part that changed: a section is
    /// valid or not as part of the configuration it sits in. References are
    /// checked too, but only reported — the operator may write a selector before
    /// the outbounds it names — and a start refuses what is still dangling.
    fn edit(
        &self,
        name: &str,
        if_match: Option<&str>,
        generated: &[Value],
        change: impl FnOnce(&mut Map<String, Value>) -> Result<(), Error>,
    ) -> Result<Saved, Error> {
        let _writing = self.writing.lock().expect("the configuration");
        let Document { value, etag } = self.config_document(name)?;

        if if_match.is_some_and(|expected| expected != etag) {
            return Err(Error::Stale);
        }

        let Value::Object(mut sections) = value else {
            return Err(Error::Document("a configuration is an object".to_string()));
        };
        change(&mut sections)?;
        let value = Value::Object(sections);

        let (schema, _) = self.parsed_schema()?;
        let verdict = match schema.validate(&value) {
            Verdict::Failed(fault) => {
                return Err(Error::Document(format!("{}: {}", fault.path, fault.reason)))
            }
            verdict => verdict,
        };

        let body = serde_json::to_vec_pretty(&value)?;
        fs::ensure_dir(&self.document_dir)?;
        fs::write_atomic(&self.document_dir, &document_file(name), &body)?;

        let warnings = match assemble::assemble(&value, generated) {
            Ok(_) => Vec::new(),
            Err(unfit) => vec![unfit.to_string()],
        };

        Ok(Saved {
            etag: core::sha256_hex(&body),
            unchecked: verdict.skipped().to_vec(),
            warnings,
        })
    }

    /// The module's settings; the defaults when none have been written.
    pub(crate) fn settings(&self) -> Result<Settings, Error> {
        Ok(crate::config::read_config(
            &self.config_dir.to_string_lossy(),
            SETTINGS_BASENAME,
        )?)
    }

    /// Replace the module's settings.
    ///
    /// A version that is not installed is refused; a configuration that has no
    /// document yet and a collection that does not exist are not, because both
    /// may be written after the settings that name them — a module that has just
    /// been installed has an empty configuration, and the editor writes it on
    /// the first save.
    pub(crate) fn set_settings(&self, settings: &Settings) -> Result<(), Error> {
        let _selection = self.selection.lock().expect("current selection");

        if let Some(version) = &settings.version {
            if !self.dirs.metadata(version).exists() {
                return Err(Error::Singbox(suba_singbox::core::Error::NotInstalled {
                    version: version.clone(),
                }));
            }
        }
        if let Some(name) = &settings.config {
            config_name(name)?;
        }

        self.write_settings(settings)
    }

    pub(crate) fn write_settings(&self, settings: &Settings) -> Result<(), Error> {
        let path = crate::config::config_path(&self.config_dir, SETTINGS_BASENAME);
        let body = crate::config::codec::encode(settings, &path)?;
        fs::ensure_dir(&self.config_dir)?;

        Ok(fs::write_atomic(
            &self.config_dir,
            &crate::config::config_name(SETTINGS_BASENAME),
            body,
        )?)
    }

    /// The version in use, when there is one.
    pub(crate) fn current(&self) -> Result<Option<Version>, Error> {
        Ok(self.settings()?.version)
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

        Ok(install::uninstall(
            &self.dirs,
            version,
            self.current()?.as_ref(),
        )?)
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
    /// Read from the document and the generated outbounds, without requiring it
    /// to hold up: the operator is still writing it, and the tags that exist so
    /// far are exactly what the next field needs.
    pub(crate) fn references(&self, generated: &[Value]) -> Result<Vec<Tag>, Error> {
        let document = assemble::document(&self.current_document()?.value, generated)
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

    /// The configuration the core would run: the operator's, and whatever the
    /// collections contributed.
    pub(crate) fn assemble(&self, generated: &[Value]) -> Result<Assembled, Error> {
        assemble::assemble(&self.current_document()?.value, generated)
            .map_err(|unfit| Error::Document(unfit.to_string()))
    }

    /// The configuration in use.
    fn current_document(&self) -> Result<Document, Error> {
        self.config_document(&self.config()?)
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
        let settings = self.settings()?;
        // Asked before the version is: how a core is run is a property of this
        // instance, and an operator who set that has to be told about it rather
        // than about something the module has not got to yet. Nothing is
        // written either way, so a refused start leaves the document alone.
        let drop_to = self.run_as(settings.privilege)?;
        let version = settings.version.ok_or(Error::NoVersion)?;

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

        let mut command = run::command(&binary, &config, &work);
        match drop_to {
            Some((uid, gid)) => tracing::info!("starting {version} as {uid}:{gid}"),
            // Said out loud because it is the one thing an operator cannot see
            // from the page: a core that never became root cannot create an
            // interface, and its own log is the only place that shows up.
            None => tracing::info!("starting {version} with this instance's privileges"),
        }
        if let Some((uid, gid)) = drop_to {
            // SAFETY: between `fork` and `exec` this closure makes three
            // syscalls and nothing else — no allocation, no lock, nothing a
            // forked child of a threaded process may not do.
            unsafe {
                command.pre_exec(move || drop_identity(uid, gid));
            }
        }

        let pid = self.runner.spawn(command)?;
        *self.started.lock().expect("the started version") = Some(version);
        Ok(pid)
    }

    /// Who a started core runs as, or a refusal when it cannot be who the
    /// module asked for.
    ///
    /// Nothing here reads the configuration: which inbound needs a privilege is
    /// the operator's business, and a `tun` inbound in a core that was not given
    /// one fails with the core's own words in the log. What is checked is the
    /// intent — an instance that was asked for a privilege it does not have says
    /// so instead of quietly running the core as somebody else.
    fn run_as(&self, privilege: Privilege) -> Result<Option<(u32, u32)>, Error> {
        match privilege {
            // Nothing to hand down when there is nothing to hand down from:
            // this process is already the operator.
            Privilege::Operator if !self.identity.is_root() => Ok(None),
            // Dropping to root is not dropping: an instance whose files are
            // root's has nothing to give, and says so rather than reporting a
            // start that was never unprivileged.
            Privilege::Operator => match self.identity.operator {
                Some((uid, gid)) if uid != 0 => Ok(Some((uid, gid))),
                _ => Err(Error::NoDropTarget),
            },
            Privilege::Root if !self.identity.is_root() => Err(Error::NoPrivilege),
            Privilege::Root => Ok(None),
        }
    }

    /// What a start refuses on, without starting anything.
    ///
    /// A caller that is about to replace a running core asks this first: a
    /// refusal here must not leave the operator with nothing running.
    pub(crate) fn startable(&self) -> Result<(), Error> {
        self.run_as(self.settings()?.privilege).map(drop)
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

/// Become `uid`/`gid` with none of root's groups left, between `fork` and `exec`.
///
/// The groups go first: clearing them is what needs the privilege that dropping
/// the user takes away, and a core that kept root's supplementary groups —
/// `wheel` among them — would not be dropped at all. `rustix` wraps these three
/// on Linux only, and this has to work on macOS too, so they are made through
/// `libc`.
fn drop_identity(uid: u32, gid: u32) -> std::io::Result<()> {
    // SAFETY: three syscalls that take numbers, in a child process that has not
    // yet run anything of its own. Nothing here allocates, locks or reads.
    let failed = unsafe {
        libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(gid as libc::gid_t) != 0
            || libc::setuid(uid as libc::uid_t) != 0
    };

    match failed {
        true => Err(std::io::Error::last_os_error()),
        false => Ok(()),
    }
}

/// The tag an entry is addressed by.
fn tag_of(entry: &Value) -> Option<&str> {
    entry.get("tag").and_then(Value::as_str)
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
            identity(),
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
            identity(),
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
                "log": { "type": "object", "properties": { "level": { "type": "string" } } },
                "outbounds": { "type": "array", "items": { "type": "object" } }
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
             if [ \"$1\" = generate ]; then echo 'PrivateKey: {SENTINEL}'; exit 0; fi\n\
             cd \"$2\" || exit 1\n\
             if [ ! -f \"$4\" ]; then echo 'config not found' >&2; exit 1; fi\n\
             echo started\n\
             trap 'exit 0' TERM\n\
             while :; do sleep 1; done\n",
            schema,
            SENTINEL = SENTINEL,
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

    /// What the fake core prints as a generated credential.
    const SENTINEL: &str = "SENTINELPRIVATEKEY";

    /// A generated credential is the answer and nothing else: it is not in any
    /// line this server logs while producing it.
    #[test]
    fn a_generated_credential_is_not_logged() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Captured(Arc<Mutex<Vec<u8>>>);

        impl Write for Captured {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let (_scratch, store) = store();
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();

        let output = tracing::subscriber::with_default(subscriber, || {
            tracing::info!("capturing");
            store.generate(Generate::RealityKeyPair, None)
        })
        .expect("a generated key pair");

        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(output.contains(SENTINEL), "the answer carries it: {output}");
        assert!(logged.contains("capturing"), "the capture works: {logged}");
        assert!(!logged.contains(SENTINEL), "logged: {logged}");
    }

    /// The configuration the store's tests write to.
    const NAME: &str = DEFAULT_CONFIG;

    /// A process that is not root, so the module's default — run the core as
    /// the operator — is the case that needs no drop and no privilege.
    fn identity() -> Identity {
        Identity::not_root()
    }

    /// A store over a scratch directory, with one version installed and current.
    fn store() -> (Scratch, SingboxStore) {
        store_as(identity())
    }

    /// The same, run by an instance that is something other than this process.
    fn store_as(identity: Identity) -> (Scratch, SingboxStore) {
        let scratch = Scratch::new();
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &scratch.0.join("data"),
            reqwest::Client::new(),
            identity,
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
        store
            .set_settings(&Settings {
                version: Some(version),
                privilege: Default::default(),
                config: Some(NAME.to_string()),
                collections: Vec::new(),
            })
            .expect("a current version");

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
            identity(),
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
            identity(),
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

    /// The document is checked whole before it is written, and a refusal
    /// leaves the file as it was.
    #[test]
    fn a_section_is_checked_as_part_of_the_whole_document() {
        let (_scratch, store) = store();

        let refused = store.write_section(NAME, "bogus", serde_json::json!({}), None, &[]);
        assert!(
            matches!(
                &refused,
                Err(Error::Document(message))
                    if message == "bogus: is not one of the fields this place takes"
            ),
            "{refused:?}"
        );
        assert!(!store.document_dir.join(document_file(NAME)).exists());

        let saved = store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "info" }),
                None,
                &[],
            )
            .expect("a section");
        assert!(saved.unchecked.is_empty());
        assert_eq!(
            store.section(NAME, "log").expect("a section").0,
            serde_json::json!({ "level": "info" })
        );
        assert_eq!(saved.etag, store.config_document(NAME).unwrap().etag);
    }

    /// Configurations are named documents: one is made from a copy of another,
    /// and the one in use is not the one that gets forgotten.
    #[test]
    fn a_configuration_is_made_from_a_copy_of_another() {
        let (_scratch, store) = store();

        store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "info" }),
                None,
                &[],
            )
            .expect("a section");
        assert_eq!(store.configs().unwrap(), [NAME]);

        std::fs::write(store.document_dir.join("notes.txt"), "not a configuration").unwrap();
        store.create_config("copy", Some(NAME)).expect("a copy");
        assert_eq!(store.configs().unwrap(), ["copy", NAME]);
        assert_eq!(
            store.config_document("copy").unwrap().value,
            store.config_document(NAME).unwrap().value
        );

        // A name that is taken is refused rather than quietly replacing what
        // somebody wrote.
        assert!(matches!(
            store.create_config("copy", None),
            Err(Error::ConfigExists { .. })
        ));
        // A copy of nothing is refused rather than silently coming out empty.
        assert!(matches!(
            store.create_config("third", Some("gone")),
            Err(Error::NoConfig { .. })
        ));
        // The configuration in use is not the one that gets forgotten.
        assert!(matches!(
            store.remove_config(NAME),
            Err(Error::ConfigInUse { .. })
        ));
        assert!(matches!(
            store.remove_config("gone"),
            Err(Error::NoConfig { .. })
        ));

        store.remove_config("copy").expect("a removal");
        assert_eq!(store.configs().unwrap(), [NAME]);
    }

    /// What the module asks a core to be and what this instance can give it
    /// have to agree, in both directions.
    #[test]
    fn a_privilege_this_instance_does_not_have_is_refused() {
        let (_scratch, store) = store();

        assert_eq!(
            store.run_as(Privilege::Operator).expect("as the operator"),
            None,
            "a process that is not root is already the operator, so there is \
             nothing to drop"
        );
        assert!(matches!(
            store.run_as(Privilege::Root),
            Err(Error::NoPrivilege)
        ));
    }

    /// A root instance hands its privilege down or keeps it, and never quietly
    /// does the other one.
    #[test]
    fn a_root_instance_answers_both_ways() {
        let (_scratch, store) = store_as(Identity::root_as(501, 20));

        assert_eq!(
            store.run_as(Privilege::Operator).unwrap(),
            Some((501, 20)),
            "dropped to the user whose files these are"
        );
        assert_eq!(
            store.run_as(Privilege::Root).unwrap(),
            None,
            "kept, which is what a tun inbound needs"
        );
    }

    /// An instance whose files are root's has nothing to hand down, and says so
    /// rather than running the core as root behind a setting that said not to.
    #[test]
    fn root_owning_the_files_is_not_a_user_to_drop_to() {
        let (_scratch, store) = store_as(Identity::root_as(0, 0));

        assert!(matches!(
            store.run_as(Privilege::Operator),
            Err(Error::NoDropTarget)
        ));
    }

    /// A restart asks what a start refuses on *before* it stops anything: a
    /// refusal must not leave the operator with nothing running.
    #[test]
    fn a_start_that_cannot_be_what_it_was_asked_to_be_is_refused_first() {
        let (_scratch, store) = store();
        assert!(store.startable().is_ok());

        let mut settings = store.settings().unwrap();
        settings.privilege = Privilege::Root;
        store.set_settings(&settings).unwrap();

        assert!(matches!(store.startable(), Err(Error::NoPrivilege)));
    }

    /// A settings document written before this module had a privilege setting
    /// still means what it meant, and the choice survives being written down.
    #[test]
    fn the_privilege_the_module_was_told_is_the_one_it_reads_back() {
        let (scratch, store) = store();
        let written = std::fs::read_to_string(crate::config::config_path(
            scratch.0.join("config"),
            SETTINGS_BASENAME,
        ))
        .expect("the settings");

        assert_eq!(store.settings().unwrap().privilege, Privilege::Operator);
        assert!(
            !written.contains("privilege"),
            "the default is not written down: {written}"
        );

        let mut settings = store.settings().unwrap();
        settings.privilege = Privilege::Root;
        store.write_settings(&settings).unwrap();

        assert_eq!(store.settings().unwrap().privilege, Privilege::Root);
    }

    /// A name is a name, never a path.
    #[test]
    fn a_configuration_name_cannot_be_a_path() {
        for name in [
            "",
            "a/b",
            "..",
            ".hidden",
            "a\\b",
            &"x".repeat(CONFIG_NAME_MAX + 1),
        ] {
            assert!(
                matches!(config_name(name), Err(Error::ConfigName { .. })),
                "{name}"
            );
        }

        for name in ["default", "work-2", "a.b_c"] {
            assert!(config_name(name).is_ok(), "{name}");
        }
    }

    /// A write that names the document it read is refused once someone else
    /// has written since.
    #[test]
    fn a_write_against_a_stale_etag_is_refused() {
        let (_scratch, store) = store();
        let before = store.config_document(NAME).unwrap().etag;

        let saved = store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "info" }),
                Some(&before),
                &[],
            )
            .expect("a write against the current document");

        assert!(matches!(
            store.write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "warn" }),
                Some(&before),
                &[]
            ),
            Err(Error::Stale)
        ));
        assert_eq!(
            store.section(NAME, "log").unwrap().0,
            serde_json::json!({ "level": "info" }),
            "the refused write changed nothing"
        );
        assert!(store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "warn" }),
                Some(&saved.etag),
                &[]
            )
            .is_ok());
    }

    /// An entry is addressed by its tag: written in place, added when new,
    /// removed alone.
    #[test]
    fn an_entry_is_edited_by_its_tag() {
        let (_scratch, store) = store();
        let direct = |tag: &str| serde_json::json!({ "type": "direct", "tag": tag });

        store
            .write_section(
                NAME,
                "outbounds",
                serde_json::json!([direct("a"), direct("b")]),
                None,
                &[],
            )
            .unwrap();
        store
            .write_entry(
                NAME,
                "outbounds",
                "c",
                serde_json::json!({ "type": "direct" }),
                None,
                &[],
            )
            .unwrap();
        store
            .write_entry(NAME, "outbounds", "a", direct("a"), None, &[])
            .unwrap();

        let tags = |store: &SingboxStore| -> Vec<String> {
            store
                .section(NAME, "outbounds")
                .unwrap()
                .0
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["tag"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(tags(&store), ["a", "b", "c"]);
        assert_eq!(store.entry(NAME, "outbounds", "c").unwrap().0, direct("c"));

        assert!(matches!(
            store.write_entry(NAME, "outbounds", "a", direct("renamed"), None, &[]),
            Err(Error::Document(_))
        ));

        store
            .remove_entry(NAME, "outbounds", "b", None, &[])
            .unwrap();
        assert_eq!(tags(&store), ["a", "c"]);
        assert!(matches!(
            store.remove_entry(NAME, "outbounds", "b", None, &[]),
            Err(Error::NoEntry { .. })
        ));
    }

    /// A reference that does not resolve yet is saved and reported; the start
    /// is what refuses it.
    #[test]
    fn a_dangling_reference_is_a_warning_when_saved() {
        let (_scratch, store) = store();

        let saved = store
            .write_section(
                NAME,
                "outbounds",
                serde_json::json!([{ "type": "selector", "tag": "s", "outbounds": ["gone"] }]),
                None,
                &[],
            )
            .expect("saved anyway");

        assert_eq!(saved.warnings.len(), 1, "{:?}", saved.warnings);
        assert!(saved.warnings[0].contains("gone"), "{:?}", saved.warnings);
    }

    /// The settings are the operator's file in the config directory, and the
    /// version they name is the one in use.
    #[test]
    fn the_version_in_use_is_the_one_the_settings_name() {
        let (scratch, store) = store();

        assert_eq!(store.current().unwrap(), Some(Version::from_tag("1.14.2")));
        assert!(crate::config::config_path(scratch.0.join("config"), SETTINGS_BASENAME).is_file());
        assert!(!store.dirs.root.join("current.json").exists());

        assert!(matches!(
            store.set_settings(&Settings {
                version: Some(Version::from_tag("1.99.0")),
                privilege: Default::default(),
                config: Some(NAME.to_string()),
                collections: Vec::new(),
            }),
            Err(Error::Singbox(
                suba_singbox::core::Error::NotInstalled { .. }
            ))
        ));
        assert_eq!(store.current().unwrap(), Some(Version::from_tag("1.14.2")));
    }

    #[test]
    fn the_assembled_configuration_lands_where_the_core_is_pointed() {
        let (_scratch, store) = store();
        store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "warn" }),
                None,
                &[],
            )
            .expect("a section");

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
            identity(),
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
            identity(),
        );

        assert!(matches!(store.start(&[]), Err(Error::NoVersion)));
        assert!(!store.assembled());
    }

    #[test]
    fn a_broken_document_stops_a_start_and_leaves_the_product_alone() {
        let (_scratch, store) = store();
        store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "info" }),
                None,
                &[],
            )
            .expect("a section");
        store.assemble(&[]).expect("an assembly");
        let assembled = store.assemble(&[]).expect("an assembly");
        store.write_product(&assembled.config).expect("a product");
        let before = std::fs::read(store.dirs.config().join(CONFIG)).expect("the configuration");

        // A document the schema refuses, written by hand: the one way to get
        // one past `edit`, and what a start has to survive.
        std::fs::write(
            store.document_dir.join(document_file(NAME)),
            r#"{"log": {"level": 7}}"#,
        )
        .expect("a broken document");

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
    fn a_broken_document_leaves_the_running_core_alone() {
        let (_scratch, store) = store();
        store
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "info" }),
                None,
                &[],
            )
            .expect("a section");

        let pid = store.start(&[]).expect("a start");
        wait_for(&store, "started");

        // The one way to get a broken document past `edit`.
        std::fs::write(
            store.document_dir.join(document_file(NAME)),
            r#"{"log": {"level": 7}}"#,
        )
        .expect("a broken document");

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
            .write_section(
                NAME,
                "log",
                serde_json::json!({ "level": "info" }),
                None,
                &[],
            )
            .expect("a section");

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
        let store = SingboxStore::new(
            &scratch.0.join("config"),
            &relative,
            reqwest::Client::new(),
            identity(),
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
        .expect("an installed core");
        store
            .set_settings(&Settings {
                version: Some(version),
                privilege: Default::default(),
                config: Some(NAME.to_string()),
                collections: Vec::new(),
            })
            .expect("a current version");

        store.start(&[]).expect("a start");
        wait_for(&store, "started");
        assert!(store.status().running, "the config was found after -D");
        store.stop(Duration::from_secs(2)).expect("a stop");
        std::fs::remove_dir_all(relative).expect("remove the relative scratch directory");
    }
}
