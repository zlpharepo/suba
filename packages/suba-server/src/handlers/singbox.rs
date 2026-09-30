//! The sing-box module, as HTTP resources.
//!
//! Everything here is thin: the work is the store's, and this layer decides what
//! a request means and which status it answers with. The one thing it must not
//! do is hold a running core hostage to a request — a stop waits for the process
//! to close what it opened, and that wait belongs on the blocking pool.

use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use suba_singbox::assemble::{self, Tag};
use suba_singbox::core::{Release, Version};
use suba_singbox::install::{Generate, Needs};
use suba_singbox::run::{self, Exit, Status};

use crate::{
    dto::{Authenticated, ResponseResult},
    error::Error,
    state::singbox::{InstallationTask, RuntimePhase, SingboxStore},
    AppState,
};

/// How long a stop waits for the core to close what it opened before it is
/// ended.
const PATIENCE: Duration = Duration::from_secs(10);

/// The core: which version is in use, and what state it is in.
#[derive(Debug, Serialize)]
pub struct Core {
    /// The version in use, when one is installed and current.
    pub version: Option<String>,
    /// Whether its binary is where it should be.
    pub installed: bool,
    /// Whether an assembled configuration is on disk.
    pub assembled: bool,
    /// Whether it is running now.
    pub running: bool,
}

/// What the process is doing, and the end of what it said.
#[derive(Debug, Serialize)]
pub struct Running {
    pub running: bool,
    pub pid: Option<u32>,
    pub started_at: Option<i64>,
    /// The last ways it ended, oldest first.
    pub exits: Vec<Exit>,
    /// The end of the core's own output, oldest first.
    pub log: Vec<String>,
}

/// How much of the log a caller asked for.
#[derive(Debug, Deserialize)]
pub struct Tail {
    pub tail: Option<usize>,
}

/// What to do with the process.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Action {
    pub action: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Command {
    Start,
    Stop,
    Restart,
}

/// The version to make the current one.
#[derive(Debug, Deserialize)]
pub struct Switch {
    pub version: String,
}

/// What changed, and what a caller has to do about it.
#[derive(Debug, Serialize)]
pub struct Switched {
    #[serde(flatten)]
    pub core: Core,
    /// Set when a core is running: it keeps running what it started with.
    pub note: Option<String>,
}

/// Make an installed version the one in use.
///
/// A switch does not touch a running process — the version it started with is
/// the version it is — so the answer says so instead of pretending the change
/// has taken effect.
pub async fn switch(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(switch): Json<Switch>,
) -> ResponseResult<Json<Switched>> {
    let store = state.singbox();
    let version = Version::from_tag(&switch.version);

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Switched, Error> {
            store.set_current(&version)?;

            let running = store.status().running;

            Ok(Switched {
                core: Core {
                    version: store.current()?.map(|version| version.as_str().to_string()),
                    installed: store.binary_in_place()?,
                    assembled: store.assembled(),
                    running,
                },
                note: running.then(|| {
                    "the core that is running keeps running the version it started with; restart to change it"
                        .to_string()
                }),
            })
        })
        .await??,
    ))
}

/// The core, as this instance knows it.
pub async fn index(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<Core>> {
    let store = state.singbox();

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Core, Error> {
            Ok(Core {
                version: store.current()?.map(|version| version.as_str().to_string()),
                installed: store.binary_in_place()?,
                assembled: store.assembled(),
                running: store.status().running,
            })
        })
        .await??,
    ))
}

/// What the process is doing, and the end of what it said.
pub async fn status(
    State(state): State<AppState>,
    _auth: Authenticated,
    Query(query): Query<Tail>,
) -> ResponseResult<Json<Running>> {
    let store = state.singbox();
    let tail = query.tail.unwrap_or(run::LOG_LINES).min(run::LOG_LINES);

    Ok(Json(
        tokio::task::spawn_blocking(move || {
            let status = store.status();

            Running {
                running: status.running,
                pid: status.pid,
                started_at: status.started_at,
                exits: status.exits,
                log: store.log(tail),
            }
        })
        .await?,
    ))
}

/// Start, stop or restart the core.
///
/// A start assembles, checks and writes the configuration before anything is
/// started, so a configuration that does not hold up is answered with its field
/// and leaves a running core running.
pub async fn act(
    State(state): State<AppState>,
    _auth: Authenticated,
    Query(query): Query<Tail>,
    Json(action): Json<Action>,
) -> ResponseResult<Json<Running>> {
    let store = state.singbox();
    let tail = query.tail.unwrap_or(run::LOG_LINES).min(run::LOG_LINES);

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Running, Error> {
            match action.action {
                Command::Start => {
                    store.start(&[])?;
                }
                Command::Stop => store.stop(PATIENCE)?,
                Command::Restart => {
                    store.stop(PATIENCE)?;
                    store.start(&[])?;
                }
            }

            let status: Status = store.status();

            Ok(Running {
                running: status.running,
                pid: status.pid,
                started_at: status.started_at,
                exits: status.exits,
                log: store.log(tail),
            })
        })
        .await??,
    ))
}

/// One section of the configuration the operator wrote.
pub async fn config(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(section): Path<String>,
) -> ResponseResult<Json<Value>> {
    let store = state.singbox();
    let name = section.clone();

    let fragment = tokio::task::spawn_blocking(move || store.fragment(&section)).await??;

    fragment
        .map(Json)
        .ok_or(Error::NoFragment { section: name })
}

/// One section as it was stored, and the checks that could not run on it.
#[derive(Debug, Serialize)]
pub struct Written {
    pub value: Value,
    pub unchecked: Vec<suba_singbox::schema::Skipped>,
}

/// Write one section of the configuration, once the schema has taken it.
pub async fn write_config(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(section): Path<String>,
    Json(value): Json<Value>,
) -> ResponseResult<Json<Written>> {
    let store = state.singbox();

    let (verdict, value) = tokio::task::spawn_blocking(move || {
        store
            .write_fragment(&section, &value)
            .map(|verdict| (verdict, value))
    })
    .await??;

    Ok(Json(Written {
        value,
        unchecked: verdict.skipped().to_vec(),
    }))
}

/// A version, as this instance knows it.
#[derive(Debug, Serialize)]
pub struct VersionView {
    pub version: String,
    pub tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_sha256: Option<String>,
    pub installation: InstallationView,
    pub runtime: RuntimeView,
    pub current: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum InstallationView {
    NotInstalled,
    Downloading { progress: ProgressView },
    Installed { installed_at: i64 },
    Failed { error: &'static str },
}

#[derive(Debug, Serialize)]
pub struct ProgressView {
    pub downloaded: u64,
    pub total: Option<u64>,
    pub percentage: Option<u8>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum RuntimeView {
    Stopped,
    Starting,
    Running { pid: u32 },
    Stopping,
    Failed { error: String },
}

fn version_view(store: &SingboxStore, version: &Version) -> Result<VersionView, Error> {
    let metadata = store.installed_record(version)?;
    let current = store.current()?.as_ref() == Some(version);
    let running = store.running_version().as_ref() == Some(version);
    let status = store.status();
    let runtime = if running {
        match store.runtime_phase() {
            Some(RuntimePhase::Stopping) => RuntimeView::Stopping,
            _ => RuntimeView::Running {
                pid: status.pid.expect("a running process has a pid"),
            },
        }
    } else if current {
        match store.runtime_phase() {
            Some(RuntimePhase::Starting) => RuntimeView::Starting,
            Some(RuntimePhase::Stopping)
                if store.last_started_version().as_ref() == Some(version) =>
            {
                RuntimeView::Stopping
            }
            Some(RuntimePhase::Stopping) => RuntimeView::Stopped,
            Some(RuntimePhase::Failed { error })
                if store.failed_version().as_ref() == Some(version) =>
            {
                RuntimeView::Failed {
                    error: error.to_string(),
                }
            }
            Some(RuntimePhase::Failed { .. }) => RuntimeView::Stopped,
            None if store.last_started_version().as_ref() == Some(version)
                && status.exits.last().is_some_and(|exit| {
                    exit.at >= status.started_at.unwrap_or(i64::MAX)
                        && (exit.code != Some(0) || exit.signal.is_some())
                }) =>
            {
                let exit = status.exits.last().expect("an abnormal exit was recorded");
                RuntimeView::Failed {
                    error: match (exit.code, exit.signal) {
                        (Some(code), _) => format!("the core process exited with status {code}"),
                        (_, Some(signal)) => format!("the core process ended by signal {signal}"),
                        _ => "the core process exited unexpectedly".to_string(),
                    },
                }
            }
            None => RuntimeView::Stopped,
        }
    } else {
        RuntimeView::Stopped
    };

    let installation = if let Some(ref metadata) = metadata {
        InstallationView::Installed {
            installed_at: metadata.installed_at,
        }
    } else {
        match store.installation_task(version) {
            Some(InstallationTask::Downloading { downloaded, total }) => {
                InstallationView::Downloading {
                    progress: ProgressView {
                        downloaded,
                        total,
                        percentage: total
                            .filter(|total| *total > 0)
                            .map(|total| ((downloaded.saturating_mul(100) / total).min(100)) as u8),
                    },
                }
            }
            Some(InstallationTask::Failed { error }) => InstallationView::Failed { error },
            None => InstallationView::NotInstalled,
        }
    };

    Ok(VersionView {
        version: version.as_str().to_string(),
        tag: version.tag(),
        asset: metadata.as_ref().map(|record| record.asset.clone()),
        platform: metadata.as_ref().map(|record| record.platform.clone()),
        asset_sha256: metadata.as_ref().map(|record| record.asset_sha256.clone()),
        binary_sha256: metadata.as_ref().map(|record| record.binary_sha256.clone()),
        schema_sha256: metadata.as_ref().map(|record| record.schema_sha256.clone()),
        installation,
        runtime,
        current,
    })
}

#[cfg(test)]
mod version_view_tests {
    use super::*;
    use suba_singbox::core::{Dirs, Metadata};

    #[test]
    fn absent_and_downloading_versions_have_distinct_structured_views() {
        let root = std::env::temp_dir().join(format!("suba-version-view-{}", uuid::Uuid::now_v7()));
        let store = SingboxStore::new(
            &root.join("config"),
            &root.join("data"),
            reqwest::Client::new(),
        );
        let version = Version::from_tag("1.14.2");

        let absent = serde_json::to_value(version_view(&store, &version).unwrap()).unwrap();
        assert_eq!(absent["version"], "1.14.2");
        assert_eq!(absent["tag"], "v1.14.2");
        assert_eq!(absent["installation"]["status"], "not-installed");
        assert_eq!(absent["runtime"]["status"], "stopped");
        assert_eq!(absent["current"], false);
        assert!(absent.get("asset").is_none());

        assert!(store.begin_install(&version).unwrap());
        assert!(
            !store.begin_install(&version).unwrap(),
            "one task per version"
        );
        let downloading = serde_json::to_value(version_view(&store, &version).unwrap()).unwrap();
        assert_eq!(downloading["installation"]["status"], "downloading");
        assert_eq!(downloading["installation"]["progress"]["downloaded"], 0);

        store.finish_install(
            &version,
            &Err(Error::Singbox(suba_singbox::core::Error::Network {
                reason: "the download stopped part way",
            })),
        );
        assert_eq!(
            serde_json::to_value(version_view(&store, &version).unwrap()).unwrap()["installation"]
                ["status"],
            "failed"
        );
        assert_eq!(
            serde_json::to_value(version_view(&store, &version).unwrap()).unwrap()["installation"]
                ["error"],
            "the download could not be completed"
        );
        assert!(store.begin_install(&version).unwrap());
        assert_eq!(
            serde_json::to_value(version_view(&store, &version).unwrap()).unwrap()["installation"]
                ["status"],
            "downloading",
            "a retry clears the previous failure"
        );
    }

    #[test]
    fn runtime_and_progress_have_the_requested_shapes() {
        let progress = serde_json::to_value(InstallationView::Downloading {
            progress: ProgressView {
                downloaded: 5,
                total: Some(10),
                percentage: Some(50),
            },
        })
        .unwrap();
        let running = serde_json::to_value(RuntimeView::Running { pid: 12345 }).unwrap();

        assert_eq!(progress["status"], "downloading");
        assert_eq!(progress["progress"]["percentage"], 50);
        assert_eq!(
            running,
            serde_json::json!({"status": "running", "pid": 12345})
        );
        for (phase, name) in [
            (RuntimeView::Starting, "starting"),
            (RuntimeView::Stopping, "stopping"),
            (
                RuntimeView::Failed {
                    error: "the core process exited unexpectedly".to_string(),
                },
                "failed",
            ),
        ] {
            assert_eq!(serde_json::to_value(phase).unwrap()["status"], name);
        }
    }

    #[test]
    fn installed_version_has_metadata_and_a_stopped_runtime() {
        let root =
            std::env::temp_dir().join(format!("suba-version-installed-{}", uuid::Uuid::now_v7()));
        let store = SingboxStore::new(
            &root.join("config"),
            &root.join("data"),
            reqwest::Client::new(),
        );
        let dirs = Dirs::new(root.join("data"));
        let version = Version::from_tag("1.14.2");
        let metadata = Metadata {
            version: version.clone(),
            tag: version.tag(),
            asset: "sing-box-1.14.2-darwin-arm64.tar.gz".to_string(),
            platform: "darwin-arm64".to_string(),
            asset_sha256: "asset-hash".to_string(),
            binary_sha256: "binary-hash".to_string(),
            schema_sha256: "schema-hash".to_string(),
            installed_at: 1_700_000_000,
        };
        std::fs::create_dir_all(dirs.version(&version)).unwrap();
        std::fs::write(
            dirs.metadata(&version),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();

        let view = serde_json::to_value(version_view(&store, &version).unwrap()).unwrap();
        assert_eq!(
            view["installation"],
            serde_json::json!({"status": "installed", "installed_at": 1_700_000_000})
        );
        assert_eq!(view["runtime"], serde_json::json!({"status": "stopped"}));
        assert_eq!(view["asset"], metadata.asset);
        assert_eq!(view["schema_sha256"], metadata.schema_sha256);
        assert_eq!(view["current"], false);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_start_is_reported_for_the_attempted_version() {
        let root =
            std::env::temp_dir().join(format!("suba-version-failed-{}", uuid::Uuid::now_v7()));
        let store = SingboxStore::new(
            &root.join("config"),
            &root.join("data"),
            reqwest::Client::new(),
        );
        let version = Version::from_tag("1.14.2");
        let dirs = Dirs::new(root.join("data"));
        std::fs::create_dir_all(dirs.version(&version)).unwrap();
        std::fs::write(dirs.metadata(&version), "{}").unwrap();
        suba_singbox::install::set_current(&dirs, &version).unwrap();

        assert!(store.start(&[]).is_err());
        // A broken record is reported as an error rather than used as a view.
        // Keep the metadata valid so the runtime view can be inspected.
        let metadata = Metadata {
            version: version.clone(),
            tag: version.tag(),
            asset: "asset".into(),
            platform: "platform".into(),
            asset_sha256: "asset-hash".into(),
            binary_sha256: "binary-hash".into(),
            schema_sha256: "schema-hash".into(),
            installed_at: 1_700_000_000,
        };
        std::fs::write(
            dirs.metadata(&version),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();

        let runtime = serde_json::to_value(version_view(&store, &version).unwrap()).unwrap()
            ["runtime"]
            .clone();
        assert_eq!(runtime["status"], "failed");
        assert!(
            runtime["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty()),
            "a failure says why: {runtime}"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// The versions this machine has.
pub async fn versions(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<Vec<VersionView>>> {
    let store = state.singbox();

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Vec<VersionView>, Error> {
            store
                .versions()?
                .iter()
                .map(|record| version_view(&store, &record.version))
                .collect()
        })
        .await??,
    ))
}

/// One version, as this instance knows it.
pub async fn version(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(asked): Path<String>,
) -> ResponseResult<Json<VersionView>> {
    let store = state.singbox();
    let version = Version::from_tag(&asked);

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<VersionView, Error> {
            version_view(&store, &version)
        })
        .await??,
    ))
}

/// Install a version from the release server.
///
/// An accepted request reserves the task and answers before network work begins.
pub async fn install_version(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(asked): Path<String>,
) -> ResponseResult<(StatusCode, Json<VersionView>)> {
    let store = state.singbox();
    let version = Version::from_tag(&asked);
    let preparing = store.clone();
    let requested = version.clone();
    let existing = tokio::task::spawn_blocking(move || -> Result<_, Error> {
        let response = version_view(&preparing, &requested)?;
        Ok(matches!(
            response.installation,
            InstallationView::Installed { .. } | InstallationView::Downloading { .. }
        )
        .then_some(response))
    })
    .await??;
    if let Some(response) = existing {
        return Ok((StatusCode::OK, Json(response)));
    }

    // An unknown release is a failed request, never a successfully queued job.
    let (asset, platform) = store.install_asset(&version).await?;
    let preparing = store.clone();
    let requested = version.clone();
    let (created, response) = tokio::task::spawn_blocking(move || -> Result<_, Error> {
        let created = preparing.begin_install(&requested)?;
        let response = version_view(&preparing, &requested)?;
        Ok((created, response))
    })
    .await??;
    if !created {
        return Ok((StatusCode::OK, Json(response)));
    }
    tokio::spawn(async move {
        let result = store.install(&version, asset, platform).await;
        if let Err(ref error) = result {
            tracing::error!("sing-box installation failed: {error}");
        }
        store.finish_install(&version, &result);
    });

    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Remove an installed version.
pub async fn delete_version(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(asked): Path<String>,
) -> ResponseResult<StatusCode> {
    let store = state.singbox();
    let version = Version::from_tag(&asked);

    tokio::task::spawn_blocking(move || store.uninstall(&version)).await??;

    Ok(StatusCode::NO_CONTENT)
}

/// The versions this build can install, as a caller picks between them.
///
/// Pre-releases are in the list: running one is the operator's decision, and
/// what this build insists on is only that the version is one whose schema it
/// can read. Below [`MIN_VERSION`] there is nothing to offer, which is why the
/// list starts where it does rather than being filtered afterwards.
#[derive(Debug, Serialize)]
pub struct Releases {
    /// The newest version that is not a pre-release, when there is one.
    pub stable: Option<String>,
    /// The newest version of all, pre-releases included.
    pub latest: Option<String>,
    /// Every version this build will install, newest first.
    pub versions: Vec<ReleaseView>,
}

/// One version, as a caller picks it out of the list.
#[derive(Debug, Serialize)]
pub struct ReleaseView {
    /// The version, spelled the way the rest of this API spells versions — and
    /// the way it is addressed when it is installed.
    pub version: String,
    /// The tag it is published under, which is what a release URL needs.
    pub tag: String,
    /// Where the release page is, when the release server names one.
    pub page: Option<String>,
}

/// What a caller sees of a release list.
fn offered(installable: &[&Release]) -> Releases {
    let view = |release: &&Release| ReleaseView {
        version: release.version.as_str().to_string(),
        tag: release.version.tag(),
        page: release.html_url.clone(),
    };

    Releases {
        stable: installable
            .iter()
            .find(|release| !release.version.is_prerelease())
            .map(|release| release.version.as_str().to_string()),
        latest: installable
            .first()
            .map(|release| release.version.as_str().to_string()),
        versions: installable.iter().map(view).collect(),
    }
}

/// The versions this build can install.
pub async fn releases(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<Releases>> {
    let store = state.singbox();
    let listed = store.releases().await?;
    let installable = Release::installable(&listed);

    Ok(Json(offered(&installable)))
}

#[cfg(test)]
mod releases_tests {
    use super::*;

    fn release(tag: &str) -> Release {
        let value = serde_json::json!({
            "tag_name": format!("v{tag}"),
            "prerelease": tag.contains('-'),
            "assets": [],
        });

        Release::from_json(&value).unwrap()
    }

    /// What a caller sees: the two versions to pick between, and the whole list.
    #[test]
    fn a_list_is_offered_as_the_versions_that_can_be_installed() {
        let listed = [
            release("1.13.21"),
            release("1.15.0-alpha.9"),
            release("1.14.0"),
            release("1.14.2"),
        ];
        let offered = offered(&Release::installable(&listed));

        assert_eq!(
            offered
                .versions
                .iter()
                .map(|release| release.version.as_str())
                .collect::<Vec<_>>(),
            ["1.15.0-alpha.9", "1.14.2", "1.14.0"]
        );
        assert_eq!(
            offered.versions[1].tag, "v1.14.2",
            "the tag is what a release URL is built from"
        );
        assert_eq!(
            offered.latest.as_deref(),
            Some("1.15.0-alpha.9"),
            "the newest of all, pre-release or not"
        );
        assert_eq!(
            offered.stable.as_deref(),
            Some("1.14.2"),
            "and the newest one that is not a pre-release"
        );
    }

    /// A list with nothing but pre-releases has no stable version to name, and
    /// says so rather than naming one that is not stable.
    #[test]
    fn a_pre_release_only_list_has_no_stable_version() {
        let offered = offered(&Release::installable(&[release("1.15.0-alpha.9")]));

        assert_eq!(offered.stable, None);
        assert_eq!(offered.latest.as_deref(), Some("1.15.0-alpha.9"));
    }

    /// The list is never empty behind a version that is named.
    #[test]
    fn an_empty_list_names_nothing() {
        let offered = offered(&Release::installable(&[]));

        assert_eq!(offered.stable, None);
        assert_eq!(offered.latest, None);
        assert!(offered.versions.is_empty());
    }
}

/// The schema of the version in use: the whole document, as it was written by
/// that version's own binary.
pub async fn schema(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<impl IntoResponse> {
    let store = state.singbox();
    let file = tokio::task::spawn_blocking(move || store.schema_bytes()).await??;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (name, value) in [
        ("x-sing-box-version", file.version.as_str()),
        ("x-sing-box-schema-sha256", file.sha256.as_str()),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value)
                .map_err(|_| Error::Document(format!("{name} is not a header value")))?,
        );
    }

    Ok((headers, file.body))
}

/// What to ask the core to generate.
#[derive(Debug, Deserialize)]
pub struct Generation {
    pub command: Generate,
    /// The name a certificate or an ECH configuration is for.
    pub name: Option<String>,
    /// How many bytes of randomness.
    pub length: Option<u32>,
}

/// What the core generated.
///
/// The output is a credential — a private key, a uuid — and it is the answer,
/// so it is here. It is written nowhere else: not to a log, not to a file.
#[derive(Debug, Serialize)]
pub struct Generated {
    pub command: String,
    pub output: String,
}

/// Ask the core to generate something.
pub async fn generate(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(asked): Json<Generation>,
) -> ResponseResult<Json<Generated>> {
    let store = state.singbox();

    // Which argument belongs to which command is this build's decision, and a
    // caller that sends the wrong one is told rather than ignored.
    let argument = match asked.command.needs() {
        Needs::Nothing => {
            if asked.name.is_some() || asked.length.is_some() {
                return Err(Error::Document(
                    "this command takes neither a name nor a length".to_string(),
                ));
            }

            None
        }
        Needs::Name => match (asked.name, asked.length) {
            (Some(name), None) => Some(name),
            _ => {
                return Err(Error::Document(
                    "this command takes one name, and nothing else".to_string(),
                ))
            }
        },
        Needs::Length => match (asked.length, asked.name) {
            (Some(length), None) => Some(length.to_string()),
            _ => {
                return Err(Error::Document(
                    "this command takes one length, and nothing else".to_string(),
                ))
            }
        },
    };

    let command = asked.command;
    let output =
        tokio::task::spawn_blocking(move || store.generate(command, argument.as_deref())).await??;

    Ok(Json(Generated {
        command: command.as_str().to_string(),
        output,
    }))
}

/// The tags a form can offer as references, and what was not checked about them.
#[derive(Debug, Serialize)]
pub struct References {
    pub tags: Vec<Tag>,
    pub unchecked: &'static [assemble::Unchecked],
}

/// What a form can point at.
pub async fn references(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<References>> {
    let store = state.singbox();

    // Nothing is contributed by collections yet: which collections feed a
    // configuration is an open decision (the requirements' §9.9), and until it
    // is made a configuration is what the operator wrote.
    let tags = tokio::task::spawn_blocking(move || store.references(&[])).await??;

    Ok(Json(References {
        tags,
        unchecked: assemble::UNCHECKED,
    }))
}
