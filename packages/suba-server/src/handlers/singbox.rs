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
use suba_singbox::core::{Metadata, Release, Version};
use suba_singbox::install::{Generate, Needs};
use suba_singbox::run::{self, Exit, Status};

use crate::{
    dto::{Authenticated, ResponseResult},
    error::Error,
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
#[serde(deny_unknown_fields)]
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
    #[serde(flatten)]
    pub metadata: Metadata,
    /// Whether it is the one in use.
    pub current: bool,
    /// Whether it is the one running.
    pub running: bool,
}

/// The versions this machine has.
pub async fn versions(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<Vec<VersionView>>> {
    let store = state.singbox();

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Vec<VersionView>, Error> {
            let current = store.current()?;
            let running = store.running_version();

            Ok(store
                .versions()?
                .into_iter()
                .map(|metadata| VersionView {
                    current: current.as_ref() == Some(&metadata.version),
                    running: running.as_ref() == Some(&metadata.version),
                    metadata,
                })
                .collect())
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
            let metadata = store.installed_record(&version)?.ok_or_else(|| {
                Error::Singbox(suba_singbox::core::Error::NotInstalled {
                    version: version.clone(),
                })
            })?;

            Ok(VersionView {
                current: store.current()?.as_ref() == Some(&version),
                running: store.running_version().as_ref() == Some(&version),
                metadata,
            })
        })
        .await??,
    ))
}

/// Install a version from the release server.
///
/// Already installed is an answer, not a failure: it comes back as it is, and
/// nothing is downloaded again.
pub async fn install_version(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(asked): Path<String>,
) -> ResponseResult<(StatusCode, Json<VersionView>)> {
    let store = state.singbox();
    let version = Version::from_tag(&asked);

    let already = {
        let store = state.singbox();
        let version = version.clone();

        tokio::task::spawn_blocking(move || store.installed_record(&version)).await??
    };

    if let Some(metadata) = already {
        return Ok((
            StatusCode::OK,
            Json(VersionView {
                metadata,
                current: store.current()?.as_ref() == Some(&version),
                running: false,
            }),
        ));
    }

    let metadata = store.install(&version).await?;

    Ok((
        StatusCode::CREATED,
        Json(VersionView {
            metadata,
            current: store.current()?.as_ref() == Some(&version),
            running: false,
        }),
    ))
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
#[serde(deny_unknown_fields)]
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
