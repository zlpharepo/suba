//! The sing-box module, as HTTP resources.
//!
//! Everything here is thin: the work is the store's, and this layer decides what
//! a request means and which status it answers with. The one thing it must not
//! do is hold a running core hostage to a request — a stop waits for the process
//! to close what it opened, and that wait belongs on the blocking pool.

use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
