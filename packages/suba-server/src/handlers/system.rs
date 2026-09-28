use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::{dto::Authenticated, AppState};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Public status
#[derive(Serialize, Deserialize)]
pub struct SystemStatus {
    version: String,
    administrator_configured: bool,
}

/// Authenticated status
#[derive(Serialize, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub administrator_configured: bool,
}

pub async fn ping() -> &'static str {
    "SubA"
}

pub async fn status(State(state): State<AppState>) -> Json<SystemStatus> {
    Json(SystemStatus {
        version: VERSION.to_string(),
        administrator_configured: state.settings().administrator().await.is_some(),
    })
}

pub async fn info(_auth: Authenticated, State(state): State<AppState>) -> Json<SystemInfo> {
    Json(SystemInfo {
        version: VERSION.to_string(),
        administrator_configured: state.settings().administrator().await.is_some(),
    })
}
