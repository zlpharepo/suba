use axum::{routing::get, Router};

use crate::{handlers::system, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/ping", get(system::ping))
        .route("/status", get(system::status))
        .route("/info", get(system::info))
        .route("/metrics", get(system::metrics))
}

/// Local-only instance settings are not part of peer or Agent resources.
pub fn local_route() -> Router<AppState> {
    Router::new().route(
        "/system/settings",
        get(system::settings).put(system::save_settings),
    )
}
