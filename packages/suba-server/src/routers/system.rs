use axum::{routing::get, Router};

use crate::{handlers::system, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/ping", get(system::ping))
        .route("/status", get(system::status))
        .route("/info", get(system::info))
}
