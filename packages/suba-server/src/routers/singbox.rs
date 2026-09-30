//! The sing-box core as an HTTP resource group.
//!
//! The group exists only in a build that can run a core (R0.7): with
//! `singbox-core` off, these routes are not there at all, which is how a
//! capability this build does not have is answered — absent, not "unsupported".

use axum::{
    routing::{get, post, put},
    Router,
};

use crate::{handlers::singbox, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/", get(singbox::index))
        .route("/", put(singbox::switch))
        .route("/status", get(singbox::status))
        .route("/status", put(singbox::act))
        .route("/config/{section}", get(singbox::config))
        .route("/config/{section}", put(singbox::write_config))
        .route("/versions", get(singbox::versions))
        .route(
            "/versions/{version}",
            get(singbox::version)
                .post(singbox::install_version)
                .delete(singbox::delete_version),
        )
        .route("/releases", get(singbox::releases))
        .route("/schema", get(singbox::schema))
        .route("/generate", post(singbox::generate))
        .route("/references", get(singbox::references))
}
