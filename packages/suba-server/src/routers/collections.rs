use axum::{
    routing::{delete, get, put},
    Router,
};

use crate::{handlers::collections, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/", get(collections::index))
        .route("/{name}", get(collections::get))
        .route("/{name}", delete(collections::delete))
        .route("/{name}", put(collections::insert))
        .route("/{name}/nodes", get(collections::nodes))
}
