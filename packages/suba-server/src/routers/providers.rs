use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::{handlers::providers, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/", get(providers::index))
        .route("/{name}", get(providers::get))
        .route("/{name}", delete(providers::delete))
        .route("/{name}", put(providers::insert))
        .route("/{name}/refresh", post(providers::refresh))
        .route("/{name}/content", get(providers::content))
}
