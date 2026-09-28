use axum::{
    routing::{delete, get, post, put},
    Router,
};

use crate::{handlers::proxy_providers, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/", get(proxy_providers::index))
        .route("/{name}", get(proxy_providers::get))
        .route("/{name}", delete(proxy_providers::delete))
        .route("/{name}", put(proxy_providers::insert))
        .route("/{name}/refresh", post(proxy_providers::refresh))
        .route("/{name}/content", get(proxy_providers::content))
}
