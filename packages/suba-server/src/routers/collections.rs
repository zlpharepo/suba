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
        .route("/{name}/content", get(collections::content))
        .route("/{name}/tokens", get(collections::tokens))
        .route("/{name}/tokens/{token}", put(collections::mint_token))
        .route("/{name}/tokens/{token}", delete(collections::revoke_token))
}
