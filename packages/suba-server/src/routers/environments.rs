use axum::{
    routing::{delete, get},
    Router,
};

use crate::{handlers::environments, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route(
            "/environments",
            get(environments::index).post(environments::create),
        )
        .route(
            "/environments/{id}",
            delete(environments::remove).put(environments::update),
        )
        .route(
            "/environments/{id}/{*path}",
            get(environments::forward)
                .post(environments::forward)
                .put(environments::forward)
                .delete(environments::forward),
        )
}
