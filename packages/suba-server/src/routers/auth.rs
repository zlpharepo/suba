use axum::{
    routing::{delete, post},
    Router,
};

use crate::{handlers::auth, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/password", post(auth::password_login))
        .route("/session", delete(auth::logout))
}
