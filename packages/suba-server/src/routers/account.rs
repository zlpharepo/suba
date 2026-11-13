use axum::{
    routing::{get, put},
    Router,
};

use crate::{handlers::account, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route(
            "/account",
            get(account::account).put(account::change_username),
        )
        .route("/account/password", put(account::change_password))
}
