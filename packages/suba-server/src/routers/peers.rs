use crate::{
    handlers::{agent, peers},
    AppState,
};
use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
    Router,
};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/peers", get(peers::trusted))
        .route("/peers/identity", get(peers::identity))
        .route("/peers/{id}", delete(peers::revoke))
        .route("/peers/invitations", post(peers::invite))
        .route("/peers/invitations/{id}", delete(peers::revoke_invitation))
        .route("/peers/agent/connect", get(agent::connect))
        .route("/peers/challenges", post(peers::challenge))
        .route("/peers/pairings", post(peers::accept))
        .route(
            "/peers/requests",
            post(peers::execute).layer(DefaultBodyLimit::max(
                crate::state::peers::BODY_LIMIT * 6 + 64 * 1024,
            )),
        )
}
