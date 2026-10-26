use axum::{
    extract::{DefaultBodyLimit, Request},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router,
};
use http::{header, HeaderValue};

use crate::{handlers::peers, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/hosts", get(peers::hosts).post(peers::add_host))
        .route(
            "/hosts/{id}",
            delete(peers::remove_host).put(peers::update_host),
        )
        .route(
            "/hosts/{id}/{*path}",
            get(peers::forward)
                .post(peers::forward)
                .put(peers::forward)
                .delete(peers::forward),
        )
        .route("/peers", get(peers::trusted))
        .route("/peers/identity", get(peers::identity))
        .route("/peers/{id}", delete(peers::revoke))
        .route("/peers/invitations", post(peers::invite))
        .route("/peers/invitations/{id}", delete(peers::revoke_invitation))
        .route("/peers/challenges", post(peers::challenge))
        .route("/peers/pairings", post(peers::accept))
        .route(
            "/peers/requests",
            post(peers::execute).layer(DefaultBodyLimit::max(
                crate::state::peers::BODY_LIMIT * 6 + 64 * 1024,
            )),
        )
        .layer(middleware::from_fn(no_store))
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
