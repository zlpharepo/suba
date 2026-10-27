//! Proxy users and the addresses clients dial, as resources of their own.
//!
//! These are not sing-box configuration contents, so they are not beneath
//! `/cores/sing-box`: `users` and `endpoints` are configuration keys there, and
//! a path under the module would read as one. A user is a proxy identity the
//! instance grants a configuration's inbound to, and an endpoint is the address
//! a client dials for one — both belong to the instance.
//!
//! The group exists only in a build that can run a core (R0.7), because a
//! configuration's document is what names the inbounds each answer is about.

use axum::{
    routing::{delete, get, put},
    Router,
};

use crate::{handlers::users, AppState};

pub fn route() -> Router<AppState> {
    Router::new()
        .route("/users", get(users::index))
        .route("/users/{name}", put(users::put).delete(users::delete))
        .route("/users/{name}/credentials", delete(users::renew))
        .route("/users/{name}/content", get(users::content))
        .route(
            "/users/{name}/tokens/{token}",
            put(users::mint_token).delete(users::revoke_token),
        )
        .route("/endpoints", get(users::endpoints))
        .route(
            "/endpoints/{config}/{tag}",
            put(users::put_endpoint).delete(users::delete_endpoint),
        )
        .route("/configs/{name}/exports", get(users::exports))
}
