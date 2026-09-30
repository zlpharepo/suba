mod auth;
mod collections;
mod providers;
#[cfg(feature = "singbox-core")]
mod singbox;
mod system;

use std::path::Path;

use axum::{handler::HandlerWithoutStateExt, routing::get, Router};
use http::StatusCode;
use tower_http::services::ServeDir;

use crate::{handlers, AppState};

pub struct AppRouter;

async fn not_found() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}

impl AppRouter {
    pub fn route(web_path: impl AsRef<Path>) -> Router<AppState> {
        let api_router = Router::new()
            .nest("/system", system::route())
            .nest("/auth", auth::route())
            .nest("/providers", providers::route())
            .nest("/collections", collections::route());

        #[cfg(feature = "singbox-core")]
        let api_router = api_router.nest("/cores/sing-box", singbox::route());

        let not_found_service = not_found.into_service();
        let web_service = ServeDir::new(web_path)
            .not_found_service(not_found_service)
            .precompressed_gzip()
            .precompressed_br();

        // The delivery route is not under `/api`: what it serves goes to a
        // client's core, not to this instance's own callers, and the token in it
        // is the whole of the authorization. It is merged before the web service,
        // which is the fallback and would otherwise answer for it.
        let delivery = Router::new().route("/{prefix}/{token}", get(handlers::delivery::serve));

        Router::new()
            .nest("/api", api_router)
            .merge(delivery)
            .fallback_service(web_service)
    }
}
