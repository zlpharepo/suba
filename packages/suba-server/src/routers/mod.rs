mod auth;
mod collections;
mod providers;
#[cfg(feature = "singbox-core")]
mod singbox;
mod system;

use std::path::Path;

use axum::{handler::HandlerWithoutStateExt, Router};
use http::StatusCode;
use tower_http::services::ServeDir;

use crate::AppState;

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

        Router::new()
            .nest("/api", api_router)
            .fallback_service(web_service)
    }
}
