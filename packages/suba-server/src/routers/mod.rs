mod auth;
mod collections;
mod providers;
#[cfg(feature = "singbox-core")]
mod singbox;
mod system;

use std::path::Path;

use axum::{
    body::Body,
    extract::Request,
    handler::HandlerWithoutStateExt,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use http::StatusCode;
use tower_http::services::ServeDir;

use crate::{error::Error, handlers, tracing, AppState};

pub struct AppRouter;

async fn not_found() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}

async fn no_such_delivery() -> Response {
    Error::NoSuchDelivery.into_response()
}

fn web_files(web_path: impl AsRef<Path>) -> ServeDir {
    ServeDir::new(web_path)
        .precompressed_gzip()
        .precompressed_br()
}

/// A web UI file on a path shaped like a delivery; a missing one is answered as
/// a delivery that is not there, so the two cannot be told apart.
pub(crate) async fn web_file(state: &AppState, request: Request) -> Response {
    let mut files = web_files(state.web_dir()).not_found_service(no_such_delivery.into_service());

    match files.try_call(request).await {
        Ok(response) => response.map(Body::new),
        Err(error) => {
            tracing::error!("web UI file could not be read: {error}");

            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
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
        let web_service = web_files(web_path).not_found_service(not_found_service);

        // The delivery route is not under `/api`: what it serves goes to a
        // client's core, not to this instance's own callers, and the token in it
        // is the whole of the authorization. It is merged before the web service,
        // which is the fallback and would otherwise answer for it; a path whose
        // first segment is not the prefix is handed back to the web files.
        let delivery = Router::new()
            .route("/{prefix}/{token}", get(handlers::delivery::serve))
            .route(
                "/{prefix}/{token}/download",
                get(handlers::delivery::download),
            );

        Router::new()
            .nest("/api", api_router)
            .merge(delivery)
            .fallback_service(web_service)
    }
}

/// The router as a client meets it: over a socket, through every layer, so
/// what only the wiring decides — which paths exist, which need a session, the
/// headers added after a handler returns — is pinned rather than smoke-tested.
#[cfg(test)]
mod tests {
    use http::header;
    use serde_json::{json, Value};

    use crate::{config::ServerConfig, AppState};

    struct Server {
        base: String,
        client: reqwest::Client,
        token: String,
        root: std::path::PathBuf,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    impl Server {
        /// A server on a free port with an administrator logged in.
        async fn start() -> Self {
            let root = std::env::temp_dir().join(format!("suba-http-{}", uuid::Uuid::now_v7()));
            let config = ServerConfig {
                listen: "127.0.0.1".parse().unwrap(),
                port: 0,
                config_dir: root.join("config"),
                data_dir: root.join("data"),
            };
            let state = AppState::build(&config).await.unwrap();
            let router = super::AppRouter::route(state.web_dir()).with_state(state);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, router).await });

            let client = reqwest::Client::new();
            let login = client
                .post(format!("{base}/api/auth/password"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(
                    json!({"username": "example-admin", "password": "example-password"})
                        .to_string(),
                )
                .send()
                .await
                .unwrap();
            let token = body(login).await["access_token"]
                .as_str()
                .unwrap()
                .to_string();

            Self {
                base,
                client,
                token,
                root,
            }
        }

        fn get(&self, path: &str) -> reqwest::RequestBuilder {
            self.client.get(format!("{}{path}", self.base))
        }

        fn authed(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
            self.client
                .request(method, format!("{}{path}", self.base))
                .bearer_auth(&self.token)
        }

        async fn put_json(&self, path: &str, value: Value) -> reqwest::Response {
            self.authed(reqwest::Method::PUT, path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(value.to_string())
                .send()
                .await
                .unwrap()
        }

        /// A collection over one inline node, with a delivery token for it.
        async fn delivery(&self) -> String {
            self.put_json(
                "/api/providers/alpha",
                json!({"type": "inline", "payload": "trojan://example-password@alpha.example.com:443#US-01\n"}),
            )
            .await;
            self.put_json("/api/collections/main", json!({"providers": ["alpha"]}))
                .await;
            let minted = self
                .authed(reqwest::Method::PUT, "/api/collections/main/tokens/phone")
                .send()
                .await
                .unwrap();

            body(minted).await["token"].as_str().unwrap().to_string()
        }
    }

    async fn body(response: reqwest::Response) -> Value {
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap()
    }

    /// The list carries what a page shows without a request per collection.
    #[tokio::test]
    async fn the_collection_list_carries_nodes_and_links() {
        let server = Server::start().await;
        let token = server.delivery().await;

        let listed = server
            .authed(reqwest::Method::GET, "/api/collections")
            .send()
            .await
            .unwrap();
        let main = &body(listed).await["main"];

        assert_eq!(main["providers"], json!(["alpha"]));
        assert_eq!(main["nodes"], 1);
        assert_eq!(main["unresolved"], json!([]));
        assert_eq!(
            main["links"],
            json!([{"name": "phone", "token": token, "path": format!("/s/{token}")}])
        );
    }

    /// The machine's numbers are an operator's, not a subscriber's.
    #[tokio::test]
    async fn the_metrics_need_a_session_and_describe_the_machine() {
        let server = Server::start().await;

        let anonymous = server.get("/api/system/metrics").send().await.unwrap();
        assert_eq!(anonymous.status(), 401);

        let metrics = body(
            server
                .authed(reqwest::Method::GET, "/api/system/metrics")
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert!(metrics["cpu"]["cores"].as_u64().unwrap() > 0);
        assert!(metrics["memory"]["total"].as_u64().unwrap() > 0);
        assert!(metrics["network"]["received"].is_u64());
        assert!(metrics["host"]["arch"].is_string());
    }

    /// A token listed later is the one minted, with a path that serves it.
    #[tokio::test]
    async fn a_minted_token_can_be_listed_and_opened_again() {
        let server = Server::start().await;
        let token = server.delivery().await;

        let listed = server
            .authed(reqwest::Method::GET, "/api/collections/main/tokens")
            .send()
            .await
            .unwrap();
        assert_eq!(listed.status(), 200);
        assert_eq!(
            body(listed).await,
            json!([{"name": "phone", "token": token, "path": format!("/s/{token}")}])
        );

        let opened = server.get(&format!("/s/{token}")).send().await.unwrap();
        assert_eq!(opened.status(), 200);
    }

    #[tokio::test]
    async fn the_api_needs_a_session_and_the_delivery_route_does_not() {
        let server = Server::start().await;
        let token = server.delivery().await;

        let anonymous = server.get("/api/providers").send().await.unwrap();
        assert_eq!(anonymous.status(), 401);

        let authed = server
            .authed(reqwest::Method::GET, "/api/providers")
            .send()
            .await
            .unwrap();
        assert_eq!(authed.status(), 200);

        let delivered = server.get(&format!("/s/{token}")).send().await.unwrap();
        assert_eq!(delivered.status(), 200);
    }

    /// Shown where it lands, saved when asked to be, and one answer for every
    /// way a URL can address nothing.
    #[tokio::test]
    async fn the_two_delivery_paths_and_their_not_found() {
        let server = Server::start().await;
        let token = server.delivery().await;

        let inline = server.get(&format!("/s/{token}")).send().await.unwrap();
        assert_eq!(inline.status(), 200);
        assert!(inline.headers().get(header::CONTENT_DISPOSITION).is_none());
        assert_eq!(inline.headers()[header::CACHE_CONTROL], "no-store");

        let saved = server
            .get(&format!("/s/{token}/download"))
            .send()
            .await
            .unwrap();
        assert_eq!(saved.status(), 200);
        assert!(saved.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment;"));

        for path in [
            "/s/not-a-token".to_string(),
            "/s/not-a-token/download".to_string(),
            format!("/elsewhere/{token}"),
        ] {
            let missing = server.get(&path).send().await.unwrap();
            assert_eq!(missing.status(), 404, "{path}");
            assert_eq!(
                body(missing).await,
                json!({"message": "Not found"}),
                "{path}"
            );
        }
    }

    /// The web UI's build writes `/assets/<file>`, a path shaped like a
    /// delivery; it is the UI's, and a file that is not there is the same 404.
    #[tokio::test]
    async fn the_web_ui_files_are_not_taken_for_deliveries() {
        let server = Server::start().await;
        let assets = server.root.join("data/web/assets");
        crate::fs::ensure_dir(&assets).unwrap();
        std::fs::write(assets.join("index-example.js"), "export {};\n").unwrap();

        let served = server.get("/assets/index-example.js").send().await.unwrap();
        assert_eq!(served.status(), 200);
        assert_eq!(served.text().await.unwrap(), "export {};\n");

        for path in ["/assets/missing.js", "/assets/missing.js/download"] {
            let missing = server.get(path).send().await.unwrap();
            assert_eq!(missing.status(), 404, "{path}");
            assert_eq!(
                body(missing).await,
                json!({"message": "Not found"}),
                "{path}"
            );
        }
    }

    /// The wait is a header a client reads, added outside the handler's body.
    #[tokio::test]
    async fn a_token_past_its_limit_is_told_when_to_come_back() {
        let server = Server::start().await;
        let token = server.delivery().await;

        for _ in 0..crate::state::limiter::LIMIT {
            server.get(&format!("/s/{token}")).send().await.unwrap();
        }

        let refused = server.get(&format!("/s/{token}")).send().await.unwrap();
        assert_eq!(refused.status(), 429);
        let wait: u64 = refused.headers()[header::RETRY_AFTER]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&wait), "{wait}");
    }

    /// The `ETag` a read answers with is the one a write can name, quotes and
    /// all, and a stale one is refused before anything else is looked at.
    #[cfg(feature = "singbox-core")]
    #[tokio::test]
    async fn the_configuration_etag_round_trips_over_http() {
        let server = Server::start().await;

        let read = server
            .authed(reqwest::Method::GET, "/api/cores/sing-box/config")
            .send()
            .await
            .unwrap();
        assert_eq!(read.status(), 200);
        let etag = read.headers()[header::ETAG].to_str().unwrap().to_string();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");

        let write = |if_match: &str| {
            server
                .authed(reqwest::Method::PUT, "/api/cores/sing-box/config/log")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, if_match.to_string())
                .body(json!({"level": "info"}).to_string())
                .send()
        };

        // The current tag gets past the precondition; with no version installed
        // there is no schema to check against, which is the next answer.
        assert_eq!(write(&etag).await.unwrap().status(), 409);
        assert_eq!(write("\"stale\"").await.unwrap().status(), 412);
    }

    /// With the core feature off, the group is not there at all.
    #[cfg(not(feature = "singbox-core"))]
    #[tokio::test]
    async fn a_build_without_the_core_has_no_core_routes() {
        let server = Server::start().await;

        let absent = server
            .authed(reqwest::Method::GET, "/api/cores/sing-box")
            .send()
            .await
            .unwrap();
        assert_eq!(absent.status(), 404);
    }
}
