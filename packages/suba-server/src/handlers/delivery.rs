//! The delivery route: a subscription under a token, outside the API.
//!
//! This is the one route a client's core talks to, so it is deliberately unlike
//! the rest: no session, no JSON, and nothing about it that names what is behind
//! it. A token that is not in service answers exactly what a prefix that is not
//! the configured one answers — there is no reply that would help someone
//! looking for a token that works.
//!
//! **The token is never written down**: this module logs the collection and the
//! token's name, never the token or the URL it arrived on, and the request line
//! is not logged by anything above it either.
//!
//! What is left out of a document is not said here: the node counts are the
//! operator's business, and this route answers anyone holding a token.

use axum::{
    extract::{Path, Query, Request, State},
    response::{IntoResponse, Response},
};
use http::{header, HeaderMap, HeaderValue, StatusCode};

use crate::{
    error::Error,
    handlers::collections::{artifact_headers, artifact_of, attachment, Choice},
    routers, tracing, AppState,
};

/// Serve the collection this token addresses, to be read where it lands.
///
/// No `Content-Disposition`: a browser opening the URL shows the document
/// instead of saving it, and a subscription client ignores the difference.
pub async fn serve(
    State(state): State<AppState>,
    Path((prefix, token)): Path<(String, String)>,
    Query(choice): Query<Choice>,
    request: Request,
) -> Response {
    if !addresses_deliveries(&state, &prefix).await {
        return routers::web_file(&state, request).await;
    }

    respond(deliver(&state, &prefix, &token, &choice, request.headers(), false).await)
}

/// Serve the same document as a file, named after the collection.
pub async fn download(
    State(state): State<AppState>,
    Path((prefix, token)): Path<(String, String)>,
    Query(choice): Query<Choice>,
    request: Request,
) -> Response {
    if !addresses_deliveries(&state, &prefix).await {
        return routers::web_file(&state, request).await;
    }

    respond(deliver(&state, &prefix, &token, &choice, request.headers(), true).await)
}

/// Whether a path's first segment is where deliveries live.
///
/// Any other two-segment path is the web UI's (its build writes `/assets/<file>`).
/// A prefix that cannot be read is answered by [`deliver`], which logs why.
async fn addresses_deliveries(state: &AppState, prefix: &str) -> bool {
    match state.settings().subscription_prefix().await {
        Ok(configured) => configured == prefix,
        Err(_) => true,
    }
}

fn respond(delivered: Result<(HeaderMap, String), Error>) -> Response {
    match delivered {
        Ok((headers, body)) => (StatusCode::OK, headers, body).into_response(),
        Err(Error::TooManyRequests { retry_after }) => {
            let mut response = Error::TooManyRequests { retry_after }.into_response();
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));

            response
        }
        Err(error) => error.into_response(),
    }
}

/// Find the collection behind a token and render it.
async fn deliver(
    state: &AppState,
    prefix: &str,
    token: &str,
    choice: &Choice,
    request: &HeaderMap,
    download: bool,
) -> Result<(HeaderMap, String), Error> {
    // A prefix this instance cannot use makes every delivery address nothing,
    // which is exactly what a wrong prefix means from outside — but the operator
    // is told, once per request, in the log.
    let configured = match state.settings().subscription_prefix().await {
        Ok(configured) => configured,
        Err(error) => {
            tracing::error!("deliveries cannot be addressed: {error}");

            return Err(Error::NoSuchDelivery);
        }
    };

    if prefix != configured {
        return Err(Error::NoSuchDelivery);
    }

    // A token that addresses nothing and a token that was revoked are the same
    // answer, because they are the same thing from outside.
    let Some((name, label)) = state.collections().by_token(token).await else {
        return Err(Error::NoSuchDelivery);
    };

    // Counted by the token's name, never by the token.
    if let Err(retry_after) = state.deliveries().check(&format!("{name}/{label}")) {
        tracing::warn!("Delivery '{name}' via token '{label}': rate limited");

        return Err(Error::TooManyRequests { retry_after });
    }

    let format = choice.resolve(request)?;

    // The collection can go away between the lookup and the render; that is the
    // delivery's 404 too, never a message naming it.
    let (artifact, cached) =
        artifact_of(state, &name, format)
            .await
            .map_err(|error| match error {
                Error::CollectionNotFound(_) => Error::NoSuchDelivery,
                other => other,
            })?;

    tracing::info!(
        "Delivered '{name}' via token '{label}': {} nodes as {}, {} bytes, {}",
        artifact.nodes,
        artifact.format,
        artifact.body.len(),
        match cached {
            true => "cached",
            false => "rendered",
        },
    );

    let mut headers = artifact_headers(&artifact);
    if download {
        if let Some(disposition) = attachment(&artifact, &name) {
            headers.insert(header::CONTENT_DISPOSITION, disposition);
        }
    }

    Ok((headers, artifact.body.to_string()))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        config::ServerConfig,
        provider::{Inline, Provider, SharedFields},
    };
    use suba_core::Collection;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-delivery-{}", uuid::Uuid::now_v7()))
    }

    async fn state() -> AppState {
        state_with(None).await
    }

    /// A state whose instance document says where deliveries live.
    async fn state_with(prefix: Option<&str>) -> AppState {
        let root = temp_dir();
        let config = ServerConfig {
            listen: "127.0.0.1".parse().unwrap(),
            port: 0,
            config_dir: root.join("config"),
            data_dir: root.join("data"),
        };

        if let Some(prefix) = prefix {
            crate::fs::ensure_dir(&config.config_dir).unwrap();
            crate::config::write_config(
                config.config_dir.to_str().unwrap(),
                crate::config::APP_CONFIG_BASENAME,
                &crate::config::AppConfig {
                    subscription: Some(crate::config::SubscriptionConfig {
                        prefix: Some(prefix.to_string()),
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }

        AppState::build(&config).await.unwrap()
    }

    fn link(host: &str, name: &str) -> String {
        format!("trojan://hunter2@{host}:443#{name}\n")
    }

    /// A delivery as a client with no preference asks for it.
    async fn get(
        state: &AppState,
        prefix: &str,
        token: &str,
    ) -> Result<(HeaderMap, String), Error> {
        deliver(
            state,
            prefix,
            token,
            &Choice::default(),
            &HeaderMap::new(),
            false,
        )
        .await
    }

    /// A delivery as a client that names itself.
    async fn get_as(
        state: &AppState,
        token: &str,
        format: Option<&str>,
        agent: &str,
    ) -> Result<(HeaderMap, String), Error> {
        let mut request = HeaderMap::new();
        request.insert(header::USER_AGENT, HeaderValue::from_str(agent).unwrap());
        let choice = Choice {
            format: format.map(str::to_owned),
        };

        deliver(state, "s", token, &choice, &request, false).await
    }

    async fn served(state: &AppState) {
        let provider = Provider::Inline(Inline {
            shared: SharedFields::default(),
            payload: link("alpha.example.com", "US-01"),
        });
        state
            .providers()
            .upsert("alpha", provider, state.http())
            .await
            .unwrap();
        state
            .collections()
            .insert(
                "main",
                Collection {
                    providers: vec!["alpha".to_string()],
                    ..Collection::default()
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_token_in_service_serves_the_collection() {
        let state = state().await;
        served(&state).await;

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        let (_, body) = get(&state, "s", &token).await.unwrap();

        // A collection that declares nothing is served base64-wrapped.
        let links = suba_core::proto::base64::decode_to_string(body.as_bytes()).unwrap();
        assert!(!body.contains("://"), "{body}");
        assert!(links.contains("#US-01"), "{links}");
    }

    #[tokio::test]
    async fn a_token_that_is_not_in_service_is_not_found() {
        let state = state().await;
        served(&state).await;

        assert!(matches!(
            get(&state, "sub", "0".repeat(64).as_str()).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    /// The prefix is the instance's, so a URL that is not under it is not a
    /// delivery even when the token is real.
    #[tokio::test]
    async fn the_wrong_prefix_is_not_found() {
        let state = state().await;
        served(&state).await;

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();

        assert!(matches!(
            get(&state, "elsewhere", &token).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    #[tokio::test]
    async fn a_revoked_token_is_not_found() {
        let state = state().await;
        served(&state).await;

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        state
            .collections()
            .revoke_token("main", "phone")
            .await
            .unwrap();

        assert!(matches!(
            get(&state, "s", &token).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    /// The prefix the instance is configured with is the one that serves, and
    /// the leading slash an operator writes is not part of it.
    #[tokio::test]
    async fn the_configured_prefix_is_the_one_that_serves() {
        let state = state_with(Some("/proxy")).await;
        served(&state).await;

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();

        assert!(get(&state, "proxy", &token).await.is_ok());
        assert!(matches!(
            get(&state, "s", &token).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    /// Rotating a token takes the old one out of service.
    #[tokio::test]
    async fn minting_again_leaves_the_old_token_dead() {
        let state = state().await;
        served(&state).await;

        let old = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        let new = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();

        assert_ne!(old, new);
        assert!(matches!(
            get(&state, "s", &old).await,
            Err(Error::NoSuchDelivery)
        ));
        assert!(get(&state, "s", &new).await.is_ok());
    }

    /// What a client needs is in the headers; what the operator needs is not.
    #[tokio::test]
    async fn a_delivery_carries_the_headers_a_client_reads() {
        let state = state().await;
        served(&state).await;

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        let (headers, _) = get(&state, "s", &token).await.unwrap();

        assert_eq!(headers[header::CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        // Opened in a browser, it is shown rather than saved.
        assert!(
            headers.get(header::CONTENT_DISPOSITION).is_none(),
            "{headers:?}"
        );
        // An inline provider refreshes by itself never, so there is no pace to
        // suggest.
        assert!(headers.get("profile-update-interval").is_none());
        assert!(headers.get("x-suba-nodes").is_none(), "{headers:?}");
        assert!(headers.get("x-suba-skipped").is_none(), "{headers:?}");
    }

    /// The download path is the same document, saved under the collection's
    /// name.
    #[tokio::test]
    async fn a_download_is_saved_under_the_collection_name() {
        let state = state().await;
        served(&state).await;

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        let (headers, body) = deliver(
            &state,
            "s",
            &token,
            &Choice::default(),
            &HeaderMap::new(),
            true,
        )
        .await
        .unwrap();

        assert_eq!(
            headers[header::CONTENT_DISPOSITION],
            "attachment; filename=\"subscription.txt\"; filename*=UTF-8''main.txt"
        );
        assert_eq!(body, get(&state, "s", &token).await.unwrap().1);
    }

    /// The pace suggested to a client is the fastest member's, rounded up to
    /// the hour the header counts in.
    #[tokio::test]
    async fn the_update_interval_is_the_shortest_provider_interval() {
        use crate::provider::Local;

        let state = state().await;
        served(&state).await;
        let file = state.data_dir().with_extension("links.txt");
        std::fs::write(&file, link("beta.example.com", "JP-01")).unwrap();
        for (name, interval) in [("slow", 10800), ("fast", 5400), ("manual", 0)] {
            let provider = Provider::Local(Local {
                shared: SharedFields::default(),
                path: file.clone(),
                interval,
            });
            state
                .providers()
                .upsert(name, provider, state.http())
                .await
                .unwrap();
        }
        state
            .collections()
            .insert(
                "main",
                Collection {
                    providers: ["alpha", "slow", "fast", "manual"]
                        .map(String::from)
                        .to_vec(),
                    ..Collection::default()
                },
            )
            .await
            .unwrap();

        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        let (headers, _) = get(&state, "s", &token).await.unwrap();

        assert_eq!(headers["profile-update-interval"], "2");
    }

    /// The query names a format; failing that, a client that can read only one
    /// shape gets that shape; failing that, the collection's declaration.
    #[tokio::test]
    async fn the_format_is_asked_for_or_recognised() {
        let state = state().await;
        served(&state).await;
        let token = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();

        let (headers, body) = get_as(&state, &token, Some("links"), "clash-verge/v2")
            .await
            .unwrap();
        assert_eq!(headers["x-suba-format"], "links");
        assert!(body.contains("#US-01"), "{body}");

        #[cfg(feature = "clash")]
        {
            let (headers, body) = get_as(&state, &token, None, "clash-verge/v2")
                .await
                .unwrap();
            assert_eq!(headers["x-suba-format"], "clash");
            assert_eq!(headers[header::CONTENT_TYPE], "text/yaml; charset=utf-8");
            assert!(body.contains("proxies:"), "{body}");
        }

        let (headers, _) = get_as(&state, &token, None, "curl/8.7.1").await.unwrap();
        assert_eq!(headers["x-suba-format"], "base64");

        assert!(matches!(
            get_as(&state, &token, Some("xray"), "curl/8.7.1").await,
            Err(Error::UnknownFormat)
        ));
    }

    /// A token used past its limit is refused until its window passes, and the
    /// collection's other tokens are counted on their own.
    #[tokio::test]
    async fn a_token_used_too_often_is_refused() {
        let state = state().await;
        served(&state).await;
        let phone = state
            .collections()
            .mint_token("main", "phone")
            .await
            .unwrap();
        let laptop = state
            .collections()
            .mint_token("main", "laptop")
            .await
            .unwrap();

        for _ in 0..crate::state::limiter::LIMIT {
            get(&state, "s", &phone).await.unwrap();
        }

        assert!(matches!(
            get(&state, "s", &phone).await,
            Err(Error::TooManyRequests { retry_after }) if retry_after > 0
        ));
        assert!(get(&state, "s", &laptop).await.is_ok());
    }
}
