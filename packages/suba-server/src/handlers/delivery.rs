//! The delivery route: a subscription under a token, outside the API.
//!
//! This is the one route a client's core talks to, so it is deliberately unlike
//! the rest: no session, no JSON, and nothing about it that names what is behind
//! it. A token that is not in service answers exactly what a prefix that is not
//! the configured one answers — there is no reply that would help someone
//! looking for a token that works.
//!
//! **The token is never written down**: this module logs the collection it found
//! and never the URL it arrived on, and the request line is not logged by
//! anything above it either.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
};
use http::{HeaderMap, StatusCode};

use crate::{
    error::Error,
    handlers::collections::{artifact_headers, artifact_of},
    tracing, AppState,
};

/// Serve the collection this token addresses.
pub async fn serve(
    State(state): State<AppState>,
    Path((prefix, token)): Path<(String, String)>,
) -> Result<impl IntoResponse, Error> {
    let (headers, body) = deliver(&state, &prefix, &token).await?;

    Ok((StatusCode::OK, headers, body))
}

/// Find the collection behind a token and render it.
async fn deliver(
    state: &AppState,
    prefix: &str,
    token: &str,
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
    let Some((name, _)) = state.collections().by_token(token).await else {
        return Err(Error::NoSuchDelivery);
    };

    // The collection can go away between the lookup and the render; that is the
    // delivery's 404 too, never a message naming it.
    let artifact = artifact_of(state, &name)
        .await
        .map_err(|error| match error {
            Error::CollectionNotFound(_) => Error::NoSuchDelivery,
            other => other,
        })?;

    Ok((artifact_headers(&artifact), artifact.body.to_string()))
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

        let token = state.collections().mint_token("main").await.unwrap();
        let (_, body) = deliver(&state, "s", &token).await.unwrap();

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
            deliver(&state, "sub", "0".repeat(64).as_str()).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    /// The prefix is the instance's, so a URL that is not under it is not a
    /// delivery even when the token is real.
    #[tokio::test]
    async fn the_wrong_prefix_is_not_found() {
        let state = state().await;
        served(&state).await;

        let token = state.collections().mint_token("main").await.unwrap();

        assert!(matches!(
            deliver(&state, "elsewhere", &token).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    #[tokio::test]
    async fn a_revoked_token_is_not_found() {
        let state = state().await;
        served(&state).await;

        let token = state.collections().mint_token("main").await.unwrap();
        state.collections().revoke_token("main").await.unwrap();

        assert!(matches!(
            deliver(&state, "s", &token).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    /// The prefix the instance is configured with is the one that serves, and
    /// the leading slash an operator writes is not part of it.
    #[tokio::test]
    async fn the_configured_prefix_is_the_one_that_serves() {
        let state = state_with(Some("/proxy")).await;
        served(&state).await;

        let token = state.collections().mint_token("main").await.unwrap();

        assert!(deliver(&state, "proxy", &token).await.is_ok());
        assert!(matches!(
            deliver(&state, "s", &token).await,
            Err(Error::NoSuchDelivery)
        ));
    }

    /// Rotating a token takes the old one out of service.
    #[tokio::test]
    async fn minting_again_leaves_the_old_token_dead() {
        let state = state().await;
        served(&state).await;

        let old = state.collections().mint_token("main").await.unwrap();
        let new = state.collections().mint_token("main").await.unwrap();

        assert_ne!(old, new);
        assert!(matches!(
            deliver(&state, "s", &old).await,
            Err(Error::NoSuchDelivery)
        ));
        assert!(deliver(&state, "s", &new).await.is_ok());
    }
}
