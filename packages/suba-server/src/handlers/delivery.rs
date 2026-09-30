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
    extract::{Path, Query, State},
    response::IntoResponse,
};
use http::{HeaderMap, StatusCode};

use crate::{
    error::Error,
    handlers::collections::{artifact_headers, artifact_of, Narrowing},
    AppState,
};

/// Serve the collection this token addresses.
pub async fn serve(
    State(state): State<AppState>,
    Path((prefix, token)): Path<(String, String)>,
    Query(narrowing): Query<Narrowing>,
) -> Result<impl IntoResponse, Error> {
    let (headers, body) = deliver(&state, &prefix, &token, &narrowing).await?;

    Ok((StatusCode::OK, headers, body))
}

/// Find the collection behind a token and render it.
async fn deliver(
    state: &AppState,
    prefix: &str,
    token: &str,
    narrowing: &Narrowing,
) -> Result<(HeaderMap, String), Error> {
    if prefix != state.settings().subscription_prefix().await {
        return Err(Error::NoSuchDelivery);
    }

    // A token that addresses nothing and a token that was revoked are the same
    // answer, because they are the same thing from outside.
    let Some((name, _)) = state.collections().by_token(token).await else {
        return Err(Error::NoSuchDelivery);
    };

    // The collection can go away between the lookup and the render; that is the
    // delivery's 404 too, never a message naming it.
    let artifact = artifact_of(state, &name, narrowing)
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
        let root = temp_dir();
        let config = ServerConfig {
            listen: "127.0.0.1".parse().unwrap(),
            port: 0,
            config_dir: root.join("config"),
            data_dir: root.join("data"),
        };

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
        let (_, body) = deliver(&state, "sub", &token, &Narrowing::default())
            .await
            .unwrap();

        assert!(body.contains("#US-01"), "{body}");
    }

    #[tokio::test]
    async fn a_token_that_is_not_in_service_is_not_found() {
        let state = state().await;
        served(&state).await;

        assert!(matches!(
            deliver(
                &state,
                "sub",
                "0".repeat(64).as_str(),
                &Narrowing::default()
            )
            .await,
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
            deliver(&state, "elsewhere", &token, &Narrowing::default()).await,
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
            deliver(&state, "sub", &token, &Narrowing::default()).await,
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
            deliver(&state, "sub", &old, &Narrowing::default()).await,
            Err(Error::NoSuchDelivery)
        ));
        assert!(deliver(&state, "sub", &new, &Narrowing::default())
            .await
            .is_ok());
    }
}
