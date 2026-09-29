use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use suba_core::tracing;

use crate::{
    config::Provider,
    dto::{Authenticated, ErrorResponse, ResponseResult},
    error::Error,
    AppState,
};

/// The outcome of fetching a subscription, without its contents.
///
/// A subscription may carry credentials, so only its size is reported back.
#[derive(Debug, Serialize, Deserialize)]
pub struct Refresh {
    pub name: String,
    pub bytes: usize,
}

pub async fn index(_auth: Authenticated, State(state): State<AppState>) -> impl IntoResponse {
    let providers = state.providers().list().await;

    Json(providers)
}

pub async fn get(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Some(provider) = state.providers().get(&name).await {
        Json(provider).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: format!("Provider '{}' not found", name),
            }),
        )
            .into_response()
    }
}

pub async fn insert(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(provider): Json<Provider>,
) -> ResponseResult<impl IntoResponse> {
    let refreshed = state
        .providers()
        .upsert(&name, provider, state.http())
        .await?;
    tracing::debug!(
        "Stored provider '{}' ({} bytes)",
        refreshed.name,
        refreshed.bytes
    );

    Ok((
        StatusCode::CREATED,
        Json(Refresh {
            name: refreshed.name,
            bytes: refreshed.bytes,
        }),
    ))
}

/// Re-download a provider and replace its cached contents.
///
/// The refresh path is the same one the scheduler follows, so a manual
/// refresh cannot race an automatic one.
pub async fn refresh(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let refreshed = state.providers().refresh(&name, state.http()).await?;
    tracing::debug!(
        "Refreshed provider '{}' ({} bytes)",
        refreshed.name,
        refreshed.bytes
    );

    Ok(Json(Refresh {
        name: refreshed.name,
        bytes: refreshed.bytes,
    }))
}

/// The payload last cached for a provider, exactly as it was fetched.
///
/// It is served as text because a subscription is opaquely shaped from the
/// server's point of view; conversion into a concrete format is a separate
/// step.
pub async fn content(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let content = state
        .providers()
        .content(&name)
        .await?
        .ok_or_else(|| Error::ProviderNotCached(name.clone()))?;

    Ok(content)
}

pub async fn delete(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.providers().remove(&name).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
