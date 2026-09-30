use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use suba_core::subscription::Unreadable;
use suba_core::RefreshStatus;

use crate::{
    dto::{Authenticated, ErrorResponse, ResponseResult},
    error::Error,
    provider::Provider,
    state::providers::Refreshed,
    tracing, AppState,
};

/// The outcome of reading a provider's subscription, without the payload.
///
/// A subscription may carry credentials, so what is reported is how big it is
/// and what it holds, never the bytes themselves. `status` says which of the
/// three things happened — the payload arrived, it arrived unchanged, or the
/// provider confirmed that what is held is current — because "nothing was
/// written" and "nothing arrived" are different answers.
#[derive(Debug, Serialize, Deserialize)]
pub struct Refresh {
    pub name: String,
    pub status: RefreshStatus,
    /// The size of the payload held after the refresh.
    pub bytes: usize,
    /// How many nodes it holds.
    pub nodes: usize,
    /// Why none of them came out of the payload, when its declared shape is one
    /// this build does not read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<Unreadable>,
}

impl From<Refreshed> for Refresh {
    fn from(refreshed: Refreshed) -> Self {
        Self {
            name: refreshed.name,
            status: refreshed.status,
            bytes: refreshed.bytes,
            nodes: refreshed.nodes,
            unreadable: refreshed.unreadable,
        }
    }
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
    tracing::debug!("Stored provider '{}': {}", refreshed.name, refreshed);

    Ok((StatusCode::CREATED, Json(Refresh::from(refreshed))))
}

/// Re-download a provider and replace the payload it holds.
///
/// The refresh path is the same one the scheduler follows, so a manual
/// refresh cannot race an automatic one.
pub async fn refresh(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let refreshed = state.providers().refresh(&name, state.http()).await?;
    tracing::debug!("Refreshed provider '{}': {}", refreshed.name, refreshed);

    Ok(Json(Refresh::from(refreshed)))
}

/// The payload last fetched for a provider, exactly as it arrives.
///
/// It is served as text because a subscription is opaquely shaped from the
/// server's point of view; conversion into nodes is a separate resource, and
/// into a concrete format a separate step.
pub async fn payload(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let payload = state
        .providers()
        .payload(&name)
        .await?
        .ok_or_else(|| Error::ProviderNoPayload(name.clone()))?;

    Ok(payload)
}

pub async fn delete(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.providers().remove(&name).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
