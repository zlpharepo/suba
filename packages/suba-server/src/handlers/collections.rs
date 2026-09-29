//! The collections of the instance, as HTTP resources.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use suba_core::Collection;

use crate::{
    dto::{Authenticated, ErrorResponse, ResponseResult},
    tracing, AppState,
};

pub async fn index(_auth: Authenticated, State(state): State<AppState>) -> impl IntoResponse {
    let collections = state.collections().list().await;

    Json(collections)
}

pub async fn get(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Some(collection) = state.collections().get(&name).await {
        Json(collection).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                message: format!("Collection '{}' not found", name),
            }),
        )
            .into_response()
    }
}

/// Write a collection, replacing what was there.
///
/// The collection's own filter is validated here, so a pattern that cannot be
/// used is refused with the field that is wrong rather than accepted and
/// discovered when a client asks for the subscription.
pub async fn insert(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(collection): Json<Collection>,
) -> ResponseResult<impl IntoResponse> {
    state
        .collections()
        .insert(&name, collection.clone())
        .await?;
    tracing::debug!(
        "Stored collection '{}' ({} providers)",
        name,
        collection.providers.len()
    );

    Ok((StatusCode::CREATED, Json(collection)))
}

pub async fn delete(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.collections().remove(&name).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}
