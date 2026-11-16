//! Environment registration and dispatch through the selected instance's resource scope.

use axum::{
    body::to_bytes,
    extract::{OriginalUri, Path, Request, State},
    response::{IntoResponse, Response},
    Json,
};
use http::{header, StatusCode};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    dto::{Authenticated, ResponseResult},
    error::Error,
    state::peers::{self, Invitation},
    AppState,
};

#[derive(Deserialize)]
pub struct AddEnvironment {
    name: String,
    invitation: Invitation,
}

pub async fn index(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> Json<Vec<peers::HostView>> {
    Json(
        state
            .peers()
            .hosts()
            .await
            .into_iter()
            .map(|host| state.peers().host_view(host))
            .collect(),
    )
}

pub async fn create(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(body): Json<AddEnvironment>,
) -> ResponseResult<impl IntoResponse> {
    let signer = state.settings().peer_signer().await?;
    let host = state
        .peers()
        .pair_direct(&signer, body.name, body.invitation)
        .await?;
    Ok((StatusCode::CREATED, Json(state.peers().host_view(host))))
}

pub async fn update(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(id): Path<Uuid>,
    Json(body): Json<EditEnvironment>,
) -> ResponseResult<Json<peers::HostView>> {
    let host = state
        .peers()
        .update_host(id, body.name, body.endpoint)
        .await?;
    Ok(Json(state.peers().host_view(host)))
}

#[derive(Deserialize)]
pub struct EditEnvironment {
    name: String,
    #[serde(default)]
    endpoint: Option<String>,
}

pub async fn remove(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(id): Path<Uuid>,
) -> ResponseResult<StatusCode> {
    state.peers().remove_host(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn forward(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path((id, _)): Path<(Uuid, String)>,
    OriginalUri(uri): OriginalUri,
    request: Request,
) -> ResponseResult<Response> {
    let host = state.peers().host(id).await?;
    let tail = uri
        .path_and_query()
        .map(|value| value.as_str())
        .and_then(|path| path.splitn(5, '/').nth(4))
        .ok_or(Error::PeerNotFound)?;
    let path = format!("/{tail}");
    let method = request.method().to_string();
    if !peers::resource_allowed(&method, &path) {
        return Err(Error::PeerNotFound);
    }
    #[cfg(not(feature = "singbox-core"))]
    if host.mode == peers::Mode::Agent && !path.starts_with("/system/") {
        return Err(Error::PeerNotFound);
    }
    #[cfg(feature = "singbox-core")]
    let headers = request.headers().clone();
    let if_match = request
        .headers()
        .get(header::IF_MATCH)
        .map(|value| value.to_str().map(str::to_string))
        .transpose()
        .map_err(|_| Error::PeerRequest {
            reason: "if-match: invalid header",
        })?;
    let bytes = to_bytes(request.into_body(), peers::BODY_LIMIT)
        .await
        .map_err(|_| Error::PeerRequest {
            reason: "body: the resource request is too large",
        })?;
    let body = if bytes.is_empty() {
        None
    } else {
        Some(
            String::from_utf8(bytes.to_vec()).map_err(|_| Error::PeerRequest {
                reason: "body: UTF-8 JSON is required",
            })?,
        )
    };
    #[cfg(feature = "singbox-core")]
    if host.mode == peers::Mode::Agent {
        return crate::handlers::agents::forward(state, host, method, path, headers, body).await;
    }
    super::peers::call(&state, &host, method, path, if_match, body).await
}
