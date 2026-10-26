//! Local-only trust administration and authenticated, non-delegating peer operations.

use axum::{
    body::{to_bytes, Body},
    extract::{OriginalUri, Path, Request, State},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header, HeaderName, HeaderValue, StatusCode};
use serde::Deserialize;
use tower::ServiceExt;
use uuid::Uuid;

use crate::{
    dto::{Authenticated, ResponseResult},
    error::Error,
    state::peers::{
        self, ChallengeRequest, Host, Identity, Invitation, PairClaim, PairReceipt, ResourceReply,
        ResourceRequest, Signed, TrustedPeer,
    },
    AppState,
};

#[derive(Deserialize)]
pub struct NamedEndpoint {
    name: String,
    endpoint: String,
}

#[derive(Deserialize)]
pub struct AddHost {
    name: String,
    invitation: Invitation,
}

pub async fn identity(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<Identity>> {
    Ok(Json(state.settings().peer_signer().await?.identity))
}

pub async fn trusted(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> Json<Vec<TrustedPeer>> {
    Json(state.peers().trusted().await)
}

pub async fn revoke(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(id): Path<Uuid>,
) -> ResponseResult<StatusCode> {
    state.peers().revoke(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn invite(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(body): Json<NamedEndpoint>,
) -> ResponseResult<impl IntoResponse> {
    let signer = state.settings().peer_signer().await?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .peers()
                .invite(&signer, body.name, body.endpoint)
                .await?,
        ),
    ))
}

pub async fn revoke_invitation(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(id): Path<Uuid>,
) -> StatusCode {
    state.peers().revoke_invitation(id).await;
    StatusCode::NO_CONTENT
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(body): Json<ChallengeRequest>,
) -> ResponseResult<Json<Signed<peers::Challenge>>> {
    let signer = state.settings().existing_peer_signer().await?;
    Ok(Json(state.peers().challenge(&signer, body).await?))
}

pub async fn accept(
    State(state): State<AppState>,
    Json(proof): Json<Signed<PairClaim>>,
) -> ResponseResult<Json<Signed<PairReceipt>>> {
    let signer = state.settings().existing_peer_signer().await?;
    Ok(Json(state.peers().accept(&signer, proof).await?))
}

pub async fn hosts(State(state): State<AppState>, _auth: Authenticated) -> Json<Vec<Host>> {
    Json(state.peers().hosts().await)
}

pub async fn add_host(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(body): Json<AddHost>,
) -> ResponseResult<impl IntoResponse> {
    let signer = state.settings().peer_signer().await?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .peers()
                .pair(&signer, body.name, body.invitation)
                .await?,
        ),
    ))
}

pub async fn update_host(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(id): Path<Uuid>,
    Json(body): Json<NamedEndpoint>,
) -> ResponseResult<Json<Host>> {
    Ok(Json(
        state
            .peers()
            .update_host(id, body.name, body.endpoint)
            .await?,
    ))
}

pub async fn remove_host(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(id): Path<Uuid>,
) -> ResponseResult<StatusCode> {
    state.peers().remove_host(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn execute(
    State(state): State<AppState>,
    Json(proof): Json<Signed<ResourceRequest>>,
) -> ResponseResult<Json<Signed<ResourceReply>>> {
    let signer = state.settings().existing_peer_signer().await?;
    let grant = state.peers().authorize(&signer, &proof).await?;
    let claim = proof.payload;
    if !peers::resource_allowed(&claim.method, &claim.path) {
        return Err(Error::PeerNotFound);
    }
    if claim
        .body
        .as_ref()
        .is_some_and(|body| body.len() > peers::BODY_LIMIT)
    {
        return Err(Error::PeerRequest {
            reason: "peer.body: the resource request is too large",
        });
    }
    let mut request = Request::builder()
        .method(claim.method.as_str())
        .uri(&claim.path);
    if claim.body.is_some() {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(etag) = &claim.if_match {
        request = request.header(header::IF_MATCH, etag);
    }
    let mut request = request
        .body(claim.body.map_or_else(Body::empty, Body::from))
        .map_err(|_| Error::PeerRequest {
            reason: "peer.request: invalid request metadata",
        })?;
    request.extensions_mut().insert(grant);
    // This router contains resources only, with no auth, trust, hosts, delivery or static-file routes.
    let response = crate::routers::AppRouter::resources()
        .with_state(state)
        .oneshot(request)
        .await
        .expect("infallible resource router");
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter(|(name, _)| reply_header(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect();
    let body = to_bytes(response.into_body(), peers::REPLY_LIMIT)
        .await
        .map_err(|_| Error::PeerUncertain)?;
    Ok(Json(signer.sign(
        "response",
        ResourceReply {
            nonce: claim.challenge.nonce,
            actor: claim.challenge.actor.id,
            target: signer.identity.id,
            status,
            headers,
            body: URL_SAFE_NO_PAD.encode(body),
        },
    )?))
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
    let signer = state.settings().peer_signer().await?;
    let reply = state
        .peers()
        .forward(&signer, &host, method, path, if_match, body)
        .await?;
    let status = StatusCode::from_u16(reply.status).map_err(|_| Error::PeerUnavailable)?;
    // A remote authentication failure must not sign the local administrator out.
    if status == StatusCode::UNAUTHORIZED || status.is_informational() {
        return Err(Error::PeerUnavailable);
    }
    let body = URL_SAFE_NO_PAD
        .decode(reply.body)
        .map_err(|_| Error::PeerUnavailable)?;
    if body.len() > peers::REPLY_LIMIT {
        return Err(Error::PeerUnavailable);
    }
    let mut response = (status, body).into_response();
    for (name, value) in reply.headers {
        if reply_header(&name) {
            let name = HeaderName::try_from(name).map_err(|_| Error::PeerUnavailable)?;
            let value = HeaderValue::try_from(value).map_err(|_| Error::PeerUnavailable)?;
            response.headers_mut().insert(name, value);
        }
    }
    Ok(response)
}

fn reply_header(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "content-disposition"
            | "etag"
            | "retry-after"
            | "subscription-update-interval"
            | "x-suba-format"
            | "x-suba-nodes"
            | "x-suba-skipped"
    )
}
