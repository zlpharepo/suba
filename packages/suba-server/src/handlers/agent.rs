//! The manager's WebSocket upgrade and the node's own upstream settings.
//!
//! The upgrade never initializes identity and never authorizes incoming resource
//! requests on its own: a session starts with a signed challenge the node proves.

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::Authenticated,
    error::Error,
    state::peers::{agent, AgentUpstream, Identity, Invitation},
    AppState,
};

#[derive(Deserialize)]
pub(crate) struct ConnectQuery {
    host: Uuid,
}

pub(crate) async fn connect(
    State(state): State<AppState>,
    Query(query): Query<ConnectQuery>,
    upgrade: WebSocketUpgrade,
) -> Result<Response, Error> {
    state.peers().agent_host(query.host).await?;
    state.settings().existing_peer_signer().await?;
    Ok(upgrade
        .max_message_size(agent::FRAME_LIMIT)
        .max_frame_size(agent::FRAME_LIMIT)
        .max_write_buffer_size(agent::FRAME_LIMIT + 128 * 1024)
        .on_upgrade(move |socket| agent::accept(state, query.host, socket)))
}

/// What this node knows about its own upstream manager.
///
/// The proxy is reported as configured or not: its credentials are never echoed
/// back, so a redacted value cannot be saved over the real one.
#[derive(Serialize)]
pub struct AgentView {
    pub state: agent::AgentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connected_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<AgentManager>,
    pub proxy_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_endpoint: Option<String>,
}

#[derive(Serialize)]
pub struct AgentManager {
    pub identity: Identity,
    pub endpoint: String,
}

#[derive(Deserialize)]
pub struct JoinAgent {
    pub invitation: Invitation,
    #[serde(default)]
    pub proxy: Option<String>,
}

/// A connection edit. Omitting `proxy` leaves it as it is; `null` clears it.
#[derive(Deserialize)]
pub struct EditAgent {
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    pub proxy: Option<Option<String>>,
}

/// Tell a missing field from an explicit `null`: serde collapses both into `None`.
fn double_option<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

fn view(status: agent::AgentStatus, upstream: Option<&AgentUpstream>) -> AgentView {
    let configured = upstream.and_then(|link| link.proxy.as_deref());
    AgentView {
        state: status.state,
        reason: status.reason,
        connected_at: status.connected_at,
        last_seen: status.last_seen,
        manager: upstream.map(|link| AgentManager {
            identity: link.manager.clone(),
            endpoint: link.endpoint.clone(),
        }),
        proxy_configured: configured.is_some(),
        // The userinfo of a proxy URL is a credential: only the rest is reported.
        proxy_endpoint: configured.and_then(sanitized_proxy),
    }
}

/// An HTTP proxy URL without its credentials.
fn sanitized_proxy(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    Some(parsed.as_str().trim_end_matches('/').to_string())
}

pub async fn agent_view(State(state): State<AppState>, _auth: Authenticated) -> Json<AgentView> {
    let upstream = state.peers().agent_upstream().await;
    Json(view(state.peers().agent.local_status(), upstream.as_ref()))
}

pub async fn join_agent(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(body): Json<JoinAgent>,
) -> Result<(StatusCode, Json<AgentView>), Error> {
    let signer = state.settings().peer_signer().await?;
    let link = state
        .peers()
        .join_agent(&signer, body.invitation, body.proxy)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(view(state.peers().agent.local_status(), Some(&link))),
    ))
}

pub async fn edit_agent(
    State(state): State<AppState>,
    _auth: Authenticated,
    Json(body): Json<EditAgent>,
) -> Result<Json<AgentView>, Error> {
    let link = state
        .peers()
        .edit_agent_upstream(body.endpoint, body.proxy)
        .await?;
    Ok(Json(view(state.peers().agent.local_status(), Some(&link))))
}

pub async fn leave_agent(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> Result<StatusCode, Error> {
    state.peers().leave_agent().await?;
    Ok(StatusCode::NO_CONTENT)
}
