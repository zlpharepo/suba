//! The manager's WebSocket upgrade for Agent sessions.
//!
//! The upgrade never initializes identity and never authorizes incoming resource
//! requests on its own: a session starts with a signed challenge the node proves.

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    response::Response,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{error::Error, state::peers::agent, AppState};

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
