use std::time::Duration;

use crate::{
    state::peers::{self, Identity},
    AppState, Error,
};

/// Startup inputs are separate from machine identity and the active Manager binding.
pub struct AgentOptions {
    pub manager_api_url: String,
    pub token: Option<String>,
    pub proxy: Option<String>,
}

pub(crate) struct Upstream {
    pub(crate) endpoint: String,
    pub(crate) manager: Identity,
    pub(crate) client: reqwest::Client,
}

pub(crate) async fn upstream(state: &AppState, options: AgentOptions) -> Result<Upstream, Error> {
    let endpoint = peers::manager_endpoint(&options.manager_api_url)?;
    let client = peers::outbound_builder(options.proxy.as_deref())?
        .http1_only()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| Error::PeerUnavailable)?;
    let token = options.token.as_deref().filter(|token| !token.is_empty());
    let manager = match state.peers().reusable_agent_binding(token).await? {
        Some(manager) => manager,
        None => {
            let token = token.ok_or(Error::PeerRequest {
                reason: "agent-token: required for initial pairing",
            })?;
            let signer = state.settings().peer_signer().await?;
            state
                .peers()
                .pair_agent(&client, &signer, &endpoint, token)
                .await?
        }
    };
    Ok(Upstream {
        endpoint,
        manager,
        client,
    })
}
