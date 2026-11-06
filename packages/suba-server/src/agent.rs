use crate::{state::peers, AppState, Error};

/// Startup inputs are separate from the persisted machine identity: the token
/// is consumed only while establishing the first manager binding.
pub struct AgentOptions {
    pub manager_api_url: String,
    pub token: Option<String>,
}

pub(crate) async fn pair(state: &AppState, options: AgentOptions) -> Result<(), Error> {
    let endpoint = peers::manager_endpoint(&options.manager_api_url)?;
    if let Some(upstream) = state.peers().edge_upstream().await {
        if upstream.endpoint != endpoint {
            return Err(Error::PeerConflict {
                reason: "manager-api-url: does not match the paired manager",
            });
        }
        return state
            .peers()
            .edge_manager_authorized(&upstream.manager)
            .await;
    }
    let token = options.token.ok_or(Error::PeerRequest {
        reason: "agent-token: required for initial pairing",
    })?;
    let signer = state.settings().peer_signer().await?;
    state.peers().pair_agent(&signer, &endpoint, &token).await?;
    Ok(())
}
