use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use suba_core::subscription::{self, Unreadable};
use suba_core::NodeIndex;
use suba_core::RefreshStatus;

use crate::{
    dto::{ErrorResponse, Operator, ResponseResult},
    error::Error,
    handlers::collections::NodeView,
    provider::Provider,
    state::providers::Refreshed,
    tracing, AppState,
};

/// The outcome of reading a provider's subscription, without the payload.
///
/// A subscription may carry credentials, so what is reported is how big it is
/// and what it holds, never the bytes themselves. `status` says which of the
/// three things happened — the payload arrived, it arrived unchanged, or the
/// provider confirmed that what is held is current — because unchanged bytes
/// and a response with no payload are different answers.
#[derive(Debug, Serialize, Deserialize)]
pub struct Refresh {
    pub name: String,
    pub status: RefreshStatus,
    /// The size of the payload held after the refresh.
    pub bytes: usize,
    /// How many nodes it holds.
    pub nodes: usize,
    /// Why none of them came out of the payload, when it is a shape this build
    /// does not read.
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

#[derive(Serialize)]
pub struct ProviderSummary {
    #[serde(flatten)]
    pub definition: Provider,
    /// Last successful synchronization; failed attempts do not advance it.
    pub updated_at: Option<i64>,
}

pub async fn index(
    _auth: Operator,
    State(state): State<AppState>,
) -> ResponseResult<Json<BTreeMap<String, ProviderSummary>>> {
    Ok(Json(summaries(&state).await?))
}

async fn summaries(state: &AppState) -> Result<BTreeMap<String, ProviderSummary>, Error> {
    let providers = state.providers().list().await;
    let observations = state.providers().observations().await?;

    Ok(providers
        .into_iter()
        .map(|(name, definition)| {
            let updated_at = observations.get(&name).and_then(|held| held.updated_at);
            (
                name,
                ProviderSummary {
                    definition,
                    updated_at,
                },
            )
        })
        .collect())
}

pub async fn get(
    _auth: Operator,
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
    _auth: Operator,
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
    _auth: Operator,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let refreshed = state.providers().refresh(&name, state.http()).await?;
    tracing::debug!("Refreshed provider '{}': {}", refreshed.name, refreshed);

    Ok(Json(Refresh::from(refreshed)))
}

/// The nodes a provider holds, as structure rather than as a document.
///
/// The same shape a collection's node view has, scoped to one provider: what
/// its payload parses to after its own two lists, what those lists passed over,
/// and why nothing came out when the payload is a shape this build does not
/// read.
#[derive(Debug, Serialize, Deserialize)]
pub struct Nodes {
    pub name: String,
    /// Current nodes in this provider's payload order, after its filters.
    pub nodes: Vec<NodeView>,
    /// How many nodes this provider's own filter passed over.
    pub passed_over: usize,
    pub updated_at: Option<i64>,
    /// Why the payload contributed no nodes at all, when it is a shape this
    /// build reads none of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<Unreadable>,
}

/// What this provider holds, read into nodes.
pub async fn nodes(
    _auth: Operator,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    Ok(Json(nodes_of(&state, &name).await?))
}

/// Read one provider's payload the way the rest of the instance reads it.
async fn nodes_of(state: &AppState, name: &str) -> Result<Nodes, Error> {
    let provider = state
        .providers()
        .get(name)
        .await
        .ok_or_else(|| Error::ProviderNotFound(name.to_owned()))?;

    // Other providers cannot rename this provider's entries or make its view fail.
    let observation = state.providers().observation(name).await?;
    let index = NodeIndex::from_observations(observation.iter().map(|held| (name, held)));
    let filter = provider.filter()?;
    let nodes: Vec<_> = index
        .entries()
        .iter()
        .filter(|entry| filter.admits(entry.name()))
        .map(NodeView::from)
        .collect();
    let unreadable = observation
        .as_ref()
        .and_then(|held| subscription::parse(held.payload.as_bytes(), name).unreadable);

    Ok(Nodes {
        name: name.to_owned(),
        passed_over: index.len() - nodes.len(),
        nodes,
        updated_at: observation.and_then(|held| held.updated_at),
        unreadable,
    })
}

/// The payload last fetched for a provider, exactly as it arrives.
///
/// It is served as text because a subscription is opaquely shaped from the
/// server's point of view; conversion into nodes is a separate resource, and
/// into a concrete format a separate step.
pub async fn payload(
    _auth: Operator,
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
    _auth: Operator,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.providers().remove(&name).await?;

    Ok(StatusCode::NO_CONTENT.into_response())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::provider::{Inline, SharedFields};

    /// A password that must never reach a response.
    const SENTINEL: &str = "SENTINELPASSWORD";

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-provider-nodes-{}", uuid::Uuid::now_v7()))
    }

    async fn state() -> AppState {
        let root = temp_dir();
        let config = crate::config::ServerConfig {
            listen: "127.0.0.1".parse().unwrap(),
            port: 0,
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            privileged: Default::default(),
        };

        AppState::build(&config).await.unwrap()
    }

    fn link(host: &str, name: &str) -> String {
        format!("trojan://{SENTINEL}@{host}:443#{name}\n")
    }

    fn keywords(keywords: &[&str]) -> Vec<suba_core::Pattern> {
        keywords
            .iter()
            .map(|keyword| suba_core::Pattern::Keyword(keyword.to_string()))
            .collect()
    }

    async fn inline(
        state: &AppState,
        name: &str,
        payload: &str,
        includes: &[&str],
        excludes: &[&str],
    ) {
        let provider = Provider::Inline(Inline {
            shared: SharedFields {
                includes: keywords(includes),
                excludes: keywords(excludes),
                ..SharedFields::default()
            },
            payload: payload.to_string(),
        });

        state
            .providers()
            .upsert(name, provider, state.http())
            .await
            .unwrap();
    }

    /// The names a view reports, in the order it reports them.
    fn names(nodes: &Nodes) -> Vec<&str> {
        nodes.nodes.iter().map(|node| node.name.as_str()).collect()
    }

    #[tokio::test]
    async fn the_nodes_are_what_the_payload_holds() {
        let state = state().await;
        inline(
            &state,
            "airport",
            &format!(
                "{}{}",
                link("a.example.com", "US-01"),
                link("b.example.com", "JP-01")
            ),
            &[],
            &[],
        )
        .await;

        let nodes = nodes_of(&state, "airport").await.unwrap();

        assert_eq!(nodes.name, "airport");
        assert_eq!(names(&nodes), ["US-01", "JP-01"]);
        assert_eq!(nodes.passed_over, 0);
        assert!(nodes.updated_at.is_some());
        assert_eq!(nodes.unreadable, None);
        assert!(
            !serde_json::to_string(&nodes).unwrap().contains(SENTINEL),
            "a node view never carries a credential"
        );
    }

    /// The provider's own two lists apply, and they apply exclusion first.
    #[tokio::test]
    async fn the_providers_lists_decide_which_nodes_it_serves() {
        let state = state().await;
        inline(
            &state,
            "airport",
            &format!(
                "{}{}{}",
                link("a.example.com", "US-01"),
                link("b.example.com", "US-LAX-01"),
                link("c.example.com", "JP-01")
            ),
            &["US"],
            &["LAX"],
        )
        .await;

        let nodes = nodes_of(&state, "airport").await.unwrap();

        assert_eq!(names(&nodes), ["US-01"]);
        assert_eq!(
            nodes.passed_over, 2,
            "one name the exclusion dropped, one the inclusion never admitted"
        );
    }

    #[tokio::test]
    async fn a_replaced_provider_snapshot_returns_only_its_current_nodes() {
        let state = state().await;
        inline(
            &state,
            "airport",
            &format!(
                "{}{}",
                link("a.example.com", "US-01"),
                link("b.example.com", "JP-01")
            ),
            &[],
            &[],
        )
        .await;
        inline(&state, "airport", &link("a.example.com", "US-01"), &[], &[]).await;

        let nodes = nodes_of(&state, "airport").await.unwrap();

        assert_eq!(names(&nodes), ["US-01"]);
        let encoded = serde_json::to_value(&nodes).unwrap();
        assert!(encoded.get("orphans").is_none());
        assert!(encoded["nodes"][0].get("first_seen").is_none());
        assert!(encoded["nodes"][0].get("orphan").is_none());
    }

    #[tokio::test]
    async fn provider_update_time_is_shared_by_summary_and_latest_nodes() {
        let state = state().await;
        inline(
            &state,
            "airport",
            &link("a.example.com", "Current"),
            &[],
            &[],
        )
        .await;
        let nodes = nodes_of(&state, "airport").await.unwrap();
        let listed = summaries(&state).await.unwrap();
        assert!(nodes.updated_at.is_some());
        assert_eq!(listed["airport"].updated_at, nodes.updated_at);
        let wire = serde_json::to_value(&listed["airport"]).unwrap();
        assert_eq!(wire["type"], "inline");
        assert_eq!(wire["updated_at"], nodes.updated_at.unwrap());
        let definition = state.providers().get("airport").await.unwrap();
        assert!(serde_json::to_value(definition)
            .unwrap()
            .get("updated_at")
            .is_none());
    }

    #[tokio::test]
    async fn a_provider_view_does_not_read_another_providers_observation() {
        let state = state().await;
        inline(
            &state,
            "airport",
            &link("a.example.com", "Current"),
            &[],
            &[],
        )
        .await;
        inline(
            &state,
            "other",
            &link("a.example.com", "Other Name"),
            &[],
            &[],
        )
        .await;
        std::fs::write(
            state.data_dir().join("providers/other.json"),
            "invalid JSON",
        )
        .unwrap();

        let nodes = nodes_of(&state, "airport").await.unwrap();
        assert_eq!(names(&nodes), ["Current"]);
        assert_eq!(nodes.nodes[0].sources[0].provider, "airport");
        assert_eq!(nodes.nodes[0].sources[0].name, "Current");
    }

    #[tokio::test]
    async fn a_provider_nobody_defined_is_not_found() {
        let state = state().await;

        assert!(matches!(
            nodes_of(&state, "ghost").await,
            Err(Error::ProviderNotFound(name)) if name == "ghost"
        ));
    }
}
