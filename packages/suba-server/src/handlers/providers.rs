use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use suba_core::subscription::{self, DeclaredFormat, Unreadable};
use suba_core::RefreshStatus;
use suba_core::{Collection, NodeIndex, View};

use crate::{
    dto::{Authenticated, ErrorResponse, ResponseResult},
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

/// The nodes a provider holds, as structure rather than as a document.
///
/// The same shape a collection's node view has, scoped to one provider: what
/// its payload parses to after its own two lists, what those lists passed over,
/// and why nothing came out when the declared shape is one this build does not
/// read.
#[derive(Debug, Serialize, Deserialize)]
pub struct Nodes {
    pub name: String,
    /// The nodes, oldest first, orphans included and marked.
    pub nodes: Vec<NodeView>,
    /// How many nodes this provider's own filter passed over.
    pub passed_over: usize,
    /// How many nodes it has served and no longer does.
    pub orphans: usize,
    /// Why the payload contributed no nodes at all, when its declared shape is
    /// one this build reads none of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<Unreadable>,
}

/// What this provider holds, read into nodes.
pub async fn nodes(
    _auth: Authenticated,
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

    let observations = state.providers().observations().await?;
    let declared = state.providers().formats().await;

    // The same index the collections view is built from, for the same reason: a
    // node's identity, the name it goes by and when it was first seen are facts
    // about the instance, and a view built out of one provider's bytes alone
    // would disagree with the others about the same node.
    let index = NodeIndex::from_observations(observations.iter().map(|(name, observation)| {
        (
            name.as_str(),
            declared.get(name).copied().unwrap_or(DeclaredFormat::Links),
            observation,
        )
    }));

    // One member, and the only filter that applies is this provider's own: a
    // collection's filter belongs to the collection.
    let member = Collection {
        providers: vec![name.to_owned()],
        ..Collection::default()
    };
    let resolved = member.resolve(
        &index,
        &BTreeMap::from([(name.to_owned(), provider.filter()?)]),
        &member.filter()?,
        // The structure is where an orphan is worth seeing: it has no content,
        // so nothing can be served from it, but it is the evidence that this
        // provider used to serve it.
        View { orphans: true },
    );

    let unreadable = observations.get(name).and_then(|observation| {
        let declared = declared.get(name).copied().unwrap_or(DeclaredFormat::Links);

        subscription::parse(
            observation.payload.as_bytes(),
            name,
            observation.checked_at.unwrap_or_default(),
            declared,
        )
        .unreadable
    });

    Ok(Nodes {
        name: name.to_owned(),
        nodes: resolved
            .nodes
            .iter()
            .map(|entry| NodeView::from(*entry))
            .collect(),
        passed_over: resolved.passed_over,
        orphans: resolved.orphans,
        unreadable,
    })
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
        };

        AppState::build(&config).await.unwrap()
    }

    fn link(host: &str, name: &str) -> String {
        format!("trojan://{SENTINEL}@{host}:443#{name}\n")
    }

    async fn inline(
        state: &AppState,
        name: &str,
        payload: &str,
        include: &[&str],
        exclude: &[&str],
    ) {
        let provider = Provider::Inline(Inline {
            shared: SharedFields {
                include: include.iter().map(|pattern| pattern.to_string()).collect(),
                exclude: exclude.iter().map(|pattern| pattern.to_string()).collect(),
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
        nodes
            .nodes
            .iter()
            .map(|node| node.name.as_deref().unwrap_or("<orphan>"))
            .collect()
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
        assert_eq!(nodes.orphans, 0);
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
            &["keyword:US"],
            &["keyword:LAX"],
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
    async fn a_node_it_stopped_serving_is_counted_and_marked() {
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

        assert_eq!(nodes.orphans, 1);
        assert_eq!(names(&nodes), ["US-01", "<orphan>"]);
        assert!(nodes.nodes[1].orphan, "the one nobody serves is marked");
    }

    #[tokio::test]
    async fn a_provider_nobody_defined_is_not_found() {
        let state = state().await;

        assert!(matches!(
            nodes_of(&state, "ghost").await,
            Err(Error::ProviderNotFound(name)) if name == "ghost"
        ));
    }

    #[cfg(feature = "clash")]
    #[tokio::test]
    async fn a_shape_this_build_cannot_read_says_why_the_view_is_empty() {
        let state = state().await;
        let provider = Provider::Inline(Inline {
            shared: SharedFields {
                format: DeclaredFormat::Clash,
                ..SharedFields::default()
            },
            payload: "proxies:\n  - name: node\n".to_string(),
        });

        state
            .providers()
            .upsert("airport", provider, state.http())
            .await
            .unwrap();

        let nodes = nodes_of(&state, "airport").await.unwrap();

        assert!(nodes.nodes.is_empty());
        assert_eq!(nodes.unreadable, Some(Unreadable::Clash));
    }
}
