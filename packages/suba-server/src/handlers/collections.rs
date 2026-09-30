//! The collections of the instance, as HTTP resources.

use std::collections::BTreeMap;

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use suba_core::{Collection, IndexEntry, NodeFilter, NodeIndex, Source, View};

use crate::{
    dto::{Authenticated, ResponseResult},
    error::Error,
    tracing, AppState,
};

/// A node as the API reports it: what it is and who serves it, **never its
/// credentials**.
///
/// A node carries the secrets a client dials with. A caller that wants those
/// asks for the provider's content, where they are what was asked for; a view
/// that exists to show what a collection contains must not be able to leak
/// them.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeView {
    /// The node's identity, which is what it is: two providers serving it, or
    /// two names for it, are one entry.
    pub id: String,
    /// The name it is served under, when someone serves it.
    pub name: Option<String>,
    /// The protocol, by the name the model uses for it.
    pub protocol: Option<String>,
    /// Where a client dials, when someone serves it.
    pub endpoint: Option<String>,
    /// When this instance first saw it, from any provider.
    pub first_seen: i64,
    /// Whether nothing serves it any more.
    pub orphan: bool,
    /// Everyone that has served it, whoever was first.
    pub sources: Vec<SourceView>,
}

/// One provider's part in a node.
#[derive(Debug, Serialize, Deserialize)]
pub struct SourceView {
    /// The provider that served it.
    pub provider: String,
    /// What that provider called it, when it still serves it.
    pub name: Option<String>,
    /// When that provider first served it.
    pub first_seen: i64,
    /// Whether that provider's current payload still lists it.
    pub serving: bool,
}

/// What a collection resolves to, for a caller that wants the structure rather
/// than a document to subscribe to.
///
/// What was left out is reported rather than hidden: a collection that serves
/// fewer nodes than the operator expects has to say so, whether the reason is a
/// filter or a provider that no longer exists.
#[derive(Debug, Serialize, Deserialize)]
pub struct Nodes {
    pub name: String,
    /// The nodes, oldest first, orphans included and marked.
    pub nodes: Vec<NodeView>,
    /// How many nodes a filter passed over.
    pub passed_over: usize,
    /// How many nodes nothing serves any more.
    pub orphans: usize,
    /// Providers this collection names that the instance does not have.
    pub unresolved: Vec<String>,
}

impl From<&IndexEntry> for NodeView {
    fn from(entry: &IndexEntry) -> Self {
        let node = entry.node.as_ref();

        Self {
            id: entry.id.to_string(),
            name: entry.name().map(str::to_owned),
            protocol: node.map(|node| node.protocol.kind().as_str().to_owned()),
            endpoint: node.map(|node| node.endpoint.to_string()),
            first_seen: entry.first_seen,
            orphan: entry.is_orphan(),
            sources: entry.sources.iter().map(SourceView::from).collect(),
        }
    }
}

impl From<&Source> for SourceView {
    fn from(source: &Source) -> Self {
        Self {
            provider: source.provider.clone(),
            name: source.name.clone(),
            first_seen: source.first_seen,
            serving: source.serving,
        }
    }
}

pub async fn index(_auth: Authenticated, State(state): State<AppState>) -> impl IntoResponse {
    let collections = state.collections().list().await;

    Json(collections)
}

pub async fn get(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let collection = state
        .collections()
        .get(&name)
        .await
        .ok_or(Error::CollectionNotFound(name))?;

    Ok(Json(collection))
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

/// The nodes this collection resolves to.
///
/// The structure, not a document a client can subscribe to: what each node is,
/// who serves it, and what was left out. Serving the document is the delivery
/// path's job, and this is the same resolution underneath it.
pub async fn nodes(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    Ok(Json(nodes_of(&state, &name).await?))
}

/// Resolve a collection to the view the API reports.
async fn nodes_of(state: &AppState, name: &str) -> Result<Nodes, Error> {
    let collection = state
        .collections()
        .get(name)
        .await
        .ok_or_else(|| Error::CollectionNotFound(name.to_owned()))?;

    // The index is built from **every** provider, not only the ones this
    // collection names: a node's spelling and its history are facts about the
    // instance, and a view assembled from a subset would disagree with the
    // others about the same node.
    let observations = state.providers().observations().await?;
    let declared = state.providers().formats().await;
    let index = NodeIndex::from_observations(observations.iter().map(|(name, observation)| {
        // A provider nobody defines any more has no declaration to read by:
        // it contributes nothing either way, and links is what a body with
        // no definition was read as when it was fetched.
        (
            name.as_str(),
            declared
                .get(name)
                .copied()
                .unwrap_or(suba_core::subscription::DeclaredFormat::Links),
            observation,
        )
    }));

    let filter = collection.filter()?;
    let resolved = collection.resolve(
        &index,
        &provider_filters(state, &collection).await?,
        &filter,
        // The structure is where an orphan is worth seeing: it has no content,
        // so nothing can be served from it, but it is the evidence that a
        // provider used to serve it.
        View { orphans: true },
    );

    Ok(Nodes {
        name: name.to_owned(),
        nodes: resolved
            .nodes
            .iter()
            .map(|entry| NodeView::from(*entry))
            .collect(),
        passed_over: resolved.passed_over,
        orphans: resolved.orphans,
        unresolved: resolved.unresolved,
    })
}

/// The compiled filter of every provider the collection names.
///
/// Compiled per request rather than cached. A collection names a handful of
/// providers with a handful of patterns each, and a cache would be a second copy
/// of the definitions to keep in step with every edit; if this ever shows up in
/// a profile, the answer is a cache keyed by the definition, not a filter that
/// is quietly not applied.
async fn provider_filters(
    state: &AppState,
    collection: &Collection,
) -> Result<BTreeMap<String, NodeFilter>, Error> {
    let mut filters = BTreeMap::new();

    for name in &collection.providers {
        if filters.contains_key(name) {
            continue;
        }

        if let Some(provider) = state.providers().get(name).await {
            filters.insert(name.clone(), provider.filter()?);
        }
    }

    Ok(filters)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        config::ServerConfig,
        provider::{Inline, Provider, SharedFields},
    };
    use suba_core::proto::parse_link;

    /// A password that must never reach a response.
    const SENTINEL: &str = "SENTINELPASSWORD";

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-node-view-{}", uuid::Uuid::now_v7()))
    }

    async fn state() -> AppState {
        let root = temp_dir();
        let config = ServerConfig {
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

    async fn inline(state: &AppState, name: &str, payload: &str) {
        let provider = Provider::Inline(Inline {
            shared: SharedFields::default(),
            payload: payload.to_string(),
        });

        state
            .providers()
            .upsert(name, provider, state.http())
            .await
            .unwrap();
    }

    async fn collection(state: &AppState, name: &str, providers: &[&str]) {
        let collection = Collection {
            providers: providers.iter().map(|name| name.to_string()).collect(),
            ..Collection::default()
        };

        state.collections().insert(name, collection).await.unwrap();
    }

    fn named<'a>(nodes: &'a [NodeView], name: &str) -> &'a NodeView {
        nodes
            .iter()
            .find(|node| node.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("no node named {name}"))
    }

    /// Nodes that arrive in the same second are ordered by identity, not by
    /// name, so tests look nodes up by name.
    #[tokio::test]
    async fn the_view_reports_the_nodes_a_collection_serves() {
        let state = state().await;
        let shared = link("alpha.example.com", "Shared");
        inline(&state, "alpha", &shared).await;
        inline(
            &state,
            "beta",
            &format!("{}{}", link("beta.example.com", "JP-01"), shared),
        )
        .await;
        collection(&state, "main", &["alpha", "beta"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();

        assert_eq!(nodes.name, "main");
        assert_eq!(nodes.nodes.len(), 2, "the shared node is one node");
        assert_eq!(nodes.passed_over, 0);
        assert_eq!(nodes.orphans, 0);
        assert!(nodes.unresolved.is_empty());

        let shared = named(&nodes.nodes, "Shared");
        assert_eq!(shared.protocol.as_deref(), Some("trojan"));
        assert_eq!(shared.endpoint.as_deref(), Some("alpha.example.com:443"));
        assert!(!shared.orphan);
        assert_eq!(
            shared
                .sources
                .iter()
                .map(|source| source.provider.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(
            shared.sources[1].name.as_deref(),
            Some("Shared"),
            "each provider's spelling is its own"
        );
        assert!(shared.sources.iter().all(|source| source.serving));
    }

    /// The view is a structure, and a node's credentials are not part of it.
    #[tokio::test]
    async fn the_view_never_carries_a_node_credential() {
        let state = state().await;
        inline(&state, "alpha", &link("alpha.example.com", "US-01")).await;
        collection(&state, "main", &["alpha"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();
        let printed = serde_json::to_string(&nodes).unwrap();

        assert!(
            !printed.contains(SENTINEL),
            "the node's password reached the response: {printed}"
        );
        assert!(printed.contains("US-01"), "but the node is there");
    }

    #[tokio::test]
    async fn a_filter_passes_over_a_node_and_the_view_says_so() {
        let state = state().await;
        inline(
            &state,
            "alpha",
            &format!(
                "{}{}",
                link("alpha.example.com", "US-01"),
                link("delta.example.com", "JP-01")
            ),
        )
        .await;
        inline(&state, "beta", &link("beta.example.com", "SG-01")).await;

        let filtered = Collection {
            providers: vec!["alpha".to_string()],
            exclude: vec!["JP-01".to_string()],
            ..Collection::default()
        };
        state.collections().insert("main", filtered).await.unwrap();
        collection(&state, "other", &["alpha", "beta"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();
        assert_eq!(nodes.nodes.len(), 1);
        assert_eq!(nodes.nodes[0].name.as_deref(), Some("US-01"));
        assert_eq!(nodes.passed_over, 1);

        // The same nodes, without the collection's filter: all three are served.
        let nodes = nodes_of(&state, "other").await.unwrap();
        assert_eq!(nodes.nodes.len(), 3);
        assert_eq!(nodes.passed_over, 0);
    }

    /// A provider's own filter applies too, and only to its own nodes.
    #[tokio::test]
    async fn a_providers_filter_applies_to_what_that_provider_serves() {
        let state = state().await;
        let provider = Provider::Inline(Inline {
            shared: SharedFields {
                exclude: vec!["JP-01".to_string()],
                ..SharedFields::default()
            },
            payload: format!(
                "{}{}",
                link("alpha.example.com", "US-01"),
                link("delta.example.com", "JP-01")
            ),
        });
        state
            .providers()
            .upsert("alpha", provider, state.http())
            .await
            .unwrap();

        // Another provider serves a node of its own that happens to share the
        // excluded name.
        inline(&state, "beta", &link("beta.example.com", "JP-01")).await;
        collection(&state, "main", &["alpha", "beta"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();

        let mut names: Vec<&str> = nodes
            .nodes
            .iter()
            .filter_map(|node| node.name.as_deref())
            .collect();
        names.sort_unstable();

        assert_eq!(
            names,
            ["JP-01", "US-01"],
            "alpha's exclude took away alpha's node only"
        );
        assert_eq!(nodes.passed_over, 1);
    }

    /// A node a provider stopped serving is still shown, marked.
    #[tokio::test]
    async fn an_orphan_is_shown_and_marked() {
        let state = state().await;
        let kept = link("alpha.example.com", "Kept");
        let gone = link("delta.example.com", "Gone");

        inline(&state, "alpha", &format!("{kept}{gone}")).await;
        inline(&state, "alpha", &kept).await;
        collection(&state, "main", &["alpha"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();

        assert_eq!(nodes.orphans, 1);
        assert_eq!(nodes.nodes.len(), 2, "the orphan is in the view");

        let orphan = nodes
            .nodes
            .iter()
            .find(|node| node.orphan)
            .expect("an orphan");
        assert_eq!(orphan.name, None);
        assert_eq!(orphan.protocol, None);
        assert_eq!(orphan.endpoint, None);
        assert!(!orphan.sources[0].serving);
        assert_eq!(
            orphan.sources[0].provider, "alpha",
            "who used to serve it is still known"
        );
    }

    #[tokio::test]
    async fn a_provider_that_does_not_exist_is_reported() {
        let state = state().await;
        inline(&state, "alpha", &link("alpha.example.com", "US-01")).await;
        collection(&state, "main", &["alpha", "ghost"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();

        assert_eq!(nodes.nodes.len(), 1);
        assert_eq!(nodes.unresolved, ["ghost"]);
    }

    #[tokio::test]
    async fn a_collection_that_does_not_exist_is_not_a_view() {
        let state = state().await;

        assert!(matches!(
            nodes_of(&state, "ghost").await,
            Err(Error::CollectionNotFound(name)) if name == "ghost"
        ));
    }

    /// The id is the identity, not the link it was parsed from.
    #[tokio::test]
    async fn a_node_id_is_the_identity_and_not_the_link() {
        let state = state().await;
        let one = link("alpha.example.com", "US-01");
        inline(&state, "alpha", &one).await;
        collection(&state, "main", &["alpha"]).await;

        let nodes = nodes_of(&state, "main").await.unwrap();

        assert_eq!(
            nodes.nodes[0].id,
            parse_link(&one).unwrap().id().to_string()
        );
        assert!(!nodes.nodes[0].id.contains(SENTINEL));
    }
}
