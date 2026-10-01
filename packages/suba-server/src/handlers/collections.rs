//! The collections of the instance, as HTTP resources.

use std::{collections::BTreeMap, path::Path as StdPath};

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use http::{header, HeaderMap, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use suba_core::format::{Format, RenderIntent};
use suba_core::{Collection, IndexEntry, NodeFilter, NodeIndex, Observation, Source, View};

use crate::{
    dto::{Authenticated, ResponseResult},
    error::Error,
    state::render::Artifact,
    tracing, AppState,
};

/// A node as the API reports it: what it is and who serves it, **never its
/// credentials**.
///
/// A node carries the secrets a client dials with. A caller that wants those
/// asks for the provider's payload, where they are what was asked for; a view
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

/// Which format a caller asks an artifact in.
#[derive(Debug, Default, Deserialize)]
pub struct Choice {
    pub format: Option<String>,
}

impl Choice {
    /// The format asked for by name, then by the client's `User-Agent`, then
    /// base64: a link list in base64 is the shape every client reads.
    pub(crate) fn resolve(&self, headers: &HeaderMap) -> Result<Format, Error> {
        if let Some(name) = self.format.as_deref() {
            return Format::named(name).ok_or(Error::UnknownFormat);
        }

        Ok(headers
            .get(header::USER_AGENT)
            .and_then(|agent| agent.to_str().ok())
            .and_then(Format::for_user_agent)
            .unwrap_or(Format::Base64))
    }
}

/// A delivery token and where it is served.
#[derive(Debug, Serialize)]
pub struct TokenView {
    pub name: String,
    pub token: String,
    /// Where a client asks for the subscription, as this instance is configured
    /// now. The token outlives a change of prefix, this path does not.
    pub path: String,
}

fn token_view(prefix: &str, name: String, token: String) -> TokenView {
    TokenView {
        path: format!("/{prefix}/{token}"),
        name,
        token,
    }
}

/// A collection's delivery tokens, by name.
pub async fn tokens(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    let tokens = state.collections().tokens(&name).await?;
    let prefix = state.settings().subscription_prefix().await?;

    Ok(Json(
        tokens
            .into_iter()
            .map(|(name, token)| token_view(&prefix, name, token))
            .collect::<Vec<_>>(),
    ))
}

/// Give a collection a delivery token under a name.
///
/// Minting a name that exists rotates that token: its URL stops working, which
/// is what a leaked token needs, and the collection's other tokens keep theirs.
pub async fn mint_token(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path((name, label)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    let token = state.collections().mint_token(&name, &label).await?;
    let prefix = state.settings().subscription_prefix().await?;

    // The collection and the token's name are logged, the token never is.
    tracing::debug!("Minted delivery token '{label}' for collection '{name}'");

    Ok((StatusCode::CREATED, Json(token_view(&prefix, label, token))))
}

/// Take one of a collection's delivery tokens out of service.
pub async fn revoke_token(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path((name, label)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    state.collections().revoke_token(&name, &label).await?;
    tracing::debug!("Revoked delivery token '{label}' of collection '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

/// The artifact this collection serves.
///
/// The one path a subscription comes out of: the management route previews it
/// and the delivery route hands it to a client, so the two cannot be two
/// different documents.
///
/// The answer says whether the artifact was already rendered.
pub(crate) async fn artifact_of(
    state: &AppState,
    name: &str,
    format: Format,
) -> Result<(std::sync::Arc<Artifact>, bool), Error> {
    let mut collection = state
        .collections()
        .get(name)
        .await
        .ok_or_else(|| Error::CollectionNotFound(name.to_owned()))?;

    // Tokens do not change the document, so they do not change its address.
    collection.tokens.clear();

    let observations = state.providers().observations().await?;

    let key = address(state, &collection, &observations, format).await?;

    if let Some(artifact) = state.rendered().get(&key) {
        return Ok((artifact, true));
    }

    // The same index the node view is built from, so a preview and a delivery
    // agree about identity down to the node's name.
    let index = NodeIndex::from_observations(
        observations
            .iter()
            .map(|(name, observation)| (name.as_str(), observation)),
    );

    let resolved = collection.resolve(
        &index,
        &provider_filters(state, &collection).await?,
        &collection.filter()?,
        // A delivery carries what is served now: an orphan has no content, so
        // there is nothing to hand anyone.
        View::default(),
    );

    let nodes = resolved.nodes;

    // The direction is asked for explicitly, and today every compiled format
    // writes the client one; a format that grew a server direction would have to
    // say so in its descriptor first.
    let rendered = format.render(&nodes, RenderIntent::Client)?;
    let artifact = std::sync::Arc::new(Artifact {
        body: rendered.body.into(),
        format,
        nodes: nodes.len().saturating_sub(rendered.skipped.len()),
        skipped: rendered.skipped.len(),
        update_hours: update_hours(state, &collection).await,
    });

    state.rendered().put(key, std::sync::Arc::clone(&artifact));

    Ok((artifact, false))
}

/// Everything that can change an artifact's bytes, as one address.
///
/// The collection's own bytes, each definition it names, the hash each payload
/// was fetched at, and the format. A key built by hand out of the fields that
/// «should» matter is the kind that goes stale without anyone noticing; these
/// are the bytes the answer is a function of.
async fn address(
    state: &AppState,
    collection: &Collection,
    observations: &BTreeMap<String, Observation>,
    format: Format,
) -> Result<String, Error> {
    let mut key = String::new();

    key.push_str(format.as_str());
    key.push('\n');
    key.push_str(&encode(collection)?);

    for name in &collection.providers {
        if let Some(provider) = state.providers().get(name).await {
            key.push_str(name);
            key.push_str(&encode(&provider)?);
        }

        if let Some(observation) = observations.get(name) {
            key.push_str(observation.content_hash.as_deref().unwrap_or_default());
        }
    }

    Ok(suba_core::checksum::sha256_hex(key.as_bytes()))
}

/// How often a subscriber should ask again, in whole hours, rounded up.
///
/// The shortest interval among the member providers: asking more often than
/// the fastest one changes gets nothing new, and asking less often misses it.
async fn update_hours(state: &AppState, collection: &Collection) -> Option<u64> {
    let mut shortest: Option<u64> = None;

    for name in &collection.providers {
        let seconds = state
            .providers()
            .get(name)
            .await
            .and_then(|provider| provider.interval())
            .map(|interval| interval.as_secs());

        if let Some(seconds) = seconds {
            shortest = Some(shortest.map_or(seconds, |known| known.min(seconds)));
        }
    }

    shortest.map(|seconds| seconds.div_ceil(3600))
}

/// A document as the instance's codec writes it, for the address above.
fn encode<T: Serialize>(value: &T) -> Result<String, Error> {
    crate::config::codec::encode(value, StdPath::new("render")).map_err(Error::Config)
}

/// Serve what this collection hands to a subscriber, for the operator.
///
/// The body is the document itself; what was left out is reported in headers
/// rather than in the body, which belongs to the client's core.
pub async fn content(
    _auth: Authenticated,
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(choice): Query<Choice>,
    request: HeaderMap,
) -> ResponseResult<impl IntoResponse> {
    let (artifact, _) = artifact_of(&state, &name, choice.resolve(&request)?).await?;

    let mut headers = artifact_headers(&artifact);
    headers.insert("x-suba-nodes", HeaderValue::from(artifact.nodes));
    headers.insert("x-suba-skipped", HeaderValue::from(artifact.skipped));

    Ok((headers, artifact.body.to_string()))
}

/// The headers a subscription client reads, on every artifact.
pub(crate) fn artifact_headers(artifact: &Artifact) -> HeaderMap {
    let mut headers = HeaderMap::new();

    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(artifact.format.media_type()),
    );
    headers.insert(
        "x-suba-format",
        HeaderValue::from_static(artifact.format.as_str()),
    );

    if let Some(hours) = artifact.update_hours {
        headers.insert("profile-update-interval", HeaderValue::from(hours));
    }

    // The URL carries a credential; nothing between here and the client may
    // keep a copy.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    headers
}

/// `Content-Disposition` for saving an artifact under the collection's name.
///
/// RFC 6266: the name percent-encoded, so any collection name is a valid
/// header, and a plain fallback for clients that read only `filename`.
pub(crate) fn attachment(artifact: &Artifact, name: &str) -> Option<HeaderValue> {
    let mut encoded = String::new();
    suba_core::proto::percent::encode_into(name, &mut encoded);

    HeaderValue::from_str(&format!(
        "attachment; filename=\"subscription.{extension}\"; filename*=UTF-8''{encoded}.{extension}",
        extension = artifact.format.extension(),
    ))
    .ok()
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
#[cfg(test)]
mod artifact_tests {
    use super::*;
    use suba_core::Format;

    use crate::{
        config::ServerConfig,
        provider::{Inline, Provider, SharedFields},
    };

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("suba-artifact-{}", uuid::Uuid::now_v7()))
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
        format!("trojan://hunter2@{host}:443#{name}\n")
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

    #[tokio::test]
    async fn the_artifact_is_what_the_payloads_hold() {
        let state = state().await;
        inline(&state, "alpha", &link("alpha.example.com", "US-01")).await;
        collection(&state, "main", &["alpha"]).await;

        let artifact = artifact_of(&state, "main", Format::Links).await.unwrap().0;

        assert_eq!(artifact.nodes, 1);
        assert_eq!(artifact.skipped, 0);
        assert!(
            artifact.body.contains("#US-01"),
            "a link list carries the node: {}",
            artifact.body
        );
    }

    /// The artifact is the shape the request names, and two shapes of one
    /// collection are two artifacts.
    #[cfg(feature = "clash")]
    #[tokio::test]
    async fn the_artifact_is_written_in_the_format_asked_for() {
        let state = state().await;
        inline(&state, "alpha", &link("alpha.example.com", "US-01")).await;
        collection(&state, "main", &["alpha"]).await;

        let clash = artifact_of(&state, "main", Format::Clash).await.unwrap().0;
        let links = artifact_of(&state, "main", Format::Links).await.unwrap().0;

        assert!(
            clash.body.contains("proxies:"),
            "a clash document: {}",
            clash.body
        );
        assert!(!clash.body.contains("#US-01"), "and not a link list");
        assert!(links.body.contains("#US-01"), "{}", links.body);
    }

    /// A second request for the same thing is the artifact rendered the first
    /// time.
    #[tokio::test]
    async fn the_same_request_is_rendered_once() {
        let state = state().await;
        inline(&state, "alpha", &link("alpha.example.com", "US-01")).await;
        collection(&state, "main", &["alpha"]).await;

        let once = artifact_of(&state, "main", Format::Links).await.unwrap().0;
        let twice = artifact_of(&state, "main", Format::Links).await.unwrap().0;

        assert_eq!(once.body, twice.body);
        assert!(std::sync::Arc::ptr_eq(&once, &twice), "the same artifact");
        assert_eq!(
            state.rendered().len(),
            1,
            "and it was rendered once, not twice"
        );
    }

    /// Rendered content is derived, so it stays in memory: two requests cost
    /// memory and no disk at all.
    #[tokio::test]
    async fn rendering_writes_nothing_down() {
        let state = state().await;
        inline(&state, "alpha", &link("alpha.example.com", "US-01")).await;
        collection(&state, "main", &["alpha"]).await;

        let before = std::fs::read_dir(state.data_dir()).map(Iterator::count);
        artifact_of(&state, "main", Format::Links).await.unwrap();
        artifact_of(&state, "main", Format::Links).await.unwrap();
        let after = std::fs::read_dir(state.data_dir()).map(Iterator::count);

        assert_eq!(before.unwrap(), after.unwrap(), "two renders add no files");
    }

    /// The collections a sing-box configuration names contribute their nodes as
    /// tagged outbounds, once each, and a name nothing answers to is an error.
    #[cfg(all(feature = "singbox", feature = "singbox-core"))]
    #[tokio::test]
    async fn chosen_collections_contribute_their_nodes_once() {
        let state = state().await;
        inline(
            &state,
            "alpha",
            &format!(
                "{}{}",
                link("alpha.example.com", "US-01"),
                link("beta.example.com", "JP-01")
            ),
        )
        .await;
        collection(&state, "main", &["alpha"]).await;
        collection(&state, "again", &["alpha"]).await;

        let outbounds = outbounds_of(&state, &["main".to_string(), "again".to_string()])
            .await
            .unwrap();
        let tags: Vec<&str> = outbounds
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap())
            .collect();
        assert_eq!(tags, ["US-01", "JP-01"]);

        assert!(matches!(
            outbounds_of(&state, &["missing".to_string()]).await,
            Err(Error::CollectionNotFound(name)) if name == "missing"
        ));
    }
}

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
    let index = NodeIndex::from_observations(
        observations
            .iter()
            .map(|(name, observation)| (name.as_str(), observation)),
    );

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

/// The outbounds the named collections contribute to a sing-box configuration,
/// in the order the collections are named.
///
/// A collection that does not exist is an error naming it: an empty
/// contribution would look like a collection that serves nothing.
#[cfg(all(feature = "singbox", feature = "singbox-core"))]
pub(crate) async fn outbounds_of(
    state: &AppState,
    names: &[String],
) -> Result<Vec<serde_json::Value>, Error> {
    let observations = state.providers().observations().await?;
    let index = NodeIndex::from_observations(
        observations
            .iter()
            .map(|(name, observation)| (name.as_str(), observation)),
    );

    let mut nodes: Vec<&IndexEntry> = Vec::new();
    for name in names {
        let collection = state
            .collections()
            .get(name)
            .await
            .ok_or_else(|| Error::CollectionNotFound(name.to_owned()))?;
        let resolved = collection.resolve(
            &index,
            &provider_filters(state, &collection).await?,
            &collection.filter()?,
            View::default(),
        );

        // A node two collections share is one outbound, not a duplicate tag.
        for entry in resolved.nodes {
            if !nodes.iter().any(|held| held.id == entry.id) {
                nodes.push(entry);
            }
        }
    }

    Ok(suba_core::outbounds(&nodes).0)
}

/// A build that cannot render sing-box documents contributes no outbounds: the
/// core runs what the operator wrote.
#[cfg(all(feature = "singbox-core", not(feature = "singbox")))]
pub(crate) async fn outbounds_of(
    _state: &AppState,
    _names: &[String],
) -> Result<Vec<serde_json::Value>, Error> {
    Ok(Vec::new())
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
            excludes: vec![suba_core::Pattern::Name("JP-01".to_string())],
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
                excludes: vec![suba_core::Pattern::Name("JP-01".to_string())],
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
