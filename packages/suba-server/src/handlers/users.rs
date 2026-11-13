//! Proxy users and the addresses clients dial, as resources of the module.
//!
//! A user's credentials never leave the server except as what a client needs:
//! a share link or a sing-box outbound per inbound, and the subscription its
//! links hand out. The secret they derive from is never answered with.

use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use suba_core::proto::Host;
use suba_core::target::{RenderIntent, Target};
use suba_core::{IndexEntry, NodeIndex, Source};

use crate::{
    dto::{Operator, ResponseResult},
    error::Error,
    handlers::collections::{
        artifact_headers, provider_filters, token_view, update_hours, TargetChoice, TokenView,
    },
    state::access::{Access, Endpoint, Entry, GrantMode},
    state::render::Artifact,
    state::singbox::{
        managed::{self, Export, InboundUsers, Placement, Serving, State as Applied},
        SingboxStore,
    },
    tracing, AppState,
};

/// What a form says about a user: the rest is the server's to keep.
#[derive(Debug, Deserialize)]
pub struct UserBody {
    #[serde(default)]
    pub inbounds: Vec<Entry>,
    #[serde(default)]
    pub collections: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub name: String,
    /// The inbounds this user may use, in the order they were chosen.
    pub inbounds: Vec<Entry>,
    pub collections: Vec<String>,
    /// Named, and not there: stored anyway, like a collection's providers.
    pub missing_collections: Vec<String>,
    pub links: Vec<TokenView>,
    /// Every inbound it may use, with the client that reaches it.
    pub grants: Vec<GrantView>,
}

#[derive(Debug, Serialize)]
pub struct GrantView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    /// Absent for an entry of this instance; the exporter is the reader.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<uuid::Uuid>,
    pub config: String,
    pub inbound: String,
    pub mode: GrantMode,
    /// Absent when the entry cannot use its selected access mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Applied>,
    #[serde(flatten)]
    pub export: Export,
}

/// One inbound's client endpoint and supported binding modes.
#[derive(Debug, Serialize)]
pub struct EndpointView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    pub config: String,
    pub inbound: String,
    pub modes: Vec<GrantMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_warning: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_refused: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_warning: Option<&'static str>,
    /// The stored override, when the operator set one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inner_inbound: Option<String>,
    /// Why this inbound has no binding mode, when it has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

/// Every address override, and the instance default they fall back to.
#[derive(Debug, Serialize)]
pub struct EndpointsView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    pub entries: Vec<EndpointView>,
}

/// Omitted endpoint fields keep stored values; explicit null clears them.
#[derive(Debug, Default, Deserialize)]
pub struct EndpointBody {
    #[serde(default, deserialize_with = "keep_or_clear")]
    pub address: Option<Option<String>>,
    #[serde(default, deserialize_with = "keep_or_clear")]
    pub port: Option<Option<u16>>,
    #[serde(default, deserialize_with = "keep_or_clear")]
    pub inner_inbound: Option<Option<String>>,
}

/// Tell an omitted field from an explicit `null`.
fn keep_or_clear<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Every user of every inbound of one configuration, for its editor.
#[derive(Debug, Serialize)]
pub struct ConfigUsers {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_host: Option<String>,
    pub inbounds: Vec<InboundUsers>,
}

/// The public host, or the reason every export points nowhere.
async fn public_host(state: &AppState) -> Result<Host, &'static str> {
    if state.target_host().is_some() {
        return Err("endpoint.address: an Agent requires an explicit public address");
    }
    match state.settings().public_host().await {
        Ok(Some(host)) => Ok(host),
        Ok(None) => Err("not set in config.toml"),
        Err(_) => Err("not a domain name or an IP address"),
    }
}

/// How `config` stands against the core: the product it runs, if it runs it.
fn serving<'a>(config: &str, in_use: &str, product: Option<&'a serde_json::Value>) -> Serving<'a> {
    match (config == in_use, product) {
        (true, Some(product)) => Serving::Running(product),
        (in_use, _) => Serving::Not { in_use },
    }
}

/// The users of every inbound of one configuration.
pub async fn exports(
    State(state): State<AppState>,
    _auth: Operator,
    Path(name): Path<String>,
) -> ResponseResult<Json<ConfigUsers>> {
    let access = state.access_snapshot().await;
    let host = public_host(&state).await;
    let store = state.singbox();
    let target = state.target_host();
    let remote = if let Some(id) = state.target_host() {
        let node = state.peers().host(id).await?;
        Some(agent_runtime(&state, &state, &node).await)
    } else {
        None
    };

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<ConfigUsers, Error> {
            let document = store.config_document(&name)?.value;
            let in_use = store.config()?;
            let product = store.product();

            let mut inbounds = managed::exports(
                &document,
                &name,
                &access,
                host.as_ref().map_err(|reason| *reason),
                &serving(&name, &in_use, product.as_ref()),
            );
            if let Some(runtime) = remote {
                for inbound in &mut inbounds {
                    for user in &mut inbound.managed {
                        user.state = agent_grant_state(&in_use, &name, runtime);
                    }
                }
            }
            Ok(ConfigUsers {
                host: target,
                public_host: host.as_ref().ok().map(ToString::to_string),
                inbounds,
            })
        })
        .await??,
    ))
}

/// Every user, with the inbounds it may use and its links.
pub async fn index(
    State(state): State<AppState>,
    _auth: Operator,
) -> ResponseResult<Json<Vec<UserView>>> {
    let access = state.access_snapshot().await;
    let host = public_host(&state).await;
    let prefix = state.settings().subscription_prefix().await?;
    let collections: BTreeSet<String> = state.collections().list().await.into_keys().collect();
    let mut local = access.clone();
    for user in local.users.values_mut() {
        user.inbounds.retain(|entry| entry.host.is_none());
    }
    let store = state.singbox();
    let local_prefix = prefix.clone();
    let local_collections = collections.clone();
    let mut result = tokio::task::spawn_blocking(move || {
        views(&store, &local, &host, &local_prefix, &local_collections)
    })
    .await??;
    for view in &mut result {
        view.inbounds = access.users[&view.name].inbounds.clone();
    }
    for node in state.peers().hosts().await {
        if node.mode != crate::state::peers::Mode::Edge {
            continue;
        }
        let scoped = state.for_agent(node.id).await?;
        let projected = scoped.access_snapshot().await;
        if projected.grants().is_empty() {
            continue;
        }
        let runtime = agent_runtime(&state, &scoped, &node).await;
        let store = scoped.singbox();
        let host = public_host(&scoped).await;
        let prefix = prefix.clone();
        let collections = collections.clone();
        let (remote, selected) = tokio::task::spawn_blocking(move || -> Result<_, Error> {
            Ok((
                views(&store, &projected, &host, &prefix, &collections)?,
                store.config()?,
            ))
        })
        .await??;
        for view in remote {
            if let Some(target) = result.iter_mut().find(|user| user.name == view.name) {
                for mut grant in view.grants {
                    grant.host = Some(node.id);
                    grant.host_name = Some(node.name.clone());
                    if grant.state.is_some() {
                        grant.state = Some(agent_grant_state(&selected, &grant.config, runtime));
                    }
                    target.grants.push(grant);
                }
            }
        }
    }
    for view in &mut result {
        for entry in &view.inbounds {
            if entry.host.is_some()
                && !view.grants.iter().any(|grant| {
                    grant.host == entry.host
                        && grant.config == entry.config
                        && grant.inbound == entry.inbound
                })
            {
                view.grants.push(GrantView {
                    host_name: None,
                    host: entry.host,
                    config: entry.config.clone(),
                    inbound: entry.inbound.clone(),
                    mode: entry.mode,
                    state: None,
                    export: Export {
                        reason: Some("host: the Agent is not configured".to_string()),
                        ..Export::default()
                    },
                });
            }
        }
    }
    Ok(Json(result))
}

async fn agent_runtime(
    state: &AppState,
    scoped: &AppState,
    host: &crate::state::peers::Host,
) -> Option<(bool, bool)> {
    let response = crate::handlers::peers::call(
        state,
        host,
        "GET".into(),
        "/cores/sing-box".into(),
        None,
        None,
    )
    .await
    .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let bytes = axum::body::to_bytes(response.into_body(), crate::state::peers::REPLY_LIMIT)
        .await
        .ok()?;
    let runtime: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let expected = crate::handlers::agents::deployment(scoped)
        .await
        .ok()
        .and_then(|snapshot| snapshot.id().ok());
    Some((
        runtime["running"].as_bool()?,
        expected
            .as_deref()
            .is_some_and(|expected| Some(expected) == runtime["applied"].as_str()),
    ))
}

fn agent_grant_state(selected: &str, config: &str, runtime: Option<(bool, bool)>) -> Applied {
    let Some((running, applied)) = runtime else {
        return Applied::Unknown;
    };
    if selected != config {
        Applied::Unused
    } else if !running {
        Applied::Stopped
    } else if applied {
        Applied::Applied
    } else {
        Applied::Pending
    }
}

fn views(
    store: &SingboxStore,
    access: &Access,
    host: &Result<Host, &'static str>,
    prefix: &str,
    collections: &BTreeSet<String>,
) -> Result<Vec<UserView>, Error> {
    let in_use = store.config()?;
    let product = store.product();
    let mut configs: BTreeMap<String, Vec<InboundUsers>> = BTreeMap::new();

    let mut views = Vec::new();
    for (name, user) in &access.users {
        let mut grants = Vec::new();
        for grant in access.grants_of(name, user) {
            let config = &grant.entry.config;
            if !configs.contains_key(config) {
                let document = store.config_document(config)?.value;
                let inbounds = managed::exports(
                    &document,
                    config,
                    access,
                    host.as_ref().map_err(|reason| *reason),
                    &serving(config, &in_use, product.as_ref()),
                );
                configs.insert(config.clone(), inbounds);
            }
            grants.push(grant_view(&configs[config], grant.entry, name));
        }

        views.push(UserView {
            name: name.clone(),
            missing_collections: user
                .collections
                .iter()
                .filter(|collection| !collections.contains(*collection))
                .cloned()
                .collect(),
            inbounds: user.inbounds.clone(),
            collections: user.collections.clone(),
            links: user
                .tokens
                .iter()
                .map(|(label, token)| token_view(prefix, label.clone(), token.clone()))
                .collect(),
            grants,
        });
    }

    Ok(views)
}

fn grant_view(inbounds: &[InboundUsers], entry: Entry, user: &str) -> GrantView {
    let refused = |reason: String| GrantView {
        host_name: None,
        host: entry.host,
        config: entry.config.clone(),
        inbound: entry.inbound.clone(),
        mode: entry.mode,
        state: None,
        export: Export {
            reason: Some(reason),
            ..Export::default()
        },
    };

    let Some(inbound) = inbounds
        .iter()
        .find(|inbound| inbound.tag.as_deref() == Some(entry.inbound.as_str()))
    else {
        return refused("inbound: no inbound has this tag".to_string());
    };
    let (state, export) = match entry.mode {
        GrantMode::Managed => {
            if let Some(reason) = inbound.refused {
                return refused(format!("inbound: {reason}"));
            }
            let Some(managed) = inbound.managed.iter().find(|held| held.user == user) else {
                return refused("inbound: the user is not in it".to_string());
            };
            (managed.state, managed.export.clone())
        }
        GrantMode::Shared => {
            if let Some(reason) = inbound.shared_refused {
                return refused(format!("inbound: {reason}"));
            }
            let Some(shared) = inbound.shared.iter().find(|held| held.user == user) else {
                return refused("inbound: the user is not bound to it".to_string());
            };
            (shared.state, shared.export.clone())
        }
    };

    GrantView {
        host_name: None,
        state: Some(state),
        export,
        host: entry.host,
        config: entry.config,
        inbound: entry.inbound,
        mode: entry.mode,
    }
}

/// Store a user's inbounds and collections; a new user gets its secret here.
pub async fn put(
    State(state): State<AppState>,
    _auth: Operator,
    Path(name): Path<String>,
    Json(body): Json<UserBody>,
) -> ResponseResult<impl IntoResponse> {
    for entry in &body.inbounds {
        if let Some(id) = entry.host {
            let host = state.peers().host(id).await?;
            if host.mode != crate::state::peers::Mode::Edge {
                return Err(Error::Document(
                    "inbounds.host: expected an Edge Agent".to_string(),
                ));
            }
            let scoped = state.for_agent(id).await?;
            let mut local = Entry::local(&entry.config, &entry.inbound);
            local.mode = entry.mode;
            if let Some(reason) = placement(&scoped, &local).await?.reason() {
                return Err(Error::Document(format!("inbounds.inbound: {reason}")));
            }
        } else if entry.mode == GrantMode::Shared {
            if let Some(reason) = placement(&state, entry).await?.reason() {
                return Err(Error::Document(format!("inbounds.inbound: {reason}")));
            }
        }
    }
    state
        .access()
        .put_user(&name, body.inbounds, body.collections)
        .await?;
    tracing::debug!("Stored user '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(state): State<AppState>,
    _auth: Operator,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.access().remove_user(&name).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Rotate a user's managed credentials; shared inbound secrets are untouched.
pub async fn renew(
    State(state): State<AppState>,
    _auth: Operator,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.access().renew_secret(&name).await?;
    tracing::info!("Replaced the credentials of user '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

pub async fn mint_token(
    State(state): State<AppState>,
    _auth: Operator,
    Path((name, label)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    let token = state.access().mint_token(&name, &label).await?;
    let prefix = state.settings().subscription_prefix().await?;
    tracing::debug!("Minted subscription link '{label}' for user '{name}'");

    Ok((StatusCode::CREATED, Json(token_view(&prefix, label, token))))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    _auth: Operator,
    Path((name, label)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    state.access().revoke_token(&name, &label).await?;
    tracing::debug!("Revoked subscription link '{label}' of user '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

/// What a user's links hand out, for the operator.
pub async fn content(
    State(state): State<AppState>,
    _auth: Operator,
    Path(name): Path<String>,
    Query(choice): Query<TargetChoice>,
    request: HeaderMap,
) -> ResponseResult<impl IntoResponse> {
    let artifact = user_artifact(&state, &name, choice.resolve(&request)?).await?;

    let mut headers = artifact_headers(&artifact);
    headers.insert("x-suba-nodes", HeaderValue::from(artifact.nodes));
    headers.insert("x-suba-skipped", HeaderValue::from(artifact.skipped));

    Ok((headers, artifact.body.to_string()))
}

/// A user's subscription: exportable managed nodes from the selected core
/// configurations, then collection nodes. Bindings without a client model count as skipped.
///
/// Not memoised: it holds credentials derived on the way, and the address of
/// the bytes would have to include the user's secret to be one.
pub(crate) async fn user_artifact(
    state: &AppState,
    name: &str,
    target: Target,
) -> Result<Artifact, Error> {
    let access = state.access_snapshot().await;
    let user = access
        .users
        .get(name)
        .cloned()
        .ok_or_else(|| Error::UserNotFound(name.to_owned()))?;
    let host = public_host(state).await;

    let store = state.singbox();
    let owner = name.to_owned();
    let (config, own) = tokio::task::spawn_blocking(move || -> Result<_, Error> {
        let config = store.config()?;
        let document = store.config_document(&config)?.value;
        let nodes = managed::nodes(
            &document,
            &config,
            &access,
            &owner,
            host.as_ref().map_err(|reason| *reason),
        );
        Ok((config, nodes))
    })
    .await??;

    let mut unexported = 0;
    let mut entries: Vec<IndexEntry> = Vec::new();
    for (position, node) in own.into_iter().enumerate() {
        match node {
            Ok(node) => entries.push(IndexEntry {
                id: node.id(),
                source: Source {
                    provider: config.clone(),
                    name: node.name.to_string(),
                    position,
                },
                node,
            }),
            Err(_) => unexported += 1,
        }
    }

    let hosts = state.peers().hosts().await;
    unexported += user
        .inbounds
        .iter()
        .filter(|entry| {
            entry.host.is_some_and(|id| {
                !hosts
                    .iter()
                    .any(|host| host.id == id && host.mode == crate::state::peers::Mode::Edge)
            })
        })
        .count();
    for node in hosts {
        if node.mode != crate::state::peers::Mode::Edge {
            continue;
        }
        let scoped = state.for_agent(node.id).await?;
        let projected = scoped.access_snapshot().await;
        let store = scoped.singbox();
        let owner = name.to_owned();
        let exported = tokio::task::spawn_blocking(move || -> Result<_, Error> {
            let selected = store.config()?;
            let document = store.config_document(&selected)?.value;
            Ok(managed::nodes(
                &document,
                &selected,
                &projected,
                &owner,
                Err("endpoint.address: an Agent requires an explicit public address"),
            ))
        })
        .await??;
        for (position, exported) in exported.into_iter().enumerate() {
            match exported {
                Ok(node_value) => entries.push(IndexEntry {
                    id: node_value.id(),
                    source: Source {
                        provider: node.name.clone(),
                        name: node_value.name.to_string(),
                        position,
                    },
                    node: node_value,
                }),
                Err(_) => unexported += 1,
            }
        }
    }

    let observations = state.providers().observations().await?;
    let index = NodeIndex::from_observations(
        observations
            .iter()
            .map(|(name, observation)| (name.as_str(), observation)),
    );
    let mut hours: Option<u64> = None;
    for name in &user.collections {
        let Some(collection) = state.collections().get(name).await else {
            continue;
        };
        let resolved = collection.resolve(
            &index,
            &provider_filters(state, &collection).await?,
            &collection.filter()?,
        );
        entries.extend(resolved.nodes);
        if let Some(every) = update_hours(state, &collection).await {
            hours = Some(hours.map_or(every, |known| known.min(every)));
        }
    }

    // Own servers and provider nodes share one list, so a name both use is
    // told apart the way two providers' are.
    suba_core::name_conflicts(&mut entries);
    let rendered = target.render(&entries.iter().collect::<Vec<_>>(), RenderIntent::Client)?;

    Ok(Artifact {
        body: rendered.body.into(),
        target,
        nodes: entries.len().saturating_sub(rendered.skipped.len()),
        skipped: rendered.skipped.len() + unexported,
        update_hours: hours,
    })
}

/// Every inbound of every saved configuration, with the address a client dials.
///
/// The list is complete whether or not an override is stored, so an operator
/// sees every entry and what it would currently export, not only the ones
/// somebody already edited.
pub async fn endpoints(
    State(state): State<AppState>,
    _auth: Operator,
) -> ResponseResult<Json<EndpointsView>> {
    let mut view = endpoint_view(&state).await?;
    if state.target_host().is_none() {
        for host in state.peers().hosts().await {
            if host.mode != crate::state::peers::Mode::Edge {
                continue;
            }
            let scoped = state.for_agent(host.id).await?;
            let mut remote = endpoint_view(&scoped).await?;
            for entry in &mut remote.entries {
                entry.host = Some(host.id);
                entry.host_name = Some(host.name.clone());
            }
            view.entries.extend(remote.entries);
        }
    }
    Ok(Json(view))
}

async fn endpoint_view(state: &AppState) -> Result<EndpointsView, Error> {
    let access = state.access_snapshot().await;
    let public_host = public_host(state).await.ok().map(|host| host.to_string());
    let store = state.singbox();

    tokio::task::spawn_blocking(move || -> Result<EndpointsView, Error> {
        let mut entries = Vec::new();
        for name in store.configs()? {
            let document = store.config_document(&name)?.value;
            for inbound in document
                .get("inbounds")
                .and_then(serde_json::Value::as_array)
                .map_or(&[][..], Vec::as_slice)
            {
                let Some(tag) = inbound.get("tag").and_then(serde_json::Value::as_str) else {
                    // An inbound without a tag cannot be addressed at all,
                    // so it has no address to store either.
                    continue;
                };
                let at = Entry::local(&name, tag);
                let stored = access.endpoint(&at);
                let modes = managed::modes(inbound);
                let shadowtls_problem = if inbound.get("type").and_then(serde_json::Value::as_str)
                    == Some("shadowtls")
                {
                    match stored.and_then(|endpoint| endpoint.inner_inbound.as_deref()) {
                        None => Some("select an inner inbound before exporting this entry"),
                        Some(inner) if managed::validate_inner(&document, tag, inner).is_err() => {
                            Some("selected inner inbound is unavailable")
                        }
                        Some(_) => None,
                    }
                } else {
                    None
                };
                entries.push(EndpointView {
                    host: None,
                    host_name: None,
                    reason: if modes.is_empty() {
                        managed::placement(&document, &at).reason()
                    } else {
                        shadowtls_problem
                    },
                    config: name.clone(),
                    inbound: tag.to_owned(),
                    modes,
                    shared_warning: managed::shared_warning(inbound),
                    shared_refused: managed::shared_refusal(inbound),
                    managed_warning: managed::managed_warning(inbound),
                    address: stored.and_then(|endpoint| endpoint.address.clone()),
                    port: stored.and_then(|endpoint| endpoint.port),
                    inner_inbound: stored.and_then(|endpoint| endpoint.inner_inbound.clone()),
                });
            }
        }

        Ok(EndpointsView {
            public_host,
            entries,
        })
    })
    .await?
}

/// Store or clear one inbound's client endpoint settings.
pub async fn put_endpoint(
    State(state): State<AppState>,
    _auth: Operator,
    Path((config, inbound)): Path<(String, String)>,
    Json(body): Json<EndpointBody>,
) -> ResponseResult<Json<EndpointView>> {
    let access = state.access_snapshot().await;
    let at = Entry::local(&config, &inbound);
    // An address for an inbound that is not there would never be read, so it is
    // refused where an operator can still fix it rather than stored quietly.
    let placement = placement(&state, &at).await?;
    let (modes, shared_warning, shared_refused, managed_warning, shadowtls) =
        endpoint_access(&state, &at).await?;
    let stored = access.endpoint(&at).cloned().unwrap_or_default();
    let endpoint = Endpoint {
        address: match body.address {
            Some(address) => address,
            None => stored.address,
        },
        port: match body.port {
            Some(port) => port,
            None => stored.port,
        },
        inner_inbound: match body.inner_inbound {
            Some(inner_inbound) => inner_inbound,
            None => stored.inner_inbound,
        },
    };
    let reason = if modes.is_empty() {
        placement.reason()
    } else if shadowtls && endpoint.inner_inbound.is_none() {
        Some("select an inner inbound before exporting this entry")
    } else {
        None
    };
    if let Some(inner) = endpoint.inner_inbound.as_deref() {
        let store = state.singbox();
        let config_name = config.clone();
        let outer_tag = inbound.clone();
        let inner_tag = inner.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let document = store.config_document(&config_name)?.value;
            managed::validate_inner(&document, &outer_tag, &inner_tag)
        })
        .await??;
    }
    state
        .put_endpoint(&config, &inbound, endpoint.clone())
        .await?;
    tracing::debug!("Stored inbound endpoint settings");

    Ok(Json(EndpointView {
        host: state.target_host(),
        host_name: None,
        config,
        inbound,
        modes,
        shared_warning,
        shared_refused,
        managed_warning,
        address: endpoint.address,
        port: endpoint.port,
        inner_inbound: endpoint.inner_inbound,
        reason,
    }))
}

async fn endpoint_access(
    state: &AppState,
    at: &Entry,
) -> Result<
    (
        Vec<GrantMode>,
        Option<&'static str>,
        Option<&'static str>,
        Option<&'static str>,
        bool,
    ),
    Error,
> {
    let store = state.singbox();
    let at = at.clone();
    tokio::task::spawn_blocking(move || -> Result<_, Error> {
        let document = store.config_document(&at.config)?.value;
        let inbound = document
            .get("inbounds")
            .and_then(serde_json::Value::as_array)
            .and_then(|inbounds| {
                inbounds.iter().find(|inbound| {
                    inbound.get("tag").and_then(serde_json::Value::as_str)
                        == Some(at.inbound.as_str())
                })
            });
        Ok((
            inbound.map_or_else(Vec::new, managed::modes),
            inbound.and_then(managed::shared_warning),
            inbound.and_then(managed::shared_refusal),
            inbound.and_then(managed::managed_warning),
            inbound
                .and_then(|inbound| inbound.get("type"))
                .and_then(serde_json::Value::as_str)
                == Some("shadowtls"),
        ))
    })
    .await?
}

pub async fn delete_endpoint(
    State(state): State<AppState>,
    _auth: Operator,
    Path((config, inbound)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    state.remove_endpoint(&config, &inbound).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Where an entry stands in its saved configuration document.
///
/// An entry naming no inbound of that configuration is refused: the address
/// would never be read, and storing it would only look like it worked.
async fn placement(state: &AppState, at: &Entry) -> Result<Placement, Error> {
    let store = state.singbox();
    let at = at.clone();
    tokio::task::spawn_blocking(move || -> Result<Placement, Error> {
        let document = store.config_document(&at.config)?.value;

        match managed::placement(&document, &at) {
            Placement::Unknown => Err(Error::Document(
                "inbound: no inbound of this configuration has this tag".to_string(),
            )),
            placement => Ok(placement),
        }
    })
    .await?
}
