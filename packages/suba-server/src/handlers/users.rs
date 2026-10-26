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
use suba_core::format::{Format, RenderIntent};
use suba_core::proto::Host;
use suba_core::{IndexEntry, NodeIndex, Source};

use crate::{
    dto::{Operator, ResponseResult},
    error::Error,
    handlers::collections::{
        artifact_headers, provider_filters, token_view, update_hours, Choice, TokenView,
    },
    state::access::{Access, Endpoint, Entry},
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
    pub config: String,
    pub inbound: String,
    /// Absent when the entry reaches no inbound that can take users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Applied>,
    #[serde(flatten)]
    pub export: Export,
}

/// One inbound of one configuration, with the address a client dials.
#[derive(Debug, Serialize)]
pub struct EndpointView {
    pub config: String,
    pub inbound: String,
    /// The stored override, when the operator set one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Why this inbound cannot be exported at all, when it cannot.
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

/// What a form says about one inbound's address: omitted keeps the stored
/// value, explicit null clears it.
#[derive(Debug, Default, Deserialize)]
pub struct EndpointBody {
    #[serde(default, deserialize_with = "keep_or_clear")]
    pub address: Option<Option<String>>,
    #[serde(default, deserialize_with = "keep_or_clear")]
    pub port: Option<Option<u16>>,
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
    pub public_host: Option<String>,
    pub inbounds: Vec<InboundUsers>,
}

/// The public host, or the reason every export points nowhere.
async fn public_host(state: &AppState) -> Result<Host, &'static str> {
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
    let access = state.access().snapshot().await;
    let host = public_host(&state).await;
    let store = state.singbox();

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<ConfigUsers, Error> {
            let document = store.config_document(&name)?.value;
            let in_use = store.config()?;
            let product = store.product();

            Ok(ConfigUsers {
                public_host: host.as_ref().ok().map(ToString::to_string),
                inbounds: managed::exports(
                    &document,
                    &name,
                    &access,
                    host.as_ref().map_err(|reason| *reason),
                    &serving(&name, &in_use, product.as_ref()),
                ),
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
    let access = state.access().snapshot().await;
    let host = public_host(&state).await;
    let prefix = state.settings().subscription_prefix().await?;
    let collections: BTreeSet<String> = state.collections().list().await.into_keys().collect();
    let store = state.singbox();

    Ok(Json(
        tokio::task::spawn_blocking(move || views(&store, &access, &host, &prefix, &collections))
            .await??,
    ))
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
        config: entry.config.clone(),
        inbound: entry.inbound.clone(),
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
    if let Some(reason) = inbound.refused {
        return refused(format!("inbound: {reason}"));
    }
    let Some(managed) = inbound.managed.iter().find(|managed| managed.user == user) else {
        return refused("inbound: the user is not in it".to_string());
    };

    GrantView {
        state: Some(managed.state),
        export: managed.export.clone(),
        config: entry.config,
        inbound: entry.inbound,
    }
}

/// Store a user's inbounds and collections; a new user gets its secret here.
pub async fn put(
    State(state): State<AppState>,
    _auth: Operator,
    Path(name): Path<String>,
    Json(body): Json<UserBody>,
) -> ResponseResult<impl IntoResponse> {
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

/// Forget every credential of a user; new ones derive from a new secret, and
/// each host serves them once it applies.
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
    Query(choice): Query<Choice>,
    request: HeaderMap,
) -> ResponseResult<impl IntoResponse> {
    let artifact = user_artifact(&state, &name, choice.resolve(&request)?).await?;

    let mut headers = artifact_headers(&artifact);
    headers.insert("x-suba-nodes", HeaderValue::from(artifact.nodes));
    headers.insert("x-suba-skipped", HeaderValue::from(artifact.skipped));

    Ok((headers, artifact.body.to_string()))
}

/// A user's subscription: a node per inbound it may use in the configuration
/// the core runs, then the nodes of its collections.
///
/// Not memoised: it holds credentials derived on the way, and the address of
/// the bytes would have to include the user's secret to be one.
pub(crate) async fn user_artifact(
    state: &AppState,
    name: &str,
    format: Format,
) -> Result<Artifact, Error> {
    let access = state.access().snapshot().await;
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
    let rendered = format.render(&entries.iter().collect::<Vec<_>>(), RenderIntent::Client)?;

    Ok(Artifact {
        body: rendered.body.into(),
        format,
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
    let access = state.access().snapshot().await;
    let public_host = public_host(&state).await.ok().map(|host| host.to_string());
    let store = state.singbox();

    Ok(Json(
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
                    let at = Entry {
                        config: name.clone(),
                        inbound: tag.to_owned(),
                    };
                    let stored = access.endpoint(&at);
                    entries.push(EndpointView {
                        reason: managed::placement(&document, &at).reason(),
                        config: name.clone(),
                        inbound: tag.to_owned(),
                        address: stored.and_then(|endpoint| endpoint.address.clone()),
                        port: stored.and_then(|endpoint| endpoint.port),
                    });
                }
            }

            Ok(EndpointsView {
                public_host,
                entries,
            })
        })
        .await??,
    ))
}

/// Store or clear one inbound's address override.
pub async fn put_endpoint(
    State(state): State<AppState>,
    _auth: Operator,
    Path((config, inbound)): Path<(String, String)>,
    Json(body): Json<EndpointBody>,
) -> ResponseResult<Json<EndpointView>> {
    let access = state.access().snapshot().await;
    let at = Entry {
        config: config.clone(),
        inbound: inbound.clone(),
    };
    // An address for an inbound that is not there would never be read, so it is
    // refused where an operator can still fix it rather than stored quietly.
    let placement = placement(&state, &at).await?;
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
    };
    state
        .access()
        .put_endpoint(&config, &inbound, endpoint.clone())
        .await?;
    tracing::debug!("Stored an address for {} :: {inbound}", config);

    Ok(Json(EndpointView {
        config,
        inbound,
        address: endpoint.address,
        port: endpoint.port,
        reason: placement.reason(),
    }))
}

pub async fn delete_endpoint(
    State(state): State<AppState>,
    _auth: Operator,
    Path((config, inbound)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    state.access().remove_endpoint(&config, &inbound).await?;

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
