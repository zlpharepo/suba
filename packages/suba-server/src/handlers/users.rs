//! Proxy users and pools, as resources of the sing-box module.
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
    dto::{Authenticated, ResponseResult},
    error::Error,
    handlers::collections::{
        artifact_headers, provider_filters, token_view, update_hours, Choice, TokenView,
    },
    state::access::{Access, Entry, Pool},
    state::render::Artifact,
    state::singbox::{
        managed::{self, Export, InboundUsers, Serving, State as Applied},
        SingboxStore,
    },
    tracing, AppState,
};

/// What a form says about a user: the rest is the server's to keep.
#[derive(Debug, Deserialize)]
pub struct UserBody {
    #[serde(default)]
    pub pools: Vec<String>,
    #[serde(default)]
    pub collections: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UserView {
    pub name: String,
    pub pools: Vec<String>,
    pub collections: Vec<String>,
    /// Named, and not there: stored anyway, like a collection's providers.
    pub missing_pools: Vec<String>,
    pub missing_collections: Vec<String>,
    pub links: Vec<TokenView>,
    /// Every inbound its pools grant, with the client that reaches it.
    pub grants: Vec<GrantView>,
}

#[derive(Debug, Serialize)]
pub struct GrantView {
    pub config: String,
    pub inbound: String,
    pub via: Vec<String>,
    /// Absent when the grant reaches no inbound a pool can give.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<Applied>,
    #[serde(flatten)]
    pub export: Export,
}

#[derive(Debug, Serialize)]
pub struct PoolView {
    pub name: String,
    pub entries: Vec<EntryView>,
    /// The users whose pools include this one.
    pub members: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EntryView {
    pub config: String,
    pub inbound: String,
    /// Why the entry gives nobody anything, when it does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    _auth: Authenticated,
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

/// Every user, with what its pools grant it and its links.
pub async fn index(
    State(state): State<AppState>,
    _auth: Authenticated,
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
            grants.push(grant_view(&configs[config], grant.entry, grant.via, name));
        }

        views.push(UserView {
            name: name.clone(),
            missing_pools: user
                .pools
                .iter()
                .filter(|pool| !access.pools.contains_key(*pool))
                .cloned()
                .collect(),
            missing_collections: user
                .collections
                .iter()
                .filter(|collection| !collections.contains(*collection))
                .cloned()
                .collect(),
            pools: user.pools.clone(),
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

fn grant_view(inbounds: &[InboundUsers], entry: Entry, via: Vec<String>, user: &str) -> GrantView {
    let refused = |reason: String| GrantView {
        config: entry.config.clone(),
        inbound: entry.inbound.clone(),
        via: via.clone(),
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
        via,
    }
}

/// Store a user's pools and collections; a new user gets its secret here.
pub async fn put(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(name): Path<String>,
    Json(body): Json<UserBody>,
) -> ResponseResult<impl IntoResponse> {
    state
        .access()
        .put_user(&name, body.pools, body.collections)
        .await?;
    tracing::debug!("Stored user '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.access().remove_user(&name).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Forget every credential of a user; new ones derive from a new secret, and
/// each host serves them once it applies.
pub async fn renew(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.access().renew_secret(&name).await?;
    tracing::info!("Replaced the credentials of user '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

pub async fn mint_token(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path((name, label)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    let token = state.access().mint_token(&name, &label).await?;
    let prefix = state.settings().subscription_prefix().await?;
    tracing::debug!("Minted subscription link '{label}' for user '{name}'");

    Ok((StatusCode::CREATED, Json(token_view(&prefix, label, token))))
}

pub async fn revoke_token(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path((name, label)): Path<(String, String)>,
) -> ResponseResult<impl IntoResponse> {
    state.access().revoke_token(&name, &label).await?;
    tracing::debug!("Revoked subscription link '{label}' of user '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

/// What a user's links hand out, for the operator.
pub async fn content(
    State(state): State<AppState>,
    _auth: Authenticated,
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

/// A user's subscription: a node per inbound its pools grant in the
/// configuration the core runs, then the nodes of its collections.
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

/// Every pool, with who is in it and what each entry gives.
pub async fn pools(
    State(state): State<AppState>,
    _auth: Authenticated,
) -> ResponseResult<Json<Vec<PoolView>>> {
    let access = state.access().snapshot().await;
    let store = state.singbox();

    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Vec<PoolView>, Error> {
            let mut documents = BTreeMap::new();
            let mut views = Vec::new();
            for (name, pool) in &access.pools {
                let mut entries = Vec::new();
                for entry in &pool.entries {
                    if !documents.contains_key(&entry.config) {
                        documents.insert(
                            entry.config.clone(),
                            store.config_document(&entry.config)?.value,
                        );
                    }
                    entries.push(EntryView {
                        reason: managed::unplaced(&documents[&entry.config], entry)
                            .map(str::to_owned),
                        config: entry.config.clone(),
                        inbound: entry.inbound.clone(),
                    });
                }
                views.push(PoolView {
                    name: name.clone(),
                    entries,
                    members: access
                        .users
                        .iter()
                        .filter(|(_, user)| user.pools.contains(name))
                        .map(|(user, _)| user.clone())
                        .collect(),
                });
            }

            Ok(views)
        })
        .await??,
    ))
}

pub async fn put_pool(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(name): Path<String>,
    Json(pool): Json<Pool>,
) -> ResponseResult<impl IntoResponse> {
    state.access().put_pool(&name, pool).await?;
    tracing::debug!("Stored pool '{name}'");

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_pool(
    State(state): State<AppState>,
    _auth: Authenticated,
    Path(name): Path<String>,
) -> ResponseResult<impl IntoResponse> {
    state.access().remove_pool(&name).await?;

    Ok(StatusCode::NO_CONTENT)
}
