#[cfg(feature = "singbox-core")]
pub(crate) mod access;
mod collections;
pub(crate) mod limiter;
pub(crate) mod metrics;
#[cfg(feature = "singbox-core")]
pub(crate) mod observation;
pub(crate) mod peers;
mod persisted;
pub(crate) mod providers;
pub(crate) mod render;
mod scheduler;
mod sessions;
mod settings;
#[cfg(feature = "singbox-core")]
pub(crate) mod singbox;

use std::{path::PathBuf, sync::Arc};

use reqwest::Client;

use crate::{config::ServerConfig, error::Error, identity::Identity};

#[cfg(feature = "singbox-core")]
use self::{access::AccessStore, singbox::SingboxStore};
use self::{
    collections::CollectionStore, limiter::Limiter, metrics::MetricsStore,
    providers::ProviderStore, render::RenderMemo, scheduler::Refresher, sessions::SessionStore,
    settings::SettingsStore,
};
/// Everything a request handler shares, behind a single reference count.
///
/// Cloning is one atomic increment, so extractors can hand the state to async
/// tasks freely. Each store owns its data behind its own lock and is reached
/// through the accessors below.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
    #[cfg(feature = "singbox-core")]
    scope: Option<AgentScope>,
}

#[cfg(feature = "singbox-core")]
#[derive(Clone)]
struct AgentScope {
    id: uuid::Uuid,
    core: Arc<SingboxStore>,
    endpoints: Arc<access::EndpointStore>,
}

struct Inner {
    agent: bool,
    #[cfg(feature = "singbox-core")]
    config_dir: PathBuf,
    #[cfg(feature = "singbox-core")]
    identity: Identity,
    #[cfg(feature = "singbox-core")]
    agents: std::sync::Mutex<std::collections::HashMap<uuid::Uuid, AgentScope>>,
    data_dir: PathBuf,
    http: Client,
    settings: SettingsStore,
    peers: peers::Peers,
    /// Shared with the refresher, which outlives any single request.
    providers: Option<Arc<ProviderStore>>,
    collections: Option<CollectionStore>,
    rendered: Option<RenderMemo>,
    deliveries: Option<Limiter>,
    sessions: Option<SessionStore>,
    /// Serializes login issuance with password rotation across both stores.
    auth_lock: tokio::sync::Mutex<()>,
    metrics: Arc<MetricsStore>,
    #[cfg(feature = "singbox-core")]
    singbox: Arc<SingboxStore>,
    #[cfg(feature = "singbox-core")]
    access: Option<AccessStore>,
    #[cfg(feature = "singbox-core")]
    observation: Arc<observation::Observation>,
}

impl AppState {
    /// Load every store and build the shared HTTP client.
    pub async fn build(config: &ServerConfig) -> Result<Self, Error> {
        Self::build_for(config, false).await
    }

    pub(crate) async fn build_agent(config: &ServerConfig) -> Result<Self, Error> {
        if !cfg!(feature = "singbox-core") {
            return Err(Error::PeerRequest {
                reason: "edge-agent: this build cannot run a core",
            });
        }
        Self::build_for(config, true).await
    }

    async fn build_for(config: &ServerConfig, agent: bool) -> Result<Self, Error> {
        // Before anything is read: who this run is, and whether it may be. A
        // root run writes files root owns, so they are handed back first rather
        // than after the stores have created some.
        let identity =
            Identity::discover(config.privileged, &[&config.data_dir, &config.config_dir])?;
        identity.settle_files(&[&config.data_dir, &config.config_dir]);

        // One client for the instance: subscriptions and releases both go out
        // through it, so connection reuse and timeouts are the same everywhere.
        // A user agent is not decoration: the release API answers `403` to a
        // request without one, and an instance that cannot fetch a release is
        // an instance that cannot install a core.
        let http = Client::builder()
            .user_agent(concat!("suba/", env!("CARGO_PKG_VERSION")))
            .build()?;

        Ok(Self {
            inner: Arc::new(Inner {
                agent,
                #[cfg(feature = "singbox-core")]
                config_dir: config.config_dir.clone(),
                #[cfg(feature = "singbox-core")]
                identity,
                #[cfg(feature = "singbox-core")]
                agents: std::sync::Mutex::new(std::collections::HashMap::new()),
                data_dir: config.data_dir.clone(),
                http: http.clone(),
                settings: SettingsStore::load(&config.config_dir)?,
                peers: peers::Peers::load(&config.config_dir)?,
                providers: if agent {
                    None
                } else {
                    Some(Arc::new(ProviderStore::load(
                        &config.config_dir,
                        &config.data_dir,
                    )?))
                },
                collections: if agent {
                    None
                } else {
                    Some(CollectionStore::load(&config.config_dir)?)
                },
                rendered: (!agent).then(RenderMemo::new),
                deliveries: (!agent).then(Limiter::new),
                sessions: if agent {
                    None
                } else {
                    Some(SessionStore::load(&config.data_dir)?)
                },
                auth_lock: tokio::sync::Mutex::new(()),
                metrics: Arc::new(MetricsStore::new(&config.data_dir)),
                #[cfg(feature = "singbox-core")]
                singbox: Arc::new(SingboxStore::new(
                    &if agent {
                        config.data_dir.join("agent")
                    } else {
                        config.config_dir.clone()
                    },
                    &config.data_dir,
                    http.clone(),
                    identity,
                )),
                #[cfg(feature = "singbox-core")]
                access: if agent {
                    None
                } else {
                    Some(AccessStore::load(&config.config_dir)?)
                },
                #[cfg(feature = "singbox-core")]
                observation: Arc::new(observation::Observation::new()),
            }),
            #[cfg(feature = "singbox-core")]
            scope: None,
        })
    }

    /// The background task that keeps provider subscriptions fresh.
    ///
    /// The caller decides when to run it, which keeps the server usable from
    /// tests without spawning a task per instance.
    pub(crate) fn refresher(&self) -> Refresher {
        Refresher::new(
            Arc::clone(self.inner.providers.as_ref().expect("manager providers")),
            self.inner.http.clone(),
        )
    }

    pub(crate) fn is_agent(&self) -> bool {
        self.inner.agent
    }

    /// The directory served as the web UI root.
    pub(crate) fn web_dir(&self) -> PathBuf {
        self.inner.data_dir.join("web")
    }

    /// The data directory. Used by tests that assert nothing was written.
    #[cfg(test)]
    pub(crate) fn data_dir(&self) -> &std::path::Path {
        &self.inner.data_dir
    }

    /// The client used for outbound subscription requests.
    pub(crate) fn http(&self) -> &Client {
        &self.inner.http
    }

    /// The instance settings: administrator account and key pair.
    pub(crate) fn settings(&self) -> &SettingsStore {
        &self.inner.settings
    }

    /// The configured subscription-backed providers.
    pub(crate) fn providers(&self) -> &ProviderStore {
        self.inner.providers.as_deref().expect("manager providers")
    }

    pub(crate) fn peers(&self) -> &peers::Peers {
        &self.inner.peers
    }

    /// The configured collections.
    pub(crate) fn collections(&self) -> &CollectionStore {
        self.inner
            .collections
            .as_ref()
            .expect("manager collections")
    }

    /// The artifacts rendered so far, by content address.
    pub(crate) fn rendered(&self) -> &RenderMemo {
        self.inner.rendered.as_ref().expect("manager artifacts")
    }

    /// How often each delivery token has been used lately.
    pub(crate) fn deliveries(&self) -> &Limiter {
        self.inner.deliveries.as_ref().expect("manager delivery")
    }

    /// The sessions currently allowed to authenticate.
    /// Shared so a handler can sample it on the blocking pool.
    pub(crate) fn metrics(&self) -> Arc<MetricsStore> {
        Arc::clone(&self.inner.metrics)
    }

    pub(crate) fn sessions(&self) -> &SessionStore {
        self.inner.sessions.as_ref().expect("manager sessions")
    }

    pub(crate) fn auth_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.inner.auth_lock
    }

    /// The proxy users and the addresses their clients dial.
    #[cfg(feature = "singbox-core")]
    pub(crate) fn access(&self) -> &AccessStore {
        self.inner.access.as_ref().expect("manager access")
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) fn observation(&self) -> Arc<observation::Observation> {
        Arc::clone(&self.inner.observation)
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) async fn for_agent(&self, id: uuid::Uuid) -> Result<Self, Error> {
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut agents = state.inner.agents.lock().expect("agent stores");
            let scope = if let Some(scope) = agents.get(&id) {
                scope.clone()
            } else {
                let config = state.inner.config_dir.join("hosts").join(id.to_string());
                let data = state.inner.data_dir.join("hosts").join(id.to_string());
                let scope = AgentScope {
                    id,
                    core: Arc::new(SingboxStore::remote(
                        &config,
                        &data,
                        state.inner.http.clone(),
                        state.inner.identity,
                    )),
                    endpoints: Arc::new(access::EndpointStore::load(&config)?),
                };
                agents.insert(id, scope.clone());
                scope
            };
            Ok(Self {
                inner: Arc::clone(&state.inner),
                scope: Some(scope),
            })
        })
        .await?
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) fn target_host(&self) -> Option<uuid::Uuid> {
        self.scope.as_ref().map(|scope| scope.id)
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) async fn access_snapshot(&self) -> access::Access {
        let access = self.access().snapshot().await;
        if let Some(scope) = &self.scope {
            let mut access = access.for_host(scope.id);
            access.endpoints = scope.endpoints.snapshot().await;
            access
        } else {
            access
        }
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) async fn put_endpoint(
        &self,
        config: &str,
        inbound: &str,
        endpoint: access::Endpoint,
    ) -> Result<(), Error> {
        if let Some(scope) = &self.scope {
            scope
                .endpoints
                .put_endpoint(config, inbound, endpoint)
                .await
        } else {
            self.access().put_endpoint(config, inbound, endpoint).await
        }
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) async fn remove_endpoint(&self, config: &str, inbound: &str) -> Result<(), Error> {
        if let Some(scope) = &self.scope {
            scope.endpoints.remove_endpoint(config, inbound).await
        } else {
            self.access().remove_endpoint(config, inbound).await
        }
    }

    /// The sing-box module: its fragments, its configuration, its process.
    #[cfg(feature = "singbox-core")]
    pub(crate) fn singbox(&self) -> Arc<SingboxStore> {
        self.scope.as_ref().map_or_else(
            || Arc::clone(&self.inner.singbox),
            |scope| Arc::clone(&scope.core),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-state-{}", uuid::Uuid::now_v7()))
    }

    #[tokio::test]
    async fn builds_from_the_configured_directories() {
        let root = temp_dir();
        let config = ServerConfig {
            listen: "127.0.0.1".parse().unwrap(),
            port: 0,
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            privileged: Default::default(),
        };

        let state = AppState::build(&config).await.unwrap();

        assert_eq!(state.web_dir(), root.join("data/web"));
        assert!(state.settings().administrator().await.is_none());
        assert!(state.providers().list().await.is_empty());
        assert!(!state.sessions().contains(uuid::Uuid::now_v7()).await);

        // Building the state creates the data directory and takes its lock, so
        // it is not read-only: what it must not do is touch the instance's
        // documents.
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
