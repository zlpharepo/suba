mod caches;
mod persisted;
mod providers;
mod scheduler;
mod sessions;
mod settings;

use std::{path::PathBuf, sync::Arc};

use reqwest::Client;

use crate::{config::ServerConfig, error::Error};

use self::{
    providers::ProviderStore, scheduler::Refresher, sessions::SessionStore, settings::SettingsStore,
};

/// Everything a request handler shares, behind a single reference count.
///
/// Cloning is one atomic increment, so extractors can hand the state to async
/// tasks freely. Each store owns its data behind its own lock and is reached
/// through the accessors below.
#[derive(Clone)]
pub struct AppState(Arc<Inner>);

struct Inner {
    data_dir: PathBuf,
    http: Client,
    settings: SettingsStore,
    /// Shared with the refresher, which outlives any single request.
    providers: Arc<ProviderStore>,
    sessions: SessionStore,
}

impl AppState {
    /// Load every store and build the shared HTTP client.
    pub async fn build(config: &ServerConfig) -> Result<Self, Error> {
        Ok(Self(Arc::new(Inner {
            data_dir: config.data_dir.clone(),
            http: Client::builder().build()?,
            settings: SettingsStore::load(&config.config_dir)?,
            providers: Arc::new(ProviderStore::load(&config.config_dir, &config.data_dir)?),
            sessions: SessionStore::load(&config.data_dir)?,
        })))
    }

    /// The background task that keeps provider subscriptions fresh.
    ///
    /// The caller decides when to run it, which keeps the server usable from
    /// tests without spawning a task per instance.
    pub(crate) fn refresher(&self) -> Refresher {
        Refresher::new(Arc::clone(&self.0.providers), self.0.http.clone())
    }

    /// The directory served as the web UI root.
    pub(crate) fn web_dir(&self) -> PathBuf {
        self.0.data_dir.join("web")
    }

    /// The client used for outbound subscription requests.
    pub(crate) fn http(&self) -> &Client {
        &self.0.http
    }

    /// The instance settings: administrator account and key pair.
    pub(crate) fn settings(&self) -> &SettingsStore {
        &self.0.settings
    }

    /// The configured subscription-backed providers.
    pub(crate) fn providers(&self) -> &ProviderStore {
        &self.0.providers
    }

    /// The sessions currently allowed to authenticate.
    pub(crate) fn sessions(&self) -> &SessionStore {
        &self.0.sessions
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
        };

        let state = AppState::build(&config).await.unwrap();

        assert_eq!(state.web_dir(), root.join("data/web"));
        assert!(state.settings().administrator().await.is_none());
        assert!(state.providers().list().await.is_empty());
        assert!(!state.sessions().contains(uuid::Uuid::now_v7()).await);

        // Building the state is read-only, so it may not have created anything.
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
