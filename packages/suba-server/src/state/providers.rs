use std::{collections::HashMap, path::Path};

use reqwest::Client;
use tokio::sync::watch;

use crate::{
    config::{ConfigError, Provider, ProvidersConfig, PROVIDERS_BASENAME},
    error::Error,
};

use super::{caches::CacheStore, persisted::Persisted};

/// What a refresh stored, for reporting back to the caller.
#[derive(Debug, Clone)]
pub(crate) struct Refreshed {
    pub(crate) name: String,
    pub(crate) bytes: usize,
}

/// The subscription-backed providers of the instance.
///
/// The store owns both halves of a provider: its configuration, persisted
/// beside the other configuration files, and the payload it last returned,
/// cached in the data directory. Keeping them together is what lets a refresh
/// be one operation instead of a dance between two stores.
pub(crate) struct ProviderStore {
    file: Persisted<ProvidersConfig>,
    cache: CacheStore,
    /// Bumped on every configuration change, so background work can follow
    /// the provider set instead of polling it.
    changes: watch::Sender<u64>,
}

impl ProviderStore {
    pub(crate) fn load(config_dir: &Path, data_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            file: Persisted::load(config_dir, PROVIDERS_BASENAME)?,
            cache: CacheStore::load(data_dir),
            changes: watch::Sender::new(0),
        })
    }

    /// Follow configuration changes.
    ///
    /// The returned receiver resolves whenever a provider is added, edited or
    /// removed.
    pub(crate) fn subscribe(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Wake every subscriber after a configuration change.
    fn publish(&self) {
        self.changes.send_modify(|generation| *generation += 1);
    }

    pub(crate) async fn list(&self) -> HashMap<String, Provider> {
        self.file.read(|config| config.providers.clone()).await
    }

    pub(crate) async fn get(&self, name: &str) -> Option<Provider> {
        self.file
            .read(|config| config.providers.get(name).cloned())
            .await
    }

    /// Every provider that takes part in automatic refreshing.
    pub(crate) async fn refreshable(&self) -> Vec<(String, Provider)> {
        self.file
            .read(|config| {
                config
                    .providers
                    .iter()
                    .filter(|(_, provider)| !provider.disabled())
                    .map(|(name, provider)| (name.clone(), provider.clone()))
                    .collect()
            })
            .await
    }

    /// The payload last fetched for `name`, if it was ever fetched.
    pub(crate) async fn content(&self, name: &str) -> Result<Option<String>, Error> {
        Ok(self.cache.content(name).await?)
    }

    pub(crate) async fn insert(&self, name: &str, provider: Provider) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        config.providers.insert(name.to_owned(), provider);
        locked.commit(config).await?;
        self.publish();

        Ok(())
    }

    pub(crate) async fn remove(&self, name: &str) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        config.providers.remove(name);
        locked.commit(config).await?;
        // The payload of a provider that no longer exists would only ever be
        // read by mistake.
        self.cache.remove(name).await?;
        self.publish();

        Ok(())
    }

    /// Download `provider` and adopt it as the provider stored under `name`.
    ///
    /// The download happens before anything is committed, so a provider that
    /// cannot be fetched is never left behind half-configured. The payload is
    /// staged before the configuration change is published: a worker started
    /// by that change must find the content already cached, or it would
    /// download it a second time straight away.
    pub(crate) async fn upsert(
        &self,
        name: &str,
        provider: Provider,
        client: &Client,
    ) -> Result<Refreshed, Error> {
        let content = provider.fetch(client).await?;
        self.store(name, &content).await?;
        self.insert(name, provider).await?;

        Ok(Refreshed {
            name: name.to_owned(),
            bytes: content.len(),
        })
    }

    /// Re-download the provider stored under `name` and cache the result.
    ///
    /// Writers of the same provider are serialized, so a refresh triggered by
    /// the API cannot race the scheduler.
    pub(crate) async fn refresh(&self, name: &str, client: &Client) -> Result<Refreshed, Error> {
        let _guard = self.cache.lock(name).await;

        let provider = self
            .get(name)
            .await
            .ok_or_else(|| Error::ProviderNotFound(name.to_owned()))?;
        if provider.disabled() {
            return Err(Error::ProviderDisabled(name.to_owned()));
        }

        let content = provider.fetch(client).await?;
        self.store(name, &content).await?;

        Ok(Refreshed {
            name: name.to_owned(),
            bytes: content.len(),
        })
    }

    /// Write `content` as the payload cached for `name`.
    ///
    /// The bytes are kept verbatim; interpreting them, such as converting a
    /// subscription, is left to the consumer.
    pub(crate) async fn store(&self, name: &str, content: &str) -> Result<(), Error> {
        Ok(self.cache.put(name, content).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::provider::{default_interval, Http, SharedFields};

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-providers-{}", uuid::Uuid::now_v7()))
    }

    fn provider() -> Provider {
        Provider::Http(Http {
            shared: SharedFields { disabled: false },
            url: "https://example.com/subscription".parse().unwrap(),
            headers: None,
            timeout: None,
            interval: default_interval(),
        })
    }

    fn load(dir: &Path) -> ProviderStore {
        ProviderStore::load(dir, dir).unwrap()
    }

    #[tokio::test]
    async fn providers_survive_a_reload() {
        let dir = test_dir();
        let store = load(&dir);
        assert!(store.list().await.is_empty());

        store.insert("airport", provider()).await.unwrap();
        assert!(store.get("airport").await.is_some());

        let reloaded = load(&dir);
        assert!(reloaded.get("airport").await.is_some());

        reloaded.remove("airport").await.unwrap();
        assert!(reloaded.get("airport").await.is_none());
        assert!(load(&dir).get("airport").await.is_none());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn removing_a_provider_forgets_its_payload() {
        let dir = test_dir();
        let store = load(&dir);

        store.insert("airport", provider()).await.unwrap();
        store.store("airport", "proxies: []").await.unwrap();
        assert_eq!(
            store.content("airport").await.unwrap().as_deref(),
            Some("proxies: []")
        );

        store.remove("airport").await.unwrap();
        assert_eq!(store.content("airport").await.unwrap(), None);

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn configuration_changes_wake_subscribers() {
        let dir = test_dir();
        let store = load(&dir);
        let mut changes = store.subscribe();

        store.insert("airport", provider()).await.unwrap();
        assert!(changes.changed().await.is_ok());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn refreshing_missing_or_disabled_providers_is_refused() {
        let dir = test_dir();
        let store = load(&dir);
        let client = Client::new();

        assert!(matches!(
            store.refresh("airport", &client).await,
            Err(Error::ProviderNotFound(_))
        ));

        let Provider::Http(mut disabled) = provider();
        disabled.shared.disabled = true;
        store
            .insert("airport", Provider::Http(disabled))
            .await
            .unwrap();

        assert!(matches!(
            store.refresh("airport", &client).await,
            Err(Error::ProviderDisabled(_))
        ));
        assert!(store.refreshable().await.is_empty());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
