use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use reqwest::Client;
use tokio::sync::watch;

use crate::{
    config::ConfigError,
    error::Error,
    provider::{Provider, ProvidersConfig, PROVIDERS_BASENAME},
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
    /// Where a [`Local`](crate::provider::Local) provider's relative
    /// path is resolved from.
    config_dir: PathBuf,
    /// Bumped on every configuration change, so background work can follow
    /// the provider set instead of polling it.
    changes: watch::Sender<u64>,
}

impl ProviderStore {
    pub(crate) fn load(config_dir: &Path, data_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            file: Persisted::load(config_dir, PROVIDERS_BASENAME)?,
            cache: CacheStore::load(data_dir),
            config_dir: config_dir.to_path_buf(),
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
    ///
    /// A provider that is disabled is left out, and so is one there is nothing
    /// to poll for — an inline provider serves what the configuration already
    /// holds, so a schedule for it would only ever re-read the same bytes.
    pub(crate) async fn refreshable(&self) -> Vec<(String, Provider)> {
        self.file
            .read(|config| {
                config
                    .providers
                    .iter()
                    .filter(|(_, provider)| !provider.disabled() && provider.interval().is_some())
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
        // Validated before the lock is taken: an unusable filter is the
        // caller's mistake, and the document it arrived in reads the same
        // whether or not anything else is being written.
        provider.filter()?;

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
    /// The payload is read before anything is committed, so a provider that
    /// cannot be read is never left behind half-configured. The payload is
    /// staged before the configuration change is published: a worker started
    /// by that change must find the content already cached, or it would read
    /// it a second time straight away.
    pub(crate) async fn upsert(
        &self,
        name: &str,
        provider: Provider,
        client: &Client,
    ) -> Result<Refreshed, Error> {
        // Checked before the payload is read: a definition the store will
        // refuse must not send a request, and a caller that made a mistake
        // should hear about the mistake rather than about whatever the network
        // said.
        provider.filter()?;

        let content = provider.payload(client, &self.config_dir).await?;
        self.store(name, &content).await?;
        self.insert(name, provider).await?;

        Ok(Refreshed {
            name: name.to_owned(),
            bytes: content.len(),
        })
    }

    /// Read the provider stored under `name` again and cache the result.
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

        let content = provider.payload(client, &self.config_dir).await?;
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
    use crate::provider::{default_interval, Remote, SharedFields};

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-providers-{}", uuid::Uuid::now_v7()))
    }

    fn provider() -> Provider {
        remote(false)
    }

    fn remote(disabled: bool) -> Provider {
        Provider::Remote(Remote {
            shared: SharedFields {
                disabled,
                ..SharedFields::default()
            },
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

    /// A filter that cannot be compiled is refused where it is stored.
    ///
    /// Storing it would leave a provider whose definition says one thing and
    /// whose behaviour does another; the operator would have no way to tell
    /// which had happened.
    #[tokio::test]
    async fn a_provider_with_an_unusable_filter_is_refused() {
        let dir = test_dir();
        let store = load(&dir);
        let client = Client::new();

        let Provider::Remote(mut broken) = provider() else {
            panic!("the fixture is a remote provider");
        };
        broken.shared.include = vec!["regex:(".to_string()];

        assert!(matches!(
            store
                .upsert("airport", Provider::Remote(broken), &client)
                .await,
            Err(Error::Filter(_))
        ));

        // Nothing was stored, and nothing was published: a refused definition
        // does not half-exist.
        assert!(store.get("airport").await.is_none());
        assert!(
            matches!(store.content("airport").await, Ok(None)),
            "a refused provider has no cached payload"
        );

        // A refusal this early means nothing was ever created, so there is
        // nothing to clean up and no directory to remove.
        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_provider_whose_filter_compiles_is_stored() {
        let dir = test_dir();
        let store = load(&dir);

        let Provider::Remote(mut filtered) = provider() else {
            panic!("the fixture is a remote provider");
        };
        filtered.shared.include = vec!["US-01".to_string(), "keyword:LAX".to_string()];
        filtered.shared.exclude = vec!["regex:-\\d+$".to_string()];

        store
            .insert("airport", Provider::Remote(filtered))
            .await
            .unwrap();

        assert!(store.get("airport").await.is_some());

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

        store.insert("airport", remote(true)).await.unwrap();

        assert!(matches!(
            store.refresh("airport", &client).await,
            Err(Error::ProviderDisabled(_))
        ));
        assert!(store.refreshable().await.is_empty());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
