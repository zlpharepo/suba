//! The providers of the instance, and what they last served.
//!
//! Two things are kept for a provider, and they are kept in two places on
//! purpose: its **definition**, which an operator writes and which lives in the
//! configuration directory, and its **observation**, which the program derives
//! and which lives in the data directory. The definition says where nodes come
//! from; the observation says what arrived last time and when. They are not one
//! document, so that neither has to be rewritten to repair the other.
//!
//! A refresh is the whole loop: read what is held, ask the provider — with the
//! validators from what is held, when there is something to compare against —
//! let [`decide`] work out what that means, and write what it asks for. The
//! decision belongs to [`suba_core`]; this module is the part with a clock, a
//! socket and a disk.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::Client;
use suba_core::subscription::{DeclaredFormat, Unreadable};
use suba_core::{decide, record_failure, Observation, RefreshPlan, RefreshStatus};
use tokio::sync::{watch, Mutex as AsyncMutex, OwnedMutexGuard};

use crate::{
    error::Error,
    provider::{Provider, ProvidersConfig, PROVIDERS_BASENAME},
    store::{FileStore, ObservationStore, StoreError},
};

use super::persisted::Persisted;

/// What a refresh did, for reporting back to the caller.
///
/// The payload itself is never part of this: it may carry credentials, and a
/// caller that wants it asks for it, because that is a different question.
#[derive(Debug, Clone)]
pub(crate) struct Refreshed {
    pub(crate) name: String,
    pub(crate) status: RefreshStatus,
    /// The size of the payload held after the refresh.
    pub(crate) bytes: usize,
    /// How many nodes that payload holds.
    pub(crate) nodes: usize,
    /// Why the payload that is held contributed none of them, when the shape it
    /// was declared in is one this build does not read.
    pub(crate) unreadable: Option<Unreadable>,
}

impl Refreshed {
    fn from_plan(name: &str, plan: &RefreshPlan) -> Self {
        Self {
            name: name.to_owned(),
            status: plan.status,
            // Taken from the observation rather than from the payload report: a
            // `304` carries no report, and what an operator wants to know is
            // what is held now, not what arrived.
            bytes: plan
                .observation
                .as_ref()
                .map(|observation| observation.payload.len())
                .unwrap_or_default(),
            nodes: plan.len(),
            unreadable: plan.unreadable,
        }
    }
}

impl std::fmt::Display for Refreshed {
    /// Reported without the payload: a subscription may carry credentials, and
    /// what happened, how big it is and how many nodes it holds are what an
    /// operator needs to see.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?}, {} bytes, {} nodes",
            self.status, self.bytes, self.nodes
        )?;

        // Said out loud rather than left to "0 nodes": an operator who declared
        // a format this build cannot read has to be told which one.
        if let Some(reason) = self.unreadable {
            write!(formatter, ", unreadable: {reason}")?;
        }

        Ok(())
    }
}

/// The providers of the instance.
pub(crate) struct ProviderStore {
    /// The definitions, in the configuration directory.
    file: Persisted<ProvidersConfig>,
    /// The observations, in the data directory.
    observations: Arc<dyn ObservationStore>,
    /// Where a [`Local`](crate::provider::Local) provider's relative path is
    /// resolved from.
    config_dir: PathBuf,
    /// Bumped on every configuration change, so background work can follow the
    /// provider set instead of polling it.
    changes: watch::Sender<u64>,
    /// One lock per provider, held across a whole refresh.
    ///
    /// Serializing a refresh against another refresh of *the same* provider is
    /// what keeps the two from interleaving, which would let the slower one
    /// write its older observation last. Different providers never wait for
    /// each other.
    writers: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
}

impl ProviderStore {
    pub(crate) fn load(config_dir: &Path, data_dir: &Path) -> Result<Self, Error> {
        let observations = FileStore::open(data_dir)?;

        Self::with_observations(config_dir, Arc::new(observations))
    }

    fn with_observations(
        config_dir: &Path,
        observations: Arc<dyn ObservationStore>,
    ) -> Result<Self, Error> {
        Ok(Self {
            file: Persisted::load(config_dir, PROVIDERS_BASENAME)?,
            observations,
            config_dir: config_dir.to_path_buf(),
            changes: watch::Sender::new(0),
            writers: Mutex::new(HashMap::new()),
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

    /// How every provider's payload is declared to be read.
    ///
    /// The node index reads payloads itself, and it must read them the way they
    /// were fetched: a provider whose declared shape this build cannot read
    /// contributes nothing, and a second reading that guessed would contradict
    /// the refresh that said so.
    pub(crate) async fn formats(&self) -> BTreeMap<String, DeclaredFormat> {
        self.file
            .read(|config| {
                config
                    .providers
                    .iter()
                    .map(|(name, provider)| (name.clone(), provider.format()))
                    .collect()
            })
            .await
    }

    pub(crate) async fn get(&self, name: &str) -> Option<Provider> {
        self.file
            .read(|config| config.providers.get(name).cloned())
            .await
    }

    /// Every provider that takes part in automatic refreshing.
    ///
    /// A disabled provider is left out, and so is one there is nothing to poll
    /// for: an inline provider serves what the definition already holds, so a
    /// schedule for it would only ever re-read the same bytes.
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

    /// The payload last fetched for `name`, if there is one to serve.
    ///
    /// A provider that has never been fetched and one whose every fetch has
    /// failed are the same answer here: neither has anything to serve.
    pub(crate) async fn content(&self, name: &str) -> Result<Option<String>, Error> {
        let Some(observation) = self.observation(name).await? else {
            return Ok(None);
        };

        Ok(match observation.payload.is_empty() {
            true => None,
            false => Some(observation.payload),
        })
    }

    /// Write a definition and what was read from it, then wake the subscribers.
    ///
    /// The two writes are one step as far as a subscriber is concerned: a worker
    /// started by the change must find the observation already in place, or it
    /// would go to the network for bytes this refresh is holding.
    async fn save(
        &self,
        name: &str,
        provider: Provider,
        observation: Option<&Observation>,
    ) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        config.providers.insert(name.to_owned(), provider);
        locked.commit(config).await?;

        match observation {
            Some(observation) => self.write_observation(name, observation).await?,
            None => self.remove_observation(name).await?,
        }

        self.publish();

        Ok(())
    }

    pub(crate) async fn remove(&self, name: &str) -> Result<(), Error> {
        let _guard = self.lock(name).await;

        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        config.providers.remove(name);
        locked.commit(config).await?;

        // The payload of a provider that no longer exists would only ever be
        // read by mistake.
        self.remove_observation(name).await?;
        self.publish();

        Ok(())
    }

    /// Write `provider` as the definition stored under `name`, and adopt what it
    /// just served.
    ///
    /// The payload is read before anything is written, so a definition that
    /// cannot be read is never left behind half-configured: the operator hears
    /// about the failure and keeps what they had.
    pub(crate) async fn upsert(
        &self,
        name: &str,
        provider: Provider,
        client: &Client,
    ) -> Result<Refreshed, Error> {
        // Checked before the payload is read: a definition the store will refuse
        // must not send a request, and a caller that made a mistake should hear
        // about the mistake rather than about whatever the network said.
        provider.filter()?;

        let _guard = self.lock(name).await;

        // Nothing is asked conditionally here: whatever this hub held belonged
        // to the definition being replaced.
        let fetched = provider.fetch(client, &self.config_dir, None).await?;
        let plan = decide(
            name,
            self.observation(name).await?.as_ref(),
            fetched,
            now(),
            provider.format(),
        );

        self.save(name, provider, plan.observation.as_ref()).await?;

        Ok(Refreshed::from_plan(name, &plan))
    }

    /// Read the provider stored under `name` again and keep the result.
    ///
    /// Writers of the same provider are serialized, so a refresh triggered by
    /// the API cannot race the scheduler.
    pub(crate) async fn refresh(&self, name: &str, client: &Client) -> Result<Refreshed, Error> {
        let _guard = self.lock(name).await;

        let provider = self
            .get(name)
            .await
            .ok_or_else(|| Error::ProviderNotFound(name.to_owned()))?;
        if provider.disabled() {
            return Err(Error::ProviderDisabled(name.to_owned()));
        }

        let previous = self.observation(name).await?;
        // The validators ask "is what I hold still current", so they are sent
        // only when something is held: a `304` for a version this hub does not
        // have would cost it the payload it asked for. `conditions` answers
        // `None` for exactly that case.
        let conditions = previous.as_ref().and_then(Observation::conditions);

        let fetched = match provider.fetch(client, &self.config_dir, conditions).await {
            Ok(fetched) => fetched,
            Err(error) => {
                // The last good payload stays: it is worth more than nothing.
                // What failed is recorded beside it, and only when it is news —
                // a provider that is down for a day must not rewrite the same
                // reason on every interval.
                let reason = error.to_string();
                if let Some(observation) = record_failure(previous.as_ref(), reason, now()) {
                    self.write_observation(name, &observation).await?;
                }

                return Err(error.into());
            }
        };

        let plan = decide(name, previous.as_ref(), fetched, now(), provider.format());
        if let Some(observation) = plan.observation.as_ref() {
            self.write_observation(name, observation).await?;
        }

        Ok(Refreshed::from_plan(name, &plan))
    }

    /// The exclusive writer for one provider.
    async fn lock(&self, name: &str) -> OwnedMutexGuard<()> {
        let writer = {
            let mut writers = self
                .writers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            Arc::clone(writers.entry(name.to_owned()).or_default())
        };

        writer.lock_owned().await
    }

    /// Everything this hub holds, by provider name.
    ///
    /// One blocking call for all of them rather than a round trip per provider:
    /// a caller that needs the whole picture — assembling a collection's node
    /// view — would otherwise pay the pool's latency once per provider, for the
    /// same kind of work each time.
    pub(crate) async fn observations(&self) -> Result<BTreeMap<String, Observation>, Error> {
        let names: Vec<String> = self.list().await.into_keys().collect();
        let store = Arc::clone(&self.observations);

        Ok(
            tokio::task::spawn_blocking(move || -> Result<_, StoreError> {
                let mut held = BTreeMap::new();

                for name in names {
                    if let Some(observation) = store.read(&name)? {
                        held.insert(name, observation);
                    }
                }

                Ok(held)
            })
            .await??,
        )
    }

    /// The observation held for `name`, read off the blocking pool.
    ///
    /// The store is synchronous — it is file I/O — and this is the layer that
    /// knows a request is waiting on it.
    async fn observation(&self, name: &str) -> Result<Option<Observation>, Error> {
        let store = Arc::clone(&self.observations);
        let name = name.to_owned();

        Ok(tokio::task::spawn_blocking(move || store.read(&name)).await??)
    }

    async fn write_observation(&self, name: &str, observation: &Observation) -> Result<(), Error> {
        let store = Arc::clone(&self.observations);
        let name = name.to_owned();
        let observation = observation.clone();

        Ok(tokio::task::spawn_blocking(move || store.write(&name, &observation)).await??)
    }

    async fn remove_observation(&self, name: &str) -> Result<(), Error> {
        let store = Arc::clone(&self.observations);
        let name = name.to_owned();

        Ok(tokio::task::spawn_blocking(move || store.remove(&name)).await??)
    }
}

/// Seconds since the epoch.
///
/// Read once per refresh and passed into the decision, so one refresh is one
/// moment: a clock read twice could disagree with itself about when the same
/// refresh happened.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use crate::{
        provider::{default_interval, Inline, Local, Remote, SharedFields},
        store::{MemoryStore, StoreError},
    };

    const PAYLOAD: &str = "trojan://hunter2@example.com:443#Node\n";

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-providers-{}", uuid::Uuid::now_v7()))
    }

    fn remote() -> Provider {
        Provider::Remote(Remote {
            shared: SharedFields::default(),
            url: "https://example.com/subscription".parse().unwrap(),
            headers: None,
            timeout: None,
            interval: default_interval(),
        })
    }

    fn disabled_remote() -> Provider {
        Provider::Remote(Remote {
            shared: SharedFields {
                disabled: true,
                ..SharedFields::default()
            },
            ..match remote() {
                Provider::Remote(remote) => remote,
                _ => unreachable!("the fixture is a remote provider"),
            }
        })
    }

    fn inline(payload: &str) -> Provider {
        Provider::Inline(Inline {
            shared: SharedFields::default(),
            payload: payload.to_string(),
        })
    }

    fn local(path: &str) -> Provider {
        Provider::Local(Local {
            shared: SharedFields::default(),
            path: PathBuf::from(path),
            interval: default_interval(),
        })
    }

    fn load(dir: &Path) -> ProviderStore {
        ProviderStore::with_observations(dir, Arc::new(MemoryStore::default())).unwrap()
    }

    /// A store that counts what is written to it, so that "nothing was written"
    /// is something a test can see.
    #[derive(Default)]
    struct CountingStore {
        inner: MemoryStore,
        writes: AtomicUsize,
    }

    impl CountingStore {
        fn writes(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }
    }

    impl ObservationStore for CountingStore {
        fn read(&self, provider: &str) -> Result<Option<Observation>, StoreError> {
            self.inner.read(provider)
        }

        fn write(&self, provider: &str, observation: &Observation) -> Result<(), StoreError> {
            self.writes.fetch_add(1, Ordering::SeqCst);

            self.inner.write(provider, observation)
        }

        fn remove(&self, provider: &str) -> Result<(), StoreError> {
            self.inner.remove(provider)
        }
    }

    #[tokio::test]
    async fn providers_survive_a_reload() {
        let dir = test_dir();
        let store = load(&dir);
        assert!(store.list().await.is_empty());

        store.save("airport", remote(), None).await.unwrap();
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
        let client = Client::new();

        store
            .upsert("airport", inline(PAYLOAD), &client)
            .await
            .unwrap();
        assert!(store.content("airport").await.unwrap().is_some());

        store.remove("airport").await.unwrap();
        assert_eq!(store.content("airport").await.unwrap(), None);

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// Writing a definition without reading it leaves nothing to serve: an
    /// observation belongs to the definition it was read from.
    #[tokio::test]
    async fn a_definition_stored_without_a_fetch_serves_nothing() {
        let dir = test_dir();
        let store = load(&dir);

        store
            .upsert("airport", inline(PAYLOAD), &Client::new())
            .await
            .unwrap();
        assert!(store.content("airport").await.unwrap().is_some());

        store
            .save("airport", inline("vless://x@example.com:443#Other\n"), None)
            .await
            .unwrap();
        assert_eq!(store.content("airport").await.unwrap(), None);

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn configuration_changes_wake_subscribers() {
        let dir = test_dir();
        let store = load(&dir);
        let mut changes = store.subscribe();

        store.save("airport", remote(), None).await.unwrap();
        assert!(changes.changed().await.is_ok());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A filter that cannot be compiled is refused where it is stored.
    ///
    /// Storing it would leave a provider whose definition says one thing and
    /// whose behaviour does another; the operator would have no way to tell
    /// A payload whose declared shape this build cannot read is reported as
    /// such — and is still kept, because the bytes are the record of what the
    /// provider served and a build that can read them may come later.
    #[cfg(feature = "clash")]
    #[tokio::test]
    async fn a_refresh_says_which_shape_this_build_cannot_read() {
        let dir = test_dir();
        let store = load(&dir);
        let client = Client::new();

        let declared = Provider::Inline(Inline {
            shared: SharedFields {
                format: DeclaredFormat::Clash,
                ..SharedFields::default()
            },
            payload: PAYLOAD.to_string(),
        });
        let refreshed = store.upsert("airport", declared, &client).await.unwrap();

        assert_eq!(refreshed.nodes, 0);
        assert_eq!(refreshed.unreadable, Some(Unreadable::Clash));
        assert!(
            refreshed.to_string().contains("clash"),
            "the report names the shape rather than the body: {refreshed}"
        );
        assert!(
            store.content("airport").await.unwrap().is_some(),
            "what arrived is held even when this build reads none of it"
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// which had happened.
    #[tokio::test]
    async fn a_provider_with_an_unusable_filter_is_refused() {
        let dir = test_dir();
        let store = load(&dir);
        let client = Client::new();

        let broken = Provider::Inline(Inline {
            shared: SharedFields {
                include: vec!["regex:(".to_string()],
                ..SharedFields::default()
            },
            payload: PAYLOAD.to_string(),
        });

        assert!(matches!(
            store.upsert("airport", broken, &client).await,
            Err(Error::Filter(_))
        ));

        // Nothing was stored, and nothing was published: a refused definition
        // does not half-exist.
        assert!(store.get("airport").await.is_none());
        assert_eq!(store.content("airport").await.unwrap(), None);

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_provider_whose_filter_compiles_is_stored() {
        let dir = test_dir();
        let store = load(&dir);

        let filtered = Provider::Inline(Inline {
            shared: SharedFields {
                include: vec!["US-01".to_string(), "keyword:LAX".to_string()],
                exclude: vec!["regex:-\\d+$".to_string()],
                ..SharedFields::default()
            },
            payload: PAYLOAD.to_string(),
        });

        store
            .upsert("airport", filtered, &Client::new())
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

        store
            .save("airport", disabled_remote(), None)
            .await
            .unwrap();

        assert!(matches!(
            store.refresh("airport", &client).await,
            Err(Error::ProviderDisabled(_))
        ));
        assert!(store.refreshable().await.is_empty());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// Storing a definition reads it, and what it read is held and reported.
    #[tokio::test]
    async fn a_stored_definition_holds_what_it_just_read() {
        let dir = test_dir();
        let store = load(&dir);
        let client = Client::new();

        let stored = store
            .upsert("airport", inline(PAYLOAD), &client)
            .await
            .unwrap();

        assert_eq!(stored.status, RefreshStatus::Fetched);
        assert_eq!(stored.bytes, PAYLOAD.len());
        assert_eq!(stored.nodes, 1);
        assert_eq!(
            store.content("airport").await.unwrap().as_deref(),
            Some(PAYLOAD)
        );

        // The same bytes again are the same bytes: a refresh that read the
        // payload it already holds says so rather than rewriting it.
        let refreshed = store.refresh("airport", &client).await.unwrap();

        assert_eq!(refreshed.status, RefreshStatus::Unchanged);
        assert_eq!(refreshed.nodes, 1);
        assert_eq!(refreshed.bytes, PAYLOAD.len());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// Reading a file that did not change, twice, must be known to be the same
    /// read.
    ///
    /// This is the wiring under the decision: a refresh that forgot what it held
    /// would report every interval as a new payload and rewrite the same bytes
    /// forever.
    #[tokio::test]
    async fn a_payload_that_did_not_change_is_reported_as_unchanged() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nodes.txt"), PAYLOAD).unwrap();

        let store = load(&dir);
        let client = Client::new();
        store
            .save("airport", local("nodes.txt"), None)
            .await
            .unwrap();

        let first = store.refresh("airport", &client).await.unwrap();
        let second = store.refresh("airport", &client).await.unwrap();

        assert_eq!(first.status, RefreshStatus::Fetched);
        assert_eq!(second.status, RefreshStatus::Unchanged);
        assert_eq!(second.nodes, 1);

        // A file that did change replaces what is held, nodes and all.
        std::fs::write(
            dir.join("nodes.txt"),
            format!(
                "{PAYLOAD}vless://11111111-2222-3333-4444-555555555555@example.com:443#Other\n"
            ),
        )
        .unwrap();

        let third = store.refresh("airport", &client).await.unwrap();

        assert_eq!(third.status, RefreshStatus::Fetched);
        assert_eq!(third.nodes, 2);

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A refresh that fails keeps the payload it held, and records what went
    /// wrong beside it.
    #[tokio::test]
    async fn a_failed_refresh_keeps_the_payload_it_held() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("nodes.txt"), PAYLOAD).unwrap();

        let store = load(&dir);
        let client = Client::new();
        store
            .save("airport", local("nodes.txt"), None)
            .await
            .unwrap();
        store.refresh("airport", &client).await.unwrap();

        std::fs::remove_file(dir.join("nodes.txt")).unwrap();

        assert!(store.refresh("airport", &client).await.is_err());
        assert_eq!(
            store.content("airport").await.unwrap().as_deref(),
            Some(PAYLOAD),
            "the last good payload is worth more than nothing"
        );

        let observed = store.observation("airport").await.unwrap().unwrap();
        assert!(observed.error.is_some(), "the failure is recorded");

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// The same failure twice is not two facts.
    ///
    /// A provider that is down for a day is checked on every interval, and
    /// rewriting the same reason each time would churn the disk to say nothing.
    #[tokio::test]
    async fn a_failure_that_repeats_is_not_written_again() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap();

        let counting = Arc::new(CountingStore::default());
        let store = ProviderStore::with_observations(&dir, counting.clone()).unwrap();
        let client = Client::new();

        store
            .save("airport", local("absent.txt"), None)
            .await
            .unwrap();

        assert!(store.refresh("airport", &client).await.is_err());
        let writes = counting.writes();
        assert_eq!(writes, 1, "the first failure is news");

        assert!(store.refresh("airport", &client).await.is_err());
        assert_eq!(counting.writes(), writes, "the second one is not");

        let _ = tokio::fs::remove_dir_all(dir).await;
    }
}
