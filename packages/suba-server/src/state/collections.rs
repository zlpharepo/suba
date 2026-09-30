//! The collections of the instance: named subscriptions assembled from
//! providers.
//!
//! A collection is a document an operator writes, like a provider definition,
//! and it lives in the configuration directory beside them. It holds no state of
//! its own: what it resolves to is computed from the providers' observations, so
//! there is nothing here to keep in step with a refresh.
//!
//! A collection naming a provider that does not exist is **stored anyway**. The
//! order two documents are written in is not something an operator should have
//! to think about, and refusing the collection would make it one; what a name
//! with no definition means is reported when the collection is resolved
//! ([`suba_core::Resolved::unresolved`]) rather than at the moment it is typed.

use std::{collections::HashMap, path::Path};

use serde::{Deserialize, Serialize};
use suba_core::Collection;

use crate::{config::ConfigError, error::Error};

use super::persisted::Persisted;
/// The file the collection definitions live in, without the format extension.
pub(crate) const COLLECTIONS_BASENAME: &str = "collections";

/// The document every collection definition is stored in, keyed by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CollectionsConfig {
    #[serde(flatten)]
    pub collections: HashMap<String, Collection>,
}

/// The collections of the instance.
pub(crate) struct CollectionStore {
    file: Persisted<CollectionsConfig>,
}

impl CollectionStore {
    pub(crate) fn load(config_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            file: Persisted::load(config_dir, COLLECTIONS_BASENAME)?,
        })
    }

    pub(crate) async fn list(&self) -> HashMap<String, Collection> {
        self.file.read(|config| config.collections.clone()).await
    }

    pub(crate) async fn get(&self, name: &str) -> Option<Collection> {
        self.file
            .read(|config| config.collections.get(name).cloned())
            .await
    }

    /// Store a definition under `name`, replacing what was there.
    ///
    /// The collection's own filter is compiled first: a pattern that cannot be
    /// used would otherwise be stored and fail on every request instead, which
    /// is the same mistake discovered late and repeatedly.
    pub(crate) async fn insert(&self, name: &str, collection: Collection) -> Result<(), Error> {
        collection.filter()?;

        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        config.collections.insert(name.to_owned(), collection);
        locked.commit(config).await?;

        Ok(())
    }

    pub(crate) async fn remove(&self, name: &str) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        config.collections.remove(name);
        locked.commit(config).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{config_path, read_config, APP_CONFIG_BASENAME};
    use crate::provider::PROVIDERS_BASENAME;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("suba-collections-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        dir
    }

    fn collection(providers: &[&str]) -> Collection {
        Collection {
            providers: providers.iter().map(|name| name.to_string()).collect(),
            ..Collection::default()
        }
    }

    fn load(dir: &Path) -> CollectionStore {
        CollectionStore::load(dir).unwrap()
    }

    #[tokio::test]
    async fn collections_survive_a_reload() {
        let dir = scratch("reload");
        let store = load(&dir);
        assert!(store.list().await.is_empty());

        store
            .insert("main", collection(&["airport"]))
            .await
            .unwrap();
        assert!(store.get("main").await.is_some());

        let reloaded = load(&dir);
        assert_eq!(reloaded.get("main").await.unwrap().providers, ["airport"]);

        reloaded.remove("main").await.unwrap();
        assert!(reloaded.get("main").await.is_none());
        assert!(load(&dir).get("main").await.is_none());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A collection document lives in its own file: its name is not one of the
    /// instance's other documents.
    #[tokio::test]
    async fn a_collection_document_does_not_share_a_file_with_the_others() {
        let dir = scratch("separate-files");

        load(&dir).insert("main", collection(&[])).await.unwrap();

        assert!(config_path(&dir, COLLECTIONS_BASENAME).is_file());
        assert!(!config_path(&dir, PROVIDERS_BASENAME).exists());
        assert!(!config_path(&dir, APP_CONFIG_BASENAME).exists());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A pattern that cannot be compiled is refused where it is stored.
    #[tokio::test]
    async fn a_collection_with_an_unusable_filter_is_refused() {
        let dir = scratch("broken-filter");
        let store = load(&dir);

        let broken = Collection {
            providers: vec!["airport".to_string()],
            includes: vec!["regex:(".to_string()],
            excludes: Vec::new(),
        };

        assert!(matches!(
            store.insert("main", broken).await,
            Err(Error::Filter(_))
        ));
        assert!(store.get("main").await.is_none());

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    /// The two lists are written under the names an operator edits.
    #[tokio::test]
    async fn the_two_lists_are_written_under_their_own_names() {
        let dir = scratch("list-names");
        let store = load(&dir);

        store
            .insert(
                "main",
                Collection {
                    providers: vec!["airport".to_string()],
                    includes: vec!["keyword:US".to_string()],
                    excludes: vec!["keyword:LAX".to_string()],
                },
            )
            .await
            .unwrap();

        let written = std::fs::read_to_string(config_path(&dir, COLLECTIONS_BASENAME)).unwrap();

        assert!(written.contains("includes"), "{written}");
        assert!(written.contains("excludes"), "{written}");

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A collection naming a provider that does not exist is still stored: what
    /// that means is reported when it is resolved, not when it is written.
    #[tokio::test]
    async fn a_provider_that_does_not_exist_yet_is_not_a_reason_to_refuse() {
        let dir = scratch("unknown-provider");
        let store = load(&dir);

        store
            .insert("main", collection(&["not-written-yet"]))
            .await
            .unwrap();

        assert_eq!(
            store.get("main").await.unwrap().providers,
            ["not-written-yet"]
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn missing_collections_load_as_defaults() {
        let dir = scratch("absent");

        assert!(load(&dir).list().await.is_empty());
        let loaded: CollectionsConfig =
            read_config(dir.to_str().unwrap(), COLLECTIONS_BASENAME).unwrap();
        assert!(loaded.collections.is_empty());
    }

    /// Removing the last collection leaves an empty document, and an empty
    /// document is one the next start has to read back as none.
    #[tokio::test]
    async fn an_empty_document_reads_back_as_no_collections() {
        let dir = scratch("empty-document");
        let store = load(&dir);

        store
            .insert("main", collection(&["airport"]))
            .await
            .unwrap();
        store.remove("main").await.unwrap();

        assert!(load(&dir).list().await.is_empty());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
