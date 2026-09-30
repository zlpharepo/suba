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

use getrandom::fill;
use serde::{Deserialize, Serialize};
use suba_core::checksum::sha256_hex;
use suba_core::Collection;

use crate::{config::ConfigError, error::Error};

use super::persisted::Persisted;

/// How many random bytes a delivery token is made of.
///
/// A URL that hands out a subscription is a credential, so it is drawn from the
/// operating system's entropy and long enough that guessing is not a strategy.
const TOKEN_BYTES: usize = 32;

/// The longest name a token can be given.
const TOKEN_NAME_MAX: usize = 64;
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

    /// The names of a collection's delivery tokens.
    pub(crate) async fn tokens(&self, name: &str) -> Result<Vec<String>, Error> {
        self.file
            .read(|config| {
                config
                    .collections
                    .get(name)
                    .map(|collection| collection.tokens.keys().cloned().collect())
            })
            .await
            .ok_or_else(|| Error::CollectionNotFound(name.to_owned()))
    }

    /// Give `name` a delivery token called `label`, and answer the token itself.
    ///
    /// Minting under a label that exists replaces that token, which is how a
    /// leaked one is taken out of service; the collection's other tokens keep
    /// working. The token is answered once and only its hash is stored, so this
    /// call is the only chance to read it.
    pub(crate) async fn mint_token(&self, name: &str, label: &str) -> Result<String, Error> {
        token_name(label)?;

        let mut bytes = [0u8; TOKEN_BYTES];
        fill(&mut bytes).map_err(|error| Error::Entropy(error.to_string()))?;

        let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let hash = sha256_hex(token.as_bytes());

        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        let collection = config
            .collections
            .get_mut(name)
            .ok_or_else(|| Error::CollectionNotFound(name.to_owned()))?;

        collection.tokens.insert(label.to_owned(), hash);
        locked.commit(config).await?;

        Ok(token)
    }

    /// Take one of the collection's delivery tokens out of service.
    ///
    /// A token that does not exist is not an error: revoking is asked for by
    /// the state the caller wants to be in, not by the state it found.
    pub(crate) async fn revoke_token(&self, name: &str, label: &str) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        let collection = config
            .collections
            .get_mut(name)
            .ok_or_else(|| Error::CollectionNotFound(name.to_owned()))?;

        if collection.tokens.remove(label).is_some() {
            locked.commit(config).await?;
        }

        Ok(())
    }

    /// The collection a token addresses and the token's name, in that order.
    ///
    /// Compared as hashes: what a caller holds is the token, and what is stored
    /// is the hash of it, so a comparison that is not constant time leaks bits
    /// of a value the caller cannot use.
    pub(crate) async fn by_token(&self, token: &str) -> Option<(String, String)> {
        let hash = sha256_hex(token.as_bytes());

        self.file
            .read(|config| {
                config.collections.iter().find_map(|(name, collection)| {
                    collection
                        .tokens
                        .iter()
                        .find(|(_, held)| **held == hash)
                        .map(|(label, _)| (name.clone(), label.clone()))
                })
            })
            .await
    }
}

/// Refuse a token name that could not be told apart in a URL or a log line.
fn token_name(label: &str) -> Result<(), Error> {
    let usable = !label.is_empty()
        && label.len() <= TOKEN_NAME_MAX
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));

    match usable {
        true => Ok(()),
        false => Err(Error::TokenName {
            reason: "a name is 1 to 64 letters, digits, '.', '_' or '-'",
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use suba_core::Format;

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
            includes: vec![suba_core::Pattern::Regex("(".to_string())],
            ..Collection::default()
        };

        assert!(matches!(
            store.insert("main", broken).await,
            Err(Error::Filter(_))
        ));
        assert!(store.get("main").await.is_none());

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    /// What is written down is a hash, never the token itself: a copied
    /// configuration file is not a set of working subscription URLs.
    #[tokio::test]
    async fn a_token_is_stored_as_a_hash() {
        let dir = scratch("token");
        let store = load(&dir);
        store
            .insert("main", collection(&["airport"]))
            .await
            .unwrap();

        let token = store.mint_token("main", "phone").await.unwrap();
        let written = std::fs::read_to_string(config_path(&dir, COLLECTIONS_BASENAME)).unwrap();

        assert!(!written.contains(&token), "the token itself: {written}");
        assert!(
            written.contains(&sha256_hex(token.as_bytes())),
            "the hash of it: {written}"
        );
        assert_eq!(
            store.by_token(&token).await.unwrap(),
            ("main".to_string(), "phone".to_string())
        );
        assert!(store.by_token("not-a-token").await.is_none());

        store.revoke_token("main", "phone").await.unwrap();

        assert!(store.by_token(&token).await.is_none());
        let written = std::fs::read_to_string(config_path(&dir, COLLECTIONS_BASENAME)).unwrap();
        assert!(!written.contains("tokens"), "{written}");

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A collection nobody has minted a token for is not an error to revoke.
    #[tokio::test]
    async fn revoking_a_token_that_was_never_minted_is_nothing() {
        let dir = scratch("no-token");
        let store = load(&dir);
        store.insert("main", collection(&[])).await.unwrap();

        store.revoke_token("main", "phone").await.unwrap();

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// Each token is its own: revoking one leaves the others serving, and
    /// minting under a name that exists rotates only that one.
    #[tokio::test]
    async fn one_token_is_revoked_without_the_others() {
        let dir = scratch("tokens");
        let store = load(&dir);
        store.insert("main", collection(&[])).await.unwrap();

        let phone = store.mint_token("main", "phone").await.unwrap();
        let laptop = store.mint_token("main", "laptop").await.unwrap();
        assert_eq!(store.tokens("main").await.unwrap(), ["laptop", "phone"]);

        store.revoke_token("main", "phone").await.unwrap();
        assert!(store.by_token(&phone).await.is_none());
        assert!(store.by_token(&laptop).await.is_some());

        let rotated = store.mint_token("main", "laptop").await.unwrap();
        assert!(store.by_token(&laptop).await.is_none());
        assert!(store.by_token(&rotated).await.is_some());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn a_token_name_is_a_plain_word() {
        let dir = scratch("token-names");
        let store = load(&dir);
        store.insert("main", collection(&[])).await.unwrap();

        for bad in ["", "a b", "a/b", &"x".repeat(65)] {
            assert!(
                matches!(
                    store.mint_token("main", bad).await,
                    Err(Error::TokenName { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(store.tokens("main").await.unwrap().is_empty());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// The format a collection declares survives the document, and the default
    /// is left unsaid.
    #[tokio::test]
    async fn the_default_format_is_not_written_down() {
        let dir = scratch("format-default");
        let store = load(&dir);

        store
            .insert("main", collection(&["airport"]))
            .await
            .unwrap();

        let written = std::fs::read_to_string(config_path(&dir, COLLECTIONS_BASENAME)).unwrap();
        assert!(
            !written.contains("format"),
            "base64 is what a subscription is, and saying so adds nothing: {written}"
        );
        assert_eq!(
            load(&dir).get("main").await.unwrap().format,
            Format::Base64,
            "and reading it back gives the default"
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    /// A declared format is written, and comes back.
    #[cfg(feature = "clash")]
    #[tokio::test]
    async fn a_collection_keeps_the_format_it_declares() {
        let dir = scratch("format");
        let store = load(&dir);

        store
            .insert(
                "main",
                Collection {
                    format: Format::Clash,
                    ..collection(&["airport"])
                },
            )
            .await
            .unwrap();

        let written = std::fs::read_to_string(config_path(&dir, COLLECTIONS_BASENAME)).unwrap();
        assert!(written.contains("clash"), "{written}");
        assert_eq!(
            load(&dir).get("main").await.unwrap().format,
            Format::Clash,
            "in either notation"
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
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
                    includes: vec![suba_core::Pattern::Keyword("US".to_string())],
                    excludes: vec![suba_core::Pattern::Keyword("LAX".to_string())],
                    ..Collection::default()
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
