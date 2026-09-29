use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::config::ConfigError;

/// File name prefix and suffix of a cached subscription, wrapped around the
/// provider name.
const CACHE_PREFIX: &str = "provider-";
const CACHE_EXTENSION: &str = "cache";

/// The raw payloads of providers, mirrored to the data directory.
///
/// The bytes are kept verbatim: parsing is the job of whatever consumes the
/// subscription next, so an upstream format the server does not understand is
/// still cached faithfully.
///
/// Every provider maps to a single file, so a reader never needs the store
/// itself; a write goes through [`CacheStore::lock`] to keep two refreshes of
/// the same provider from interleaving.
pub(crate) struct CacheStore {
    dir: PathBuf,
    /// Per-provider write locks, created on first use and kept for the life of
    /// the process so a lock can never be dropped while a writer still holds
    /// it.
    locks: Mutex<HashMap<String, std::sync::Arc<Mutex<()>>>>,
}

impl CacheStore {
    /// The cache directory inside `data_dir`.
    ///
    /// Nothing is touched on disk: the directory is created by the first
    /// write, so simply building the state stays free of side effects.
    pub(crate) fn load(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join("caches"),
            locks: Mutex::new(HashMap::new()),
        }
    }

    /// The payload cached for `name`, if any.
    ///
    /// A missing file is not an error: it simply means the provider has not
    /// been fetched yet.
    pub(crate) async fn content(&self, name: &str) -> Result<Option<String>, ConfigError> {
        match tokio::fs::read_to_string(self.path(name)).await {
            Ok(content) => Ok(Some(content)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Serialize writers of the same provider.
    ///
    /// The returned guard owns a reference to the lock, so the entry stays
    /// alive for as long as any writer may still hold it.
    pub(crate) async fn lock(&self, name: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().await;
            locks
                .entry(name.to_owned())
                .or_insert_with(|| std::sync::Arc::new(Mutex::new(())))
                .clone()
        };
        lock.lock_owned().await
    }

    /// Store `content` for `name`, written atomically.
    pub(crate) async fn put(&self, name: &str, content: &str) -> Result<(), ConfigError> {
        let destination = self.path(name);
        tokio::fs::create_dir_all(&self.dir).await?;

        let temporary =
            destination.with_extension(format!("{CACHE_EXTENSION}.{}.tmp", uuid::Uuid::now_v7()));
        if let Err(error) = write_atomically(&temporary, &destination, content.as_bytes()).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }

        Ok(())
    }

    /// Forget the payload cached for `name`, if any.
    pub(crate) async fn remove(&self, name: &str) -> Result<(), ConfigError> {
        match tokio::fs::remove_file(self.path(name)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir
            .join(format!("{CACHE_PREFIX}{name}.{CACHE_EXTENSION}"))
    }
}

async fn write_atomically(
    temporary: &Path,
    destination: &Path,
    content: &[u8],
) -> Result<(), ConfigError> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .await?;
    file.write_all(content).await?;
    file.sync_all().await?;
    drop(file);

    tokio::fs::rename(temporary, destination).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-caches-{}", uuid::Uuid::now_v7()))
    }

    #[tokio::test]
    async fn cached_content_survives_a_reload() {
        let dir = test_dir();
        let store = CacheStore::load(&dir);
        assert_eq!(store.content("airport").await.unwrap(), None);

        store.put("airport", "proxies: []").await.unwrap();
        assert_eq!(
            store.content("airport").await.unwrap().as_deref(),
            Some("proxies: []")
        );

        let reloaded = CacheStore::load(&dir);
        assert_eq!(
            reloaded.content("airport").await.unwrap().as_deref(),
            Some("proxies: []")
        );

        reloaded.remove("airport").await.unwrap();
        assert_eq!(reloaded.content("airport").await.unwrap(), None);
        reloaded.remove("airport").await.unwrap();

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn provider_names_do_not_collide() {
        let dir = test_dir();
        let store = CacheStore::load(&dir);

        store.put("US.LAX", "west").await.unwrap();
        store.put("US.LAX.443", "west-tls").await.unwrap();

        assert_eq!(
            store.content("US.LAX").await.unwrap().as_deref(),
            Some("west")
        );
        assert_eq!(
            store.content("US.LAX.443").await.unwrap().as_deref(),
            Some("west-tls")
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
