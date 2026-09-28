//! The persistence primitive shared by every store behind the server state.

use std::path::Path;

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard};

use crate::config::{read_config, write_config, ConfigError};

/// A value mirrored to a file inside the configuration directory.
///
/// Writes go through [`Locked::commit`]: the next value is written to disk
/// first and only then adopted in memory, so the process never serves data
/// that failed to persist.
pub(crate) struct Persisted<T> {
    /// Configuration directory, kept as the caller provided it.
    base: String,
    /// File name inside `base`, without the format extension.
    name: &'static str,
    /// Current value.
    value: Mutex<T>,
}

impl<T> Persisted<T>
where
    T: for<'de> Deserialize<'de> + Default,
{
    /// Load the value, falling back to [`Default`] when the file is missing or
    /// empty.
    pub(crate) fn load(base: &Path, name: &'static str) -> Result<Self, ConfigError> {
        let base = base.to_string_lossy().into_owned();
        let value = read_config(&base, name)?;

        Ok(Self {
            base,
            name,
            value: Mutex::new(value),
        })
    }
}

impl<T> Persisted<T> {
    /// Inspect the value without cloning it.
    pub(crate) async fn read<R>(&self, inspect: impl FnOnce(&T) -> R) -> R {
        let value = self.value.lock().await;
        inspect(&value)
    }

    /// Lock the value for a read-modify-write that no other writer can
    /// interleave with.
    ///
    /// The lock is held until [`Locked::commit`] returns, which is what keeps
    /// concurrent writers from committing a snapshot taken before their
    /// change.
    pub(crate) async fn lock(&self) -> Locked<'_, T> {
        Locked {
            store: self,
            value: self.value.lock().await,
        }
    }
}

impl<T> Persisted<T>
where
    T: Serialize,
{
    /// Persist `value` to the backing file.
    async fn write(&self, value: &T) -> Result<(), ConfigError> {
        write_config(&self.base, self.name, value).await
    }
}

/// A write lock over a [`Persisted`] value.
pub(crate) struct Locked<'a, T> {
    store: &'a Persisted<T>,
    value: MutexGuard<'a, T>,
}

impl<T> Locked<'_, T> {
    /// The current value, to derive the next one from.
    pub(crate) fn get(&self) -> &T {
        &self.value
    }
}

impl<T> Locked<'_, T>
where
    T: Serialize,
{
    /// Persist `next` and adopt it as the current value.
    ///
    /// Nothing changes in memory when the write fails.
    pub(crate) async fn commit(mut self, next: T) -> Result<(), ConfigError> {
        self.store.write(&next).await?;
        *self.value = next;

        Ok(())
    }
}
