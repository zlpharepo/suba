//! The observation store kept in memory.
//!
//! It exists to keep the trait honest: it has no files, so an operation that
//! could only be expressed by writing one would not fit it. The service's tests
//! run on it when the point is the behaviour and not the layout.
//!
//! Nothing here persists, which is the whole of it: a restart on this store is
//! an empty instance.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use suba_core::Observation;

use super::{ObservationStore, StoreError};
use crate::provider::provider_name;
/// An observation store with nothing behind it.
#[derive(Default)]
pub(crate) struct MemoryStore {
    observations: Mutex<HashMap<String, Observation>>,
}

/// A poisoned lock is a panic in another thread, and this store holds no
/// invariant a panic could have broken halfway: take the value and carry on.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl ObservationStore for MemoryStore {
    fn read(&self, provider: &str) -> Result<Option<Observation>, StoreError> {
        provider_name(provider)?;

        Ok(lock(&self.observations).get(provider).cloned())
    }

    fn write(&self, provider: &str, observation: &Observation) -> Result<(), StoreError> {
        provider_name(provider)?;

        lock(&self.observations).insert(provider.to_string(), observation.clone());

        Ok(())
    }

    fn remove(&self, provider: &str) -> Result<(), StoreError> {
        provider_name(provider)?;

        lock(&self.observations).remove(provider);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(payload: &str) -> Observation {
        Observation {
            payload: payload.to_string(),
            ..Observation::default()
        }
    }

    #[test]
    fn a_store_that_was_never_written_is_empty() {
        let store = MemoryStore::default();

        assert_eq!(store.read("airport").unwrap(), None);
        store.remove("airport").unwrap();
    }

    #[test]
    fn what_goes_in_comes_back() {
        let store = MemoryStore::default();
        let stored = observation("payload");

        store.write("airport", &stored).unwrap();

        assert_eq!(store.read("airport").unwrap(), Some(stored));
    }

    #[test]
    fn writing_replaces_and_removing_forgets() {
        let store = MemoryStore::default();

        store.write("airport", &observation("first")).unwrap();
        store.write("airport", &observation("second")).unwrap();
        assert_eq!(store.read("airport").unwrap().unwrap().payload, "second");

        store.remove("airport").unwrap();
        assert_eq!(store.read("airport").unwrap(), None);
    }

    #[test]
    fn a_provider_name_that_is_a_path_is_refused() {
        let store = MemoryStore::default();

        assert!(store.read("../config").is_err());
        assert!(store.write("a/b", &observation("x")).is_err());
    }
}
