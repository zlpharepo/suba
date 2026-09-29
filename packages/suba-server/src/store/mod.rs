//! Where the running instance keeps what it observed.
//!
//! This is the **data** directory: everything here is written by the program and
//! never by a person, which is the line that separates it from the
//! configuration directory — that one holds documents the operator authors.
//!
//! ```text
//! suba.lock               the single-writer lock
//! providers/<name>.json   one observation per provider
//! ```
//!
//! One provider, one file, replaced whole. That is the entire durability story:
//! there is no multi-file change to reconcile, so there is nothing a manifest
//! could detect and nothing a generation could fence. A crash leaves each file
//! holding an older complete observation or a newer one.
//!
//! The observations are JSON whichever configuration format is compiled in: the
//! `toml`/`json` feature picks the notation of the documents an operator writes
//! and may hand-edit. Nothing here is hand-edited, so there is no reason to
//! carry two notations of it.

mod file;
#[cfg(test)]
mod memory;

pub(crate) use file::FileStore;
#[cfg(test)]
pub(crate) use memory::MemoryStore;

use std::io;

use suba_core::Observation;

/// A store operation failed.
///
/// It fails the way files fail. What a client is told about a failure belongs
/// to the layer that reports it, not to the store, so nothing here decides a
/// status code.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Another process holds the data directory.
    #[error(
        "the data directory is already open in another process{}",
        .pid.map(|pid| format!(" (pid {pid})")).unwrap_or_default()
    )]
    Locked { pid: Option<u32> },
}

/// What the instance keeps between requests.
///
/// Synchronous on purpose: the work is file I/O and it blocks. The caller that
/// must not block — an HTTP handler — is the one that knows it and hands the
/// call to a blocking pool. A store that returned futures would put an async
/// runtime under a layer whose whole point is to be a small set of documents.
pub(crate) trait ObservationStore: Send + Sync + 'static {
    /// The observation held for `provider`, if any.
    ///
    /// A provider that has never been fetched is not an error: it has nothing to
    /// say yet, which is different from failing to say it.
    fn read(&self, provider: &str) -> Result<Option<Observation>, StoreError>;

    /// Replace the observation held for `provider`.
    fn write(&self, provider: &str, observation: &Observation) -> Result<(), StoreError>;

    /// Forget the observation held for `provider`.
    ///
    /// Removing what is not there is not a failure: the caller is getting rid of
    /// a provider, and one that was never fetched is already gone.
    fn remove(&self, provider: &str) -> Result<(), StoreError>;
}
