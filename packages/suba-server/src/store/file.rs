//! The observation store as a directory of files.
//!
//! ```text
//! suba.lock               the single-writer lock
//! providers/<name>.json   one observation per provider
//! ```
//!
//! Every write is one file and one atomic rename ([`crate::fs`]), so a crash
//! leaves a file whole or absent and never half-written. The lock exists because
//! two processes writing the same directory corrupt each other in ways nobody
//! can debug afterwards — and it is cheap to prevent.

use std::{
    fs::File,
    io::{self, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

use rustix::fs::FlockOperation;
use suba_core::Observation;

use super::{ObservationStore, StoreError};
use crate::{
    fs as disk,
    provider::{provider_name, PROVIDERS_BASENAME},
};

/// The single-writer lock, inside the data directory.
const LOCK: &str = "suba.lock";
/// The directory holding one observation per provider.
const OBSERVATIONS: &str = PROVIDERS_BASENAME;

/// The store as a directory of files.
pub(crate) struct FileStore {
    root: PathBuf,
    /// Held open for as long as the store is: dropping it releases the lock.
    /// Never read, which is the point — holding it is the whole behaviour.
    _lock: File,
}

impl FileStore {
    /// Open the data directory, creating what is missing.
    ///
    /// A directory another process holds is refused, by name. The lock is
    /// released by the operating system when the holder exits, so a crash does
    /// not leave a directory that can never be opened again.
    pub(crate) fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();

        // Through the same trusted-directory check as every other write, so the
        // data directory cannot be a place another user can put files.
        disk::ensure_dir(&root)?;
        disk::ensure_dir(root.join(OBSERVATIONS))?;

        let lock = take_lock(&root.join(LOCK))?;

        Ok(Self { root, _lock: lock })
    }

    /// The file one provider's observation lives in.
    fn name(provider: &str) -> String {
        format!("{provider}.json")
    }
}

impl ObservationStore for FileStore {
    fn read(&self, provider: &str) -> Result<Option<Observation>, StoreError> {
        // The name is checked for being a name before it becomes a filename:
        // it arrives from a URL path segment, where `%2F` decodes to a
        // separator.
        provider_name(provider)?;

        let dir = self.root.join(OBSERVATIONS);
        let file = Self::name(provider);

        let Some(document) = disk::read_to_string(&dir, &file)? else {
            return Ok(None);
        };

        serde_json::from_str(&document).map(Some).map_err(|error| {
            // A document that cannot be read is reported rather than taken as
            // "nothing was observed": the caller must not fetch again and
            // overwrite a payload that a new build could read.
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}: {error}", dir.join(&file).display()),
            )
            .into()
        })
    }

    fn write(&self, provider: &str, observation: &Observation) -> Result<(), StoreError> {
        provider_name(provider)?;

        let document = serde_json::to_vec_pretty(observation)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        disk::write_atomic(
            &self.root.join(OBSERVATIONS),
            &Self::name(provider),
            document,
        )?;

        Ok(())
    }

    fn remove(&self, provider: &str) -> Result<(), StoreError> {
        provider_name(provider)?;

        disk::remove(&self.root.join(OBSERVATIONS), &Self::name(provider))?;

        Ok(())
    }
}

/// Take the lock, or say which process holds it.
///
/// Advisory, and held by the open file, so it is released by the operating
/// system when the holder exits. The pid written into it is for the operator:
/// the lock is the lock, the pid is who to look for.
fn take_lock(path: &Path) -> Result<File, StoreError> {
    let mut file = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;

    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            return Err(StoreError::Locked {
                pid: lock_holder(&mut file),
            })
        }
        Err(error) => return Err(io::Error::from_raw_os_error(error.raw_os_error()).into()),
    }

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(std::process::id().to_string().as_bytes())?;
    file.sync_all()?;

    Ok(file)
}

/// The pid the holder wrote, if it is readable.
fn lock_holder(file: &mut File) -> Option<u32> {
    let mut content = String::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_to_string(&mut content).ok()?;

    content.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("suba-store-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        dir
    }

    fn observation(payload: &str) -> Observation {
        Observation {
            payload: payload.to_string(),
            fetched_at: Some(1_700_000_000),
            content_hash: Some("abc".to_string()),
            sighting: std::collections::BTreeMap::from([(
                suba_core::proto::NodeFingerprint::parse("00000000000000000000000000000001")
                    .expect("a fingerprint"),
                1_700_000_000,
            )]),
            ..Observation::default()
        }
    }

    #[test]
    fn a_second_holder_is_refused_and_the_pid_is_named() {
        let dir = scratch("lock-refused");
        disk::ensure_dir(&dir).unwrap();
        let path = dir.join(LOCK);

        let _held = take_lock(&path).expect("the first holder");
        let refused = take_lock(&path).expect_err("the second holder");

        match refused {
            StoreError::Locked { pid } => assert_eq!(pid, Some(std::process::id())),
            other => panic!("expected a locked store, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_lock_goes_away_with_the_holder() {
        let dir = scratch("lock-released");
        disk::ensure_dir(&dir).unwrap();
        let path = dir.join(LOCK);

        {
            let _held = take_lock(&path).expect("the first holder");
        }

        // Released by dropping the file, so a restart is not blocked by the
        // process that just stopped.
        take_lock(&path).expect("the lock is free again");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_provider_that_was_never_fetched_has_no_observation() {
        let dir = scratch("absent");
        let store = FileStore::open(&dir).unwrap();

        assert_eq!(store.read("airport").unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_observation_survives_being_closed() {
        let dir = scratch("survives");
        let stored = observation("trojan://hunter2@example.com:443#Node\n");

        {
            let store = FileStore::open(&dir).unwrap();
            store.write("airport", &stored).unwrap();
        }

        let reopened = FileStore::open(&dir).unwrap();

        assert_eq!(reopened.read("airport").unwrap(), Some(stored));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writing_replaces_what_was_there() {
        let dir = scratch("replace");
        let store = FileStore::open(&dir).unwrap();

        store.write("airport", &observation("first")).unwrap();
        store.write("airport", &observation("second")).unwrap();

        assert_eq!(
            store.read("airport").unwrap().unwrap().payload,
            "second",
            "one provider, one document"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_what_was_never_written_is_not_a_failure() {
        let dir = scratch("remove-absent");
        let store = FileStore::open(&dir).unwrap();

        store.remove("airport").unwrap();
        store.write("airport", &observation("x")).unwrap();
        store.remove("airport").unwrap();
        store.remove("airport").unwrap();

        assert_eq!(store.read("airport").unwrap(), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A provider name arrives from a URL path segment, so it is a name or it
    /// is refused — never a way out of the observations directory.
    #[test]
    fn a_provider_name_that_is_a_path_is_refused() {
        let dir = scratch("escape");
        let store = FileStore::open(&dir).unwrap();

        for name in ["../config", "a/b", "..", ""] {
            assert!(store.read(name).is_err(), "read accepted {name:?}");
            assert!(
                store.write(name, &observation("x")).is_err(),
                "write accepted {name:?}"
            );
            assert!(store.remove(name).is_err(), "remove accepted {name:?}");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_document_that_cannot_be_read_is_reported_rather_than_taken_as_nothing() {
        let dir = scratch("corrupt");
        let store = FileStore::open(&dir).unwrap();
        std::fs::write(dir.join(OBSERVATIONS).join("airport.json"), "{not json").unwrap();

        let error = store
            .read("airport")
            .expect_err("a corrupt document is an error");

        assert!(
            matches!(error, StoreError::Io(ref io_error) if io_error.kind() == io::ErrorKind::InvalidData),
            "{error:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
