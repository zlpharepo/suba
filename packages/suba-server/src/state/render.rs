//! Rendered artifacts, remembered by the content they were made from.
//!
//! A render is a pure function of things that are already in memory, so what
//! remembering one buys is not correctness but the second subscriber: the same
//! collection, over the same payloads, in the same format produces the same
//! bytes, and producing them again would walk every node of every payload again.
//! The key is a content address — the collection's bytes, each contributing
//! definition's bytes, the hash each payload was fetched at, and the format — so
//! an edit, a refresh or a format change misses, and a request that changes
//! nothing hits.
//!
//! Nothing here is written down (I3). What is remembered is derived from the
//! payloads, and the derived things that get written to disk are the ones that
//! go stale.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use suba_core::Format;

/// How many artifacts are kept.
///
/// A collection is asked for repeatedly by everyone subscribed to it, and the
/// ones next to each other in time are the ones worth keeping. The limit is what
/// keeps a memo from becoming the instance's memory.
const LIMIT: usize = 16;

/// The artifacts rendered so far, most recent last.
pub(crate) struct RenderMemo {
    entries: Mutex<Entries>,
}

#[derive(Default)]
struct Entries {
    bodies: HashMap<String, Arc<Artifact>>,
    /// Oldest first, which is the one dropped when the limit is reached.
    order: VecDeque<String>,
}

/// An artifact, and what it is worth telling a caller about it.
#[derive(Debug)]
pub(crate) struct Artifact {
    pub(crate) body: Arc<str>,
    /// The format the body is written in, as the request chose it.
    pub(crate) format: Format,
    /// How many nodes the body holds.
    pub(crate) nodes: usize,
    /// How many nodes the format could not write.
    pub(crate) skipped: usize,
    /// How often a client should ask again, in hours: the shortest refresh
    /// interval among the providers, or `None` when none refreshes by itself.
    pub(crate) update_hours: Option<u64>,
}

impl RenderMemo {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(Entries::default()),
        }
    }

    /// The artifact that was rendered from this content before, if it is here.
    pub(crate) fn get(&self, key: &str) -> Option<Arc<Artifact>> {
        self.lock().bodies.get(key).cloned()
    }

    /// Remember an artifact under the content it was made from.
    pub(crate) fn put(&self, key: String, artifact: Arc<Artifact>) {
        let mut entries = self.lock();

        if entries.bodies.insert(key.clone(), artifact).is_none() {
            entries.order.push_back(key);
        }

        while entries.order.len() > LIMIT {
            if let Some(oldest) = entries.order.pop_front() {
                entries.bodies.remove(&oldest);
            }
        }
    }

    /// How many artifacts are held. Used by tests, and by nothing else.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().bodies.len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Entries> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(body: &str) -> Arc<Artifact> {
        Arc::new(Artifact {
            body: Arc::from(body),
            format: Format::Links,
            nodes: 1,
            skipped: 0,
            update_hours: None,
        })
    }

    #[test]
    fn the_same_key_gets_the_same_artifact_back() {
        let memo = RenderMemo::new();

        assert!(memo.get("a").is_none());
        memo.put("a".to_string(), artifact("first"));

        assert_eq!(&*memo.get("a").unwrap().body, "first");
        assert!(memo.get("b").is_none());
    }

    #[test]
    fn remembering_the_same_key_again_replaces_it_without_growing() {
        let memo = RenderMemo::new();

        memo.put("a".to_string(), artifact("first"));
        memo.put("a".to_string(), artifact("second"));

        assert_eq!(&*memo.get("a").unwrap().body, "second");
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn the_oldest_goes_when_the_limit_is_reached() {
        let memo = RenderMemo::new();

        for index in 0..LIMIT {
            memo.put(format!("key-{index}"), artifact("body"));
        }
        assert_eq!(memo.len(), LIMIT);

        memo.put("one-more".to_string(), artifact("body"));

        assert_eq!(memo.len(), LIMIT);
        assert!(memo.get("key-0").is_none(), "the oldest is the one dropped");
        assert!(memo.get("one-more").is_some());
        assert!(memo.get(&format!("key-{}", LIMIT - 1)).is_some());
    }
}
