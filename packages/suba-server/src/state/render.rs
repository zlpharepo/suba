//! Rendered artifacts, remembered by the content they were made from.
//!
//! A render is a pure function of things that are already in memory, so what
//! remembering one buys is not correctness but the second subscriber: the same
//! collection, over the same payloads, in the same target produces the same
//! bytes, and producing them again would walk every node of every payload again.
//! The key is a content address — the collection's bytes, each contributing
//! render settings, the last hash of each payload, and the target. Requests
//! that share an address also share an in-flight render.
//!
//! Nothing here is written down (I3). What is remembered is derived from the
//! payloads, and the derived things that get written to disk are the ones that
//! go stale.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex},
};

use axum::body::Bytes;
use futures_util::future::{FutureExt, Shared};
use suba_core::Target;
use tokio::sync::{oneshot, Semaphore, SemaphorePermit};

use crate::error::{Error, HttpError, IntoHttpError};

/// How many artifacts are kept.
///
/// A collection is asked for repeatedly by everyone subscribed to it, and the
/// ones next to each other in time are the ones worth keeping. The limit is what
/// keeps a memo from becoming the instance's memory.
const LIMIT: usize = 16;
const BYTE_LIMIT: usize = 32 * 1024 * 1024;
const CONCURRENT_JOBS: usize = 2;

type RenderResult = Result<Arc<Artifact>, HttpError>;
type Flight = Shared<oneshot::Receiver<RenderResult>>;

/// The artifacts rendered so far, most recent last.
pub(crate) struct RenderMemo {
    entries: Arc<Mutex<Entries>>,
    jobs: Semaphore,
}

#[derive(Default)]
struct Entries {
    bodies: HashMap<String, Arc<Artifact>>,
    flights: HashMap<String, Flight>,
    bytes: usize,
    /// Oldest first, which is the one dropped when the limit is reached.
    order: VecDeque<String>,
}

/// An artifact, and what it is worth telling a caller about it.
#[derive(Debug)]
pub(crate) struct Artifact {
    pub(crate) body: Bytes,
    /// The conversion target selected by the request.
    pub(crate) target: Target,
    /// How many nodes the body holds.
    pub(crate) nodes: usize,
    /// How many nodes the target could not write.
    pub(crate) skipped: usize,
    /// How often a client should ask again, in hours: the shortest refresh
    /// interval among the providers, or `None` when none refreshes by itself.
    pub(crate) update_hours: Option<u64>,
}

impl RenderMemo {
    pub(crate) fn new() -> Self {
        Self {
            entries: Arc::default(),
            jobs: Semaphore::new(CONCURRENT_JOBS),
        }
    }

    /// Admit expensive subscription work before loading its payloads.
    pub(crate) async fn admit(&self) -> SemaphorePermit<'_> {
        self.jobs.acquire().await.expect("subscription job queue")
    }

    /// Share the result with current callers even if it exceeds the cache
    /// budget. A disconnected caller cannot cancel work others still need.
    pub(crate) async fn get_or_render(
        &self,
        key: String,
        render: impl Future<Output = Result<(Artifact, bool), Error>> + Send + 'static,
    ) -> Result<(Arc<Artifact>, bool), Error> {
        let (flight, reused) = {
            let mut entries = lock(&self.entries);
            if let Some(artifact) = entries.bodies.get(&key) {
                return Ok((Arc::clone(artifact), true));
            }
            if let Some(flight) = entries.flights.get(&key) {
                (flight.clone(), true)
            } else {
                let (send, receive) = oneshot::channel();
                let flight = receive.shared();
                entries.flights.insert(key.clone(), flight.clone());
                let entries = Arc::clone(&self.entries);
                let job = tokio::spawn(render);
                tokio::spawn(async move {
                    let result = job
                        .await
                        .map_err(Error::from)
                        .and_then(|result| result)
                        .map_err(IntoHttpError::into_http_error);
                    let mut entries = lock(&entries);
                    let result = result.map(|(artifact, unchanged)| {
                        let artifact = Arc::new(artifact);
                        if unchanged {
                            entries.put(key.clone(), Arc::clone(&artifact), BYTE_LIMIT);
                        }
                        artifact
                    });
                    let _ = send.send(result);
                    entries.flights.remove(&key);
                });
                (flight, false)
            }
        };
        let artifact = flight
            .await
            .expect("render result published")
            .map_err(Error::SharedRender)?;
        Ok((artifact, reused))
    }

    /// How many artifacts are held. Used by tests, and by nothing else.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        lock(&self.entries).bodies.len()
    }
}

fn lock(entries: &Mutex<Entries>) -> std::sync::MutexGuard<'_, Entries> {
    entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Entries {
    fn put(&mut self, key: String, artifact: Arc<Artifact>, byte_limit: usize) {
        let bytes = artifact.body.len();
        if bytes > byte_limit {
            return;
        }

        if let Some(previous) = self.bodies.insert(key.clone(), artifact) {
            self.bytes -= previous.body.len();
        } else {
            self.order.push_back(key);
        }
        self.bytes += bytes;

        while self.order.len() > LIMIT || self.bytes > byte_limit {
            let oldest = self.order.pop_front().expect("an entry to evict");
            self.bytes -= self
                .bodies
                .remove(&oldest)
                .expect("cached entry")
                .body
                .len();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(body: &str) -> Arc<Artifact> {
        Arc::new(Artifact {
            body: Bytes::copy_from_slice(body.as_bytes()),
            target: Target::Links,
            nodes: 1,
            skipped: 0,
            update_hours: None,
        })
    }

    #[test]
    fn the_same_key_gets_the_same_artifact_back() {
        let mut memo = Entries::default();

        assert!(!memo.bodies.contains_key("a"));
        memo.put("a".to_string(), artifact("first"), BYTE_LIMIT);

        assert_eq!(memo.bodies.get("a").unwrap().body, "first");
        assert!(!memo.bodies.contains_key("b"));
    }

    #[test]
    fn remembering_the_same_key_again_replaces_it_without_growing() {
        let mut memo = Entries::default();

        memo.put("a".to_string(), artifact("first"), BYTE_LIMIT);
        memo.put("a".to_string(), artifact("second"), BYTE_LIMIT);

        assert_eq!(memo.bodies.get("a").unwrap().body, "second");
        assert_eq!(memo.bodies.len(), 1);
    }

    #[test]
    fn the_byte_budget_evicts_old_bodies_and_skips_oversized_ones() {
        let mut memo = Entries::default();
        memo.put("a".to_owned(), artifact("first"), 8);
        memo.put("b".to_owned(), artifact("second"), 8);
        memo.put("c".to_owned(), artifact("oversized"), 8);

        assert_eq!(memo.bodies.keys().collect::<Vec<_>>(), ["b"]);
        assert_eq!(memo.bytes, 6);
    }

    #[tokio::test]
    async fn overlapping_requests_share_a_result_that_is_not_cached() {
        let memo = RenderMemo::new();
        let (finish, wait) = oneshot::channel();
        let first = memo.get_or_render("key".to_owned(), async {
            wait.await.unwrap();
            Ok((Arc::try_unwrap(artifact("payload")).unwrap(), false))
        });
        let second = memo.get_or_render("key".to_owned(), async {
            panic!("a second render started");
        });
        tokio::pin!(first, second);
        assert!(futures_util::poll!(&mut first).is_pending());
        assert!(futures_util::poll!(&mut second).is_pending());

        finish.send(()).unwrap();
        let (first, second) = tokio::join!(first, second);
        let (first, started_elsewhere) = first.unwrap();
        let (second, reused) = second.unwrap();
        assert!(!started_elsewhere);
        assert!(reused);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(memo.len(), 0);
    }

    #[test]
    fn the_oldest_goes_when_the_limit_is_reached() {
        let mut memo = Entries::default();

        for index in 0..LIMIT {
            memo.put(format!("key-{index}"), artifact("body"), BYTE_LIMIT);
        }
        assert_eq!(memo.bodies.len(), LIMIT);

        memo.put("one-more".to_string(), artifact("body"), BYTE_LIMIT);

        assert_eq!(memo.bodies.len(), LIMIT);
        assert!(
            !memo.bodies.contains_key("key-0"),
            "the oldest is the one dropped"
        );
        assert!(memo.bodies.contains_key("one-more"));
        assert!(memo.bodies.contains_key(&format!("key-{}", LIMIT - 1)));
    }
}
