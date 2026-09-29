//! What this hub observed from a provider: the payload exactly as it arrived,
//! the validators that make the next fetch cheap, and the one fact that cannot
//! be derived from the payload — when each node was first seen.
//!
//! One provider, one document. That is the whole reason this is a single type:
//! a refresh replaces it with one atomic rename, so a crash leaves the old
//! complete document or the new complete document, never a payload from one
//! fetch and timestamps from another.
//!
//! Everything else about the node set is derived from here. An orphan, for
//! instance, is not stored: it is a node in [`Observation::sighting`] that the
//! current payload does not mention.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::proto::NodeFingerprint;

/// What a provider served, and what this hub knows about it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// The ETag the provider served, sent back as `If-None-Match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,

    /// The `Last-Modified` the provider served, sent back as
    /// `If-Modified-Since`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,

    /// When the payload was last replaced, in seconds since the epoch.
    ///
    /// A `304` does not move it: the payload did not change, so its age is
    /// still its age.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<i64>,

    /// When the provider was last asked, in seconds since the epoch. A `200`, a
    /// `304` and a failure all count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,

    /// The sha256 of the payload as it arrived.
    ///
    /// What keeps a provider with no validators from rewriting an identical
    /// payload on every interval: if the bytes are the same, there is nothing
    /// to write, and the payload keeps the time it was first served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// The last failure, kept so that a provider that has been failing is
    /// visible without reading the log of a process that tried hours ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// The payload, byte for byte as the provider served it.
    ///
    /// Parsing is the job of whatever consumes it: an upstream format this
    /// build does not understand is still cached faithfully, and a new reader
    /// can be pointed at what is already stored without a second fetch.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub payload: String,

    /// Node identity to the first time this hub saw it from this provider.
    ///
    /// The one fact the payload cannot be asked again. Bounded by the number of
    /// distinct nodes the provider has ever served, not by how often they were
    /// fetched.
    ///
    /// Keyed by identity rather than by a name or a position, so a node the
    /// provider renamed is still the node this hub first saw: an identity
    /// outlives every spelling of it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sighting: BTreeMap<NodeFingerprint, i64>,
}

impl Observation {
    /// Whether nothing has ever been observed from this provider.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty() && self.sighting.is_empty() && self.error.is_none()
    }

    /// The conditional-request material, for a fetch that has something to
    /// compare against.
    ///
    /// A client with no payload must not ask conditionally: a `304` would tell
    /// it that the version it does not have is current.
    pub fn conditions(&self) -> Option<(&str, Option<&str>)> {
        self.etag
            .as_deref()
            .map(|etag| (etag, self.last_modified.as_deref()))
    }

    /// Note that nodes were seen now, without moving a time that is already
    /// older.
    ///
    /// A node the provider has served before keeps the first time it was seen —
    /// that is what makes the fact worth storing.
    pub fn note_sightings(&mut self, ids: impl IntoIterator<Item = NodeFingerprint>, now: i64) {
        for id in ids {
            let seen = self.sighting.entry(id).or_insert(now);

            if now < *seen {
                *seen = now;
            }
        }
    }

    /// The identities this hub remembers seeing from this provider.
    pub fn remembered(&self) -> impl Iterator<Item = NodeFingerprint> + '_ {
        self.sighting.keys().copied()
    }

    /// How many of the remembered nodes the current payload does not mention.
    ///
    /// An orphan is derived, never stored: it is a node that was served and is
    /// not served now. Counted rather than dropped, because a provider that has
    /// quietly shrunk is something an operator needs to see.
    pub fn orphans<'a>(&'a self, served: impl IntoIterator<Item = &'a NodeFingerprint>) -> usize {
        let served: BTreeSet<&NodeFingerprint> = served.into_iter().collect();

        self.sighting
            .keys()
            .filter(|id| !served.contains(id))
            .count()
    }

    /// Fold a previous observation into this one.
    ///
    /// What survives a refresh is the history: a node served two releases ago
    /// keeps the time it was first seen even if the payload no longer mentions
    /// it. That is what makes removing it from the payload reversible.
    pub fn merge_history(&mut self, previous: &Observation) {
        for (id, first_seen) in &previous.sighting {
            let seen = self.sighting.entry(*id).or_insert(*first_seen);

            if *first_seen < *seen {
                *seen = *first_seen;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fingerprint with a shape of its own, for tests that care about
    /// identities but not about which node they belong to.
    fn id(spelling: char) -> NodeFingerprint {
        NodeFingerprint::parse(&spelling.to_string().repeat(32)).expect("a fingerprint")
    }

    fn observed(payload: &str, ids: &[(NodeFingerprint, i64)]) -> Observation {
        let mut observation = Observation {
            payload: payload.to_string(),
            ..Observation::default()
        };

        for (id, seen) in ids {
            observation.sighting.insert(*id, *seen);
        }

        observation
    }

    #[test]
    fn conditions_are_absent_until_there_is_something_to_compare_against() {
        // A client with nothing cached must not ask conditionally.
        assert_eq!(Observation::default().conditions(), None);

        let with_etag = Observation {
            etag: Some("\"v1\"".to_string()),
            ..Observation::default()
        };
        assert_eq!(with_etag.conditions(), Some(("\"v1\"", None)));

        let with_both = Observation {
            etag: Some("\"v1\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
            ..Observation::default()
        };
        assert_eq!(
            with_both.conditions(),
            Some(("\"v1\"", Some("Wed, 21 Oct 2015 07:28:00 GMT")))
        );
    }

    #[test]
    fn a_node_seen_again_keeps_the_first_time_it_was_seen() {
        let mut observation = observed("payload", &[(id('a'), 1_000)]);

        observation.note_sightings([id('a'), id('b')], 2_000);

        assert_eq!(
            observation.sighting[&id('a')],
            1_000,
            "the first sighting wins"
        );
        assert_eq!(observation.sighting[&id('b')], 2_000, "the new one is now");
    }

    #[test]
    fn a_newer_time_never_overwrites_an_older_one() {
        let mut observation = Observation::default();

        observation.note_sightings([id('a')], 2_000);
        observation.note_sightings([id('a')], 1_000);

        assert_eq!(
            observation.sighting[&id('a')],
            1_000,
            "the earliest time this hub has is the answer"
        );
    }

    #[test]
    fn history_survives_a_refresh_that_no_longer_mentions_the_node() {
        let previous = observed("old", &[(id('a'), 1_000)]);
        let mut fresh = observed("new", &[(id('b'), 2_000)]);

        fresh.merge_history(&previous);

        assert_eq!(fresh.sighting[&id('b')], 2_000);
        assert_eq!(
            fresh.sighting[&id('a')],
            1_000,
            "a node the payload dropped is still remembered"
        );
    }

    #[test]
    fn an_orphan_is_a_remembered_node_the_payload_no_longer_serves() {
        let observation = observed("payload", &[(id('a'), 1_000), (id('b'), 1_000)]);

        assert_eq!(observation.orphans([&id('a')]), 1);
        assert_eq!(observation.orphans([&id('a'), &id('b')]), 0);
    }

    #[test]
    fn a_failure_is_visible_without_the_payload_being_touched() {
        let observation = Observation {
            error: Some("the provider refused the connection".to_string()),
            payload: "still here".to_string(),
            ..Observation::default()
        };

        assert!(!observation.is_empty(), "a failure is something observed");
        assert_eq!(observation.payload, "still here");
    }

    #[test]
    fn an_observation_with_nothing_in_it_is_empty() {
        assert!(Observation::default().is_empty());
        assert!(!observed("payload", &[]).is_empty());
    }
}
