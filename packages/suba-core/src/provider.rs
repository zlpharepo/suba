//! What a fetch means for what this hub keeps.
//!
//! This is the decision, not the I/O. A caller fetches — with a real HTTP
//! client, or by reading a file, or by handing over what an operator typed —
//! and passes what arrived to [`decide`]; what comes back is *what the store
//! must become*. Keeping the socket out of it is what lets the whole refresh
//! path be tested without a network, and it is why the only thing that knows
//! about files is the caller.
//!
//! Three answers come out of one fetch, and they are different things:
//!
//! * **`Fetched`** — bytes arrived that this hub did not have. The payload is
//!   replaced and its validators are recorded.
//! * **`Unchanged`** — bytes arrived and they are the bytes already held. A
//!   provider with no validators serves the same payload every interval;
//!   rewriting an identical payload each time would churn the disk to say
//!   nothing, so the timestamps move and the payload keeps its own.
//! * **`NotModified`** — a `304`. The provider confirmed that what this hub
//!   holds is current, but nothing was read: the payload and its timestamp stay,
//!   and only the check time moves.
//!
//! A failed fetch is not one of these. It is an error the caller records —
//! the last good payload is worth more than nothing — and the payload is left
//! exactly as it was.

use serde::{Deserialize, Serialize};

use crate::node::NodeRecord;
use crate::observation::Observation;
use crate::subscription::{self, DeclaredFormat, SkippedLine, SourceFormat, Unreadable};

/// What a fetch produced, before anything was decided about it.
///
/// Plain data, so a test can build any of the three without a socket.
#[derive(Debug, Clone, PartialEq)]
pub enum Fetched {
    /// The provider served bytes, with whatever validators make the next fetch
    /// cheap.
    Modified {
        payload: String,
        etag: Option<String>,
        last_modified: Option<String>,
    },

    /// The provider answered `304 Not Modified`: what this hub already has is
    /// what it serves.
    NotModified { etag: Option<String> },
}

impl Fetched {
    /// Whether a payload arrived, which is the question every caller is really
    /// asking.
    pub fn is_modified(&self) -> bool {
        matches!(self, Self::Modified { .. })
    }

    /// A payload with no validators.
    ///
    /// What a source that cannot answer conditionally produces: a file on disk
    /// and a hand-written payload have no `ETag` to offer, and their bytes are
    /// all there is to compare.
    pub fn from_payload(payload: impl Into<String>) -> Self {
        Self::Modified {
            payload: payload.into(),
            etag: None,
            last_modified: None,
        }
    }

    /// Attach the validators a provider sent with its payload.
    ///
    /// Called after the body is read, because that is when it is known that the
    /// payload is going to be kept: a validator is only useful next to the bytes
    /// it describes.
    pub fn with_validators(self, etag: Option<String>, last_modified: Option<String>) -> Self {
        match self {
            Self::Modified { payload, .. } => Self::Modified {
                payload,
                etag,
                last_modified,
            },
            other => other,
        }
    }
}

/// What a refresh did, in the terms an operator needs.
///
/// Serialized as it is named: this is what a refresh reports back, and a client
/// that has to map numbers to meanings is a client that will get one wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefreshStatus {
    /// A payload arrived and replaced what this hub had.
    Fetched,
    /// A payload arrived, byte for byte the one already held: nothing was
    /// written, and the payload keeps the time it was first served.
    Unchanged,
    /// The provider answered `304 Not Modified`.
    NotModified,
}

/// What a payload turned out to be, once it was read. Reported, never the bytes
/// themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadReport {
    /// What the body was recognised as, when it was recognised at all.
    pub format: Option<SourceFormat>,
    pub bytes: usize,
    pub nodes: usize,
    pub duplicates: usize,
    pub skipped: Vec<SkippedLine>,
    pub skipped_omitted: usize,
}

/// The change a refresh asks the store for.
///
/// Returning the change rather than performing it keeps this function pure. The
/// caller writes `observation` — which is `None` when what is held is already
/// correct — and that is the whole write.
#[derive(Debug, Clone, PartialEq)]
pub struct RefreshPlan {
    /// How the refresh went, for the report and the log.
    pub status: RefreshStatus,
    /// Why the payload that is held now contributes no nodes at all, when it is
    /// beyond this build.
    ///
    /// On the plan rather than only on the report: a `304` carries no report,
    /// and "this provider serves nothing" is worth saying even when the body
    /// did not arrive this time.
    pub unreadable: Option<Unreadable>,
    /// The nodes the payload currently serves.
    pub nodes: Vec<NodeRecord>,
    /// What arrived, when something did.
    pub payload: Option<PayloadReport>,
    /// The observation to store, or `None` when nothing needs writing.
    pub observation: Option<Observation>,
}

impl RefreshPlan {
    /// How many nodes the provider serves now.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the provider serves nothing.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

/// Decide what a fetch means for what this hub keeps.
///
/// `previous` is the observation already held — `None` on a first fetch — and
/// `now` is seconds since the epoch, passed in rather than read so the decision
/// is deterministic and testable.
pub fn decide(
    provider: &str,
    previous: Option<&Observation>,
    fetched: Fetched,
    now: i64,
    declared: DeclaredFormat,
) -> RefreshPlan {
    let previous = previous.cloned().unwrap_or_default();

    match fetched {
        Fetched::NotModified { etag } => {
            // Nothing was served, but the provider was *confirmed* to still
            // serve what it served. The validators move; the payload does not.
            let observation = Observation {
                etag: etag.or_else(|| previous.etag.clone()),
                ..previous.clone()
            }
            .checked_at(now);

            // The nodes are what the held payload parses to, reported so the
            // caller can answer "how many nodes does this provider have"
            // without a second read.
            let parsed = subscription::parse(previous.payload.as_bytes(), provider, now, declared);

            RefreshPlan {
                status: RefreshStatus::NotModified,
                nodes: parsed.nodes,
                unreadable: parsed.unreadable,
                payload: None,
                observation: Some(observation),
            }
        }
        Fetched::Modified {
            payload,
            etag,
            last_modified,
        } => {
            let digest = crate::checksum::sha256_hex(payload.as_bytes());
            let parsed = subscription::parse(payload.as_bytes(), provider, now, declared);

            // A provider with no validators serves the same bytes every time.
            // Rewriting an identical payload on every interval would churn the
            // disk to say nothing, so the hash decides.
            let unchanged = previous.content_hash.as_deref() == Some(digest.as_str())
                && !previous.payload.is_empty();

            let report = PayloadReport {
                format: parsed.format,
                bytes: payload.len(),
                nodes: parsed.len(),
                duplicates: parsed.duplicates,
                skipped: parsed.skipped,
                skipped_omitted: parsed.skipped_omitted,
            };

            if unchanged {
                // The timestamps move, the payload does not. `fetched_at` stays
                // where it was: the payload's age is the age of the bytes, not
                // of the check.
                let observation = Observation {
                    content_hash: Some(digest),
                    ..previous.clone()
                }
                .checked_at(now);

                return RefreshPlan {
                    status: RefreshStatus::Unchanged,
                    nodes: parsed.nodes,
                    unreadable: parsed.unreadable,
                    payload: Some(report),
                    observation: Some(observation),
                };
            }

            let mut observation = Observation {
                payload,
                etag,
                last_modified,
                fetched_at: Some(now),
                checked_at: Some(now),
                content_hash: Some(digest),
                error: None,
                sighting: previous.sighting.clone(),
            };
            // A node this hub has served before keeps the time it was first
            // seen; one it has not starts now.
            observation.note_sightings(parsed.nodes.iter().map(NodeRecord::id), now);

            RefreshPlan {
                status: RefreshStatus::Fetched,
                nodes: parsed.nodes,
                unreadable: parsed.unreadable,
                payload: Some(report),
                observation: Some(observation),
            }
        }
    }
}

/// Record a failed fetch.
///
/// The reason is scrubbed by the caller: a provider URL can carry a token, and
/// a transport error quotes it. What this does is the bookkeeping — when it was
/// checked and what went wrong — and it deliberately touches nothing else,
/// because the last good payload is worth more than nothing.
///
/// Returns `None` when there is nothing to record: a provider that has never
/// succeeded and failed the same way it did last time has no new fact, and
/// writing one would churn the disk on every failing interval.
pub fn record_failure(
    previous: Option<&Observation>,
    reason: String,
    now: i64,
) -> Option<Observation> {
    let mut observation = previous.cloned().unwrap_or_default();
    let repeated = observation.error.as_deref() == Some(reason.as_str());

    observation.checked_at = Some(now);
    observation.error = Some(reason);

    match repeated && previous.is_some() {
        true => None,
        false => Some(observation),
    }
}

impl Observation {
    /// The same observation, with the check time moved.
    fn checked_at(mut self, now: i64) -> Self {
        self.checked_at = Some(now);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const TROJAN: &str = "trojan://hunter2@example.com:443#Node";
    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443#Other";

    fn modified(payload: &str) -> Fetched {
        Fetched::Modified {
            payload: payload.to_string(),
            etag: Some("\"v1\"".to_string()),
            last_modified: None,
        }
    }

    fn payload_of(text: &str) -> String {
        format!("{text}\n")
    }

    /// A declared shape this build cannot read is reported, and what arrived
    /// is still kept: a later build reads it, and until then the bytes are the
    /// only record of what the provider served.
    #[cfg(feature = "clash")]
    #[test]
    fn a_declared_shape_this_build_cannot_read_is_reported() {
        let plan = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Clash,
        );

        assert_eq!(plan.status, RefreshStatus::Fetched);
        assert_eq!(plan.unreadable, Some(Unreadable::Clash));
        assert!(
            plan.is_empty(),
            "no node can come out of a body we did not read"
        );
        assert_eq!(
            plan.payload.expect("it arrived").format,
            None,
            "and nothing was recognised either"
        );
        assert!(
            plan.observation
                .expect("kept")
                .payload
                .contains("trojan://"),
            "the body is held even when this build cannot read it"
        );
    }

    #[test]
    fn a_first_fetch_writes_a_payload_and_its_validators() {
        let plan = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.status, RefreshStatus::Fetched);
        assert_eq!(plan.len(), 1);

        let observation = plan.observation.expect("an observation");
        assert_eq!(observation.payload, payload_of(TROJAN));
        assert_eq!(observation.etag.as_deref(), Some("\"v1\""));
        assert_eq!(observation.fetched_at, Some(NOW));
        assert_eq!(observation.checked_at, Some(NOW));
        assert!(observation.content_hash.is_some());
        assert!(observation.error.is_none());
        assert_eq!(
            observation.remembered().count(),
            1,
            "the node was seen for the first time"
        );
    }

    #[test]
    fn the_payload_is_kept_byte_for_byte() {
        // Whitespace, a trailing newline, an unusual line ending: all of it is
        // what the provider served.
        let body = "  trojan://hunter2@example.com:443#Node  \r\n\r\n";
        let plan = decide("primary", None, modified(body), NOW, DeclaredFormat::Links);

        assert_eq!(plan.observation.unwrap().payload, body);
    }

    #[test]
    fn a_304_moves_the_check_time_and_leaves_the_payload_alone() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();

        let later = NOW + 3_600;
        let plan = decide(
            "primary",
            Some(&held),
            Fetched::NotModified { etag: None },
            later,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.status, RefreshStatus::NotModified);
        assert_eq!(plan.len(), 1, "the held payload still serves its node");

        let observation = plan.observation.unwrap();
        assert_eq!(observation.checked_at, Some(later));
        assert_eq!(
            observation.fetched_at,
            Some(NOW),
            "the payload was not replaced, so its time does not move"
        );
        assert_eq!(
            observation.etag.as_deref(),
            Some("\"v1\""),
            "a 304 with no validator keeps the one held"
        );
    }

    #[test]
    fn a_304_may_rotate_the_validator_it_sends() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();

        let plan = decide(
            "primary",
            Some(&held),
            Fetched::NotModified {
                etag: Some("\"v2\"".to_string()),
            },
            NOW + 1,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.observation.unwrap().etag.as_deref(), Some("\"v2\""));
    }

    #[test]
    fn identical_bytes_without_a_304_are_not_written_again() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();

        // A provider with no validators serves the same bytes again.
        let again = Fetched::Modified {
            payload: held.payload.clone(),
            etag: None,
            last_modified: None,
        };
        let later = NOW + 3_600;
        let plan = decide("primary", Some(&held), again, later, DeclaredFormat::Links);

        assert_eq!(plan.status, RefreshStatus::Unchanged);
        let observation = plan.observation.unwrap();
        assert_eq!(
            observation.fetched_at,
            Some(NOW),
            "the payload's time is when the bytes were first served"
        );
        assert_eq!(observation.checked_at, Some(later));
    }

    #[test]
    fn changed_bytes_replace_the_payload() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();

        let changed = payload_of(VLESS);
        let plan = decide(
            "primary",
            Some(&held),
            modified(&changed),
            NOW + 3_600,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.status, RefreshStatus::Fetched);
        let observation = plan.observation.unwrap();
        assert_eq!(observation.payload, changed);
        assert_eq!(observation.fetched_at, Some(NOW + 3_600));
        assert_ne!(observation.content_hash, held.content_hash);
    }

    #[test]
    fn a_node_the_provider_no_longer_serves_keeps_the_time_it_was_first_seen() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();
        let gone = held.remembered().next().unwrap();

        let plan = decide(
            "primary",
            Some(&held),
            modified(&payload_of(VLESS)),
            NOW + 3_600,
            DeclaredFormat::Links,
        );

        let observation = plan.observation.unwrap();
        assert_eq!(
            observation.sighting[&gone], NOW,
            "history survives a payload that dropped the node"
        );
    }

    #[test]
    fn a_first_fetch_has_no_previous_to_merge_from() {
        let plan = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.observation.unwrap().sighting.len(), 1);
    }

    #[test]
    fn a_payload_with_no_usable_nodes_is_still_kept() {
        // What the provider served is a fact even when it is useless: an
        // operator needs to see it, and the next fetch can compare against it.
        let plan = decide(
            "primary",
            None,
            modified("not a link\n"),
            NOW,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.status, RefreshStatus::Fetched);
        assert!(plan.is_empty(), "no nodes");
        assert_eq!(plan.payload.unwrap().skipped.len(), 1);
        assert_eq!(plan.observation.unwrap().payload, "not a link\n");
    }

    #[test]
    fn a_failure_records_why_and_leaves_the_payload_exactly_as_it_was() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();

        let later = NOW + 600;
        let failed = record_failure(
            Some(&held),
            "the provider refused the connection".to_string(),
            later,
        )
        .expect("a failure to record");

        assert_eq!(failed.checked_at, Some(later));
        assert_eq!(
            failed.error.as_deref(),
            Some("the provider refused the connection")
        );
        assert_eq!(failed.payload, held.payload);
        assert_eq!(failed.fetched_at, held.fetched_at);
        assert_eq!(failed.etag, held.etag);
    }

    #[test]
    fn a_failure_before_anything_was_ever_stored_still_records_a_time() {
        let failed = record_failure(None, "timeout".to_string(), NOW).expect("a failure to record");

        assert_eq!(failed.checked_at, Some(NOW));
        assert_eq!(failed.error.as_deref(), Some("timeout"));
        assert_eq!(failed.fetched_at, None);
        assert!(failed.payload.is_empty());
    }

    #[test]
    fn an_unchanged_failure_is_not_written_again() {
        let first = record_failure(None, "timeout".to_string(), NOW).unwrap();

        // The provider is still down, for the same reason: there is no new
        // fact, and writing one would churn the disk on every interval.
        assert!(record_failure(Some(&first), "timeout".to_string(), NOW + 60).is_none());

        // A different reason is a different fact.
        assert!(record_failure(Some(&first), "dns".to_string(), NOW + 60).is_some());
    }

    #[test]
    fn the_sighting_a_node_keeps_is_the_first_time_this_hub_saw_it() {
        let first = decide(
            "primary",
            None,
            modified(&payload_of(TROJAN)),
            NOW,
            DeclaredFormat::Links,
        );
        let held = first.observation.unwrap();
        let id = held.remembered().next().unwrap();

        // A later fetch of the same node: the payload is new, the sighting is
        // not.
        let plan = decide(
            "primary",
            Some(&held),
            modified(&format!("{TROJAN}\n{VLESS}\n")),
            NOW + 3_600,
            DeclaredFormat::Links,
        );

        assert_eq!(plan.observation.unwrap().sighting[&id], NOW);
    }
}
