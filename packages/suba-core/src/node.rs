//! A node as a subscription hub knows it: the node itself, plus where it came
//! from.
//!
//! The node — endpoint, carriage, TLS, protocol payload — belongs to
//! [`suba_proto`](crate::proto). What a hub adds is provenance: which provider
//! served it, where in that provider's payload it appeared, when it was seen,
//! and the link exactly as it arrived.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::proto::{Client, Node, Server};

/// One node, with everyone who served it.
///
/// Identity is the node's own content hash, so the same node served by two
/// providers is one record with two provenances — which is what lets a
/// collection survive a provider renaming it.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeRecord {
    /// The node itself.
    pub node: Node<Client>,
    /// Every provider that has served it, in the order they first did.
    pub provenance: Vec<Provenance>,
}

impl NodeRecord {
    /// A node that has not been attributed to a provider yet.
    pub fn new(node: Node<Client>) -> Self {
        Self {
            node,
            provenance: Vec::new(),
        }
    }

    /// The content hash that identifies the node, which is how it is keyed.
    pub fn id(&self) -> crate::proto::NodeFingerprint {
        self.node.id()
    }

    /// The name a client sees.
    pub fn name(&self) -> &str {
        self.node.name.as_str()
    }

    /// Note a sighting: the first one starts a provenance, later ones extend it.
    ///
    /// Returns whether this was the first sighting by that provider, which is
    /// the caller's signal that something new was learned.
    pub fn seen_at(&mut self, provider: &str, position: usize, now: i64, raw: &str) -> bool {
        match self
            .provenance
            .iter_mut()
            .find(|entry| entry.provider == provider)
        {
            Some(entry) => {
                entry.last_seen = now;
                false
            }
            None => {
                self.provenance
                    .push(Provenance::new(provider, position, now, raw));
                true
            }
        }
    }

    /// Whether no provider has served it, which means it is hand-written rather
    /// than subscribed to.
    pub fn is_hand_written(&self) -> bool {
        self.provenance.is_empty()
    }
}

impl fmt::Debug for NodeRecord {
    /// The node and the bookkeeping, never the links.
    ///
    /// Every credential in a node is a `Secret`, so the node itself is safe to
    /// print; the raw link is not, because it is the credential-bearing text
    /// exactly as a provider served it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeRecord")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("node", &self.node)
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// Where a node was seen, when, and as what.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The provider that served it.
    pub provider: String,
    /// Where in that provider's payload it appeared.
    ///
    /// This is what "the provider's order" means: the same payload fetched twice
    /// yields the same positions, so a node that moved can be told from one that
    /// was renamed, and ordering by source does not depend on the order a map
    /// happened to iterate in.
    #[serde(default)]
    pub position: usize,
    /// When this hub first saw it, in seconds since the epoch.
    pub first_seen: i64,
    /// When it was last seen.
    pub last_seen: i64,
    /// The link exactly as it arrived.
    ///
    /// Kept so that what a provider served can be audited and re-exported
    /// without a second parse — and never printed, because it carries the
    /// credentials.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

impl Provenance {
    /// A first sighting, at `position` in the payload that carried it.
    pub fn new(
        provider: impl Into<String>,
        position: usize,
        now: i64,
        raw: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            position,
            first_seen: now,
            last_seen: now,
            raw: raw.into(),
        }
    }

    /// Note that it is still there.
    pub fn seen_again(&mut self, now: i64) {
        self.last_seen = now;
    }
}

impl fmt::Debug for Provenance {
    /// Which provider, seen when — and not the raw link, which is the node's
    /// credentials in the form the provider wrote them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provenance")
            .field("provider", &self.provider)
            .field("position", &self.position)
            .field("first_seen", &self.first_seen)
            .field("last_seen", &self.last_seen)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::parse_link;

    const LINK: &str = "trojan://hunter2@example.com:443#Node";

    fn record() -> NodeRecord {
        NodeRecord::new(parse_link(LINK).expect("the link parses"))
    }

    #[test]
    fn a_record_is_identified_by_its_node_content() {
        let record = record();

        assert_eq!(record.name(), "Node");
        assert_eq!(record.id(), record.node.id());
        assert!(record.is_hand_written(), "nothing has served it yet");
    }

    #[test]
    fn seeing_the_same_node_twice_from_one_provider_extends_one_provenance() {
        let mut record = record();

        assert!(
            record.seen_at("primary", 0, 1_000, LINK),
            "the first sighting"
        );
        assert!(
            !record.seen_at("primary", 1, 2_000, LINK),
            "the second is not a new provenance"
        );

        assert_eq!(record.provenance.len(), 1);
        assert_eq!(
            record.provenance[0].first_seen, 1_000,
            "the first time wins"
        );
        assert_eq!(record.provenance[0].last_seen, 2_000);
    }

    #[test]
    fn two_providers_serving_one_node_are_two_provenances() {
        let mut record = record();

        record.seen_at("primary", 0, 1_000, LINK);
        record.seen_at("backup", 4, 1_500, LINK);

        assert_eq!(record.provenance.len(), 2);
        assert!(!record.is_hand_written());
        assert_eq!(
            record
                .provenance
                .iter()
                .map(|entry| entry.provider.as_str())
                .collect::<Vec<_>>(),
            ["primary", "backup"]
        );
    }

    #[test]
    fn a_record_never_prints_the_link_it_was_built_from() {
        let mut record = record();
        record.seen_at(
            "primary",
            0,
            1_000,
            "trojan://SENTINELPASSWORD@example.com:443#Node",
        );

        let printed = format!("{record:?}");

        assert!(!printed.contains("SENTINELPASSWORD"), "{printed}");
        assert!(printed.contains("primary"), "{printed}");
        assert!(
            printed.contains("Node"),
            "the name is not a secret: {printed}"
        );
    }
}
