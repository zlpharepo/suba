//! A subscription node with its current source attribution.
//!
//! Protocol content belongs to [`suba_proto`](crate::proto). Provenance keeps
//! payload positions and raw links without retaining previous snapshots.

use std::fmt;

use serde::{Deserialize, Serialize};

pub use crate::proto::{Client, Node, Server};

/// A parsed node and its attribution within the current payload.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node: Node<Client>,
    /// Current sources only; records from different providers remain separate.
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

    /// Content identity; the source provider remains separate from this hash.
    pub fn id(&self) -> crate::proto::NodeFingerprint {
        self.node.id()
    }

    /// The name a client sees.
    pub fn name(&self) -> &str {
        self.node.name.as_str()
    }

    /// Attribute a current source, retaining its first position and raw spelling
    /// when the same payload repeats an identity. Returns whether it was added.
    pub fn attribute(&mut self, provider: &str, position: usize, raw: &str) -> bool {
        if self
            .provenance
            .iter()
            .any(|entry| entry.provider == provider)
        {
            return false;
        }

        self.provenance
            .push(Provenance::new(provider, position, raw));
        true
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

/// Source attribution within the current payload, never a historical record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub provider: String,
    /// Zero-based payload position, including skipped lines.
    pub position: usize,
    /// Kept for re-export without parsing again; omitted from Debug because it
    /// contains the credentials exactly as the provider supplied them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

impl Provenance {
    pub fn new(provider: impl Into<String>, position: usize, raw: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            position,
            raw: raw.into(),
        }
    }
}

impl fmt::Debug for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provenance")
            .field("provider", &self.provider)
            .field("position", &self.position)
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
    fn duplicate_attribution_keeps_the_first_payload_position_and_raw_link() {
        let mut record = record();

        assert!(record.attribute("primary", 0, LINK));
        assert!(!record.attribute("primary", 1, "a duplicate spelling"));

        assert_eq!(record.provenance.len(), 1);
        assert_eq!(record.provenance[0].position, 0);
        assert_eq!(record.provenance[0].raw, LINK);
    }

    #[test]
    fn two_providers_serving_one_node_are_two_provenances() {
        let mut record = record();

        record.attribute("primary", 0, LINK);
        record.attribute("backup", 4, LINK);

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
        record.attribute(
            "primary",
            0,
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
