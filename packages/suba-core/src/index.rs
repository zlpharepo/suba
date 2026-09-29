//! Every node the instance knows, merged from what each provider currently
//! serves.
//!
//! The index is a **pure function of the observations**: the same observations
//! always merge into the same index, and nothing here remembers a previous
//! merge. That is the point of deriving it rather than storing it — a stored
//! view would be a second truth that can drift from the payloads it came from,
//! and the one fact the payloads cannot answer (when a node was first seen) is
//! already kept beside them.
//!
//! Three properties make it a view an operator can trust:
//!
//! * **One entry per identity.** A node is its content, so the same endpoint
//!   served by three providers, or served under two names, is one entry with
//!   three sources. It is what lets a collection be assembled from providers
//!   that overlap without the overlap showing up as duplicates.
//! * **Orphans are kept and marked.** A provider dropping a node is not a
//!   reason to forget it existed: the entry stays, with no node and the time it
//!   was first seen. What it was cannot be answered once no payload mentions it
//!   — inventing that from an earlier merge would make the same observations
//!   produce two different indexes.
//! * **Everything is ordered deterministically.** Sources by who served it
//!   first, entries by when they were first seen; ties by name, then by
//!   identity. A view that reordered itself between two merges of the same input
//!   would rename nodes on every restart.

use std::collections::{BTreeMap, BTreeSet};

use crate::observation::Observation;
use crate::proto::{Client, Node, NodeFingerprint};
use crate::subscription;

/// Every node the instance knows, whether or not someone still serves it.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeIndex {
    /// Oldest first.
    entries: Vec<IndexEntry>,
}

impl NodeIndex {
    /// Merge what every provider has observed.
    ///
    /// The caller's iteration order is not part of the answer: a map that
    /// happened to iterate the other way round produces the same index.
    pub fn from_observations<'a, I>(observations: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a Observation)>,
    {
        let mut merged: BTreeMap<NodeFingerprint, Merged> = BTreeMap::new();

        for (provider, observation) in observations {
            let checked_at = observation.checked_at.unwrap_or_default();
            let parsed = subscription::parse(observation.payload.as_bytes(), provider, checked_at);

            // What this provider serves right now.
            let mut served: BTreeSet<NodeFingerprint> = BTreeSet::new();

            for record in parsed.nodes {
                let id = record.id();
                let first_seen = observation.sighting.get(&id).copied().unwrap_or(checked_at);

                served.insert(id);
                merged.entry(id).or_insert_with(|| Merged::new(id)).push(
                    Source {
                        provider: provider.to_string(),
                        name: Some(record.name().to_string()),
                        first_seen,
                        serving: true,
                    },
                    Some(record.node),
                );
            }

            // What it has served and does not any more. The sighting is the only
            // thing that still knows these existed — and the only thing that
            // knows when they were first seen.
            for (id, first_seen) in &observation.sighting {
                if served.contains(id) {
                    continue;
                }

                merged.entry(*id).or_insert_with(|| Merged::new(*id)).push(
                    Source {
                        provider: provider.to_string(),
                        // The payload that named it is gone.
                        name: None,
                        first_seen: *first_seen,
                        serving: false,
                    },
                    None,
                );
            }
        }

        let mut entries: Vec<IndexEntry> = merged.into_values().map(Merged::finish).collect();
        entries.sort_by(|left, right| {
            left.first_seen
                .cmp(&right.first_seen)
                .then_with(|| left.id.cmp(&right.id))
        });

        Self { entries }
    }

    /// The nodes, oldest first.
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries someone serves now.
    pub fn served(&self) -> impl Iterator<Item = &IndexEntry> {
        self.entries.iter().filter(|entry| !entry.is_orphan())
    }

    /// The entries nobody serves any more.
    pub fn orphans(&self) -> impl Iterator<Item = &IndexEntry> {
        self.entries.iter().filter(|entry| entry.is_orphan())
    }

    /// How many nodes nothing serves any more.
    pub fn orphan_count(&self) -> usize {
        self.orphans().count()
    }
}

/// One node, and everyone who has served it.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexEntry {
    /// What the node is. Two providers serving it, or two names for it, are one
    /// entry because this is the same.
    pub id: NodeFingerprint,
    /// The node, spelled the way whoever served it first spells it.
    ///
    /// `None` is an orphan: it was served, and nothing serves it now.
    pub node: Option<Node<Client>>,
    /// When this instance first saw it, from any provider.
    pub first_seen: i64,
    /// Everyone that has served it, whoever was first.
    pub sources: Vec<Source>,
}

impl IndexEntry {
    /// Whether nothing serves it any more.
    pub fn is_orphan(&self) -> bool {
        self.node.is_none()
    }

    /// What a client would call it, when someone serves it.
    pub fn name(&self) -> Option<&str> {
        self.node.as_ref().map(|node| node.name.as_str())
    }
}

/// One provider's part in a node: what it called it, and from when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The provider that served it.
    pub provider: String,
    /// What that provider called it.
    ///
    /// `None` for a provider that has stopped serving it: the sighting keeps the
    /// identity, and a name is not part of an identity.
    pub name: Option<String>,
    /// When that provider first served it.
    pub first_seen: i64,
    /// Whether that provider's current payload still lists it.
    pub serving: bool,
}

/// An entry while it is still being merged.
///
/// Each source is held with the node it served, so that the spelling can be
/// decided once the order is known rather than while the input is being read.
struct Merged {
    id: NodeFingerprint,
    sources: Vec<(Source, Option<Node<Client>>)>,
}

impl Merged {
    fn new(id: NodeFingerprint) -> Self {
        Self {
            id,
            sources: Vec::new(),
        }
    }

    fn push(&mut self, source: Source, node: Option<Node<Client>>) {
        self.sources.push((source, node));
    }

    fn finish(mut self) -> IndexEntry {
        // Who served it first; a tie is settled by name, so that two providers
        // that found it in the same second are still ordered the same way every
        // time. There is no further tie to break: one provider appears once.
        self.sources.sort_by(|(left, _), (right, _)| {
            left.first_seen
                .cmp(&right.first_seen)
                .then_with(|| left.provider.cmp(&right.provider))
        });

        let first_seen = self
            .sources
            .first()
            .map(|(source, _)| source.first_seen)
            .unwrap_or_default();
        let node = self.sources.iter().find_map(|(_, node)| node.clone());
        let sources = self.sources.into_iter().map(|(source, _)| source).collect();

        IndexEntry {
            id: self.id,
            node,
            first_seen,
            sources,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::parse_link;

    /// The endpoint the fixtures share, so that the same node can be served
    /// under several names.
    const SHARED: &str = "trojan://hunter2@example.com:443";

    /// The time the fixtures were checked, well after the sightings below.
    const NOW: i64 = 1_700_000_000;

    /// The shared node, under `name`.
    fn link(name: &str) -> String {
        format!("{SHARED}#{name}\n")
    }

    /// A different node — another endpoint, so another identity.
    fn elsewhere(host: &str, name: &str) -> String {
        format!("trojan://hunter2@{host}:443#{name}\n")
    }

    fn id(link: &str) -> NodeFingerprint {
        parse_link(link.trim_end())
            .expect("the fixture parses")
            .id()
    }

    /// An observation of `payload`, where each line is the identity of a node
    /// this provider has ever served, and the time it was first seen.
    fn observed(payload: &str, seen: &[(&str, i64)]) -> Observation {
        let mut observation = Observation {
            payload: payload.to_string(),
            fetched_at: Some(NOW),
            checked_at: Some(NOW),
            ..Observation::default()
        };

        for (link, first_seen) in seen {
            observation.sighting.insert(id(link), *first_seen);
        }

        observation
    }

    #[test]
    fn a_node_three_providers_serve_is_one_entry_with_three_sources() {
        let node = link("Node");
        let observations = [
            ("charlie", observed(&node, &[(&node, 3_000)])),
            ("alpha", observed(&node, &[(&node, 1_000)])),
            ("beta", observed(&node, &[(&node, 2_000)])),
        ];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));

        assert_eq!(index.len(), 1, "one node, however many providers serve it");

        let entry = &index.entries()[0];
        assert_eq!(entry.name(), Some("Node"));
        assert!(!entry.is_orphan());
        assert_eq!(
            entry
                .sources
                .iter()
                .map(|source| source.provider.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta", "charlie"],
            "who served it first, first"
        );
        assert_eq!(entry.sources[0].first_seen, 1_000);
        assert_eq!(entry.first_seen, 1_000);
        assert_eq!(index.orphan_count(), 0);
    }

    #[test]
    fn a_tie_is_settled_by_provider_name() {
        let node = link("Node");
        let observations = [
            ("zulu", observed(&node, &[(&node, 1_000)])),
            ("alpha", observed(&node, &[(&node, 1_000)])),
        ];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));
        let entry = &index.entries()[0];

        assert_eq!(
            entry
                .sources
                .iter()
                .map(|source| source.provider.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "zulu"]
        );
    }

    #[test]
    fn a_node_nobody_serves_is_kept_and_marked() {
        let node = link("Node");
        let observations = [("alpha", observed("", &[(&node, 1_000)]))];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));

        assert_eq!(index.len(), 1, "it existed, so it is still here");
        assert_eq!(index.orphan_count(), 1);
        assert!(index.served().next().is_none());

        let entry = &index.entries()[0];
        assert!(entry.is_orphan());
        assert_eq!(entry.node, None);
        assert_eq!(entry.name(), None);
        assert_eq!(entry.first_seen, 1_000, "when it was first seen survives");
        assert_eq!(entry.sources.len(), 1);
        assert!(!entry.sources[0].serving);
        assert_eq!(
            entry.sources[0].name, None,
            "the name went with the payload"
        );
    }

    #[test]
    fn a_node_that_comes_back_keeps_the_time_it_was_first_seen() {
        let node = link("Node");
        let observations = [("alpha", observed(&node, &[(&node, 1_000)]))];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));
        let entry = &index.entries()[0];

        assert!(!entry.is_orphan());
        assert_eq!(
            entry.first_seen, 1_000,
            "not the time this observation was checked"
        );
    }

    #[test]
    fn the_same_observations_always_merge_into_the_same_index() {
        let node = link("Node");
        let observations = [
            ("beta", observed(&node, &[(&node, 2_000)])),
            ("alpha", observed(&node, &[(&node, 2_000)])),
            ("charlie", observed(&node, &[(&node, 1_000)])),
        ];

        let forwards =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));
        let backwards =
            NodeIndex::from_observations(observations.iter().rev().map(|(name, one)| (*name, one)));

        assert_eq!(
            forwards, backwards,
            "the order the observations arrive in is not part of the answer"
        );
    }

    #[test]
    fn the_node_is_spelled_the_way_whoever_served_it_first_spells_it() {
        let us = link("US-01");
        let states = link("United States");

        assert_eq!(
            id(&us),
            id(&states),
            "a name is not part of an identity, which is what makes this one node"
        );

        let observations = [
            ("beta", observed(&states, &[(&states, 2_000)])),
            ("alpha", observed(&us, &[(&us, 1_000)])),
        ];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));
        let entry = &index.entries()[0];

        assert_eq!(entry.name(), Some("US-01"));
        assert_eq!(
            entry
                .sources
                .iter()
                .map(|source| source.name.clone())
                .collect::<Vec<_>>(),
            [Some("US-01".to_string()), Some("United States".to_string())],
            "each provider's spelling is kept where it came from"
        );

        // The first one stops serving it: the next spelling takes over, and the
        // entry is still the same node with the same history.
        let observations = [
            ("beta", observed(&states, &[(&states, 2_000)])),
            ("alpha", observed("", &[(&us, 1_000)])),
        ];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));
        let entry = &index.entries()[0];

        assert_eq!(entry.name(), Some("United States"));
        assert_eq!(entry.first_seen, 1_000, "the history does not move");
        assert!(!entry.sources[0].serving, "alpha dropped it");
        assert!(entry.sources[1].serving);
    }

    #[test]
    fn entries_are_the_oldest_first() {
        let later = elsewhere("b.example.com", "Later");
        let earlier = elsewhere("a.example.com", "Earlier");
        let payload = format!("{later}{earlier}");

        let observations = [(
            "alpha",
            observed(&payload, &[(&later, 2_000), (&earlier, 1_000)]),
        )];

        let index =
            NodeIndex::from_observations(observations.iter().map(|(name, one)| (*name, one)));

        assert_eq!(
            index
                .entries()
                .iter()
                .map(|entry| entry.name().expect("a name"))
                .collect::<Vec<_>>(),
            ["Earlier", "Later"],
            "the payload's order is not the index's order"
        );
    }

    #[test]
    fn an_observation_with_nothing_in_it_adds_nothing() {
        let quiet = Observation::default();

        let index = NodeIndex::from_observations([("quiet", &quiet)]);

        assert!(index.is_empty());
        assert_eq!(index.orphan_count(), 0);
    }
}
