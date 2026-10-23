//! Latest provider snapshots, indexed without merging distinct providers.
//!
//! Entries are derived solely from current payloads. Provider-name order makes
//! construction independent of map iteration; each provider retains its payload
//! order and its own spelling, even when another provider serves the same node.

use std::collections::{BTreeMap, BTreeSet};

use crate::observation::Observation;
use crate::proto::{Client, Node, NodeFingerprint};
use crate::subscription;

/// One entry per provider and content identity, in provider-name/payload order.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeIndex {
    entries: Vec<IndexEntry>,
}

impl NodeIndex {
    /// The input supplies one current observation per provider.
    pub fn from_observations<'a, I>(observations: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a Observation)>,
    {
        let observations: BTreeMap<_, _> = observations.into_iter().collect();
        let mut entries = Vec::new();

        for (provider, observation) in observations {
            let parsed = subscription::parse(observation.payload.as_bytes(), provider);

            for record in parsed.nodes {
                let source = Source {
                    provider: provider.to_string(),
                    name: record.name().to_string(),
                    position: record.provenance[0].position,
                };
                entries.push(IndexEntry {
                    id: record.id(),
                    node: record.node,
                    source,
                });
            }
        }

        Self { entries }
    }

    /// Stable provider-name order, then first occurrence in each payload.
    pub fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A current source entry; identity alone does not identify its provider.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexEntry {
    pub id: NodeFingerprint,
    pub node: Node<Client>,
    pub source: Source,
}

impl IndexEntry {
    /// The output spelling, which may be disambiguated without changing identity.
    pub fn name(&self) -> &str {
        self.node.name.as_str()
    }
}

/// The provider's unmodified spelling and zero-based payload position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub provider: String,
    pub name: String,
    pub position: usize,
}

/// Disambiguate shared identities or names without changing source attribution.
///
/// Names are rebuilt from `source.name`, so collection unions can apply this
/// again without double-prefixing. Slice order breaks ties deterministically.
/// Candidate names are reserved before suffixing, including names that already
/// look like generated prefixes or numeric suffixes.
pub fn name_conflicts(entries: &mut [IndexEntry]) {
    let mut identities = BTreeMap::new();
    let mut names = BTreeMap::new();
    for entry in entries.iter() {
        *identities.entry(entry.id).or_insert(0) += 1;
        *names.entry(entry.source.name.as_str()).or_insert(0) += 1;
    }

    let candidates: Vec<String> = entries
        .iter()
        .map(|entry| {
            if identities[&entry.id] > 1 || names[entry.source.name.as_str()] > 1 {
                format!("[{}] {}", entry.source.provider, entry.source.name)
            } else {
                entry.source.name.clone()
            }
        })
        .collect();
    let reserved: BTreeSet<&str> = candidates.iter().map(String::as_str).collect();
    let mut used = BTreeSet::new();
    let mut suffixes = BTreeMap::new();

    for (entry, candidate) in entries.iter_mut().zip(&candidates) {
        let mut name = candidate.clone();
        if used.contains(&name) {
            let suffix = suffixes.entry(candidate).or_insert(2);
            loop {
                name = format!("{candidate} ({suffix})");
                *suffix += 1;
                if !reserved.contains(name.as_str()) && !used.contains(&name) {
                    break;
                }
            }
        }
        used.insert(name.clone());
        entry.node.name = name.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{decide, Fetched};

    fn link(host: &str, name: &str) -> String {
        format!("trojan://PASSWORD@{host}:443#{name}\n")
    }

    fn observed(payload: &str) -> Observation {
        Observation {
            payload: payload.to_string(),
            ..Observation::default()
        }
    }

    fn entry(provider: &str, host: &str, name: &str) -> IndexEntry {
        NodeIndex::from_observations([(provider, &observed(&link(host, name)))])
            .entries
            .remove(0)
    }

    #[test]
    fn a_replaced_snapshot_drops_removed_nodes_and_uses_current_payload_order() {
        let first = link("first.example.com", "First");
        let second = link("second.example.com", "Second");
        let third = link("third.example.com", "Third");
        let original = decide(
            "alpha",
            None,
            Fetched::from_payload(format!("{first}{second}")),
            10,
        )
        .observation
        .unwrap();
        let replacement = decide(
            "alpha",
            Some(&original),
            Fetched::from_payload(format!("{third}{second}")),
            20,
        )
        .observation
        .unwrap();
        let index = NodeIndex::from_observations([("alpha", &replacement)]);

        assert_eq!(
            index
                .entries()
                .iter()
                .map(IndexEntry::name)
                .collect::<Vec<_>>(),
            ["Third", "Second"]
        );
        assert_eq!(index.entries()[1].source.position, 1);

        let empty = decide("alpha", Some(&replacement), Fetched::from_payload(""), 30)
            .observation
            .unwrap();
        assert!(NodeIndex::from_observations([("alpha", &empty)]).is_empty());
    }

    #[test]
    fn provider_name_order_then_payload_order_is_independent_of_input_iteration() {
        let alpha = observed(&format!(
            "# comment\n{}\n{}",
            link("z.example.com", "Last alphabetically"),
            link("a.example.com", "First alphabetically")
        ));
        let beta = observed(&link("b.example.com", "Beta"));
        let forwards = NodeIndex::from_observations([("beta", &beta), ("alpha", &alpha)]);
        let backwards = NodeIndex::from_observations([("alpha", &alpha), ("beta", &beta)]);

        assert_eq!(forwards, backwards);
        assert_eq!(
            forwards
                .entries()
                .iter()
                .map(|entry| (
                    entry.source.provider.as_str(),
                    entry.name(),
                    entry.source.position
                ))
                .collect::<Vec<_>>(),
            [
                ("alpha", "Last alphabetically", 1),
                ("alpha", "First alphabetically", 3),
                ("beta", "Beta", 0),
            ]
        );
    }

    #[test]
    fn identical_content_from_distinct_providers_keeps_each_source_and_spelling() {
        let alpha = observed(&link("shared.example.com", "Alpha spelling"));
        let beta = observed(&link("shared.example.com", "Beta spelling"));
        let index = NodeIndex::from_observations([("beta", &beta), ("alpha", &alpha)]);

        assert_eq!(index.len(), 2);
        assert_eq!(index.entries()[0].id, index.entries()[1].id);
        assert_eq!(index.entries()[0].source.provider, "alpha");
        assert_eq!(index.entries()[0].name(), "Alpha spelling");
        assert_eq!(index.entries()[1].source.provider, "beta");
        assert_eq!(index.entries()[1].name(), "Beta spelling");
    }

    #[test]
    fn in_provider_identity_dedup_keeps_first_spelling_and_position() {
        let held = observed(&format!(
            "# comment\n{}{}{}",
            link("shared.example.com", "First"),
            link("other.example.com", "Other"),
            link("shared.example.com", "Duplicate")
        ));
        let index = NodeIndex::from_observations([("alpha", &held)]);

        assert_eq!(index.len(), 2);
        assert_eq!(
            index
                .entries()
                .iter()
                .map(IndexEntry::name)
                .collect::<Vec<_>>(),
            ["First", "Other"]
        );
        assert_eq!(index.entries()[0].source.name, "First");
        assert_eq!(index.entries()[0].source.position, 1);
    }

    #[test]
    fn shared_identities_prefix_even_distinct_names_without_changing_identity() {
        let mut entries = vec![
            entry("alpha", "shared.example.com", "First"),
            entry("beta", "shared.example.com", "Second"),
        ];
        let original = entries.clone();
        name_conflicts(&mut entries);

        assert_eq!(
            entries.iter().map(IndexEntry::name).collect::<Vec<_>>(),
            ["[alpha] First", "[beta] Second"]
        );
        for (named, original) in entries.iter().zip(original) {
            assert_eq!(named.id, original.id);
            assert_eq!(named.node.id(), original.node.id());
            assert_eq!(named.source, original.source);
        }
    }

    #[test]
    fn name_conflicts_across_and_within_providers_are_unique() {
        let mut entries = vec![
            entry("alpha", "first.example.com", "Shared"),
            entry("alpha", "second.example.com", "Shared"),
            entry("beta", "third.example.com", "Shared"),
            entry("beta", "fourth.example.com", "Unchanged"),
        ];
        name_conflicts(&mut entries);
        assert_eq!(
            entries.iter().map(IndexEntry::name).collect::<Vec<_>>(),
            [
                "[alpha] Shared",
                "[alpha] Shared (2)",
                "[beta] Shared",
                "Unchanged"
            ]
        );
    }

    #[test]
    fn generated_prefixes_and_suffixes_cannot_collide_with_original_names() {
        let mut entries = vec![
            entry("alpha", "first.example.com", "Shared"),
            entry("alpha", "second.example.com", "Shared"),
            entry("beta", "third.example.com", "[alpha] Shared"),
            entry("beta", "fourth.example.com", "[alpha] Shared (2)"),
            entry("beta", "fifth.example.com", "[alpha] Shared (3)"),
        ];
        name_conflicts(&mut entries);
        assert_eq!(
            entries.iter().map(IndexEntry::name).collect::<Vec<_>>(),
            [
                "[alpha] Shared",
                "[alpha] Shared (4)",
                "[alpha] Shared (5)",
                "[alpha] Shared (2)",
                "[alpha] Shared (3)"
            ]
        );
    }

    #[test]
    fn colliding_prefix_shapes_from_distinct_provider_names_remain_unique() {
        let mut entries = vec![
            entry("alpha] [beta", "first.example.com", "Node"),
            entry("alpha", "first.example.com", "[beta] Node"),
        ];
        name_conflicts(&mut entries);
        assert_eq!(
            entries.iter().map(IndexEntry::name).collect::<Vec<_>>(),
            ["[alpha] [beta] Node", "[alpha] [beta] Node (2)"]
        );
    }

    #[test]
    fn naming_restarts_from_sources_when_reapplied_or_membership_changes() {
        let mut entries = vec![
            entry("alpha", "first.example.com", "Shared"),
            entry("beta", "second.example.com", "Shared"),
        ];
        name_conflicts(&mut entries);
        assert_eq!(
            entries.iter().map(IndexEntry::name).collect::<Vec<_>>(),
            ["[alpha] Shared", "[beta] Shared"]
        );
        let once = entries.clone();
        name_conflicts(&mut entries);
        assert_eq!(entries, once);
        entries.pop();
        name_conflicts(&mut entries);
        assert_eq!(entries[0].name(), "Shared");
    }

    #[test]
    fn an_observation_with_nothing_in_it_adds_nothing() {
        let quiet = Observation::default();
        assert!(NodeIndex::from_observations([("quiet", &quiet)]).is_empty());
    }
}
