//! A collection: one subscription, assembled from providers.
//!
//! A collection is a **view, not a copy**. It names the providers it is built
//! from and how to narrow what they serve; it never holds nodes, and nothing
//! about it changes a provider. Nodes change, membership does not: a node that
//! appears in a provider shows up in every collection that names it, and one
//! that vanishes from a provider vanishes from them too.
//!
//! That is why it holds **names, never node ids**. An id list is a second truth
//! that drifts from what the providers actually serve — the operator edits the
//! subscription, the list does not notice — while "the part of that provider I
//! want" is a filter, evaluated against what is served right now.
//!
//! Resolution is a pure function of the index and the compiled filters: the same
//! inputs give the same nodes, in listed provider order and then payload order.
//! Different providers remain distinct sources even when their content matches;
//! conflicts are named only after filtering, without changing the provider index.
//!
//! Two filters apply, and they apply to the same spelling — the name the
//! provider itself used, because that is the name its own filter was written
//! against. A node survives a provider's filter and the collection's; a node the
//! collection's providers do not serve is not this collection's business at all
//! and is not counted anywhere.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::filter::{FilterError, NodeFilter, Pattern};
use crate::index::{IndexEntry, NodeIndex};

/// A collection: which providers it serves from, and what it filters out.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Collection {
    /// The providers it is assembled from, by the names their own document
    /// uses.
    ///
    /// Listed provider order determines result order; each provider retains
    /// its current payload order. A name listed twice contributes once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,

    /// Nodes to keep, as [`Pattern`]s.
    ///
    /// Extra filtering on top of what each provider already does: the provider's
    /// filter is a property of the source, this one of the collection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<Pattern>,

    /// Nodes to drop, in the same shape. Takes precedence over
    /// [`includes`](Self::includes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excludes: Vec<Pattern>,

    /// The delivery tokens, by the name the operator gave each one.
    ///
    /// One per device or person, so one can be revoked without changing the URL
    /// everyone else holds. Kept as minted, so the operator can read a URL again;
    /// this file is therefore a set of working subscription URLs.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tokens: BTreeMap<String, String>,
}

impl Collection {
    /// The collection's own filter, compiled.
    ///
    /// Called when the definition is written, so a pattern that cannot be used
    /// is refused where it was typed rather than discovered by a filter that
    /// quietly does less than it says.
    pub fn filter(&self) -> Result<NodeFilter, FilterError> {
        NodeFilter::compile(&self.includes, &self.excludes)
    }

    /// The nodes this collection serves.
    ///
    /// `providers` holds the compiled filter of every provider the caller knows
    /// about, by name; a name the collection lists that is not in there
    /// contributes nothing and is reported in [`Resolved::unresolved`], because
    /// a collection that quietly resolves to fewer nodes than it names is a
    /// collection whose operator is looking at the wrong subscription.
    ///
    /// `filter` is this collection's own, compiled by the caller: it is the same
    /// value for every request, and compiling it here would re-read the same
    /// patterns on every one.
    pub fn resolve(
        &self,
        index: &NodeIndex,
        providers: &BTreeMap<String, NodeFilter>,
        filter: &NodeFilter,
    ) -> Resolved {
        let mut visited = BTreeSet::new();
        let mut unresolved = Vec::new();
        let mut nodes = Vec::new();
        let mut passed_over = 0;

        for name in &self.providers {
            if !visited.insert(name) {
                continue;
            }
            let Some(provider) = providers.get(name) else {
                unresolved.push(name.clone());
                continue;
            };

            for entry in index
                .entries()
                .iter()
                .filter(|entry| entry.source.provider == *name)
            {
                if provider.admits(&entry.source.name) && filter.admits(&entry.source.name) {
                    nodes.push(entry.clone());
                } else {
                    passed_over += 1;
                }
            }
        }

        crate::index::name_conflicts(&mut nodes);
        Resolved {
            nodes,
            passed_over,
            unresolved,
        }
    }
}

/// Owned output names cannot change the provider's original spelling.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// Listed provider order, then each provider's payload order.
    pub nodes: Vec<IndexEntry>,
    pub passed_over: usize,
    /// Missing provider definitions, in first-listed order.
    pub unresolved: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{observation::Observation, proto::parse_link, proto::NodeFingerprint};

    const ALPHA: &str = "alpha.example.com";
    const BETA: &str = "beta.example.com";

    fn link(host: &str, name: &str) -> String {
        format!("trojan://hunter2@{host}:443#{name}\n")
    }

    fn id(link: &str) -> NodeFingerprint {
        parse_link(link.trim_end())
            .expect("the fixture parses")
            .id()
    }

    fn observed(payload: &str) -> Observation {
        Observation {
            payload: payload.to_string(),
            ..Observation::default()
        }
    }

    fn index(observations: &[(&str, &Observation)]) -> NodeIndex {
        NodeIndex::from_observations(
            observations
                .iter()
                .map(|(provider, observation)| (*provider, *observation)),
        )
    }

    fn filter(include: &[&str], exclude: &[&str]) -> NodeFilter {
        NodeFilter::compile(
            &crate::filter::prefixed(include),
            &crate::filter::prefixed(exclude),
        )
        .expect("the fixture compiles")
    }

    fn unfiltered() -> NodeFilter {
        filter(&[], &[])
    }

    fn providers(filters: Vec<(&str, NodeFilter)>) -> BTreeMap<String, NodeFilter> {
        filters
            .into_iter()
            .map(|(name, filter)| (name.to_string(), filter))
            .collect()
    }

    fn collection(providers: &[&str]) -> Collection {
        Collection {
            providers: providers.iter().map(|name| name.to_string()).collect(),
            ..Collection::default()
        }
    }

    fn names(resolved: &Resolved) -> Vec<&str> {
        resolved.nodes.iter().map(IndexEntry::name).collect()
    }

    #[test]
    fn a_provider_the_collection_does_not_name_is_not_its_business() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let beta = observed(&link(BETA, "JP-01"));
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &unfiltered(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(
            resolved.passed_over, 0,
            "a node no named provider serves was never a candidate"
        );
    }

    #[test]
    fn the_providers_it_names_contribute_together() {
        let shared = link(ALPHA, "Shared");
        let alpha = observed(&shared);
        let beta = observed(&format!("{}{}", link(BETA, "JP-01"), shared));
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha", "beta"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &unfiltered(),
        );

        assert_eq!(
            names(&resolved),
            ["[alpha] Shared", "JP-01", "[beta] Shared"],
            "each provider contributes its own source entry"
        );
    }

    #[test]
    fn a_node_a_filter_passes_over_is_counted() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let beta = observed(&link(BETA, "JP-01"));
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha", "beta"]).resolve(
            &index,
            &providers(vec![
                ("alpha", unfiltered()),
                ("beta", filter(&[], &["JP-01"])),
            ]),
            &unfiltered(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.passed_over, 1, "the count is reported, not lost");
    }

    #[test]
    fn exclude_still_beats_include() {
        let us = link(ALPHA, "US-01");
        let jp = link(BETA, "JP-01");
        let alpha = observed(&format!("{us}{jp}"));
        let index = index(&[("alpha", &alpha)]);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &filter(&["US-01", "JP-01"], &["JP-01"]),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.passed_over, 1);
    }

    /// A filter is read against the name the provider itself used.
    ///
    /// The same node can be spelled differently by two providers, and a
    /// provider's filter is a statement about *its* payload — so the collection's
    /// filter is read the same way, against the spelling of the provider that
    /// offered the node.
    #[test]
    fn a_name_is_matched_the_way_the_provider_spelled_it() {
        let us = link(ALPHA, "US-01");
        let states = link(ALPHA, "United States");

        assert_eq!(id(&us), id(&states), "the fixture is one node, two names");

        let alpha = observed(&us);
        let beta = observed(&states);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        // Both providers named: alpha's spelling matches, so the node is in.
        let resolved = collection(&["alpha", "beta"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &filter(&["US-01"], &[]),
        );
        assert_eq!(names(&resolved), ["US-01"]);

        // Only the provider that spells it differently: now nothing matches.
        let resolved = collection(&["beta"]).resolve(
            &index,
            &providers(vec![("beta", unfiltered())]),
            &filter(&["US-01"], &[]),
        );
        assert!(resolved.nodes.is_empty());
        assert_eq!(resolved.passed_over, 1);
    }

    #[test]
    fn a_provider_it_names_that_has_no_definition_is_reported() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let index = index(&[("alpha", &alpha)]);

        let resolved = collection(&["alpha", "ghost"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &unfiltered(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.unresolved, ["ghost"]);
    }

    #[test]
    fn a_name_listed_twice_contributes_once() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let index = index(&[("alpha", &alpha)]);

        let resolved = collection(&["alpha", "alpha", "ghost", "ghost"]).resolve(
            &index,
            &providers(vec![("alpha", filter(&["US-01"], &[]))]),
            &unfiltered(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.unresolved, ["ghost"]);
    }

    #[test]
    fn listed_provider_order_takes_precedence_over_index_order() {
        let first = link(ALPHA, "First");
        let second = link(BETA, "Second");
        let alpha = observed(&first);
        let beta = observed(&second);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["beta", "alpha"]).resolve(
            &index,
            &providers(vec![("beta", unfiltered()), ("alpha", unfiltered())]),
            &unfiltered(),
        );

        assert_eq!(names(&resolved), ["Second", "First"]);
    }

    /// Removing a provider takes away its nodes and nothing else.
    #[test]
    fn removing_a_provider_leaves_the_other_nodes_untouched() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let beta = observed(&link(BETA, "JP-01"));
        let inline = observed(&link("local", "Hand written"));
        let index = index(&[("alpha", &alpha), ("beta", &beta), ("inline", &inline)]);
        let filters = providers(vec![
            ("alpha", unfiltered()),
            ("beta", unfiltered()),
            ("inline", unfiltered()),
        ]);

        let all = collection(&["alpha", "beta", "inline"]).resolve(&index, &filters, &unfiltered());
        let without_alpha =
            collection(&["beta", "inline"]).resolve(&index, &filters, &unfiltered());

        assert_eq!(names(&all), ["US-01", "JP-01", "Hand written"]);
        assert_eq!(
            names(&without_alpha),
            ["JP-01", "Hand written"],
            "only the removed provider's node is gone"
        );
        assert_eq!(
            all.nodes[1..]
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            without_alpha
                .nodes
                .iter()
                .map(|entry| entry.id)
                .collect::<Vec<_>>(),
            "and the others are the same nodes, in the same order"
        );
    }

    #[test]
    fn resolved_entries_keep_provider_payload_order_and_leave_source_names_untouched() {
        let alpha = observed(&format!(
            "{}{}",
            link(ALPHA, "Shared"),
            link("third.example.com", "Alpha tail")
        ));
        let beta = observed(&format!("{}{}", link(BETA, "Shared"), link(ALPHA, "Alias")));
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);
        let original = index.clone();
        let filters = providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]);

        let resolved =
            collection(&["beta", "alpha", "beta"]).resolve(&index, &filters, &unfiltered());
        assert_eq!(
            names(&resolved),
            [
                "[beta] Shared",
                "[beta] Alias",
                "[alpha] Shared",
                "Alpha tail"
            ]
        );
        assert_eq!(
            resolved
                .nodes
                .iter()
                .map(|entry| (entry.source.provider.as_str(), entry.source.position))
                .collect::<Vec<_>>(),
            [("beta", 0), ("beta", 1), ("alpha", 0), ("alpha", 1)]
        );
        assert_eq!(resolved.nodes[1].id, resolved.nodes[2].id);
        assert_eq!(index, original);

        let narrowed =
            collection(&["beta", "alpha"]).resolve(&index, &filters, &filter(&["Alias"], &[]));
        assert_eq!(names(&narrowed), ["Alias"]);
        assert_eq!(narrowed.passed_over, 3);
        assert_eq!(narrowed.nodes[0].source.provider, "beta");
    }

    #[test]
    fn the_same_collection_resolves_to_the_same_nodes_twice() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let beta = observed(&link(BETA, "JP-01"));
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);
        let filters = providers(vec![
            ("alpha", unfiltered()),
            ("beta", filter(&[], &["nothing"])),
        ]);
        let collection = collection(&["alpha", "beta"]);

        let once = collection.resolve(&index, &filters, &unfiltered());
        let twice = collection.resolve(&index, &filters, &unfiltered());

        assert_eq!(once, twice);
    }

    #[test]
    fn an_empty_collection_resolves_to_nothing() {
        let alpha = observed(&link(ALPHA, "US-01"));
        let index = index(&[("alpha", &alpha)]);

        let resolved = Collection::default().resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &unfiltered(),
        );

        assert!(resolved.nodes.is_empty());
    }

    /// A pattern that cannot be compiled is refused where it is stored.
    #[test]
    fn the_collections_own_filter_is_validated_like_a_providers() {
        let broken = Collection {
            providers: vec!["alpha".to_string()],
            includes: crate::filter::prefixed(&["regex:("]),
            ..Collection::default()
        };

        assert!(matches!(broken.filter(), Err(FilterError::Pattern { .. })));
        assert!(Collection::default().filter().unwrap().is_unfiltered());
    }
}
