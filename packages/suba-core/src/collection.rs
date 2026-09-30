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
//! inputs give the same nodes, in the same order, and the order is the index's
//! (oldest first). Node order is what a client displays and what a rename can
//! refer to by position, so it must not depend on the order a map iterated in.
//!
//! Two filters apply, and they apply to the same spelling — the name the
//! provider itself used, because that is the name its own filter was written
//! against. A node survives a provider's filter and the collection's; a node the
//! collection's providers do not serve is not this collection's business at all
//! and is not counted anywhere.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::filter::{FilterError, NodeFilter};
use crate::format::Format;
use crate::index::{IndexEntry, NodeIndex};

/// A collection: which providers it serves from, and what it filters out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Collection {
    /// The providers it is assembled from, by the names their own document
    /// uses.
    ///
    /// The order they are listed in is not the order of the result: a node's
    /// position is the index's, so that adding a provider to the list does not
    /// renumber the nodes the other providers contributed. A name listed twice
    /// contributes once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,

    /// Nodes to keep, in the vocabulary of [`NodeFilter`].
    ///
    /// Extra filtering on top of what each provider already does: the provider's
    /// filter is a property of the source, this one of the collection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<String>,

    /// Nodes to drop, in the same vocabulary. Takes precedence over
    /// [`includes`](Self::includes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excludes: Vec<String>,

    /// The format this collection's artifact is written in.
    ///
    /// Declared, not guessed: whoever subscribes to the URL gets what this says,
    /// and a client that wants something else is asking the wrong URL. Links by
    /// default, because a collection hands out a subscription and a link list is
    /// the shape every client reads.
    #[serde(default = "links", skip_serializing_if = "is_links")]
    pub format: Format,

    /// The delivery token, as a hash.
    ///
    /// The token itself is handed to whoever minted it and is never written
    /// down: what is kept is the sha256 of it, so a copied configuration file is
    /// not a set of working subscription URLs. Recognising a token that comes
    /// back in a URL needs nothing but the hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// The format a collection serves in when its document does not say.
fn links() -> Format {
    Format::Links
}

/// Whether a collection is written in the format a subscription is in anyway.
fn is_links(format: &Format) -> bool {
    *format == Format::Links
}

impl Default for Collection {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            includes: Vec::new(),
            excludes: Vec::new(),
            format: Format::Links,
            token: None,
        }
    }
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
    pub fn resolve<'a>(
        &self,
        index: &'a NodeIndex,
        providers: &BTreeMap<String, NodeFilter>,
        filter: &NodeFilter,
        view: View,
    ) -> Resolved<'a> {
        let mut members: Vec<(&str, &NodeFilter)> = Vec::new();
        let mut unresolved: Vec<String> = Vec::new();

        for name in &self.providers {
            match providers.get(name.as_str()) {
                Some(provider) if !members.iter().any(|(member, _)| *member == name) => {
                    members.push((name, provider));
                }
                Some(_) => {}
                None if !unresolved.contains(name) => unresolved.push(name.clone()),
                None => {}
            }
        }

        let mut nodes = Vec::new();
        let mut passed_over = 0;
        let mut orphans = 0;

        for entry in index.entries() {
            let mut belongs = false;
            let mut serves_now = false;
            let mut admitted = false;

            for source in &entry.sources {
                let Some((_, provider)) = members.iter().find(|(name, _)| *name == source.provider)
                else {
                    continue;
                };

                belongs = true;

                // A source that has stopped serving it says the node existed,
                // not that it is served now; there is no name to filter either.
                if !source.serving {
                    continue;
                }

                serves_now = true;

                if let Some(name) = source.name.as_deref() {
                    admitted |= provider.admits(name) && filter.admits(name);
                }
            }

            if !belongs {
                // Some other provider's node entirely: not dropped, not this
                // collection's business.
                continue;
            }

            if entry.is_orphan() {
                // Counted whether or not it was asked for: a provider that
                // quietly shrank is something the operator needs to see.
                orphans += 1;

                if view.orphans {
                    nodes.push(entry);
                }

                continue;
            }

            if !serves_now {
                // A provider of this collection dropped it, and nobody else
                // here serves it. It is not a filter's doing.
                continue;
            }

            match admitted {
                true => nodes.push(entry),
                false => passed_over += 1,
            }
        }

        Resolved {
            nodes,
            passed_over,
            orphans,
            unresolved,
        }
    }
}

/// What a resolution was asked for.
///
/// Everything here narrows what a collection serves; nothing here can add a node
/// the collection would not otherwise serve.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct View {
    /// Include the nodes nothing serves any more.
    ///
    /// Off by default. An orphan has no content — no payload mentions it — so a
    /// delivery cannot send it anywhere; what a structural view can do with it is
    /// show that it existed, and that it is gone.
    pub orphans: bool,
}

/// What a collection resolves to.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved<'a> {
    /// The nodes to serve, in the index's order.
    pub nodes: Vec<&'a IndexEntry>,
    /// How many nodes a filter passed over.
    pub passed_over: usize,
    /// How many nodes nothing serves any more.
    pub orphans: usize,
    /// Providers the collection names whose definition the caller could not
    /// supply.
    pub unresolved: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{observation::Observation, proto::parse_link, proto::NodeFingerprint};

    const NOW: i64 = 1_700_000_000;
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

    /// An observation of `payload`, where `seen` are the nodes it has ever
    /// served and when each was first seen.
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

    fn index(observations: &[(&str, &Observation)]) -> NodeIndex {
        // These fixtures are all link lists; which shapes a build can read is
        // not what this module is about.
        let links = crate::subscription::DeclaredFormat::Links;

        NodeIndex::from_observations(
            observations
                .iter()
                .map(|(provider, observation)| (*provider, links, *observation)),
        )
    }

    fn filter(include: &[&str], exclude: &[&str]) -> NodeFilter {
        let owned = |patterns: &[&str]| {
            patterns
                .iter()
                .map(|pattern| pattern.to_string())
                .collect::<Vec<_>>()
        };

        NodeFilter::compile(&owned(include), &owned(exclude)).expect("the fixture compiles")
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

    fn names<'a>(resolved: &Resolved<'a>) -> Vec<&'a str> {
        resolved
            .nodes
            .iter()
            .map(|entry| entry.name().expect("every resolved node is served"))
            .collect()
    }

    #[test]
    fn a_provider_the_collection_does_not_name_is_not_its_business() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let beta = observed(&link(BETA, "JP-01"), &[(&link(BETA, "JP-01"), 2_000)]);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &unfiltered(),
            View::default(),
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
        let alpha = observed(&shared, &[(&shared, 1_000)]);
        let beta = observed(
            &format!("{}{}", link(BETA, "JP-01"), shared),
            &[(&link(BETA, "JP-01"), 2_000), (&shared, 1_000)],
        );
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha", "beta"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &unfiltered(),
            View::default(),
        );

        assert_eq!(
            names(&resolved),
            ["Shared", "JP-01"],
            "a node two providers serve is one node"
        );
    }

    #[test]
    fn a_node_a_filter_passes_over_is_counted() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let beta = observed(&link(BETA, "JP-01"), &[(&link(BETA, "JP-01"), 2_000)]);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha", "beta"]).resolve(
            &index,
            &providers(vec![
                ("alpha", unfiltered()),
                ("beta", filter(&[], &["JP-01"])),
            ]),
            &unfiltered(),
            View::default(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.passed_over, 1, "the count is reported, not lost");
    }

    #[test]
    fn exclude_still_beats_include() {
        let us = link(ALPHA, "US-01");
        let jp = link(BETA, "JP-01");
        let alpha = observed(&format!("{us}{jp}"), &[(&us, 1_000), (&jp, 1_000)]);
        let index = index(&[("alpha", &alpha)]);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &filter(&["US-01", "JP-01"], &["JP-01"]),
            View::default(),
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

        let alpha = observed(&us, &[(&us, 1_000)]);
        let beta = observed(&states, &[(&states, 2_000)]);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        // Both providers named: alpha's spelling matches, so the node is in.
        let resolved = collection(&["alpha", "beta"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &filter(&["US-01"], &[]),
            View::default(),
        );
        assert_eq!(names(&resolved), ["US-01"]);

        // Only the provider that spells it differently: now nothing matches.
        let resolved = collection(&["beta"]).resolve(
            &index,
            &providers(vec![("beta", unfiltered())]),
            &filter(&["US-01"], &[]),
            View::default(),
        );
        assert!(resolved.nodes.is_empty());
        assert_eq!(resolved.passed_over, 1);
    }

    #[test]
    fn orphans_are_counted_and_left_out_unless_they_are_asked_for() {
        let gone = link(ALPHA, "Gone");
        let alpha = observed("", &[(&gone, 1_000)]);
        let index = index(&[("alpha", &alpha)]);
        let providers = providers(vec![("alpha", unfiltered())]);

        let resolved =
            collection(&["alpha"]).resolve(&index, &providers, &unfiltered(), View::default());
        assert!(resolved.nodes.is_empty(), "a dead endpoint is not served");
        assert_eq!(resolved.orphans, 1);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers,
            &unfiltered(),
            View { orphans: true },
        );
        assert_eq!(resolved.nodes.len(), 1);
        assert!(resolved.nodes[0].is_orphan());
    }

    #[test]
    fn an_orphan_of_a_provider_it_does_not_name_is_not_counted() {
        let gone = link(BETA, "Gone");
        let beta = observed("", &[(&gone, 1_000)]);
        let index = index(&[("beta", &beta)]);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered()), ("beta", unfiltered())]),
            &unfiltered(),
            View::default(),
        );

        assert!(resolved.nodes.is_empty());
        assert_eq!(resolved.orphans, 0);
    }

    /// A node a member stopped serving is not this collection's to report when
    /// someone else still serves it: it is not an orphan (the index says so), and
    /// no filter passed over it.
    #[test]
    fn a_node_a_member_dropped_but_still_served_is_not_reported() {
        let shared = link(ALPHA, "Shared");
        let alpha = observed("", &[(&shared, 1_000)]);
        let beta = observed(&shared, &[(&shared, 2_000)]);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["alpha"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &unfiltered(),
            View { orphans: true },
        );

        assert!(resolved.nodes.is_empty());
        assert_eq!(resolved.orphans, 0);
        assert_eq!(resolved.passed_over, 0);
    }

    #[test]
    fn a_provider_it_names_that_has_no_definition_is_reported() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let index = index(&[("alpha", &alpha)]);

        let resolved = collection(&["alpha", "ghost"]).resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &unfiltered(),
            View::default(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.unresolved, ["ghost"]);
    }

    #[test]
    fn a_name_listed_twice_contributes_once() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let index = index(&[("alpha", &alpha)]);

        let resolved = collection(&["alpha", "alpha", "ghost", "ghost"]).resolve(
            &index,
            &providers(vec![("alpha", filter(&["US-01"], &[]))]),
            &unfiltered(),
            View::default(),
        );

        assert_eq!(names(&resolved), ["US-01"]);
        assert_eq!(resolved.unresolved, ["ghost"]);
    }

    /// The result's order is the index's, so the listing order cannot renumber
    /// nodes.
    #[test]
    fn the_order_is_the_index_order_not_the_listing_order() {
        let first = link(ALPHA, "First");
        let second = link(BETA, "Second");
        let alpha = observed(&first, &[(&first, 1_000)]);
        let beta = observed(&second, &[(&second, 2_000)]);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);

        let resolved = collection(&["beta", "alpha"]).resolve(
            &index,
            &providers(vec![("beta", unfiltered()), ("alpha", unfiltered())]),
            &unfiltered(),
            View::default(),
        );

        assert_eq!(names(&resolved), ["First", "Second"]);
    }

    /// Removing a provider takes away its nodes and nothing else.
    #[test]
    fn removing_a_provider_leaves_the_other_nodes_untouched() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let beta = observed(&link(BETA, "JP-01"), &[(&link(BETA, "JP-01"), 2_000)]);
        let inline = observed(
            &link("local", "Hand written"),
            &[(&link("local", "Hand written"), 3_000)],
        );
        let index = index(&[("alpha", &alpha), ("beta", &beta), ("inline", &inline)]);
        let filters = providers(vec![
            ("alpha", unfiltered()),
            ("beta", unfiltered()),
            ("inline", unfiltered()),
        ]);

        let all = collection(&["alpha", "beta", "inline"]).resolve(
            &index,
            &filters,
            &unfiltered(),
            View::default(),
        );
        let without_alpha = collection(&["beta", "inline"]).resolve(
            &index,
            &filters,
            &unfiltered(),
            View::default(),
        );

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
    fn the_same_collection_resolves_to_the_same_nodes_twice() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let beta = observed(&link(BETA, "JP-01"), &[(&link(BETA, "JP-01"), 2_000)]);
        let index = index(&[("alpha", &alpha), ("beta", &beta)]);
        let filters = providers(vec![
            ("alpha", unfiltered()),
            ("beta", filter(&[], &["nothing"])),
        ]);
        let collection = collection(&["alpha", "beta"]);

        let once = collection.resolve(&index, &filters, &unfiltered(), View::default());
        let twice = collection.resolve(&index, &filters, &unfiltered(), View::default());

        assert_eq!(once, twice);
    }

    #[test]
    fn an_empty_collection_resolves_to_nothing() {
        let alpha = observed(&link(ALPHA, "US-01"), &[(&link(ALPHA, "US-01"), 1_000)]);
        let index = index(&[("alpha", &alpha)]);

        let resolved = Collection::default().resolve(
            &index,
            &providers(vec![("alpha", unfiltered())]),
            &unfiltered(),
            View::default(),
        );

        assert!(resolved.nodes.is_empty());
    }

    /// A pattern that cannot be compiled is refused where it is stored.
    #[test]
    fn the_collections_own_filter_is_validated_like_a_providers() {
        let broken = Collection {
            providers: vec!["alpha".to_string()],
            includes: vec!["regex:(".to_string()],
            ..Collection::default()
        };

        assert!(matches!(broken.filter(), Err(FilterError::Pattern { .. })));
        assert!(Collection::default().filter().unwrap().is_unfiltered());
    }
}
