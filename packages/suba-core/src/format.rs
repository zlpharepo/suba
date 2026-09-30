//! The formats a collection can be served in, and what each of them can say.
//!
//! A format is a **document shape**, not a step in a pipeline. Rendering is a
//! pure function of the nodes and the direction the caller asked for, so the
//! same node set can be handed out as links, as a clash document, as a sing-box
//! configuration — and the caller is the one who knows which of those the
//! client on the other end understands.
//!
//! Two things are deliberate here:
//!
//! * **The direction is asked for, never assumed.** A node can be written as
//!   something a client dials or as something a server runs, and the two are not
//!   the same document; a default would silently hand out the wrong one. A
//!   format that cannot write the direction asked for refuses, rather than
//!   producing its other one.
//! * **What cannot be written is reported, not dropped.** A node a format has no
//!   representation for is left out *with a reason*, per node, and a caller can
//!   learn what a format will refuse **before** rendering, from its
//!   [`FormatDescriptor`]. A subscription that quietly serves fewer nodes than
//!   it should is worse than one that says which ones it could not serve.
//!
//! A format whose dialect is not compiled into this build is not a
//! [`Format`] at all: [`Format::all`] is the truth about what this build serves,
//! and a request naming anything else cannot be parsed into one.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::index::IndexEntry;
use crate::proto::{self, write_link, Kind};
#[cfg(any(feature = "singbox", feature = "clash"))]
use crate::proto::{Client, Node};

/// A document shape a collection can be served in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// The share links themselves, one per line.
    Links,
    /// A sing-box configuration, with one outbound per node.
    #[cfg(feature = "singbox")]
    Singbox,
    /// A clash configuration, with one proxy per node.
    #[cfg(feature = "clash")]
    Clash,
}

impl Format {
    /// Every format this build can serve.
    ///
    /// Compiled, not configured: a format whose dialect is behind a feature that
    /// is off is absent here, which is what makes "this build does not serve
    /// that" a fact rather than a runtime check somebody can forget to perform.
    pub fn all() -> &'static [Self] {
        #[cfg(all(feature = "singbox", feature = "clash"))]
        let formats: &'static [Self] = &[Self::Links, Self::Singbox, Self::Clash];
        #[cfg(all(feature = "singbox", not(feature = "clash")))]
        let formats: &'static [Self] = &[Self::Links, Self::Singbox];
        #[cfg(all(feature = "clash", not(feature = "singbox")))]
        let formats: &'static [Self] = &[Self::Links, Self::Clash];
        #[cfg(not(any(feature = "singbox", feature = "clash")))]
        let formats: &'static [Self] = &[Self::Links];

        formats
    }

    /// The name it is spelled with, in documents and in URLs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Links => "links",
            #[cfg(feature = "singbox")]
            Self::Singbox => "singbox",
            #[cfg(feature = "clash")]
            Self::Clash => "clash",
        }
    }

    /// What it can express, before anything is rendered.
    pub const fn descriptor(self) -> FormatDescriptor {
        match self {
            Self::Links => FormatDescriptor {
                format: self,
                intents: &[RenderIntent::Client],
                // A link is what the model is parsed *from*: whatever a provider
                // served, the model holds enough to write it back. A protocol
                // whose link form is unknown is kept whole for exactly this
                // reason.
                protocols: ProtocolSupport::Everything,
            },
            // The dialect's own table, so that what it says it can write and
            // what it writes cannot drift apart.
            #[cfg(feature = "singbox")]
            Self::Singbox => FormatDescriptor {
                format: self,
                intents: &[RenderIntent::Client],
                protocols: ProtocolSupport::Only(suba_singbox::PROTOCOLS),
            },
            #[cfg(feature = "clash")]
            Self::Clash => FormatDescriptor {
                format: self,
                intents: &[RenderIntent::Client],
                protocols: ProtocolSupport::Only(suba_clash::PROTOCOLS),
            },
        }
    }

    /// Write `nodes` as this format.
    ///
    /// The nodes are the resolved ones, in the order they are to appear;
    /// anything this format cannot write is left out and reported in
    /// [`Rendered::skipped`], with one reason per node.
    pub fn render(
        self,
        nodes: &[&IndexEntry],
        intent: RenderIntent,
    ) -> Result<Rendered, RenderError> {
        if !self.descriptor().intents.contains(&intent) {
            return Err(RenderError::Intent {
                format: self,
                intent,
            });
        }

        let mut rendered = Rendered::default();

        match self {
            Self::Links => rendered.body = self.render_links(nodes, &mut rendered.skipped),
            #[cfg(feature = "singbox")]
            Self::Singbox => rendered.body = self.render_singbox(nodes, &mut rendered.skipped),
            #[cfg(feature = "clash")]
            Self::Clash => rendered.body = self.render_clash(nodes, &mut rendered.skipped),
        }

        Ok(rendered)
    }

    /// The links, one per line.
    fn render_links(self, nodes: &[&IndexEntry], skipped: &mut Vec<Skipped>) -> String {
        let mut body = String::new();

        for entry in nodes {
            let Some(node) = entry.node.as_ref() else {
                skipped.push(orphan(entry));

                continue;
            };

            match write_link(node) {
                Ok(link) => {
                    body.push_str(&link);
                    body.push('\n');
                }
                // Never silently dropped: the node is left out with what the
                // model said about it.
                Err(error) => skipped.push(Skipped {
                    id: entry.id,
                    name: entry.name().map(str::to_owned),
                    reason: SkipReason::Refused {
                        kind: error.kind(),
                        reason: error.to_string(),
                    },
                }),
            }
        }

        body
    }

    /// A sing-box configuration, as the dialect writes it.
    #[cfg(feature = "singbox")]
    fn render_singbox(self, nodes: &[&IndexEntry], skipped: &mut Vec<Skipped>) -> String {
        let (outbounds, refused) = outbounds(nodes);
        skipped.extend(refused);

        // The values are built here, so a failure would be this crate's bug
        // rather than something a caller could act on.
        serde_json::to_string(&serde_json::json!({ "outbounds": outbounds }))
            .expect("the document this crate built")
    }

    /// A clash document, as the dialect writes it.
    #[cfg(feature = "clash")]
    fn render_clash(self, nodes: &[&IndexEntry], skipped: &mut Vec<Skipped>) -> String {
        // What can be written at all: a node nobody serves has no content, so it
        // is not the dialect's to refuse.
        let writable: Vec<(&IndexEntry, &Node<Client>)> = nodes
            .iter()
            .filter_map(|entry| match entry.node.as_ref() {
                Some(node) => Some((*entry, node)),
                None => {
                    skipped.push(orphan(entry));

                    None
                }
            })
            .collect();

        let named: Vec<(&str, &Node<Client>)> = writable
            .iter()
            .map(|(entry, node)| (entry.name().unwrap_or_default(), *node))
            .collect();

        let (body, refused) = suba_clash::client_config(&named);

        // A refusal names a position in what the dialect was given, which is the
        // position in `writable`: orphans were taken out before it was called.
        for refusal in refused {
            let (entry, _) = writable[refusal.index];

            skipped.push(Skipped {
                id: entry.id,
                name: entry.name().map(str::to_owned),
                reason: match refusal.reason {
                    suba_clash::Reason::Protocol(kind) => SkipReason::Protocol(kind),
                    suba_clash::Reason::Transport(carriage) => SkipReason::Transport(carriage),
                    // The dialect could not spell a value clash accepts; the field
                    // and what the node said are the whole explanation, and
                    // neither is a credential.
                    suba_clash::Reason::Value { field, spelling } => SkipReason::Refused {
                        kind: proto::ErrorKind::InvalidValue,
                        reason: format!("{field}: {spelling} has no clash spelling"),
                    },
                },
            });
        }

        body
    }
}

/// A node no document can contain: nothing serves it any more, so there is no
/// content to write into one. `IndexEntry` keeps the identity and the history,
/// deliberately not a copy of a payload that is gone.
fn orphan(entry: &IndexEntry) -> Skipped {
    Skipped {
        id: entry.id,
        name: None,
        reason: SkipReason::Orphan,
    }
}
/// The outbounds a set of nodes contributes to a configuration this host runs.
///
/// The same walk a rendered sing-box document takes, stopping one step earlier:
/// the values, not the document, because a caller puts them beside the fragments
/// a user wrote rather than serving them. What the dialect refuses is reported
/// against the entry it came from, so an assembly can say what it did not carry
/// instead of quietly carrying less.
#[cfg(feature = "singbox")]
pub fn outbounds(entries: &[&IndexEntry]) -> (Vec<serde_json::Value>, Vec<Skipped>) {
    let mut skipped = Vec::new();
    let writable = writable(entries, &mut skipped);

    let named: Vec<(&str, &Node<Client>)> = writable
        .iter()
        .map(|(entry, node)| (entry.name().unwrap_or_default(), *node))
        .collect();

    let (outbounds, refused) = suba_singbox::outbounds(&named);
    refusals(&writable, refused, &mut skipped);

    (outbounds, skipped)
}

/// The entries a document can hold at all.
///
/// A node nobody serves any more has no content, so leaving it out is a fact
/// about the index rather than something a dialect decided.
#[cfg(feature = "singbox")]
fn writable<'a>(
    entries: &[&'a IndexEntry],
    skipped: &mut Vec<Skipped>,
) -> Vec<(&'a IndexEntry, &'a Node<Client>)> {
    entries
        .iter()
        .filter_map(|entry| match entry.node.as_ref() {
            Some(node) => Some((*entry, node)),
            None => {
                skipped.push(orphan(entry));

                None
            }
        })
        .collect()
}

/// Which entry each refusal came from.
///
/// A dialect reports a position in what it was given, which is the position in
/// `writable`: the orphans were taken out before it was called.
#[cfg(feature = "singbox")]
fn refusals(
    writable: &[(&IndexEntry, &Node<Client>)],
    refused: Vec<suba_singbox::Refused>,
    skipped: &mut Vec<Skipped>,
) {
    for refusal in refused {
        let (entry, _) = writable[refusal.index];

        skipped.push(Skipped {
            id: entry.id,
            name: entry.name().map(str::to_owned),
            reason: match refusal.reason {
                suba_singbox::Reason::Protocol(kind) => SkipReason::Protocol(kind),
                suba_singbox::Reason::Transport(carriage) => SkipReason::Transport(carriage),
                // The dialect could not spell a value sing-box accepts; the
                // field and what the node said are the whole explanation, and
                // neither is a credential.
                suba_singbox::Reason::Value { field, spelling } => SkipReason::Refused {
                    kind: proto::ErrorKind::InvalidValue,
                    reason: format!("{field}: {spelling} has no sing-box spelling"),
                },
            },
        });
    }
}
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which way round a document is written.
///
/// Asked for by the caller, never defaulted: the two directions are different
/// documents, and only the caller knows which one the other end can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RenderIntent {
    /// A document a client subscribes to: the nodes as that client dials them.
    Client,
    /// A document a server runs: the same nodes as what it serves.
    Server,
}

impl RenderIntent {
    /// The name it is spelled with, in documents and in URLs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

impl fmt::Display for RenderIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a format can express, before anything is rendered.
///
/// The point of asking first: a caller can tell an operator which nodes will be
/// left out *before* a document is produced, instead of comparing what was asked
/// for against what came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatDescriptor {
    pub format: Format,
    /// The directions this format can write.
    pub intents: &'static [RenderIntent],
    /// The protocols it can express.
    pub protocols: ProtocolSupport,
}

impl FormatDescriptor {
    /// Why this format cannot write a node of this kind, if it cannot.
    pub fn refuses(&self, kind: Kind) -> Option<SkipReason> {
        match self.protocols.expresses(kind) {
            true => None,
            false => Some(SkipReason::Protocol(kind)),
        }
    }
}

/// Which protocols a format has a representation for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSupport {
    /// Every protocol the model knows — including one it does not model, which
    /// it can still hand back as it arrived.
    Everything,
    /// These, and no others.
    Only(&'static [Kind]),
}

impl ProtocolSupport {
    pub fn expresses(&self, kind: Kind) -> bool {
        match self {
            Self::Everything => true,
            Self::Only(kinds) => kinds.contains(&kind),
        }
    }
}

/// A document, and what had to be left out of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rendered {
    /// The document.
    pub body: String,
    /// The nodes it does not contain, each with the reason.
    pub skipped: Vec<Skipped>,
}

/// A node a document does not contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Which node, by identity.
    pub id: crate::proto::NodeFingerprint,
    /// What it would have been called, when that is known.
    pub name: Option<String>,
    /// Why it is not there.
    pub reason: SkipReason,
}

/// Why a node is not in a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The format has no representation for this protocol.
    Protocol(Kind),
    /// The format has no representation for how the node is carried.
    Transport(String),
    /// Nothing serves it any more, so there is no content to write.
    Orphan,
    /// The model refused to write it, with a typed kind and the model's own
    /// static explanation — never a value from the node.
    Refused {
        kind: proto::ErrorKind,
        reason: String,
    },
}

/// A document this format does not write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// The direction asked for is not one this format can produce.
    #[error("`{format}` does not write a {intent} document")]
    Intent {
        format: Format,
        intent: RenderIntent,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::NodeIndex;
    use crate::observation::Observation;
    use crate::subscription;

    /// The shapes providers actually serve, from the protocol crate's own
    /// fixture file.
    ///
    /// One list, held by both crates: a shape this renderer cannot write is a
    /// shape that crate cannot write either, and there is no second copy to
    /// drift from it.
    fn links() -> Vec<String> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../suba-proto/tests/golden/links.txt");
        let fixtures = std::fs::read_to_string(&path).expect("the protocol crate's fixtures");

        fixtures
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    }

    fn payload(links: &[String]) -> String {
        links.iter().map(|link| format!("{link}\n")).collect()
    }

    fn observation(links: &[String]) -> Observation {
        Observation {
            payload: payload(links),
            checked_at: Some(1_700_000_000),
            ..Observation::default()
        }
    }

    fn index(links: &[String]) -> NodeIndex {
        NodeIndex::from_observations([("airport", &observation(links))])
    }

    fn entries(index: &NodeIndex) -> Vec<&IndexEntry> {
        index.served().collect()
    }

    /// The other half of the same walk: the values an assembly merges, rather
    /// than a document someone is served.
    #[cfg(feature = "singbox")]
    #[test]
    fn the_same_walk_gives_the_values_an_assembly_merges() {
        let fixtures = links();
        let index = index(&fixtures);
        let nodes = entries(&index);

        let (outbounds, skipped) = crate::outbounds(&nodes);

        assert!(!outbounds.is_empty());
        assert!(
            outbounds
                .iter()
                .all(|outbound| outbound["tag"].as_str().is_some_and(|tag| !tag.is_empty())),
            "every outbound an assembly merges is named: {outbounds:?}"
        );

        // One walk, two callers: the document is these values under one key.
        let rendered = Format::Singbox
            .render(&nodes, RenderIntent::Client)
            .expect("a client document");
        let document: serde_json::Value = serde_json::from_str(&rendered.body).expect("valid JSON");

        assert_eq!(document["outbounds"], serde_json::Value::Array(outbounds));
        assert_eq!(rendered.skipped.len(), skipped.len());
    }

    /// A node the dialect cannot write is reported against the entry it came
    /// from, because an assembly has to say what it did not carry.
    #[cfg(feature = "singbox")]
    #[test]
    fn a_refused_node_is_reported_against_its_entry() {
        let fixtures = vec![
            "trojan://PASSWORD@example.com:443?sni=example.com#Trojan".to_string(),
            "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM".to_string(),
        ];
        let index = index(&fixtures);
        let nodes = entries(&index);

        let (outbounds, skipped) = crate::outbounds(&nodes);

        assert_eq!(outbounds.len(), 1);
        assert_eq!(outbounds[0]["tag"], serde_json::json!("Trojan"));
        assert_eq!(skipped.len(), 1);
        assert!(
            nodes.iter().any(|entry| entry.id == skipped[0].id),
            "the refusal names an entry that was given"
        );
        assert!(matches!(
            skipped[0].reason,
            SkipReason::Protocol(Kind::ShadowsocksR)
        ));
    }

    #[test]
    fn every_link_survives_the_round_trip_through_the_model() {
        let fixtures = links();
        let index = index(&fixtures);
        let nodes = entries(&index);

        let rendered = Format::Links
            .render(&nodes, RenderIntent::Client)
            .expect("a client document");

        assert!(
            rendered.skipped.is_empty(),
            "links can write what links were parsed from: {:?}",
            rendered.skipped
        );

        // The index orders nodes by when they were first seen, not by the order a
        // payload listed them, and two fixtures that differ only in something the
        // identity ignores are one node — so the document is compared against the
        // shapes the fixtures can become, not line by line.
        let mut written: Vec<&str> = rendered.body.lines().collect();
        let mut expected: Vec<String> = Vec::new();
        let mut identities = std::collections::BTreeSet::new();

        for link in &fixtures {
            let node = proto::parse_link(link).expect("the fixture parses");
            let line = proto::write_link(&node).expect("the fixture is writable");

            // What comes out is a subscription a client can use, not text that
            // merely looks like one: parsed back, it is the same node.
            let read_back = proto::parse_link(&line).expect("the written link parses");
            assert_eq!(read_back.id(), node.id(), "{link} became {line}");
            assert_eq!(read_back, node, "{link} became {line}");

            identities.insert(node.id());
            if !expected.contains(&line) {
                expected.push(line);
            }
        }

        assert_eq!(
            written.len(),
            nodes.len(),
            "every node in the index is one line of the document"
        );
        assert_eq!(
            nodes.len(),
            identities.len(),
            "the index holds one node per identity"
        );

        written.sort_unstable();
        expected.sort_unstable();

        for line in &written {
            assert!(
                expected.iter().any(|expected| expected == line),
                "the document wrote something no fixture could have: {line}"
            );
        }
    }

    #[test]
    fn the_document_is_one_link_per_line() {
        let index = index(&links()[..2]);
        let rendered = Format::Links
            .render(&entries(&index), RenderIntent::Client)
            .unwrap();

        assert!(
            rendered.body.ends_with('\n'),
            "a subscription ends its lines"
        );
        assert_eq!(rendered.body.lines().count(), 2);
        assert_eq!(rendered.body.matches('\n').count(), 2);
    }

    /// A node nothing serves has no content, so no document can contain it.
    #[test]
    fn a_node_nobody_serves_is_left_out_with_its_reason() {
        let fixtures = links();
        let kept = proto::parse_link(&fixtures[0]).expect("the fixture parses");
        let dropped = proto::parse_link(&fixtures[2]).expect("the fixture parses");

        // A node the provider has served and dropped: the sighting keeps it, the
        // payload does not.
        let held = Observation {
            payload: payload(&fixtures[..1]),
            checked_at: Some(1_700_000_000),
            sighting: [(kept.id(), 1_700_000_000), (dropped.id(), 1_700_000_000)]
                .into_iter()
                .collect(),
            ..Observation::default()
        };

        let index = NodeIndex::from_observations([("airport", &held)]);
        let all: Vec<&IndexEntry> = index.entries().iter().collect();
        let rendered = Format::Links
            .render(&all, RenderIntent::Client)
            .expect("a client document");

        assert_eq!(rendered.body.lines().count(), 1);
        assert_eq!(rendered.skipped.len(), 1);
        assert_eq!(rendered.skipped[0].id, dropped.id());
        assert_eq!(rendered.skipped[0].name, None);
        assert_eq!(rendered.skipped[0].reason, SkipReason::Orphan);
    }

    /// Links describe a client. A server document is a different shape, and one
    /// this format does not have.
    #[test]
    fn the_direction_that_was_asked_for_is_the_one_written() {
        let index = index(&links()[..1]);

        assert!(matches!(
            Format::Links.render(&entries(&index), RenderIntent::Server),
            Err(RenderError::Intent {
                format: Format::Links,
                intent: RenderIntent::Server
            })
        ));
        assert!(Format::Links
            .render(&entries(&index), RenderIntent::Client)
            .is_ok());
    }

    #[test]
    fn every_format_this_build_serves_answers_for_itself() {
        assert!(!Format::all().is_empty());

        for format in Format::all() {
            let descriptor = format.descriptor();
            assert_eq!(descriptor.format, *format);
            assert!(
                !descriptor.intents.is_empty(),
                "{format} writes no direction"
            );

            // The name it is spelled with and the name it serializes as are one
            // name: a client that reads the capability list and asks for what it
            // saw must be asking for this.
            let spelled = serde_json::to_value(format).unwrap();
            assert_eq!(
                spelled,
                serde_json::Value::String(format.as_str().to_string())
            );

            let parsed: Format = serde_json::from_value(spelled).unwrap();
            assert_eq!(parsed, *format);
        }
    }

    #[test]
    fn a_format_that_cannot_write_a_protocol_says_which_one() {
        let everything = Format::Links.descriptor();
        for link in links() {
            let node = proto::parse_link(&link).expect("the fixture parses");
            assert_eq!(
                everything.refuses(node.protocol.kind()),
                None,
                "links cannot write {link}"
            );
        }

        let picky = FormatDescriptor {
            format: Format::Links,
            intents: &[RenderIntent::Client],
            protocols: ProtocolSupport::Only(&[Kind::Trojan]),
        };

        assert_eq!(
            picky.refuses(Kind::Vless),
            Some(SkipReason::Protocol(Kind::Vless))
        );
        assert_eq!(picky.refuses(Kind::Trojan), None);
    }

    #[test]
    fn an_empty_collection_renders_an_empty_document() {
        let index = index(&Vec::new());
        let rendered = Format::Links
            .render(&entries(&index), RenderIntent::Client)
            .unwrap();

        assert!(rendered.body.is_empty());
        assert!(rendered.skipped.is_empty());
    }

    /// The feature decides the capability list: a format whose dialect is not
    /// compiled in is not a format at all, and a client that reads the list
    /// never asks for one this build cannot answer.
    #[test]
    fn the_formats_this_build_has_are_the_compiled_ones() {
        let names: Vec<&str> = Format::all().iter().map(|format| format.as_str()).collect();

        #[cfg(all(feature = "singbox", feature = "clash"))]
        assert_eq!(names, ["links", "singbox", "clash"]);
        #[cfg(all(feature = "singbox", not(feature = "clash")))]
        assert_eq!(names, ["links", "singbox"]);
        #[cfg(all(feature = "clash", not(feature = "singbox")))]
        assert_eq!(names, ["links", "clash"]);
        #[cfg(not(any(feature = "singbox", feature = "clash")))]
        assert_eq!(names, ["links"]);
    }

    /// A node the dialect has no outbound for is left out of the document and
    /// named, and the nodes it can write are all there.
    #[cfg(feature = "singbox")]
    #[test]
    fn a_document_holds_what_it_can_write_and_reports_what_it_cannot() {
        let fixtures = vec![
            "trojan://PASSWORD@example.com:443?sni=example.com#Trojan".to_string(),
            "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM"
                .to_string(),
        ];
        let index = index(&fixtures);
        let rendered = Format::Singbox
            .render(&entries(&index), RenderIntent::Client)
            .expect("a client document");

        let document: serde_json::Value =
            serde_json::from_str(&rendered.body).expect("a JSON document");
        let outbounds = document["outbounds"].as_array().expect("outbounds");

        assert_eq!(outbounds.len(), 1, "{} was not written", rendered.body);
        assert_eq!(outbounds[0]["tag"], serde_json::json!("Trojan"));
        assert_eq!(rendered.skipped.len(), 1);
        assert_eq!(rendered.skipped[0].name.as_deref(), Some("SSR"));
        assert_eq!(
            rendered.skipped[0].reason,
            SkipReason::Protocol(Kind::ShadowsocksR)
        );
    }

    /// A sing-box document describes a client, like the links do: a server
    /// document is a different shape, and this build does not write it yet.
    #[cfg(feature = "singbox")]
    #[test]
    fn sing_box_does_not_write_a_server_document() {
        let index = index(&links()[..1]);

        assert!(matches!(
            Format::Singbox.render(&entries(&index), RenderIntent::Server),
            Err(RenderError::Intent {
                format: Format::Singbox,
                intent: RenderIntent::Server
            })
        ));
    }

    /// A clash document holds the proxies it can write and names the nodes it
    /// cannot, from the dialect's own refusal.
    #[cfg(feature = "clash")]
    #[test]
    fn a_clash_document_holds_the_proxies_it_can_write() {
        let fixtures = vec![
            "trojan://PASSWORD@example.com:443?sni=example.com#Trojan".to_string(),
            "snell://1.2.3.4:443?psk=PSK&version=4#Snell".to_string(),
        ];
        let index = index(&fixtures);
        let rendered = Format::Clash
            .render(&entries(&index), RenderIntent::Client)
            .expect("a client document");

        assert!(
            rendered.body.starts_with("---\nproxies:\n"),
            "{}",
            rendered.body
        );
        assert!(
            rendered.body.contains("\n  - name: Trojan\n"),
            "{}",
            rendered.body
        );
        assert_eq!(rendered.skipped.len(), 1);
        assert_eq!(rendered.skipped[0].name.as_deref(), Some("Snell"));
        assert_eq!(
            rendered.skipped[0].reason,
            SkipReason::Protocol(Kind::Other)
        );
    }

    /// A clash document describes a client, like the links do: a server document
    /// is a different shape, and this build does not write it yet.
    #[cfg(feature = "clash")]
    #[test]
    fn clash_does_not_write_a_server_document() {
        let index = index(&links()[..1]);

        assert!(matches!(
            Format::Clash.render(&entries(&index), RenderIntent::Server),
            Err(RenderError::Intent {
                format: Format::Clash,
                intent: RenderIntent::Server
            })
        ));
    }

    /// The name in the document is the node's own name, not the provider's name
    /// for the provider.
    #[test]
    fn a_node_is_written_under_the_name_it_is_served_with() {
        let fixture = links()
            .into_iter()
            .find(|link| link.contains('#'))
            .expect("a named fixture");
        let node = proto::parse_link(&fixture).expect("the fixture parses");
        assert!(!node.name.as_str().is_empty(), "the fixture is named");

        let index = index(&[fixture]);
        let rendered = Format::Links
            .render(&entries(&index), RenderIntent::Client)
            .unwrap();

        let written = proto::parse_link(rendered.body.trim_end()).expect("the line parses");
        assert_eq!(written.name, node.name);
    }

    /// The subscription parser and the renderer agree on what a node is.
    #[test]
    fn what_the_subscription_parser_reads_is_what_the_renderer_writes() {
        let fixtures = links();
        let parsed = subscription::parse(payload(&fixtures).as_bytes(), "airport", 1_700_000_000);

        let index = index(&fixtures);
        let rendered = Format::Links
            .render(&entries(&index), RenderIntent::Client)
            .unwrap();

        assert_eq!(
            rendered.body.lines().count(),
            parsed.nodes.len(),
            "the same payload is the same number of nodes either way"
        );
    }
}
