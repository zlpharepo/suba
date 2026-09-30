//! Subscription formats: what a provider served, read into nodes.
//!
//! A subscription is a list of nodes in one of a few shapes — plain links, the
//! same wrapped in base64, or a clash document. The per-protocol link codec is
//! [`crate::proto`]'s; this module is the container.
//!
//! Reading never fails. A body that is entirely unreadable comes back with no
//! nodes and a reason per line it could not use, because an operator looking at
//! a provider that serves nothing needs to see *what it served*, not that
//! parsing gave up. A caller that must treat "no nodes" as an error can ask
//! [`Subscription::is_empty`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::node::NodeRecord;
use crate::proto::{self, NodeFingerprint};

/// How many lines a body may fail to contribute before the reasons are dropped.
///
/// A body of garbage would otherwise produce a diagnostic per line, and the
/// diagnostics are themselves the largest thing the server would hold. The count
/// of what was dropped is kept, so the limit is visible rather than silent.
const MAX_SKIPPED: usize = 128;

/// The shape a payload turned out to be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceFormat {
    /// Share links, one per line.
    Links,
    /// The same, wrapped in base64.
    Base64,
    /// A clash/mihomo YAML document.
    Clash,
}

/// The shape a provider says its payload is in.
///
/// Declared, not detected — [`SourceFormat`] is what a body turned out to be.
/// A declaration picks the reader instead of guessing at one, and a shape whose
/// reader is not compiled in does not exist here at all (I4), so choosing it is
/// a refusal rather than a silently different reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeclaredFormat {
    /// Share links, one per line, optionally wrapped in base64.
    #[default]
    Links,
    /// A clash/mihomo document.
    #[cfg(feature = "clash")]
    Clash,
    /// A sing-box configuration document.
    #[cfg(feature = "singbox")]
    Singbox,
}

impl DeclaredFormat {
    /// The word this is written as, which is also how a reason names it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Links => "links",
            #[cfg(feature = "clash")]
            Self::Clash => "clash",
            #[cfg(feature = "singbox")]
            Self::Singbox => "singbox",
        }
    }

    /// Why this build reads nothing of this shape, or `None` when it reads it.
    ///
    /// Both document shapes are declared but not readable yet — a reader is its
    /// writer's inverse and lands later — and until then a declaration is
    /// answered with this instead of an empty subscription. An operator who
    /// declared a format must not be told "0 nodes" as if the body were at
    /// fault.
    pub fn unreadable(self) -> Option<Unreadable> {
        match self {
            Self::Links => None,
            #[cfg(feature = "clash")]
            Self::Clash => Some(Unreadable::Clash),
            #[cfg(feature = "singbox")]
            Self::Singbox => Some(Unreadable::Singbox),
        }
    }
}

/// Why a body contributed no nodes at all.
///
/// Static, and chosen by the reader: a body carries credentials, so nothing
/// that came out of it may be quoted back. This is a classified answer, not a
/// message — a caller that must tell the cases apart matches on it rather than
/// on the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unreadable {
    /// It was declared a clash document, and this build reads none.
    #[cfg(feature = "clash")]
    Clash,
    /// It was declared a sing-box document, and this build reads none.
    #[cfg(feature = "singbox")]
    Singbox,
    /// It was declared links, and it is a clash document.
    LooksLikeClash,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            #[cfg(feature = "clash")]
            Self::Clash => "the provider declares a clash document, and this build reads none",
            #[cfg(feature = "singbox")]
            Self::Singbox => "the provider declares a sing-box document, and this build reads none",
            Self::LooksLikeClash => {
                "the body is a clash document, and this build reads none of those"
            }
        };

        formatter.write_str(text)
    }
}

/// A line the reader could not use, and why.
///
/// The reason is written when the reader is written, so it never quotes the
/// line: a subscription line carries credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedLine {
    /// 1-based, counted in the decoded text.
    pub line: usize,
    /// A static explanation, chosen by the reader.
    pub reason: String,
}

/// What a payload turned out to contain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    /// What the body was recognised as. `None` when nothing was: a shape this
    /// build cannot read is not a shape it can name.
    pub format: Option<SourceFormat>,
    /// The nodes, in the order they appeared, deduplicated by identity.
    pub nodes: Vec<NodeRecord>,
    /// How many entries collapsed into a node that was already seen.
    pub duplicates: usize,
    /// The lines that were not usable, up to [`MAX_SKIPPED`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<SkippedLine>,
    /// How many reasons were dropped past the limit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_omitted: usize,
    /// Why nothing was read at all, when the whole body is beyond this build.
    ///
    /// Distinct from an empty `nodes` with no reason: that one is a body whose
    /// lines were all unusable, which is a different thing to tell an operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<Unreadable>,
}

impl Subscription {
    /// Whether nothing usable was found.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// How many nodes the payload contributed.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// The identity of every node, for merging one subscription into another.
    pub fn identities(&self) -> Vec<NodeFingerprint> {
        self.nodes.iter().map(NodeRecord::id).collect()
    }
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// Read a subscription payload.
///
/// `declared` is how the provider says it is to be read; within links, the
/// shape is still detected, because one layer of base64 around the same lines
/// is the same subscription. The link is kept as it arrived, so what a provider
/// served can be audited and re-exported without a second parse.
pub fn parse(payload: &[u8], provider: &str, now: i64, declared: DeclaredFormat) -> Subscription {
    if let Some(reason) = declared.unreadable() {
        return Subscription::unreadable(None, reason);
    }
    // A body that is base64 of a link list is the common case for a provider;
    // anything else is read as the text it is.
    let (text, format) = match proto::base64::decode_if_text(payload) {
        Some(decoded) => (decoded, SourceFormat::Base64),
        None => (
            String::from_utf8_lossy(payload).into_owned(),
            SourceFormat::Links,
        ),
    };

    if looks_like_clash(&text) {
        // The declaration said links and the body disagrees. Read as links, this
        // becomes one skipped reason per line — noise about the wrong problem.
        return Subscription::unreadable(Some(SourceFormat::Clash), Unreadable::LooksLikeClash);
    }

    read_links(&text, format, provider, now)
}

/// Read one share link per line.
fn read_links(text: &str, format: SourceFormat, provider: &str, now: i64) -> Subscription {
    let mut reader = Reader::new(format, provider, now);

    for (index, line) in text.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        reader.line(line, index + 1);
    }

    reader.finish()
}

/// Whether a body is a clash document rather than a link list.
///
/// The shape is a top-level `proxies:` key, which is unmistakable and is not
/// something a link list contains: a link list's comments and links never start
/// a line with it. Recognising it is what lets the reader say "this is the
/// format that is not supported" instead of reporting every YAML line as a
/// malformed link.
fn looks_like_clash(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();

        line.starts_with("proxies:") && !line.starts_with("proxies://")
    })
}

impl Subscription {
    /// A body this build read nothing out of, and the reason why.
    fn unreadable(format: Option<SourceFormat>, why: Unreadable) -> Self {
        Self {
            format,
            nodes: Vec::new(),
            duplicates: 0,
            skipped: Vec::new(),
            skipped_omitted: 0,
            unreadable: Some(why),
        }
    }
}

/// Accumulates nodes and the reasons some lines did not become one.
struct Reader<'a> {
    format: SourceFormat,
    provider: &'a str,
    now: i64,
    nodes: Vec<NodeRecord>,
    /// Identity to position, so a duplicate folds into what was already read.
    seen: HashMap<NodeFingerprint, usize>,
    duplicates: usize,
    skipped: Vec<SkippedLine>,
    skipped_omitted: usize,
}

impl<'a> Reader<'a> {
    fn new(format: SourceFormat, provider: &'a str, now: i64) -> Self {
        Self {
            format,
            provider,
            now,
            nodes: Vec::new(),
            seen: HashMap::new(),
            duplicates: 0,
            skipped: Vec::new(),
            skipped_omitted: 0,
        }
    }

    /// Read one line, which is one share link.
    fn line(&mut self, line: &str, number: usize) {
        let node = match proto::parse_link(line) {
            Ok(node) => node,
            Err(error) => {
                return self.skip(number, error.kind().as_str());
            }
        };

        let mut record = NodeRecord::new(node);
        let id = record.id();

        // The position is where in the payload it appeared, which is what makes
        // "the provider's order" reproducible.
        record.seen_at(self.provider, number - 1, self.now, line);

        match self.seen.get(&id) {
            // The same node twice: the first sighting keeps its position, and
            // the count says the payload mentioned it twice.
            Some(&position) => {
                self.duplicates += 1;
                self.nodes[position].seen_at(self.provider, number - 1, self.now, line);
            }
            None => {
                self.seen.insert(id, self.nodes.len());
                self.nodes.push(record);
            }
        }
    }

    fn skip(&mut self, line: usize, reason: &str) {
        if self.skipped.len() < MAX_SKIPPED {
            self.skipped.push(SkippedLine {
                line,
                reason: reason.to_string(),
            });
        } else {
            self.skipped_omitted += 1;
        }
    }

    fn finish(self) -> Subscription {
        Subscription {
            format: Some(self.format),
            nodes: self.nodes,
            duplicates: self.duplicates,
            skipped: self.skipped,
            skipped_omitted: self.skipped_omitted,
            unreadable: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000;
    const TROJAN: &str = "trojan://hunter2@example.com:443#First";
    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443#Second";

    fn read(text: &str) -> Subscription {
        parse(text.as_bytes(), "primary", NOW, DeclaredFormat::Links)
    }

    #[test]
    fn a_link_list_reads_every_line() {
        let subscription = read(&format!("{TROJAN}\n{VLESS}\n"));

        assert_eq!(subscription.format, Some(SourceFormat::Links));
        assert_eq!(subscription.unreadable, None);
        assert_eq!(subscription.len(), 2);
        assert_eq!(subscription.nodes[0].name(), "First");
        assert_eq!(subscription.nodes[1].name(), "Second");
        assert!(subscription.skipped.is_empty());
    }

    #[test]
    fn a_base64_wrapped_list_is_detected_and_read() {
        let body = proto::base64::encode(format!("{TROJAN}\n{VLESS}\n").as_bytes());

        let subscription = read(&body);

        assert_eq!(subscription.format, Some(SourceFormat::Base64));
        assert_eq!(subscription.len(), 2, "the decoded body is the same list");
    }

    #[test]
    fn blank_lines_and_comments_are_not_reported() {
        let subscription = read(&format!("# a comment\n\n   \n{TROJAN}\n"));

        assert_eq!(subscription.len(), 1);
        assert!(
            subscription.skipped.is_empty(),
            "nothing was unusable: {:?}",
            subscription.skipped
        );
    }

    #[test]
    fn the_link_a_provider_served_is_kept_verbatim() {
        let subscription = read(&format!("  {TROJAN}  \n"));

        assert_eq!(subscription.nodes[0].provenance[0].raw, TROJAN);
    }

    #[test]
    fn the_position_is_where_it_appeared_in_the_payload() {
        let subscription = read(&format!("# comment\n{TROJAN}\n\n{VLESS}\n"));

        assert_eq!(
            subscription.nodes[0].provenance[0].position, 1,
            "line two, zero-based"
        );
        assert_eq!(subscription.nodes[1].provenance[0].position, 3);
    }

    #[test]
    fn a_line_that_is_not_a_link_is_reported_with_its_line_number() {
        let subscription = read(&format!("{TROJAN}\nnot a link\n"));

        assert_eq!(subscription.len(), 1, "the good line still reads");
        assert_eq!(subscription.skipped.len(), 1);
        assert_eq!(subscription.skipped[0].line, 2);
        assert!(
            !subscription.skipped[0].reason.contains("not a link"),
            "the reason is static, and never quotes the line: {:?}",
            subscription.skipped[0]
        );
    }

    #[test]
    fn the_same_node_twice_is_one_record_and_a_counted_duplicate() {
        let subscription = read(&format!("{TROJAN}\n{TROJAN}\n"));

        assert_eq!(subscription.len(), 1);
        assert_eq!(subscription.duplicates, 1);
        assert_eq!(
            subscription.nodes[0].provenance[0].position, 0,
            "the first sighting keeps its position"
        );
    }

    #[test]
    fn a_body_of_garbage_reports_what_it_could_not_read() {
        let subscription = read("garbage one\ngarbage two\n");

        assert!(subscription.is_empty(), "nothing usable, and no panic");
        assert_eq!(subscription.skipped.len(), 2);
    }

    #[test]
    fn reasons_are_bounded_and_the_count_says_how_many_were_dropped() {
        let body = "garbage\n".repeat(MAX_SKIPPED + 10);
        let subscription = read(&body);

        assert_eq!(subscription.skipped.len(), MAX_SKIPPED);
        assert_eq!(subscription.skipped_omitted, 10);
    }

    #[test]
    fn a_body_that_is_a_clash_document_is_recognised_and_named() {
        let subscription = read("proxies:\n  - name: node\n    type: ss\n");

        assert_eq!(
            subscription.format,
            Some(SourceFormat::Clash),
            "recognised, not misread as links"
        );
        assert_eq!(subscription.unreadable, Some(Unreadable::LooksLikeClash));
        assert!(
            subscription.is_empty(),
            "this build has no clash reader yet"
        );
    }

    /// A shape the provider declared and this build cannot read is named.
    ///
    /// The declaration decides, so the body is never even looked at: a body that
    /// happens to hold links must not be read by a provider that said it holds
    /// something else, or the same declaration would mean two things.
    #[cfg(feature = "clash")]
    #[test]
    fn a_declared_clash_body_is_refused_by_name() {
        let subscription = parse(
            format!("{TROJAN}\n").as_bytes(),
            "primary",
            NOW,
            DeclaredFormat::Clash,
        );

        assert!(subscription.is_empty(), "nothing was read");
        assert_eq!(subscription.format, None, "and nothing was recognised");
        assert_eq!(subscription.unreadable, Some(Unreadable::Clash));
        assert!(
            subscription.skipped.is_empty(),
            "one reason, not one per line of something we never read"
        );
    }

    #[cfg(feature = "singbox")]
    #[test]
    fn a_declared_singbox_body_is_refused_by_name() {
        let subscription = parse(
            br#"{"outbounds": []}"#,
            "primary",
            NOW,
            DeclaredFormat::Singbox,
        );

        assert!(subscription.is_empty());
        assert_eq!(subscription.format, None);
        assert_eq!(subscription.unreadable, Some(Unreadable::Singbox));
    }

    /// What the reason says is static, so it can be shown to an operator.
    #[test]
    fn a_reason_names_the_format_and_not_the_body() {
        assert_eq!(
            Unreadable::LooksLikeClash.to_string(),
            "the body is a clash document, and this build reads none of those"
        );
        assert!(
            !Unreadable::LooksLikeClash.to_string().contains(TROJAN),
            "a reason never quotes what it read"
        );
    }

    #[test]
    fn a_link_list_that_mentions_proxies_is_still_a_link_list() {
        let subscription = read(&format!("# proxies: are served elsewhere\n{TROJAN}\n"));

        assert_eq!(subscription.format, Some(SourceFormat::Links));
        assert_eq!(subscription.len(), 1);
    }

    #[test]
    fn an_empty_body_is_an_empty_subscription() {
        let subscription = read("");

        assert!(subscription.is_empty());
        assert_eq!(subscription.duplicates, 0);
    }
}
