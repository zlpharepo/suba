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
    pub format: SourceFormat,
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
/// Detects the shape, then reads it. The link is kept as it arrived, so what a
/// provider served can be audited and re-exported without a second parse.
pub fn parse(payload: &[u8], provider: &str, now: i64) -> Subscription {
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
        return clash_not_supported(&text);
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

/// A clash document was recognised and this build cannot read it.
fn clash_not_supported(_text: &str) -> Subscription {
    Subscription {
        format: SourceFormat::Clash,
        nodes: Vec::new(),
        duplicates: 0,
        skipped: Vec::new(),
        skipped_omitted: 0,
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
            format: self.format,
            nodes: self.nodes,
            duplicates: self.duplicates,
            skipped: self.skipped,
            skipped_omitted: self.skipped_omitted,
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
        parse(text.as_bytes(), "primary", NOW)
    }

    #[test]
    fn a_link_list_reads_every_line() {
        let subscription = read(&format!("{TROJAN}\n{VLESS}\n"));

        assert_eq!(subscription.format, SourceFormat::Links);
        assert_eq!(subscription.len(), 2);
        assert_eq!(subscription.nodes[0].name(), "First");
        assert_eq!(subscription.nodes[1].name(), "Second");
        assert!(subscription.skipped.is_empty());
    }

    #[test]
    fn a_base64_wrapped_list_is_detected_and_read() {
        let body = proto::base64::encode(format!("{TROJAN}\n{VLESS}\n").as_bytes());

        let subscription = read(&body);

        assert_eq!(subscription.format, SourceFormat::Base64);
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
    fn a_clash_document_is_recognised_and_reported_as_unsupported() {
        let subscription = read("proxies:\n  - name: node\n    type: ss\n");

        assert_eq!(
            subscription.format,
            SourceFormat::Clash,
            "recognised, not misread as links"
        );
        assert!(
            subscription.is_empty(),
            "this build has no clash reader yet"
        );
    }

    #[test]
    fn a_link_list_that_mentions_proxies_is_still_a_link_list() {
        let subscription = read(&format!("# proxies: are served elsewhere\n{TROJAN}\n"));

        assert_eq!(subscription.format, SourceFormat::Links);
        assert_eq!(subscription.len(), 1);
    }

    #[test]
    fn an_empty_body_is_an_empty_subscription() {
        let subscription = read("");

        assert!(subscription.is_empty());
        assert_eq!(subscription.duplicates, 0);
    }
}
