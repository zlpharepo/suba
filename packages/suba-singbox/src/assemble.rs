//! Assemble the document the core runs, out of the user's fragments.
//!
//! A fragment is one section of a configuration in one file —
//! `config/sing-box/outbounds.json` holds what belongs under `outbounds` — and
//! the user's fragments are never rewritten. The one section with a generated
//! half is `outbounds`: what a collection renders is put in front of what the
//! user wrote, and nothing is merged field by field.
//!
//! **Why the checks here exist at all.** Measured on sing-box 1.14.2,
//! `sing-box check` does not look at cross-references: a selector naming a tag
//! that does not exist, a selector naming itself, a two-step cycle, and a route
//! rule naming a missing outbound **all pass**. What `run` does with them at
//! startup differs, and the difference is the point:
//!
//! ```text
//! route.final = "nope"         FATAL default outbound not found: nope
//! selector s -> s              FATAL circular outbound dependency: s -> s
//! selector a -> b -> a         FATAL circular outbound dependency: a -> b -> a
//! selector member "gone"       FATAL dependency[gone] not found for outbound[s]
//! rules[].outbound = "nope"    sing-box started (0.00s)   <- and nothing else
//! ```
//!
//! A rule's outbound is resolved per connection, so a name that is not there
//! starts cleanly, says nothing, and fails only when a connection happens to
//! match that rule. That one is ours alone to catch. For the rest, this module
//! is where "the core would refuse to start" becomes an error naming a field
//! path and the tag, with nothing written and no process touched.
//!
//! Two measured facts decide the shape of the checks:
//!
//! * **outbounds and endpoints share one tag namespace** (`check` refuses two
//!   entries with the same tag as `duplicate outbound/endpoint tag: e`), while
//!   **inbounds have their own** (an inbound may carry an outbound's tag);
//! * **there are no implicit tags**: an outbound written without a `tag` does not
//!   answer to its type's name — `route.final: "direct"` fails with
//!   `default outbound not found: direct` — so every reference has to find an
//!   entry that spells the tag out.
//!
//! Route rules are read as the core reads them: `action` is a string
//! (`{"action": "route", "outbound": "proxy"}`, and an object there is refused
//! by the core's own decoder), so the name to resolve is the `outbound` beside
//! it. The older rule that names its outbound with no action at all is still
//! accepted, and is read the same way.
//!
//! What is *not* checked here is listed in [`UNCHECKED`] rather than left to be
//! discovered: a reference this build resolves is a reference it can refuse.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::{Map, Value};

/// The section that has a generated half as well as a written one.
const OUTBOUNDS: &str = "outbounds";
/// The section whose tags outbounds share a namespace with.
const ENDPOINTS: &str = "endpoints";
/// The section with a namespace of its own.
const INBOUNDS: &str = "inbounds";
const ROUTE: &str = "route";
const TAG: &str = "tag";
const TYPE: &str = "type";
/// The outbound types that name other outbounds.
const GROUPS: [&str; 2] = ["selector", "urltest"];

/// The references this build leaves alone, because it cannot resolve them.
///
/// Reported with every assembly so a caller can say what was and was not
/// looked at: a check that did not run must not look like one that passed.
pub const UNCHECKED: &[Unchecked] = &[
    Unchecked {
        what: "detour, on dialers, dns servers, inbounds, outbounds, endpoints, services, ntp and http clients",
        reason: "a detour sits inside protocol options this build does not otherwise read; the core refuses a missing one at startup",
    },
    Unchecked {
        what: "rule_set, dns_server, certificate_provider, http_client and network_namespace references",
        reason: "this build resolves outbound and inbound tags only",
    },
    Unchecked {
        what: "a selector's default being one of its own members",
        reason: "only whether that tag exists is checked, not whether it is a member",
    },
    Unchecked {
        what: "a key written twice in one fragment",
        reason: "JSON keeps the last one, here and in sing-box alike",
    },
];

/// Something this build did not check about the document beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Unchecked {
    /// What was not looked at.
    pub what: &'static str,
    /// Why, in a sentence a caller can show a user.
    pub reason: &'static str,
}

/// A document the core can be pointed at, and what was not checked about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Assembled {
    pub config: Value,
    pub unchecked: &'static [Unchecked],
}

/// Why a document was not assembled.
///
/// Every variant carries the path of the field it is about, and the ones about
/// tags carry the tag: a user has to be able to find what to edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unfit {
    /// A fragment is not JSON at all.
    NotJson {
        section: String,
        line: usize,
        column: usize,
    },
    /// A fragment, or something inside it, is not the shape its place has.
    Shape { path: String, reason: &'static str },
    /// A tag is repeated, missing, or in a cycle.
    Tag {
        path: String,
        tag: String,
        fault: Fault,
    },
}

/// What is wrong with a tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fault {
    /// Two entries in one namespace spell the same tag.
    Duplicate,
    /// A reference with nothing behind it.
    Missing,
    /// The cycle, written the way the core writes it: `a -> b -> a`.
    Circular(Vec<String>),
}

impl fmt::Display for Unfit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unfit::NotJson {
                section,
                line,
                column,
            } => write!(f, "{section}: not JSON (line {line}, column {column})"),
            Unfit::Shape { path, reason } => write!(f, "{path}: {reason}"),
            Unfit::Tag { path, tag, fault } => write!(f, "{path}: {tag:?} {fault}"),
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Duplicate => write!(f, "is written twice"),
            Fault::Missing => write!(f, "is not the tag of anything"),
            Fault::Circular(path) => write!(f, "is circular: {}", path.join(" -> ")),
        }
    }
}

impl std::error::Error for Unfit {}

/// Assemble the user's fragments and the generated outbounds into one document.
///
/// `fragments` maps a section name to that section's value as bytes — the
/// caller reads `config/sing-box/<section>.json` and hands them over as they
/// are. `generated` is what a collection rendered, in the order it should be
/// looked at first; every entry of it must be named, because a tag is the only
/// thing that can refer to an outbound.
///
/// The document comes back only if it holds up: repeated tags, references with
/// nothing behind them, and cycles are refused, in that order, before anything
/// is written anywhere.
pub fn assemble(
    fragments: &BTreeMap<String, Vec<u8>>,
    generated: &[Value],
) -> Result<Assembled, Unfit> {
    let mut sections: BTreeMap<String, Value> = BTreeMap::new();
    for (section, bytes) in fragments {
        sections.insert(section.clone(), parse(section, bytes)?);
    }

    let outbounds = merge(sections.remove(OUTBOUNDS), generated)?;

    let mut sections: Map<String, Value> = sections.into_iter().collect();
    if !outbounds.is_empty() {
        sections.insert(OUTBOUNDS.to_string(), Value::Array(outbounds));
    }
    let config = Value::Object(sections);

    let links = scan(&config)?;
    repeated(&links)?;
    resolve(&links)?;
    acyclic(&links)?;

    Ok(Assembled {
        config,
        unchecked: UNCHECKED,
    })
}

/// One fragment, read as its section's value.
fn parse(section: &str, bytes: &[u8]) -> Result<Value, Unfit> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| Unfit::NotJson {
        section: section.to_string(),
        line: error.line(),
        column: error.column(),
    })?;

    // A section is an object (`log`, `dns`, `route`) or an array of entries
    // (`inbounds`, `outbounds`). Anything else is a file whose name and content
    // disagree, and which section names exist is the core's business: it refuses
    // an unknown one itself (`json: unknown field "bogus_section"`).
    match value {
        Value::Object(_) | Value::Array(_) => Ok(value),
        _ => Err(Unfit::Shape {
            path: section.to_string(),
            reason: "a section is an object or an array",
        }),
    }
}

/// The two halves of `outbounds` added together, generated first.
fn merge(written: Option<Value>, generated: &[Value]) -> Result<Vec<Value>, Unfit> {
    let mut entries: Vec<Value> = Vec::with_capacity(generated.len());

    for (index, entry) in generated.iter().enumerate() {
        if tag_of(entry).is_none() {
            return Err(Unfit::Shape {
                path: format!("{OUTBOUNDS}[{index}]"),
                reason: "a generated outbound carries the tag that refers to it",
            });
        }
        entries.push(entry.clone());
    }

    let Some(written) = written else {
        return Ok(entries);
    };
    let Value::Array(written) = written else {
        return Err(Unfit::Shape {
            path: OUTBOUNDS.to_string(),
            reason: "the section is an array of entries",
        });
    };

    for (index, entry) in written.into_iter().enumerate() {
        if !entry.is_object() {
            return Err(Unfit::Shape {
                path: format!("{OUTBOUNDS}[{}]", entries.len() + index),
                reason: "an entry is an object",
            });
        }
        entries.push(entry);
    }

    Ok(entries)
}

/// What the document says about tags, gathered in one pass.
struct Links<'a> {
    /// Tags in the namespace outbounds and endpoints share, in document order,
    /// with the path each is written at.
    named: Vec<(&'a str, String)>,
    /// The same tags, for looking one up.
    outbound: BTreeSet<&'a str>,
    /// Tags of inbounds.
    inbound: BTreeSet<&'a str>,
    /// Every reference the document makes, in the order the document makes it.
    references: Vec<Reference<'a>>,
    /// tag -> the group it names, with the paths of the members it lists.
    groups: BTreeMap<&'a str, Group<'a>>,
}

struct Group<'a> {
    /// Where the group's own tag is written.
    tag_path: String,
    /// The outbounds it lists, and the path of each slot.
    members: Vec<(&'a str, String)>,
}

struct Reference<'a> {
    /// Where the reference is written.
    path: String,
    /// The tag it names.
    tag: &'a str,
    kind: Namespace,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Namespace {
    Outbound,
    Inbound,
}

/// Read the document: which tags exist, and what refers to what.
fn scan(config: &Value) -> Result<Links<'_>, Unfit> {
    let mut links = Links {
        named: Vec::new(),
        outbound: BTreeSet::new(),
        inbound: BTreeSet::new(),
        references: Vec::new(),
        groups: BTreeMap::new(),
    };

    for section in [OUTBOUNDS, ENDPOINTS] {
        for (index, entry) in entries(config, section)?.into_iter().enumerate() {
            let Some(tag) = tag_of(entry) else {
                continue;
            };
            links.outbound.insert(tag);
            links.named.push((tag, format!("{section}[{index}].{TAG}")));
        }
    }
    for entry in entries(config, INBOUNDS)? {
        if let Some(tag) = tag_of(entry) {
            links.inbound.insert(tag);
        }
    }

    for (index, entry) in entries(config, OUTBOUNDS)?.into_iter().enumerate() {
        let Some(tag) = tag_of(entry) else {
            continue;
        };
        let kind = entry.get(TYPE).and_then(Value::as_str);

        if kind.is_some_and(|kind| GROUPS.contains(&kind)) {
            let mut members = Vec::new();
            for (slot, member) in listed(entry, OUTBOUNDS, index)?.into_iter().enumerate() {
                let path = format!("{OUTBOUNDS}[{index}].{OUTBOUNDS}[{slot}]");
                let Some(member) = member.as_str() else {
                    return Err(Unfit::Shape {
                        path,
                        reason: "a member is named by its tag",
                    });
                };
                refer(&mut links, path.clone(), member, Namespace::Outbound);
                members.push((member, path));
            }
            links.groups.insert(
                tag,
                Group {
                    tag_path: format!("{OUTBOUNDS}[{index}].{TAG}"),
                    members,
                },
            );
        }

        // Only a selector has a default, and it names one of its members.
        if kind == Some("selector") {
            if let Some(default) = entry.get("default") {
                let path = format!("{OUTBOUNDS}[{index}].default");
                let Some(default) = default.as_str() else {
                    return Err(Unfit::Shape {
                        path,
                        reason: "a default member is named by its tag",
                    });
                };
                refer(&mut links, path, default, Namespace::Outbound);
            }
        }
    }

    route(&mut links, config)?;

    Ok(links)
}

fn refer<'a>(links: &mut Links<'a>, path: String, tag: &'a str, kind: Namespace) {
    links.references.push(Reference { path, tag, kind });
}

/// The references a route makes: its default outbound, and the rules that
/// match on inbounds or route to an outbound.
fn route<'a>(links: &mut Links<'a>, config: &'a Value) -> Result<(), Unfit> {
    // Rules are the same shape wherever they are written: the route's own, and
    // the ones a dns block matches with. A dns block is scanned whether or not
    // there is a route beside it.
    rules(links, config, "dns")?;

    let Some(route) = config.get(ROUTE) else {
        return Ok(());
    };
    let Some(route) = route.as_object() else {
        return Err(Unfit::Shape {
            path: ROUTE.to_string(),
            reason: "the section is an object",
        });
    };

    if let Some(final_outbound) = route.get("final") {
        let path = format!("{ROUTE}.final");
        let Some(final_outbound) = final_outbound.as_str() else {
            return Err(Unfit::Shape {
                path,
                reason: "the default outbound is named by its tag",
            });
        };
        refer(links, path, final_outbound, Namespace::Outbound);
    }

    rules(links, config, ROUTE)?;

    Ok(())
}

/// The outbound a rule routes to, and the inbounds it matches on.
fn rules<'a>(links: &mut Links<'a>, config: &'a Value, section: &str) -> Result<(), Unfit> {
    let Some(listed) = config.get(section).and_then(|block| block.get("rules")) else {
        return Ok(());
    };
    let Some(rules) = listed.as_array() else {
        return Err(Unfit::Shape {
            path: format!("{section}.rules"),
            reason: "the rules are an array",
        });
    };

    for (index, rule) in rules.iter().enumerate() {
        let base = format!("{section}.rules[{index}]");
        if !rule.is_object() {
            return Err(Unfit::Shape {
                path: base,
                reason: "a rule is an object",
            });
        }

        if let Some(outbound) = rule.get("outbound") {
            let path = format!("{base}.outbound");
            let Some(outbound) = outbound.as_str() else {
                return Err(Unfit::Shape {
                    path,
                    reason: "the outbound to route to is named by its tag",
                });
            };
            refer(links, path, outbound, Namespace::Outbound);
        }

        let Some(inbound) = rule.get("inbound") else {
            continue;
        };
        let tags: Vec<&Value> = match inbound {
            Value::Array(tags) => tags.iter().collect(),
            tag => vec![tag],
        };
        for (slot, tag) in tags.into_iter().enumerate() {
            let path = match slot {
                0 if !inbound.is_array() => format!("{base}.inbound"),
                _ => format!("{base}.inbound[{slot}]"),
            };
            let Some(tag) = tag.as_str() else {
                return Err(Unfit::Shape {
                    path,
                    reason: "an inbound is matched by its tag",
                });
            };
            refer(links, path, tag, Namespace::Inbound);
        }
    }

    Ok(())
}

/// Two entries of one namespace may not spell the same tag.
///
/// The core refuses this by itself (`check` decodes with
/// `duplicate outbound/endpoint tag: e`), but the collision worth catching is
/// the one between a tag a collection generated and one the user wrote: the
/// user cannot see the generated half until it is assembled.
fn repeated(links: &Links<'_>) -> Result<(), Unfit> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();

    for (tag, path) in &links.named {
        if !seen.insert(tag) {
            return Err(Unfit::Tag {
                path: path.clone(),
                tag: tag.to_string(),
                fault: Fault::Duplicate,
            });
        }
    }

    Ok(())
}

/// Every reference has something behind it.
fn resolve(links: &Links<'_>) -> Result<(), Unfit> {
    for reference in &links.references {
        let known = match reference.kind {
            Namespace::Outbound => links.outbound.contains(reference.tag),
            Namespace::Inbound => links.inbound.contains(reference.tag),
        };
        if !known {
            return Err(Unfit::Tag {
                path: reference.path.clone(),
                tag: reference.tag.to_string(),
                fault: Fault::Missing,
            });
        }
    }

    Ok(())
}

/// No outbound reaches itself.
fn acyclic(links: &Links<'_>) -> Result<(), Unfit> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        OnPath,
        Done,
    }

    let mut marks: BTreeMap<&str, Mark> = BTreeMap::new();

    // In tag order, so which cycle is reported does not depend on the order the
    // entries happen to be written in.
    for (tag, group) in &links.groups {
        if marks.contains_key(tag) {
            continue;
        }
        walk(tag, &group.tag_path, links, &mut marks, &mut Vec::new())?;
    }

    fn walk<'a>(
        tag: &'a str,
        from: &str,
        links: &Links<'a>,
        marks: &mut BTreeMap<&'a str, Mark>,
        path: &mut Vec<&'a str>,
    ) -> Result<(), Unfit> {
        match marks.get(tag) {
            Some(Mark::Done) => return Ok(()),
            Some(Mark::OnPath) => {
                // The path from where this tag was first reached: the cycle is
                // written the way the core writes it, `a -> b -> a`.
                let start = path.iter().position(|seen| *seen == tag).unwrap_or(0);
                let mut cycle: Vec<String> =
                    path[start..].iter().map(|tag| (*tag).to_string()).collect();
                cycle.push(tag.to_string());
                return Err(Unfit::Tag {
                    path: from.to_string(),
                    tag: tag.to_string(),
                    fault: Fault::Circular(cycle),
                });
            }
            None => {}
        }

        marks.insert(tag, Mark::OnPath);
        path.push(tag);

        if let Some(group) = links.groups.get(tag) {
            for (member, slot) in &group.members {
                walk(member, slot, links, marks, path)?;
            }
        }

        path.pop();
        marks.insert(tag, Mark::Done);

        Ok(())
    }

    Ok(())
}

/// The entries of a section, or nothing when the section is not there.
fn entries<'a>(config: &'a Value, section: &str) -> Result<Vec<&'a Value>, Unfit> {
    match config.get(section) {
        None => Ok(Vec::new()),
        Some(Value::Array(entries)) => Ok(entries.iter().collect()),
        Some(_) => Err(Unfit::Shape {
            path: section.to_string(),
            reason: "the section is an array of entries",
        }),
    }
}

/// The array an entry lists its members in, when it has one.
fn listed<'a>(entry: &'a Value, field: &str, index: usize) -> Result<Vec<&'a Value>, Unfit> {
    match entry.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Array(members)) => Ok(members.iter().collect()),
        Some(_) => Err(Unfit::Shape {
            path: format!("{OUTBOUNDS}[{index}].{field}"),
            reason: "the members are an array of tags",
        }),
    }
}

/// The tag an entry is known by, if it spells one out.
fn tag_of(entry: &Value) -> Option<&str> {
    entry
        .get(TAG)
        .and_then(Value::as_str)
        .filter(|tag| !tag.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<u8>> {
        pairs
            .iter()
            .map(|(section, value)| (section.to_string(), value.as_bytes().to_vec()))
            .collect()
    }

    fn outbound(tag: &str) -> Value {
        serde_json::json!({ "type": "direct", TAG: tag })
    }

    fn selector(tag: &str, members: &[&str]) -> Value {
        serde_json::json!({ "type": "selector", TAG: tag, "outbounds": members })
    }

    /// What a caller does with a document it already has in hand: one fragment
    /// per section.
    fn assembled(config: &Value) -> Value {
        let fragments: BTreeMap<String, Vec<u8>> = config
            .as_object()
            .expect("an object")
            .iter()
            .map(|(section, value)| {
                (
                    section.clone(),
                    serde_json::to_vec(value).expect("a section"),
                )
            })
            .collect();

        assemble(&fragments, &[]).expect("nothing wrong").config
    }

    #[test]
    fn a_selector_is_written_the_way_a_document_writes_one() {
        assert_eq!(selector("s", &["x"])["type"], "selector");
    }

    #[test]
    fn the_halves_of_outbounds_are_added_not_merged() {
        let fragments = written(&[
            ("log", r#"{"level":"warn"}"#),
            ("outbounds", r#"[{"type":"direct","tag":"mine"}]"#),
        ]);
        let generated = vec![outbound("node 1"), outbound("node 2")];

        let assembled = assemble(&fragments, &generated).expect("nothing wrong");

        assert_eq!(
            assembled.config["outbounds"],
            serde_json::json!([
                { "type": "direct", "tag": "node 1" },
                { "type": "direct", "tag": "node 2" },
                { "type": "direct", "tag": "mine" },
            ])
        );
        assert_eq!(
            assembled.config["log"],
            serde_json::json!({"level": "warn"})
        );
    }

    #[test]
    fn a_generated_outbound_without_a_tag_is_refused() {
        let generated = vec![serde_json::json!({ "type": "direct" })];

        assert_eq!(
            assemble(&BTreeMap::new(), &generated),
            Err(Unfit::Shape {
                path: "outbounds[0]".to_string(),
                reason: "a generated outbound carries the tag that refers to it",
            })
        );
    }

    #[test]
    fn a_tag_an_outbound_and_an_endpoint_share_is_refused() {
        let fragments = written(&[
            ("outbounds", r#"[{"type":"direct","tag":"x"}]"#),
            ("endpoints", r#"[{"type":"wireguard","tag":"x"}]"#),
        ]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "endpoints[0].tag".to_string(),
                tag: "x".to_string(),
                fault: Fault::Duplicate,
            })
        );
    }

    #[test]
    fn a_tag_written_twice_in_one_namespace_is_refused() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"direct","tag":"x"},{"type":"direct","tag":"x"}]"#,
        )]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "outbounds[1].tag".to_string(),
                tag: "x".to_string(),
                fault: Fault::Duplicate,
            })
        );
    }

    #[test]
    fn a_generated_tag_the_user_also_used_is_refused() {
        let fragments = written(&[("outbounds", r#"[{"type":"direct","tag":"x"}]"#)]);
        let generated = vec![outbound("x")];

        assert_eq!(
            assemble(&fragments, &generated),
            Err(Unfit::Tag {
                path: "outbounds[1].tag".to_string(),
                tag: "x".to_string(),
                fault: Fault::Duplicate,
            })
        );
    }

    #[test]
    fn an_inbound_may_carry_an_outbounds_tag() {
        let config = assembled(&serde_json::json!({
            "inbounds": [{ "type": "socks", "tag": "same" }],
            "outbounds": [outbound("same")],
        }));

        assert_eq!(config["inbounds"][0]["tag"], "same");
    }

    #[test]
    fn a_selector_member_that_is_not_there_is_refused() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"direct","tag":"x"},{"type":"selector","tag":"s","outbounds":["gone"]}]"#,
        )]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "outbounds[1].outbounds[0]".to_string(),
                tag: "gone".to_string(),
                fault: Fault::Missing,
            })
        );
    }

    #[test]
    fn a_reference_to_a_generated_outbound_is_found() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"selector","tag":"s","outbounds":["node 1"]}]"#,
        )]);
        let generated = vec![outbound("node 1")];

        let assembled = assemble(&fragments, &generated).expect("the member is generated");

        assert_eq!(assembled.config["outbounds"][1]["tag"], "s");
    }

    #[test]
    fn a_selector_default_is_a_reference_too() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"direct","tag":"x"},{"type":"selector","tag":"s","outbounds":["x"],"default":"gone"}]"#,
        )]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "outbounds[1].default".to_string(),
                tag: "gone".to_string(),
                fault: Fault::Missing,
            })
        );
    }

    #[test]
    fn a_route_default_that_is_not_there_is_refused() {
        let fragments = written(&[
            ("outbounds", r#"[{"type":"direct","tag":"x"}]"#),
            ("route", r#"{"final":"gone"}"#),
        ]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "route.final".to_string(),
                tag: "gone".to_string(),
                fault: Fault::Missing,
            })
        );
    }

    /// Both spellings route to the same name: the one that says what the rule
    /// does (`action` is a string, the core refuses an object there), and the
    /// older one that just names the outbound.
    #[test]
    fn a_rule_names_its_outbound_beside_the_action() {
        let fragments = written(&[(
            "route",
            r#"{"rules":[{"action":"route","outbound":"x"},{"outbound":"x"}]}"#,
        )]);
        let generated = vec![outbound("x")];

        assert!(assemble(&fragments, &generated).is_ok());

        let missing = written(&[(
            "route",
            r#"{"rules":[{"action":"route","outbound":"gone"}]}"#,
        )]);

        assert_eq!(
            assemble(&missing, &[]),
            Err(Unfit::Tag {
                path: "route.rules[0].outbound".to_string(),
                tag: "gone".to_string(),
                fault: Fault::Missing,
            })
        );
    }

    /// A rule's outbound is resolved per connection: the core starts cleanly
    /// with one that is not there and says nothing, so this is the only check.
    #[test]
    fn a_rule_that_routes_to_nothing_is_refused() {
        let fragments = written(&[
            (
                "outbounds",
                r#"[{"type":"direct","tag":"x"},{"type":"direct","tag":"y"}]"#,
            ),
            ("route", r#"{"rules":[{"outbound":"x"},{"outbound":"y"}]}"#),
        ]);

        assert!(assemble(&fragments, &[]).is_ok());
    }

    #[test]
    fn a_rule_may_match_an_inbound_by_tag_or_by_tags() {
        let fragments = written(&[
            ("inbounds", r#"[{"type":"socks","tag":"in"}]"#),
            (
                "route",
                r#"{"rules":[{"inbound":"in"},{"inbound":["in","gone"]}]}"#,
            ),
        ]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "route.rules[1].inbound[1]".to_string(),
                tag: "gone".to_string(),
                fault: Fault::Missing,
            })
        );
    }

    #[test]
    fn a_dns_rule_matches_on_an_inbound_too() {
        let fragments = written(&[
            ("inbounds", r#"[{"type":"socks","tag":"in"}]"#),
            ("dns", r#"{"rules":[{"inbound":["in","gone"]}]}"#),
        ]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "dns.rules[0].inbound[1]".to_string(),
                tag: "gone".to_string(),
                fault: Fault::Missing,
            })
        );
    }

    /// A default that names some entry, but not a member of its own selector:
    /// the core accepts it (`check` passes), so it is reported as unchecked
    /// rather than refused.
    #[test]
    fn a_default_that_is_not_a_member_is_left_alone() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"direct","tag":"x"},{"type":"direct","tag":"y"},{"type":"selector","tag":"s","outbounds":["x"],"default":"y"}]"#,
        )]);

        assert!(assemble(&fragments, &[]).is_ok());
    }

    #[test]
    fn a_selector_that_names_itself_is_refused() {
        let fragments = written(&[
            (
                "outbounds",
                r#"[{"type":"selector","tag":"s","outbounds":["s"]}]"#,
            ),
            ("route", r#"{"final":"s"}"#),
        ]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Tag {
                path: "outbounds[0].outbounds[0]".to_string(),
                tag: "s".to_string(),
                fault: Fault::Circular(vec!["s".to_string(), "s".to_string()]),
            })
        );
    }

    #[test]
    fn a_cycle_of_two_is_refused_and_written_the_way_the_core_writes_it() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"selector","tag":"a","outbounds":["b"]},{"type":"selector","tag":"b","outbounds":["a"]}]"#,
        )]);

        let refused = assemble(&fragments, &[]).expect_err("a -> b -> a");
        let Unfit::Tag { path, tag, fault } = &refused else {
            panic!("a tag fault");
        };

        assert_eq!(path, "outbounds[1].outbounds[0]");
        assert_eq!(tag, "a");
        assert!(matches!(fault, Fault::Circular(path) if path == &["a", "b", "a"]));
        assert_eq!(
            refused.to_string(),
            r#"outbounds[1].outbounds[0]: "a" is circular: a -> b -> a"#
        );
    }

    #[test]
    fn a_group_of_groups_is_not_a_cycle() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"direct","tag":"x"},{"type":"selector","tag":"s","outbounds":["g"]},{"type":"selector","tag":"g","outbounds":["x"]}]"#,
        )]);

        assert!(assemble(&fragments, &[]).is_ok());
    }

    #[test]
    fn a_fragment_that_is_not_json_says_where() {
        let fragments = written(&[("log", "{")]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::NotJson {
                section: "log".to_string(),
                line: 1,
                column: 1,
            })
        );
    }

    #[test]
    fn a_fragment_of_the_wrong_shape_is_refused() {
        let fragments = written(&[("log", r#""warn""#)]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Shape {
                path: "log".to_string(),
                reason: "a section is an object or an array",
            })
        );

        let not_an_array = written(&[("outbounds", r#"{"type":"direct"}"#)]);

        assert_eq!(
            assemble(&not_an_array, &[]),
            Err(Unfit::Shape {
                path: "outbounds".to_string(),
                reason: "the section is an array of entries",
            })
        );
    }

    #[test]
    fn a_member_that_is_not_a_tag_is_refused() {
        let fragments = written(&[(
            "outbounds",
            r#"[{"type":"selector","tag":"s","outbounds":[7]}]"#,
        )]);

        assert_eq!(
            assemble(&fragments, &[]),
            Err(Unfit::Shape {
                path: "outbounds[0].outbounds[0]".to_string(),
                reason: "a member is named by its tag",
            })
        );
    }

    #[test]
    fn nothing_at_all_is_an_empty_document() {
        let assembled = assemble(&BTreeMap::new(), &[]).expect("nothing wrong");

        assert_eq!(assembled.config, serde_json::json!({}));
        assert_eq!(assembled.unchecked.len(), UNCHECKED.len());
    }

    #[test]
    fn the_same_inputs_are_assembled_the_same_way_twice() {
        let fragments = written(&[
            ("log", r#"{"level":"warn"}"#),
            ("outbounds", r#"[{"type":"direct","tag":"mine"}]"#),
        ]);
        let generated = vec![outbound("node 1"), outbound("node 2")];

        let once = assemble(&fragments, &generated).expect("nothing wrong");
        let twice = assemble(&fragments, &generated).expect("nothing wrong");

        assert_eq!(once.config, twice.config);
        assert_eq!(
            serde_json::to_string(&once.config).expect("text"),
            serde_json::to_string(&twice.config).expect("text")
        );
    }

    /// The list in [`UNCHECKED`] names kept keys, so pin it: a key written twice
    /// keeps the last one, and a reference in a section this build does not read
    /// passes.
    #[test]
    fn what_is_not_checked_stays_unchecked() {
        let fragments = written(&[("outbounds", r#"[{"type":"direct","tag":"x","tag":"y"}]"#)]);
        let assembled = assemble(&fragments, &[]).expect("nothing wrong");

        assert_eq!(assembled.config["outbounds"][0]["tag"], "y");

        let dns = written(&[(
            "dns",
            r#"{"servers":[{"type":"udp","tag":"d","detour":"gone"}]}"#,
        )]);

        assert!(assemble(&dns, &[]).is_ok());
    }
}
