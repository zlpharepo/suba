//! The schema an installed core generated, and what it says about a document.
//!
//! The schema is sing-box's own output (`sing-box schema -o`), one per installed
//! version, so a document is always read against the grammar of the binary that
//! will run it.
//!
//! **What this module refuses, and when.** The validator implements the
//! keywords sing-box's schema actually uses — measured on 1.14.2: `$ref`,
//! `type`, `properties`, `required`, `additionalProperties`,
//! `unevaluatedProperties`, `items`, `enum`, `const`, `oneOf`, `anyOf`,
//! `allOf`, `pattern`, `propertyNames`, `minimum`, `maximum`, `examples`,
//! `$schema`, `$id`, `$defs`, and `x-tag-reference` (171 times, the only
//! extension). Anything else — a keyword, or a keyword used in a shape it does
//! not have here — makes the **whole schema** unreadable, at read time rather
//! than at use time. That is deliberate: a schema with a keyword we do not
//! implement is a schema we would silently check *less* of, and a version bump
//! that introduces one has to fail loudly enough for someone to come here and
//! implement it. The same strictness applies to `x-*`: they are read as
//! comments, but they still have to be `x-*`.
//!
//! **What it is not.** This is a courtesy validator: it says which field is
//! wrong before the core is asked to load the document. The core's own decoder
//! remains the authority (it is stricter about unknown fields, and it checks
//! things no schema can express), and the cross-reference checks live in
//! `assemble`. Where a check here cannot run, the verdict says so rather than
//! passing quietly.

use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::Value;

/// How deep a document may nest before this build stops walking it.
///
/// The deepest thing sing-box's schema describes is a route rule inside a rule
/// inside a route, a handful of levels. A document deeper than this is not
/// refused — it is *reported* as unchecked, because refusing a document for
/// being deep would be a claim this build cannot back up.
const MAX_DEPTH: usize = 64;

/// How a keyword this build implements is laid out, when it is not a leaf.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// The value is a schema.
    Schema,
    /// The value is a map of names to schemas.
    Map,
    /// The value is a non-empty list of schemas.
    Branches,
    /// The value is a schema or a boolean.
    SchemaOrBool,
    /// The value is a boolean. Only `unevaluatedProperties` is written this way
    /// in sing-box's schema, always as `false`, and a schema there is refused
    /// rather than half-implemented.
    Bool,
}

/// How this build reads a keyword, or nothing when it does not read it at all.
fn layout(keyword: &str) -> Option<Layout> {
    Some(match keyword {
        "items" | "propertyNames" => Layout::Schema,
        "additionalProperties" => Layout::SchemaOrBool,
        "unevaluatedProperties" => Layout::Bool,
        "properties" | "$defs" => Layout::Map,
        "oneOf" | "anyOf" | "allOf" => Layout::Branches,
        _ => return None,
    })
}

/// Whether a keyword this build knows carries facts rather than structure.
fn is_leaf(keyword: &str) -> bool {
    matches!(
        keyword,
        "type"
            | "enum"
            | "const"
            | "required"
            | "minimum"
            | "maximum"
            | "pattern"
            | "examples"
            | "$schema"
            | "$id"
            | "$ref"
    )
}

/// Why a schema could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unreadable {
    /// The bytes are not JSON.
    NotJson { line: usize, column: usize },
    /// A keyword this build does not implement, and where it is.
    Keyword { at: String, keyword: String },
    /// A keyword this build implements, used in a shape it does not have.
    Shape {
        at: String,
        keyword: String,
        reason: &'static str,
    },
    /// The document is not the schema of this format at all.
    Malformed { at: String, reason: &'static str },
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unreadable::NotJson { line, column } => {
                write!(f, "the schema is not JSON (line {line}, column {column})")
            }
            Unreadable::Keyword { at, keyword } => {
                write!(f, "{at}: the keyword {keyword:?} is not implemented")
            }
            Unreadable::Shape {
                at,
                keyword,
                reason,
            } => write!(f, "{at}: {keyword}: {reason}"),
            Unreadable::Malformed { at, reason } => write!(f, "{at}: {reason}"),
        }
    }
}

impl std::error::Error for Unreadable {}

/// Something that was not checked.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Skipped {
    /// What was not looked at.
    pub what: String,
    /// What a caller could do about it.
    pub fix: &'static str,
}

/// The verdict on a document: three states, never two.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Every check this build implements ran, and passed.
    Ok,
    /// The document passed, but some checks could not run.
    Skipped(Vec<Skipped>),
    /// A field is wrong. Nothing else is reported — fix this one and look again.
    Failed(Fault),
}

impl Verdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, Verdict::Ok | Verdict::Skipped(_))
    }

    pub fn failed(&self) -> Option<&Fault> {
        match self {
            Verdict::Failed(fault) => Some(fault),
            _ => None,
        }
    }

    pub fn skipped(&self) -> &[Skipped] {
        match self {
            Verdict::Skipped(skipped) => skipped,
            _ => &[],
        }
    }
}

/// A field that is wrong: where it is, and what is wrong with it.
///
/// The reason is assembled from static text and from the schema's own names —
/// never from the document, whose values may be credentials.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Fault {
    pub path: String,
    pub reason: String,
}

/// A schema this build can check documents against.
#[derive(Debug)]
pub struct Schema {
    /// The document as it was given, which is also what a caller may serve.
    value: Value,
    /// The `type` values `$defs/Inbound` accepts, in the order it lists them.
    inbound: Vec<String>,
    /// The `type` values `$defs/Outbound` accepts.
    outbound: Vec<String>,
    /// How often each `x-tag-reference` kind appears, for callers that want to
    /// say what a schema can refer to.
    references: BTreeMap<String, usize>,
    /// The `pattern` values, compiled once. `None` is a pattern the regex crate
    /// cannot compile: the check is reported as skipped rather than passed.
    patterns: BTreeMap<String, Option<Regex>>,
}

impl Schema {
    /// Read a schema, refusing anything this build would only check part of.
    pub fn read(bytes: &[u8]) -> Result<Schema, Unreadable> {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| Unreadable::NotJson {
            line: error.line(),
            column: error.column(),
        })?;

        let census = census(&value)?;
        let inbound = protocols(&value, "Inbound")?;
        let outbound = protocols(&value, "Outbound")?;

        Ok(Schema {
            value,
            inbound,
            outbound,
            references: census.references,
            patterns: census.patterns,
        })
    }

    /// The `type` values an inbound may carry.
    pub fn inbound_types(&self) -> &[String] {
        &self.inbound
    }

    /// The `type` values an outbound may carry.
    pub fn outbound_types(&self) -> &[String] {
        &self.outbound
    }

    /// How often each `x-tag-reference` kind appears in the schema.
    pub fn references(&self) -> &BTreeMap<String, usize> {
        &self.references
    }

    /// Check a document against the schema.
    pub fn validate(&self, document: &Value) -> Verdict {
        let mut skipped = Vec::new();

        match self.check(&self.value, document, "", 0, &mut skipped) {
            Err(fault) => Verdict::Failed(fault),
            Ok(_) if skipped.is_empty() => Verdict::Ok,
            Ok(_) => Verdict::Skipped(skipped),
        }
    }

    /// Check one value against one schema node, collecting the property names
    /// that node evaluated (which is what `unevaluatedProperties` asks about).
    fn check(
        &self,
        schema: &Value,
        value: &Value,
        path: &str,
        depth: usize,
        skipped: &mut Vec<Skipped>,
    ) -> Result<Evaluated, Fault> {
        if depth > MAX_DEPTH {
            skipped.push(Skipped {
                what: format!("{path}: this deep into the document"),
                fix: "nesting this deep is beyond what this build walks; the core still checks it",
            });
            return Ok(Evaluated::default());
        }

        let Some(fields) = schema.as_object() else {
            skipped.push(Skipped {
                what: format!("{path}: a schema node that is not an object"),
                fix: "this build reads schemas whose every position holds an object",
            });
            return Ok(Evaluated::default());
        };

        let mut evaluated = Evaluated::default();

        // `$ref` is an assertion like any other, and may have siblings.
        if let Some(Value::String(reference)) = fields.get("$ref") {
            let Some(target) = resolve(&self.value, reference) else {
                skipped.push(Skipped {
                    what: format!("{path}: the reference {reference}"),
                    fix: "this build resolves #/$defs/<name> only",
                });
                return Ok(evaluated);
            };
            evaluated = self.check(target, value, path, depth + 1, skipped)?;
        }

        if let Some(types) = fields.get("type") {
            if !type_matches(types, value) {
                return Err(Fault {
                    path: path.to_string(),
                    reason: format!("is {}, not {}", type_name(value), type_names(types)),
                });
            }
        }

        if let Some(constant) = fields.get("const") {
            if value != constant {
                return Err(Fault {
                    path: path.to_string(),
                    reason: "is not the one value this place takes".to_string(),
                });
            }
        }

        if let Some(values) = fields.get("enum").and_then(Value::as_array) {
            if !values.contains(value) {
                let names: Vec<&str> = values.iter().filter_map(Value::as_str).collect();
                return Err(Fault {
                    path: path.to_string(),
                    reason: if names.is_empty() {
                        "is not one of the values this place takes".to_string()
                    } else {
                        format!("is not one of: {}", names.join(", "))
                    },
                });
            }
        }

        if let Some(number) = value.as_f64() {
            let broke = match (fields.get("minimum"), fields.get("maximum")) {
                (Some(minimum), _) if minimum.as_f64().is_some_and(|bound| number < bound) => true,
                (_, Some(maximum)) => maximum.as_f64().is_some_and(|bound| number > bound),
                _ => false,
            };
            if broke {
                return Err(Fault {
                    path: path.to_string(),
                    reason: "is outside the range this place takes".to_string(),
                });
            }
        }

        if let Some(pattern) = fields.get("pattern").and_then(Value::as_str) {
            let text = value.as_str().unwrap_or_default();
            match self.patterns.get(pattern) {
                Some(Some(pattern)) if pattern.is_match(text) => {}
                Some(Some(_)) => {
                    return Err(Fault {
                        path: path.to_string(),
                        reason: "is not written the way this field is".to_string(),
                    })
                }
                _ => skipped.push(Skipped {
                    what: format!("{path}: the pattern this place is written by"),
                    fix: "this build cannot compile that pattern; the core still checks it",
                }),
            }
        }

        // Unions are asked before anything that needs an object or an array:
        // `{"anyOf": [{"type": "string"}, {"type": "array", …}]}` is how this
        // schema says "a string or an array", and it has to hold for values that
        // are neither.
        for keyword in ["allOf", "anyOf", "oneOf"] {
            let Some(branches) = fields.get(keyword).and_then(Value::as_array) else {
                continue;
            };
            let mut passed = Vec::new();
            let mut faults = Vec::new();
            for (index, branch) in branches.iter().enumerate() {
                let mut branch_skipped = Vec::new();
                match self.check(branch, value, path, depth + 1, &mut branch_skipped) {
                    Ok(branch_evaluated) => passed.push((branch, branch_evaluated, branch_skipped)),
                    Err(fault) => faults.push((index, fault)),
                }
            }

            match keyword {
                "allOf" => {
                    if let Some((_, fault)) = faults.into_iter().next() {
                        return Err(fault);
                    }
                    for (_, branch_evaluated, branch_skipped) in passed {
                        skipped.extend(branch_skipped);
                        evaluated.merge(branch_evaluated);
                    }
                }
                "anyOf" => {
                    if passed.is_empty() {
                        return Err(no_branch(branches, faults, path, value));
                    }
                    for (_, branch_evaluated, branch_skipped) in passed {
                        skipped.extend(branch_skipped);
                        evaluated.merge(branch_evaluated);
                    }
                }
                _ => {
                    if passed.len() != 1 {
                        return Err(if passed.len() > 1 {
                            Fault {
                                path: path.to_string(),
                                reason: "matches more than one thing this place can be".to_string(),
                            }
                        } else {
                            no_branch(branches, faults, path, value)
                        });
                    }
                    let (_, branch_evaluated, branch_skipped) = passed.pop().expect("one");
                    skipped.extend(branch_skipped);
                    evaluated.merge(branch_evaluated);
                }
            }
        }

        if let Some(items) = fields.get("items") {
            if let Some(list) = value.as_array() {
                for (index, item) in list.iter().enumerate() {
                    let element = format!("{path}[{index}]");
                    evaluated.merge(self.check(items, item, &element, depth + 1, skipped)?);
                }
            }
        }

        let Some(object) = value.as_object() else {
            return Ok(evaluated);
        };

        if let Some(properties) = fields.get("properties").and_then(Value::as_object) {
            for (name, sub) in properties {
                evaluated.insert(name);
                let Some((written, child)) =
                    object.iter().find(|(written, _)| same_field(name, written))
                else {
                    continue;
                };
                let child_evaluated =
                    self.check(sub, child, &field(path, written), depth + 1, skipped)?;
                evaluated.merge(child_evaluated);
            }
        }

        if let Some(extra) = fields.get("additionalProperties") {
            for (name, child) in object {
                let declared = fields
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|properties| {
                        properties.keys().any(|known| same_field(known, name))
                    });
                if declared {
                    continue;
                }
                match extra {
                    Value::Bool(false) => {
                        return Err(Fault {
                            path: field(path, name),
                            reason: "is not one of the fields this place takes".to_string(),
                        })
                    }
                    Value::Bool(true) => {}
                    sub => {
                        evaluated.insert(name);
                        self.check(sub, child, &field(path, name), depth + 1, skipped)?;
                    }
                }
            }
        }

        if let Some(names) = fields.get("propertyNames") {
            for name in object.keys() {
                let child = field(path, name);
                self.check(
                    names,
                    &Value::String(name.clone()),
                    &child,
                    depth + 1,
                    skipped,
                )?;
            }
        }

        // Asked after the fields that are written: a value that is the wrong
        // kind is the fault to fix first, and it is the one the core reports.
        if let Some(names) = fields.get("required").and_then(Value::as_array) {
            for name in names.iter().filter_map(Value::as_str) {
                let written = object.keys().any(|key| same_field(name, key));
                if !written {
                    return Err(Fault {
                        path: field(path, name),
                        reason: "is required here".to_string(),
                    });
                }
            }
        }

        // Asked last: everything above had its chance to evaluate a name.
        if let Some(Value::Bool(false)) = fields.get("unevaluatedProperties") {
            for name in object.keys() {
                if !evaluated.names.iter().any(|known| same_field(known, name)) {
                    return Err(Fault {
                        path: field(path, name),
                        reason: "is not one of the fields this place takes".to_string(),
                    });
                }
            }
        }

        Ok(evaluated)
    }
}

/// The property names a schema node evaluated, for `unevaluatedProperties`.
#[derive(Default, Clone)]
struct Evaluated {
    names: BTreeSet<String>,
}

impl Evaluated {
    fn insert(&mut self, name: &str) {
        self.names.insert(name.to_string());
    }

    fn merge(&mut self, other: Evaluated) {
        self.names.extend(other.names);
    }
}

/// The fault a union reports when nothing matched its branches.
///
/// When the branches are told apart by a `type` (every inbound and outbound is),
/// the useful thing to say is that the type is not one this version knows; when
/// they are not, the closest fault is the one reported.
fn no_branch(branches: &[Value], faults: Vec<(usize, Fault)>, path: &str, value: &Value) -> Fault {
    let named = value.get("type").and_then(Value::as_str);

    // The document says which one it is: that branch's own fault is the thing
    // to fix, and it is the one the core reports too.
    if let Some(named) = named {
        let mut matching = faults.iter().filter(|(index, _)| {
            branch_types(&branches[*index])
                .iter()
                .any(|kind| kind == named)
        });
        if let (Some((_, fault)), None) = (matching.next(), matching.next()) {
            return fault.clone();
        }
    }

    // The branches of an inbound or an outbound differ by the `type` they
    // insist on, so a value that does not name one of them is the whole story.
    let mut types = Vec::new();
    for branch in branches {
        collect_types_from(branch, &mut types);
    }
    if types.len() == branches.len() && !named.is_some_and(|named| types.iter().any(|t| t == named))
    {
        return Fault {
            path: field(path, "type"),
            reason: format!("is not one of the {} types this version knows", types.len()),
        };
    }

    // A union of plain types (this is how the schema says "a string or an
    // array"): a value that is not even one of those types says so.
    let plain: Vec<&str> = branches
        .iter()
        .filter_map(|branch| branch.get("type").and_then(Value::as_str))
        .collect();
    if plain.len() == branches.len() && !plain.contains(&type_name(value)) {
        return Fault {
            path: path.to_string(),
            reason: format!("is {}, not {}", type_name(value), plain.join(" or ")),
        };
    }

    match faults.into_iter().max_by_key(|(_, fault)| fault.path.len()) {
        Some((_, fault)) => fault,
        None => Fault {
            path: path.to_string(),
            reason: format!(
                "matches none of the {} things this place can be",
                branches.len()
            ),
        },
    }
}

/// The types a branch accepts, following a union of its own.
fn branch_types(branch: &Value) -> Vec<String> {
    let mut kinds = Vec::new();
    collect_types_from(branch, &mut kinds);
    kinds
}

/// The `type` a branch insists on, when it insists on one directly.
fn branch_type(branch: &Value) -> Option<&str> {
    branch
        .get("properties")?
        .get("type")?
        .get("const")?
        .as_str()
}

fn collect_types(root: &Value, branch: &Value, kinds: &mut Vec<String>) {
    let previous = kinds.len();
    collect_types_from(branch, kinds);
    if kinds.len() != previous {
        return;
    }
    // A branch that is a union of its own: look through its reference.
    if let Some(reference) = branch.get("$ref").and_then(Value::as_str) {
        if let Some(target) = resolve(root, reference) {
            collect_types_from(target, kinds);
        }
    }
}

fn collect_types_from(node: &Value, kinds: &mut Vec<String>) {
    if let Some(kind) = branch_type(node) {
        if !kinds.iter().any(|known| known == kind) {
            kinds.push(kind.to_string());
        }
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = node.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                collect_types_from(branch, kinds);
            }
        }
    }
}

/// What the census of a schema found.
struct Census {
    references: BTreeMap<String, usize>,
    patterns: BTreeMap<String, Option<Regex>>,
}

/// Walk every schema position of the document, refusing a keyword or a shape
/// this build does not implement, and gathering what the schema says.
fn census(root: &Value) -> Result<Census, Unreadable> {
    let mut found = Census {
        references: BTreeMap::new(),
        patterns: BTreeMap::new(),
    };
    walk(root, root, "", &mut found)?;
    Ok(found)
}

fn walk(root: &Value, node: &Value, at: &str, found: &mut Census) -> Result<(), Unreadable> {
    let Some(fields) = node.as_object() else {
        return Err(Unreadable::Malformed {
            at: place(at),
            reason: "a schema position holds an object",
        });
    };

    for (keyword, value) in fields {
        let child = match at.is_empty() {
            true => format!("/{keyword}"),
            false => format!("{at}/{keyword}"),
        };

        if keyword.starts_with("x-") {
            if let Some(kind) = value.as_str() {
                if keyword == "x-tag-reference" {
                    *found.references.entry(kind.to_string()).or_default() += 1;
                }
            }
            continue;
        }

        if let Some(layout) = layout(keyword) {
            match (layout, value) {
                (Layout::Schema, Value::Object(_)) => walk(root, value, &child, found)?,
                (Layout::SchemaOrBool, Value::Bool(_)) | (Layout::Bool, Value::Bool(_)) => {}
                (Layout::SchemaOrBool, Value::Object(_)) => walk(root, value, &child, found)?,
                (Layout::Map, Value::Object(names)) => {
                    for (name, sub) in names {
                        walk(root, sub, &format!("{child}/{name}"), found)?;
                    }
                }
                (Layout::Branches, Value::Array(branches)) if !branches.is_empty() => {
                    for (index, branch) in branches.iter().enumerate() {
                        walk(root, branch, &format!("{child}[{index}]"), found)?;
                    }
                }
                (Layout::Schema, _) => {
                    return Err(Unreadable::Shape {
                        at: place(at),
                        keyword: keyword.to_string(),
                        reason: "is a schema",
                    })
                }
                (Layout::SchemaOrBool, _) => {
                    return Err(Unreadable::Shape {
                        at: place(at),
                        keyword: keyword.to_string(),
                        reason: "is a schema or a boolean",
                    })
                }
                (Layout::Bool, _) => {
                    return Err(Unreadable::Shape {
                        at: place(at),
                        keyword: keyword.to_string(),
                        reason: "is a boolean",
                    })
                }
                (Layout::Map, _) => {
                    return Err(Unreadable::Shape {
                        at: place(at),
                        keyword: keyword.to_string(),
                        reason: "is a map of names to schemas",
                    })
                }
                (Layout::Branches, _) => {
                    return Err(Unreadable::Shape {
                        at: place(at),
                        keyword: keyword.to_string(),
                        reason: "is a non-empty list of schemas",
                    })
                }
            }
            continue;
        }

        if !is_leaf(keyword) {
            return Err(Unreadable::Keyword {
                at: place(at),
                keyword: keyword.to_string(),
            });
        }

        if keyword == "pattern" {
            let Some(pattern) = value.as_str() else {
                return Err(Unreadable::Shape {
                    at: place(at),
                    keyword: keyword.to_string(),
                    reason: "is a pattern, as text",
                });
            };
            found
                .patterns
                .insert(pattern.to_string(), Regex::new(pattern).ok());
        }

        if keyword == "$ref" {
            let Some(reference) = value.as_str() else {
                return Err(Unreadable::Shape {
                    at: place(at),
                    keyword: keyword.to_string(),
                    reason: "is a reference, as text",
                });
            };
            if resolve(root, reference).is_none() {
                return Err(Unreadable::Shape {
                    at: place(at),
                    keyword: keyword.to_string(),
                    reason: "is a reference this build can resolve: #/$defs/<name>",
                });
            }
        }
    }

    Ok(())
}

/// A schema position, written the way a reader expects to see it.
fn place(at: &str) -> String {
    match at.is_empty() {
        true => "/".to_string(),
        false => at.to_string(),
    }
}

/// The types `$defs/<name>` accepts.
///
/// A branch is usually `{"properties": {"type": {"const": "vless"}}}`, but a
/// few are a union of their own (snell, for its two versions), so the search
/// follows branches rather than looking only at the top of one.
fn protocols(root: &Value, name: &str) -> Result<Vec<String>, Unreadable> {
    let def = resolve(root, &format!("#/$defs/{name}")).ok_or_else(|| Unreadable::Malformed {
        at: format!("/$defs/{name}"),
        reason: "a schema of this format has this definition",
    })?;
    let branches =
        def.get("oneOf")
            .and_then(Value::as_array)
            .ok_or_else(|| Unreadable::Malformed {
                at: format!("/$defs/{name}"),
                reason: "a schema of this format lists its types as a oneOf",
            })?;

    let mut kinds = Vec::new();
    for branch in branches {
        collect_types(root, branch, &mut kinds);
    }
    if kinds.is_empty() {
        return Err(Unreadable::Malformed {
            at: format!("/$defs/{name}"),
            reason: "a schema of this format names the type each branch is",
        });
    }

    Ok(kinds)
}

/// The target of a `#/$defs/<name>` reference, if it is there.
fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let name = reference.strip_prefix("#/$defs/")?;
    if name.is_empty() || name.contains('/') {
        return None;
    }
    root.get("$defs")?.get(name)
}

/// A field path with one more name on it.
fn field(path: &str, name: &str) -> String {
    match path.is_empty() {
        true => name.to_string(),
        false => format!("{path}.{name}"),
    }
}

/// Whether a name the schema declares and a key a document writes are the same
/// field.
///
/// One definition in sing-box's schema spells its fields the way Go names them
/// (`Username`, `Password`) instead of giving them the json names every config
/// uses, and the decoder — Go's `encoding/json` — matches keys
/// case-insensitively, so `username` is loaded. A validator that insisted on the
/// exact spelling would refuse documents the core takes, one of which is how
/// this was found; names are compared the way the core compares them.
fn same_field(declared: &str, written: &str) -> bool {
    declared == written || declared.eq_ignore_ascii_case(written)
}

/// Whether a value is of a type a `type` keyword names.
fn type_matches(types: &Value, value: &Value) -> bool {
    let matches = |kind: &str| match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        _ => false,
    };
    match types {
        Value::String(kind) => matches(kind),
        Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).any(matches),
        _ => false,
    }
}

/// The JSON type names a `type` keyword lists.
fn type_names(types: &Value) -> String {
    match types {
        Value::String(kind) => kind.to_string(),
        Value::Array(kinds) => {
            let names: Vec<&str> = kinds.iter().filter_map(Value::as_str).collect();
            names.join(" or ")
        }
        _ => "of a type this build does not read".to_string(),
    }
}

/// The JSON type name of a value.
fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_f64() => "number",
        Value::Number(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A schema with one of every keyword this build reads.
    fn schema() -> Schema {
        let document = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://example.com/schema.json",
            "type": "object",
            "properties": {
                "log": {
                    "type": "object",
                    "properties": {
                        "level": { "type": "string", "enum": ["trace", "debug", "info"] },
                        "output": { "type": "string", "pattern": "^[a-z]+$" },
                        "timestamp": { "type": "boolean" }
                    },
                    "additionalProperties": false
                },
                "listen": { "type": "integer", "minimum": 0, "maximum": 65535 },
                "marks": {
                    "type": "array",
                    "items": { "type": "integer", "minimum": 0 }
                },
                "rule_set": { "$ref": "#/$defs/RuleSet" },
                "rules": { "type": "array", "items": { "$ref": "#/$defs/Rule" } },
                "inbounds": { "type": "array", "items": { "$ref": "#/$defs/Inbound" } },
                "outbounds": { "type": "array", "items": { "$ref": "#/$defs/Outbound" } }
            },
            "additionalProperties": false,
            "$defs": {
                "RuleSet": {
                    "type": "object",
                    "propertyNames": { "pattern": "^[a-z_]+$" },
                    "additionalProperties": { "type": "string" }
                },
                "Rule": {
                    "type": "object",
                    "properties": {
                        "outbound": { "type": "string", "x-tag-reference": "outbound" }
                    },
                    "oneOf": [
                        { "properties": { "action": { "const": "route" } }, "required": ["action"] },
                        { "properties": { "action": { "const": "resolve" } }, "required": ["action"] }
                    ],
                    "unevaluatedProperties": false
                },
                "Inbound": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "socks" },
                                "tag": { "type": "string" },
                                "listen_port": { "type": "integer", "minimum": 0, "maximum": 65535 }
                            },
                            "required": ["type"],
                            "additionalProperties": false
                        },
                        {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "properties": { "type": { "const": "snell" }, "version": { "const": 5 } },
                                    "required": ["type"],
                                    "additionalProperties": false
                                }
                            ]
                        }
                    ]
                },
                "Outbound": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "direct" },
                                "tag": { "type": "string" },
                                "override_address": { "type": "string" }
                            },
                            "required": ["type"],
                            "additionalProperties": false
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "selector" },
                                "tag": { "type": "string" },
                                "outbounds": { "type": "array", "items": { "type": "string", "x-tag-reference": "outbound" } }
                            },
                            "required": ["type", "outbounds"],
                            "additionalProperties": false
                        }
                    ]
                }
            }
        });

        Schema::read(document.to_string().as_bytes()).expect("a readable schema")
    }

    fn refused(document: Value) -> Unreadable {
        Schema::read(document.to_string().as_bytes()).expect_err("refused")
    }

    /// The unions a schema of this format has, said as little as they can be.
    fn unions() -> Value {
        json!({
            "Inbound": { "oneOf": [
                { "type": "object", "properties": { "type": { "const": "socks" } } }
            ] },
            "Outbound": { "oneOf": [
                { "type": "object", "properties": { "type": { "const": "direct" } } }
            ] }
        })
    }

    /// A schema about one keyword, and nothing else.
    fn small(properties: Value) -> Schema {
        let document = json!({
            "type": "object",
            "properties": properties,
            "$defs": unions()
        });

        Schema::read(document.to_string().as_bytes()).expect("a readable schema")
    }

    fn failed(schema: &Schema, document: Value) -> Fault {
        schema
            .validate(&document)
            .failed()
            .expect("a fault")
            .clone()
    }

    #[test]
    fn a_document_the_schema_describes_passes() {
        let schema = schema();

        let verdict = schema.validate(&json!({
            "log": { "level": "debug", "output": "stdout" },
            "listen": 1080,
            "marks": [1, 2],
            "outbounds": [
                { "type": "selector", "tag": "s", "outbounds": ["x"] },
                { "type": "direct", "tag": "x" }
            ],
            "rules": [{ "action": "route", "outbound": "s" }]
        }));

        assert_eq!(verdict, Verdict::Ok);
    }

    #[test]
    fn the_types_a_union_takes_are_read_through_a_union_of_its_own() {
        let schema = schema();

        assert_eq!(schema.inbound_types(), ["socks", "snell"]);
        assert_eq!(schema.outbound_types(), ["direct", "selector"]);
        assert_eq!(schema.references().get("outbound"), Some(&2));
    }

    #[test]
    fn a_keyword_this_build_does_not_implement_makes_the_schema_unreadable() {
        let refused = refused(json!({
            "type": "object",
            "$defs": unions(),
            "if": { "type": "string" }
        }));

        assert_eq!(
            refused,
            Unreadable::Keyword {
                at: "/".to_string(),
                keyword: "if".to_string(),
            }
        );
        assert_eq!(
            refused.to_string(),
            r#"/: the keyword "if" is not implemented"#
        );
    }

    #[test]
    fn a_keyword_in_a_shape_it_does_not_have_makes_the_schema_unreadable() {
        let refused = refused(json!({
            "type": "object",
            "properties": { "marks": { "items": [{ "type": "integer" }] } },
            "$defs": unions()
        }));

        assert_eq!(
            refused,
            Unreadable::Shape {
                at: "/properties/marks".to_string(),
                keyword: "items".to_string(),
                reason: "is a schema",
            }
        );
    }

    #[test]
    fn a_reference_this_build_cannot_resolve_makes_the_schema_unreadable() {
        let refused = refused(json!({
            "type": "object",
            "properties": { "x": { "$ref": "https://example.com/other.json" } },
            "$defs": unions()
        }));

        assert!(matches!(
            refused,
            Unreadable::Shape {
                keyword,
                reason: "is a reference this build can resolve: #/$defs/<name>",
                ..
            } if keyword == "$ref"
        ));
    }

    #[test]
    fn a_schema_without_the_unions_this_build_derives_from_is_refused() {
        let refused = refused(json!({ "type": "object", "$defs": {} }));

        assert_eq!(
            refused,
            Unreadable::Malformed {
                at: "/$defs/Inbound".to_string(),
                reason: "a schema of this format has this definition",
            }
        );
    }

    #[test]
    fn a_fragment_that_is_not_json_says_where() {
        let refused = Schema::read(b"{").expect_err("refused");

        assert_eq!(refused, Unreadable::NotJson { line: 1, column: 1 });
    }

    #[test]
    fn a_type_that_is_not_the_one_this_place_takes_is_refused() {
        let fault = failed(&schema(), json!({ "listen": "1080" }));

        assert_eq!(fault.path, "listen");
        assert_eq!(fault.reason, "is string, not integer");
    }

    #[test]
    fn a_field_that_is_missing_is_named() {
        let fault = failed(&schema(), json!({ "outbounds": [{ "type": "selector" }] }));

        assert_eq!(fault.path, "outbounds[0].outbounds");
        assert_eq!(fault.reason, "is required here");
    }

    #[test]
    fn a_field_this_place_does_not_take_is_named() {
        let fault = failed(
            &schema(),
            json!({ "log": { "level": "info", "outputs": "stdout" } }),
        );

        assert_eq!(fault.path, "log.outputs");
        assert_eq!(fault.reason, "is not one of the fields this place takes");
    }

    /// The rule's own fields are closed by `unevaluatedProperties`, which only
    /// sees a name once some branch of the `oneOf` beside it has evaluated it.
    #[test]
    fn a_field_no_branch_of_a_union_evaluated_is_named() {
        let fault = failed(
            &schema(),
            json!({ "rules": [{ "action": "route", "outboudn": "s" }] }),
        );

        assert_eq!(fault.path, "rules[0].outboudn");
        assert_eq!(fault.reason, "is not one of the fields this place takes");
    }

    #[test]
    fn a_value_that_is_not_in_the_set_this_place_takes_is_refused() {
        let fault = failed(&schema(), json!({ "log": { "level": "loud" } }));

        assert_eq!(fault.path, "log.level");
        assert_eq!(fault.reason, "is not one of: trace, debug, info");

        let fault = failed(&schema(), json!({ "rules": [{ "action": "block" }] }));

        assert_eq!(fault.path, "rules[0].action");
        assert_eq!(fault.reason, "is not the one value this place takes");
    }

    #[test]
    fn a_number_outside_the_range_is_refused() {
        let fault = failed(&schema(), json!({ "listen": 70000 }));

        assert_eq!(fault.path, "listen");
        assert_eq!(fault.reason, "is outside the range this place takes");

        let fault = failed(&schema(), json!({ "marks": [1, -1] }));

        assert_eq!(fault.path, "marks[1]");
        assert_eq!(fault.reason, "is outside the range this place takes");
    }

    #[test]
    fn a_field_written_against_its_pattern_is_refused() {
        let fault = failed(&schema(), json!({ "log": { "output": "Stdout" } }));

        assert_eq!(fault.path, "log.output");
        assert_eq!(fault.reason, "is not written the way this field is");
    }

    /// `propertyNames` is asked about the keys themselves, so the fault names
    /// the key that does not fit.
    #[test]
    fn a_key_written_against_its_pattern_is_named() {
        let fault = failed(
            &schema(),
            json!({ "rule_set": { "Set One": "https://example.com/a" } }),
        );

        assert_eq!(fault.path, "rule_set.Set One");
        assert_eq!(fault.reason, "is not written the way this field is");
    }

    #[test]
    fn a_union_says_the_type_is_not_one_it_knows() {
        let fault = failed(&schema(), json!({ "outbounds": [{ "type": "stun" }] }));

        assert_eq!(fault.path, "outbounds[0].type");
        assert_eq!(fault.reason, "is not one of the 2 types this version knows");
    }

    #[test]
    fn a_fault_inside_the_branch_a_union_took_is_the_one_reported() {
        let fault = failed(
            &schema(),
            json!({ "outbounds": [{ "type": "selector", "tag": "s", "outbounds": [7] }] }),
        );

        assert_eq!(fault.path, "outbounds[0].outbounds[0]");
        assert_eq!(fault.reason, "is integer, not string");
    }

    /// `anyOf` is how this schema says "a string or an array", so it has to be
    /// asked about values that are neither.
    #[test]
    fn a_union_is_asked_about_values_that_are_not_objects() {
        let schema = small(json!({
            "x": { "anyOf": [{ "type": "string" }, { "type": "integer" }] }
        }));

        assert!(schema.validate(&json!({ "x": "a string" })).is_ok());
        assert!(schema.validate(&json!({ "x": 7 })).is_ok());
        assert_eq!(
            failed(&schema, json!({ "x": true })),
            Fault {
                path: "x".to_string(),
                reason: "is boolean, not string or integer".to_string(),
            }
        );
    }

    /// `$defs/User` in the real schema spells `Username`/`Password`, and the
    /// core loads a config that writes them the way every config does.
    #[test]
    fn a_field_is_matched_the_way_the_core_matches_it() {
        let schema = small(json!({
            "user": {
                "type": "object",
                "properties": { "Username": { "type": "string" }, "Password": { "type": "string" } },
                "additionalProperties": false
            }
        }));

        assert!(schema
            .validate(&json!({ "user": { "username": "a", "password": "b" } }))
            .is_ok());
        assert!(schema
            .validate(&json!({ "user": { "Username": "a" } }))
            .is_ok());

        let fault = failed(&schema, json!({ "user": { "usernam": "a" } }));
        assert_eq!(fault.path, "user.usernam");

        let fault = failed(&schema, json!({ "user": { "username": 7 } }));
        assert_eq!(fault.path, "user.username");
        assert_eq!(fault.reason, "is integer, not string");
    }

    /// A `number` takes an integer, but an `integer` does not take a fraction:
    /// JSON Schema draws the line there, and so does the core.
    #[test]
    fn a_number_is_wider_than_an_integer() {
        let schema = small(json!({
            "a": { "type": "number" },
            "b": { "type": "integer" }
        }));

        assert!(schema.validate(&json!({ "a": 7 })).is_ok());
        assert!(schema.validate(&json!({ "b": 7 })).is_ok());
        assert_eq!(
            failed(&schema, json!({ "b": 7.5 })).reason,
            "is number, not integer"
        );
    }

    #[test]
    fn a_reference_is_followed_where_it_is_written() {
        let fault = failed(&schema(), json!({ "rule_set": { "set": 7 } }));

        assert_eq!(fault.path, "rule_set.set");
        assert_eq!(fault.reason, "is integer, not string");
    }

    #[test]
    fn a_pattern_this_build_cannot_compile_is_reported_rather_than_passed() {
        let schema = small(json!({
            "x": { "type": "string", "pattern": "(?=x)" }
        }));

        let verdict = schema.validate(&json!({ "x": "anything" }));

        assert_eq!(verdict.skipped().len(), 1);
        assert!(verdict.skipped()[0]
            .what
            .contains("the pattern this place is written by"));
    }

    #[test]
    fn a_document_too_deep_to_walk_is_reported_rather_than_passed() {
        // A schema that refers to itself, and a document that follows it down.
        let document = json!({
            "type": "object",
            "properties": { "next": { "$ref": "#/$defs/Chain" } },
            "$defs": {
                "Chain": { "type": "object", "properties": { "next": { "$ref": "#/$defs/Chain" } } },
                "Inbound": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "socks" } } }
                ] },
                "Outbound": { "oneOf": [
                    { "type": "object", "properties": { "type": { "const": "direct" } } }
                ] }
            }
        });
        let schema = Schema::read(document.to_string().as_bytes()).expect("a readable schema");

        let mut deep = json!({});
        for _ in 0..(MAX_DEPTH + 2) {
            deep = json!({ "next": deep });
        }

        let verdict = schema.validate(&deep);

        assert_eq!(verdict.skipped().len(), 1);
        assert!(verdict.skipped()[0]
            .what
            .contains("this deep into the document"));
    }
}
