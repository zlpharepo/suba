//! Collection bindings belong to authored documents, never to native sing-box.
//!
//! Projection validates the extension before removing only its allowed locations.
//! Expansion uses the same resolved batch as the generated runtime outbounds, so
//! renamed tags and shared collection provenance cannot diverge.

use std::collections::BTreeSet;

use serde_json::Value;
use suba_singbox::assemble::{self, Assembled, Fault, Unfit};

use super::{ConversionSkip, GeneratedOutbound};
use crate::{error::Error, state::access::Access};

const EXTENSION: &str = "x-suba-collections";

/// What one run gets beside the operator's document, resolved before any lock:
/// the selected collections' outbounds, with their provenance, and the users
/// and pools that decide which inbounds get pool users.
#[derive(Default)]
pub(crate) struct Contributions {
    pub selected: Vec<String>,
    pub outbounds: Vec<GeneratedOutbound>,
    pub skipped: Vec<ConversionSkip>,
    /// A missing selected collection must not masquerade as an empty one.
    pub unavailable: bool,
    pub access: Access,
}

impl Contributions {
    /// A failed resolution must not look like a valid empty contribution.
    pub(crate) fn ensure_available(&self) -> Result<(), Error> {
        if self.unavailable {
            return Err(fault(
                "outbounds.x-suba-collections",
                "a selected collection is unavailable",
            ));
        }
        Ok(())
    }
}

fn fault(path: &str, reason: &'static str) -> Error {
    Error::Document(format!("{path}: {reason}"))
}

/// Only top-level group entries may carry this extension. Unknown native keys
/// remain intact for schema validation rather than being silently stripped.
pub(super) fn project(document: &Value) -> Result<Value, Error> {
    let mut native = document.clone();
    if let Some(entries) = native.get_mut("outbounds").and_then(Value::as_array_mut) {
        for (index, entry) in entries.iter_mut().enumerate() {
            if let Some(names) = entry.get(EXTENSION) {
                let path = format!("outbounds[{index}].{EXTENSION}");
                if !matches!(
                    entry.get("type").and_then(Value::as_str),
                    Some("selector" | "urltest")
                ) {
                    return Err(fault(
                        &path,
                        "is only allowed on selector or urltest outbounds",
                    ));
                }
                let Some(names) = names.as_array() else {
                    return Err(fault(&path, "must be an array of collection names"));
                };
                for (slot, name) in names.iter().enumerate() {
                    if !name.is_string() {
                        return Err(fault(
                            &format!("{path}[{slot}]"),
                            "must be a collection name string",
                        ));
                    }
                }
                entry
                    .as_object_mut()
                    .expect("an outbound object")
                    .remove(EXTENSION);
            }
        }
    }
    if contains_extension(&native) {
        return Err(fault(
            EXTENSION,
            "is only allowed on top-level selector or urltest outbounds",
        ));
    }
    Ok(native)
}

fn contains_extension(value: &Value) -> bool {
    match value {
        Value::Object(fields) => {
            fields.contains_key(EXTENSION) || fields.values().any(contains_extension)
        }
        Value::Array(values) => values.iter().any(contains_extension),
        _ => false,
    }
}

pub(super) fn assemble(document: &Value, snapshot: &Contributions) -> Result<Assembled, Error> {
    let mut native = project(document)?;
    snapshot.ensure_available()?;
    let mut bound = false;
    if let Some(entries) = document.get("outbounds").and_then(Value::as_array) {
        for (index, entry) in entries.iter().enumerate() {
            let Some(names) = entry.get(EXTENSION).and_then(Value::as_array) else {
                continue;
            };
            bound = true;
            let path = format!("outbounds[{index}]");
            for (slot, name) in names.iter().enumerate() {
                if !snapshot
                    .selected
                    .iter()
                    .any(|selected| name.as_str() == Some(selected))
                {
                    return Err(fault(
                        &format!("{path}.{EXTENSION}[{slot}]"),
                        "the bound collection is not selected",
                    ));
                }
            }
            if !cfg!(feature = "singbox") && !names.is_empty() {
                return Err(fault(
                    &format!("{path}.{EXTENSION}"),
                    "collection rendering is unavailable",
                ));
            }
            let manual = match entry.get("outbounds") {
                None => &[][..],
                Some(Value::Array(values)) => values.as_slice(),
                Some(_) => {
                    return Err(fault(
                        &format!("{path}.outbounds"),
                        "must be an array of member tags",
                    ))
                }
            };
            let mut members = Vec::new();
            let mut seen = BTreeSet::new();
            for (slot, member) in manual.iter().enumerate() {
                let Some(tag) = member.as_str() else {
                    return Err(fault(
                        &format!("{path}.outbounds[{slot}]"),
                        "must be a member tag string",
                    ));
                };
                if seen.insert(tag) {
                    members.push(Value::String(tag.to_owned()));
                }
            }
            for outbound in &snapshot.outbounds {
                if !outbound
                    .collections
                    .iter()
                    .any(|collection| names.iter().any(|name| name.as_str() == Some(collection)))
                {
                    continue;
                }
                let Some(tag) = outbound
                    .value
                    .get("tag")
                    .and_then(Value::as_str)
                    .filter(|tag| !tag.is_empty())
                else {
                    return Err(fault(
                        &format!("{path}.{EXTENSION}"),
                        "a generated outbound has no usable tag",
                    ));
                };
                if seen.insert(tag) {
                    members.push(Value::String(tag.to_owned()));
                }
            }
            if members.is_empty() {
                return Err(fault(
                    &format!("{path}.outbounds"),
                    "must contain at least one member after collection expansion",
                ));
            }
            if entry.get("type").and_then(Value::as_str) == Some("selector") {
                if let Some(default) = entry.get("default") {
                    if !members.contains(default) {
                        return Err(fault(
                            &format!("{path}.default"),
                            "must name a member of this selector",
                        ));
                    }
                }
            }
            native["outbounds"][index]["outbounds"] = Value::Array(members);
        }
    }
    let generated: Vec<_> = snapshot
        .outbounds
        .iter()
        .map(|outbound| outbound.value.clone())
        .collect();
    assemble::assemble(&native, &generated).map_err(|unfit| {
        if bound {
            match unfit {
                Unfit::Shape { path, reason } => fault(&path, reason),
                Unfit::Tag {
                    path,
                    fault: problem,
                    ..
                } => fault(
                    &path,
                    match problem {
                        Fault::Duplicate => "a tag is declared more than once",
                        Fault::Missing => "a referenced tag is not declared",
                        Fault::Circular(_) => "outbound dependencies contain a cycle",
                    },
                ),
            }
        } else {
            Error::Document(unfit.to_string())
        }
    })
}
