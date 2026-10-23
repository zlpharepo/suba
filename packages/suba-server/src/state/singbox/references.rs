//! Schema tag declarations for editor suggestions, independent of runtime validation.
//!
//! Incomplete definitions and collisions remain useful while editing. Paths are
//! relative to their source: the saved document or the selected collections'
//! generated outbounds, not an assembled document's shifted array indices.
//! Collection provenance is attached during resolution, before rendering can
//! rename or omit nodes; the catalog never guesses ownership from a tag.

use serde::Serialize;
use serde_json::Value;

/// Provenance travels with the rendered value, not its potentially renamed tag.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GeneratedOutbound {
    pub value: Value,
    pub collections: Vec<String>,
}

/// Input positions identify skipped entries without exposing node names or credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ConversionSkip {
    pub path: String,
    pub reason: &'static str,
}

/// Owned definitions keep editor previews from changing their source data.
#[derive(Debug, Serialize)]
pub(crate) struct Tag {
    tag: String,
    space: &'static str,
    kind: Option<String>,
    path: String,
    source: Source,
    /// Empty for authored definitions; otherwise all contributors in selected order.
    collections: Vec<String>,
    value: Value,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Source {
    Config,
    Collection,
}

pub(super) fn catalog(document: &Value, generated: &[GeneratedOutbound]) -> Vec<Tag> {
    let mut found = Vec::new();
    append(
        &mut found,
        generated
            .iter()
            .map(|outbound| (&outbound.value, outbound.collections.as_slice())),
        "outbound",
        "outbounds",
        Source::Collection,
    );
    for (space, pointer, path) in [
        ("outbound", "/outbounds", "outbounds"),
        ("outbound", "/endpoints", "endpoints"),
        ("inbound", "/inbounds", "inbounds"),
        ("dns_server", "/dns/servers", "dns.servers"),
        ("rule_set", "/route/rule_set", "route.rule_set"),
        (
            "certificate_provider",
            "/certificate_providers",
            "certificate_providers",
        ),
        ("http_client", "/http_clients", "http_clients"),
        (
            "network_namespace",
            "/network_namespaces",
            "network_namespaces",
        ),
    ] {
        if let Some(entries) = document.pointer(pointer).and_then(Value::as_array) {
            append(
                &mut found,
                entries.iter().map(|value| (value, [].as_slice())),
                space,
                path,
                Source::Config,
            );
        }
    }
    found
}

fn append<'a>(
    found: &mut Vec<Tag>,
    entries: impl Iterator<Item = (&'a Value, &'a [String])>,
    space: &'static str,
    path: &str,
    source: Source,
) {
    for (index, (value, collections)) in entries.enumerate() {
        let Some(tag) = value.get("tag") else {
            continue;
        };
        let tags = tag
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_else(|| std::slice::from_ref(tag));
        for (alias, name) in tags.iter().enumerate() {
            let Some(name) = name.as_str().filter(|name| !name.is_empty()) else {
                continue;
            };
            let mut path = format!("{path}[{index}].tag");
            if tag.is_array() {
                path.push_str(&format!("[{alias}]"));
            }
            found.push(Tag {
                tag: name.to_owned(),
                space,
                kind: value.get("type").and_then(Value::as_str).map(str::to_owned),
                path,
                source,
                collections: collections.to_vec(),
                value: value.clone(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn entry(
        tag: &str,
        space: &str,
        kind: Option<&str>,
        path: &str,
        source: &str,
        value: &Value,
    ) -> Value {
        json!({
            "tag": tag, "space": space, "kind": kind, "path": path,
            "source": source, "collections": [], "value": value
        })
    }

    #[test]
    fn reference_catalog_carries_every_namespace_and_complete_definition() {
        let document = json!({
            "outbounds": [{"tag": "direct", "type": "direct", "bind_interface": "example0"}],
            "endpoints": [{"tag": "tunnel", "type": "wireguard", "peers": [{"allowed_ips": ["192.0.2.0/24"]}]}],
            "inbounds": [{"tag": "listener", "type": "mixed", "listen_port": 1080}],
            "dns": {"servers": [{"tag": "local-dns", "type": "local", "prefer_go": true}]},
            "route": {"rule_set": [
                {"tag": ["rules", "rules-alias"], "type": "inline", "rules": [{"domain_suffix": ["example.com"]}]},
                {"tag": "implicit-rules", "rules": []}
            ]},
            "certificate_providers": [{"tag": "certificates", "type": "tailscale", "endpoint": "tunnel"}],
            "http_clients": [{"tag": "client", "headers": {"X-Example": "example-value"}}],
            "network_namespaces": [{"tag": "namespace", "path": "/run/netns/example"}]
        });
        let expected = [
            (
                "direct",
                "outbound",
                Some("direct"),
                "outbounds[0].tag",
                "/outbounds/0",
            ),
            (
                "tunnel",
                "outbound",
                Some("wireguard"),
                "endpoints[0].tag",
                "/endpoints/0",
            ),
            (
                "listener",
                "inbound",
                Some("mixed"),
                "inbounds[0].tag",
                "/inbounds/0",
            ),
            (
                "local-dns",
                "dns_server",
                Some("local"),
                "dns.servers[0].tag",
                "/dns/servers/0",
            ),
            (
                "rules",
                "rule_set",
                Some("inline"),
                "route.rule_set[0].tag[0]",
                "/route/rule_set/0",
            ),
            (
                "rules-alias",
                "rule_set",
                Some("inline"),
                "route.rule_set[0].tag[1]",
                "/route/rule_set/0",
            ),
            (
                "implicit-rules",
                "rule_set",
                None,
                "route.rule_set[1].tag",
                "/route/rule_set/1",
            ),
            (
                "certificates",
                "certificate_provider",
                Some("tailscale"),
                "certificate_providers[0].tag",
                "/certificate_providers/0",
            ),
            (
                "client",
                "http_client",
                None,
                "http_clients[0].tag",
                "/http_clients/0",
            ),
            (
                "namespace",
                "network_namespace",
                None,
                "network_namespaces[0].tag",
                "/network_namespaces/0",
            ),
        ]
        .map(|(tag, space, kind, path, pointer)| {
            entry(
                tag,
                space,
                kind,
                path,
                "config",
                document.pointer(pointer).unwrap(),
            )
        });
        assert_eq!(
            serde_json::to_value(catalog(&document, &[])).unwrap(),
            json!(expected)
        );
    }

    #[test]
    fn reference_catalog_retains_collisions_and_owns_its_definitions() {
        let document = json!({
            "outbounds": [
                {"type": "direct", "tag": "shared"},
                {"type": "selector", "tag": "shared", "outbounds": ["missing"]}
            ],
            "endpoints": [{"type": "wireguard", "tag": "shared"}],
            "inbounds": [{"type": "mixed", "tag": "shared"}]
        });
        let generated = vec![
            GeneratedOutbound {
                value: json!({"type": "trojan", "tag": "shared", "server_port": 443}),
                collections: vec!["second".to_string(), "first".to_string()],
            },
            GeneratedOutbound {
                value: json!({"type": "direct", "tag": "shared"}),
                collections: vec!["third".to_string()],
            },
        ];
        let original = (document.clone(), generated.clone());
        let mut found = catalog(&document, &generated);
        let mut expected = json!([
            entry(
                "shared",
                "outbound",
                Some("trojan"),
                "outbounds[0].tag",
                "collection",
                &generated[0].value
            ),
            entry(
                "shared",
                "outbound",
                Some("direct"),
                "outbounds[1].tag",
                "collection",
                &generated[1].value
            ),
            entry(
                "shared",
                "outbound",
                Some("direct"),
                "outbounds[0].tag",
                "config",
                &document["outbounds"][0]
            ),
            entry(
                "shared",
                "outbound",
                Some("selector"),
                "outbounds[1].tag",
                "config",
                &document["outbounds"][1]
            ),
            entry(
                "shared",
                "outbound",
                Some("wireguard"),
                "endpoints[0].tag",
                "config",
                &document["endpoints"][0]
            ),
            entry(
                "shared",
                "inbound",
                Some("mixed"),
                "inbounds[0].tag",
                "config",
                &document["inbounds"][0]
            )
        ]);
        expected[0]["collections"] = json!(["second", "first"]);
        expected[1]["collections"] = json!(["third"]);
        assert_eq!(serde_json::to_value(&found).unwrap(), expected);
        found[0].value["tag"] = json!("changed-preview");
        found[2].value["tag"] = json!("changed-preview");
        assert_eq!((document, generated), original);
    }

    #[test]
    fn reference_catalog_skips_unusable_tags_without_validating_other_fields() {
        let document = json!({
            "outbounds": [null, {}, {"tag": ""}, {"tag": 4}, {"tag": "usable", "type": 5}],
            "inbounds": "unfinished",
            "dns": {"servers": [{"tag": "dns", "type": "local"}], "rules": [{"tag": "not-a-server"}]},
            "route": {"rule_set": [{"tag": [null, "", "alias", 4, "alias"], "rules": []}], "final": "missing"},
            "services": [{"tag": "not-a-reference-namespace"}]
        });
        assert_eq!(
            serde_json::to_value(catalog(&document, &[])).unwrap(),
            json!([
                entry(
                    "usable",
                    "outbound",
                    None,
                    "outbounds[4].tag",
                    "config",
                    &document["outbounds"][4]
                ),
                entry(
                    "dns",
                    "dns_server",
                    Some("local"),
                    "dns.servers[0].tag",
                    "config",
                    &document["dns"]["servers"][0]
                ),
                entry(
                    "alias",
                    "rule_set",
                    None,
                    "route.rule_set[0].tag[2]",
                    "config",
                    &document["route"]["rule_set"][0]
                ),
                entry(
                    "alias",
                    "rule_set",
                    None,
                    "route.rule_set[0].tag[4]",
                    "config",
                    &document["route"]["rule_set"][0]
                )
            ])
        );
    }
}
