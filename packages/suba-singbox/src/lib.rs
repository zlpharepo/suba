//! Nodes as a sing-box document.
//!
//! sing-box reads its own schema: a node that a share link spells one way is an
//! object with `type`, `server`, `server_port` and a field per credential, and
//! the carriage and TLS are nested objects of their own. This crate is the
//! translation, and it is a **pure function** of the nodes: nothing here reads a
//! clock, a file or a socket, so the whole mapping is testable against documents
//! written by hand.
//!
//! What it will not do:
//!
//! * **It refuses what it cannot express**, per node, naming the thing it could
//!   not express — a protocol, a carriage. A node left out silently would be a
//!   subscription that quietly serves less than the operator configured.
//! * **It does not invent.** A field sing-box has and the model does not is left
//!   at sing-box's own default rather than filled with a guess.
//!
//! The document is the part a *collection* owns: the outbounds. The rest of a
//! client's configuration — its inbounds, its DNS, its routing — belongs to
//! whoever runs the client, and a converter that guessed at it would be handing
//! out a configuration nobody asked for.

use serde_json::{json, Map, Value};

use suba_proto::{Client, Endpoint, Kind, Node, Outbound, TlsClient, Transport};

/// The protocols this mapping can write.
///
/// The capability list is built from this, and so is every refusal: one table,
/// so what this crate says it can do and what it does cannot drift apart.
pub const PROTOCOLS: &[Kind] = &[Kind::Trojan, Kind::Shadowsocks, Kind::Socks, Kind::Http];

/// A node the document does not contain, by its position in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    /// Where the node was in the list it was given.
    pub index: usize,
    /// What could not be expressed.
    pub reason: Reason,
}

/// Why a node is not in the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The protocol has no outbound in sing-box.
    Protocol(Kind),
    /// How the node is carried has no representation.
    Transport(String),
}

/// One node as a sing-box outbound.
///
/// `tag` is what the document calls it: what sing-box refers to it by in a
/// selector or a routing rule.
pub fn outbound(tag: &str, node: &Node<Client>) -> Result<Value, Reason> {
    if !PROTOCOLS.contains(&node.protocol.kind()) {
        return Err(Reason::Protocol(node.protocol.kind()));
    }

    let mut outbound = Map::new();
    outbound.insert("tag".to_string(), json!(tag));
    outbound.insert("server".to_string(), json!(node.endpoint.host.to_string()));
    outbound.insert("server_port".to_string(), json!(node.endpoint.port.get()));

    match &node.protocol {
        Outbound::Trojan(client) => {
            outbound.insert("type".to_string(), json!("trojan"));
            outbound.insert("password".to_string(), json!(client.password.as_str()));
        }
        Outbound::Shadowsocks(client) => {
            outbound.insert("type".to_string(), json!("shadowsocks"));
            outbound.insert("method".to_string(), json!(client.method.as_ref()));
            outbound.insert("password".to_string(), json!(client.password.as_str()));

            if let Some(plugin) = &client.plugin {
                // sing-box takes the plugin's name and its options separately,
                // where a link spells them as one string.
                outbound.insert("plugin".to_string(), json!(plugin.name.as_ref()));
                outbound.insert("plugin_opts".to_string(), json!(plugin.to_string()));
            }
        }
        Outbound::Socks(client) => {
            outbound.insert("type".to_string(), json!("socks"));
            outbound.insert(
                "version".to_string(),
                json!(client.version.as_str().trim_start_matches("socks")),
            );

            if let Some(username) = &client.username {
                outbound.insert("username".to_string(), json!(username.as_ref()));
            }
            if let Some(password) = &client.password {
                outbound.insert("password".to_string(), json!(password.as_str()));
            }
        }
        Outbound::Http(client) => {
            outbound.insert("type".to_string(), json!("http"));

            if let Some(username) = &client.username {
                outbound.insert("username".to_string(), json!(username.as_ref()));
            }
            if let Some(password) = &client.password {
                outbound.insert("password".to_string(), json!(password.as_str()));
            }
        }
        // Refused above: the table and this match are checked against each other
        // by the fixture test below.
        other => return Err(Reason::Protocol(other.kind())),
    }

    if let Some(tls) = node.tls.as_ref() {
        outbound.insert("tls".to_string(), tls_of(tls, &node.endpoint));
    }

    if let Some(carriage) = transport_of(&node.transport) {
        outbound.insert("transport".to_string(), carriage?);
    }

    Ok(Value::Object(outbound))
}

/// A client document: one outbound per node, in the order they are given.
///
/// Nodes this crate cannot express are left out and reported, with the position
/// they had in the input so that a caller can say which one it was.
pub fn client_config(nodes: &[(&str, &Node<Client>)]) -> (String, Vec<Refused>) {
    let mut outbounds = Vec::new();
    let mut refused = Vec::new();
    let mut tags: Vec<String> = Vec::new();

    for (index, (name, node)) in nodes.iter().enumerate() {
        let tag = unique_tag(name, index, &mut tags);

        match outbound(&tag, node) {
            Ok(outbound) => outbounds.push(outbound),
            Err(reason) => refused.push(Refused { index, reason }),
        }
    }

    let document = json!({ "outbounds": outbounds });
    // The values are built here, so a failure would be this crate's bug rather
    // than something a caller could act on.
    let body = serde_json::to_string(&document).expect("the document this crate built");

    (body, refused)
}

/// The tag for one node.
///
/// sing-box identifies an outbound by its tag and refuses a configuration with
/// two of the same, so a name used twice is disambiguated here rather than
/// handed over as a document that will not load. The name is otherwise kept as
/// the provider spelled it: an operator finds their nodes by that name.
fn unique_tag(name: &str, index: usize, taken: &mut Vec<String>) -> String {
    let base = match name.is_empty() {
        true => format!("node-{}", index + 1),
        false => name.to_string(),
    };

    let mut tag = base.clone();
    let mut suffix = 2;

    while taken.contains(&tag) {
        tag = format!("{base} {suffix}");
        suffix += 1;
    }

    taken.push(tag.clone());

    tag
}

/// The TLS block, when the node is wrapped in TLS.
fn tls_of(tls: &TlsClient, endpoint: &Endpoint) -> Value {
    let mut block = Map::new();

    block.insert("enabled".to_string(), json!(true));
    block.insert(
        "server_name".to_string(),
        json!(match tls.server_name.as_ref() {
            Some(name) => name.to_string(),
            None => endpoint.host.to_string(),
        }),
    );

    if tls.insecure {
        block.insert("insecure".to_string(), json!(true));
    }

    if !tls.alpn.is_empty() {
        block.insert(
            "alpn".to_string(),
            json!(tls
                .alpn
                .iter()
                .map(|alpn| alpn.to_string())
                .collect::<Vec<_>>()),
        );
    }

    if let Some(fingerprint) = &tls.fingerprint {
        block.insert(
            "utls".to_string(),
            json!({ "enabled": true, "fingerprint": fingerprint.to_string() }),
        );
    }

    if let Some(reality) = &tls.reality {
        let mut reality_block = Map::new();
        reality_block.insert("enabled".to_string(), json!(true));
        reality_block.insert("public_key".to_string(), json!(reality.public_key.as_str()));

        if let Some(short_id) = &reality.short_id {
            reality_block.insert("short_id".to_string(), json!(short_id.as_str()));
        }

        block.insert("reality".to_string(), Value::Object(reality_block));
    }

    Value::Object(block)
}

/// The carriage, as sing-box spells it.
///
/// `None` is a carriage sing-box writes by saying nothing at all, or one this
/// build does not model; `Some(Err(..))` is a carriage it cannot express.
fn transport_of(transport: &Transport) -> Option<Result<Value, Reason>> {
    match transport {
        Transport::Tcp => None,
        Transport::Ws(ws) => {
            let mut block = Map::new();
            block.insert("type".to_string(), json!("ws"));
            block.insert("path".to_string(), json!(ws.path.as_ref()));

            if let Some(host) = &ws.host {
                block.insert("headers".to_string(), json!({ "Host": host.to_string() }));
            }
            if let Some(early_data) = ws.early_data {
                block.insert("max_early_data".to_string(), json!(early_data));
            }

            Some(Ok(Value::Object(block)))
        }
        Transport::Grpc(grpc) => {
            let mut block = Map::new();
            block.insert("type".to_string(), json!("grpc"));
            block.insert(
                "service_name".to_string(),
                json!(grpc.service_name.as_ref()),
            );

            if grpc.multi_mode {
                block.insert("permit_without_stream".to_string(), json!(true));
            }

            Some(Ok(Value::Object(block)))
        }
        // sing-box spells HTTP/2 as its `http` carriage.
        Transport::Http2(http2) => {
            let mut block = Map::new();
            block.insert("type".to_string(), json!("http"));

            if let Some(host) = &http2.host {
                block.insert("host".to_string(), json!([host.to_string()]));
            }
            if let Some(path) = &http2.path {
                block.insert("path".to_string(), json!(path.as_ref()));
            }

            Some(Ok(Value::Object(block)))
        }
        Transport::HttpUpgrade(upgrade) => {
            let mut block = Map::new();
            block.insert("type".to_string(), json!("httpupgrade"));
            block.insert("path".to_string(), json!(upgrade.path.as_ref()));

            if let Some(host) = &upgrade.host {
                block.insert("host".to_string(), json!(host.to_string()));
            }

            Some(Ok(Value::Object(block)))
        }
        Transport::Quic(_) => Some(Err(Reason::Transport("quic".to_string()))),
        Transport::Other(other) => Some(Err(Reason::Transport(other.name.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suba_proto::parse_link;

    fn node(link: &str) -> Node<Client> {
        parse_link(link).expect("the fixture parses")
    }

    fn written(tag: &str, link: &str) -> Value {
        outbound(tag, &node(link)).expect("the fixture is expressible")
    }

    #[test]
    fn a_trojan_node_becomes_a_trojan_outbound() {
        let outbound = written(
            "Tokyo",
            "trojan://PASSWORD@example.com:443?sni=www.apple.com#Tokyo",
        );

        assert_eq!(
            outbound,
            json!({
                "type": "trojan",
                "tag": "Tokyo",
                "server": "example.com",
                "server_port": 443,
                "password": "PASSWORD",
                "tls": { "enabled": true, "server_name": "www.apple.com" }
            })
        );
    }

    #[test]
    fn a_shadowsocks_node_becomes_a_shadowsocks_outbound() {
        let outbound = written(
            "SIP002",
            "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080#SIP002",
        );

        assert_eq!(
            outbound,
            json!({
                "type": "shadowsocks",
                "tag": "SIP002",
                "server": "192.0.2.10",
                "server_port": 1080,
                "method": "aes-256-gcm",
                "password": "PASSWORD"
            })
        );
    }

    #[test]
    fn a_shadowsocks_plugin_is_written_the_way_sing_box_spells_it() {
        let outbound = written(
            "Obfs",
            "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#Obfs",
        );

        assert_eq!(outbound["plugin"], json!("obfs-local"));
        assert_eq!(
            outbound["plugin_opts"],
            json!("obfs-local;obfs=http;obfs-host=cdn.example.com")
        );
    }

    #[test]
    fn a_carriage_the_document_understands_is_nested_under_transport() {
        let outbound = written(
            "TrojanWS",
            "trojan://PASSWORD@example.com:443?sni=www.apple.com&type=ws&path=%2Fws&host=cdn.example.com#TrojanWS",
        );

        assert_eq!(
            outbound["transport"],
            json!({ "type": "ws", "path": "/ws", "headers": { "Host": "cdn.example.com" } })
        );
    }

    #[test]
    fn an_insecure_node_says_so_rather_than_being_quietly_verified() {
        let outbound = written(
            "TrojanWS",
            "trojan://P%40SSW0RD%2F%3D@example.com:443?sni=www.apple.com&type=ws&allowInsecure=1#TrojanWS",
        );

        assert_eq!(outbound["tls"]["insecure"], json!(true));
        assert_eq!(outbound["tls"]["server_name"], json!("www.apple.com"));
    }

    /// Plain TCP is what sing-box does when a carriage is not mentioned, so the
    /// document says nothing rather than saying `tcp`.
    #[test]
    fn a_plain_carriage_is_not_mentioned() {
        let outbound = written("Trojan", "trojan://PASSWORD@example.com:443#Trojan");

        assert!(outbound.get("transport").is_none(), "{outbound}");
    }

    #[test]
    fn a_protocol_with_no_outbound_is_refused_by_name() {
        let vless = node(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none#IPv6",
        );

        assert_eq!(outbound("IPv6", &vless), Err(Reason::Protocol(Kind::Vless)));
    }

    #[test]
    fn a_carriage_with_no_representation_is_refused_by_name() {
        let quic = node("trojan://PASSWORD@example.com:443?type=quic&security=tls#Quic");

        assert_eq!(
            outbound("Quic", &quic),
            Err(Reason::Transport("quic".to_string()))
        );
    }

    #[test]
    fn the_document_holds_the_nodes_that_can_be_written_and_names_the_rest() {
        let trojan = node("trojan://PASSWORD@example.com:443?sni=example.com#Trojan");
        let vless = node(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none#IPv6",
        );

        let (body, refused) = client_config(&[("Trojan", &trojan), ("IPv6", &vless)]);

        let document: Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(document["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(document["outbounds"][0]["tag"], json!("Trojan"));
        assert_eq!(
            refused,
            [Refused {
                index: 1,
                reason: Reason::Protocol(Kind::Vless)
            }]
        );
    }

    /// Two nodes with one name are two outbounds, and sing-box has to be able to
    /// tell them apart.
    #[test]
    fn a_name_used_twice_is_disambiguated() {
        let first = node("trojan://PASSWORD@example.com:443?sni=example.com#Tokyo");
        let second = node("trojan://OTHER@example.org:443?sni=example.org#Tokyo");

        let (body, refused) = client_config(&[("Tokyo", &first), ("Tokyo", &second)]);
        let document: Value = serde_json::from_str(&body).expect("valid JSON");
        let tags: Vec<&str> = document["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap())
            .collect();

        assert!(refused.is_empty());
        assert_eq!(tags, ["Tokyo", "Tokyo 2"]);
        assert_ne!(
            document["outbounds"][0]["server"],
            document["outbounds"][1]["server"]
        );
    }

    #[test]
    fn a_node_with_no_name_still_gets_a_tag() {
        let anonymous = node("trojan://PASSWORD@example.com:443?sni=example.com");

        let (body, _) = client_config(&[("", &anonymous)]);
        let document: Value = serde_json::from_str(&body).expect("valid JSON");

        assert_eq!(document["outbounds"][0]["tag"], json!("node-1"));
    }

    /// Whatever this crate says it can write, it writes.
    #[test]
    fn the_capability_list_is_the_truth() {
        let fixtures = [
            "trojan://PASSWORD@example.com:443?sni=example.com#Trojan",
            "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080#SIP002",
            "socks5://doge:letmein@127.0.0.1:1080#LocalSocks",
            "http://doge:letmein@127.0.0.1:8080#LocalHttp",
        ];

        for fixture in fixtures {
            let node = node(fixture);
            assert!(
                PROTOCOLS.contains(&node.protocol.kind()),
                "{fixture} is not in the capability list"
            );
            assert!(outbound("tag", &node).is_ok(), "{fixture} was refused");
        }
    }
}
