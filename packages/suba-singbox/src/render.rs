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

use suba_proto::protocol::vless::Flow;
use suba_proto::{Client, Endpoint, Kind, Node, Outbound, TlsClient, Transport};

/// The protocols this mapping can write.
///
/// The capability list is built from this, and so is every refusal: one table,
/// so what this crate says it can do and what it does cannot drift apart.
///
/// ShadowsocksR is absent on purpose: sing-box deprecated its outbound, and a
/// mapping onto something a released build may refuse to load is worse than
/// saying so.
pub const PROTOCOLS: &[Kind] = &[
    Kind::Vless,
    Kind::Trojan,
    Kind::Shadowsocks,
    Kind::Vmess,
    Kind::Hysteria2,
    Kind::Tuic,
    Kind::AnyTls,
    Kind::Socks,
    Kind::Http,
];

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
    /// A value sing-box has no spelling for.
    Value {
        /// Which field.
        field: &'static str,
        /// What the node said, as it said it. Never a credential: the values
        /// this can be reached with are a flow, an encryption and a port list.
        spelling: String,
    },
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
        Outbound::Vless(client) => {
            outbound.insert("type".to_string(), json!("vless"));
            outbound.insert("uuid".to_string(), json!(client.id.expose().to_string()));

            match client.flow {
                Flow::None => {}
                Flow::XtlsRprxVision => {
                    outbound.insert("flow".to_string(), json!("xtls-rprx-vision"));
                }
                // sing-box carries Reality with Vision and nothing else; the
                // older splice is not expressible.
                other => {
                    return Err(Reason::Value {
                        field: "flow",
                        spelling: other.to_string(),
                    })
                }
            }

            // VLESS is unencrypted by definition in sing-box: a link asking for
            // anything but `none` cannot be carried there.
            if let Some(encryption) = client
                .encryption
                .as_deref()
                .filter(|encryption| !encryption.eq_ignore_ascii_case("none"))
            {
                return Err(Reason::Value {
                    field: "encryption",
                    spelling: encryption.to_string(),
                });
            }
        }
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
        Outbound::Vmess(client) => {
            outbound.insert("type".to_string(), json!("vmess"));
            outbound.insert("uuid".to_string(), json!(client.id.expose().to_string()));
            outbound.insert("security".to_string(), json!(client.security.as_str()));
            outbound.insert("alter_id".to_string(), json!(client.alter_id));
        }
        Outbound::Hysteria2(client) => {
            outbound.insert("type".to_string(), json!("hysteria2"));
            outbound.insert("password".to_string(), json!(client.password.as_str()));

            if let Some(obfs) = &client.obfs {
                outbound.insert(
                    "obfs".to_string(),
                    json!({
                        "type": obfs.to_string(),
                        "password": client
                            .obfs_password
                            .as_ref()
                            .map(|password| password.as_str())
                            .unwrap_or_default(),
                    }),
                );
            }

            if let Some(ports) = &client.ports {
                outbound.insert("server_ports".to_string(), json!(server_ports(ports)?));
            }
            if let Some(hop_interval) = client.hop_interval {
                outbound.insert(
                    "hop_interval".to_string(),
                    json!(format!("{hop_interval}s")),
                );
            }
            if let Some(up) = client.up {
                outbound.insert("up_mbps".to_string(), json!(up));
            }
            if let Some(down) = client.down {
                outbound.insert("down_mbps".to_string(), json!(down));
            }
        }
        Outbound::Tuic(client) => {
            outbound.insert("type".to_string(), json!("tuic"));
            outbound.insert("uuid".to_string(), json!(client.uuid.expose().to_string()));
            outbound.insert("password".to_string(), json!(client.password.as_str()));
            outbound.insert(
                "congestion_control".to_string(),
                json!(client.congestion_control.as_str()),
            );

            if let Some(mode) = client.udp_relay_mode {
                outbound.insert("udp_relay_mode".to_string(), json!(mode.as_str()));
            }
            if client.zero_rtt_handshake {
                outbound.insert("zero_rtt_handshake".to_string(), json!(true));
            }
        }
        Outbound::AnyTls(client) => {
            outbound.insert("type".to_string(), json!("anytls"));
            outbound.insert("password".to_string(), json!(client.password.as_str()));
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

    // Xray's UDP-over-TCP encoding, which the model keeps whole because it does
    // not model it. sing-box spells the same two values, so it is passed on when
    // a link named one and left at sing-box's default when it did not.
    //
    // Only where sing-box has the field: writing it on an outbound that does not
    // accept it makes the whole configuration unloadable, which the released
    // binary points out as `unknown field "packet_encoding"`.
    if matches!(node.protocol.kind(), Kind::Vless | Kind::Vmess) {
        if let Some(encoding) = node.extra.get("packetEncoding") {
            outbound.insert("packet_encoding".to_string(), json!(encoding));
        }
    }

    match node.tls.as_ref() {
        Some(tls) => {
            outbound.insert("tls".to_string(), tls_of(tls, &node.endpoint));
        }
        // A protocol that carries itself is TLS by construction: a link with no
        // TLS parameters describes a node whose certificate check is left at the
        // default, not a node without TLS.
        None if carries_itself(node.protocol.kind()) => {
            outbound.insert("tls".to_string(), json!({ "enabled": true }));
        }
        None => {}
    }

    // The carriage belongs to the protocols that are carried over something.
    // Hysteria2, TUIC and AnyTLS run over QUIC by construction: a link that says
    // `quic` is saying what the protocol already is, and sing-box has no carriage
    // field for them.
    if !carries_itself(node.protocol.kind()) {
        if let Some(carriage) = transport_of(&node.transport) {
            outbound.insert("transport".to_string(), carriage?);
        }
    }

    Ok(Value::Object(outbound))
}

/// Whether the protocol carries itself, over QUIC and TLS by construction.
///
/// It is one property with two consequences: there is nothing to say about the
/// carriage, and there is nothing to say about whether TLS is on.
fn carries_itself(kind: Kind) -> bool {
    matches!(kind, Kind::Hysteria2 | Kind::Tuic | Kind::AnyTls)
}

/// One outbound per node, in the order they are given.
///
/// This is the piece every caller wants: a document someone is served is these
/// values under an `outbounds` key, and a configuration this host runs is these
/// values beside whatever else the user wrote. Nodes this crate cannot express
/// are left out and reported, with the position they had in the input so that a
/// caller can say which one it was.
pub fn outbounds(nodes: &[(&str, &Node<Client>)]) -> (Vec<Value>, Vec<Refused>) {
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

    (outbounds, refused)
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

/// A port list, as sing-box spells it: a list of ranges, with `:` for a range
/// where hysteria writes `-`.
///
/// A single port is written as a one-port range — `3000:3000` — because the
/// released binary refuses `3000` with `bad port range`. The two spellings say
/// the same thing; only one of them loads.
fn server_ports(ports: &str) -> Result<Vec<String>, Reason> {
    let mut written = Vec::new();

    for segment in ports.split(',') {
        let segment = segment.trim();
        let spelled = match segment.split_once('-') {
            Some((from, to)) if is_port(from) && is_port(to) => format!("{from}:{to}"),
            None if is_port(segment) => format!("{segment}:{segment}"),
            _ => {
                return Err(Reason::Value {
                    field: "ports",
                    spelling: ports.to_string(),
                })
            }
        };

        written.push(spelled);
    }

    Ok(written)
}

fn is_port(text: &str) -> bool {
    !text.is_empty()
        && text.chars().all(|digit| digit.is_ascii_digit())
        && text.parse::<u16>().is_ok()
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
    fn a_vless_node_becomes_a_vless_outbound() {
        let outbound = written(
            "Tokyo",
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&spx=%2F&flow=xtls-rprx-vision&type=ws&path=%2Fws&host=cdn.example.com&ed=2048#Tokyo",
        );

        assert_eq!(outbound["type"], json!("vless"));
        assert_eq!(
            outbound["uuid"],
            json!("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(outbound["flow"], json!("xtls-rprx-vision"));
        assert_eq!(outbound["tls"]["server_name"], json!("www.apple.com"));
        assert_eq!(outbound["tls"]["reality"]["short_id"], json!("ab12"));
        assert_eq!(
            outbound["transport"],
            json!({
                "type": "ws",
                "path": "/ws",
                "headers": { "Host": "cdn.example.com" },
                "max_early_data": 2048
            })
        );
    }

    /// The splice flow is not one sing-box carries: refusing beats writing a
    /// node it cannot run.
    #[test]
    fn a_flow_sing_box_cannot_carry_is_refused() {
        let direct = node(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&flow=xtls-rprx-direct#Direct",
        );

        assert_eq!(
            outbound("Direct", &direct),
            Err(Reason::Value {
                field: "flow",
                spelling: "xtls-rprx-direct".to_string()
            })
        );
    }

    #[test]
    fn a_vmess_node_becomes_a_vmess_outbound() {
        let outbound = written(
            "Golden",
            "vmess://eyJ2IjoiMiIsInBzIjoiR29sZGVuIiwiYWRkIjoiZ29sZGVuLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ==",
        );

        assert_eq!(outbound["type"], json!("vmess"));
        assert_eq!(
            outbound["uuid"],
            json!("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(outbound["security"], json!("auto"));
        assert_eq!(outbound["alter_id"], json!(0));
    }

    /// Hysteria spells a port range with a hyphen where sing-box uses a colon,
    /// and spells the list as a list.
    #[test]
    fn a_hysteria2_node_becomes_a_hysteria2_outbound() {
        let outbound = written(
            "Tokyo",
            "hysteria2://letmein@example.com:443?obfs=salamander&obfs-password=obfspw&sni=www.apple.com&mport=1000-2000,3000&up=100&down=200#Tokyo",
        );

        assert_eq!(outbound["type"], json!("hysteria2"));
        assert_eq!(outbound["password"], json!("letmein"));
        assert_eq!(
            outbound["obfs"],
            json!({ "type": "salamander", "password": "obfspw" })
        );
        assert_eq!(outbound["server_ports"], json!(["1000:2000", "3000:3000"]));
        assert_eq!(outbound["up_mbps"], json!(100));
        assert_eq!(outbound["down_mbps"], json!(200));
        assert_eq!(outbound["tls"]["server_name"], json!("www.apple.com"));
    }

    #[test]
    fn a_tuic_node_becomes_a_tuic_outbound() {
        let outbound = written(
            "GoldenTUIC",
            "tuic://11111111-2222-3333-4444-555555555555:letmein@golden.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=www.apple.com#GoldenTUIC",
        );

        assert_eq!(outbound["type"], json!("tuic"));
        assert_eq!(
            outbound["uuid"],
            json!("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(outbound["password"], json!("letmein"));
        assert_eq!(outbound["congestion_control"], json!("bbr"));
        assert_eq!(outbound["udp_relay_mode"], json!("native"));
        assert_eq!(outbound["tls"]["server_name"], json!("www.apple.com"));
    }

    /// AnyTLS is TLS by construction, so a node without TLS parameters is still
    /// a TLS node — not one the document leaves unverified and unexplained.
    #[test]
    fn an_anytls_node_becomes_an_anytls_outbound() {
        let named = written(
            "GoldenAnyTLS",
            "anytls://letmein@golden.example.com:443?sni=www.apple.com#GoldenAnyTLS",
        );

        assert_eq!(named["type"], json!("anytls"));
        assert_eq!(named["password"], json!("letmein"));
        assert_eq!(named["tls"]["enabled"], json!(true));

        let bare = node("anytls://letmein@golden.example.com:443");
        // The parser fills TLS in for a protocol that is TLS by construction;
        // clearing it is what a hand-built node without TLS material looks like.
        let bare = Node { tls: None, ..bare };
        let bare = outbound("bare", &bare).expect("an outbound");
        assert_eq!(bare["tls"], json!({ "enabled": true }));
    }

    #[test]
    fn a_protocol_with_no_outbound_is_refused_by_name() {
        let ssr = node(
            "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM",
        );

        assert_eq!(
            outbound("SSR", &ssr),
            Err(Reason::Protocol(Kind::ShadowsocksR)),
            "sing-box deprecated its shadowsocksr outbound"
        );

        let snell = node("snell://1.2.3.4:443?psk=PSK&version=4#Snell");
        assert_eq!(
            outbound("Snell", &snell),
            Err(Reason::Protocol(Kind::Other)),
            "a protocol the model does not know has no outbound either"
        );
    }

    #[test]
    fn a_carriage_with_no_representation_is_refused_by_name() {
        let quic = node("trojan://PASSWORD@example.com:443?type=quic&security=tls#Quic");

        assert_eq!(
            outbound("Quic", &quic),
            Err(Reason::Transport("quic".to_string()))
        );
    }

    /// A protocol that runs over QUIC says so by being itself: the carriage is
    /// not a field sing-box has for it, and the link's `quic` is not a refusal.
    #[test]
    fn a_protocol_that_carries_itself_needs_no_carriage() {
        let hysteria2 = node("hysteria2://letmein@example.com:443?sni=www.apple.com#Tokyo");

        let outbound = outbound("Tokyo", &hysteria2).expect("an outbound");

        assert!(outbound.get("transport").is_none(), "{outbound}");
        assert_eq!(outbound["tls"]["enabled"], json!(true));
    }

    #[test]
    fn the_walk_writes_the_nodes_that_can_be_written_and_names_the_rest() {
        let trojan = node("trojan://PASSWORD@example.com:443?sni=example.com#Trojan");
        let ssr = node(
            "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM",
        );

        let (outbounds, refused) = outbounds(&[("Trojan", &trojan), ("SSR", &ssr)]);

        assert_eq!(outbounds.len(), 1);
        assert_eq!(outbounds[0]["tag"], json!("Trojan"));
        assert_eq!(
            refused,
            [Refused {
                index: 1,
                reason: Reason::Protocol(Kind::ShadowsocksR)
            }]
        );
    }

    /// Two nodes with one name are two outbounds, and sing-box has to be able to
    /// tell them apart.
    #[test]
    fn a_name_used_twice_is_disambiguated() {
        let first = node("trojan://PASSWORD@example.com:443?sni=example.com#Tokyo");
        let second = node("trojan://OTHER@example.org:443?sni=example.org#Tokyo");

        let (outbounds, refused) = outbounds(&[("Tokyo", &first), ("Tokyo", &second)]);
        let tags: Vec<&str> = outbounds
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap())
            .collect();

        assert!(refused.is_empty());
        assert_eq!(tags, ["Tokyo", "Tokyo 2"]);
        assert_ne!(outbounds[0]["server"], outbounds[1]["server"]);
    }

    #[test]
    fn a_node_with_no_name_still_gets_a_tag() {
        let anonymous = node("trojan://PASSWORD@example.com:443?sni=example.com");

        let (outbounds, _) = outbounds(&[("", &anonymous)]);

        assert_eq!(outbounds[0]["tag"], json!("node-1"));
    }

    /// Whatever this crate says it can write, it writes.
    #[test]
    fn the_capability_list_is_the_truth() {
        let fixtures = [
            "trojan://PASSWORD@example.com:443?sni=example.com#Trojan",
            "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080#SIP002",
            "socks5://doge:letmein@127.0.0.1:1080#LocalSocks",
            "http://doge:letmein@127.0.0.1:8080#LocalHttp",
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none#IPv6",
            "vmess://eyJ2IjoiMiIsInBzIjoiR29sZGVuIiwiYWRkIjoiZ29sZGVuLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ==",
            "hysteria2://letmein@example.com:443?obfs=salamander&sni=www.apple.com#Tokyo",
            "tuic://11111111-2222-3333-4444-555555555555:letmein@golden.example.com:443?congestion_control=bbr#GoldenTUIC",
            "anytls://letmein@golden.example.com:443?sni=www.apple.com#GoldenAnyTLS",
        ];

        let mut kinds = Vec::new();

        for fixture in fixtures {
            let node = node(fixture);
            assert!(
                PROTOCOLS.contains(&node.protocol.kind()),
                "{fixture} is not in the capability list"
            );
            assert!(outbound("tag", &node).is_ok(), "{fixture} was refused");
            kinds.push(node.protocol.kind());
        }

        for kind in PROTOCOLS {
            assert!(
                kinds.contains(kind),
                "{kind} is in the capability list with no fixture proving it"
            );
        }
    }

    /// Hysteria spells a port range with a hyphen, sing-box with a colon, and a
    /// value that is neither is refused rather than passed on as something it is
    /// not.
    #[test]
    fn a_port_list_is_translated_and_a_broken_one_is_refused() {
        assert_eq!(
            server_ports("1000-2000,3000").unwrap(),
            ["1000:2000", "3000:3000"]
        );
        assert_eq!(server_ports("443").unwrap(), ["443:443"]);

        for broken in ["", "1000-", "-2000", "1000:2000", "high", "70000"] {
            assert_eq!(
                server_ports(broken),
                Err(Reason::Value {
                    field: "ports",
                    spelling: broken.to_string()
                }),
                "{broken} is not a port list"
            );
        }
    }
}
