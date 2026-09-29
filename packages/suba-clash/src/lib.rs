//! Nodes as a clash document.
//!
//! clash — and the cores that read its configuration, mihomo among them — spells
//! a node as one flat YAML entry: `name`, `type`, `server`, `port`, a field per
//! credential, TLS spread over the same entry (`tls`, `sni`, `skip-cert-verify`)
//! and the carriage in `network` with an `*-opts` mapping beside it. This crate
//! is the translation, and it is a **pure function** of the nodes: nothing here
//! reads a clock, a file or a socket, so the whole mapping is testable against
//! documents written by hand.
//!
//! What it will not do:
//!
//! * **It refuses what it cannot express**, per node, naming the thing it could
//!   not express — a protocol, a carriage, a value with no clash spelling. A node
//!   left out silently would be a subscription that quietly serves less than the
//!   operator configured.
//! * **It does not invent.** A field clash has and the model does not is left at
//!   clash's own default rather than filled with a guess.
//! * **It does not put a value in a field that means something else.** Mihomo's
//!   `fingerprint` is a certificate pin, not a uTLS profile, so a model
//!   fingerprint is written as `client-fingerprint` where the protocol has one
//!   and **left unsaid** where it does not: the QUIC protocols carry no uTLS in
//!   mihomo's stack, and a bare SOCKS or HTTP proxy has no such field. Dropping
//!   it means the core's own default, which is the only thing there is to run.
//!
//! The document is the part a *collection* owns: the `proxies` list. The rest of
//! a client's configuration — its groups, its rules, its listeners — belongs to
//! whoever runs the client, and a converter that guessed at it would be handing
//! out a configuration nobody asked for.

use std::borrow::Cow;

use saphyr::{Mapping, Scalar, Sequence, Yaml, YamlEmitter};

use suba_proto::protocol::shadowsocks::Plugin;
use suba_proto::protocol::vless::Flow;
use suba_proto::{Client, Kind, Node, Outbound, Transport};

/// The protocols this mapping can write.
///
/// The capability list is built from this, and so is every refusal: one table, so
/// what this crate says it can do and what it does cannot drift apart.
///
/// ShadowsocksR is here, unlike in the sing-box mapping: mihomo still serves it,
/// and the model holds the whole of it — the cipher, the protocol plugin and the
/// obfuscation, each with its parameter — so there is nothing to leave out.
pub const PROTOCOLS: &[Kind] = &[
    Kind::Vless,
    Kind::Trojan,
    Kind::Shadowsocks,
    Kind::ShadowsocksR,
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
    /// The protocol has no proxy type in clash.
    Protocol(Kind),
    /// How the node is carried has no representation.
    Transport(String),
    /// A value clash has no spelling for.
    Value {
        /// Which field.
        field: &'static str,
        /// What the node said, as it said it. Never a credential: the values
        /// this can be reached with are a flow, a cipher name, a plugin and a
        /// transport.
        spelling: String,
    },
}

/// One node as a clash proxy.
///
/// `name` is what the document calls it: what clash refers to it by in a group
/// or a rule.
pub fn proxy(name: &str, node: &Node<Client>) -> Result<Yaml<'static>, Reason> {
    let kind = node.protocol.kind();

    if !PROTOCOLS.contains(&kind) {
        return Err(Reason::Protocol(kind));
    }

    let mut entry = Mapping::new();
    entry.insert(text("name"), text(name));
    entry.insert(text("type"), text(proxy_type(&node.protocol)?));
    entry.insert(text("server"), text(node.endpoint.host.to_string()));
    entry.insert(text("port"), count(i64::from(node.endpoint.port.get())));

    match &node.protocol {
        Outbound::Vless(client) => {
            entry.insert(text("uuid"), text(client.id.expose().to_string()));

            match client.flow {
                Flow::None => {}
                Flow::XtlsRprxVision => {
                    entry.insert(text("flow"), text("xtls-rprx-vision"));
                }
                // Mihomo carries the Reality flow and nothing else — any other
                // is refused with `unsupported xtls flow type` — so a node that
                // asks for one is refused here rather than written as something
                // it would not run.
                other => {
                    return Err(Reason::Value {
                        field: "flow",
                        spelling: other.to_string(),
                    })
                }
            }

            // Xray's VLESS encryption, which mihomo parses with the same
            // spellings. `none` is what the core does anyway, so it is left out
            // rather than said twice.
            if let Some(encryption) = client
                .encryption
                .as_deref()
                .filter(|encryption| !encryption.eq_ignore_ascii_case("none"))
            {
                entry.insert(text("encryption"), text(encryption));
            }
        }
        Outbound::Trojan(client) => {
            entry.insert(text("password"), text(client.password.as_str()));
        }
        Outbound::Shadowsocks(client) => {
            entry.insert(text("cipher"), text(client.method.as_ref()));
            entry.insert(text("password"), text(client.password.as_str()));

            if let Some(plugin) = &client.plugin {
                // A link spells the plugin and its options as one string; clash
                // has a name and a mapping of the plugin's own keys.
                entry.insert(text("plugin"), text(plugin_name(&plugin.name)?));
                entry.insert(text("plugin-opts"), plugin_opts(plugin)?);
            }
        }
        Outbound::ShadowsocksR(client) => {
            entry.insert(text("cipher"), text(client.method.as_ref()));
            entry.insert(text("password"), text(client.password.as_str()));
            entry.insert(text("protocol"), text(client.protocol.as_ref()));
            entry.insert(text("obfs"), text(client.obfs.as_ref()));

            // Both are optional in the dialect and empty when a link did not set
            // them, which is exactly clash's own default.
            if !client.protocol_param.is_empty() {
                entry.insert(text("protocol-param"), text(client.protocol_param.as_ref()));
            }
            if !client.obfs_param.is_empty() {
                entry.insert(text("obfs-param"), text(client.obfs_param.as_ref()));
            }
        }
        Outbound::Vmess(client) => {
            entry.insert(text("uuid"), text(client.id.expose().to_string()));
            entry.insert(text("alterId"), count(i64::from(client.alter_id)));
            entry.insert(text("cipher"), text(client.security.as_str()));
        }
        Outbound::Hysteria2(client) => {
            entry.insert(text("password"), text(client.password.as_str()));

            if let Some(obfs) = &client.obfs {
                // Mihomo refuses a configuration whose obfuscation has no
                // password (`missing obfs password`), so a node that names one
                // without the other is refused here.
                let password = client.obfs_password.as_ref().ok_or_else(|| Reason::Value {
                    field: "obfs-password",
                    spelling: obfs.to_string(),
                })?;

                entry.insert(text("obfs"), text(obfs.to_string()));
                entry.insert(text("obfs-password"), text(password.as_str()));
            }

            // A port list and a hop interval in the same spellings, seconds for
            // the interval.
            if let Some(ports) = &client.ports {
                entry.insert(text("ports"), text(ports.as_ref()));
            }
            if let Some(hop_interval) = client.hop_interval {
                entry.insert(text("hop-interval"), text(hop_interval.to_string()));
            }

            // The model holds Mbps, which is `up`'s unit when none is written;
            // it is written out so that the number is read the way the model
            // means it whatever the core's default is.
            if let Some(up) = client.up {
                entry.insert(text("up"), text(format!("{up} Mbps")));
            }
            if let Some(down) = client.down {
                entry.insert(text("down"), text(format!("{down} Mbps")));
            }
        }
        Outbound::Tuic(client) => {
            entry.insert(text("uuid"), text(client.uuid.expose().to_string()));
            entry.insert(text("password"), text(client.password.as_str()));
            entry.insert(
                text("congestion-controller"),
                text(client.congestion_control.as_str()),
            );

            if let Some(mode) = client.udp_relay_mode {
                entry.insert(text("udp-relay-mode"), text(mode.as_str()));
            }
            // The same setting as sing-box's `zero_rtt_handshake`: a handshake
            // that may be skipped on a reconnection.
            if client.zero_rtt_handshake {
                entry.insert(text("reduce-rtt"), flag(true));
            }
        }
        Outbound::AnyTls(client) => {
            entry.insert(text("password"), text(client.password.as_str()));
        }
        Outbound::Socks(client) => {
            if let Some(username) = &client.username {
                entry.insert(text("username"), text(username.as_ref()));
            }
            if let Some(password) = &client.password {
                entry.insert(text("password"), text(password.as_str()));
            }
        }
        Outbound::Http(client) => {
            if let Some(username) = &client.username {
                entry.insert(text("username"), text(username.as_ref()));
            }
            if let Some(password) = &client.password {
                entry.insert(text("password"), text(password.as_str()));
            }
        }
        // Refused above: the table and this match are checked against each other
        // by the fixture test below.
        other => return Err(Reason::Protocol(other.kind())),
    }

    // Xray's UDP-over-TCP encoding, which the model keeps whole because it does
    // not model it. Mihomo spells the same two values and has the field on
    // exactly these two proxies — writing it anywhere else would be a field no
    // proxy type has.
    if matches!(kind, Kind::Vless | Kind::Vmess) {
        if let Some(encoding) = node.extra.get("packetEncoding") {
            entry.insert(text("packet-encoding"), text(encoding));
        }
    }

    for (key, value) in carriage(kind, &node.transport)? {
        entry.insert(text(key), value);
    }

    tls_fields(&mut entry, kind, node)?;

    Ok(Yaml::Mapping(entry))
}

/// A proxies document: one entry per node, in the order they are given.
///
/// Nodes this crate cannot express are left out and reported, with the position
/// they had in the input so that a caller can say which one it was.
pub fn client_config(nodes: &[(&str, &Node<Client>)]) -> (String, Vec<Refused>) {
    let mut proxies = Sequence::new();
    let mut refused = Vec::new();
    let mut names: Vec<String> = Vec::new();

    for (index, (name, node)) in nodes.iter().enumerate() {
        let name = unique_name(name, index, &mut names);

        match proxy(&name, node) {
            Ok(entry) => proxies.push(entry),
            Err(reason) => refused.push(Refused { index, reason }),
        }
    }

    let mut document = Mapping::new();
    document.insert(text("proxies"), Yaml::Sequence(proxies));

    (emit(&Yaml::Mapping(document)), refused)
}

/// The type clash spells this protocol with.
fn proxy_type(protocol: &Outbound) -> Result<&'static str, Reason> {
    Ok(match protocol {
        Outbound::Vless(_) => "vless",
        Outbound::Trojan(_) => "trojan",
        Outbound::Shadowsocks(_) => "ss",
        Outbound::ShadowsocksR(_) => "ssr",
        Outbound::Vmess(_) => "vmess",
        Outbound::Hysteria2(_) => "hysteria2",
        Outbound::Tuic(_) => "tuic",
        Outbound::AnyTls(_) => "anytls",
        // There is one SOCKS proxy type and it speaks SOCKS5; the model's
        // SOCKS4 node has nothing to be written as.
        Outbound::Socks(client) if client.version.as_str() == "5" => "socks5",
        Outbound::Socks(_) => {
            return Err(Reason::Value {
                field: "version",
                spelling: "4".to_string(),
            })
        }
        Outbound::Http(_) => "http",
        other => return Err(Reason::Protocol(other.kind())),
    })
}

/// Whether the protocol carries itself, over QUIC by construction.
///
/// It is one property with two consequences: there is nothing to say about the
/// carriage, and the core needs no field to know TLS is on.
fn carries_itself(kind: Kind) -> bool {
    matches!(kind, Kind::Hysteria2 | Kind::Tuic | Kind::AnyTls)
}

/// The carriage, as clash spells it: `network` and an `*-opts` mapping beside
/// it, or nothing at all for the carriage a core assumes when none is written.
fn carriage(
    kind: Kind,
    transport: &Transport,
) -> Result<Vec<(&'static str, Yaml<'static>)>, Reason> {
    let carried = matches!(kind, Kind::Vless | Kind::Vmess | Kind::Trojan);

    match transport {
        Transport::Tcp => Ok(Vec::new()),
        // A link that says `quic` for a protocol that *is* QUIC is saying what
        // it already is, and mihomo has no carriage field for those types.
        Transport::Quic(_) if carries_itself(kind) => Ok(Vec::new()),
        // Everything else is carried over something: the protocols that are not
        // have no field to write a carriage into, and writing nothing would hand
        // out a node that is not the one the provider served.
        _ if !carried => Err(Reason::Transport(transport.name().to_string())),
        Transport::Ws(ws) => {
            let mut opts = Mapping::new();
            opts.insert(text("path"), text(ws.path.as_ref()));

            if let Some(host) = &ws.host {
                opts.insert(text("headers"), Yaml::Mapping(headers_of("Host", host)));
            }
            if let Some(early_data) = ws.early_data {
                opts.insert(text("max-early-data"), count(i64::from(early_data)));
            }

            Ok(vec![
                ("network", text("ws")),
                ("ws-opts", Yaml::Mapping(opts)),
            ])
        }
        // Xray's HTTP upgrade is the WebSocket carriage with the upgrade header,
        // which is how mihomo spells it: the same wire, one field away.
        Transport::HttpUpgrade(upgrade) => {
            let mut opts = Mapping::new();
            opts.insert(text("path"), text(upgrade.path.as_ref()));
            opts.insert(text("v2ray-http-upgrade"), flag(true));

            if let Some(host) = &upgrade.host {
                opts.insert(text("headers"), Yaml::Mapping(headers_of("Host", host)));
            }

            Ok(vec![
                ("network", text("ws")),
                ("ws-opts", Yaml::Mapping(opts)),
            ])
        }
        Transport::Grpc(grpc) => {
            let mut opts = Mapping::new();
            opts.insert(text("grpc-service-name"), text(grpc.service_name.as_ref()));

            // `multi` is Xray's stream-permission hint and has no clash field;
            // the core's own default is what is left, not a guess at it.

            Ok(vec![
                ("network", text("grpc")),
                ("grpc-opts", Yaml::Mapping(opts)),
            ])
        }
        // Every protocol here carries HTTP/2 over the same stream, except the one
        // core that does not: mihomo's trojan reads `ws` and `grpc` and treats
        // anything else as plain TCP, so an HTTP/2 trojan node is refused rather
        // than handed over as a node that is quietly not the one asked for.
        Transport::Http2(http2) if matches!(kind, Kind::Vless | Kind::Vmess) => {
            let mut opts = Mapping::new();

            if let Some(host) = &http2.host {
                opts.insert(text("host"), Yaml::Sequence(vec![text(host.to_string())]));
            }
            if let Some(path) = &http2.path {
                opts.insert(text("path"), text(path.as_ref()));
            }

            Ok(vec![
                ("network", text("h2")),
                ("h2-opts", Yaml::Mapping(opts)),
            ])
        }
        Transport::Http2(_) => Err(Reason::Transport("h2".to_string())),
        Transport::Quic(_) => Err(Reason::Transport("quic".to_string())),
        Transport::Other(other) => Err(Reason::Transport(other.name.to_string())),
    }
}

/// One request header, which is how clash spells the Host a WebSocket asked for.
fn headers_of(name: &str, value: impl ToString) -> Mapping<'static> {
    let mut headers = Mapping::new();
    headers.insert(text(name), text(value.to_string()));

    headers
}

/// The TLS fields, written into the proxy they belong to.
///
/// Every client here spells TLS its own way: VLESS and VMess say `tls: true` and
/// name the certificate `servername`, Trojan is TLS by construction and says
/// `sni`, a plain SOCKS proxy can be wrapped but has no name field of its own.
/// One node, one client, so the difference is a table rather than a branch per
/// protocol.
fn tls_fields(entry: &mut Mapping<'static>, kind: Kind, node: &Node<Client>) -> Result<(), Reason> {
    let Some(tls) = node.tls.as_ref() else {
        // A protocol that is TLS by construction needs no field to say so, and a
        // node of a protocol that can be either is exactly what it looks like:
        // plain.
        return Ok(());
    };

    // Whether the client needs to be told TLS is on, which key its name goes
    // under, whether it imitates a browser, and whether Reality is one of the
    // ways it authenticates.
    let (enables, name_key, fingerprint, supports_reality) = match kind {
        Kind::Vless | Kind::Vmess => (true, Some("servername"), true, true),
        Kind::Trojan => (false, Some("sni"), true, true),
        // Mihomo does not support AnyTLS with Reality and says it will not.
        Kind::AnyTls => (false, Some("sni"), true, false),
        Kind::Hysteria2 | Kind::Tuic => (false, Some("sni"), false, false),
        Kind::Http => (true, Some("sni"), false, false),
        // A SOCKS proxy verifies against the address it dials and has no field
        // for another name, which is the same default the model has.
        Kind::Socks => (true, None, false, false),
        // A proxy with no TLS of its own: writing the entry without it would
        // hand out a node that does not use the TLS the provider asked for.
        other => {
            return Err(Reason::Value {
                field: "tls",
                spelling: other.to_string(),
            })
        }
    };

    if enables {
        entry.insert(text("tls"), flag(true));
    }

    if let (Some(key), Some(name)) = (name_key, tls.server_name.as_ref()) {
        entry.insert(text(key), text(name.to_string()));
    }
    if tls.insecure {
        entry.insert(text("skip-cert-verify"), flag(true));
    }
    if !tls.alpn.is_empty() {
        entry.insert(
            text("alpn"),
            texts(tls.alpn.iter().map(|alpn| alpn.as_str())),
        );
    }

    if let Some(profile) = &tls.fingerprint {
        if fingerprint {
            entry.insert(text("client-fingerprint"), text(profile.as_str()));
        }
        // Elsewhere the core has no uTLS to imitate with, and its `fingerprint`
        // is a certificate pin — a different thing, which a profile name would
        // make a node that cannot connect. Left unsaid, it is the core's default.
    }

    if let Some(reality) = &tls.reality {
        if !supports_reality {
            return Err(Reason::Value {
                field: "reality",
                spelling: kind.to_string(),
            });
        }

        let mut block = Mapping::new();
        block.insert(text("public-key"), text(reality.public_key.as_str()));

        if let Some(short_id) = &reality.short_id {
            block.insert(text("short-id"), text(short_id.as_str()));
        }

        entry.insert(text("reality-opts"), Yaml::Mapping(block));
    }

    Ok(())
}

/// The plugin's name, as clash spells it.
///
/// SIP002 names simple-obfs in both of its spellings and everything else the way
/// clash does; a plugin clash does not have (`shadow-tls`, `kcptun`) is refused
/// rather than written under its link name, because the two do not agree about
/// what the options are called either.
fn plugin_name(name: &str) -> Result<&'static str, Reason> {
    Ok(match name {
        "obfs-local" | "simple-obfs" => "obfs",
        "v2ray-plugin" => "v2ray-plugin",
        other => {
            return Err(Reason::Value {
                field: "plugin",
                spelling: other.to_string(),
            })
        }
    })
}

/// The plugin's options, as clash spells them: a mapping of the plugin's own
/// keys, where a link has one semicolon-separated string.
fn plugin_opts(plugin: &Plugin) -> Result<Yaml<'static>, Reason> {
    let mut opts = Mapping::new();

    match plugin_name(&plugin.name)? {
        // Simple-obfs calls the mode and the host by the plugin's own names,
        // where clash says `mode` and `host`.
        "obfs" => {
            if let Some(mode) = plugin.get("obfs") {
                opts.insert(text("mode"), text(mode));
            }
            if let Some(host) = plugin.get("obfs-host") {
                opts.insert(text("host"), text(host));
            }
        }
        // v2ray-plugin's options are spelled the same on both sides.
        _ => {
            for (key, value) in &plugin.options {
                match key.as_ref() {
                    "mode" | "host" | "path" => {
                        opts.insert(text(key.as_ref()), text(value.as_ref()));
                    }
                    // A flag the link writes bare when it wants TLS.
                    "tls" => {
                        opts.insert(text("tls"), flag(true));
                    }
                    // Anything else the link asked for has no clash spelling and
                    // is left at the plugin's own default.
                    _ => {}
                }
            }
        }
    }

    Ok(Yaml::Mapping(opts))
}

/// The name for one node.
///
/// clash identifies a proxy by its name and refuses a configuration with two of
/// the same, so a name used twice is disambiguated here rather than handed over
/// as a document that will not load. The name is otherwise kept as the provider
/// spelled it: an operator finds their nodes by that name.
fn unique_name(name: &str, index: usize, taken: &mut Vec<String>) -> String {
    let base = match name.is_empty() {
        true => format!("node-{}", index + 1),
        false => name.to_string(),
    };

    let mut unique = base.clone();
    let mut suffix = 2;

    while taken.contains(&unique) {
        unique = format!("{base} {suffix}");
        suffix += 1;
    }

    taken.push(unique.clone());

    unique
}

/// The document as text, ending in a newline.
fn emit(document: &Yaml<'_>) -> String {
    let mut body = String::new();
    let mut emitter = YamlEmitter::new(&mut body);

    // The value is built here, so a failure would be this crate's bug rather
    // than something a caller could act on.
    emitter
        .dump(document)
        .expect("the document this crate built");

    if !body.ends_with('\n') {
        body.push('\n');
    }

    body
}

/// A string value, in the spelling YAML needs to read it back as that string.
///
/// The quoting and the escaping are the emitter's: it writes a bare scalar only
/// when reading it back yields the same string, so a password that looks like a
/// number, a name with a colon in it and a value with a newline in it all survive
/// whatever they contain.
fn text(value: impl Into<String>) -> Yaml<'static> {
    Yaml::Value(Scalar::String(Cow::Owned(value.into())))
}

fn flag(value: bool) -> Yaml<'static> {
    Yaml::Value(Scalar::Boolean(value))
}

fn count(value: i64) -> Yaml<'static> {
    Yaml::Value(Scalar::Integer(value))
}

fn texts<'a>(values: impl IntoIterator<Item = &'a str>) -> Yaml<'static> {
    Yaml::Sequence(values.into_iter().map(text).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use saphyr::LoadableYamlNode;
    use suba_proto::parse_link;

    fn node(link: &str) -> Node<Client> {
        parse_link(link).expect("the fixture parses")
    }

    /// One entry as the document writes it. The field names in this text are the
    /// contract: they are what a core reads, so they are what the tests pin.
    fn written(name: &str, link: &str) -> String {
        emit(&proxy(name, &node(link)).expect("the fixture is expressible"))
    }

    /// A document, parsed and written again. A value that did not survive the
    /// first trip comes back different, or does not come back at all.
    fn reread(body: &str) -> String {
        let documents = Yaml::load_from_str(body).expect("a YAML document");
        assert_eq!(documents.len(), 1, "one document, not many");

        emit(&documents[0])
    }

    /// The shapes providers actually serve, from the protocol crate's own
    /// fixture file. One list, held by both crates: a shape this dialect cannot
    /// write is a shape that crate cannot read either.
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

    #[test]
    fn a_trojan_node_becomes_a_trojan_proxy() {
        assert_eq!(
            written(
                "Tokyo",
                "trojan://PASSWORD@example.com:443?sni=www.apple.com&allowInsecure=1#Tokyo"
            ),
            "\
---
name: Tokyo
type: trojan
server: example.com
port: 443
password: PASSWORD
sni: www.apple.com
skip-cert-verify: true
"
        );
    }

    /// Everything a Reality node is at once: the carriage it is carried over, the
    /// certificate it checks, the client it imitates and the identity it proves.
    #[test]
    fn a_vless_node_becomes_a_vless_proxy() {
        assert_eq!(
            written(
                "Tokyo",
                "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&spx=%2F&flow=xtls-rprx-vision&type=ws&path=%2Fws&host=cdn.example.com&ed=2048#Tokyo"
            ),
            "\
---
name: Tokyo
type: vless
server: example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
flow: xtls-rprx-vision
network: ws
ws-opts:
  path: /ws
  headers:
    Host: cdn.example.com
  max-early-data: 2048
tls: true
servername: www.apple.com
client-fingerprint: chrome
reality-opts:
  public-key: PUBKEY
  short-id: ab12
"
        );
    }

    /// The flow mihomo carries, and nothing else: an older splice is refused
    /// rather than written as something the core would not run.
    #[test]
    fn a_flow_the_core_cannot_carry_is_refused() {
        let direct = node(
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=tls&flow=xtls-rprx-direct#Direct",
        );

        assert_eq!(
            proxy("Direct", &direct),
            Err(Reason::Value {
                field: "flow",
                spelling: "xtls-rprx-direct".to_string()
            })
        );
    }

    #[test]
    fn a_vmess_node_becomes_a_vmess_proxy() {
        assert_eq!(
            written(
                "Golden",
                "vmess://eyJ2IjoiMiIsInBzIjoiR29sZGVuIiwiYWRkIjoiZ29sZGVuLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ=="
            ),
            "\
---
name: Golden
type: vmess
server: golden.example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
alterId: 0
cipher: auto
network: ws
ws-opts:
  path: /ws
tls: true
servername: golden.example.com
"
        );
    }

    #[test]
    fn a_shadowsocks_node_becomes_an_ss_proxy() {
        assert_eq!(
            written(
                "SIP002",
                "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080#SIP002"
            ),
            "\
---
name: SIP002
type: ss
server: 192.0.2.10
port: 1080
cipher: aes-256-gcm
password: PASSWORD
"
        );
    }

    /// The plugin is one semicolon-separated string on the way in and a name
    /// plus a mapping of the plugin's own keys on the way out.
    #[test]
    fn a_shadowsocks_plugin_becomes_plugin_options() {
        assert_eq!(
            written(
                "Obfs",
                "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#Obfs"
            ),
            "\
---
name: Obfs
type: ss
server: 192.0.2.10
port: 1080
cipher: aes-256-gcm
password: PASSWORD
plugin: obfs
plugin-opts:
  mode: http
  host: cdn.example.com
"
        );
    }

    /// v2ray-plugin's options are spelled the same on both sides, so the keys are
    /// passed on as they are — including the flag the link writes bare.
    #[test]
    fn a_v2ray_plugin_is_written_key_by_key() {
        assert_eq!(
            written(
                "V2Ray",
                "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fws%3Btls#V2Ray"
            ),
            "\
---
name: V2Ray
type: ss
server: 192.0.2.10
port: 1080
cipher: aes-256-gcm
password: PASSWORD
plugin: v2ray-plugin
plugin-opts:
  mode: websocket
  host: cdn.example.com
  path: /ws
  tls: true
"
        );
    }

    /// A plugin whose options clash calls something else entirely is refused
    /// rather than written under the name the link used.
    #[test]
    fn a_plugin_the_core_does_not_have_is_refused_by_name() {
        let shadow = node(
            "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080?plugin=shadow-tls%3Bpassword%3Dx#Shadow",
        );

        assert_eq!(
            proxy("Shadow", &shadow),
            Err(Reason::Value {
                field: "plugin",
                spelling: "shadow-tls".to_string()
            })
        );
    }

    /// ShadowsocksR is a proxy type here, and the model holds every part of it.
    #[test]
    fn a_shadowsocksr_node_becomes_an_ssr_proxy() {
        assert_eq!(
            written(
                "SSR",
                "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM"
            ),
            "\
---
name: SSR
type: ssr
server: golden.example.com
port: 443
cipher: aes-256-cfb
password: letmein
protocol: auth_sha1_v4
obfs: http_simple
"
        );
    }

    /// A port list, a hop interval and the rates, in the spellings the core
    /// reads: the interval in seconds as a string, the rates in Mbps.
    #[test]
    fn a_hysteria2_node_becomes_a_hysteria2_proxy() {
        assert_eq!(
            written(
                "Tokyo",
                "hysteria2://letmein@example.com:443?obfs=salamander&obfs-password=obfspw&sni=www.apple.com&mport=1000-2000,3000&up=100&down=200#Tokyo"
            ),
            "\
---
name: Tokyo
type: hysteria2
server: example.com
port: 443
password: letmein
obfs: salamander
obfs-password: obfspw
ports: \"1000-2000,3000\"
up: 100 Mbps
down: 200 Mbps
sni: www.apple.com
"
        );
    }

    /// The core refuses a configuration whose obfuscation has no password, so a
    /// node that names one without the other is refused here.
    #[test]
    fn an_obfuscation_without_its_password_is_refused() {
        let obfs =
            node("hysteria2://letmein@example.com:443?obfs=salamander&sni=www.apple.com#Tokyo");

        assert_eq!(
            proxy("Tokyo", &obfs),
            Err(Reason::Value {
                field: "obfs-password",
                spelling: "salamander".to_string()
            })
        );
    }

    #[test]
    fn a_tuic_node_becomes_a_tuic_proxy() {
        assert_eq!(
            written(
                "GoldenTUIC",
                "tuic://11111111-2222-3333-4444-555555555555:letmein@golden.example.com:443?congestion_control=bbr&udp_relay_mode=native&zero_rtt=1&sni=www.apple.com#GoldenTUIC"
            ),
            "\
---
name: GoldenTUIC
type: tuic
server: golden.example.com
port: 443
uuid: 11111111-2222-3333-4444-555555555555
password: letmein
congestion-controller: bbr
udp-relay-mode: native
reduce-rtt: true
sni: www.apple.com
"
        );
    }

    /// AnyTLS imitates a browser, so the model's fingerprint has a field here.
    #[test]
    fn an_anytls_node_becomes_an_anytls_proxy() {
        assert_eq!(
            written(
                "GoldenAnyTLS",
                "anytls://letmein@golden.example.com:443?sni=www.apple.com&fp=firefox#GoldenAnyTLS"
            ),
            "\
---
name: GoldenAnyTLS
type: anytls
server: golden.example.com
port: 443
password: letmein
sni: www.apple.com
client-fingerprint: firefox
"
        );
    }

    /// Mihomo does not support AnyTLS with Reality and says it will not, so the
    /// node has no representation rather than a degraded one.
    #[test]
    fn an_anytls_node_asking_for_reality_is_refused() {
        let anytls = node("anytls://letmein@golden.example.com:443?sni=www.apple.com#GoldenAnyTLS");
        let reality = suba_proto::tls::RealityClient {
            public_key: "PUBKEY".into(),
            short_id: None,
            spider_x: None,
        };
        let tls = suba_proto::TlsClient {
            reality: Some(reality),
            ..anytls.tls.clone().expect("anytls is a TLS protocol")
        };
        let with_reality = Node {
            tls: Some(tls),
            ..anytls
        };

        assert_eq!(
            proxy("Reality", &with_reality),
            Err(Reason::Value {
                field: "reality",
                spelling: "anytls".to_string()
            })
        );
    }

    #[test]
    fn a_socks_node_becomes_a_socks5_proxy() {
        assert_eq!(
            written(
                "LocalSocks",
                "socks5://doge:letmein@127.0.0.1:1080#LocalSocks"
            ),
            "\
---
name: LocalSocks
type: socks5
server: 127.0.0.1
port: 1080
username: doge
password: letmein
"
        );
    }

    /// There is one SOCKS proxy type and it speaks SOCKS5.
    #[test]
    fn a_socks_4_node_has_nothing_to_be_written_as() {
        let local = node("socks4://127.0.0.1:1080#Local");

        assert_eq!(
            proxy("Local", &local),
            Err(Reason::Value {
                field: "version",
                spelling: "4".to_string()
            })
        );
    }

    #[test]
    fn an_http_node_becomes_an_http_proxy() {
        assert_eq!(
            written("LocalHttp", "http://doge:letmein@127.0.0.1:8080#LocalHttp"),
            "\
---
name: LocalHttp
type: http
server: 127.0.0.1
port: 8080
username: doge
password: letmein
"
        );
    }

    /// A carriage the proxy type has a field for: `network` and the options that
    /// belong to it.
    #[test]
    fn a_carriage_the_proxy_type_carries_is_written() {
        assert_eq!(
            written(
                "TrojanGRPC",
                "trojan://PASSWORD@example.com:443?sni=example.com&type=grpc&serviceName=proxy#TrojanGRPC"
            ),
            "\
---
name: TrojanGRPC
type: trojan
server: example.com
port: 443
password: PASSWORD
network: grpc
grpc-opts:
  grpc-service-name: proxy
sni: example.com
"
        );
    }

    /// Xray's HTTP upgrade is the WebSocket carriage with the upgrade header,
    /// which is how the core spells it: the same wire, one field away.
    #[test]
    fn an_http_upgrade_is_written_as_the_websocket_it_is() {
        assert_eq!(
            written(
                "GoldenUpgrade",
                "trojan://letmein@golden.example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.com&sni=golden.example.com#GoldenUpgrade"
            ),
            "\
---
name: GoldenUpgrade
type: trojan
server: golden.example.com
port: 443
password: letmein
network: ws
ws-opts:
  path: /up
  v2ray-http-upgrade: true
  headers:
    Host: cdn.example.com
sni: golden.example.com
"
        );
    }

    /// HTTP/2 is a carriage VLESS and VMess have and trojan does not: the core
    /// would read the field and dial plain TCP, so the node is refused instead.
    #[test]
    fn an_http_2_trojan_is_refused_while_an_http_2_vless_is_written() {
        assert_eq!(
            written(
                "H2",
                "vless://11111111-2222-3333-4444-555555555555@example.com:8443?security=tls&sni=example.com&alpn=h2,http%2F1.1&type=h2&host=cdn.example.com&path=%2Fh2#H2"
            ),
            "\
---
name: H2
type: vless
server: example.com
port: 8443
uuid: 11111111-2222-3333-4444-555555555555
network: h2
h2-opts:
  host:
    - cdn.example.com
  path: /h2
tls: true
servername: example.com
alpn:
  - h2
  - http/1.1
"
        );

        let trojan = node(
            "trojan://PASSWORD@example.com:443?sni=example.com&type=h2&host=cdn.example.com&path=%2Fh2#TrojanH2",
        );

        assert_eq!(
            proxy("TrojanH2", &trojan),
            Err(Reason::Transport("h2".to_string()))
        );
    }

    /// A proxy type with no carriage field at all: writing the entry without the
    /// carriage would hand out a node that is not the one the provider served.
    #[test]
    fn a_carriage_the_proxy_type_has_no_field_for_is_refused_by_name() {
        let websocket =
            node("ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080?type=ws&path=%2Fws#Ws");

        assert_eq!(
            proxy("Ws", &websocket),
            Err(Reason::Transport("ws".to_string()))
        );
    }

    /// A protocol that runs over QUIC says so by being itself: the carriage is
    /// not a field the core has for it, and the link's `quic` is not a refusal.
    #[test]
    fn a_protocol_that_carries_itself_needs_no_carriage() {
        let hysteria2 = node("hysteria2://letmein@example.com:443?sni=www.apple.com#Tokyo");
        let entry = written(
            "Tokyo",
            "hysteria2://letmein@example.com:443?sni=www.apple.com#Tokyo",
        );

        assert!(!entry.contains("network"), "{entry}");
        assert!(proxy("Tokyo", &hysteria2).is_ok());

        let quic = node("trojan://PASSWORD@example.com:443?type=quic&security=tls#Quic");

        assert_eq!(
            proxy("Quic", &quic),
            Err(Reason::Transport("quic".to_string()))
        );
    }

    #[test]
    fn a_protocol_with_no_proxy_type_is_refused_by_name() {
        let snell = node("snell://1.2.3.4:443?psk=PSK&version=4#Snell");

        assert_eq!(
            proxy("Snell", &snell),
            Err(Reason::Protocol(Kind::Other)),
            "a protocol the model does not know has no proxy type either"
        );
    }

    /// The test the whole table hangs on: every fixture either becomes a proxy or
    /// is refused with the name of the thing that stopped it, never left out
    /// quietly.
    #[test]
    fn every_fixture_is_written_or_refused_by_name() {
        let fixtures = links();
        let mut written = 0;
        let mut refused = Vec::new();

        for link in &fixtures {
            let node = node(link);

            match proxy("fixture", &node) {
                Ok(_) => written += 1,
                Err(reason) => refused.push((node.protocol.kind(), reason)),
            }
        }

        assert_eq!(
            refused,
            [
                (Kind::Trojan, Reason::Transport("h2".to_string())),
                (Kind::Other, Reason::Protocol(Kind::Other)),
                (Kind::Other, Reason::Protocol(Kind::Other)),
            ],
            "the shapes providers serve that this dialect cannot write"
        );
        assert_eq!(written + refused.len(), fixtures.len());
    }

    /// What this crate wrote, a core can read: parsed back and written again, the
    /// document is the same text, down to which scalars needed quoting.
    #[test]
    fn the_document_reads_back_as_it_was_written() {
        let nodes: Vec<Node<Client>> = links().iter().map(|link| node(link)).collect();
        let named: Vec<(&str, &Node<Client>)> = nodes
            .iter()
            .map(|node| (node.name.as_str(), node))
            .collect();

        let (body, refused) = client_config(&named);

        assert_eq!(refused.len(), 3, "the three fixtures with no proxy type");
        assert_eq!(reread(&body), body);

        // Nothing else is in the document: the entries are the collection's, the
        // rest of a client's configuration is not.
        assert!(body.starts_with("---\nproxies:\n"), "{body}");
    }

    /// A document of what can be written, and a reason per node that cannot.
    #[test]
    fn the_document_holds_the_nodes_that_can_be_written_and_names_the_rest() {
        let trojan = node("trojan://PASSWORD@example.com:443?sni=example.com#Trojan");
        let snell = node("snell://1.2.3.4:443?psk=PSK&version=4#Snell");
        let ssr = node(
            "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM",
        );

        let (body, refused) =
            client_config(&[("Trojan", &trojan), ("Snell", &snell), ("SSR", &ssr)]);

        assert_eq!(
            refused,
            [Refused {
                index: 1,
                reason: Reason::Protocol(Kind::Other)
            }]
        );
        assert_eq!(body.matches("\n  - name: ").count(), 2, "{body}");
        assert!(body.contains("\n  - name: Trojan\n"), "{body}");
        assert!(body.contains("\n  - name: SSR\n"), "{body}");
    }

    /// Two nodes with one name are two proxies, and clash has to be able to tell
    /// them apart.
    #[test]
    fn a_name_used_twice_is_disambiguated() {
        let first = node("trojan://PASSWORD@example.com:443?sni=example.com#Tokyo");
        let second = node("trojan://OTHER@example.org:443?sni=example.org#Tokyo");

        let (body, refused) = client_config(&[("Tokyo", &first), ("Tokyo", &second)]);

        assert!(refused.is_empty());
        assert!(body.contains("\n  - name: Tokyo\n"), "{body}");
        assert!(body.contains("\n  - name: Tokyo 2\n"), "{body}");
        assert!(body.contains("server: example.org"), "{body}");
    }

    #[test]
    fn a_node_with_no_name_still_gets_one() {
        let anonymous = node("trojan://PASSWORD@example.com:443?sni=example.com");

        let (body, _) = client_config(&[("", &anonymous)]);

        assert!(body.contains("\n  - name: node-1\n"), "{body}");
    }

    /// A name or a credential that YAML would read as something else — a number,
    /// a boolean, a string that starts a comment — is written so that it reads
    /// back as the string it is. The quoting is the emitter's; what is tested
    /// here is that no value depends on being written bare.
    #[test]
    fn a_value_yaml_would_read_as_something_else_survives_the_round_trip() {
        let hostile = node("trojan://0123@example.com:443?sni=example.com#Hostile");

        let (body, _) = client_config(&[
            ("true", &hostile),
            ("  padded  ", &hostile),
            ("a: b # c", &hostile),
            ("", &hostile),
        ]);

        assert_eq!(reread(&body), body);
        assert!(body.contains("password: \"0123\""), "{body}");
        assert!(body.contains("name: \"a: b # c\""), "{body}");
    }

    /// Whatever this crate says it can write, it writes.
    #[test]
    fn the_capability_list_is_the_truth() {
        let fixtures = [
            "trojan://PASSWORD@example.com:443?sni=example.com#Trojan",
            "ss://YWVzLTI1Ni1nY206UEFTU1dPUkQ@192.0.2.10:1080#SIP002",
            "ssr://Z29sZGVuLmV4YW1wbGUuY29tOjQ0MzphdXRoX3NoYTFfdjQ6YWVzLTI1Ni1jZmI6aHR0cF9zaW1wbGU6YkdWMGJXVnBiZy8_b2Jmc3BhcmFtPSZyZW1hcmtzPVUxTlM",
            "socks5://doge:letmein@127.0.0.1:1080#LocalSocks",
            "http://doge:letmein@127.0.0.1:8080#LocalHttp",
            "vless://11111111-2222-3333-4444-555555555555@example.com:443?encryption=none#IPv6",
            "vmess://eyJ2IjoiMiIsInBzIjoiR29sZGVuIiwiYWRkIjoiZ29sZGVuLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTExMTExMTEtMjIyMi0zMzMzLTQ0NDQtNTU1NTU1NTU1NTU1IiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInBhdGgiOiIvd3MiLCJ0bHMiOiJ0bHMifQ==",
            "hysteria2://letmein@example.com:443?obfs=salamander&obfs-password=obfspw&sni=www.apple.com#Tokyo",
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
            assert!(proxy("name", &node).is_ok(), "{fixture} was refused");
            kinds.push(node.protocol.kind());
        }

        for kind in PROTOCOLS {
            assert!(
                kinds.contains(kind),
                "{kind} is in the capability list with no fixture proving it"
            );
        }
    }
}
