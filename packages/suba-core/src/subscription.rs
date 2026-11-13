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

use saphyr::{LoadableYamlNode, Scalar, Yaml};
use saphyr_parser::{Event, Parser};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::node::NodeRecord;
use crate::proto::protocol::{
    anytls, http, hysteria, hysteria2, shadowsocks, shadowsocksr, snell, socks, trojan, tuic,
    vless, vmess,
};
use crate::proto::tls::{Alpn, Fingerprint, RealityClient, ShortId};
use crate::proto::transport::{Grpc, Http2, HttpUpgrade, Quic, Ws};
use crate::proto::{self, NodeFingerprint};
use crate::proto::{
    Client, Endpoint, Host, Name, Node, Outbound, Port, RawParams, Secret, TlsClient, Transport,
    Uuid,
};

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
    /// A mihomo `proxies` document in YAML or JSON; `clash` is an alias.
    Clash,
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
    /// A recognised Clash document has invalid syntax or shape.
    MalformedClash,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::MalformedClash => "the body is not a valid clash proxies document",
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
    /// 1-based for links; zero for a structured entry identified by `path`.
    pub line: usize,
    /// A structural location such as `proxies[0]`, never source text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
    /// Why nothing was read at all, when the whole document is malformed.
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

    /// Content identities within this payload. Pair them with the provider when
    /// combining subscriptions so distinct providers remain separate sources.
    pub fn identities(&self) -> Vec<NodeFingerprint> {
        self.nodes.iter().map(NodeRecord::id).collect()
    }
}

fn is_zero(count: &usize) -> bool {
    *count == 0
}

/// Read a subscription payload.
///
/// The shape is detected, because one layer of base64 around the same lines is
/// the same subscription. The link is kept as it arrived, so what a provider
/// served can be audited and re-exported without a second parse.
pub fn parse(payload: &[u8], provider: &str) -> Subscription {
    // A body that is base64 of a link list is the common case for a provider;
    // anything else is read as the text it is.
    let (text, format) = match proto::base64::decode_if_text(payload) {
        Some(decoded) => (decoded, SourceFormat::Base64),
        None => (
            String::from_utf8_lossy(payload).into_owned(),
            SourceFormat::Links,
        ),
    };

    if looks_like_clash(&text) || looks_like_clash_json(&text) {
        return read_clash(&text, provider);
    }

    read_links(&text, format, provider)
}

/// Read one share link per line.
fn read_links(text: &str, format: SourceFormat, provider: &str) -> Subscription {
    let mut reader = Reader::new(format, provider);

    for (index, line) in text.lines().enumerate() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        reader.line(line, index + 1);
    }

    reader.finish()
}

/// Whether a body is a mihomo YAML document rather than a link list.
///
/// The shape is a top-level `proxies:` key, which is unmistakable and is not
/// something a link list contains: a link list's comments and links never start
/// a line with it. Recognising it gives container errors one static reason
/// instead of reporting every YAML line as a malformed link.
fn looks_like_clash(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();

        line.starts_with("proxies:") && !line.starts_with("proxies://")
    })
}

fn looks_like_clash_json(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with('{') && trimmed.contains("\"proxies\"")
}

fn read_clash(text: &str, provider: &str) -> Subscription {
    let parsed = if text.trim_start().starts_with('{') {
        serde_json::from_str::<Value>(text).ok()
    } else {
        yaml_allowed(text)
            .then(|| Yaml::load_from_str(text).ok())
            .flatten()
            .filter(|documents| documents.len() == 1)
            .and_then(|mut documents| yaml_value(&documents.remove(0), 0))
    };
    let Some(Value::Object(mut document)) = parsed else {
        return Subscription::unreadable(Some(SourceFormat::Clash), Unreadable::MalformedClash);
    };
    let Some(Value::Array(proxies)) = document.remove("proxies") else {
        return Subscription::unreadable(Some(SourceFormat::Clash), Unreadable::MalformedClash);
    };
    let mut reader = Reader::new(SourceFormat::Clash, provider);
    for (index, proxy) in proxies.into_iter().enumerate() {
        match clash_proxy(proxy) {
            Ok(node) => reader.node(node, index, ""),
            Err(reason) => reader.skip_path(index, reason),
        }
    }
    reader.finish()
}

fn yaml_allowed(text: &str) -> bool {
    let mut depth = 0usize;
    for (index, event) in Parser::new_from_str(text).enumerate() {
        if index >= 500_000 {
            return false;
        }
        let Ok((event, _)) = event else {
            return false;
        };
        match event {
            Event::Alias(_) => return false,
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                depth += 1;
                if depth > 32 {
                    return false;
                }
            }
            Event::SequenceEnd | Event::MappingEnd => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

fn yaml_value(node: &Yaml<'_>, depth: usize) -> Option<Value> {
    if depth > 32 {
        return None;
    }
    match node {
        Yaml::Value(Scalar::Null) => Some(Value::Null),
        Yaml::Value(Scalar::Boolean(value)) => Some(Value::Bool(*value)),
        Yaml::Value(Scalar::Integer(value)) => Some(Value::from(*value)),
        Yaml::Value(Scalar::String(value)) => Some(Value::String(value.to_string())),
        Yaml::Value(Scalar::FloatingPoint(value)) => {
            serde_json::Number::from_f64(value.into_inner()).map(Value::Number)
        }
        Yaml::Sequence(items) => items
            .iter()
            .map(|item| yaml_value(item, depth + 1))
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        Yaml::Mapping(entries) => {
            let mut map = Map::new();
            for (key, value) in entries {
                let key = key.as_str()?;
                if map
                    .insert(key.to_string(), yaml_value(value, depth + 1)?)
                    .is_some()
                {
                    return None;
                }
            }
            Some(Value::Object(map))
        }
        _ => None,
    }
}

fn clash_proxy(proxy: Value) -> Result<Node<Client>, &'static str> {
    let Value::Object(mut proxy) = proxy else {
        return Err("a proxy object is needed");
    };
    let name = take_string(&mut proxy, "name")?;
    let kind = take_string(&mut proxy, "type")?;
    let host = Host::parse(&take_string(&mut proxy, "server")?)
        .map_err(|_| "server: a valid address is needed")?;
    let port = proxy
        .remove("port")
        .and_then(|value| value.as_u64())
        .and_then(|value| u16::try_from(value).ok())
        .and_then(Port::new)
        .ok_or("port: a valid port is needed")?;
    let protocol = clash_protocol(&kind, &mut proxy)?;
    let transport = clash_transport(&kind, &mut proxy)?;
    let tls = clash_tls(&kind, &mut proxy)?;
    // These are local dialer hints, not fields of the proxy wire protocol.
    // UDP enabled is the default for supported clients; disabling it cannot
    // be represented by the node model, so that case is refused.
    if take_optional_bool(&mut proxy, "udp")? == Some(false) {
        return Err("udp: disabling relay has no node mapping");
    }
    let _ = take_optional_bool(&mut proxy, "tfo")?;
    let mut extra = RawParams::new();
    if matches!(kind.as_str(), "vless" | "vmess") {
        if let Some(encoding) = take_optional_string(&mut proxy, "packet-encoding")? {
            extra.push("packetEncoding", &encoding);
        }
    }
    if !proxy.is_empty() {
        return Err("a proxy field has no model mapping");
    }
    Ok(Node {
        name: Name::from(name.as_str()),
        endpoint: Endpoint::new(host, port),
        listen: (),
        transport,
        tls,
        protocol,
        extra,
    })
}

fn clash_protocol(kind: &str, proxy: &mut Map<String, Value>) -> Result<Outbound, &'static str> {
    Ok(match kind {
        "ss" => {
            let mut client = shadowsocks::Client::new(
                take_string(proxy, "cipher")?,
                take_string(proxy, "password")?,
            );
            if let Some(plugin) = take_optional_string(proxy, "plugin")? {
                let options = take_object(proxy, "plugin-opts")?.unwrap_or_default();
                let name = match plugin.as_str() {
                    "obfs" => "obfs-local".into(),
                    "v2ray-plugin" => "v2ray-plugin".into(),
                    _ => return Err("plugin: this plugin has no model mapping"),
                };
                let mut parsed = shadowsocks::Plugin {
                    name,
                    options: Vec::new(),
                };
                for (key, value) in options {
                    let key = if plugin == "obfs" {
                        match key.as_str() {
                            "mode" => "obfs",
                            "host" => "obfs-host",
                            _ => return Err("plugin-opts: an option has no model mapping"),
                        }
                    } else {
                        match key.as_str() {
                            "mode" | "host" | "path" | "tls" => key.as_str(),
                            _ => return Err("plugin-opts: an option has no model mapping"),
                        }
                    };
                    let value = match value {
                        Value::String(value) => value,
                        Value::Bool(true) if key == "tls" => String::new(),
                        _ => return Err("plugin-opts: an option has an invalid value"),
                    };
                    parsed.options.push((key.into(), value.into_boxed_str()));
                }
                client.plugin = Some(parsed);
            }
            Outbound::Shadowsocks(client)
        }
        "ssr" => {
            let mut client = shadowsocksr::Client::new(
                take_string(proxy, "cipher")?,
                take_string(proxy, "password")?,
            );
            client.protocol = take_string(proxy, "protocol")?.into_boxed_str();
            client.obfs = take_string(proxy, "obfs")?.into_boxed_str();
            client.protocol_param = take_optional_string(proxy, "protocol-param")?
                .unwrap_or_default()
                .into_boxed_str();
            client.obfs_param = take_optional_string(proxy, "obfs-param")?
                .unwrap_or_default()
                .into_boxed_str();
            Outbound::ShadowsocksR(client)
        }
        "snell" => {
            let version =
                take_optional_u64(proxy, "version")?.ok_or("version: a Snell version is needed")?;
            let version = u8::try_from(version)
                .ok()
                .filter(|version| (1..=6).contains(version))
                .ok_or("version: this Snell version is unsupported")?;
            let mut client = snell::Client::new(version, take_string(proxy, "psk")?);
            client.reuse = take_optional_bool(proxy, "reuse")?.unwrap_or(false);
            client.mode = take_optional_string(proxy, "mode")?.map(String::into_boxed_str);
            if let Some(mut opts) = take_object(proxy, "obfs-opts")? {
                client.obfs_mode =
                    take_optional_string(&mut opts, "mode")?.map(String::into_boxed_str);
                client.obfs_host =
                    take_optional_string(&mut opts, "host")?.map(String::into_boxed_str);
                if !opts.is_empty() {
                    return Err("obfs-opts: an option has no model mapping");
                }
            }
            if version == 6 && (client.obfs_mode.is_some() || client.obfs_host.is_some()) {
                return Err("obfs-opts: Snell v6 does not support HTTP obfuscation");
            }
            if version != 6 && client.mode.is_some() {
                return Err("mode: traffic shaping belongs to Snell v6");
            }
            Outbound::Snell(client)
        }
        "trojan" => Outbound::Trojan(trojan::Client::new(take_string(proxy, "password")?)),
        "vless" => {
            let id = Uuid::parse(&take_string(proxy, "uuid")?)
                .map_err(|_| "uuid: a valid UUID is needed")?;
            let mut client = vless::Client::new(id);
            if let Some(flow) = take_optional_string(proxy, "flow")? {
                client.flow =
                    vless::Flow::parse(&flow).ok_or("flow: this flow has no model mapping")?;
            }
            client.encryption =
                take_optional_string(proxy, "encryption")?.map(String::into_boxed_str);
            Outbound::Vless(client)
        }
        "vmess" => {
            let id = Uuid::parse(&take_string(proxy, "uuid")?)
                .map_err(|_| "uuid: a valid UUID is needed")?;
            let mut client = vmess::Client::new(id);
            client.alter_id = take_optional_u64(proxy, "alterId")?
                .map(|id| u16::try_from(id).map_err(|_| "alterId: a valid count is needed"))
                .transpose()?
                .unwrap_or_default();
            if let Some(cipher) = take_optional_string(proxy, "cipher")? {
                client.security = vmess::Security::parse(&cipher)
                    .ok_or("cipher: this cipher has no model mapping")?;
            }
            Outbound::Vmess(client)
        }
        "hysteria2" => {
            let mut client = hysteria2::Client {
                password: Secret::new(take_string(proxy, "password")?.into_boxed_str()),
                obfs: None,
                obfs_password: None,
                ports: None,
                hop_interval: None,
                up: None,
                down: None,
                pin_sha256: None,
            };
            if let Some(obfs) = take_optional_string(proxy, "obfs")? {
                client.obfs = Some(
                    hysteria2::Obfs::parse(&obfs).ok_or("obfs: this type has no model mapping")?,
                );
                client.obfs_password = Some(Secret::new(
                    take_string(proxy, "obfs-password")?.into_boxed_str(),
                ));
            }
            client.ports = take_optional_string(proxy, "ports")?.map(String::into_boxed_str);
            client.hop_interval = take_optional_u64_or_string(proxy, "hop-interval")?;
            client.up = take_mbps(proxy, "up")?;
            client.down = take_mbps(proxy, "down")?;
            Outbound::Hysteria2(client)
        }
        "hysteria" => {
            let auth = match take_optional_string(proxy, "auth-str")? {
                Some(auth) => auth,
                None => take_optional_string(proxy, "auth_str")?
                    .ok_or("auth-str: an authentication password is needed")?,
            };
            let mut client = hysteria::Client::new(auth);
            client.obfs = take_optional_string(proxy, "obfs")?
                .map(|value| Secret::new(value.into_boxed_str()));
            client.up = take_mbps(proxy, "up")?;
            client.down = take_mbps(proxy, "down")?;
            client.ports = take_optional_string(proxy, "ports")?.map(String::into_boxed_str);
            client.hop_interval = take_optional_u64_or_string(proxy, "hop-interval")?;
            Outbound::Hysteria(client)
        }
        "tuic" => {
            let id = Uuid::parse(&take_string(proxy, "uuid")?)
                .map_err(|_| "uuid: a valid UUID is needed")?;
            let mut client = tuic::Client::new(id, take_string(proxy, "password")?);
            if let Some(congestion) = take_optional_string(proxy, "congestion-controller")? {
                client.congestion_control = tuic::CongestionControl::parse(&congestion)
                    .ok_or("congestion-controller: this mode has no model mapping")?;
            }
            if let Some(mode) = take_optional_string(proxy, "udp-relay-mode")? {
                client.udp_relay_mode = Some(
                    tuic::UdpRelayMode::parse(&mode)
                        .ok_or("udp-relay-mode: this mode has no model mapping")?,
                );
            }
            client.zero_rtt_handshake = take_optional_bool(proxy, "reduce-rtt")?.unwrap_or(false);
            Outbound::Tuic(client)
        }
        "anytls" => Outbound::AnyTls(anytls::Client::new(take_string(proxy, "password")?)),
        "socks5" => {
            let username = take_optional_string(proxy, "username")?.map(String::into_boxed_str);
            let password = take_optional_string(proxy, "password")?
                .map(|password| Secret::new(password.into_boxed_str()));
            Outbound::Socks(socks::Client {
                version: socks::Version::V5,
                username,
                password,
            })
        }
        "http" => {
            let username = take_optional_string(proxy, "username")?.map(String::into_boxed_str);
            let password = take_optional_string(proxy, "password")?
                .map(|password| Secret::new(password.into_boxed_str()));
            Outbound::Http(http::Client { username, password })
        }
        _ => return Err("type: this proxy type has no model mapping"),
    })
}

fn clash_transport(kind: &str, proxy: &mut Map<String, Value>) -> Result<Transport, &'static str> {
    let network = take_optional_string(proxy, "network")?.unwrap_or_else(|| "tcp".to_string());
    let carried = matches!(kind, "vless" | "vmess" | "trojan");
    match network.as_str() {
        "tcp" => Ok(if matches!(kind, "hysteria" | "hysteria2" | "tuic") {
            Transport::Quic(Quic::default())
        } else {
            Transport::Tcp
        }),
        _ if !carried => Err("network: this proxy type has no transport mapping"),
        "ws" => {
            let mut opts = take_object(proxy, "ws-opts")?.unwrap_or_default();
            let path = take_optional_string(&mut opts, "path")?.unwrap_or_else(|| "/".to_string());
            let headers = take_object(&mut opts, "headers")?.unwrap_or_default();
            let host = headers
                .get("Host")
                .and_then(Value::as_str)
                .map(Host::parse)
                .transpose()
                .map_err(|_| "ws-opts.headers.Host: a valid host is needed")?;
            if headers.len() != usize::from(host.is_some()) {
                return Err("ws-opts.headers: a header has no model mapping");
            }
            let upgrade = take_optional_bool(&mut opts, "v2ray-http-upgrade")?.unwrap_or(false);
            let early_data = take_optional_u64(&mut opts, "max-early-data")?
                .map(|value| {
                    u32::try_from(value)
                        .map_err(|_| "ws-opts.max-early-data: the value is too large")
                })
                .transpose()?;
            if !opts.is_empty() {
                return Err("ws-opts: an option has no model mapping");
            }
            if upgrade {
                if early_data.is_some() {
                    return Err("ws-opts.max-early-data: HTTP upgrade cannot carry early data");
                }
                Ok(Transport::HttpUpgrade(HttpUpgrade {
                    host,
                    path: path.into_boxed_str(),
                    extra: RawParams::new(),
                }))
            } else {
                Ok(Transport::Ws(Ws {
                    path: path.into_boxed_str(),
                    host,
                    early_data,
                    header_name: None,
                    extra: RawParams::new(),
                }))
            }
        }
        "grpc" => {
            let mut opts = take_object(proxy, "grpc-opts")?.unwrap_or_default();
            let service_name =
                take_optional_string(&mut opts, "grpc-service-name")?.unwrap_or_default();
            if !opts.is_empty() {
                return Err("grpc-opts: an option has no model mapping");
            }
            Ok(Transport::Grpc(Grpc {
                service_name: service_name.into_boxed_str(),
                authority: None,
                multi_mode: false,
                extra: RawParams::new(),
            }))
        }
        "h2" if matches!(kind, "vless" | "vmess") => {
            let mut opts = take_object(proxy, "h2-opts")?.unwrap_or_default();
            let path = take_optional_string(&mut opts, "path")?.map(String::into_boxed_str);
            let host = match opts.remove("host") {
                None => None,
                Some(Value::Array(hosts)) if hosts.len() == 1 => hosts[0]
                    .as_str()
                    .map(Host::parse)
                    .transpose()
                    .map_err(|_| "h2-opts.host: a valid host is needed")?,
                _ => return Err("h2-opts.host: one host is needed"),
            };
            if !opts.is_empty() {
                return Err("h2-opts: an option has no model mapping");
            }
            Ok(Transport::Http2(Http2 {
                host,
                path,
                extra: RawParams::new(),
            }))
        }
        _ => Err("network: this transport has no model mapping"),
    }
}

fn clash_tls(
    kind: &str,
    proxy: &mut Map<String, Value>,
) -> Result<Option<TlsClient>, &'static str> {
    let explicit = take_optional_bool(proxy, "tls")?;
    let inherent = matches!(
        kind,
        "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls"
    );
    if inherent && explicit == Some(false) {
        return Err("tls: this protocol requires TLS");
    }
    let name_field = if matches!(kind, "vless" | "vmess") {
        "servername"
    } else {
        "sni"
    };
    let name = take_optional_string(proxy, name_field)?;
    let insecure = take_optional_bool(proxy, "skip-cert-verify")?.unwrap_or(false);
    let fingerprint = take_optional_string(proxy, "client-fingerprint")?;
    let alpn = match proxy.remove("alpn") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|item| {
                item.as_str()
                    .and_then(|value| Alpn::parse(value).ok())
                    .ok_or("alpn: identifiers must be nonempty strings")
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("alpn: an array of strings is needed"),
    };
    let reality = take_object(proxy, "reality-opts")?;
    let enabled = inherent
        || explicit == Some(true)
        || name.is_some()
        || insecure
        || fingerprint.is_some()
        || !alpn.is_empty()
        || reality.is_some();
    if !enabled {
        return Ok(None);
    }
    if matches!(kind, "ss" | "ssr") {
        return Err("tls: this proxy type has no TLS mapping");
    }
    let mut tls = TlsClient {
        server_name: name
            .map(|name| Host::parse(&name).map_err(|_| "sni: a valid host is needed"))
            .transpose()?,
        insecure,
        alpn,
        ..Default::default()
    };
    if let Some(fingerprint) = fingerprint {
        if !matches!(kind, "vless" | "vmess" | "trojan" | "anytls") {
            return Err("client-fingerprint: this proxy type has no fingerprint mapping");
        }
        tls.fingerprint = Some(
            Fingerprint::parse(&fingerprint)
                .map_err(|_| "client-fingerprint: a profile is needed")?,
        );
    }
    if let Some(mut reality) = reality {
        if !matches!(kind, "vless" | "vmess" | "trojan") {
            return Err("reality-opts: this proxy type has no Reality mapping");
        }
        let mut client = RealityClient::new(take_string(&mut reality, "public-key")?);
        client.short_id = take_optional_string(&mut reality, "short-id")?
            .map(|id| {
                ShortId::parse(&id).map_err(|_| "reality-opts.short-id: a valid short id is needed")
            })
            .transpose()?;
        if !reality.is_empty() {
            return Err("reality-opts: an option has no model mapping");
        }
        tls.reality = Some(client);
    }
    Ok(Some(tls))
}

fn take_optional_string(
    proxy: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, &'static str> {
    match proxy.remove(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err("a proxy field must be a string"),
    }
}

fn take_optional_bool(
    proxy: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<bool>, &'static str> {
    match proxy.remove(field) {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(value)),
        _ => Err("a proxy field must be a boolean"),
    }
}

fn take_optional_u64(
    proxy: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, &'static str> {
    match proxy.remove(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or("a proxy field must be a nonnegative integer")
            .map(Some),
        _ => Err("a proxy field must be a nonnegative integer"),
    }
}

fn take_optional_u64_or_string(
    proxy: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, &'static str> {
    match proxy.remove(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or("a proxy field must be a nonnegative integer")
            .map(Some),
        Some(Value::String(value)) => value
            .parse()
            .map(Some)
            .map_err(|_| "a proxy field must be a nonnegative integer"),
        _ => Err("a proxy field must be a nonnegative integer"),
    }
}

fn take_mbps(proxy: &mut Map<String, Value>, field: &str) -> Result<Option<u64>, &'static str> {
    match proxy.remove(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or("a bandwidth must be in Mbps")
            .map(Some),
        Some(Value::String(value)) => value
            .strip_suffix(" Mbps")
            .unwrap_or(&value)
            .parse()
            .map(Some)
            .map_err(|_| "a bandwidth must be in Mbps"),
        _ => Err("a bandwidth must be in Mbps"),
    }
}

fn take_object(
    proxy: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<Map<String, Value>>, &'static str> {
    match proxy.remove(field) {
        None => Ok(None),
        Some(Value::Object(value)) => Ok(Some(value)),
        _ => Err("a proxy option block must be an object"),
    }
}

fn take_string(
    proxy: &mut Map<String, Value>,
    field: &'static str,
) -> Result<String, &'static str> {
    proxy
        .remove(field)
        .and_then(|value| value.as_str().map(str::to_string))
        .filter(|value| !value.is_empty())
        .ok_or(match field {
            "name" => "name: a nonempty name is needed",
            "type" => "type: a proxy type is needed",
            "server" => "server: an address is needed",
            "cipher" => "cipher: a method is needed",
            _ => "password: a credential is needed",
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
    nodes: Vec<NodeRecord>,
    /// Identity to position, so a duplicate folds into what was already read.
    seen: HashMap<NodeFingerprint, usize>,
    duplicates: usize,
    skipped: Vec<SkippedLine>,
    skipped_omitted: usize,
}

impl<'a> Reader<'a> {
    fn new(format: SourceFormat, provider: &'a str) -> Self {
        Self {
            format,
            provider,
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

        self.node(node, number - 1, line);
    }

    fn node(&mut self, node: proto::Node<proto::Client>, position: usize, raw: &str) {
        let mut record = NodeRecord::new(node);
        let id = record.id();

        // The position is where in the payload it appeared, which is what makes
        // "the provider's order" reproducible.
        record.attribute(self.provider, position, raw);

        match self.seen.get(&id) {
            // Keep the first occurrence's spelling and position within this payload.
            Some(_) => {
                self.duplicates += 1;
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
                path: None,
                reason: reason.to_string(),
            });
        } else {
            self.skipped_omitted += 1;
        }
    }

    fn skip_path(&mut self, index: usize, reason: &'static str) {
        if self.skipped.len() < MAX_SKIPPED {
            self.skipped.push(SkippedLine {
                line: 0,
                path: Some(format!("proxies[{index}]")),
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

    const TROJAN: &str = "trojan://hunter2@example.com:443#First";
    const VLESS: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443#Second";

    fn read(text: &str) -> Subscription {
        parse(text.as_bytes(), "primary")
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
            "the first occurrence keeps its position"
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
        let subscription = read("proxies:\n  - name: node\n    type: ss\n    server: example.com\n    port: 8388\n    cipher: aes-128-gcm\n    password: example-secret\n");

        assert_eq!(
            subscription.format,
            Some(SourceFormat::Clash),
            "recognised, not misread as links"
        );
        assert_eq!(subscription.unreadable, None);
        assert_eq!(subscription.len(), 1);
        assert_eq!(subscription.nodes[0].name(), "node");
    }

    #[test]
    fn a_clash_json_document_uses_the_same_node_reader() {
        let subscription = read(
            r#"{"proxies":[{"name":"node","type":"ss","server":"example.com","port":8388,"cipher":"aes-128-gcm","password":"example-secret"}]}"#,
        );
        assert_eq!(subscription.format, Some(SourceFormat::Clash));
        assert_eq!(subscription.len(), 1);
        assert_eq!(subscription.nodes[0].name(), "node");
    }

    #[test]
    fn a_mihomo_hysteria_v1_proxy_keeps_its_credentials() {
        let body = b"proxies:\n  - name: Hysteria\n    type: hysteria\n    server: example.com\n    port: 443\n    auth-str: personal-key\n    up: 20\n    down: 50\n    obfs: shared-obfs\n";
        let parsed = parse(body, "provider");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.nodes[0].node.protocol.kind(), proto::Kind::Hysteria);
    }

    #[test]
    fn hysteria_v1_accepts_the_common_auth_str_alias() {
        let body = b"proxies:\n  - name: Hysteria\n    type: hysteria\n    server: example.com\n    port: 443\n    auth_str: personal-key\n    up: 20\n    down: 50\n";
        let parsed = parse(body, "provider");
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn a_bad_clash_entry_does_not_hide_usable_entries_or_credentials() {
        let body = "proxies:\n  - { name: first, type: ss, server: example.com, port: 8388, cipher: aes-128-gcm, password: first-secret }\n  - { name: invalid, type: ss, server: example.com, port: 8389, cipher: aes-128-gcm, password: second-secret, unknown: true }\n  - { name: last, type: trojan, server: example.com, port: 443, password: third-secret }\n";
        let subscription = read(body);
        assert_eq!(subscription.len(), 2);
        assert_eq!(subscription.nodes[0].provenance[0].position, 0);
        assert_eq!(subscription.nodes[1].provenance[0].position, 2);
        assert_eq!(subscription.skipped.len(), 1);
        assert_eq!(subscription.skipped[0].path.as_deref(), Some("proxies[1]"));
        assert_eq!(subscription.skipped[0].line, 0);
        assert!(!format!("{:?}", subscription.skipped).contains("second-secret"));
    }

    #[test]
    fn malformed_clash_json_reports_a_static_container_reason() {
        let subscription = read("{\"proxies\": [invalid-secret}");
        assert_eq!(subscription.format, Some(SourceFormat::Clash));
        assert_eq!(subscription.unreadable, Some(Unreadable::MalformedClash));
        assert!(!subscription
            .unreadable
            .unwrap()
            .to_string()
            .contains("invalid-secret"));
    }

    /// What the reason says is static, so it can be shown to an operator.
    #[test]
    fn a_reason_names_the_format_and_not_the_body() {
        assert_eq!(
            Unreadable::MalformedClash.to_string(),
            "the body is not a valid clash proxies document"
        );
        assert!(
            !Unreadable::MalformedClash.to_string().contains(TROJAN),
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
