//! Surge remote policy lines derived from client nodes.
//!
//! A policy-path resource contains declarations without a profile header.
//! Field refusals prevent an unsupported wire option from becoming a different
//! proxy that merely looks valid.

use std::fmt::Write as _;

use crate::proto::protocol::shadowsocks::Plugin;
use crate::proto::{Client, Kind, Node, Outbound, Transport};

pub const PROTOCOLS: &[Kind] = &[
    Kind::Shadowsocks,
    Kind::Snell,
    Kind::Trojan,
    Kind::Vless,
    Kind::Vmess,
    Kind::Hysteria2,
    Kind::Tuic,
    Kind::AnyTls,
    Kind::Socks,
    Kind::Http,
];

pub struct Refused {
    pub index: usize,
    pub reason: Reason,
}

pub enum Reason {
    Protocol(Kind),
    Field(&'static str, &'static str),
}

fn field(path: &'static str, reason: &'static str) -> Reason {
    Reason::Field(path, reason)
}

pub fn client_config(nodes: &[(&str, &Node<Client>)]) -> (String, Vec<Refused>) {
    let mut body = String::new();
    let mut refused = Vec::new();
    let mut names = Vec::new();
    for (index, (name, node)) in nodes.iter().enumerate() {
        let name = unique_name(name, &mut names);
        match proxy(&name, node) {
            Ok(line) => {
                body.push_str(&line);
                body.push('\n');
            }
            Err(reason) => refused.push(Refused { index, reason }),
        }
    }
    (body, refused)
}

fn unique_name(name: &str, names: &mut Vec<String>) -> String {
    let base = if name.is_empty() { "Proxy" } else { name };
    let mut candidate = base.to_string();
    let mut suffix = 2;
    while names.contains(&candidate) {
        candidate = format!("{base} {suffix}");
        suffix += 1;
    }
    names.push(candidate.clone());
    candidate
}

fn proxy(name: &str, node: &Node<Client>) -> Result<String, Reason> {
    if !PROTOCOLS.contains(&node.protocol.kind()) {
        return Err(Reason::Protocol(node.protocol.kind()));
    }
    if name.contains(['=', ',', '\n', '\r']) {
        return Err(field(
            "name",
            "this name cannot be written in a policy line",
        ));
    }
    if !node.extra.is_empty() {
        return Err(field("extra", "a node parameter has no Surge mapping"));
    }
    let kind = match &node.protocol {
        Outbound::Shadowsocks(_) => "ss",
        Outbound::Snell(_) => "snell",
        Outbound::Trojan(_) => "trojan",
        Outbound::Vless(_) => "vless",
        Outbound::Vmess(_) => "vmess",
        Outbound::Hysteria2(_) => "hysteria2",
        Outbound::Tuic(_) => "tuic-v5",
        Outbound::AnyTls(_) => "anytls",
        Outbound::Socks(_) => "socks5",
        Outbound::Http(_) if node.tls.is_some() => "https",
        Outbound::Http(_) => "http",
        other => return Err(Reason::Protocol(other.kind())),
    };
    let mut line = format!(
        "{name} = {kind}, {}, {}",
        node.endpoint.host,
        node.endpoint.port.get()
    );
    protocol_fields(&mut line, node)?;
    transport_fields(&mut line, node)?;
    tls_fields(&mut line, node)?;
    Ok(line)
}

fn append(line: &mut String, key: &str, value: &str, path: &'static str) -> Result<(), Reason> {
    if value.contains(['\n', '\r', '"']) {
        return Err(field(path, "this value cannot be written in a policy line"));
    }
    if value.contains(',') {
        write!(line, ", {key}=\"{value}\"").expect("writing to a string");
    } else {
        write!(line, ", {key}={value}").expect("writing to a string");
    }
    Ok(())
}

fn credentials(
    line: &mut String,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), Reason> {
    if let Some(username) = username {
        append(line, "username", username, "username")?;
    }
    if let Some(password) = password {
        append(line, "password", password, "password")?;
    }
    Ok(())
}

fn shadowsocks_plugin(line: &mut String, plugin: &Plugin) -> Result<(), Reason> {
    if !matches!(plugin.name.as_ref(), "obfs-local" | "simple-obfs") {
        return Err(field("plugin", "this plugin has no Surge mapping"));
    }
    let mode = plugin
        .get("obfs")
        .ok_or_else(|| field("plugin.obfs", "an obfuscation mode is needed"))?;
    append(line, "obfs", mode, "plugin.obfs")?;
    if let Some(host) = plugin.get("obfs-host") {
        append(line, "obfs-host", host, "plugin.obfs-host")?;
    }
    if plugin
        .options
        .iter()
        .any(|(key, _)| !matches!(key.as_ref(), "obfs" | "obfs-host"))
    {
        return Err(field("plugin", "a plugin option has no Surge mapping"));
    }
    Ok(())
}

fn protocol_fields(line: &mut String, node: &Node<Client>) -> Result<(), Reason> {
    match &node.protocol {
        Outbound::Shadowsocks(client) => {
            if !matches!(
                client.method.as_ref(),
                "aes-128-gcm"
                    | "aes-192-gcm"
                    | "aes-256-gcm"
                    | "chacha20-ietf-poly1305"
                    | "xchacha20-ietf-poly1305"
                    | "2022-blake3-aes-128-gcm"
                    | "2022-blake3-aes-256-gcm"
            ) {
                return Err(field(
                    "method",
                    "this Shadowsocks cipher has no Surge mapping",
                ));
            }
            append(line, "encrypt-method", &client.method, "method")?;
            append(line, "password", client.password.as_str(), "password")?;
            if let Some(plugin) = &client.plugin {
                shadowsocks_plugin(line, plugin)?;
            }
        }
        Outbound::Snell(client) => {
            if client.userkey.is_some() {
                return Err(field("userkey", "Surge cannot use Snell user keys"));
            }
            if client.version == 6 && (client.obfs_mode.is_some() || client.obfs_host.is_some()) {
                return Err(field(
                    "obfs_mode",
                    "Snell v6 does not support HTTP obfuscation",
                ));
            }
            if client.version != 6 && client.mode.is_some() {
                return Err(field("mode", "traffic shaping belongs to Snell v6"));
            }
            append(line, "psk", client.psk.as_str(), "psk")?;
            write!(line, ", version={}", client.version).expect("writing to a string");
            if client.reuse {
                line.push_str(", reuse=true");
            }
            if let Some(mode) = &client.obfs_mode {
                append(line, "obfs", mode, "obfs_mode")?;
            }
            if let Some(host) = &client.obfs_host {
                append(line, "obfs-host", host, "obfs_host")?;
            }
            if let Some(mode) = &client.mode {
                append(line, "mode", mode, "mode")?;
            }
        }
        Outbound::Trojan(client) => append(line, "password", client.password.as_str(), "password")?,
        Outbound::Vless(client) => {
            if client
                .encryption
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                return Err(field("encryption", "Surge only supports none"));
            }
            append(line, "username", &client.id.expose().to_string(), "uuid")?;
            if let Some(flow) = client.flow.as_str() {
                if flow != "xtls-rprx-vision"
                    || !matches!(node.transport, Transport::Tcp)
                    || node.tls.is_none()
                {
                    return Err(field(
                        "flow",
                        "this Vision combination has no Surge mapping",
                    ));
                }
                append(line, "flow", flow, "flow")?;
            }
        }
        Outbound::Vmess(client) => {
            if client.alter_id != 0 {
                return Err(field("alter_id", "Surge requires the AEAD handshake"));
            }
            append(line, "username", &client.id.expose().to_string(), "uuid")?;
            line.push_str(", vmess-aead=true");
            let method = match client.security {
                crate::proto::protocol::vmess::Security::Auto
                | crate::proto::protocol::vmess::Security::Aes128Gcm => "aes-128-gcm",
                crate::proto::protocol::vmess::Security::Chacha20Poly1305 => {
                    "chacha20-ietf-poly1305"
                }
                _ => return Err(field("security", "this VMess cipher has no Surge mapping")),
            };
            append(line, "encrypt-method", method, "security")?;
        }
        Outbound::Hysteria2(client) => {
            append(line, "password", client.password.as_str(), "password")?;
            if client.obfs.is_some() {
                let password = client
                    .obfs_password
                    .as_ref()
                    .ok_or_else(|| field("obfs_password", "a Salamander password is needed"))?;
                append(
                    line,
                    "salamander-password",
                    password.as_str(),
                    "obfs_password",
                )?;
            }
            if let Some(ports) = &client.ports {
                append(line, "port-hopping", &ports.replace(',', ";"), "ports")?;
            }
            if let Some(interval) = client.hop_interval {
                write!(line, ", port-hopping-interval={interval}").expect("writing to a string");
            }
            if let Some(down) = client.down {
                write!(line, ", download-bandwidth={down}").expect("writing to a string");
            }
            if client.up.is_some() || client.pin_sha256.is_some() {
                return Err(field("hysteria2", "an option has no Surge mapping"));
            }
        }
        Outbound::Tuic(client) => {
            append(line, "uuid", &client.uuid.expose().to_string(), "uuid")?;
            append(line, "password", client.password.as_str(), "password")?;
            if client.congestion_control != crate::proto::protocol::tuic::CongestionControl::Cubic
                || client.udp_relay_mode.is_some()
                || client.zero_rtt_handshake
            {
                return Err(field("tuic", "an option has no Surge mapping"));
            }
        }
        Outbound::AnyTls(client) => append(line, "password", client.password.as_str(), "password")?,
        Outbound::Socks(client) => {
            if client.version != crate::proto::protocol::socks::Version::V5 {
                return Err(field("version", "Surge only supports SOCKS5"));
            }
            credentials(
                line,
                client.username.as_deref(),
                client.password.as_ref().map(|value| value.as_str()),
            )?;
        }
        Outbound::Http(client) => credentials(
            line,
            client.username.as_deref(),
            client.password.as_ref().map(|value| value.as_str()),
        )?,
        other => return Err(Reason::Protocol(other.kind())),
    }
    Ok(())
}

fn transport_fields(line: &mut String, node: &Node<Client>) -> Result<(), Reason> {
    match &node.transport {
        Transport::Tcp => Ok(()),
        Transport::Quic(quic)
            if matches!(node.protocol, Outbound::Hysteria2(_) | Outbound::Tuic(_))
                && *quic == Default::default() =>
        {
            Ok(())
        }
        Transport::Ws(ws)
            if matches!(
                node.protocol,
                Outbound::Vless(_) | Outbound::Vmess(_) | Outbound::Trojan(_)
            ) =>
        {
            if ws.early_data.is_some() || ws.header_name.is_some() || !ws.extra.is_empty() {
                return Err(field("transport.ws", "an option has no Surge mapping"));
            }
            line.push_str(", ws=true");
            append(line, "ws-path", &ws.path, "transport.ws.path")?;
            if let Some(host) = &ws.host {
                append(
                    line,
                    "ws-headers",
                    &format!("Host:{host}"),
                    "transport.ws.host",
                )?;
            }
            Ok(())
        }
        Transport::Grpc(grpc) if matches!(node.protocol, Outbound::Vless(_)) => {
            if !grpc.extra.is_empty() {
                return Err(field("transport.grpc", "an option has no Surge mapping"));
            }
            line.push_str(", grpc=true");
            append(
                line,
                "grpc-service-name",
                &grpc.service_name,
                "transport.grpc.service_name",
            )?;
            if grpc.multi_mode {
                line.push_str(", grpc-mode=multi");
            }
            if let Some(authority) = &grpc.authority {
                append(
                    line,
                    "grpc-authority",
                    &authority.to_string(),
                    "transport.grpc.authority",
                )?;
            }
            Ok(())
        }
        Transport::HttpUpgrade(_) => Err(field(
            "transport",
            "Surge does not support HTTP upgrade transport",
        )),
        _ => Err(field("transport", "this transport has no Surge mapping")),
    }
}

fn tls_fields(line: &mut String, node: &Node<Client>) -> Result<(), Reason> {
    let required = matches!(
        node.protocol,
        Outbound::Trojan(_) | Outbound::Hysteria2(_) | Outbound::Tuic(_) | Outbound::AnyTls(_)
    );
    let Some(tls) = &node.tls else {
        if required {
            return Err(field("tls", "this protocol requires TLS"));
        }
        return Ok(());
    };
    if matches!(node.protocol, Outbound::Shadowsocks(_) | Outbound::Snell(_)) {
        return Err(field("tls", "Shadowsocks has no Surge TLS mapping"));
    }
    if !tls.extra.is_empty() || tls.fingerprint.is_some() {
        return Err(field("tls", "a TLS option has no Surge mapping"));
    }
    if !required {
        line.push_str(", tls=true");
    }
    if let Some(name) = &tls.server_name {
        append(line, "sni", &name.to_string(), "tls.server_name")?;
    }
    if tls.insecure {
        line.push_str(", skip-cert-verify=true");
    }
    if !tls.alpn.is_empty() {
        let alpn = tls
            .alpn
            .iter()
            .map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join(",");
        append(line, "alpn", &alpn, "tls.alpn")?;
    }
    if let Some(reality) = &tls.reality {
        if !matches!(node.protocol, Outbound::Vless(_)) || reality.spider_x.is_some() {
            return Err(field(
                "tls.reality",
                "this Reality combination has no Surge mapping",
            ));
        }
        append(
            line,
            "reality-public-key",
            reality.public_key.as_str(),
            "tls.reality.public_key",
        )?;
        if let Some(id) = &reality.short_id {
            append(
                line,
                "reality-short-id",
                id.as_str(),
                "tls.reality.short_id",
            )?;
        }
    }
    Ok(())
}
