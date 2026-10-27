//! Inbound users, read from the server's side and handed to a client's.
//!
//! Three things a managed user needs from a native inbound, and nothing
//! else: whether the inbound can take one, the user entry the core reads, and
//! the client node that reaches it. The inbound is read where it is written —
//! the user's own JSON — and is never rewritten through a model.
//!
//! What the core does with a user is measured, not assumed (sing-box 1.14.3):
//!
//! * A VLESS server compares the client's `flow` with the user's and refuses a
//!   mismatch; Vision only runs directly on a TLS connection (sing-vmess
//!   `vless/vision.go`), so no transport and no multiplex.
//! * A server keys its users by credential and keeps the last of two equal
//!   ones without a word, which is why a caller compares credentials before it
//!   adds a user.
//! * REALITY accepts only `tls.server_name` as the client's SNI; the handshake
//!   server is where probes go, not a name a client sends.

use serde_json::{json, Value};
use suba_proto::protocol::{
    anytls, http, hysteria2, shadowsocks, socks, trojan, tuic, vless, vmess,
};
use suba_proto::tls::{Alpn, Fingerprint, RealityClient, RealityServer, ShortId};
use suba_proto::transport::{Grpc, HttpUpgrade, Ws};
use suba_proto::{
    Client, Endpoint, Host, Name, Node, Outbound, Port, RawParams, Secret, TlsClient, Transport,
    Uuid,
};

/// The protocols a managed user can be granted on, and what each needs.
///
/// Every protocol whose inbound takes per-user credentials is here. What the
/// core demands of a user differs by protocol, and it is measured rather than
/// assumed (sing-box 1.14.3, `option/*.go` and a real `sing-box check`):
///
/// * VLESS, VMess, TUIC and Shadowsocks key a user by a UUID or a key.
/// * Trojan, Hysteria2, AnyTLS and ShadowTLS key a user by a password.
/// * Snell keys a user by a `userkey` beside the inbound's own `psk`.
/// * Hysteria v1 keys a user by `auth_str`, beside the inbound's `obfs`.
/// * HTTP, SOCKS and Naive take `auth.User`, which is `username` and
///   `password` and **no** `name` — see [`user`], where these get a `username`
///   from the user's name because the core refuses a `name` field.
///
/// Shadowsocks is the one with a shape of its own: multi-user needs the
/// inbound's own `password` as well, and the 2022 ciphers need every key the
/// same length as the cipher's, which is why [`user`] can refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Trojan,
    Vmess,
    Tuic,
    AnyTls,
    Hysteria2,
    Hysteria,
    ShadowTls,
    Snell,
    Shadowsocks,
    Http,
    Socks,
    Naive,
}

/// Why something about a user cannot be exported, and the field it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unexportable {
    /// Relative to the inbound, such as `tls.server_name` or `users[2].name`.
    pub path: String,
    pub reason: &'static str,
}

impl std::fmt::Display for Unexportable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}

fn unexportable(path: impl Into<String>, reason: &'static str) -> Unexportable {
    Unexportable {
        path: path.into(),
        reason,
    }
}

/// Whether an inbound can take a managed user, and as which protocol.
pub fn grantable(inbound: &Value) -> Result<Protocol, &'static str> {
    match inbound.get("type").and_then(Value::as_str) {
        Some("vless") => Ok(Protocol::Vless),
        Some("trojan") => Ok(Protocol::Trojan),
        Some("vmess") => Ok(Protocol::Vmess),
        Some("tuic") => Ok(Protocol::Tuic),
        Some("anytls") => Ok(Protocol::AnyTls),
        Some("hysteria2") => Ok(Protocol::Hysteria2),
        Some("hysteria") => Ok(Protocol::Hysteria),
        Some("shadowtls") => Ok(Protocol::ShadowTls),
        Some("snell") => Ok(Protocol::Snell),
        Some("http") => Ok(Protocol::Http),
        Some("socks") => Ok(Protocol::Socks),
        Some("naive") => Ok(Protocol::Naive),
        // A `mixed` listener *can* take users, but it is the plaintext
        // local entry — the one an operator runs for their own machine. Giving
        // it managed users would turn authentication on for everyone already
        // using it, which is a decision about the operator's document and not
        // one a grant should make silently.
        Some("mixed") => Err("a mixed listener is a local entry; users are not granted on it"),
        Some("shadowsocks") => shadowsocks(inbound),
        Some("direct" | "tun" | "redirect" | "tproxy" | "cloudflared") => {
            Err("this is not a proxy inbound users dial")
        }
        // ShadowsocksR was removed from the core in 1.6.0; a grant here would
        // write a document the core refuses to load.
        Some("shadowsocksr") => Err("ShadowsocksR is removed from sing-box"),
        _ => Err("this inbound has no users"),
    }
}

/// Whether a Shadowsocks inbound can carry managed users, and why not when it
/// cannot.
///
/// Multi-user is a mode of its own: the core refuses `users` beside
/// `destinations` and beside `managed`, and it needs the inbound's own
/// `password` to derive per-user keys. It is never a matter of scaling the
/// single-user case up.
fn shadowsocks(inbound: &Value) -> Result<Protocol, &'static str> {
    let method = inbound
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if inbound.get("destinations").is_some() {
        return Err("a relay inbound takes destinations, not users");
    }
    // `managed` is a plain flag, not an `{enabled}` block, and the core
    // refuses users beside it: a managed server sizes its own users, and
    // injecting ours would stop it from starting.
    if inbound.get("managed").and_then(Value::as_bool) == Some(true) {
        return Err("a managed Shadowsocks server sizes its own users");
    }
    if inbound
        .get("password")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .is_none()
    {
        return Err("multi-user Shadowsocks needs the inbound's own password");
    }
    // Measured: every 2022 cipher refuses a user key that is not its own length,
    // and the chacha20-poly1305 one refuses multi-user outright.
    if method == "2022-blake3-chacha20-poly1305" {
        return Err("this cipher cannot have more than one user");
    }
    if method.starts_with("2022-blake3-") && shadowsocks_key_len(method).is_none() {
        return Err("only the 2022 key lengths can be derived");
    }

    Ok(Protocol::Shadowsocks)
}

/// How many raw bytes a 2022 user key is, for the ciphers that take one.
fn shadowsocks_key_len(method: &str) -> Option<usize> {
    match method {
        "2022-blake3-aes-128-gcm" => Some(16),
        "2022-blake3-aes-256-gcm" => Some(32),
        _ => None,
    }
}

/// The flow every VLESS user of this inbound has to use, from its shape.
///
/// Derived each time rather than stored with the user: the server demands the
/// exact flow, so the user it runs and the client it hands out must follow the
/// inbound together when its shape changes.
pub fn flow(inbound: &Value) -> Option<&'static str> {
    let vless = inbound.get("type").and_then(Value::as_str) == Some("vless");
    let direct = inbound.get("transport").is_none() && !enabled(inbound.get("multiplex"));

    (vless && enabled(inbound.get("tls")) && direct).then_some("xtls-rprx-vision")
}

/// The user entry the core reads, shaped for `protocol` from 32 random bytes.
///
/// The first half makes a UUID and the second a password, so a protocol that
/// needs both never repeats one in the other. `None` when this inbound cannot
/// take a user at all — today only a 2022 Shadowsocks one, whose cipher decides
/// how long a key has to be.
pub fn user(protocol: Protocol, inbound: &Value, name: &str, material: &[u8; 32]) -> Option<Value> {
    let uuid = derive_uuid(material);
    let entry = match protocol {
        Protocol::Vless => {
            let mut entry = json!({ "name": name, "uuid": uuid });
            if let Some(flow) = flow(inbound) {
                entry["flow"] = json!(flow);
            }
            entry
        }
        Protocol::Vmess => json!({ "name": name, "uuid": uuid, "alterId": 0 }),
        Protocol::Tuic => {
            json!({ "name": name, "uuid": uuid, "password": derive_password(material) })
        }
        Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria2 | Protocol::ShadowTls => {
            json!({ "name": name, "password": derive_password(material) })
        }
        // Snell's user key and Hysteria v1's auth are each named for what they
        // are beside the inbound's own key, and the core takes no other name.
        Protocol::Snell => json!({ "name": name, "userkey": derive_password(material) }),
        Protocol::Hysteria => json!({ "name": name, "auth_str": derive_password(material) }),
        Protocol::Shadowsocks => {
            let method = inbound
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let key = match shadowsocks_key_len(method) {
                None => derive_password(material),
                Some(len) => suba_proto::base64::encode_standard(&material[..len]),
            };
            json!({ "name": name, "password": key })
        }
        // `auth.User` has a `username` and a `password` and no `name` at all:
        // the core refuses a `name` field here, and the username is what it
        // reports as the connection's user. The password is therefore the only
        // private half, and the username has to travel as the user's name.
        Protocol::Http | Protocol::Socks | Protocol::Naive => {
            json!({ "username": name, "password": derive_password(material) })
        }
    };

    Some(entry)
}

/// A UUID from the first half of `material`, version 4 and variant 1, as any
/// client expects one.
fn derive_uuid(material: &[u8; 32]) -> String {
    let mut bytes: [u8; 16] = material[..16].try_into().expect("sixteen bytes");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Uuid::from_bytes(bytes).to_string()
}

/// A password from the second half of `material`.
fn derive_password(material: &[u8; 32]) -> String {
    suba_proto::base64::encode(&material[16..])
}

/// The credential a server keys this user by, for finding two that collide.
///
/// Names the field the core itself keys by, per protocol, so two users the core
/// would consider one are the two this reports as one.
pub fn credential(protocol: Protocol, user: &Value) -> Option<&str> {
    let field = match protocol {
        Protocol::Vless | Protocol::Vmess | Protocol::Tuic => "uuid",
        Protocol::Trojan
        | Protocol::AnyTls
        | Protocol::Hysteria2
        | Protocol::ShadowTls
        | Protocol::Shadowsocks => "password",
        Protocol::Snell => "userkey",
        Protocol::Hysteria => "auth_str",
        // For these the username is the name the core reports, so the pair is
        // the identity and neither half alone is.
        Protocol::Http | Protocol::Socks | Protocol::Naive => "username",
    };

    user.get(field).and_then(Value::as_str)
}

/// The client node that reaches `user` of `inbound` at `host`, named `name`.
///
/// `user_path` is where the user sits, such as `users[2]`, for the reasons that
/// are about the user rather than the inbound.
pub fn client(
    inbound: &Value,
    user: &Value,
    user_path: &str,
    host: &Host,
    name: &str,
) -> Result<Node<Client>, Unexportable> {
    let protocol = grantable(inbound).map_err(|reason| unexportable("type", reason))?;
    let port = inbound
        .get("listen_port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .and_then(Port::new)
        .ok_or_else(|| unexportable("listen_port", "a port clients can dial is needed"))?;
    let tls = tls(inbound, host)?;
    let transport = transport(inbound)?;

    let protocol = match protocol {
        Protocol::Vless => {
            let id = text(user, "uuid")
                .and_then(|id| Uuid::parse(id).ok())
                .ok_or_else(|| {
                    unexportable(format!("{user_path}.uuid"), "only a UUID can be exported")
                })?;
            let flow = match text(user, "flow") {
                None => vless::Flow::None,
                Some(spelling) => vless::Flow::parse(spelling).ok_or_else(|| {
                    unexportable(format!("{user_path}.flow"), "this flow cannot be exported")
                })?,
            };

            Outbound::Vless(vless::Client {
                id: Secret::new(id),
                flow,
                encryption: None,
            })
        }
        Protocol::Vmess => Outbound::Vmess(vmess::Client {
            id: Secret::new(uuid_field(user, user_path)?),
            // Always zero: AEAD is the only header format current clients
            // speak, and a non-zero counter would be a downgrade.
            alter_id: 0,
            security: vmess::Security::Auto,
        }),
        Protocol::Tuic => {
            if tls.is_none() {
                return Err(unexportable("tls", "TUIC runs over TLS"));
            }

            Outbound::Tuic(tuic::Client {
                uuid: Secret::new(uuid_field(user, user_path)?),
                password: password(user, user_path)?,
                congestion_control: Default::default(),
                udp_relay_mode: None,
                zero_rtt_handshake: false,
            })
        }
        Protocol::Trojan => Outbound::Trojan(trojan::Client {
            password: password(user, user_path)?,
        }),
        Protocol::AnyTls => Outbound::AnyTls(anytls::Client {
            password: password(user, user_path)?,
        }),
        Protocol::Hysteria2 => {
            if tls.is_none() {
                return Err(unexportable("tls", "Hysteria2 runs over TLS"));
            }
            let (obfs, obfs_password) = match inbound.get("obfs") {
                None => (None, None),
                Some(obfs) => match text(obfs, "type").map(hysteria2::Obfs::parse) {
                    Some(Some(kind)) => (
                        Some(kind),
                        text(obfs, "password").map(|value| Secret::new(Box::from(value))),
                    ),
                    _ => return Err(unexportable("obfs.type", "only salamander can be exported")),
                },
            };

            Outbound::Hysteria2(hysteria2::Client {
                password: password(user, user_path)?,
                obfs,
                obfs_password,
                ports: None,
                hop_interval: None,
                up: None,
                down: None,
                pin_sha256: None,
            })
        }
        Protocol::Shadowsocks => {
            let method = text(inbound, "method")
                .ok_or_else(|| unexportable("method", "a cipher is needed"))?;
            let user_key = password(user, user_path)?;
            // Multi-user 2022 keys are per-user and the inbound's own password
            // is never a client's: the client carries `<server key>:<user key>`,
            // which is the pair the core splits to find the user.
            let password = match shadowsocks_key_len(method) {
                None => user_key.into_inner(),
                Some(_) => {
                    let server = text(inbound, "password").ok_or_else(|| {
                        unexportable(
                            "password",
                            "multi-user Shadowsocks needs the inbound's own password",
                        )
                    })?;
                    format!("{server}:{}", user_key.as_str()).into_boxed_str()
                }
            };

            Outbound::Shadowsocks(shadowsocks::Client {
                method: Box::from(method),
                password: Secret::new(password),
                plugin: None,
            })
        }
        // A listener this build can dial as a proxy: the user's name is the
        // username, and the credential is the password.
        Protocol::Http => Outbound::Http(http::Client {
            username: Some(Box::from(username(user, user_path)?)),
            password: Some(password(user, user_path)?),
        }),
        Protocol::Socks => Outbound::Socks(socks::Client {
            version: socks::Version::V5,
            username: Some(Box::from(username(user, user_path)?)),
            password: Some(password(user, user_path)?),
        }),
        // Snell, Hysteria v1 and ShadowTLS each need a client shape this build
        // does not have yet. The credential is injected and the core serves it;
        // only the subscription is missing the node.
        Protocol::Snell => {
            return Err(unexportable(
                "type",
                "Snell has no client model yet, so this user's node cannot be written",
            ))
        }
        Protocol::Hysteria => {
            return Err(unexportable(
                "type",
                "Hysteria v1 has no client model yet, so this user's node cannot be written",
            ))
        }
        Protocol::ShadowTls => {
            return Err(unexportable(
                "type",
                "ShadowTLS has no client model yet, so this user's node cannot be written",
            ))
        }
        // Naive serves HTTPS and HTTP/3 rather than a TLS proxy inbound, so it
        // has no client model here even though the credential pair is the same.
        Protocol::Naive => {
            return Err(unexportable(
                "type",
                "Naive has no client model yet, so this user's node cannot be written",
            ))
        }
    };

    Ok(Node {
        name: Name::from(name),
        endpoint: Endpoint::new(host.clone(), port),
        listen: (),
        transport,
        tls,
        protocol,
        extra: RawParams::new(),
    })
}

/// A `uuid` field, parsed.
fn uuid_field(user: &Value, user_path: &str) -> Result<Uuid, Unexportable> {
    text(user, "uuid")
        .and_then(|id| Uuid::parse(id).ok())
        .ok_or_else(|| unexportable(format!("{user_path}.uuid"), "only a UUID can be exported"))
}

/// A `username`, which is what an authenticated listener reports as the user.
fn username<'a>(user: &'a Value, user_path: &str) -> Result<&'a str, Unexportable> {
    text(user, "username")
        .ok_or_else(|| unexportable(format!("{user_path}.username"), "a username is needed"))
}

fn password(user: &Value, user_path: &str) -> Result<Secret<Box<str>>, Unexportable> {
    text(user, "password")
        .map(|value| Secret::new(Box::from(value)))
        .ok_or_else(|| unexportable(format!("{user_path}.password"), "a password is needed"))
}

/// The TLS a client needs, or none when the inbound speaks without it.
fn tls(inbound: &Value, host: &Host) -> Result<Option<TlsClient>, Unexportable> {
    let Some(block) = inbound.get("tls").filter(|block| enabled(Some(block))) else {
        return Ok(None);
    };

    if enabled(block.get("ech")) {
        return Err(unexportable("tls.ech", "ECH cannot be exported yet"));
    }
    if block.get("client_authentication").is_some() || block.get("client_certificate").is_some() {
        return Err(unexportable(
            "tls.client_authentication",
            "a client certificate cannot be exported",
        ));
    }

    let reality = block
        .get("reality")
        .filter(|reality| enabled(Some(reality)));
    let server_name = match text(block, "server_name") {
        Some(name) => Some(
            Host::parse(name).map_err(|_| unexportable("tls.server_name", "not a host name"))?,
        ),
        None if reality.is_some() => {
            return Err(unexportable(
                "tls.server_name",
                "REALITY accepts only this name, so a client needs it",
            ));
        }
        // Without a name of its own, the certificate is the public host's.
        None => host.domain().map(|_| host.clone()),
    };

    let alpn = listed(block.get("alpn"))
        .iter()
        .map(|item| {
            Alpn::parse(item).map_err(|_| unexportable("tls.alpn", "not an ALPN identifier"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let reality = match reality {
        None => None,
        Some(reality) => Some(reality_client(reality)?),
    };

    Ok(Some(TlsClient {
        server_name,
        alpn,
        insecure: false,
        // REALITY runs only behind a uTLS fingerprint on the client.
        fingerprint: reality
            .is_some()
            .then(|| Fingerprint::parse("chrome").expect("a uTLS profile")),
        reality,
        extra: RawParams::new(),
    }))
}

fn reality_client(reality: &Value) -> Result<RealityClient, Unexportable> {
    let private_key = text(reality, "private_key")
        .ok_or_else(|| unexportable("tls.reality.private_key", "the key pair is needed"))?;
    // Deriving needs only the private key; the handshake server stays here.
    let server = RealityServer::new(
        private_key,
        Endpoint::new(
            Host::parse("localhost").expect("a host"),
            Port::new(443).expect("a port"),
        ),
    );
    let public_key = server.derive_public_key().map_err(|_| {
        unexportable(
            "tls.reality.private_key",
            "not a key a public key derives from",
        )
    })?;

    let mut client = RealityClient::new(public_key);
    client.short_id = match listed(reality.get("short_id")).first() {
        None => None,
        Some(id) => Some(
            ShortId::parse(id)
                .map_err(|_| unexportable("tls.reality.short_id", "not a short id"))?,
        ),
    };

    Ok(client)
}

/// How the inbound carries the protocol, as a client has to.
fn transport(inbound: &Value) -> Result<Transport, Unexportable> {
    let Some(block) = inbound.get("transport") else {
        return Ok(Transport::Tcp);
    };

    match text(block, "type") {
        Some("ws") => Ok(Transport::Ws(Ws {
            path: Box::from(text(block, "path").unwrap_or("/")),
            host: None,
            early_data: block
                .get("max_early_data")
                .and_then(Value::as_u64)
                .filter(|length| *length > 0)
                .and_then(|length| u32::try_from(length).ok()),
            header_name: text(block, "early_data_header_name").map(Box::from),
            extra: RawParams::new(),
        })),
        Some("grpc") => Ok(Transport::Grpc(Grpc {
            service_name: Box::from(text(block, "service_name").unwrap_or_default()),
            authority: None,
            multi_mode: false,
            extra: RawParams::new(),
        })),
        Some("httpupgrade") => Ok(Transport::HttpUpgrade(HttpUpgrade {
            // The server compares the Host header with this one when it is set.
            host: match text(block, "host") {
                None => None,
                Some(host) => Some(
                    Host::parse(host)
                        .map_err(|_| unexportable("transport.host", "not a host name"))?,
                ),
            },
            path: Box::from(text(block, "path").unwrap_or("/")),
            extra: RawParams::new(),
        })),
        _ => Err(unexportable(
            "transport.type",
            "this transport cannot be exported yet",
        )),
    }
}

/// A non-empty string field.
fn text<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// A field the core accepts as one string or a list of them.
fn listed(value: Option<&Value>) -> Vec<&str> {
    match value {
        Some(Value::String(one)) if !one.is_empty() => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// Whether an options block is there and switched on.
fn enabled(block: Option<&Value>) -> bool {
    block
        .and_then(|block| block.get("enabled"))
        .and_then(Value::as_bool)
        == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use suba_proto::write_link;

    // A throwaway X25519 key; its public half is what a client is given.
    const PRIVATE_KEY: &str = "UPLJ7jF8V4gCQx8Fq4aJ3ux3Tx7GgSj2dX8JX0X7S2E";

    fn host() -> Host {
        Host::parse("proxy.example.com").unwrap()
    }

    fn reality() -> Value {
        json!({
            "type": "vless",
            "tag": "vless-in",
            "listen_port": 443,
            "tls": {
                "enabled": true,
                "server_name": "www.example.org",
                "reality": {
                    "enabled": true,
                    "handshake": { "server": "www.example.org", "server_port": 443 },
                    "private_key": PRIVATE_KEY,
                    "short_id": ["0123abcd", "ffff"]
                }
            },
            "users": []
        })
    }

    /// Every inbound type the shipped schema knows, and whether it exposes a
    /// `users` field. Frozen here because the schema is a runtime artefact:
    /// `data/sing-box/versions/<v>/schema.json`, `$defs.Inbound`, 1.14.3.
    ///
    /// The rule the owner set is exactly this list minus `mixed`: an inbound
    /// that has nowhere to put a user cannot be granted one, and `mixed` is the
    /// one that has a place and still must not, because it is the plaintext
    /// local entry.
    const SCHEMA_INBOUNDS: &[(&str, bool)] = &[
        ("anytls", true),
        ("cloudflared", false),
        ("direct", false),
        ("http", true),
        ("hysteria", true),
        ("hysteria2", true),
        ("mixed", true),
        ("naive", true),
        ("redirect", false),
        ("shadowsocks", true),
        ("shadowtls", true),
        ("snell", true),
        ("socks", true),
        ("tproxy", false),
        ("trojan", true),
        ("tuic", true),
        ("tun", false),
        ("vless", true),
        ("vmess", true),
    ];

    /// Every protocol whose inbound takes per-user credentials is grantable,
    /// and what cannot be is refused with the reason that makes it true.
    #[test]
    fn every_protocol_with_users_is_grantable_and_the_rest_say_why() {
        assert_eq!(grantable(&reality()), Ok(Protocol::Vless));
        for (kind, protocol) in [
            ("trojan", Protocol::Trojan),
            ("vmess", Protocol::Vmess),
            ("tuic", Protocol::Tuic),
            ("anytls", Protocol::AnyTls),
            ("hysteria2", Protocol::Hysteria2),
            ("hysteria", Protocol::Hysteria),
            ("shadowtls", Protocol::ShadowTls),
            ("snell", Protocol::Snell),
            ("http", Protocol::Http),
            ("socks", Protocol::Socks),
            ("naive", Protocol::Naive),
        ] {
            assert_eq!(grantable(&json!({ "type": kind })), Ok(protocol), "{kind}");
        }

        // Shadowsocks is a mode, not just a type: only a multi-user one, with
        // the inbound's own key and a cipher that has per-user keys.
        let ss = |method: &str, extra: Value| {
            let mut inbound =
                json!({"type": "shadowsocks", "method": method, "password": "c2VydmVy"});
            for (key, value) in extra.as_object().unwrap() {
                inbound[key] = value.clone();
            }
            inbound
        };
        assert_eq!(
            grantable(&ss("aes-256-gcm", json!({}))),
            Ok(Protocol::Shadowsocks)
        );
        assert_eq!(
            grantable(&ss("2022-blake3-aes-256-gcm", json!({}))),
            Ok(Protocol::Shadowsocks)
        );
        assert_eq!(
            grantable(&ss("2022-blake3-aes-128-gcm", json!({}))),
            Ok(Protocol::Shadowsocks)
        );
        for (method, reason) in [
            (
                "2022-blake3-chacha20-poly1305",
                "this cipher cannot have more than one user",
            ),
            (
                "aes-256-gcm",
                "multi-user Shadowsocks needs the inbound's own password",
            ),
        ] {
            let mut inbound = ss(method, json!({}));
            if reason.contains("own password") {
                inbound.as_object_mut().unwrap().remove("password");
            }
            assert_eq!(grantable(&inbound), Err(reason), "{method}");
        }
        assert_eq!(
            grantable(&ss(
                "aes-256-gcm",
                json!({"destinations": [{"name": "d", "server": "x.example.com", "server_port": 443, "password": "x"}]})
            )),
            Err("a relay inbound takes destinations, not users")
        );
        assert_eq!(
            grantable(&ss("aes-256-gcm", json!({"managed": true}))),
            Err("a managed Shadowsocks server sizes its own users")
        );

        for (kind, reason) in [
            // The schema gives `mixed` a `users` field, so this refusal is a
            // product decision rather than a capability gap, and it says so.
            (
                "mixed",
                "a mixed listener is a local entry; users are not granted on it",
            ),
            ("shadowsocksr", "ShadowsocksR is removed from sing-box"),
            ("direct", "this is not a proxy inbound users dial"),
            ("tun", "this is not a proxy inbound users dial"),
            ("nonsense", "this inbound has no users"),
        ] {
            assert_eq!(grantable(&json!({ "type": kind })), Err(reason), "{kind}");
        }
    }

    /// The rule, over the schema's own inbound list rather than a hand-picked
    /// few: granted when there is a `users` field, refused when there is not,
    /// and `mixed` refused despite having one.
    #[test]
    fn what_can_be_granted_is_exactly_what_has_a_place_for_a_user() {
        for (kind, has_users) in SCHEMA_INBOUNDS {
            let inbound = json!({ "type": kind, "method": "aes-256-gcm", "password": "c2VydmVy" });
            let granted = grantable(&inbound).is_ok();
            let expected = *has_users && *kind != "mixed";

            assert_eq!(granted, expected, "{kind} (users field: {has_users})");
            if let Err(reason) = grantable(&inbound) {
                assert!(
                    !reason.contains("not yet") && !reason.contains("unsupported"),
                    "{kind} is refused for a reason that does not name the cause: {reason}"
                );
            }
        }

        // A type the schema does not know — a misspelling, or a protocol a
        // newer core added — is refused rather than granted by falling through.
        for kind in ["nonsense", "wireguard", "ssh", "tor", "shadowsocksr", ""] {
            assert!(
                grantable(&json!({ "type": kind })).is_err(),
                "{kind} must not be granted"
            );
        }
    }

    /// Each protocol gets the entry the core reads, with the field that
    /// protocol keys a user by.
    #[test]
    fn a_user_carries_the_field_its_protocol_keys_by() {
        let material = [9u8; 32];
        let simple = |kind: &str| json!({ "type": kind, "listen_port": 1080 });

        // A credential that only a UUID can be, and a second half only a
        // password can be: two protocols needing one each never repeat.
        let uuid_of = |entry: &Value| entry["uuid"].as_str().unwrap().to_owned();
        let vmess = user(Protocol::Vmess, &simple("vmess"), "a", &material).unwrap();
        assert_eq!(vmess["alterId"], json!(0));
        assert_eq!(credential(Protocol::Vmess, &vmess), Some(&*uuid_of(&vmess)));
        let vless = user(Protocol::Vless, &simple("vless"), "a", &material).unwrap();
        assert_eq!(
            uuid_of(&vless),
            uuid_of(&vmess),
            "one UUID per (user, inbound)"
        );

        let tuic = user(Protocol::Tuic, &simple("tuic"), "a", &material).unwrap();
        assert_eq!(uuid_of(&tuic), uuid_of(&vless));
        assert!(tuic["password"].is_string());
        assert_eq!(credential(Protocol::Tuic, &tuic), Some(&*uuid_of(&tuic)));

        for (protocol, kind) in [
            (Protocol::Trojan, "trojan"),
            (Protocol::AnyTls, "anytls"),
            (Protocol::Hysteria2, "hysteria2"),
            (Protocol::ShadowTls, "shadowtls"),
        ] {
            let entry = user(protocol, &simple(kind), "a", &material).unwrap();
            assert!(entry["password"].is_string(), "{kind}");
            assert!(entry.get("uuid").is_none(), "{kind}");
            assert_eq!(credential(protocol, &entry), entry["password"].as_str());
        }

        // Snell names its per-user key after what it is beside the inbound's psk.
        let snell = user(Protocol::Snell, &simple("snell"), "a", &material).unwrap();
        assert!(snell["userkey"].is_string());
        assert!(snell.get("password").is_none());
        assert_eq!(
            credential(Protocol::Snell, &snell),
            snell["userkey"].as_str()
        );

        // Hysteria v1 names it after what it is: an auth beside the inbound's obfs.
        let hysteria = user(Protocol::Hysteria, &simple("hysteria"), "a", &material).unwrap();
        assert!(hysteria["auth_str"].is_string());
        assert!(hysteria.get("password").is_none());
        assert_eq!(
            credential(Protocol::Hysteria, &hysteria),
            hysteria["auth_str"].as_str()
        );

        // `auth.User` is `username` and `password` and no `name` at all.
        for (protocol, kind) in [
            (Protocol::Http, "http"),
            (Protocol::Socks, "socks"),
            (Protocol::Naive, "naive"),
        ] {
            let entry = user(protocol, &simple(kind), "a", &material).unwrap();
            assert_eq!(entry["username"], json!("a"), "{kind}");
            assert!(entry["password"].is_string(), "{kind}");
            assert!(entry.get("name").is_none(), "{kind}");
            assert_eq!(credential(protocol, &entry), Some("a"));
        }
    }

    /// A Shadowsocks user key has to be the cipher's own length, and what a
    /// client carries is the pair the core splits.
    #[test]
    fn a_shadowsocks_key_matches_its_cipher_and_a_client_pairs_it() {
        let material = [4u8; 32];
        let ss = |method: &str| json!({"type": "shadowsocks", "method": method, "listen_port": 1080, "password": "c2VydmVy"});

        // Legacy AEAD takes any password, so the derived one is used as it is.
        let legacy = ss("aes-256-gcm");
        let key = user(Protocol::Shadowsocks, &legacy, "a", &material).unwrap();
        let raw = key["password"].as_str().unwrap().to_owned();
        let node = client(&legacy, &key, "users[0]", &host(), "ss").unwrap();
        assert!(
            matches!(node.protocol, Outbound::Shadowsocks(ref ss) if ss.password.as_str() == raw),
            "a legacy client carries its own password"
        );

        // 2022 keys carry the cipher's length, and the client's is the pair.
        for (method, raw_len, encoded_len) in [
            ("2022-blake3-aes-128-gcm", 16, 24),
            ("2022-blake3-aes-256-gcm", 32, 44),
        ] {
            let inbound = ss(method);
            let user = user(Protocol::Shadowsocks, &inbound, "a", &material).unwrap();
            let key = user["password"].as_str().unwrap();
            assert_eq!(key.len(), encoded_len, "{method}");

            let node = client(&inbound, &user, "users[0]", &host(), "ss").unwrap();
            let Outbound::Shadowsocks(ref client) = node.protocol else {
                panic!("{method} is a Shadowsocks outbound")
            };
            assert_eq!(client.password.as_str(), format!("c2VydmVy:{key}"));
            assert_eq!(
                client
                    .password
                    .as_str()
                    .split(':')
                    .next_back()
                    .unwrap()
                    .len(),
                encoded_len,
                "{method}"
            );
            let _ = raw_len;
        }
    }

    #[test]
    fn vision_follows_the_inbound_shape() {
        assert_eq!(flow(&reality()), Some("xtls-rprx-vision"));

        let mut carried = reality();
        carried["transport"] = json!({"type": "ws", "path": "/vl"});
        assert_eq!(
            flow(&carried),
            None,
            "Vision needs the TLS connection itself"
        );

        let mut multiplexed = reality();
        multiplexed["multiplex"] = json!({"enabled": true});
        assert_eq!(flow(&multiplexed), None);

        let mut plain = reality();
        plain["tls"]["enabled"] = json!(false);
        assert_eq!(flow(&plain), None);

        assert_eq!(
            flow(&json!({"type": "trojan", "tls": {"enabled": true}})),
            None
        );
    }

    #[test]
    fn a_user_is_shaped_for_its_protocol() {
        let material = [7u8; 32];

        let vless = user(Protocol::Vless, &reality(), "alice", &material).unwrap();
        let id = vless["uuid"].as_str().unwrap();
        assert_eq!(&id[14..15], "4", "a version 4 UUID: {id}");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"), "{id}");
        assert_eq!(vless["flow"], json!("xtls-rprx-vision"));
        assert_eq!(vless["name"], json!("alice"));

        let trojan = user(
            Protocol::Trojan,
            &json!({"type": "trojan"}),
            "bob",
            &material,
        )
        .unwrap();
        assert_eq!(trojan["password"].as_str().unwrap().len(), 22);
        assert!(trojan.get("uuid").is_none());
        assert_eq!(
            credential(Protocol::Trojan, &trojan),
            trojan["password"].as_str()
        );
    }

    #[test]
    fn a_reality_user_exports_with_the_derived_key_and_the_inbound_name() {
        let inbound = reality();
        let user = user(Protocol::Vless, &inbound, "alice", &[1u8; 32]).unwrap();

        let node = client(&inbound, &user, "users[0]", &host(), "vless-in").unwrap();
        let link = write_link(&node).unwrap();

        assert!(link.starts_with("vless://"), "{link}");
        assert!(link.contains("@proxy.example.com:443"), "{link}");
        assert!(link.contains("sni=www.example.org"), "{link}");
        assert!(link.contains("sid=0123abcd"), "{link}");
        assert!(link.contains("fp=chrome"), "{link}");
        assert!(link.contains("flow=xtls-rprx-vision"), "{link}");
        assert!(
            !link.contains(PRIVATE_KEY),
            "the private key stays on the server"
        );

        let tls = node.tls.unwrap();
        let derived = tls.reality.unwrap().public_key.expose().to_string();
        assert_eq!(derived.len(), 43, "a 32-byte key, URL-safe base64");
    }

    #[test]
    fn reality_without_a_server_name_is_not_exported() {
        let mut inbound = reality();
        inbound["tls"]
            .as_object_mut()
            .unwrap()
            .remove("server_name");
        let user = user(Protocol::Vless, &inbound, "alice", &[1u8; 32]).unwrap();

        let refused = client(&inbound, &user, "users[0]", &host(), "x").unwrap_err();

        assert_eq!(refused.path, "tls.server_name");
    }

    #[test]
    fn a_plain_tls_inbound_lends_the_public_host_as_its_name() {
        let inbound = json!({
            "type": "trojan",
            "listen_port": 8443,
            "tls": { "enabled": true },
            "transport": { "type": "ws", "path": "/ws" }
        });
        let user = user(Protocol::Trojan, &inbound, "bob", &[2u8; 32]).unwrap();

        let node = client(&inbound, &user, "users[0]", &host(), "trojan-ws").unwrap();

        assert_eq!(node.tls.unwrap().server_name, Some(host()));
        assert!(matches!(node.transport, Transport::Ws(ref ws) if &*ws.path == "/ws"));
    }

    #[test]
    fn what_a_client_cannot_be_told_is_refused_with_its_field() {
        let mut ech = reality();
        ech["tls"]["ech"] = json!({"enabled": true});
        let mut gecko = json!({
            "type": "hysteria2",
            "listen_port": 8444,
            "tls": {"enabled": true, "server_name": "proxy.example.com"},
            "obfs": {"type": "gecko", "password": "x"}
        });
        let plain_hysteria = json!({"type": "hysteria2", "listen_port": 8444});
        let mut quic = reality();
        quic["transport"] = json!({"type": "quic"});

        let cases = [
            (&ech, "tls.ech"),
            (&gecko, "obfs.type"),
            (&plain_hysteria, "tls"),
            (&quic, "transport.type"),
        ];
        for (inbound, path) in cases {
            let protocol = grantable(inbound).unwrap();
            let user = user(protocol, inbound, "x", &[3u8; 32]).unwrap();
            assert_eq!(
                client(inbound, &user, "users[0]", &host(), "x")
                    .unwrap_err()
                    .path,
                path
            );
        }

        gecko["obfs"]["type"] = json!("salamander");
        let user = user(Protocol::Hysteria2, &gecko, "x", &[3u8; 32]).unwrap();
        let node = client(&gecko, &user, "users[0]", &host(), "hy2").unwrap();
        assert!(write_link(&node).unwrap().contains("obfs=salamander"));
    }

    #[test]
    fn a_hand_written_user_that_is_not_a_uuid_says_which_one() {
        let inbound = reality();
        let user = json!({"name": "carol", "uuid": "not-a-uuid"});

        let refused = client(&inbound, &user, "users[3]", &host(), "x").unwrap_err();

        assert_eq!(refused.path, "users[3].uuid");
    }
}
