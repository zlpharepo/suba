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
use suba_proto::protocol::{hysteria2, trojan, vless};
use suba_proto::tls::{Alpn, Fingerprint, RealityClient, RealityServer, ShortId};
use suba_proto::transport::{Grpc, HttpUpgrade, Ws};
use suba_proto::{
    Client, Endpoint, Host, Name, Node, Outbound, Port, RawParams, Secret, TlsClient, Transport,
    Uuid,
};

/// The protocols a managed user can be granted on today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Vless,
    Trojan,
    Hysteria2,
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
        Some("hysteria2") => Ok(Protocol::Hysteria2),
        Some("vmess" | "tuic" | "anytls" | "shadowsocks") => {
            Err("this protocol is not granted to users yet")
        }
        Some("naive" | "hysteria" | "snell") => Err("this protocol cannot be exported yet"),
        Some("shadowtls") => {
            Err("ShadowTLS wraps another inbound, whose users are the ones to grant")
        }
        // Without users these listen with no authentication at all, so a
        // grant would quietly turn authentication on for everyone else.
        Some("mixed" | "http" | "socks") => {
            Err("an inbound without users needs no authentication; a grant would require it")
        }
        _ => Err("this inbound has no users"),
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
/// needs both never repeats one in the other.
pub fn user(protocol: Protocol, inbound: &Value, name: &str, material: &[u8; 32]) -> Value {
    match protocol {
        Protocol::Vless => {
            let mut bytes: [u8; 16] = material[..16].try_into().expect("sixteen bytes");
            // Version 4, variant 1: a random UUID, as any client expects one.
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;

            let mut entry = json!({ "name": name, "uuid": Uuid::from_bytes(bytes).to_string() });
            if let Some(flow) = flow(inbound) {
                entry["flow"] = json!(flow);
            }
            entry
        }
        Protocol::Trojan | Protocol::Hysteria2 => json!({
            "name": name,
            "password": suba_proto::base64::encode(&material[16..]),
        }),
    }
}

/// The credential a server keys this user by, for finding two that collide.
pub fn credential(protocol: Protocol, user: &Value) -> Option<&str> {
    let field = match protocol {
        Protocol::Vless => "uuid",
        Protocol::Trojan | Protocol::Hysteria2 => "password",
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
        Protocol::Trojan => Outbound::Trojan(trojan::Client {
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

    #[test]
    fn only_the_first_protocols_are_grantable_and_the_rest_say_why() {
        assert_eq!(grantable(&reality()), Ok(Protocol::Vless));
        assert_eq!(grantable(&json!({"type": "trojan"})), Ok(Protocol::Trojan));
        assert_eq!(
            grantable(&json!({"type": "hysteria2"})),
            Ok(Protocol::Hysteria2)
        );

        for kind in ["vmess", "mixed", "shadowtls", "naive", "tun"] {
            assert!(grantable(&json!({ "type": kind })).is_err(), "{kind}");
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

        let vless = user(Protocol::Vless, &reality(), "alice", &material);
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
        );
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
        let user = user(Protocol::Vless, &inbound, "alice", &[1u8; 32]);

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
        let user = user(Protocol::Vless, &inbound, "alice", &[1u8; 32]);

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
        let user = user(Protocol::Trojan, &inbound, "bob", &[2u8; 32]);

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
            let user = user(protocol, inbound, "x", &[3u8; 32]);
            assert_eq!(
                client(inbound, &user, "users[0]", &host(), "x")
                    .unwrap_err()
                    .path,
                path
            );
        }

        gecko["obfs"]["type"] = json!("salamander");
        let user = user(Protocol::Hysteria2, &gecko, "x", &[3u8; 32]);
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
