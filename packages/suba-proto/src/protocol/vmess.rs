//! VMess.
//!
//! VMess is the first protocol here whose link is **not a query string**. A `vmess://` link is a
//! base64 blob containing a JSON object, and everything the other protocols spread over parameters —
//! address, port, transport, TLS, name — lives inside it:
//!
//! ```text
//! vmess://eyJ2IjoiMiIsInBzIjoiVG9reW8iLCJhZGQiOiJleGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6Ii4uLiJ9
//! ```
//!
//! That is why this module owns its whole link rather than a set of parameters, and why the crate
//! dispatches to it before it parses anything shared: there is nothing shared to parse. The JSON keys
//! are the ones every client writes (`v`, `ps`, `add`, `port`, `id`, `aid`, `scy`, `net`, `type`,
//! `host`, `path`, `tls`, `sni`, `alpn`, `fp`), which is a spelling the community owns rather than any
//! one implementation.
//!
//! ### What happens to a key this module does not name
//!
//! Nothing, and that is a decision rather than an omission. Extras exist so that a query parameter no
//! protocol claimed can be written back in the shape it arrived in; this dialect has no query
//! parameters, and the model has no field to hold a JSON object in. So an extension key is not carried
//! by the node at all: it is *replayed*, because the record around the node keeps the link as it
//! arrived (`Provenance::raw`, `NodeRecord::raw`) and re-reading that link is what reproduces the
//! provider's own bytes. Writing a node back out therefore writes the fields this crate models —
//! quietly dropping them would be the alternative, and it is worse than saying so here.

use core::fmt;

use base64::Engine as _;

use crate::addr::{Endpoint, Host, Port};
use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::Link;
use crate::node::{self, Node};
use crate::params::RawParams;
use crate::prelude::*;
use crate::protocol::{ClientLink, Kind, LinkParts, Outbound, Protocol};
use crate::secret::Secret;
use crate::tls::{Alpn, Fingerprint, TlsClient};
use crate::transport::{self, Transport};
use crate::uuid::Uuid;

/// The encryption VMess negotiates on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Security {
    /// Negotiate with the client's own choice, which is what almost every node uses.
    #[default]
    Auto,
    /// No encryption: authentication only.
    None,
    /// AES-128-GCM.
    Aes128Gcm,
    /// ChaCha20-Poly1305.
    Chacha20Poly1305,
    /// Zero overhead, VMess AEAD only.
    Zero,
}

impl Security {
    /// The spelling the link and the wire use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::None => "none",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
            Self::Zero => "zero",
        }
    }

    /// Read the spelling. An unknown one is `None` rather than a guess.
    pub fn parse(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "none" => Some(Self::None),
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            "zero" => Some(Self::Zero),
            _ => None,
        }
    }
}

impl fmt::Display for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A VMess client: one user id, and the header format the two sides agree on.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The user id.
    pub id: Secret<Uuid>,
    /// The header obfuscation counter. Zero is AEAD, and what every current client uses.
    pub alter_id: u16,
    /// The encryption to negotiate.
    pub security: Security,
}

/// One user on a VMess listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The user id.
    pub id: Secret<Uuid>,
    /// The header obfuscation counter this user is allowed.
    pub alter_id: u16,
    /// The encryption this user may negotiate.
    pub security: Security,
    /// The user's level, which VMess carries but nothing enforces.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub level: Option<u8>,
}

/// A VMess listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// Everyone allowed in.
    pub users: Vec<User>,
}

impl Server {
    /// Whether there is anyone who can get in.
    pub fn is_complete(&self) -> bool {
        !self.users.is_empty()
    }
}

// No `Default` anywhere here: an empty listener and a client with a nil id are decisions, not
// something a derive should hand out by accident.
impl Client {
    /// A client.
    pub fn new(id: Uuid) -> Self {
        Self {
            id: Secret::new(id),
            alter_id: 0,
            security: Security::Auto,
        }
    }

    /// The user id.
    pub fn uuid(&self) -> &Uuid {
        self.id.expose()
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Vmess
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.id.expose().is_nil()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Vmess
    }

    fn scheme(&self) -> &str {
        <Client as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        self.is_complete()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

/// Read a whole `vmess://` link.
///
/// Not a `from_query`: there is no query. The blob is base64, the JSON inside it is the link, and the
/// address, the carriage and the TLS settings all come out of the same object.
pub(crate) fn parse(link: &Link<'_>) -> Result<LinkParts> {
    let blob = link
        .raw()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let blob = blob.split('#').next().unwrap_or(blob).trim();

    let json = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(blob))
        .map_err(|_| Error::field(ErrorKind::InvalidBase64, "vmess link"))?;

    let json = core::str::from_utf8(&json)
        .map_err(|_| Error::field(ErrorKind::InvalidValue, "vmess link"))?;

    let object: serde_json::Value = serde_json::from_str(json)
        .map_err(|_| Error::field(ErrorKind::InvalidValue, "vmess link"))?;

    let text = |key: &str| -> Option<&str> { object.get(key).and_then(|value| value.as_str()) };
    let missing = |field: &'static str| Error::field(ErrorKind::MissingField, field);

    let host = text("add").ok_or_else(|| missing("add"))?;
    // The port arrives as a string from half the generators and as a number from the other half, and
    // both spellings go through the same range check: a port is a port.
    let port = match object.get("port") {
        None => return Err(missing("port")),
        Some(serde_json::Value::String(text)) => Port::parse(text)?,
        Some(value) => scalar(value)
            .and_then(|port| u16::try_from(port).ok())
            .and_then(Port::new)
            .ok_or_else(|| Error::field(ErrorKind::InvalidPort, "port"))?,
    };
    let endpoint = Endpoint {
        host: Host::parse(host)?,
        port,
    };

    let id = text("id").ok_or_else(|| missing("id"))?;
    let alter_id = match object.get("aid") {
        None => 0,
        Some(serde_json::Value::String(text)) if text.is_empty() => 0,
        Some(value) => scalar(value)
            .and_then(|aid| u16::try_from(aid).ok())
            .ok_or_else(|| Error::field(ErrorKind::InvalidValue, "aid"))?,
    };
    let security = text("scy").and_then(Security::parse).unwrap_or_default();

    let transport = transport_from(text, endpoint.host.clone())?;
    let tls = tls_from(text, endpoint.host.clone())?;

    Ok(LinkParts {
        endpoint,
        name: text("ps").filter(|name| !name.is_empty()).map(Box::from),
        tls,
        transport,
        // A whole-object dialect has nowhere to put a parameter the model does not name: extras are a
        // parameter list, and this dialect has none. See the note at the top of the module.
        extra: RawParams::new(),
        protocol: Outbound::Vmess(Client {
            id: Secret::new(Uuid::parse(id)?),
            alter_id,
            security,
        }),
    })
}

/// The carriage, from the keys the community uses for it.
/// A JSON field a generator may have written as a string or as a number.
///
/// Both spellings are in the wild for the same value — `"port": 443` and `"port": "443"` — so both are
/// read, and the caller range-checks whichever it gets.
fn scalar(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn transport_from<'a>(text: impl Fn(&str) -> Option<&'a str>, host: Host) -> Result<Transport> {
    let kind = text("net").unwrap_or("tcp").to_ascii_lowercase();
    let path = text("path").filter(|value| !value.is_empty());
    let header = text("type").filter(|value| !value.is_empty());
    let ws_host = text("host")
        .filter(|value| !value.is_empty())
        .and_then(|value| Host::parse(value).ok());

    Ok(match kind.as_str() {
        "" | "tcp" | "raw" => match header {
            // A TCP carriage with an HTTP header is the shape VMess calls `tcp+http`.
            Some(header) => Transport::Other(transport::Other {
                name: format!("tcp+{header}").into_boxed_str(),
                extra: crate::params::RawParams::new(),
            }),
            None => Transport::Tcp,
        },
        // This dialect has no early data and no header name for it: what it carries is the path and
        // the host.
        "ws" | "websocket" => Transport::Ws(transport::Ws {
            path: path.map_or_else(|| Box::from("/"), Box::from),
            host: ws_host,
            early_data: None,
            // This dialect carries neither early data nor a header name for it.
            header_name: None,
            extra: crate::params::RawParams::new(),
        }),
        "grpc" | "gun" => Transport::Grpc(transport::Grpc {
            service_name: path.map_or_else(Box::default, Box::from),
            authority: ws_host,
            multi_mode: false,
            extra: crate::params::RawParams::new(),
        }),
        // `http` is Xray's own alias for `h2` — `infra/conf/transport_internet.go` maps
        // `"h2", "h3", "http"` to one transport — so an `http` here is HTTP/2. (Mihomo's
        // `network: http` is a different carriage, the HTTP/1.1 one; this dialect is not that dialect.)
        "h2" | "http" => Transport::Http2(transport::Http2 {
            host: ws_host,
            path: path.map(Box::from),
            extra: crate::params::RawParams::new(),
        }),
        "httpupgrade" | "http-upgrade" => Transport::HttpUpgrade(transport::HttpUpgrade {
            host: ws_host,
            path: path.map_or_else(|| Box::from("/"), Box::from),
            extra: crate::params::RawParams::new(),
        }),
        "quic" => Transport::Quic(transport::Quic {
            security: transport::QuicSecurity::None,
            key: Secret::new(Box::from("")),
            header: header.map(Box::from),
            extra: crate::params::RawParams::new(),
        }),
        other => {
            let _ = host;

            Transport::Other(transport::Other {
                name: Box::from(other),
                extra: crate::params::RawParams::new(),
            })
        }
    })
}

/// TLS, from the keys the community uses for it.
fn tls_from<'a>(text: impl Fn(&str) -> Option<&'a str>, host: Host) -> Result<Option<TlsClient>> {
    let enabled = matches!(
        text("tls").map(str::to_ascii_lowercase).as_deref(),
        Some("tls") | Some("reality") | Some("1") | Some("true")
    );

    if !enabled {
        return Ok(None);
    }

    let alpn = text("alpn")
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .split(',')
                .filter_map(|id| Alpn::parse(id.trim()).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(TlsClient {
        server_name: text("sni")
            .filter(|value| !value.is_empty())
            .and_then(|value| Host::parse(value).ok())
            .or(Some(host)),
        alpn,
        insecure: false,
        fingerprint: text("fp")
            .filter(|value| !value.is_empty())
            .and_then(|value| Fingerprint::parse(value).ok()),
        reality: None,
        extra: crate::params::RawParams::new(),
    }))
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Vmess;
    const SCHEME: &'static str = "vmess";

    /// Never called: a `vmess://` link has no query, so [`parse`] owns the whole link instead.
    fn from_query(_reader: &mut crate::link::Reader<'_>, _userinfo: &str) -> Result<Self> {
        Err(Error::field(
            ErrorKind::MalformedLink,
            "vmess (this dialect is a whole-link format)",
        ))
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        let host = node.endpoint.host.to_string();
        let mut object = serde_json::Map::new();

        object.insert("v".into(), "2".into());
        object.insert("ps".into(), node.name.as_str().into());
        object.insert("add".into(), host.into());
        object.insert("port".into(), node.endpoint.port.get().to_string().into());
        object.insert("id".into(), self.id.expose().to_string().into());
        object.insert("aid".into(), self.alter_id.to_string().into());
        object.insert("scy".into(), self.security.as_str().into());

        let (net, header, path, ws_host) = carriage_for_link(&node.transport);
        object.insert("net".into(), net.into());

        if let Some(header) = header {
            object.insert("type".into(), header.into());
        }

        if let Some(path) = path {
            object.insert("path".into(), path.into());
        }

        if let Some(ws_host) = ws_host {
            object.insert("host".into(), ws_host.into());
        }

        if let Some(tls) = &node.tls {
            object.insert("tls".into(), "tls".into());

            if let Some(server_name) = &tls.server_name {
                object.insert("sni".into(), server_name.to_string().into());
            }

            if !tls.alpn.is_empty() {
                let mut list = String::new();

                for (index, id) in tls.alpn.iter().enumerate() {
                    if index > 0 {
                        list.push(',');
                    }

                    list.push_str(id.as_str());
                }

                object.insert("alpn".into(), list.into());
            }

            if let Some(fingerprint) = &tls.fingerprint {
                object.insert("fp".into(), fingerprint.as_str().into());
            }
        }

        let json = serde_json::Value::Object(object).to_string();
        out.push_str(Self::SCHEME);
        out.push_str("://");
        out.push_str(&base64::engine::general_purpose::STANDARD.encode(json));

        Ok(())
    }
}

/// The keys a link writes for a carriage, and what it cannot say.
fn carriage_for_link(transport: &Transport) -> (&str, Option<&str>, Option<&str>, Option<String>) {
    match transport {
        Transport::Tcp => ("tcp", None, None, None),
        Transport::Ws(ws) => (
            "ws",
            None,
            Some(ws.path.as_ref()),
            ws.host.as_ref().map(|host| host.to_string()),
        ),
        Transport::Grpc(grpc) => (
            "grpc",
            None,
            Some(grpc.service_name.as_ref()),
            grpc.authority.as_ref().map(|host| host.to_string()),
        ),
        Transport::Http2(http) => (
            "h2",
            None,
            http.path.as_deref(),
            http.host.as_ref().map(|host| host.to_string()),
        ),
        Transport::HttpUpgrade(upgrade) => (
            "httpupgrade",
            None,
            Some(upgrade.path.as_ref()),
            upgrade.host.as_ref().map(|host| host.to_string()),
        ),
        Transport::Quic(quic) => ("quic", quic.header.as_deref(), None, None),
        Transport::Other(other) => match other.name.split_once('+') {
            Some(("tcp", header)) => ("tcp", Some(header), None, None),
            // A carriage this build does not model goes back out under its own name. Writing `tcp`
            // here is what the fuzzer caught: `net=us` came back as `net=tcp`, and a node whose
            // identity depends on whether it has been written out yet is not a node.
            _ => (other.name.as_ref(), None, None, None),
        },
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.display(self.id.expose());
        out.number(self.alter_id as u64);
        out.text(self.security.as_str());
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| {
            out.display(user.id.expose());
            out.number(user.alter_id as u64);
            out.text(user.security.as_str());
            out.number(user.level.unwrap_or(0) as u64);
        });
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("vmess::Client")
            .field("id", &self.id)
            .field("alter_id", &self.alter_id)
            .field("security", &self.security)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link};

    /// `{"v":"2","ps":"Tokyo","add":"example.com","port":"443","id":"…","aid":"0","scy":"auto",
    ///   "net":"ws","path":"/ws","host":"cdn.example.com","tls":"tls","sni":"www.apple.com"}`.
    fn link() -> String {
        let json = r#"{"v":"2","ps":"Tokyo","add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","path":"/ws","host":"cdn.example.com","tls":"tls","sni":"www.apple.com","alpn":"h2,http/1.1","fp":"chrome"}"#;

        format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }

    /// The same link with the port and the aid written as JSON numbers, which half the generators do.
    fn numeric_link() -> String {
        let json = r#"{"v":2,"ps":"Tokyo","add":"example.com","port":443,"id":"11111111-2222-3333-4444-555555555555","aid":0,"scy":"auto","net":"tcp"}"#;

        format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        )
    }

    #[test]
    fn a_numeric_port_and_aid_read_like_the_string_spelling() {
        let numeric = parse_link(&numeric_link()).unwrap();

        assert_eq!(numeric.endpoint.to_string(), "example.com:443");
        assert_eq!(numeric.protocol.as_vmess().unwrap().alter_id, 0);

        // Both spellings of the same link are the same node.
        let textual = numeric_link().replace("\"port\":443", "\"port\":\"443\"");
        assert_eq!(parse_link(&textual).unwrap(), numeric);
    }

    #[test]
    fn an_httpupgrade_carriage_is_the_model_variant_not_a_whole_name() {
        // The carriage that used to be kept whole here too: its host and path decide what the node
        // dials, so leaving them in the extras left them out of the identity.
        let json = r#"{"v":"2","add":"example.com","port":"443","id":"11111111-2222-3333-4444-555555555555","net":"httpupgrade","host":"cdn.example.com","path":"/up"}"#;
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        );
        let node = parse_link(&link).expect("a link");

        let crate::Transport::HttpUpgrade(upgrade) = &node.transport else {
            panic!("{:?}", node.transport);
        };

        assert_eq!(upgrade.path.as_ref(), "/up");
        assert_eq!(
            upgrade.host.as_ref().map(ToString::to_string).as_deref(),
            Some("cdn.example.com")
        );
        assert!(node.extra.is_empty(), "{:?}", node.extra);

        // And it is written back in this dialect, not as a bare name.
        let written = write_link(&node).expect("a link");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(written.trim_start_matches("vmess://"))
            .expect("base64");
        let json: serde_json::Value = serde_json::from_slice(&decoded).expect("json");

        assert_eq!(json["net"], "httpupgrade");
        assert_eq!(json["path"], "/up");
        assert_eq!(json["host"], "cdn.example.com");
    }

    #[test]
    fn a_port_that_is_not_a_port_is_refused() {
        for port in ["70000", "\"70000\"", "\"0\"", "\"443abc\"", "null"] {
            let json = format!(
                r#"{{"add":"example.com","port":{port},"id":"11111111-2222-3333-4444-555555555555"}}"#
            );
            let link = format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(&json)
            );

            let error = parse_link(&link).expect_err("not a port");

            assert!(
                matches!(
                    error.kind(),
                    ErrorKind::InvalidPort | ErrorKind::MissingField
                ),
                "{port}: {error}"
            );
        }
    }

    #[test]
    fn a_key_the_model_does_not_name_is_not_carried() {
        // A whole-object dialect has no parameter list to put extras in, and the model has no field for
        // a JSON object. What the crate models comes out again; the rest is replayed from the raw link
        // the record keeps, which is the decision the module documents.
        let json = r#"{"ps":"Tokyo","add":"example.com","port":443,"id":"11111111-2222-3333-4444-555555555555","futureKey":"futureValue"}"#;
        let node = parse_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        ))
        .unwrap();

        assert!(
            node.extra.is_empty(),
            "a whole-object dialect has no extras"
        );

        let written = write_link(&node).unwrap();
        let rewritten = base64::engine::general_purpose::STANDARD
            .decode(written.trim_start_matches("vmess://"))
            .unwrap();
        let rewritten = core::str::from_utf8(&rewritten).unwrap();

        assert!(!rewritten.contains("futureKey"), "{rewritten}");
        assert!(rewritten.contains("\"add\":\"example.com\""), "{rewritten}");
    }

    #[test]
    fn a_whole_link_is_a_whole_node() {
        let node = parse_link(&link()).unwrap();

        // Everything the other dialects spread over parameters comes out of the blob.
        assert_eq!(node.name.as_str(), "Tokyo");
        assert_eq!(node.endpoint.to_string(), "example.com:443");
        assert_eq!(node.transport.name(), "ws");
        assert_eq!(node.transport.extra().len(), 0);

        let client = node.protocol.as_vmess().unwrap();
        assert_eq!(
            client.uuid().to_string(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(client.alter_id, 0);
        assert_eq!(client.security, Security::Auto);

        let tls = node.tls.unwrap();
        assert_eq!(tls.server_name.unwrap().domain(), Some("www.apple.com"));
        assert_eq!(tls.alpn.len(), 2);
        assert_eq!(tls.fingerprint.unwrap().as_str(), "chrome");
    }

    #[test]
    fn a_link_round_trips_through_the_blob() {
        let node = parse_link(&link()).unwrap();
        let written = write_link(&node).unwrap();
        let again = parse_link(&written).unwrap();

        assert_eq!(again, node, "{written}");
        assert_eq!(again.id(), node.id());
    }

    #[test]
    fn a_tcp_carriage_with_an_http_header_survives() {
        let json = r#"{"v":"2","ps":"Tokyo","add":"example.com","port":"80","id":"11111111-2222-3333-4444-555555555555","net":"tcp","type":"http"}"#;
        let node = parse_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        ))
        .unwrap();

        assert_eq!(node.transport.name(), "tcp+http");

        let again = parse_link(&write_link(&node).unwrap()).unwrap();
        assert_eq!(again, node);
    }

    #[test]
    fn a_link_without_an_address_is_reported() {
        let json =
            r#"{"v":"2","ps":"Tokyo","port":"443","id":"11111111-2222-3333-4444-555555555555"}"#;
        let error = parse_link(&format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        ))
        .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
        assert!(error.reason().contains("add"), "{}", error.reason());
    }

    #[test]
    fn text_that_is_not_a_vmess_link_is_reported() {
        let error = parse_link("vmess://not base64 at all").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidBase64);
    }

    #[test]
    fn the_id_never_reaches_a_rendering() {
        let node = parse_link(&link()).unwrap();
        let rendered = format!("{:?}", node.protocol);

        assert!(rendered.contains("vmess::Client"), "{rendered}");
        assert!(
            !rendered.contains("11111111-2222-3333-4444-555555555555"),
            "{rendered}"
        );
    }
}
