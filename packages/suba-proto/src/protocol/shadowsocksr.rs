//! ShadowsocksR.
//!
//! Shadowsocks with an obfuscation layer and a protocol plugin in front of it, and a link that is a
//! whole base64 blob rather than a query string:
//!
//! ```text
//! ssr://<base64url of host:port:protocol:method:obfs:base64url(password)/?obfsparam=…&protoparam=…&remarks=…>
//! ```
//!
//! So it takes the whole-link path, like [`vmess`](super::vmess). Everything it carries beyond the
//! address is protocol-owned text: this protocol names its own ciphers, its own obfuscation and its
//! own handshake obfuscation, and neither vocabulary is Shadowsocks'.

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

/// A ShadowsocksR client.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The cipher.
    pub method: Box<str>,
    /// The password.
    pub password: Secret<Box<str>>,
    /// The protocol plugin.
    pub protocol: Box<str>,
    /// The protocol plugin's parameter.
    #[cfg_attr(feature = "serde", serde(default))]
    pub protocol_param: Box<str>,
    /// The obfuscation.
    pub obfs: Box<str>,
    /// The obfuscation's parameter.
    #[cfg_attr(feature = "serde", serde(default))]
    pub obfs_param: Box<str>,
}

/// A ShadowsocksR listener.
///
/// The same six fields: this protocol has one credential per listener, and no user list.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// The cipher.
    pub method: Box<str>,
    /// The password.
    pub password: Secret<Box<str>>,
    /// The protocol plugin.
    pub protocol: Box<str>,
    /// The protocol plugin's parameter.
    #[cfg_attr(feature = "serde", serde(default))]
    pub protocol_param: Box<str>,
    /// The obfuscation.
    pub obfs: Box<str>,
    /// The obfuscation's parameter.
    #[cfg_attr(feature = "serde", serde(default))]
    pub obfs_param: Box<str>,
}

impl Server {
    /// Whether the listener has what it needs to talk to anyone.
    pub fn is_complete(&self) -> bool {
        !self.password.is_empty() && !self.method.is_empty()
    }
}

impl Client {
    /// A client with a cipher and a password.
    pub fn new(method: impl Into<Box<str>>, password: impl Into<Box<str>>) -> Self {
        Self {
            method: method.into(),
            password: Secret::new(password.into()),
            protocol: Box::from("origin"),
            protocol_param: Box::from(""),
            obfs: Box::from("plain"),
            obfs_param: Box::from(""),
        }
    }

    /// The password, for the one caller allowed to hold it.
    pub fn password(&self) -> &str {
        self.password.expose()
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::ShadowsocksR
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.password.is_empty() && !self.method.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::ShadowsocksR
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

/// Read a whole `ssr://` link.
pub(crate) fn parse(link: &Link<'_>) -> Result<LinkParts> {
    let blob = link
        .raw()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let blob = blob.split('#').next().unwrap_or(blob).trim();

    let decoded = decode(blob.trim_end_matches('/'))?;
    let text = core::str::from_utf8(&decoded)
        .map_err(|_| Error::field(ErrorKind::InvalidValue, "ssr link"))?;

    let (head, query) = text.split_once("/?").unwrap_or((text, ""));
    let head = head.trim_end_matches('/');

    // host:port:protocol:method:obfs:base64url(password)
    let mut fields = head.splitn(6, ':');
    let missing = |field: &'static str| Error::field(ErrorKind::MissingField, field);

    let host = fields.next().ok_or_else(|| missing("host"))?;
    let port = fields.next().ok_or_else(|| missing("port"))?;
    let protocol = fields.next().ok_or_else(|| missing("protocol"))?;
    let method = fields.next().ok_or_else(|| missing("method"))?;
    let obfs = fields.next().ok_or_else(|| missing("obfs"))?;
    let password = fields.next().ok_or_else(|| missing("password"))?;

    if host.is_empty() || port.is_empty() || method.is_empty() {
        return Err(missing("host:port:protocol:method:obfs:password"));
    }

    let password = decode(password)?;
    let password = core::str::from_utf8(&password)
        .map_err(|_| Error::field(ErrorKind::InvalidBase64, "password"))?;

    // The rest is base64url, and the spellings of the parameters are the community's.
    let mut params = RawParams::new();
    let mut obfs_param = Box::from("");
    let mut protocol_param = Box::from("");
    let mut name = None;

    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = decode(value.trim_end_matches('/')).unwrap_or_default();
        let value = core::str::from_utf8(&value).unwrap_or_default();

        match key.to_ascii_lowercase().as_str() {
            "obfsparam" => obfs_param = Box::from(value),
            "protoparam" => protocol_param = Box::from(value),
            "remarks" => name = Some(Box::from(value)),
            _ => params.insert(key, value),
        }
    }

    Ok(LinkParts {
        endpoint: Endpoint {
            host: Host::parse(host)?,
            port: Port::parse(port)?,
        },
        name,
        tls: None,
        transport: Client::default_transport(),
        extra: params,
        protocol: Outbound::ShadowsocksR(Client {
            method: Box::from(method),
            password: Secret::new(Box::from(password)),
            protocol: Box::from(protocol),
            protocol_param,
            obfs: Box::from(obfs),
            obfs_param,
        }),
    })
}

/// The base64 dialect these links use: urlsafe, and padded or not depending on who generated it.
fn decode(input: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(input))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input))
        .map_err(|_| Error::field(ErrorKind::InvalidBase64, "ssr link"))
}

/// The same dialect, written back the way these links are generated.
fn encode(input: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

impl ClientLink for Client {
    const KIND: Kind = Kind::ShadowsocksR;
    const SCHEME: &'static str = "ssr";

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        let host = node.endpoint.host.to_string();
        let mut head = format!(
            "{host}:{}:{}:{}:{}:{}",
            node.endpoint.port.get(),
            self.protocol,
            self.method,
            self.obfs,
            encode(self.password.expose()),
        );

        if !self.obfs_param.is_empty() || !self.protocol_param.is_empty() {
            head.push_str("/?");

            if !self.obfs_param.is_empty() {
                head.push_str("obfsparam=");
                head.push_str(&encode(&self.obfs_param));
            }

            if !self.protocol_param.is_empty() {
                if !self.obfs_param.is_empty() {
                    head.push('&');
                }

                head.push_str("protoparam=");
                head.push_str(&encode(&self.protocol_param));
            }
        }

        // The name is this dialect's `remarks`, and it belongs inside the blob with everything else:
        // a parameter after the base64 is not part of this format and no client reads it.
        if !node.name.as_str().is_empty() {
            head.push_str(if head.contains("/?") { "&" } else { "/?" });
            head.push_str("remarks=");
            head.push_str(&encode(node.name.as_str()));
        }

        out.push_str(Self::SCHEME);
        out.push_str("://");
        out.push_str(&encode(&head));

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(&self.method);
        out.display(self.password.expose());
        out.text(&self.protocol);
        out.text(&self.protocol_param);
        out.text(&self.obfs);
        out.text(&self.obfs_param);
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.text(&self.method);
        out.display(self.password.expose());
        out.text(&self.protocol);
        out.text(&self.protocol_param);
        out.text(&self.obfs);
        out.text(&self.obfs_param);
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("method", &self.method)
            .field("password", &self.password)
            .field("protocol", &self.protocol)
            .field("protocol_param", &self.protocol_param)
            .field("obfs", &self.obfs)
            .field("obfs_param", &self.obfs_param)
            .finish()
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("method", &self.method)
            .field("password", &self.password)
            .field("protocol", &self.protocol)
            .field("obfs", &self.obfs)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link};

    /// `example.com:443:auth_sha1_v4:aes-256-cfb:http_simple:BASE64(letmein)/?obfsparam=BASE64(cdn.example.com)`
    fn link() -> String {
        format!(
            "ssr://{}",
            encode(&format!(
                "example.com:443:auth_sha1_v4:aes-256-cfb:http_simple:{}/?obfsparam={}&remarks={}",
                encode("letmein"),
                encode("cdn.example.com"),
                encode("Tokyo"),
            ))
        )
    }

    #[test]
    fn a_whole_link_is_a_whole_node() {
        let node = parse_link(&link()).unwrap();

        assert_eq!(node.name.as_str(), "Tokyo");
        assert_eq!(node.endpoint.to_string(), "example.com:443");

        let client = node.protocol.as_shadowsocksr().unwrap();
        assert_eq!(&*client.method, "aes-256-cfb");
        assert_eq!(client.password(), "letmein");
        assert_eq!(&*client.protocol, "auth_sha1_v4");
        assert_eq!(&*client.obfs, "http_simple");
        assert_eq!(&*client.obfs_param, "cdn.example.com");
    }

    #[test]
    fn a_link_round_trips_through_the_blob() {
        let node = parse_link(&link()).unwrap();
        let again = parse_link(&write_link(&node).unwrap()).unwrap();

        assert_eq!(again, node);
        assert_eq!(again.id(), node.id());
    }

    #[test]
    fn a_blob_that_is_not_base64_is_reported() {
        let error = parse_link("ssr://not a blob").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidBase64);
    }

    #[test]
    fn the_password_never_reaches_a_rendering() {
        let node = parse_link(&link()).unwrap();
        let rendered = format!("{:?}", node.protocol);

        assert!(!rendered.contains("letmein"), "{rendered}");
    }
}
