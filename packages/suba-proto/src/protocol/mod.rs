//! The protocols, one module each, and the enum that dispatches between them.
//!
//! A protocol module owns three things and nothing else: the shape of its credentials in each
//! direction, how it is spelled as a share link, and what it contributes to TLS and carriage. It
//! does not know about subscriptions, storage, sing-box or any other consumer — that is the whole
//! point of this crate being able to stand alone.
//!
//! # Shape
//!
//! * `vless::Client` / `vless::Server` — the same protocol in the two directions, sharing the types they
//!   genuinely share (`Flow`) and differing where the wire differs (`id` versus `users`).
//! * [`Outbound`] / [`Inbound`] — one enum per direction, so a `match` is exhaustive, dispatch is
//!   static, and a new protocol cannot be added without the compiler pointing at every place that
//!   has to learn about it.
//! * [`ClientLink`] — the trait a payload implements to be spelled as a share link. Links describe
//!   clients only, so it is implemented for the client half alone.

pub mod hysteria2;
pub mod opaque;
pub mod shadowsocks;
pub mod trojan;
use crate::addr::Endpoint;

use crate::error::Result;

pub mod anytls;
pub mod http;
pub mod shadowsocksr;
pub mod socks;
pub mod tuic;
pub mod vless;
pub mod vmess;

use core::fmt;

use crate::identity::{Encode, Hasher};
use crate::link::{self, Link, Reader};
use crate::node::{Client, Name, Node};
use crate::params::RawParams;
use crate::percent;
use crate::prelude::*;
use crate::tls::{self, Alpn, TlsClient, TlsServer};
use crate::transport::{self, Transport};

pub use opaque::Opaque;

/// Which protocol a node speaks.
///
/// Separate from the payload types on purpose: a caller that only needs to branch on the protocol —
/// a filter, a rule engine, a picker — should not have to name a credential-bearing type to do it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Kind {
    /// VLESS.
    Vless,
    /// Trojan.
    Trojan,
    /// Shadowsocks, including its 2022 ciphers.
    Shadowsocks,
    /// Hysteria2.
    Hysteria2,
    /// VMess.
    Vmess,
    /// ShadowsocksR.
    ShadowsocksR,
    /// TUIC.
    Tuic,
    /// AnyTLS.
    AnyTls,
    /// SOCKS, a local listener rather than a provider's product.
    Socks,
    /// HTTP CONNECT, likewise.
    Http,
    /// A protocol this build does not model, kept whole.
    Other,
}

impl Kind {
    /// A name for it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Vless => "vless",
            Self::Trojan => "trojan",
            Self::Shadowsocks => "shadowsocks",
            Self::Hysteria2 => "hysteria2",
            Self::Vmess => "vmess",
            Self::ShadowsocksR => "shadowsocksr",
            Self::Tuic => "tuic",
            Self::AnyTls => "anytls",
            Self::Socks => "socks",
            Self::Http => "http",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What both directions of a protocol can be asked.
pub trait Protocol {
    /// Which protocol this is.
    fn kind(&self) -> Kind;

    /// The scheme a share link uses. For an unmodelled protocol it is whatever the provider used.
    fn scheme(&self) -> &str;

    /// Whether the payload carries a credential. The distinction matters to a UI and to a policy
    /// that decides what may be exported.
    fn has_credentials(&self) -> bool;

    /// Whether this protocol can be served as well as dialled.
    fn supports_inbound(&self) -> bool;
}

/// The trait a client payload implements to be spelled as a share link.
///
/// Opt-in, and separate from [`Outbound`] on purpose: a payload a client dials does not have to have
/// a link form — a `tun` listener, or a routing target such as `direct` — and a payload without one is
/// written by [`Outbound::write_link`] as
/// [`ErrorKind::NoLinkForm`](crate::error::ErrorKind::NoLinkForm).
pub trait ClientLink: Sized + Encode {
    /// Which protocol this is.
    const KIND: Kind;

    /// The scheme this protocol's links use.
    const SCHEME: &'static str;

    /// Whether TLS is not optional for this protocol, so a link that mentions none still speaks it.
    const TLS_ONLY: bool = false;

    /// How this protocol is carried when the link names no transport.
    ///
    /// Almost always TCP: a link that says nothing about carriage means TCP. Hysteria2 and TUIC are
    /// QUIC by construction, so for them the carriage is a property of the protocol and a `type=`
    /// parameter would be a lie about the wire.
    fn default_transport() -> Transport {
        Transport::Tcp
    }

    /// Read this protocol's own parameters.
    ///
    /// `reader` still holds everything TLS and carriage did not claim, and whatever is left when this
    /// returns becomes the node's unmodelled parameters. `userinfo` is the part before the host,
    /// which is where most of these dialects keep the credential.
    ///
    /// A dialect whose links are whole objects rather than a userinfo plus a query does not implement
    /// this: the default is what makes "no query form" expressible, so that no implementor has to write
    /// a method that can only reject.
    fn from_query(_reader: &mut Reader<'_>, _userinfo: &str) -> Result<Self> {
        Err(crate::error::Error::field(
            crate::error::ErrorKind::MalformedLink,
            "this dialect is a whole-link format and has no query form",
        ))
    }

    /// Write this protocol's own parameters.
    fn write_params(&self, out: &mut String, first: &mut bool) -> Result<()> {
        let _ = (out, first);
        Ok(())
    }

    /// Write the whole link into `out`.
    ///
    /// Default implementation: scheme, the credential, this protocol's parameters, TLS and
    /// carriage, then the name. A protocol that needs a different userinfo — SIP002's base64 blob —
    /// overrides this and starts from [`link::begin`] itself.
    fn write_link(&self, node: &Node<Client>, out: &mut String) -> Result<()>;
}

/// What a whole-link dialect says: everything the query dialects spread over parameters.
///
/// A `vmess://` or `ssr://` link is one base64 blob holding the address, the carriage, the TLS
/// settings and the name, so the protocol returns them together and nothing shared is parsed first.
pub(crate) struct LinkParts {
    /// Where the node is.
    pub endpoint: Endpoint,
    /// The name inside the blob.
    pub name: Option<Box<str>>,
    /// TLS, when the blob asks for it.
    pub tls: Option<TlsClient>,
    /// How the protocol is carried.
    pub transport: Transport,
    /// Parameters the model does not recognise, kept as they were written.
    pub extra: RawParams,
    /// The client payload, wrapped as the direction it belongs to.
    pub protocol: Outbound,
}

/// A node a client dials.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "protocol", rename_all = "lowercase"))]
pub enum Outbound {
    /// VLESS.
    Vless(vless::Client),
    /// Trojan.
    Trojan(trojan::Client),
    /// Shadowsocks.
    Shadowsocks(shadowsocks::Client),
    /// Hysteria2.
    Hysteria2(hysteria2::Client),
    /// VMess.
    Vmess(vmess::Client),
    /// ShadowsocksR.
    ShadowsocksR(shadowsocksr::Client),
    /// TUIC.
    Tuic(tuic::Client),
    /// AnyTLS.
    AnyTls(anytls::Client),
    /// SOCKS.
    Socks(socks::Client),
    /// HTTP CONNECT.
    Http(http::Client),
    /// Something this build does not model.
    Other(Opaque),
}

/// A node a listener serves.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "protocol", rename_all = "lowercase"))]
pub enum Inbound {
    /// VLESS.
    Vless(vless::Server),
    /// Trojan.
    Trojan(trojan::Server),
    /// Shadowsocks.
    Shadowsocks(shadowsocks::Server),
    /// Hysteria2.
    Hysteria2(hysteria2::Server),
    /// VMess.
    Vmess(vmess::Server),
    /// ShadowsocksR.
    ShadowsocksR(shadowsocksr::Server),
    /// TUIC.
    Tuic(tuic::Server),
    /// AnyTLS.
    AnyTls(anytls::Server),
    /// SOCKS.
    Socks(socks::Server),
    /// HTTP CONNECT.
    Http(http::Server),
}

impl Outbound {
    /// Which protocol this is.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Vless(_) => Kind::Vless,
            Self::Trojan(_) => Kind::Trojan,
            Self::Shadowsocks(_) => Kind::Shadowsocks,
            Self::Hysteria2(_) => Kind::Hysteria2,
            Self::Vmess(_) => Kind::Vmess,
            Self::ShadowsocksR(_) => Kind::ShadowsocksR,
            Self::Tuic(_) => Kind::Tuic,
            Self::AnyTls(_) => Kind::AnyTls,
            Self::Socks(_) => Kind::Socks,
            Self::Http(_) => Kind::Http,
            Self::Other(_) => Kind::Other,
        }
    }

    /// The link scheme.
    pub fn scheme(&self) -> &str {
        match self {
            Self::Vless(_) => <vless::Client as ClientLink>::SCHEME,
            Self::Trojan(_) => <trojan::Client as ClientLink>::SCHEME,
            Self::Shadowsocks(_) => <shadowsocks::Client as ClientLink>::SCHEME,
            Self::Hysteria2(_) => <hysteria2::Client as ClientLink>::SCHEME,
            Self::Vmess(_) => <vmess::Client as ClientLink>::SCHEME,
            Self::ShadowsocksR(_) => <shadowsocksr::Client as ClientLink>::SCHEME,
            Self::Tuic(_) => <tuic::Client as ClientLink>::SCHEME,
            Self::AnyTls(_) => <anytls::Client as ClientLink>::SCHEME,
            Self::Socks(_) => "socks",
            Self::Http(_) => "http",
            Self::Other(payload) => payload.scheme(),
        }
    }

    /// Cast to a specific payload, as a slide of the enum rather than a `match` at every call site.
    pub fn as_vless(&self) -> Option<&vless::Client> {
        match self {
            Self::Vless(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a Trojan payload.
    pub fn as_trojan(&self) -> Option<&trojan::Client> {
        match self {
            Self::Trojan(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a Shadowsocks payload.
    pub fn as_shadowsocks(&self) -> Option<&shadowsocks::Client> {
        match self {
            Self::Shadowsocks(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a VMess payload.
    pub fn as_vmess(&self) -> Option<&vmess::Client> {
        match self {
            Self::Vmess(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to an AnyTLS payload.
    pub fn as_anytls(&self) -> Option<&anytls::Client> {
        match self {
            Self::AnyTls(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a TUIC payload.
    pub fn as_tuic(&self) -> Option<&tuic::Client> {
        match self {
            Self::Tuic(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a ShadowsocksR payload.
    pub fn as_shadowsocksr(&self) -> Option<&shadowsocksr::Client> {
        match self {
            Self::ShadowsocksR(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a SOCKS payload.
    pub fn as_socks(&self) -> Option<&socks::Client> {
        match self {
            Self::Socks(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to an HTTP payload.
    pub fn as_http(&self) -> Option<&http::Client> {
        match self {
            Self::Http(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a Hysteria2 payload.
    pub fn as_hysteria2(&self) -> Option<&hysteria2::Client> {
        match self {
            Self::Hysteria2(payload) => Some(payload),
            _ => None,
        }
    }

    /// How this protocol is carried when a link names no transport.
    pub fn default_transport(&self) -> Transport {
        match self {
            Self::Vless(_) => vless::Client::default_transport(),
            Self::Trojan(_) => trojan::Client::default_transport(),
            Self::Shadowsocks(_) => shadowsocks::Client::default_transport(),
            Self::Hysteria2(_) => hysteria2::Client::default_transport(),
            Self::Vmess(_) => vmess::Client::default_transport(),
            Self::ShadowsocksR(_) => shadowsocksr::Client::default_transport(),
            Self::Tuic(_) => tuic::Client::default_transport(),
            Self::AnyTls(_) => anytls::Client::default_transport(),
            Self::Socks(_) => Transport::Tcp,
            Self::Http(_) => Transport::Tcp,
            Self::Other(_) => Transport::Tcp,
        }
    }

    /// Write the node as a share link.
    pub fn write_link(&self, node: &Node<Client>, out: &mut String) -> Result<()> {
        match self {
            Self::Vless(payload) => payload.write_link(node, out),
            Self::Trojan(payload) => payload.write_link(node, out),
            Self::Shadowsocks(payload) => payload.write_link(node, out),
            Self::Hysteria2(payload) => payload.write_link(node, out),
            Self::Vmess(payload) => payload.write_link(node, out),
            Self::ShadowsocksR(payload) => payload.write_link(node, out),
            Self::Tuic(payload) => payload.write_link(node, out),
            Self::AnyTls(payload) => payload.write_link(node, out),
            Self::Socks(payload) => payload.write_link(node, out),
            Self::Http(payload) => payload.write_link(node, out),
            Self::Other(payload) => payload.write_link(node, out),
        }
    }
}

impl Protocol for Outbound {
    fn kind(&self) -> Kind {
        Outbound::kind(self)
    }

    fn scheme(&self) -> &str {
        Outbound::scheme(self)
    }

    fn has_credentials(&self) -> bool {
        match self {
            Self::Vless(payload) => payload.has_credentials(),
            Self::Trojan(payload) => payload.has_credentials(),
            Self::Shadowsocks(payload) => payload.has_credentials(),
            Self::Hysteria2(payload) => payload.has_credentials(),
            Self::Vmess(payload) => payload.has_credentials(),
            Self::ShadowsocksR(payload) => payload.has_credentials(),
            Self::Tuic(payload) => payload.has_credentials(),
            Self::AnyTls(payload) => payload.has_credentials(),
            Self::Socks(payload) => payload.has_credentials(),
            Self::Http(payload) => payload.has_credentials(),
            Self::Other(_) => false,
        }
    }

    fn supports_inbound(&self) -> bool {
        match self {
            Self::Vless(_) => true,
            Self::Trojan(_) => true,
            Self::Shadowsocks(_) => true,
            Self::Hysteria2(_) => true,
            Self::Vmess(_) => true,
            Self::ShadowsocksR(_) => true,
            Self::Tuic(_) => true,
            Self::AnyTls(_) => true,
            Self::Socks(_) => true,
            Self::Http(_) => true,
            Self::Other(payload) => payload.supports_inbound(),
        }
    }
}

impl Inbound {
    /// Which protocol this is.
    pub fn kind(&self) -> Kind {
        match self {
            Self::Vless(_) => Kind::Vless,
            Self::Trojan(_) => Kind::Trojan,
            Self::Shadowsocks(_) => Kind::Shadowsocks,
            Self::Hysteria2(_) => Kind::Hysteria2,
            Self::Vmess(_) => Kind::Vmess,
            Self::ShadowsocksR(_) => Kind::ShadowsocksR,
            Self::Tuic(_) => Kind::Tuic,
            Self::AnyTls(_) => Kind::AnyTls,
            Self::Socks(_) => Kind::Socks,
            Self::Http(_) => Kind::Http,
        }
    }

    /// The link scheme the matching client side would use. A listener is not addressable as a link;
    /// this is only ever used to name the protocol.
    pub fn scheme(&self) -> &str {
        match self {
            Self::Vless(_) => <vless::Client as ClientLink>::SCHEME,
            Self::Trojan(_) => <trojan::Client as ClientLink>::SCHEME,
            Self::Shadowsocks(_) => <shadowsocks::Client as ClientLink>::SCHEME,
            Self::Hysteria2(_) => <hysteria2::Client as ClientLink>::SCHEME,
            Self::Vmess(_) => <vmess::Client as ClientLink>::SCHEME,
            Self::ShadowsocksR(_) => <shadowsocksr::Client as ClientLink>::SCHEME,
            Self::Tuic(_) => <tuic::Client as ClientLink>::SCHEME,
            Self::AnyTls(_) => <anytls::Client as ClientLink>::SCHEME,
            Self::Socks(_) => "socks",
            Self::Http(_) => "http",
        }
    }

    /// How many credentials the listener accepts.
    pub fn user_count(&self) -> usize {
        match self {
            Self::Vless(payload) => payload.users.len(),
            Self::Trojan(payload) => payload.users.len(),
            // A Shadowsocks listener holds its credential in one of two places: the single password
            // of the classic mode, or the user list of the 2022 mode. Either way it has one.
            Self::Shadowsocks(payload) => payload.users.len().max(1),
            Self::Hysteria2(payload) => payload.users.len(),
            Self::Vmess(payload) => payload.users.len(),
            Self::Tuic(payload) => payload.users.len(),
            Self::AnyTls(payload) => payload.users.len(),
            Self::ShadowsocksR(_) => 1,
            Self::Socks(payload) => payload.users.len().max(1),
            Self::Http(payload) => payload.users.len().max(1),
        }
    }

    /// Cast to a VLESS payload.
    pub fn as_vless(&self) -> Option<&vless::Server> {
        match self {
            Self::Vless(payload) => Some(payload),
            _ => None,
        }
    }

    /// Cast to a Hysteria2 payload.
    pub fn as_hysteria2(&self) -> Option<&hysteria2::Server> {
        match self {
            Self::Hysteria2(payload) => Some(payload),
            _ => None,
        }
    }
}

impl Protocol for Inbound {
    fn kind(&self) -> Kind {
        Inbound::kind(self)
    }

    fn scheme(&self) -> &str {
        Inbound::scheme(self)
    }

    fn has_credentials(&self) -> bool {
        match self {
            Self::Vless(payload) => payload.has_credentials(),
            Self::Trojan(payload) => payload.has_credentials(),
            Self::Shadowsocks(payload) => payload.has_credentials(),
            Self::Hysteria2(payload) => payload.has_credentials(),
            Self::Vmess(payload) => payload.has_credentials(),
            Self::ShadowsocksR(payload) => payload.has_credentials(),
            Self::Tuic(payload) => payload.has_credentials(),
            Self::AnyTls(payload) => payload.has_credentials(),
            Self::Socks(payload) => payload.has_credentials(),
            Self::Http(payload) => payload.has_credentials(),
        }
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Encode for Outbound {
    fn encode(&self, out: &mut Hasher) {
        out.byte(1);
        // The protocol's own name, before its fields: two dialects whose payloads happen to encode the
        // same way are not the same node, and the direction byte alone does not say which they are.
        out.text(self.kind().as_str());

        match self {
            Self::Vless(payload) => payload.encode(out),
            Self::Trojan(payload) => payload.encode(out),
            Self::Shadowsocks(payload) => payload.encode(out),
            Self::Hysteria2(payload) => payload.encode(out),
            Self::Vmess(payload) => payload.encode(out),
            Self::ShadowsocksR(payload) => payload.encode(out),
            Self::Tuic(payload) => payload.encode(out),
            Self::AnyTls(payload) => payload.encode(out),
            Self::Socks(payload) => payload.encode(out),
            Self::Http(payload) => payload.encode(out),
            Self::Other(payload) => payload.encode(out),
        }
    }
}

impl Encode for Inbound {
    fn encode(&self, out: &mut Hasher) {
        out.byte(2);
        out.text(self.kind().as_str());

        match self {
            Self::Vless(payload) => payload.encode(out),
            Self::Trojan(payload) => payload.encode(out),
            Self::Shadowsocks(payload) => payload.encode(out),
            Self::Hysteria2(payload) => payload.encode(out),
            Self::Vmess(payload) => payload.encode(out),
            Self::ShadowsocksR(payload) => payload.encode(out),
            Self::Tuic(payload) => payload.encode(out),
            Self::AnyTls(payload) => payload.encode(out),
            Self::Socks(payload) => payload.encode(out),
            Self::Http(payload) => payload.encode(out),
        }
    }
}

impl fmt::Debug for Outbound {
    /// Safe in full: every credential in these payloads is a `Secret`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless(payload) => fmt::Debug::fmt(payload, f),
            Self::Trojan(payload) => fmt::Debug::fmt(payload, f),
            Self::Shadowsocks(payload) => fmt::Debug::fmt(payload, f),
            Self::Hysteria2(payload) => fmt::Debug::fmt(payload, f),
            Self::Vmess(payload) => fmt::Debug::fmt(payload, f),
            Self::ShadowsocksR(payload) => fmt::Debug::fmt(payload, f),
            Self::Tuic(payload) => fmt::Debug::fmt(payload, f),
            Self::AnyTls(payload) => fmt::Debug::fmt(payload, f),
            Self::Socks(payload) => fmt::Debug::fmt(payload, f),
            Self::Http(payload) => fmt::Debug::fmt(payload, f),
            Self::Other(payload) => fmt::Debug::fmt(payload, f),
        }
    }
}

impl fmt::Debug for Inbound {
    /// Safe in full: every credential in these payloads is a `Secret`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vless(payload) => fmt::Debug::fmt(payload, f),
            Self::Trojan(payload) => fmt::Debug::fmt(payload, f),
            Self::Shadowsocks(payload) => fmt::Debug::fmt(payload, f),
            Self::Hysteria2(payload) => fmt::Debug::fmt(payload, f),
            Self::Vmess(payload) => fmt::Debug::fmt(payload, f),
            Self::ShadowsocksR(payload) => fmt::Debug::fmt(payload, f),
            Self::Tuic(payload) => fmt::Debug::fmt(payload, f),
            Self::AnyTls(payload) => fmt::Debug::fmt(payload, f),
            Self::Socks(payload) => fmt::Debug::fmt(payload, f),
            Self::Http(payload) => fmt::Debug::fmt(payload, f),
        }
    }
}

/// Read a share link into a node.
pub fn parse_link(input: &str) -> Result<Node<Client>> {
    let link = Link::parse(input)?;

    // A dialect that is not a query string owns its whole link. `vmess://` is a base64 JSON blob
    // carrying the address, the carriage, the TLS settings and the name, so there is nothing shared
    // left to parse before it runs, and nothing left for the parameter reader to see.
    if let Some(parts) = match scheme_kind(link.scheme()) {
        Some(Kind::Vmess) => Some(vmess::parse(&link)?),
        Some(Kind::ShadowsocksR) => Some(shadowsocksr::parse(&link)?),
        _ => None,
    } {
        return Ok(Node {
            name: parts
                .name
                .as_deref()
                .map_or_else(|| Name::new(link.name().as_ref()), Name::new),
            endpoint: parts.endpoint,
            listen: (),
            transport: parts.transport,
            tls: parts.tls,
            protocol: parts.protocol,
            extra: parts.extra,
        });
    }

    let mut reader = Reader::new(link.query());

    let tls = parse_client_tls(&mut reader, scheme_is_tls_only(link.scheme()));
    let transport = parse_transport(&mut reader);

    // The credential lives in the userinfo for most of these dialects, so it is handed to the
    // protocol reader as text rather than written into the parameter list: a protocol that does not
    // want it never sees it, and nothing is copied twice.
    let userinfo = percent::decode(link.userinfo());
    let mut endpoint_hint = None;

    let protocol = match scheme_kind(link.scheme()) {
        Some(Kind::Vless) => Outbound::Vless(vless::Client::from_query(&mut reader, &userinfo)?),
        Some(Kind::Trojan) => Outbound::Trojan(trojan::Client::from_query(&mut reader, &userinfo)?),
        Some(Kind::Shadowsocks) => {
            let (hint, client) = shadowsocks::parse(&link, &mut reader, &userinfo)?;
            endpoint_hint = hint;

            Outbound::Shadowsocks(client)
        }
        Some(Kind::Hysteria2) => {
            Outbound::Hysteria2(hysteria2::Client::from_query(&mut reader, &userinfo)?)
        }
        Some(Kind::AnyTls) => Outbound::AnyTls(anytls::Client::from_query(&mut reader, &userinfo)?),
        Some(Kind::Tuic) => Outbound::Tuic(tuic::Client::from_query(&mut reader, &userinfo)?),
        Some(Kind::Socks) => {
            let mut client = socks::Client::from_query(&mut reader, &userinfo)?;
            // The version is the scheme's, `socks4` against `socks5`, and the reader never sees the
            // scheme: it reads parameters.
            client.version = socks::Version::from_scheme(link.scheme());

            Outbound::Socks(client)
        }
        Some(Kind::Http) => Outbound::Http(http::Client::from_query(&mut reader, &userinfo)?),
        _ => Outbound::Other(Opaque::from_link(&link)),
    };

    let endpoint = match endpoint_hint {
        Some(endpoint) => endpoint,
        None => link.endpoint()?,
    };

    // A protocol whose carriage is a property of the protocol — hysteria2 is QUIC, always — supplies
    // the transport when the link says nothing, because there is nothing for the link to say.
    let transport = transport.unwrap_or_else(|| protocol.default_transport());

    Ok(Node {
        name: Name::new(link.name().as_ref()),
        endpoint,
        listen: (),
        transport,
        tls,
        protocol,
        extra: reader.leftover(),
    })
}

/// Write a node as a share link.
///
/// Allocates exactly one string, the link. A caller that already has a buffer should use
/// [`write_link_into`].
pub fn write_link(node: &Node<Client>) -> Result<String> {
    let mut out = String::with_capacity(256);
    write_link_into(node, &mut out)?;

    Ok(out)
}

/// Write a node as a share link into an existing buffer.
pub fn write_link_into(node: &Node<Client>, out: &mut String) -> Result<()> {
    out.clear();
    node.protocol.write_link(node, out)
}

/// Whether a scheme is known to speak TLS and say so nowhere.
///
/// Hysteria2, TUIC and AnyTLS authenticate with TLS by construction, so a link that mentions no TLS
/// parameter is not a link to a plaintext node.
pub(crate) fn scheme_is_tls_only(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "trojan" | "hysteria2" | "hy2" | "tuic" | "anytls" | "https"
    )
}

/// Which protocol a scheme names, when it names one this build models.
pub(crate) fn scheme_kind(scheme: &str) -> Option<Kind> {
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => Some(Kind::Vless),
        "trojan" => Some(Kind::Trojan),
        "ss" | "shadowsocks" => Some(Kind::Shadowsocks),
        "hysteria2" | "hy2" => Some(Kind::Hysteria2),
        "vmess" => Some(Kind::Vmess),
        "ssr" | "shadowsocksr" => Some(Kind::ShadowsocksR),
        "tuic" => Some(Kind::Tuic),
        "anytls" => Some(Kind::AnyTls),
        // Both are dialled from the outside as often as they are dialled locally, and both dialects
        // are in the wild, so they are read: `socks5h` is SOCKS5 with remote resolution.
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => Some(Kind::Socks),
        "http" | "https" => Some(Kind::Http),
        _ => None,
    }
}

fn parse_client_tls(reader: &mut Reader<'_>, tls_only: bool) -> Option<TlsClient> {
    let mode = reader
        .owned("security")
        .unwrap_or_default()
        .to_ascii_lowercase();

    // A mode from a newer client is not a mode to drop: the parameter travels in the extras, and the
    // rest of the link is read as if it had not been written.
    if !matches!(mode.as_str(), "" | "none" | "tls" | "reality" | "xtls") {
        reader.release("security");
    }

    let mut tls = TlsClient::default();
    let mut requested = tls_only || matches!(mode.as_str(), "tls" | "reality" | "xtls");

    if let Some(name) = reader
        .any_owned(&["sni", "peer"])
        .filter(|name| !name.is_empty())
    {
        // A name that is an IP literal is not a name to verify against; keep it, the renderer decides.
        // A name that will not parse at all is given back rather than dropped.
        match crate::addr::Host::parse(&name) {
            Ok(host) => tls.server_name = Some(host),
            Err(_) => reader.release_any(&["sni", "peer"]),
        }

        requested = true;
    }

    if let Some(alpn) = reader.owned("alpn") {
        if alpn.is_empty() {
            // An empty list asks for nothing, and the writer has nothing to write back for it, so it is
            // given back rather than kept as a request: keeping it meant the request was gone the first
            // time the link was written out (the fuzzer's shape: a bare `alpn` next to an unreadable
            // `security`, which the TLS writer then declines to write as well).
            reader.release("alpn");
        } else {
            match tls::parse_alpn(&alpn) {
                Ok(alpn) => tls.alpn = alpn,
                Err(_) => reader.release("alpn"),
            }

            requested = true;
        }
    }

    if reader.flag(&["allowInsecure", "allow_insecure", "insecure"]) {
        tls.insecure = true;
        requested = true;
    }

    if let Some(fingerprint) = reader.any_owned(&["fp", "fingerprint"]) {
        match tls::Fingerprint::parse(&fingerprint) {
            Ok(fingerprint) => tls.fingerprint = Some(fingerprint),
            Err(_) => reader.release_any(&["fp", "fingerprint"]),
        }

        requested = true;
    }

    let public_key = reader.owned("pbk").unwrap_or_default();
    let short_id = reader.owned("sid").filter(|value| !value.is_empty());
    let spider_x = reader.owned("spx").filter(|value| !value.is_empty());

    if mode == "reality" || !public_key.is_empty() || short_id.is_some() || spider_x.is_some() {
        let mut reality = tls::RealityClient::new(public_key);

        // A short id or a spider path with no key is still a Reality node: the node is malformed, and
        // saying so is the renderer's job, not something to hide by dropping the object here.
        reality.short_id = short_id.and_then(|value| match tls::ShortId::parse(&value) {
            Ok(short_id) => Some(short_id),
            Err(_) => {
                reader.release("sid");

                None
            }
        });
        reality.spider_x = spider_x;
        tls.reality = Some(reality);
        requested = true;
    }

    requested.then_some(tls)
}

/// Read a value and interpret it, claiming the parameter only if the interpretation worked.
///
/// A value this build cannot interpret is neither an error nor a drop: the occurrence goes back to
/// being unclaimed, so it travels in the extras and the link keeps meaning what the provider wrote.
/// `Reader` documents the whole policy.
fn interpreted<'a, T>(
    reader: &mut Reader<'a>,
    name: &str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Option<T> {
    let value = reader.owned(name)?;

    match parse(&value) {
        Some(value) => Some(value),
        None => {
            reader.release(name);

            None
        }
    }
}

fn parse_transport(reader: &mut Reader<'_>) -> Option<Transport> {
    let name = reader
        .owned("type")
        .unwrap_or_default()
        .to_ascii_lowercase();

    match name.as_str() {
        "" | "tcp" | "raw" => None,
        "ws" | "websocket" => {
            let path = reader.owned("path").unwrap_or_else(|| Box::from("/"));
            let host = interpreted(reader, "host", |value| crate::addr::Host::parse(value).ok());
            let early_data = interpreted(reader, "ed", |value| value.parse::<u32>().ok());
            let header_name = reader.owned("eh").filter(|name| !name.is_empty());

            Some(Transport::Ws(transport::Ws {
                path,
                host,
                early_data,
                header_name,
                extra: RawParams::new(),
            }))
        }
        "grpc" | "gun" => {
            let service_name = reader
                .any_owned(&["serviceName", "servicename"])
                .unwrap_or_default();
            let authority = interpreted(reader, "authority", |value| {
                crate::addr::Host::parse(value).ok()
            });
            let multi_mode = reader
                .owned("mode")
                .map(|mode| mode.eq_ignore_ascii_case("multi"))
                .unwrap_or(false);

            Some(Transport::Grpc(transport::Grpc {
                service_name,
                authority,
                multi_mode,
                extra: RawParams::new(),
            }))
        }
        "h2" | "http" => {
            let host = interpreted(reader, "host", |value| crate::addr::Host::parse(value).ok());
            let path = reader.owned("path").filter(|value| !value.is_empty());

            Some(Transport::Http2(transport::Http2 {
                host,
                path,
                extra: RawParams::new(),
            }))
        }
        "httpupgrade" | "http-upgrade" => {
            // Modelled rather than kept whole: unlike the carriages this build has never heard of, its
            // host and path decide what the node is, so they belong in the model — and in the identity.
            let path = reader.owned("path").unwrap_or_else(|| Box::from("/"));
            let host = interpreted(reader, "host", |value| crate::addr::Host::parse(value).ok());

            Some(Transport::HttpUpgrade(transport::HttpUpgrade {
                host,
                path,
                extra: RawParams::new(),
            }))
        }
        "quic" => {
            let security = interpreted(reader, "quicSecurity", transport::QuicSecurity::parse)
                .unwrap_or_default();
            let key = reader.owned("key").unwrap_or_default();
            let header = reader.owned("headerType").filter(|value| !value.is_empty());

            Some(Transport::Quic(transport::Quic {
                security,
                key: crate::secret::Secret::new(key),
                header,
                extra: RawParams::new(),
            }))
        }
        other => Some(Transport::Other(transport::Other {
            name: Box::from(other),
            extra: RawParams::new(),
        })),
    }
}

/// Write TLS and carriage into a link.
pub(crate) fn write_shared(node: &Node<Client>, out: &mut String, first: &mut bool) {
    if let Some(tls) = &node.tls {
        let reality = tls.reality.is_some();

        // A `security` this build could not read is in the extras and is written below, as the provider
        // wrote it. Writing the derived one here as well would put the name in the link twice, and the
        // next read takes the first — so the link would come back saying TLS where it said something
        // else. Nothing is lost: a protocol that always terminates TLS says so by being that protocol,
        // and the read derives it again.
        if !node.extra.contains("security") {
            link::param(
                out,
                first,
                "security",
                if reality {
                    Some("reality")
                } else {
                    Some("tls")
                },
            );
        }

        if let Some(server_name) = &tls.server_name {
            link::param_display(out, first, "sni", server_name);
        }

        if !tls.alpn.is_empty() {
            link::param_display(out, first, "alpn", &AlpnList(&tls.alpn));
        }

        if tls.insecure {
            link::param(out, first, "allowInsecure", Some("1"));
        }

        if let Some(fingerprint) = &tls.fingerprint {
            link::param(out, first, "fp", Some(fingerprint.as_str()));
        }

        if let Some(reality) = &tls.reality {
            link::param(out, first, "pbk", Some(reality.public_key.as_str()));
            link::param(
                out,
                first,
                "sid",
                reality.short_id.as_ref().map(|id| id.as_str()),
            );
            link::param(out, first, "spx", reality.spider_x.as_deref());
        }
    }

    // A protocol whose carriage is not a parameter (hysteria2) must not write a `type=` that none of
    // its clients write, or the link stops round-tripping through other people's parsers.
    if node.transport != node.protocol.default_transport() {
        write_transport(&node.transport, out, first);
    }
}

fn write_transport(transport: &Transport, out: &mut String, first: &mut bool) {
    match transport {
        Transport::Tcp => {}
        Transport::Ws(ws) => {
            link::param(out, first, "type", Some("ws"));
            link::param(out, first, "path", Some(&ws.path));

            if let Some(host) = &ws.host {
                link::param_display(out, first, "host", host);
            }

            if let Some(early_data) = ws.early_data {
                link::param_display(out, first, "ed", &early_data);
            }

            if let Some(header_name) = &ws.header_name {
                link::param(out, first, "eh", Some(header_name));
            }
        }
        Transport::HttpUpgrade(upgrade) => {
            link::param(out, first, "type", Some("httpupgrade"));
            link::param(out, first, "path", Some(&upgrade.path));

            if let Some(host) = &upgrade.host {
                link::param_display(out, first, "host", host);
            }
        }
        Transport::Grpc(grpc) => {
            link::param(out, first, "type", Some("grpc"));
            link::param(out, first, "serviceName", Some(&grpc.service_name));

            if let Some(authority) = &grpc.authority {
                link::param_display(out, first, "authority", authority);
            }

            if grpc.multi_mode {
                link::param(out, first, "mode", Some("multi"));
            }
        }
        Transport::Http2(http) => {
            link::param(out, first, "type", Some("h2"));

            if let Some(host) = &http.host {
                link::param_display(out, first, "host", host);
            }

            link::param(out, first, "path", http.path.as_deref());
        }
        Transport::Quic(quic) => {
            link::param(out, first, "type", Some("quic"));
            link::param(out, first, "quicSecurity", Some(quic.security.as_str()));
            link::param(out, first, "key", Some(quic.key.as_str()));
            link::param(out, first, "headerType", quic.header.as_deref());
        }
        Transport::Other(other) => link::param(out, first, "type", Some(&other.name)),
    }
}

/// An ALPN list, as a link spells it.
struct AlpnList<'a>(&'a [Alpn]);

impl fmt::Display for AlpnList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        tls::write_alpn(self.0, f)
    }
}

/// Write a node's unmodelled parameters.
pub(crate) fn write_extra(params: &RawParams, out: &mut String, first: &mut bool) {
    for (name, value) in params.iter() {
        link::param(out, first, name, Some(value));
    }
}

impl Encode for Transport {
    fn encode(&self, out: &mut Hasher) {
        out.text(self.name());

        match self {
            Transport::Tcp => {}
            Transport::Ws(ws) => {
                out.optional(ws.header_name.as_deref());
                out.text(&ws.path);
                // A host is written through its display form, so that a domain and an IP literal
                // never hash alike by accident.
                out.optional_display(ws.host.as_ref().map(|host| host as &dyn fmt::Display));
                out.number(ws.early_data.unwrap_or(0) as u64);
            }
            Transport::HttpUpgrade(upgrade) => {
                out.optional_display(upgrade.host.as_ref().map(|host| host as &dyn fmt::Display));
                out.text(&upgrade.path);
            }
            Transport::Grpc(grpc) => {
                out.text(&grpc.service_name);
                // The authority is a dialled name: a node that verifies one is not the same node as one
                // that does not.
                out.optional_display(
                    grpc.authority
                        .as_ref()
                        .map(|host| host as &dyn fmt::Display),
                );
                out.flag(grpc.multi_mode);
            }
            Transport::Http2(http) => {
                out.optional_display(http.host.as_ref().map(|host| host as &dyn fmt::Display));
                out.optional(http.path.as_deref());
            }
            Transport::Quic(quic) => {
                out.text(quic.security.as_str());
                out.text(quic.key.as_str());
                out.optional(quic.header.as_deref());
            }
            Transport::Other(other) => out.text(&other.name),
        }
    }
}

impl Encode for TlsClient {
    fn encode(&self, out: &mut Hasher) {
        out.optional_display(
            self.server_name
                .as_ref()
                .map(|host| host as &dyn fmt::Display),
        );
        out.each(&self.alpn, |out, identifier| out.text(identifier.as_str()));
        out.flag(self.insecure);
        out.optional(
            self.fingerprint
                .as_ref()
                .map(|fingerprint| fingerprint.as_str()),
        );
        out.optional(
            self.reality
                .as_ref()
                .map(|reality| reality.public_key.as_str()),
        );
        out.optional(
            self.reality
                .as_ref()
                .and_then(|reality| reality.short_id.as_ref())
                .map(|short_id| short_id.as_str()),
        );
        out.optional(
            self.reality
                .as_ref()
                .and_then(|reality| reality.spider_x.as_deref()),
        );
    }
}

impl Encode for TlsServer {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.certificates, |out, certificate| {
            out.text(&certificate.certificate_path);
            out.text(&certificate.key_path);
        });
        out.each(&self.alpn, |out, identifier| out.text(identifier.as_str()));
        // How a listener treats client certificates decides who can connect, so it is part of what the
        // listener is.
        out.byte(self.client_auth as u8);

        match &self.reality {
            None => out.byte(0),
            Some(reality) => {
                out.byte(1);
                out.text(reality.private_key.as_str());
                out.each(&reality.short_ids, |out, short_id| {
                    out.text(short_id.as_str())
                });
                out.display(&reality.handshake);
                out.number(reality.max_time_diff_ms.unwrap_or(0));
            }
        }
    }
}

impl crate::identity::private::Sealed for Transport {}
impl crate::identity::private::Sealed for TlsClient {}
impl crate::identity::private::Sealed for TlsServer {}
impl crate::identity::private::Sealed for Outbound {}
impl crate::identity::private::Sealed for Inbound {}

#[cfg(test)]
mod tests {
    /// The list of schemes that speak TLS without saying so has to agree with each payload's own
    /// answer, or a link parses into a plaintext node that no client can dial.
    #[test]
    fn the_tls_only_scheme_list_agrees_with_the_payloads() {
        for (scheme, tls_only) in [
            ("vless", <vless::Client as ClientLink>::TLS_ONLY),
            ("trojan", <trojan::Client as ClientLink>::TLS_ONLY),
            ("ss", <shadowsocks::Client as ClientLink>::TLS_ONLY),
            ("hysteria2", <hysteria2::Client as ClientLink>::TLS_ONLY),
            ("hy2", <hysteria2::Client as ClientLink>::TLS_ONLY),
            ("anytls", true),
            ("tuic", true),
        ] {
            assert_eq!(scheme_is_tls_only(scheme), tls_only, "{scheme}");
        }
    }

    use super::*;
    use crate::error::ErrorKind;

    #[test]
    fn the_scheme_table_is_case_insensitive() {
        assert!(scheme_is_tls_only("Hysteria2"));
        assert!(scheme_is_tls_only("TROJAN"));
        assert!(!scheme_is_tls_only("vless"));
    }

    #[test]
    fn a_node_survives_a_round_trip_without_losing_parameters() {
        let text = "trojan://hunter2@example.com:443?security=tls&sni=www.apple.com&type=ws&path=%2Fws&host=cdn.example.com&weird=1&flag#Tokyo";
        let node = parse_link(text).unwrap();

        assert_eq!(node.protocol.kind(), Kind::Trojan);
        assert_eq!(node.extra.get("weird"), Some("1"));
        assert!(node.extra.contains("flag"));

        let again = write_link(&node).unwrap();
        let reparsed = parse_link(&again).unwrap();

        assert_eq!(reparsed, node);
        assert_eq!(reparsed.id(), node.id());
    }

    #[test]
    fn an_httpupgrade_carriage_is_modelled_rather_than_kept_whole() {
        // `httpupgrade` is a carriage sing-box has a name for, and its host and path decide what the
        // node dials: keeping it whole as `Other` put both outside the identity.
        let node = parse_link(
            "trojan://letmein@example.com:443?type=httpupgrade&path=%2Fup&host=cdn.example.com#T",
        )
        .expect("a link");

        let Transport::HttpUpgrade(upgrade) = &node.transport else {
            panic!("{:?}", node.transport);
        };

        assert_eq!(upgrade.path.as_ref(), "/up");
        assert_eq!(
            upgrade.host.as_ref().map(ToString::to_string).as_deref(),
            Some("cdn.example.com")
        );
        assert!(node.extra.is_empty(), "{:?}", node.extra);

        // The reader claims what it models and leaves the rest: an unmodelled parameter still travels.
        let other =
            parse_link("trojan://letmein@example.com:443?type=httpupgrade&path=%2Fup&tfo=1#T")
                .expect("a link");

        assert_eq!(other.extra.get("tfo"), Some("1"));
    }

    #[test]
    fn an_unknown_scheme_is_kept_whole() {
        let node = parse_link("snell://1.2.3.4:443?psk=secret#Mystery").unwrap();

        assert_eq!(node.protocol.kind(), Kind::Other);
        assert_eq!(node.protocol.scheme(), "snell");
        assert!(
            !node.protocol.has_credentials(),
            "an unmodelled payload claims nothing"
        );
    }

    #[test]
    fn a_link_without_an_address_is_reported_not_stored() {
        let error = parse_link("snell://something-odd#Mystery").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
    }

    /// Every kind reaches `scheme_kind`, from a scheme that resolves back to it.
    ///
    /// The `match` is the reason this test exists and the reason it is written this way: it is
    /// exhaustive, so a new protocol does not compile until it is named here, and the assertion then
    /// fails if `scheme_kind` was not told about the scheme either. That is the failure the migration
    /// hit — one missing arm, and eleven dialects quietly became `Opaque` — and nothing else in the
    /// crate notices it, because an unmodelled scheme is a supported state.
    #[test]
    fn every_kind_is_reachable_from_its_scheme() {
        for kind in [
            Kind::Vless,
            Kind::Trojan,
            Kind::Shadowsocks,
            Kind::Hysteria2,
            Kind::Vmess,
            Kind::ShadowsocksR,
            Kind::Tuic,
            Kind::AnyTls,
            Kind::Socks,
            Kind::Http,
            Kind::Other,
        ] {
            // `Other` is not a protocol — it is the payload that holds the ones this build does not
            // model — so it is the one kind with no scheme to check.
            let Some(scheme) = (match kind {
                Kind::Vless => Some("vless"),
                Kind::Trojan => Some("trojan"),
                Kind::Shadowsocks => Some("ss"),
                Kind::Hysteria2 => Some("hysteria2"),
                Kind::Vmess => Some("vmess"),
                Kind::ShadowsocksR => Some("ssr"),
                Kind::Tuic => Some("tuic"),
                Kind::AnyTls => Some("anytls"),
                Kind::Socks => Some("socks5"),
                Kind::Http => Some("http"),
                Kind::Other => None,
            }) else {
                continue;
            };

            assert_eq!(scheme_kind(scheme), Some(kind), "{scheme}");
        }

        // A scheme nobody models is `None`, never `Other`: the distinction is what makes the
        // completeness above checkable at all.
        assert_eq!(scheme_kind("snell"), None);
    }

    /// The aliases a provider may write, which are the schemes that are not canonical.
    #[test]
    fn the_alias_schemes_resolve_to_their_protocol() {
        for (scheme, kind) in [
            ("hy2", Kind::Hysteria2),
            ("socks", Kind::Socks),
            ("socks4", Kind::Socks),
            ("socks4a", Kind::Socks),
            ("socks5h", Kind::Socks),
            ("https", Kind::Http),
        ] {
            assert_eq!(scheme_kind(scheme), Some(kind), "{scheme}");
        }
    }
}
