//! TUIC.
//!
//! QUIC by construction, like Hysteria2, and TLS with it. The credential is a pair — a UUID and a
//! password — which is why its links write `uuid:password` in the userinfo, and why the carriage is
//! this protocol's property rather than a parameter a link could contradict.
//!
//! ```text
//! tuic://UUID:PASSWORD@example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=www.apple.com#Tokyo
//! ```

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{ClientLink, Kind, Protocol};
use crate::secret::Secret;
use crate::transport::{Quic, Transport};
use crate::uuid::Uuid;

/// How TUIC reacts to congestion.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CongestionControl {
    /// CUBIC, the default everywhere.
    #[default]
    Cubic,
    /// NewReno.
    NewReno,
    /// BBR, which is what a long fat pipe wants.
    Bbr,
}

impl CongestionControl {
    /// The spelling the link and the wire use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
            Self::Bbr => "bbr",
        }
    }

    /// Read the spelling. An unknown one is `None` rather than a guess.
    pub fn parse(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().replace('-', "_").as_str() {
            "cubic" => Some(Self::Cubic),
            "new_reno" | "newreno" => Some(Self::NewReno),
            "bbr" => Some(Self::Bbr),
            _ => None,
        }
    }
}

impl fmt::Display for CongestionControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How TUIC carries UDP inside QUIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UdpRelayMode {
    /// UDP over the QUIC stream.
    Native,
    /// UDP over QUIC datagrams.
    Quic,
}

impl UdpRelayMode {
    /// The spelling the link and the wire use.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Quic => "quic",
        }
    }

    /// Read the spelling.
    pub fn parse(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().as_str() {
            "native" => Some(Self::Native),
            "quic" => Some(Self::Quic),
            _ => None,
        }
    }
}

impl fmt::Display for UdpRelayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A TUIC client.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The UUID.
    pub uuid: Secret<Uuid>,
    /// The password.
    pub password: Secret<Box<str>>,
    /// How to react to congestion.
    pub congestion_control: CongestionControl,
    /// How to carry UDP, when the link says.
    pub udp_relay_mode: Option<UdpRelayMode>,
    /// Whether a reconnection may start before the handshake finishes.
    pub zero_rtt_handshake: bool,
}

/// One user on a TUIC listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The UUID.
    pub uuid: Secret<Uuid>,
    /// The password.
    pub password: Secret<Box<str>>,
    /// The user's level, which TUIC carries but nothing enforces.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub level: Option<u8>,
}

/// A TUIC listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// Everyone allowed in.
    pub users: Vec<User>,
    /// How to react to congestion.
    pub congestion_control: CongestionControl,
    /// Whether a reconnection may start before the handshake finishes.
    pub zero_rtt_handshake: bool,
}

impl Server {
    /// Whether there is anyone who can get in.
    pub fn is_complete(&self) -> bool {
        !self.users.is_empty()
            && self
                .users
                .iter()
                .all(|user| !user.password.is_empty() && !user.uuid.expose().is_nil())
    }
}

impl Client {
    /// A client with a credential pair.
    pub fn new(uuid: Uuid, password: impl Into<Box<str>>) -> Self {
        Self {
            uuid: Secret::new(uuid),
            password: Secret::new(password.into()),
            congestion_control: CongestionControl::default(),
            udp_relay_mode: None,
            zero_rtt_handshake: false,
        }
    }

    /// The UUID.
    pub fn id(&self) -> &Uuid {
        self.uuid.expose()
    }

    /// The password, for the one caller allowed to hold it.
    pub fn password(&self) -> &str {
        self.password.expose()
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Tuic
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.password.is_empty() && !self.uuid.expose().is_nil()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Tuic
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

impl ClientLink for Client {
    const KIND: Kind = Kind::Tuic;
    const SCHEME: &'static str = "tuic";

    /// TUIC is QUIC, and QUIC is TLS.
    const TLS_ONLY: bool = true;

    fn default_transport() -> Transport {
        // TUIC is QUIC by construction. A link says nothing about carriage because there is nothing to
        // say, and a `type=` parameter would be a lie about the wire.
        Transport::Quic(Quic::default())
    }

    fn from_query(reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        // The pair is written `uuid:password`, which is the one place in these dialects where the
        // userinfo holds two fields.
        let (id, password) = userinfo.split_once(':').ok_or_else(|| {
            Error::field(
                ErrorKind::MissingField,
                "uuid:password (the userinfo holds both)",
            )
        })?;

        if id.is_empty() || password.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "uuid:password"));
        }

        Ok(Self {
            uuid: Secret::new(Uuid::parse(id)?),
            password: Secret::new(Box::from(password)),
            congestion_control: reader
                .owned("congestion_control")
                .and_then(|value| CongestionControl::parse(&value))
                .unwrap_or_default(),
            udp_relay_mode: reader
                .owned("udp_relay_mode")
                .and_then(|value| UdpRelayMode::parse(&value)),
            zero_rtt_handshake: reader.flag(&["zero_rtt_handshake", "zero_rtt"]),
        })
    }

    fn write_params(&self, out: &mut String, first: &mut bool) -> Result<()> {
        link::param(
            out,
            first,
            "congestion_control",
            Some(self.congestion_control.as_str()),
        );
        link::param(
            out,
            first,
            "udp_relay_mode",
            self.udp_relay_mode.map(UdpRelayMode::as_str),
        );

        if self.zero_rtt_handshake {
            link::param(out, first, "zero_rtt_handshake", Some("1"));
        }

        Ok(())
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        let mut first = true;
        // Two fields joined by a separator: each half is encoded, the separator is not, which is what
        // `begin_encoded` is for. A password containing `@` would otherwise move the host.
        let mut userinfo = String::new();
        crate::percent::encode_display(self.uuid.expose(), &mut userinfo);
        userinfo.push(':');
        crate::percent::encode_into(self.password.expose(), &mut userinfo);

        link::begin_encoded(out, Self::SCHEME, &userinfo, &node.endpoint);
        self.write_params(out, &mut first)?;
        crate::protocol::write_shared(node, out, &mut first);
        crate::protocol::write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.display(self.uuid.expose());
        out.display(self.password.expose());
        out.text(self.congestion_control.as_str());
        out.optional(self.udp_relay_mode.map(UdpRelayMode::as_str));
        out.flag(self.zero_rtt_handshake);
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| {
            out.display(user.uuid.expose());
            out.display(user.password.expose());
            out.number(user.level.unwrap_or(0) as u64);
        });
        out.text(self.congestion_control.as_str());
        out.flag(self.zero_rtt_handshake);
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("uuid", &self.uuid)
            .field("password", &self.password)
            .field("congestion_control", &self.congestion_control)
            .field("udp_relay_mode", &self.udp_relay_mode)
            .field("zero_rtt_handshake", &self.zero_rtt_handshake)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link};

    const TUIC: &str = "tuic://11111111-2222-3333-4444-555555555555:letmein@example.com:443\
                        ?congestion_control=bbr&udp_relay_mode=native&sni=www.apple.com&alpn=h3#Tokyo";

    #[test]
    fn a_link_becomes_a_node_and_back() {
        let node = parse_link(TUIC).unwrap();

        let client = node.protocol.as_tuic().unwrap();
        assert_eq!(
            client.id().to_string(),
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(client.password(), "letmein");
        assert_eq!(client.congestion_control, CongestionControl::Bbr);
        assert_eq!(client.udp_relay_mode, Some(UdpRelayMode::Native));

        // QUIC without being told, and it does not come back as a parameter nobody wrote.
        assert_eq!(node.transport.name(), "quic");
        assert_eq!(node.transport.extra().len(), 0);

        let written = write_link(&node).unwrap();
        assert!(!written.contains("type="), "{written}");
        assert_eq!(parse_link(&written).unwrap(), node);
    }

    #[test]
    fn a_userinfo_without_both_halves_is_reported() {
        let error = parse_link("tuic://letmein@example.com:443").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
        assert!(
            error.reason().contains("uuid:password"),
            "{}",
            error.reason()
        );
    }

    #[test]
    fn the_credential_never_reaches_a_rendering() {
        let node = parse_link(TUIC).unwrap();
        let rendered = format!("{:?}", node.protocol);

        assert!(!rendered.contains("letmein"), "{rendered}");
        assert!(
            !rendered.contains("11111111-2222-3333-4444-555555555555"),
            "{rendered}"
        );
    }
}
