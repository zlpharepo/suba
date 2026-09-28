//! Hysteria2.
//!
//! A QUIC protocol with one shared password per listener, an optional obfuscator in front of the
//! QUIC packets, and port hopping. Field names follow hysteria's own configuration — `obfs`, `ports`,
//! `hop_interval`, `up`, `down` — and not any consumer's spelling of them.
//!
//! Two things here are not link parameters and must not be treated as if they were:
//!
//! * The carriage is QUIC by construction, so [`ClientLink::default_transport`] says so instead of
//!   the link carrying a `type=` that no hysteria2 client writes.
//! * TLS is not optional either; [`ClientLink::TLS_ONLY`] is what makes a link that mentions no TLS
//!   parameter parse into a node that has TLS, rather than a plaintext one.

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{ClientLink, Kind, Protocol};
use crate::secret::Secret;
use crate::transport::Transport;

/// The obfuscator hysteria2 puts in front of its QUIC packets.
///
/// `salamander` is the only one upstream ships, and it is what every client writes, so the type is an
/// enum rather than a string: an unknown value is a provider doing something this build does not
/// know about, and that belongs in the node's unmodelled parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Obfs {
    /// The obfuscator upstream ships.
    Salamander,
}

impl Obfs {
    /// The spelling hysteria uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Salamander => "salamander",
        }
    }

    /// Read the spelling.
    pub fn parse(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().as_str() {
            "salamander" => Some(Self::Salamander),
            _ => None,
        }
    }
}

impl fmt::Display for Obfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A hysteria2 password, and the obfuscator password that goes with it.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The authentication password. The only credential in the protocol.
    pub password: Secret<Box<str>>,
    /// The obfuscator, when one is in use.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub obfs: Option<Obfs>,
    /// The obfuscator's password, when the obfuscator needs one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub obfs_password: Option<Secret<Box<str>>>,
    /// Ports to hop between, as hysteria spells them: `1000-2000,3000`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub ports: Option<Box<str>>,
    /// How often to hop, in seconds.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub hop_interval: Option<u64>,
    /// The client's uplink, in Mbps.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub up: Option<u64>,
    /// The client's downlink, in Mbps.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub down: Option<u64>,
    /// A pinned certificate, by SHA-256 of its public key.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pin_sha256: Option<Box<str>>,
}

/// One password on a hysteria2 listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The password this user authenticates with.
    pub password: Secret<Box<str>>,
}

impl User {
    /// A user.
    pub fn new(password: impl Into<Box<str>>) -> Self {
        Self {
            password: Secret::new(password.into()),
        }
    }
}

/// A hysteria2 listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// Everyone allowed in. A listener with no users lets nobody in.
    pub users: Vec<User>,
    /// The obfuscator, when one is in use.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub obfs: Option<Obfs>,
    /// The password both ends of the obfuscator share.
    ///
    /// A listener needs it as much as a client does: `salamander` authenticates every packet with it,
    /// so a listener without it would decrypt nothing. A share link carries it, which is why a
    /// listener built from one has it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub obfs_password: Option<Secret<Box<str>>>,
    /// The listener's uplink, in Mbps.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub up: Option<u64>,
    /// The listener's downlink, in Mbps.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub down: Option<u64>,
}

// No `Default`: an empty listener is a decision, not something a derive should do by accident.
#[allow(clippy::new_without_default)]
impl Server {
    /// A listener with no users.
    pub fn new() -> Self {
        Self {
            users: Vec::new(),
            obfs: None,
            obfs_password: None,
            up: None,
            down: None,
        }
    }

    /// Whether there is anyone who can get in, and everyone can understand each other.
    pub fn is_complete(&self) -> bool {
        !self.users.is_empty() && (self.obfs.is_none() || self.obfs_password.is_some())
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Hysteria2
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.password.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Hysteria2
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
    const KIND: Kind = Kind::Hysteria2;
    const SCHEME: &'static str = "hysteria2";
    const TLS_ONLY: bool = true;

    fn from_query(reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        if userinfo.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "auth"));
        }

        // An obfuscation this build cannot read is given back rather than dropped: it travels in the
        // extras and comes out again.
        let obfs = match reader.owned("obfs") {
            Some(value) => match Obfs::parse(&value) {
                Some(obfs) => Some(obfs),
                None => {
                    reader.release("obfs");

                    None
                }
            },
            None => None,
        };

        Ok(Self {
            password: Secret::new(userinfo.into()),
            obfs,
            obfs_password: reader.owned("obfs-password").map(Secret::new),
            ports: reader.any_owned(&["mport", "ports"]),
            hop_interval: reader.number("hop-interval"),
            up: reader.number("up"),
            down: reader.number("down"),
            pin_sha256: reader.any_owned(&["pinSHA256", "pin_sha256"]),
        })
    }

    fn write_params(&self, out: &mut String, first: &mut bool) -> Result<()> {
        if let Some(obfs) = self.obfs {
            link::param(out, first, "obfs", Some(obfs.as_str()));
        }

        link::param(
            out,
            first,
            "obfs-password",
            self.obfs_password.as_ref().map(Secret::as_str),
        );
        link::param(out, first, "mport", self.ports.as_deref());
        link::number(out, first, "hop-interval", self.hop_interval);
        link::number(out, first, "up", self.up);
        link::number(out, first, "down", self.down);
        link::param(out, first, "pinSHA256", self.pin_sha256.as_deref());

        Ok(())
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        link::begin(out, Self::SCHEME, self.password.as_str(), &node.endpoint);

        let mut first = true;
        self.write_params(out, &mut first)?;
        crate::protocol::write_shared(node, out, &mut first);
        crate::protocol::write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }

    fn default_transport() -> Transport {
        // Hysteria2 is QUIC by construction. A link says nothing about carriage because there is
        // nothing to say.
        Transport::Quic(crate::transport::Quic::default())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(self.password.expose());
        out.optional(self.obfs.map(Obfs::as_str));
        out.optional(self.obfs_password.as_ref().map(Secret::as_str));
        out.optional(self.ports.as_deref());
        out.number(self.hop_interval.unwrap_or(0));
        out.number(self.up.unwrap_or(0));
        out.number(self.down.unwrap_or(0));
        out.optional(self.pin_sha256.as_deref());
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| out.text(user.password.expose()));
        out.optional(self.obfs.map(Obfs::as_str));
        out.optional(self.obfs_password.as_ref().map(Secret::as_str));
        out.number(self.up.unwrap_or(0));
        out.number(self.down.unwrap_or(0));
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("hysteria2::Client")
            .field("password", &self.password)
            .field("obfs", &self.obfs)
            .field("obfs_password", &self.obfs_password)
            .field("ports", &self.ports)
            .field("hop_interval", &self.hop_interval)
            .field("up", &self.up)
            .field("down", &self.down)
            .field("pin_sha256", &self.pin_sha256)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link};

    const LINK: &str = "hysteria2://letmein@example.com:443?obfs=salamander&obfs-password=obfssecret&sni=www.apple.com&mport=1000-2000,3000&up=100&down=200#Tokyo";

    #[test]
    fn a_link_parses_into_the_protocols_own_fields() {
        let node = parse_link(LINK).unwrap();

        let client = node.protocol.as_hysteria2().unwrap();
        assert_eq!(client.password.as_str(), "letmein");
        assert_eq!(client.obfs, Some(Obfs::Salamander));
        assert_eq!(
            client.obfs_password.as_ref().map(Secret::as_str),
            Some("obfssecret")
        );
        assert_eq!(client.ports.as_deref(), Some("1000-2000,3000"));
        assert_eq!(client.up, Some(100));
        assert_eq!(client.down, Some(200));
    }

    #[test]
    fn the_carriage_is_the_protocols_not_the_links() {
        let node = parse_link(LINK).unwrap();

        // No `type=` anywhere in that link, and the node is still QUIC: a hysteria2 node that claimed
        // TCP would be a node no client could dial.
        assert_eq!(node.transport.name(), "quic");
    }

    #[test]
    fn a_link_with_no_tls_parameters_still_speaks_tls() {
        let node = parse_link("hysteria2://letmein@example.com:443#Tokyo").unwrap();

        assert!(node.tls.is_some());
        assert_eq!(node.protocol.scheme(), "hysteria2");
    }

    #[test]
    fn a_bandwidth_written_with_a_unit_still_reads() {
        // `up=100 mbps` is the spelling hysteria2's own documentation uses. The unit is not part of
        // the number, and dropping the parameter instead would lose what the provider said.
        let node = parse_link(
            "hysteria2://letmein@example.com:443?up=100%20mbps&down=200Mbps&hop-interval=30s#Tokyo",
        )
        .unwrap();
        let client = node.protocol.as_hysteria2().unwrap();

        assert_eq!(client.up, Some(100));
        assert_eq!(client.down, Some(200));
        assert_eq!(client.hop_interval, Some(30));

        // What is written back is the number: a unit is presentation, not data.
        let written = write_link(&node).unwrap();
        assert!(written.contains("up=100"), "{written}");
        assert!(!written.contains("mbps"), "{written}");
    }

    #[test]
    fn a_listener_whose_obfuscator_has_no_password_is_incomplete() {
        let mut server = Server::new();
        server.users.push(User::new("letmein"));

        assert!(server.is_complete());

        // `salamander` derives its key from the password, so a listener that has the obfuscator but
        // not the password can decrypt nothing: that is an incomplete listener, not a valid one.
        server.obfs = Some(Obfs::Salamander);
        assert!(!server.is_complete());

        server.obfs_password = Some(Secret::new(Box::from("obfspw")));
        assert!(server.is_complete());
    }

    #[test]
    fn the_short_scheme_is_the_same_protocol() {
        let node = parse_link("hy2://letmein@example.com:443#Tokyo").unwrap();

        assert_eq!(node.protocol.kind(), Kind::Hysteria2);
    }

    #[test]
    fn a_link_without_a_password_is_reported() {
        let error = parse_link("hysteria2://example.com:443#Tokyo").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
        assert!(error.reason().contains("auth"), "{}", error.reason());
    }

    #[test]
    fn a_link_round_trips() {
        let node = parse_link(LINK).unwrap();
        let written = write_link(&node).unwrap();
        let again = parse_link(&written).unwrap();

        assert_eq!(again, node, "{written}");
        assert_eq!(again.id(), node.id());
        assert!(!written.contains("type="), "{written}");
    }

    #[test]
    fn the_password_never_reaches_a_rendering() {
        let node = parse_link(LINK).unwrap();
        let rendered = format!("{:?}", node.protocol);

        assert!(rendered.contains("hysteria2::Client"), "{rendered}");
        assert!(!rendered.contains("letmein"), "{rendered}");
        assert!(!rendered.contains("obfssecret"), "{rendered}");
    }

    #[test]
    fn a_listener_with_no_users_lets_nobody_in() {
        assert!(!Server::new().is_complete());

        let mut server = Server::new();
        server.users.push(User::new("letmein"));
        assert!(server.is_complete());
    }
}
