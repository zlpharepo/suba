//! Nodes, and the direction they are used in.
//!
//! A proxy node is one thing seen two ways. A client dials it; a listener serves it. Almost every
//! field is the same — address, carriage, protocol — but the credentials, the TLS material and
//! whether there is a listen address are not, so the direction is a type parameter and the
//! differences hang off it. That is what lets one crate model a subscription and a server
//! configuration without either pretending to be the other, and it is why a future client can be
//! written against the same types.

use core::fmt;

use crate::addr::Endpoint;
use crate::identity::{Encode, Hasher, NodeFingerprint};
use crate::params::RawParams;
use crate::prelude::*;
use crate::protocol::{Inbound, Outbound};
use crate::tls::{TlsClient, TlsServer};
use crate::transport::Transport;

/// Which way a node is used.
///
/// Sealed: the two implementors are [`Client`] and [`Server`], and a third would mean a third set of
/// field shapes nobody has agreed on.
pub trait Direction: sealed::Sealed + Copy + Clone + fmt::Debug + 'static {
    /// The TLS material this direction carries.
    type Tls;
    /// The protocols this direction can express.
    type Protocol;
    /// `()` for a client; the bound address for a listener.
    type Listen;

    /// Which of the two this is.
    const KIND: Role;

    /// A name for it.
    fn kind() -> Role {
        Self::KIND
    }
}

/// Whether a node is dialled or served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Role {
    /// A node a client dials.
    Client,
    /// A node a listener serves.
    Server,
}

impl Role {
    /// A name for it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A node that is dialled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Client;

/// A node that is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Server;

impl Direction for Client {
    type Listen = ();
    type Protocol = Outbound;
    type Tls = TlsClient;

    const KIND: Role = Role::Client;
}

impl Direction for Server {
    type Listen = Endpoint;
    type Protocol = Inbound;
    type Tls = TlsServer;

    const KIND: Role = Role::Server;
}

mod sealed {
    /// The two directions, and nothing else.
    pub trait Sealed {}

    impl Sealed for super::Client {}
    impl Sealed for super::Server {}
}

/// A node's display name.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Name(Box<str>);

impl Name {
    /// A name.
    pub fn new(name: impl Into<Box<str>>) -> Self {
        Self(name.into())
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether there is a name at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for Name {
    fn from(value: &str) -> Self {
        Self(value.into())
    }
}

impl From<String> for Name {
    fn from(value: String) -> Self {
        Self(value.into_boxed_str())
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

/// One proxy endpoint.
///
/// `endpoint` is the address a client dials. For a listener it is the address handed out to clients
/// — the one that has to be reachable — which is not necessarily the address the kernel binds:
/// a listener usually binds `127.0.0.1` behind a reverse proxy, and telling a client to dial that is
/// how a subscription ends up full of nodes that cannot be reached. `listen` holds the bind address
/// for the server direction, and is `()` for a client, so a client pays nothing for a field it can
/// never have.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "D::Protocol: serde::Serialize, D::Tls: serde::Serialize, D::Listen: serde::Serialize",
        deserialize = "D::Protocol: serde::Deserialize<'de>, D::Tls: serde::Deserialize<'de>, D::Listen: serde::Deserialize<'de>",
    ))
)]
pub struct Node<D: Direction> {
    /// The display name. Not part of the identity.
    pub name: Name,
    /// The address a client dials, or the address advertised to clients.
    pub endpoint: Endpoint,
    /// The bind address, for the server direction.
    pub listen: D::Listen,
    /// How the protocol is carried.
    pub transport: Transport,
    /// TLS, when the node is wrapped in it. `None` is a node without TLS.
    pub tls: Option<D::Tls>,
    /// The protocol, in this direction's vocabulary.
    pub protocol: D::Protocol,
    /// Parameters nobody modelled. Kept so that writing the node back is lossless.
    pub extra: RawParams,
}

impl<D: Direction> Node<D> {
    /// Which way this node is used.
    pub fn direction(&self) -> Role {
        D::KIND
    }

    /// The node's identity: a content hash of everything that decides what it *is*.
    ///
    /// The name and the extra parameters are outside it: renaming a node does not make it a different
    /// node, and neither does the same provider spelling it differently. A listener's bind address is
    /// inside it, because where a listener binds decides what it serves.
    pub fn id(&self) -> NodeFingerprint
    where
        D::Protocol: Encode,
        D::Tls: Encode,
        D::Listen: Encode,
    {
        let mut hasher = Hasher::new();
        hasher.byte(match D::KIND {
            Role::Client => 1,
            Role::Server => 2,
        });
        Endpoint::encode(&self.endpoint, &mut hasher);
        // A client binds nothing (`()` encodes to nothing); a listener's bind address decides what it
        // serves, so moving it is a different listener and a different identity.
        self.listen.encode(&mut hasher);
        self.transport.encode(&mut hasher);

        match &self.tls {
            None => hasher.byte(0),
            Some(tls) => {
                hasher.byte(1);
                tls.encode(&mut hasher);
            }
        }

        self.protocol.encode(&mut hasher);
        hasher.finish()
    }
}

impl<D: Direction> fmt::Debug for Node<D>
where
    D::Protocol: fmt::Debug,
    D::Tls: fmt::Debug,
    D::Listen: fmt::Debug,
{
    /// Safe to print in full: every credential in the tree is a `Secret`, which prints as a
    /// placeholder.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("direction", &D::KIND)
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("listen", &self.listen)
            .field("transport", &self.transport)
            .field("tls", &self.tls)
            .field("protocol", &self.protocol)
            .field("extra", &self.extra)
            .finish()
    }
}

impl crate::identity::private::Sealed for () {}

impl Encode for () {
    /// A client's `listen` is nothing, and nothing is what it writes.
    fn encode(&self, _out: &mut Hasher) {}
}

impl Encode for Endpoint {
    fn encode(&self, out: &mut Hasher) {
        out.byte(match self.host {
            crate::addr::Host::Domain(_) => 1,
            crate::addr::Host::Ip(core::net::IpAddr::V4(_)) => 2,
            crate::addr::Host::Ip(core::net::IpAddr::V6(_)) => 3,
        });
        out.display(&self.host);
        out.number(self.port.get() as u64);
    }
}

impl crate::identity::private::Sealed for Endpoint {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Endpoint, Host, Port};
    use crate::protocol::{Opaque, Outbound};
    use crate::tls::TlsClient;

    fn node(name: &str, transport: Transport) -> Node<Client> {
        Node {
            name: Name::new(name),
            endpoint: Endpoint::new(Host::parse("example.com").unwrap(), Port::new(443).unwrap()),
            listen: (),
            transport,
            tls: Some(TlsClient {
                server_name: Some(Host::parse("example.com").unwrap()),
                ..TlsClient::default()
            }),
            protocol: Outbound::Other(Opaque::new("snell")),
            extra: RawParams::new(),
        }
    }

    #[test]
    fn a_rename_is_not_a_new_node() {
        assert_eq!(
            node("Tokyo", Transport::Tcp).id(),
            node("Tokyo Two", Transport::Tcp).id()
        );
    }

    #[test]
    fn a_different_carriage_is_a_new_node() {
        assert_ne!(
            node("Tokyo", Transport::Tcp).id(),
            node("Tokyo", Transport::Ws(Default::default())).id()
        );
    }

    #[test]
    fn a_direction_is_part_of_the_identity() {
        let client = node("Tokyo", Transport::Tcp);

        assert_eq!(client.direction(), Role::Client);
        assert!(!client.id().is_empty());
        assert_eq!(
            core::mem::size_of::<Node<Client>>(),
            core::mem::size_of::<Node<Client>>()
        );
    }

    #[test]
    fn a_client_pays_nothing_for_the_listen_field() {
        assert_eq!(core::mem::size_of::<()>(), 0);
    }
}
