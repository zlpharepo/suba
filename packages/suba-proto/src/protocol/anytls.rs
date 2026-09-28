//! AnyTLS.
//!
//! A TLS connection with a session multiplexer on top and padding to disguise its shape. The protocol
//! itself is thin — one password per client, a user list on the listener — and it has one property the
//! model has to respect: it does not exist without TLS, so a link that mentions none still speaks it
//! ([`TLS_ONLY`](ClientLink::TLS_ONLY)).
//!
//! ```text
//! anytls://PASSWORD@example.com:443?sni=www.apple.com#Tokyo
//! ```

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{ClientLink, Kind, Protocol};
use crate::secret::Secret;

/// An AnyTLS client: one password, and the padding the two sides were told to use.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The password.
    pub password: Secret<Box<str>>,
}

/// One user on an AnyTLS listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The password.
    pub password: Secret<Box<str>>,
}

/// An AnyTLS listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// Everyone allowed in.
    pub users: Vec<User>,
}

impl Server {
    /// Whether there is anyone who can get in.
    pub fn is_complete(&self) -> bool {
        !self.users.is_empty() && self.users.iter().all(|user| !user.password.is_empty())
    }
}

impl Client {
    /// A client with a password.
    pub fn new(password: impl Into<Box<str>>) -> Self {
        Self {
            password: Secret::new(password.into()),
        }
    }

    /// The password, for the one caller allowed to hold it.
    pub fn password(&self) -> &str {
        self.password.expose()
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::AnyTls
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
        Kind::AnyTls
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
    const KIND: Kind = Kind::AnyTls;
    const SCHEME: &'static str = "anytls";

    /// AnyTLS is a TLS connection by construction; a link that says nothing still speaks it.
    const TLS_ONLY: bool = true;

    fn from_query(reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        let password = reader
            .owned("password")
            .unwrap_or_else(|| Box::from(userinfo));

        if password.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "password"));
        }

        Ok(Self {
            password: Secret::new(password),
        })
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        let mut first = true;

        link::begin_display(out, Self::SCHEME, self.password.expose(), &node.endpoint);
        crate::protocol::write_shared(node, out, &mut first);
        crate::protocol::write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.display(self.password.expose());
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| out.display(user.password.expose()));
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("password", &self.password)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link};

    #[test]
    fn a_link_becomes_a_node_and_back() {
        let node = parse_link("anytls://letmein@example.com:443?sni=www.apple.com#Tokyo").unwrap();

        assert_eq!(node.protocol.as_anytls().unwrap().password(), "letmein");
        // TLS without being told: the protocol has no other way to be carried.
        let tls = node.tls.as_ref().unwrap();
        assert_eq!(
            tls.server_name.as_ref().unwrap().domain(),
            Some("www.apple.com")
        );

        let again = parse_link(&write_link(&node).unwrap()).unwrap();
        assert_eq!(again, node);
    }

    #[test]
    fn a_link_without_a_password_is_reported() {
        let error = parse_link("anytls://@example.com:443").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
        assert!(error.reason().contains("password"), "{}", error.reason());
    }

    #[test]
    fn the_password_never_reaches_a_rendering() {
        let node = parse_link("anytls://letmein@example.com:443?sni=www.apple.com").unwrap();
        let rendered = format!("{:?}", node.protocol);

        assert!(!rendered.contains("letmein"), "{rendered}");
    }
}
