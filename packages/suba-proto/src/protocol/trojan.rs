//! Trojan.
//!
//! A password and a TLS connection, which is the whole protocol. A listener holds many passwords
//! where a client holds one, and it may hand an unauthorised connection to a real site — the
//! fallback, which is a listener-side idea and is modelled as one.

use core::fmt;

use crate::addr::Endpoint;
use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;

/// A client's Trojan credentials.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The password.
    pub password: Secret<Box<str>>,
}

/// One password a Trojan listener accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The password.
    pub password: Secret<Box<str>>,
    /// The Xray user level, which decides policy.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub level: Option<u8>,
}

/// A Trojan listener.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// The passwords the listener accepts.
    pub users: Vec<User>,
    /// Where to send a connection that does not authenticate.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub fallback: Option<Endpoint>,
}

impl Client {
    /// Build one from a password.
    pub fn new(password: impl Into<Box<str>>) -> Self {
        Self {
            password: Secret::new(password.into()),
        }
    }

    /// Whether the password is there.
    pub fn is_complete(&self) -> bool {
        !self.password.is_empty()
    }
}

impl Server {
    /// Build one from a list of passwords.
    pub fn with_passwords(passwords: impl IntoIterator<Item = impl Into<Box<str>>>) -> Self {
        Self {
            users: passwords
                .into_iter()
                .map(|password| User {
                    password: Secret::new(password.into()),
                    level: None,
                })
                .collect(),
            fallback: None,
        }
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Trojan
    }

    fn scheme(&self) -> &str {
        <Self as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        self.is_complete()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Trojan
    }

    fn scheme(&self) -> &str {
        <Client as ClientLink>::SCHEME
    }

    fn has_credentials(&self) -> bool {
        !self.users.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Trojan;
    const SCHEME: &'static str = "trojan";

    /// Trojan authenticates with TLS by construction: a link that mentions none dials TLS with
    /// verification on.
    const TLS_ONLY: bool = true;

    fn from_query(_reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        if userinfo.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "password"));
        }

        Ok(Client::new(userinfo))
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        if self.password.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "password"));
        }

        let mut first = true;
        link::begin(out, Self::SCHEME, self.password.as_str(), &node.endpoint);
        self.write_params(out, &mut first)?;
        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(self.password.as_str());
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| {
            out.text(user.password.as_str());
        });

        match &self.fallback {
            None => out.byte(0),
            Some(fallback) => {
                out.byte(1);
                let mut text = String::new();
                fallback.write_to(&mut text);
                out.text(&text);
            }
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("password", &self.password)
            .finish()
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("users", &self.users)
            .field("fallback", &self.fallback)
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
    fn a_trojan_link_carries_a_password_in_the_userinfo() {
        let node = parse_link("trojan://hunter2@example.com:443?sni=www.apple.com#Tokyo").unwrap();
        let trojan = node.protocol.as_trojan().unwrap();

        assert_eq!(trojan.password.as_str(), "hunter2");
        assert!(Protocol::has_credentials(&node.protocol));

        let tls = node
            .tls
            .as_ref()
            .expect("trojan speaks TLS by construction");
        assert_eq!(
            tls.server_name.as_ref().unwrap().domain(),
            Some("www.apple.com")
        );
    }

    #[test]
    fn the_password_is_percent_decoded_and_never_printed() {
        let node = parse_link("trojan://p%40ss%2Fword@example.com:443#N").unwrap();
        let trojan = node.protocol.as_trojan().unwrap();

        assert_eq!(trojan.password.as_str(), "p@ss/word");
        assert!(!format!("{node:?}").contains("p@ss/word"));
        assert!(write_link(&node).unwrap().contains("p%40ss%2Fword"));
    }

    #[test]
    fn a_link_without_a_password_is_reported() {
        let error = parse_link("trojan://example.com:443#Tokyo").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::MissingField);
    }

    #[test]
    fn a_listener_holds_many_passwords_and_a_fallback() {
        let mut server = Server::with_passwords(["one", "two"]);

        server.fallback = Some(Endpoint::parse("127.0.0.1:8080").unwrap());

        assert_eq!(server.users.len(), 2);
        assert!(Protocol::has_credentials(&server));
        assert_eq!(server.fallback.unwrap().to_string(), "127.0.0.1:8080");
    }
}
