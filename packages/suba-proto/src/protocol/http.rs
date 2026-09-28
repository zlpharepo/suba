//! HTTP CONNECT.
//!
//! A local HTTP proxy, and like [`socks`](super::socks) it also has a link form, because both are
//! dialled from the outside too: `http://user:pass@host:8080#Name` is the dialect. `https://` is the
//! same thing over TLS, so the scheme decides it and the writer picks `https` whenever the node
//! carries TLS.

use crate::error::Result;
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;

/// An HTTP CONNECT dialer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The username, when the proxy asks for one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub username: Option<Box<str>>,
    /// The password, when the proxy asks for one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub password: Option<Secret<Box<str>>>,
}

/// One user on an HTTP listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The username.
    pub username: Box<str>,
    /// The password.
    pub password: Secret<Box<str>>,
}

/// An HTTP listener.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// Everyone allowed in. Empty means no authentication.
    pub users: Vec<User>,
}

impl Server {
    /// Whether the listener can serve anyone.
    pub fn is_complete(&self) -> bool {
        true
    }
}

impl Client {
    /// Whether the dialer carries a credential.
    pub fn has_credentials(&self) -> bool {
        self.username.is_some()
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Http
    }

    fn scheme(&self) -> &str {
        "http"
    }

    fn has_credentials(&self) -> bool {
        Client::has_credentials(self)
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Http
    }

    fn scheme(&self) -> &str {
        "http"
    }

    fn has_credentials(&self) -> bool {
        !self.users.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Http;
    const SCHEME: &'static str = "http";

    fn from_query(_reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        let (username, password) = match userinfo.split_once(':') {
            Some((username, password)) => (username, Some(password)),
            None => (userinfo, None),
        };

        Ok(Self {
            username: (!username.is_empty()).then(|| Box::from(username)),
            password: password
                .filter(|password| !password.is_empty())
                .map(|password| Secret::new(Box::from(password))),
        })
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        // Same grammar as `socks5://`: two fields, one separator that is not part of either.
        let mut userinfo = String::new();

        if let Some(username) = &self.username {
            crate::percent::encode_into(username, &mut userinfo);
        }
        if let Some(password) = &self.password {
            userinfo.push(':');
            crate::percent::encode_into(password.as_str(), &mut userinfo);
        }

        // `https` is the scheme for the TLS half of the same protocol, so a node that carries TLS is
        // written as one and reads back as TLS without a parameter saying so.
        let scheme = match node.tls.is_some() {
            true => "https",
            false => Self::SCHEME,
        };

        let mut first = true;
        link::begin_encoded(out, scheme, &userinfo, &node.endpoint);
        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.optional(self.username.as_deref());
        out.optional_display(
            self.password
                .as_ref()
                .map(|password| password.expose() as &dyn core::fmt::Display),
        );
    }
}

impl Encode for Server {
    fn encode(&self, out: &mut Hasher) {
        out.each(&self.users, |out, user| {
            out.text(&user.username);
            out.display(user.password.expose());
        });
    }
}

impl crate::identity::private::Sealed for Client {}
impl crate::identity::private::Sealed for Server {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use crate::node::{Client as ClientRole, Node};
    use crate::protocol::{parse_link, write_link, Outbound};

    fn dialer() -> Node<ClientRole> {
        Node {
            name: crate::node::Name::new("Local"),
            endpoint: crate::addr::Endpoint::parse("127.0.0.1:8080").unwrap(),
            listen: (),
            transport: crate::transport::Transport::Tcp,
            tls: None,
            protocol: Outbound::Http(Client::default()),
            extra: crate::params::RawParams::new(),
        }
    }

    #[test]
    fn a_link_round_trips_with_its_credentials() -> Result<()> {
        let node = parse_link("http://doge:letmein@127.0.0.1:8080#Local")?;

        assert_eq!(node.protocol.kind(), Kind::Http);
        assert!(node.protocol.has_credentials());
        assert_eq!(
            write_link(&node)?,
            "http://doge:letmein@127.0.0.1:8080#Local"
        );
        assert_eq!(parse_link(&write_link(&node)?)?.protocol, node.protocol);

        Ok(())
    }

    #[test]
    fn https_is_the_same_protocol_over_tls() -> Result<()> {
        let node = parse_link("https://127.0.0.1:8443#Local")?;

        assert!(node.tls.is_some(), "the scheme says TLS");
        assert!(write_link(&node)?.starts_with("https://"));
        assert!(parse_link(&write_link(&node)?)?.tls.is_some());

        Ok(())
    }

    #[test]
    fn it_names_itself_without_a_scheme_of_its_own() {
        let node = dialer();

        assert_eq!(node.protocol.kind(), Kind::Http);
        assert_eq!(node.protocol.scheme(), "http");
        assert!(!node.protocol.has_credentials());
    }
}
