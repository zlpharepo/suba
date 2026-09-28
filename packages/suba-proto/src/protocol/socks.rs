//! SOCKS.
//!
//! Both a listener a client dials locally and a proxy a provider can actually sell, which is why it
//! has a link form after all: `socks5://user:pass@host:1080#Name` is what providers and other tools
//! write, and the credentials sit in the userinfo the way SIP002 puts them. The version comes from
//! the scheme — `socks4`, `socks4a`, `socks5`, `socks5h` are all read, `socks5` is what is written
//! when nothing says otherwise.
//!
//! This is a dialer with no server-side analogue in the wild, so the link is a dialer's.

use core::fmt;

use crate::error::Result;
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;

/// Which SOCKS speaks the listener.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Version {
    /// SOCKS4.
    V4,
    /// SOCKS5, with authentication when credentials are set.
    #[default]
    V5,
}

impl Version {
    /// The spelling the wire uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "4",
            Self::V5 => "5",
        }
    }

    /// The version a scheme names.
    ///
    /// `socks5h` is SOCKS5 with remote name resolution, which is a client-side behaviour rather than
    /// a different protocol on the wire, so it reads as V5.
    pub fn from_scheme(scheme: &str) -> Self {
        match scheme.to_ascii_lowercase().as_str() {
            "socks4" | "socks4a" => Self::V4,
            _ => Self::V5,
        }
    }

    /// The scheme this version is written as.
    pub const fn scheme(self) -> &'static str {
        match self {
            Self::V4 => "socks4",
            Self::V5 => "socks5",
        }
    }

    /// Read the spelling.
    pub fn parse(input: &str) -> Option<Self> {
        match input.to_ascii_lowercase().as_str() {
            "4" | "4a" | "v4" => Some(Self::V4),
            "5" | "v5" => Some(Self::V5),
            _ => None,
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A SOCKS dialer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// Which SOCKS this is.
    pub version: Version,
    /// The username, when the proxy asks for one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub username: Option<Box<str>>,
    /// The password, when the proxy asks for one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub password: Option<Secret<Box<str>>>,
}

/// One user on a SOCKS listener.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct User {
    /// The username.
    pub username: Box<str>,
    /// The password.
    pub password: Secret<Box<str>>,
}

/// A SOCKS listener.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Server {
    /// Which SOCKS this is.
    pub version: Version,
    /// Everyone allowed in. Empty means no authentication, which is normal for a local listener.
    pub users: Vec<User>,
}

impl Server {
    /// Whether the listener can serve anyone. A local listener with no users is still complete.
    pub fn is_complete(&self) -> bool {
        true
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Socks
    }

    fn scheme(&self) -> &str {
        "socks"
    }

    /// Nothing here is a secret: a local dialer has no credential of its own, and the proxy's is the
    /// proxy's.
    fn has_credentials(&self) -> bool {
        self.username.is_some()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl Protocol for Server {
    fn kind(&self) -> Kind {
        Kind::Socks
    }

    fn scheme(&self) -> &str {
        "socks"
    }

    fn has_credentials(&self) -> bool {
        !self.users.is_empty()
    }

    fn supports_inbound(&self) -> bool {
        true
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Socks;
    const SCHEME: &'static str = "socks5";

    fn from_query(_reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        // The version is a property of the scheme, which the dispatcher applies; what is in the
        // userinfo is `user:pass`, plain, exactly as the dialect writes it.
        let (username, password) = match userinfo.split_once(':') {
            Some((username, password)) => (username, Some(password)),
            None => (userinfo, None),
        };

        Ok(Self {
            version: Version::V5,
            username: (!username.is_empty()).then(|| Box::from(username)),
            password: password
                .filter(|password| !password.is_empty())
                .map(|password| Secret::new(Box::from(password))),
        })
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        // `user:pass` is two fields with a separator that is part of the grammar, not of either
        // value, so each half is encoded and the colon is written as itself.
        let mut userinfo = String::new();

        if let Some(username) = &self.username {
            crate::percent::encode_into(username, &mut userinfo);
        }
        if let Some(password) = &self.password {
            userinfo.push(':');
            crate::percent::encode_into(password.as_str(), &mut userinfo);
        }

        let mut first = true;
        link::begin_encoded(out, self.version.scheme(), &userinfo, &node.endpoint);
        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());

        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(self.version.as_str());
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
        out.text(self.version.as_str());
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
            endpoint: crate::addr::Endpoint::parse("127.0.0.1:1080").unwrap(),
            listen: (),
            transport: crate::transport::Transport::Tcp,
            tls: None,
            protocol: Outbound::Socks(Client::default()),
            extra: crate::params::RawParams::new(),
        }
    }

    #[test]
    fn it_is_a_dialer_a_provider_never_sells() {
        let node = dialer();

        assert_eq!(node.protocol.kind(), Kind::Socks);
        assert_eq!(node.protocol.scheme(), "socks");
        assert!(node.protocol.supports_inbound());
    }

    #[test]
    fn a_link_round_trips_with_its_credentials() -> Result<()> {
        let node = parse_link("socks5://doge:letmein@127.0.0.1:1080#Local")?;

        assert_eq!(node.protocol.kind(), Kind::Socks);
        assert_eq!(
            write_link(&node)?,
            "socks5://doge:letmein@127.0.0.1:1080#Local"
        );
        assert_eq!(parse_link(&write_link(&node)?)?.protocol, node.protocol);

        Ok(())
    }

    #[test]
    fn a_version_is_the_schemes() -> Result<()> {
        let v4 = parse_link("socks4://127.0.0.1:1080#Local")?;
        assert!(
            matches!(v4.protocol, Outbound::Socks(ref client) if client.version == Version::V4)
        );

        // `socks5h` is SOCKS5 with remote resolution: the same wire protocol, so it reads as V5.
        let v5h = parse_link("socks5h://127.0.0.1:1080#Local")?;
        assert!(
            matches!(v5h.protocol, Outbound::Socks(ref client) if client.version == Version::V5)
        );

        Ok(())
    }

    #[test]
    fn an_unauthenticated_link_round_trips() -> Result<()> {
        let node = parse_link("socks5://127.0.0.1:1080#Local")?;

        assert!(matches!(node.protocol, Outbound::Socks(ref client) if client.username.is_none()));
        assert_eq!(write_link(&node)?, "socks5://127.0.0.1:1080#Local");

        Ok(())
    }

    #[test]
    fn credentials_are_shaped_like_the_wire_uses_them() -> Result<()> {
        let client = Client {
            version: Version::V5,
            username: Some(Box::from("doge")),
            password: Some(Secret::new(Box::from("letmein"))),
        };

        assert!(client.has_credentials());
        assert!(!format!("{client:?}").contains("letmein"));

        Ok(())
    }
}
