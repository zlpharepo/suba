//! Hysteria v1 client credentials and QUIC rate settings.

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;
use crate::transport::{Quic, Transport};

/// One Hysteria v1 client. The obfuscation password belongs to the listener.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The user's authentication password.
    pub auth: Secret<Box<str>>,
    /// The listener's shared obfuscation password.
    pub obfs: Option<Secret<Box<str>>>,
    /// Client uplink capacity in Mbps.
    pub up: Option<u64>,
    /// Client downlink capacity in Mbps.
    pub down: Option<u64>,
    /// Ports used for hopping.
    pub ports: Option<Box<str>>,
    /// Port hopping interval in seconds.
    pub hop_interval: Option<u64>,
}

impl Client {
    /// A client with its user authentication password.
    pub fn new(auth: impl Into<Box<str>>) -> Self {
        Self {
            auth: Secret::new(auth.into()),
            obfs: None,
            up: None,
            down: None,
            ports: None,
            hop_interval: None,
        }
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Hysteria
    }
    fn scheme(&self) -> &str {
        Self::SCHEME
    }
    fn has_credentials(&self) -> bool {
        !self.auth.is_empty()
    }
    fn supports_inbound(&self) -> bool {
        false
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Hysteria;
    const SCHEME: &'static str = "hysteria";
    const TLS_ONLY: bool = true;

    fn from_query(reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        let auth = reader
            .any_owned(&["auth", "auth_str"])
            .unwrap_or_else(|| userinfo.into());
        if auth.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "auth"));
        }
        if let Some(mode) = reader.owned("obfs") {
            if mode.as_ref() != "xplus" {
                reader.release("obfs");
            }
        }
        Ok(Self {
            auth: Secret::new(auth),
            obfs: reader
                .any_owned(&["obfsParam", "obfs-param"])
                .map(Secret::new),
            up: reader.number("upmbps").or_else(|| reader.number("up")),
            down: reader.number("downmbps").or_else(|| reader.number("down")),
            ports: reader.any_owned(&["mport", "ports"]),
            hop_interval: reader.number("hop-interval"),
        })
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        if self.auth.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "auth"));
        }
        out.push_str("hysteria://");
        node.endpoint.write_to(out);
        let mut first = true;
        link::param(out, &mut first, "auth", Some(self.auth.as_str()));
        if self.obfs.is_some() {
            link::param(out, &mut first, "obfs", Some("xplus"));
        }
        link::param(
            out,
            &mut first,
            "obfsParam",
            self.obfs.as_ref().map(Secret::as_str),
        );
        link::number(out, &mut first, "upmbps", self.up);
        link::number(out, &mut first, "downmbps", self.down);
        link::param(out, &mut first, "mport", self.ports.as_deref());
        link::number(out, &mut first, "hop-interval", self.hop_interval);
        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());
        Ok(())
    }

    fn default_transport() -> Transport {
        Transport::Quic(Quic::default())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(self.auth.as_str());
        out.optional(self.obfs.as_ref().map(Secret::as_str));
        out.flag(self.up.is_some());
        out.number(self.up.unwrap_or_default());
        out.flag(self.down.is_some());
        out.number(self.down.unwrap_or_default());
        out.optional(self.ports.as_deref());
        out.flag(self.hop_interval.is_some());
        out.number(self.hop_interval.unwrap_or_default());
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("hysteria::Client")
            .field("auth", &self.auth)
            .field("obfs", &self.obfs)
            .field("up", &self.up)
            .field("down", &self.down)
            .field("ports", &self.ports)
            .field("hop_interval", &self.hop_interval)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
