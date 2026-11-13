//! Snell client credentials, including the optional multi-user key.
//!
//! A v5 server speaks the v4 TCP wire protocol. The version is retained here
//! so a target that understands v5 can name it, while sing-box maps it to v4.

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::identity::{Encode, Hasher};
use crate::link::{self, Reader};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{write_extra, write_shared, ClientLink, Kind, Protocol};
use crate::secret::Secret;

/// A Snell proxy that a client can dial.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// The declared protocol version, from 1 through 6.
    pub version: u8,
    /// The inbound's pre-shared key.
    pub psk: Secret<Box<str>>,
    /// Present only when the server has native users.
    pub userkey: Option<Secret<Box<str>>>,
    /// Whether the client reuses connections.
    pub reuse: bool,
    /// HTTP obfuscation mode for versions 1 through 5.
    pub obfs_mode: Option<Box<str>>,
    /// HTTP obfuscation host for versions 1 through 5.
    pub obfs_host: Option<Box<str>>,
    /// Traffic shaping mode for version 6.
    pub mode: Option<Box<str>>,
}

impl Client {
    /// Build from an inbound's shared PSK or a managed user's user key.
    pub fn new(version: u8, psk: impl Into<Box<str>>) -> Self {
        Self {
            version,
            psk: Secret::new(psk.into()),
            userkey: None,
            reuse: false,
            obfs_mode: None,
            obfs_host: None,
            mode: None,
        }
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Snell
    }
    fn scheme(&self) -> &str {
        Self::SCHEME
    }
    fn has_credentials(&self) -> bool {
        !self.psk.is_empty()
    }
    fn supports_inbound(&self) -> bool {
        false
    }
}

impl ClientLink for Client {
    const KIND: Kind = Kind::Snell;
    const SCHEME: &'static str = "snell";

    fn from_query(reader: &mut Reader<'_>, userinfo: &str) -> Result<Self> {
        let psk = reader.owned("psk").unwrap_or_else(|| userinfo.into());
        if psk.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "psk"));
        }
        let version = match reader.owned("version") {
            Some(value) => value
                .parse::<u8>()
                .ok()
                .filter(|version| (1..=6).contains(version))
                .ok_or_else(|| Error::field(ErrorKind::InvalidValue, "version"))?,
            None => 1,
        };
        let userkey = reader.owned("userkey").map(Secret::new);
        let reuse = reader.flag(&["reuse"]);
        let obfs_mode = reader.owned("obfs_mode").or_else(|| reader.owned("obfs"));
        let obfs_host = reader
            .owned("obfs_host")
            .or_else(|| reader.owned("obfs-host"));
        let mode = reader.owned("mode");
        if version == 6 && (obfs_mode.is_some() || obfs_host.is_some()) {
            return Err(Error::field(ErrorKind::InvalidValue, "obfs_mode"));
        }
        if version != 6 && mode.is_some() {
            return Err(Error::field(ErrorKind::InvalidValue, "mode"));
        }
        Ok(Self {
            version,
            psk: Secret::new(psk),
            userkey,
            reuse,
            obfs_mode,
            obfs_host,
            mode,
        })
    }

    fn write_link(&self, node: &Node<node::Client>, out: &mut String) -> Result<()> {
        if self.psk.is_empty() {
            return Err(Error::field(ErrorKind::MissingField, "psk"));
        }
        out.push_str("snell://");
        node.endpoint.write_to(out);
        let mut first = true;
        link::param(out, &mut first, "psk", Some(self.psk.as_str()));
        link::number(out, &mut first, "version", Some(u64::from(self.version)));
        link::param(
            out,
            &mut first,
            "userkey",
            self.userkey.as_ref().map(Secret::as_str),
        );
        if self.reuse {
            link::param(out, &mut first, "reuse", Some("true"));
        }
        link::param(out, &mut first, "obfs_mode", self.obfs_mode.as_deref());
        link::param(out, &mut first, "obfs_host", self.obfs_host.as_deref());
        link::param(out, &mut first, "mode", self.mode.as_deref());
        write_shared(node, out, &mut first);
        write_extra(&node.extra, out, &mut first);
        link::finish(out, node.name.as_str());
        Ok(())
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.byte(self.version);
        out.text(self.psk.as_str());
        out.optional(self.userkey.as_ref().map(Secret::as_str));
        out.flag(self.reuse);
        out.optional(self.obfs_mode.as_deref());
        out.optional(self.obfs_host.as_deref());
        out.optional(self.mode.as_deref());
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("snell::Client")
            .field("version", &self.version)
            .field("psk", &self.psk)
            .field("userkey", &self.userkey)
            .field("reuse", &self.reuse)
            .field("obfs_mode", &self.obfs_mode)
            .field("obfs_host", &self.obfs_host)
            .field("mode", &self.mode)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
