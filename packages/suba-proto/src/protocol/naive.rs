//! Native NaiveProxy client credentials.
//!
//! NaiveProxy has no interoperable share-link dialect. A client can still be
//! rendered for a target with a native NaiveProxy outbound.

use core::fmt;

use crate::identity::{Encode, Hasher};
use crate::prelude::*;
use crate::protocol::{Kind, Protocol};
use crate::secret::Secret;

/// An HTTPS or HTTP/3 NaiveProxy client.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// HTTP authentication username.
    pub username: Box<str>,
    /// HTTP authentication password.
    pub password: Secret<Box<str>>,
    /// Use HTTP/3 over QUIC rather than HTTP/2 over TCP.
    pub quic: bool,
}

impl Client {
    /// A client with its authentication pair and transport choice.
    pub fn new(username: impl Into<Box<str>>, password: impl Into<Box<str>>, quic: bool) -> Self {
        Self {
            username: username.into(),
            password: Secret::new(password.into()),
            quic,
        }
    }
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::Naive
    }
    fn scheme(&self) -> &str {
        "naive"
    }
    fn has_credentials(&self) -> bool {
        !self.username.is_empty() && !self.password.is_empty()
    }
    fn supports_inbound(&self) -> bool {
        false
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.text(&self.username);
        out.text(self.password.as_str());
        out.flag(self.quic);
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("naive::Client")
            .field("username", &self.username)
            .field("password", &self.password)
            .field("quic", &self.quic)
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
