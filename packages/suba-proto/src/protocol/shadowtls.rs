//! A ShadowTLS outer connection composed with an explicitly selected inner proxy.
//!
//! ShadowTLS carries a TCP stream. Its outer credential does not replace the
//! inner proxy's authentication, so the inner client remains a complete node.

use core::fmt;

use crate::identity::{Encode, Hasher};
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{Kind, Protocol};
use crate::secret::Secret;

/// An outer ShadowTLS client and the proxy it carries.
#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Client {
    /// ShadowTLS protocol version, from 1 through 3.
    pub version: u8,
    /// The shared v2 password or the v3 user's password; absent for v1.
    pub password: Option<Secret<Box<str>>>,
    /// The inner proxy, authenticated independently from the outer layer.
    pub inner: Box<Node<node::Client>>,
}

impl Protocol for Client {
    fn kind(&self) -> Kind {
        Kind::ShadowTls
    }
    fn scheme(&self) -> &str {
        "shadowtls"
    }
    fn has_credentials(&self) -> bool {
        self.inner.protocol.has_credentials()
    }
    fn supports_inbound(&self) -> bool {
        false
    }
}

impl Encode for Client {
    fn encode(&self, out: &mut Hasher) {
        out.byte(self.version);
        out.optional(self.password.as_ref().map(Secret::as_str));
        out.display(&self.inner.id());
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("shadowtls::Client")
            .field("version", &self.version)
            .field("password", &self.password)
            .field("inner_protocol", &self.inner.protocol.kind())
            .finish()
    }
}

impl crate::identity::private::Sealed for Client {}
