//! Protocols this build does not model.
//!
//! A subscription is full of schemes a given build has never heard of, and a converter that drops
//! them loses the user's nodes. [`Opaque`] keeps the link exactly as it arrived and hands it back
//! unchanged, so an unmodelled node passes through a SubA subscription intact.
//!
//! # What an unmodelled link still has to be
//!
//! A link is kept once its address can be read, which means the authority grammar — `scheme://…@host`
//! followed by a port. A link that states no port is refused with a named field, so
//! `snell://example.com#Tokyo` is an error rather than a node whose port was invented. A [`Node`]
//! always has an endpoint, and a node whose address this build cannot read is not a node it can carry;
//! carrying one without an endpoint is a model change, and it belongs to the design gate rather than
//! to this module. Everything else about the link — parameters, payload, spelling — is untouched.

use core::fmt;

use crate::identity::{Encode, Hasher};
use crate::link::Link;
use crate::node::{self, Node};
use crate::prelude::*;
use crate::protocol::{Kind, Protocol};
use crate::secret::Secret;

/// A protocol this build does not model, kept whole.
///
/// The raw text is a credential-bearing string and is kept deliberately: it is the only way to give
/// a node back the way it came. `Debug` prints the scheme and nothing else.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Opaque {
    scheme: Box<str>,
    raw: Box<str>,
}

impl Opaque {
    /// An unmodelled protocol with no payload yet.
    pub fn new(scheme: impl Into<Box<str>>) -> Self {
        Self {
            scheme: scheme.into(),
            raw: Box::from(""),
        }
    }

    /// The payload as it arrived.
    pub fn with_raw(scheme: impl Into<Box<str>>, raw: impl Into<Box<str>>) -> Self {
        Self {
            scheme: scheme.into(),
            raw: raw.into(),
        }
    }

    /// Keep a link whole.
    pub(crate) fn from_link(link: &Link<'_>) -> Self {
        Self::with_raw(link.scheme().to_ascii_lowercase(), link.raw())
    }

    /// The scheme.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The link as it arrived.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Whether the payload is empty, which happens for a node built by hand rather than parsed.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Never: nothing is known about how to serve a protocol nobody has modelled.
    pub const fn supports_inbound(&self) -> bool {
        false
    }
}

impl Protocol for Opaque {
    fn kind(&self) -> Kind {
        Kind::Other
    }

    fn scheme(&self) -> &str {
        &self.scheme
    }

    /// Deliberately `false`: a build that does not know the protocol cannot know whether the link
    /// carries a credential, and claiming either way would be a guess.
    fn has_credentials(&self) -> bool {
        false
    }

    fn supports_inbound(&self) -> bool {
        false
    }
}

impl Opaque {
    /// Give the link back, byte for byte.
    pub(crate) fn write_link(
        &self,
        node: &Node<node::Client>,
        out: &mut String,
    ) -> crate::error::Result<()> {
        let _ = node;

        out.push_str(&self.raw);

        Ok(())
    }
}

impl Encode for Opaque {
    fn encode(&self, out: &mut Hasher) {
        out.text(&self.scheme);

        // An unmodelled node's identity falls back to the link as written: without knowing the
        // protocol, the query is the only place its credential can be, and two nodes that differ
        // only there must not collide.
        out.text(&self.raw);
    }
}

impl fmt::Debug for Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opaque")
            .field("scheme", &self.scheme)
            .field("raw", &Secret::new(""))
            .finish()
    }
}

impl crate::identity::private::Sealed for Opaque {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{parse_link, write_link, Kind};

    #[test]
    fn an_unmodelled_link_passes_through_untouched() {
        let text = "snell://1.2.3.4:443?psk=hunter2&version=4#Mystery";
        let node = parse_link(text).unwrap();

        assert_eq!(node.protocol.kind(), Kind::Other);
        assert_eq!(node.protocol.scheme(), "snell");
        assert_eq!(write_link(&node).unwrap(), text);
    }

    #[test]
    fn an_unmodelled_link_is_never_printed() {
        let node = parse_link("snell://1.2.3.4:443?psk=hunter2#Mystery").unwrap();
        let rendered = format!("{node:?}");

        // The parameter *names* are printed on purpose: seeing which unknowns a node carries is how
        // a modelling gap gets noticed. The values never are.
        assert!(rendered.contains("psk"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn two_unmodelled_nodes_that_differ_in_a_parameter_are_two_nodes() {
        let one = parse_link("snell://1.2.3.4:443?psk=a#M").unwrap();
        let two = parse_link("snell://1.2.3.4:443?psk=b#M").unwrap();

        assert_ne!(one.id(), two.id());
    }
}
