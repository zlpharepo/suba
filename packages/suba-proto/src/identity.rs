//! Node identity.
//!
//! Two subscriptions offering the same endpoint are one node, and the way to know that is to hash
//! what the node *is* — protocol, credentials, address, transport, TLS — and not how it is spelled.
//! The name, the provider it came from and the parameters nobody models are deliberately outside the
//! hash: a rename is not a new node, and a subscribe link gaining a comment is not either.
//!
//! The hash is SHA-256 over a canonical encoding, truncated to 128 bits. Canonical means every field
//! is length-prefixed before it is written, so that `("ab", "c")` and `("a", "bc")` cannot collide.
//!
//! The encoding carries a version, written before anything else. An identity is a contract — a stored
//! node keeps its identity across releases, and a build that hashed the same node differently would
//! silently duplicate every node in a subscription — so a change to what goes into the hash is a
//! change to the version, taken deliberately rather than discovered later.

use core::fmt::{self, Write as _};

use sha2::{Digest, Sha256};

use crate::error::Result;

/// What the canonical encoding is, before anything is written into it.
///
/// Bump this when a field is added to, removed from, or reordered in any [`Encode`] implementation.
/// Identities from before a bump do not match identities from after it, which is the point: it is a
/// deliberate break, and the alternative is two different nodes that hash alike.
pub const ENCODING_VERSION: &str = "suba.node.v2";

/// Sealing for [`Encode`].
///
/// A private module means the trait inside it cannot be named outside this crate, so `Encode` cannot
/// be implemented outside it either. That is deliberate: the hash is a contract — the same node has
/// to hash the same way in every build and every release — and an outside implementation could
/// change what "the same node" means without anything in here noticing. A consumer that needs its
/// own identity can hash this one alongside its own state; it does not get to redefine this one.
pub(crate) mod private {
    /// Implemented inside this crate, and nowhere else.
    pub trait Sealed {}
}

/// Something that can be written into an identity hash.
///
/// Public as a bound — [`Node::id`](crate::Node::id) needs it — and sealed so that the encoding stays
/// the crate's own.
#[allow(private_bounds)]
pub trait Encode: private::Sealed {
    /// Write the fields that make up this value's identity.
    fn encode(&self, out: &mut Hasher);
}

/// The identity hash of a node: a stable, content-derived name for it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct NodeFingerprint([u8; 16]);

impl NodeFingerprint {
    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Whether this is the empty identity, which no real node has.
    pub fn is_empty(&self) -> bool {
        self.0 == [0; 16]
    }
}

impl NodeFingerprint {
    /// Parse the hexadecimal spelling.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() != 32 {
            return Err(crate::error::Error::new(
                crate::error::ErrorKind::InvalidValue,
                "an identity is thirty-two hexadecimal characters",
            ));
        }

        let mut bytes = [0u8; 16];

        for (index, slot) in bytes.iter_mut().enumerate() {
            let pair = input.get(index * 2..index * 2 + 2).ok_or_else(|| {
                crate::error::Error::new(
                    crate::error::ErrorKind::InvalidValue,
                    "an identity is thirty-two hexadecimal characters",
                )
            })?;

            *slot = u8::from_str_radix(pair, 16).map_err(|_| {
                crate::error::Error::new(
                    crate::error::ErrorKind::InvalidValue,
                    "an identity is hexadecimal",
                )
            })?;
        }

        Ok(Self(bytes))
    }
}

impl fmt::Display for NodeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl fmt::Debug for NodeFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl core::str::FromStr for NodeFingerprint {
    type Err = ();

    fn from_str(input: &str) -> core::result::Result<Self, ()> {
        Self::parse(input).map_err(|_| ())
    }
}

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(NodeFingerprint);

/// The canonical encoding a [`NodeFingerprint`] is made of.
///
/// Every method writes an unambiguous tag, so that the encoding never depends on the order in which
/// unrelated fields happen to be written.
#[derive(Default)]
pub struct Hasher(Sha256);

impl Hasher {
    /// A new encoder, stamped with the encoding version.
    pub fn new() -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.text(ENCODING_VERSION);

        hasher
    }

    /// Write a length-prefixed string.
    pub fn text(&mut self, value: &str) {
        self.number(value.len() as u64);
        self.0.update(value.as_bytes());
    }

    /// Write an optional string, distinctly from the empty string.
    pub fn optional(&mut self, value: Option<&str>) {
        match value {
            None => self.0.update([0u8]),
            Some(value) => {
                self.0.update([1u8]);
                self.text(value);
            }
        }
    }

    /// Write a value through its `Display`, with no intermediate string.
    ///
    /// A NUL terminator separates two display values as well as a length prefix would, and nothing
    /// in this model formats to a string containing NUL.
    pub fn display(&mut self, value: &dyn fmt::Display) {
        self.0.update([2u8]);

        let mut writer = DigestWriter(&mut self.0);
        let _ = write!(writer, "{value}");

        self.0.update([0u8]);
    }

    /// Write an optional display value, distinctly from a missing one.
    pub fn optional_display(&mut self, value: Option<&dyn fmt::Display>) {
        match value {
            None => self.0.update([0u8]),
            Some(value) => self.display(value),
        }
    }

    /// Write a number.
    pub fn number(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    /// Write a byte.
    pub fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    /// Write a boolean.
    pub fn flag(&mut self, value: bool) {
        self.0.update([u8::from(value)]);
    }

    /// Write items through a closure, with their length.
    pub fn each<T>(&mut self, items: &[T], mut write: impl FnMut(&mut Hasher, &T)) {
        self.number(items.len() as u64);

        for item in items {
            write(self, item);
        }
    }

    /// The identity.
    pub fn finish(self) -> NodeFingerprint {
        let digest = self.0.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);

        NodeFingerprint(bytes)
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hasher(..)")
    }
}

/// A `fmt::Write` straight into the digest.
struct DigestWriter<'a>(&'a mut Sha256);

impl fmt::Write for DigestWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.update(text.as_bytes());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // The tests are built without `std` too when the feature is off, and then `to_string` comes from a
    // trait that has to be in scope.
    use alloc::string::ToString;

    #[test]
    fn the_encoding_is_unambiguous() {
        let mut a = Hasher::new();
        a.text("ab");
        a.text("c");

        let mut b = Hasher::new();
        b.text("a");
        b.text("bc");

        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn absent_and_empty_are_different() {
        let mut a = Hasher::new();
        a.optional(None);

        let mut b = Hasher::new();
        b.optional(Some(""));

        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn an_identity_prints_and_parses_back() {
        let mut hasher = Hasher::new();
        hasher.text("trojan");
        let id = hasher.finish();

        assert_eq!(id.to_string().parse::<NodeFingerprint>().unwrap(), id);
    }
}
