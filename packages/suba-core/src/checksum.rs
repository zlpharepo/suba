//! One definition of "the same bytes".
//!
//! Used to answer whether a provider is serving the payload it served last
//! time. One implementation, because two would eventually disagree.

use sha2::{Digest, Sha256};

/// The sha256 of `bytes`, lowercase hex, the way `sha256sum` prints it.
///
/// Printed rather than parsed: it goes into a file an operator may read.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The empty string's sha256 is the same everywhere, which is what makes
    /// this a checksum rather than an implementation detail.
    #[test]
    fn it_is_sha256_in_hex() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256_hex(b"a").len(), 64);
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }

    #[test]
    fn the_same_bytes_are_the_same_hash() {
        assert_eq!(sha256_hex(b"payload"), sha256_hex(b"payload"));
        assert_ne!(
            sha256_hex(b"payload"),
            sha256_hex(b"payload "),
            "a trailing space is a different payload"
        );
    }
}
