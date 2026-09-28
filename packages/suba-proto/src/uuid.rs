//! UUIDs, in the sixteen bytes they are on the wire.

use core::fmt;

use crate::error::{Error, ErrorKind, Result};
use crate::prelude::*;

/// A UUID.
///
/// Stored as its sixteen bytes rather than as a string: a ten-thousand node working set holds ten
/// thousand of these, and `[u8; 16]` is `Copy`, ordered, hashable, and four times smaller than the
/// hyphenated form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Uuid([u8; 16]);

impl Uuid {
    /// The all-zero UUID.
    pub const NIL: Self = Self([0; 16]);

    /// From the sixteen wire bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The sixteen wire bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Whether this is [`Uuid::NIL`], which a provider that meant to fill it in did not.
    pub fn is_nil(&self) -> bool {
        self.0 == [0; 16]
    }

    /// Parse the hyphenated or plain hexadecimal form, case-insensitive.
    ///
    /// Hyphens are allowed anywhere and ignored, which also accepts the 8-4-4-4-12 spelling.
    pub fn parse(input: &str) -> Result<Self> {
        let mut bytes = [0u8; 16];
        let mut high: Option<u8> = None;
        let mut index = 0usize;

        for byte in input.bytes() {
            if byte == b'-' {
                continue;
            }

            let value = match hex_value(byte) {
                Some(value) => value,
                None => return Err(malformed(input)),
            };

            match high.take() {
                None => high = Some(value),
                Some(first) => {
                    if index == 16 {
                        return Err(malformed(input));
                    }

                    bytes[index] = (first << 4) | value;
                    index += 1;
                }
            }
        }

        if index != 16 || high.is_some() {
            return Err(malformed(input));
        }

        Ok(Self(bytes))
    }
}

#[cold]
fn malformed(input: &str) -> Error {
    Error::owned(ErrorKind::InvalidUuid, format!("'{input}' is not a uuid"))
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }

            let pair = [HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]];
            f.write_str(core::str::from_utf8(&pair).unwrap_or("??"))?;
        }

        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(Uuid);

#[cfg(test)]
mod tests {
    use super::*;

    const SPOKEN: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn parses_every_spelling_a_provider_uses() {
        let expected = Uuid::parse(SPOKEN).unwrap();

        assert_eq!(
            Uuid::parse("11111111222233334444555555555555").unwrap(),
            expected
        );
        assert_eq!(
            Uuid::parse("11111111-22223333-4444-555555555555").unwrap(),
            expected
        );
        assert_eq!(
            Uuid::parse(
                "11111111-2222-3333-4444-555555555555"
                    .to_uppercase()
                    .as_str()
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn an_invalid_uuid_names_itself() {
        let error = Uuid::parse("1111").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidUuid);
        assert_eq!(error.reason(), "'1111' is not a uuid");
    }

    #[test]
    fn prints_the_hyphenated_form() {
        assert_eq!(Uuid::parse(SPOKEN).unwrap().to_string(), SPOKEN);
    }

    #[test]
    fn nil_is_recognised() {
        assert!(Uuid::NIL.is_nil());
        assert!(!Uuid::parse(SPOKEN).unwrap().is_nil());
    }

    #[test]
    fn sixteen_bytes_and_not_a_pointer() {
        assert_eq!(core::mem::size_of::<Uuid>(), 16);
        assert_eq!(
            core::mem::size_of::<Option<Uuid>>(),
            17,
            "no niche, but still a value type"
        );
    }
}
