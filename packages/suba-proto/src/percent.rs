//! Percent-encoding, borrowing whenever it can.
//!
//! A share link usually has nothing to escape, and [`decode`] hands the input back untouched in
//! that case: that is what keeps a parse from allocating for a name or a path.

use core::fmt;

use crate::prelude::*;

/// The characters a link writes unescaped: the URI unreserved set, and nothing else.
///
/// Deliberately strict. A password containing `@` or `/` has to be escaped, or
/// `trojan://p@ss/word@example.com:443` is two different links depending on who reads it; the same
/// goes for a name containing `#`. Being conservative costs a few bytes in a link nobody reads by
/// hand, and buys a link that means exactly one thing.
const UNRESERVED: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

/// Percent-encode everything written through it.
///
/// This is what lets a `Display` value — a host, an ALPN list, a number — be written into a query
/// without a temporary `String`: the formatter writes into this, and this escapes on the way past.
pub struct Encoder<'a> {
    out: &'a mut String,
}

impl<'a> Encoder<'a> {
    pub fn new(out: &'a mut String) -> Self {
        Self { out }
    }
}

impl fmt::Write for Encoder<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        encode_into(text, self.out);

        Ok(())
    }
}

/// Decode `%XY` escapes, borrowing the input when there are none.
pub fn decode(input: &str) -> Cow<'_, str> {
    match input.as_bytes().iter().position(|byte| *byte == b'%') {
        None => Cow::Borrowed(input),
        Some(_) => Cow::Owned(decode_to_string(input)),
    }
}

/// Take ownership of `input`, decoding only if there is something to decode.
///
/// One allocation either way, which is what makes it usable on the path where a value is being
/// stored: `decode(..).into_owned()` would allocate the borrowed case twice.
pub fn decode_owned(input: &str) -> String {
    match decode(input) {
        Cow::Borrowed(_) => input.to_string(),
        Cow::Owned(decoded) => decoded,
    }
}

/// Decode `%XY` escapes into a new string.
///
/// A lone `%` or a malformed escape is kept verbatim. A link is data from a provider, and refusing
/// the whole line over one bad escape throws away a node that would have worked.
pub fn decode_to_string(input: &str) -> String {
    let raw = input.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut index = 0;

    while index < raw.len() {
        let byte = raw[index];

        if byte == b'%' && index + 2 < raw.len() {
            if let (Some(high), Some(low)) = (hex_value(raw[index + 1]), hex_value(raw[index + 2]))
            {
                out.push((high << 4) | low);
                index += 3;
                continue;
            }
        }

        out.push(byte);
        index += 1;
    }

    // Escapes that do not form UTF-8 are not this crate's to replace: a value is handed back as it was
    // written rather than as the replacement character a lossy decode would invent.
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

/// Append a `Display` value, escaping what a URI cannot carry unescaped.
///
/// The counterpart of [`encode_into`] for values that are not `&str` yet — a UUID, a [`Secret`]'s
/// contents — and the reason none of them needs a temporary string on the way out.
///
/// [`Secret`]: crate::Secret
pub fn encode_display(value: &dyn fmt::Display, out: &mut String) {
    let mut encoder = Encoder::new(out);

    let _ = fmt::Write::write_fmt(&mut encoder, format_args!("{value}"));
}

/// Append `value` to `out`, escaping what a URI cannot carry unescaped.
pub fn encode_into(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    for byte in value.bytes() {
        if UNRESERVED.as_bytes().contains(&byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrowed_when_there_is_nothing_to_decode() {
        assert!(matches!(decode("Tokyo"), Cow::Borrowed("Tokyo")));
    }

    #[test]
    fn decodes_utf8_and_keeps_bad_escapes() {
        assert_eq!(decode("%E6%B5%8B%E8%AF%95").as_ref(), "测试");
        assert_eq!(decode("100%").as_ref(), "100%");
        assert_eq!(decode("%zz").as_ref(), "%zz");
    }

    #[test]
    fn round_trips_through_encode() {
        let mut out = String::new();
        encode_into("东京 / Tokyo", &mut out);

        assert_eq!(decode(&out).as_ref(), "东京 / Tokyo");
    }
}
