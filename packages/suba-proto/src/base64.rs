//! Base64, in the dialects share links and subscriptions actually use.
//!
//! The alphabets are not interchangeable, and a provider will use whichever it
//! likes: SIP002 asks for URL-safe without padding, a v2ray VMess payload is
//! standard, and a pasted subscription often carries whitespace along with it.
//! Decoding therefore tries every alphabet and tolerates whitespace rather than
//! rejecting a link over punctuation.

use alloc::string::String;
use alloc::vec::Vec;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

use crate::error::{Error, ErrorKind, Result};

/// Encode to URL-safe base64 without padding: what SIP002 asks for.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes.as_ref())
}

/// Encode to standard base64 with padding: what a subscription body is wrapped
/// in, because some clients decode that alphabet only.
pub fn encode_standard(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes.as_ref())
}

/// Decode base64 written in any of the four dialects, with or without padding.
///
/// Accepts padded and unpadded input in both alphabets, and ignores ASCII
/// whitespace: a payload pasted into a configuration file has line breaks and
/// spaces in it, and none of them are the provider's fault.
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    for engine in engines() {
        if let Ok(bytes) = engine.decode(input) {
            return Ok(bytes);
        }
    }

    // Whitespace creeps in when a payload is copied; strip it and try once more.
    let compact: Vec<u8> = input
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();

    if compact.len() != input.len() {
        for engine in engines() {
            if let Ok(bytes) = engine.decode(&compact) {
                return Ok(bytes);
            }
        }
    }

    Err(Error::new(
        ErrorKind::InvalidBase64,
        "the value is not base64",
    ))
}

/// Decode base64 into text.
///
/// The bytes are checked as UTF-8 rather than replaced: a payload that is not
/// text is not a subscription, and silently substituting characters would hand a
/// caller text the provider never sent.
pub fn decode_to_string(input: &[u8]) -> Result<String> {
    let bytes = decode(input)?;

    String::from_utf8(bytes).map_err(|_| {
        Error::new(
            ErrorKind::InvalidBase64,
            "the decoded value is not valid UTF-8",
        )
    })
}

/// Decode when `input` is base64, or `None` when it is plainly something else.
///
/// This is the test a subscription body needs: it may be base64-wrapped or a
/// list of links, and the only way to tell is to try. Unlike [`decode`], a
/// failure here is an answer rather than an error — most bodies are not base64.
///
/// A successful decode is only accepted when the bytes look like text, because
/// a body that happens to be valid base64 by accident should still be read as
/// the links it is.
pub fn decode_if_text(input: &[u8]) -> Option<String> {
    let bytes = decode(input).ok()?;
    let text = String::from_utf8(bytes).ok()?;

    // A decoded blob with control characters in it is binary that happened to
    // survive the alphabet, not a decoded subscription.
    let text_like = text.chars().all(|character| {
        !character.is_control() || character == '\n' || character == '\r' || character == '\t'
    });

    text_like.then_some(text)
}

/// The alphabets to try, in the order a provider is most likely to have used.
fn engines() -> [&'static base64::engine::GeneralPurpose; 4] {
    [&STANDARD_NO_PAD, &STANDARD, &URL_SAFE_NO_PAD, &URL_SAFE]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_url_safe_without_padding() {
        assert_eq!(encode(b"hello"), "aGVsbG8");
        assert_eq!(decode(encode(b"hello").as_bytes()).unwrap(), b"hello");
    }

    #[test]
    fn a_subscription_body_is_standard_and_padded() {
        // `>>?` is where the two alphabets differ; one byte short of a block pads.
        assert_eq!(encode_standard(b">>?"), "Pj4/");
        assert_eq!(encode_standard(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn decodes_every_dialect() {
        let text = b"aes-256-gcm:secret";

        for encoded in [
            STANDARD.encode(text),
            STANDARD_NO_PAD.encode(text),
            URL_SAFE.encode(text),
            URL_SAFE_NO_PAD.encode(text),
        ] {
            assert_eq!(decode(encoded.as_bytes()).unwrap(), text, "{encoded}");
        }
    }

    #[test]
    fn tolerates_pasted_whitespace() {
        let text = "trojan://secret@example.com:443#Node";
        let encoded = STANDARD.encode(text);

        assert_eq!(decode(encoded.as_bytes()).unwrap(), text.as_bytes());
        assert_eq!(
            decode(format!("{encoded}\n").as_bytes()).unwrap(),
            text.as_bytes()
        );
        assert_eq!(
            decode(format!("  {encoded}\t").as_bytes()).unwrap(),
            text.as_bytes()
        );
    }

    #[test]
    fn refuses_nonsense() {
        let error = decode(b"not base64 at all !!!").expect_err("not base64");

        assert_eq!(error.kind(), ErrorKind::InvalidBase64);
    }

    #[test]
    fn a_decoded_value_must_be_text() {
        assert_eq!(
            decode_to_string(b"aGVsbG8=").unwrap(),
            "hello",
            "standard base64 decodes to text"
        );

        // Bytes that decode but are not UTF-8 are refused rather than replaced.
        assert!(decode_to_string(b"/w==").is_err());
    }

    #[test]
    fn the_if_text_form_answers_instead_of_failing() {
        // What a subscription body looks like when it is not base64-wrapped.
        assert_eq!(
            decode_if_text(b"trojan://secret@example.com:443#Node"),
            None,
            "a link list is not base64, and that is not an error"
        );

        assert_eq!(
            decode_if_text(b"dHJvamFuOi8vc2VjcmV0QGV4YW1wbGUuY29tOjQ0MyNOb2Rl"),
            Some("trojan://secret@example.com:443#Node".to_string())
        );
    }

    #[test]
    fn base64_that_decodes_to_binary_is_not_a_subscription() {
        // Valid base64, but the bytes are not text: a body like this is links
        // that happened to survive the alphabet, so it must not be decoded.
        assert_eq!(decode_if_text(b"AAECAwQ="), None);
    }
}
