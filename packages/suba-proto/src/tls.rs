//! TLS, in both directions.
//!
//! A client and a server do not describe TLS the same way — sing-box, Xray and every other
//! implementation agree on that much — so the model does not pretend otherwise. A client knows a
//! name to verify, a fingerprint to imitate, and a Reality public key; a server knows the
//! certificate it presents and the Reality private key it authenticates with. Inbound and outbound
//! are peers here, which is what lets the same crate model a subscription and a listener.

use core::fmt;

use crate::addr::{Endpoint, Host};
use crate::error::{Error, ErrorKind, Result};
use crate::params::RawParams;
use crate::prelude::*;
use crate::secret::Secret;

/// An ALPN protocol identifier.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Alpn(Box<str>);

impl Alpn {
    /// `h2`.
    pub fn h2() -> Self {
        Self(Box::from("h2"))
    }

    /// `http/1.1`.
    pub fn http_11() -> Self {
        Self(Box::from("http/1.1"))
    }

    /// Parse an identifier.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "an ALPN identifier is empty",
            ));
        }

        Ok(Self(input.into()))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Alpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Alpn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(Alpn);

/// A TLS fingerprint to imitate, as uTLS names the profiles.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint(Box<str>);

impl Fingerprint {
    /// Parse a profile name: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `random`,
    /// `randomized`, or a versioned spelling such as `chrome_120`.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidValue,
                "the fingerprint is empty",
            ));
        }

        Ok(Self(input.to_ascii_lowercase().into_boxed_str()))
    }

    /// The profile name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(Fingerprint);

/// A Reality short id: up to eight bytes, written as hexadecimal.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShortId(Box<str>);

impl ShortId {
    /// Parse a short id. An empty string is not one: a link that sets no short id leaves the field
    /// as `None`, which is a different statement from setting it to nothing.
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty()
            || input.len() > 16
            || !input.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::owned(
                ErrorKind::InvalidValue,
                format!("'{input}' is not a Reality short id"),
            ));
        }

        Ok(Self(input.to_ascii_lowercase().into_boxed_str()))
    }

    /// The hexadecimal spelling.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(ShortId);

/// A certificate a listener presents.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Certificate {
    /// Path to the certificate chain.
    pub certificate_path: Box<str>,
    /// Path to the private key.
    pub key_path: Box<str>,
}

impl Certificate {
    /// Build one.
    pub fn new(certificate_path: impl Into<Box<str>>, key_path: impl Into<Box<str>>) -> Self {
        Self {
            certificate_path: certificate_path.into(),
            key_path: key_path.into(),
        }
    }

    /// Whether both paths are set, which is what a listener needs to work at all.
    pub fn is_complete(&self) -> bool {
        !self.certificate_path.is_empty() && !self.key_path.is_empty()
    }
}

impl fmt::Debug for Certificate {
    /// Paths only. The key path is a location, not a key, so it is safe to print; the key itself is
    /// never in this struct.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certificate")
            .field("certificate_path", &self.certificate_path)
            .field("key_path", &self.key_path)
            .finish()
    }
}

/// The client half of TLS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsClient {
    /// The name to verify against. `None` means "use the endpoint's host".
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub server_name: Option<Host>,
    /// ALPN identifiers to offer.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub alpn: Vec<Alpn>,
    /// Whether to skip verification. Honest about what it is: the setting every provider tells you
    /// to enable.
    pub insecure: bool,
    /// A TLS fingerprint to imitate.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub fingerprint: Option<Fingerprint>,
    /// Reality, when the client authenticates that way.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub reality: Option<RealityClient>,
    /// Anything the link carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

/// The server half of TLS.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsServer {
    /// The certificates to present.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub certificates: Vec<Certificate>,
    /// ALPN identifiers to accept.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub alpn: Vec<Alpn>,
    /// How client certificates are treated.
    pub client_auth: ClientAuth,
    /// Reality, when the listener hides behind another site.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub reality: Option<RealityServer>,
    /// Anything the configuration carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

/// What a client needs to speak Reality.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RealityClient {
    /// The server's public key. A credential: it is what proves the client is allowed in.
    pub public_key: Secret<Box<str>>,
    /// The short id, when the link sets one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub short_id: Option<ShortId>,
    /// The site to fetch when a probe arrives, when the link sets one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub spider_x: Option<Box<str>>,
}

impl RealityClient {
    /// Build one from the public key.
    pub fn new(public_key: impl Into<Box<str>>) -> Self {
        Self {
            public_key: Secret::new(public_key.into()),
            short_id: None,
            spider_x: None,
        }
    }

    /// Whether the key is there. A node that says `security=reality` and carries no key is
    /// malformed, and a renderer must say so rather than dial plain TLS.
    pub fn is_complete(&self) -> bool {
        !self.public_key.is_empty()
    }
}

impl fmt::Debug for RealityClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityClient")
            .field("public_key", &"<redacted>")
            .field("short_id", &self.short_id)
            .field("spider_x", &self.spider_x)
            .finish()
    }
}

/// What a listener needs to speak Reality.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RealityServer {
    /// The private key. A credential, and the one thing that must never leave the listener.
    pub private_key: Secret<Box<str>>,
    /// The short ids to accept. Empty means the server accepts any short id, including none.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub short_ids: Vec<ShortId>,
    /// The site to hand a probe to.
    pub handshake: Endpoint,
    /// How far the client's clock may be off, in milliseconds.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub max_time_diff_ms: Option<u64>,
}

impl RealityServer {
    /// Build one.
    pub fn new(private_key: impl Into<Box<str>>, handshake: Endpoint) -> Self {
        Self {
            private_key: Secret::new(private_key.into()),
            short_ids: Vec::new(),
            handshake,
            max_time_diff_ms: None,
        }
    }

    /// Whether the listener can actually start.
    pub fn is_complete(&self) -> bool {
        !self.private_key.is_empty() && self.handshake.port.get() != 0
    }
}

impl fmt::Debug for RealityServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityServer")
            .field("private_key", &"<redacted>")
            .field("short_ids", &self.short_ids)
            .field("handshake", &self.handshake)
            .field("max_time_diff_ms", &self.max_time_diff_ms)
            .finish()
    }
}

/// How a listener treats client certificates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum ClientAuth {
    /// Do not ask.
    #[default]
    NoClientCert,
    /// Ask, but do not insist.
    RequestClientCert,
    /// Insist on a certificate, without verifying it.
    RequireAnyClientCert,
    /// Verify one when it is offered.
    VerifyClientCertIfGiven,
    /// Insist on a certificate that verifies.
    RequireAndVerifyClientCert,
}

/// What both halves of TLS have in common.
pub trait TlsOptions {
    /// The ALPN identifiers.
    fn alpn(&self) -> &[Alpn];

    /// Whether Reality is configured, in either direction.
    fn uses_reality(&self) -> bool;

    /// The parameters the model did not name.
    fn extra(&self) -> &RawParams;
}

impl TlsOptions for TlsClient {
    fn alpn(&self) -> &[Alpn] {
        &self.alpn
    }

    fn uses_reality(&self) -> bool {
        self.reality.is_some()
    }

    fn extra(&self) -> &RawParams {
        &self.extra
    }
}

impl TlsOptions for TlsServer {
    fn alpn(&self) -> &[Alpn] {
        &self.alpn
    }

    fn uses_reality(&self) -> bool {
        self.reality.is_some()
    }

    fn extra(&self) -> &RawParams {
        &self.extra
    }
}

/// Append a comma separated ALPN list, as a link spells it.
pub(crate) fn write_alpn(alpn: &[Alpn], out: &mut impl fmt::Write) -> fmt::Result {
    for (index, identifier) in alpn.iter().enumerate() {
        if index > 0 {
            out.write_char(',')?;
        }

        out.write_str(identifier.as_str())?;
    }

    Ok(())
}

/// Parse a comma separated ALPN list, ignoring empty entries.
pub(crate) fn parse_alpn(input: &str) -> Result<Vec<Alpn>> {
    input
        .split(',')
        .filter(|item| !item.is_empty())
        .map(Alpn::parse)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_id_is_bounded_hexadecimal() {
        assert_eq!(ShortId::parse("ab12").unwrap().as_str(), "ab12");
        assert_eq!(ShortId::parse("AB12").unwrap().as_str(), "ab12");
        assert!(ShortId::parse("").is_err());
        assert!(ShortId::parse("not-hex").is_err());
        assert!(
            ShortId::parse("0123456789abcdef012").is_err(),
            "longer than eight bytes"
        );
    }

    #[test]
    fn a_reality_client_without_a_key_says_so() {
        assert!(RealityClient::new("PUBKEY").is_complete());
        assert!(!RealityClient::new("").is_complete());
    }

    #[test]
    fn a_reality_key_is_never_printed() {
        let client = RealityClient::new("PUBKEY-hunter2");

        let rendered = format!("{client:?}");

        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(client.public_key.expose().as_ref(), "PUBKEY-hunter2");
    }

    #[test]
    fn both_halves_answer_the_shared_questions() {
        let client = TlsClient {
            alpn: vec![Alpn::h2()],
            reality: Some(RealityClient::new("PUBKEY")),
            ..TlsClient::default()
        };
        let server = TlsServer {
            alpn: vec![Alpn::http_11()],
            ..TlsServer::default()
        };

        assert_eq!(client.alpn()[0].as_str(), "h2");
        assert!(client.uses_reality());
        assert_eq!(server.alpn()[0].as_str(), "http/1.1");
        assert!(!server.uses_reality());
    }

    #[test]
    fn alpn_lists_round_trip() {
        let parsed = parse_alpn("h2,http/1.1,").unwrap();

        assert_eq!(parsed.len(), 2);

        let mut out = String::new();
        write_alpn(&parsed, &mut out).unwrap();

        assert_eq!(out, "h2,http/1.1");
    }
}
