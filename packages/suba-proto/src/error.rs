//! The crate error type.
//!
//! An error is a kind plus a reason. Reasons are `Cow<'static, str>`: the ones the crate knows
//! itself are static strings, so the common failure paths do not allocate. Only a reason that
//! quotes provider-supplied text costs an allocation, and those constructors are `#[cold]`.

use core::fmt;

use crate::prelude::*;

/// What went wrong, for callers that branch on a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The text is not a share link at all.
    MalformedLink,
    /// The scheme is not one this build knows.
    UnknownScheme,
    /// The scheme is known, but the role cannot express it: a share link describes a client.
    UnsupportedRole,
    /// The payload has no share link, and never did. Reserved for the shapes that genuinely have no
    /// dialect — a `tun`/`mixed` listener, or a routing target such as `direct` — so that asking for a
    /// link is this error rather than a made-up string. Nothing in the model uses it yet: SOCKS and
    /// HTTP are names others do write (`socks5://`, `http://`), so they have a link form.
    NoLinkForm,
    /// The link is well formed but something required is missing.
    MissingField,
    /// A port was not a number in range.
    InvalidPort,
    /// An address was neither a host name nor an IP literal.
    InvalidAddress,
    /// A UUID was not a UUID.
    InvalidUuid,
    /// A base64 payload did not decode.
    InvalidBase64,
    /// A value was outside what the field allows.
    InvalidValue,
}

impl ErrorKind {
    /// A short, stable name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedLink => "malformed link",
            Self::UnknownScheme => "unknown scheme",
            Self::UnsupportedRole => "unsupported role",
            Self::MissingField => "missing field",
            Self::InvalidPort => "invalid port",
            Self::InvalidAddress => "invalid address",
            Self::InvalidUuid => "invalid uuid",
            Self::InvalidBase64 => "invalid base64",
            Self::NoLinkForm => "this payload has no share link",
            Self::InvalidValue => "invalid value",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parse or conversion failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    reason: Cow<'static, str>,
}

impl Error {
    /// The failure kind.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Why it failed, in the words a human needs.
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Build an error from a static reason: no allocation.
    #[cold]
    pub(crate) fn new(kind: ErrorKind, reason: &'static str) -> Self {
        Self {
            kind,
            reason: Cow::Borrowed(reason),
        }
    }

    /// Build an error that quotes something the provider sent.
    #[cold]
    pub(crate) fn owned(kind: ErrorKind, reason: String) -> Self {
        Self {
            kind,
            reason: Cow::Owned(reason),
        }
    }

    /// The constructor the protocol modules use most: a named field that was wrong or absent.
    ///
    /// The reason *is* the field name, so a caller can read the name on its own and put it in a
    /// sentence of its own ("… without certificate_path and key_path"); the kind says what was wrong
    /// with it. Displaying that as `missing field: certificate_path and key_path` is the whole
    /// message, and costs no allocation.
    #[cold]
    pub(crate) fn field(kind: ErrorKind, field: &'static str) -> Self {
        Self::new(kind, field)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.reason)
    }
}

impl core::error::Error for Error {}

/// The crate result alias.
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_static_reason_does_not_allocate() {
        let error = Error::new(ErrorKind::InvalidPort, "port out of range");

        assert!(matches!(error.reason, Cow::Borrowed(_)));
        assert_eq!(error.kind(), ErrorKind::InvalidPort);
        assert_eq!(error.to_string(), "invalid port: port out of range");
    }
}
