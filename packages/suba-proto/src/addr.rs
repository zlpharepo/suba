//! Hosts, ports and endpoints.
//!
//! An IP literal is kept as an IP, not as the string it arrived in. That is what makes the
//! bracketed-IPv6 handling a parse-time concern instead of a bug that reappears in every renderer,
//! and it is why a domain is lowercased once, here.

use core::{
    fmt::{self, Write as _},
    net::IpAddr,
    num::NonZeroU16,
    str::FromStr,
};

use crate::error::{Error, ErrorKind, Result};
use crate::prelude::*;

/// A host: either a name or an IP literal.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Host {
    /// A host name, lowercased, without a trailing dot.
    Domain(Box<str>),
    /// An IP literal, already parsed.
    Ip(IpAddr),
}

impl Host {
    /// Parse a host, accepting a bracketed IPv6 literal.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(input);

        // Every trailing dot goes, and it goes *before* the IP literal is recognised. A trailing dot is
        // the root label, so `example.com.` and `example.com` are one host — but stripping only one
        // means a value that ends in two dots loses one per parse, and `192.0.2.1.`, stripped after the
        // IP parse had already failed, became a *domain* that says `192.0.2.1` — which the next read
        // takes as an IP literal. A node whose host changes every time it is written out and read back
        // has no identity. (The fuzzer found both shapes: one on a gRPC `authority`, one on an `ss://`
        // line.)
        let input = input.trim_end_matches('.');

        if input.is_empty() {
            return Err(Error::new(ErrorKind::InvalidAddress, "the host is empty"));
        }

        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }

        if input.len() > 253 {
            return Err(Error::new(
                ErrorKind::InvalidAddress,
                "the host name is longer than 253 bytes",
            ));
        }

        if input
            .bytes()
            .any(|byte| matches!(byte, b' ' | b'/' | b':' | b'@' | b'#' | b'?' | b'[' | b']'))
        {
            return Err(Error::owned(
                ErrorKind::InvalidAddress,
                format!("'{input}' is neither a host name nor an IP literal"),
            ));
        }

        Ok(Self::Domain(input.to_ascii_lowercase().into_boxed_str()))
    }

    /// Append the host to `out`, without allocating. IPv6 is bracketed, so that `host:port`
    /// always parses back.
    pub fn write_to(&self, out: &mut String) {
        let _ = write!(out, "{self}");
    }

    /// Whether this is an IP literal.
    pub const fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    /// The IP literal, when there is one.
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Domain(_) => None,
        }
    }

    /// The host name, when there is one.
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::Domain(name) => Some(name),
            Self::Ip(_) => None,
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(name) => f.write_str(name),
            Self::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
            Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
        }
    }
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

/// A port that exists.
///
/// `NonZeroU16` rather than `u16`: a port of zero is never valid on the wire, so the type says so,
/// and `Option<Port>` is two bytes instead of four.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct Port(NonZeroU16);

impl Port {
    /// A port, if the number is one.
    pub const fn new(port: u16) -> Option<Self> {
        match NonZeroU16::new(port) {
            Some(port) => Some(Self(port)),
            None => None,
        }
    }

    /// The number.
    pub const fn get(self) -> u16 {
        self.0.get()
    }

    /// Parse a decimal port.
    pub fn parse(input: &str) -> Result<Self> {
        let port: u16 = input.parse().map_err(|_| {
            Error::owned(ErrorKind::InvalidPort, format!("'{input}' is not a port"))
        })?;

        Self::new(port).ok_or_else(|| Error::new(ErrorKind::InvalidPort, "port 0 is not usable"))
    }
}

impl TryFrom<u16> for Port {
    type Error = Error;

    fn try_from(port: u16) -> Result<Self> {
        Self::new(port).ok_or_else(|| Error::new(ErrorKind::InvalidPort, "port 0 is not usable"))
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        port.get()
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

impl fmt::Debug for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Where a node is, or where it listens.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// The host.
    pub host: Host,
    /// The port.
    pub port: Port,
}

impl Endpoint {
    /// Build an endpoint.
    pub const fn new(host: Host, port: Port) -> Self {
        Self { host, port }
    }

    /// Parse `host:port`, accepting `[v6]:port`.
    ///
    /// An IPv6 literal without brackets is refused rather than guessed at: `::1:443` could be
    /// either side of the split, and a proxy that dials the wrong address fails in a way nobody can
    /// diagnose from a log line.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();

        let mut bracketed = false;

        let (host, port) = match input.strip_prefix('[') {
            Some(rest) => {
                bracketed = true;

                let (inside, after) = rest.split_once(']').ok_or_else(|| {
                    Error::new(ErrorKind::MalformedLink, "the IPv6 literal is not closed")
                })?;

                let port = after.strip_prefix(':').ok_or_else(|| {
                    Error::new(ErrorKind::MissingField, "the endpoint has no port")
                })?;

                (inside, port)
            }
            None => input
                .rsplit_once(':')
                .ok_or_else(|| Error::new(ErrorKind::MissingField, "the endpoint has no port"))?,
        };

        if !bracketed && host.contains(':') {
            return Err(Error::new(
                ErrorKind::InvalidAddress,
                "an IPv6 literal needs brackets: [::1]:443",
            ));
        }

        Ok(Self {
            host: Host::parse(host)?,
            port: Port::parse(port)?,
        })
    }

    /// Append `host:port` to `out`, without allocating.
    pub fn write_to(&self, out: &mut String) {
        let _ = write!(out, "{self}");
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Endpoint {
    type Err = Error;

    fn from_str(input: &str) -> Result<Self> {
        Self::parse(input)
    }
}

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(Host);

#[cfg(feature = "serde")]
crate::serde_str::serde_string!(Endpoint);

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_domain_is_lowercased_and_stripped_of_its_dot() {
        assert_eq!(
            Host::parse("Example.COM.").unwrap().domain(),
            Some("example.com")
        );
    }

    #[test]
    fn an_ip_literal_stays_an_ip() {
        assert_eq!(
            Host::parse("1.2.3.4").unwrap().ip(),
            Some(Ipv4Addr::new(1, 2, 3, 4).into())
        );
        assert_eq!(
            Host::parse("[::1]").unwrap().ip(),
            Some(Ipv6Addr::LOCALHOST.into())
        );
    }

    #[test]
    fn a_bare_ipv6_is_refused_rather_than_guessed() {
        let error = Endpoint::parse("::1:443").unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidAddress);
    }

    #[test]
    fn endpoints_round_trip_through_their_spelling() {
        for text in [
            "example.com:443",
            "[2605:52c0:2:129::1]:8443",
            "1.2.3.4:1080",
        ] {
            let endpoint = Endpoint::parse(text).unwrap();

            assert_eq!(endpoint.to_string(), text);
            assert_eq!(Endpoint::parse(&endpoint.to_string()).unwrap(), endpoint);
        }
    }

    #[test]
    fn a_port_of_zero_is_not_a_port() {
        assert!(Port::new(0).is_none());
        assert_eq!(Port::parse("0").unwrap_err().kind(), ErrorKind::InvalidPort);
        assert_eq!(
            Port::parse("70000").unwrap_err().kind(),
            ErrorKind::InvalidPort
        );
    }

    #[test]
    fn options_of_small_types_are_free() {
        // A port cannot be zero, so `None` costs nothing beyond the port itself.
        assert_eq!(core::mem::size_of::<Port>(), 2);
        assert_eq!(core::mem::size_of::<Option<Port>>(), 2);

        // A domain is a box and an IP is a value, so the host is one word plus a tag.
        assert!(core::mem::size_of::<Host>() <= 32);
        assert!(core::mem::size_of::<Endpoint>() <= 40);
    }
}
