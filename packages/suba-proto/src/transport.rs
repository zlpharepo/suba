//! How a protocol is carried.
//!
//! These are the wire transports the share-link world settled on, named the way v2ray names them,
//! because that is the vocabulary a provider and a client both use. A transport the model does not
//! know is kept, with its parameters, in [`Transport::Other`]: the design rule is that nothing a
//! provider sends is silently dropped.

use core::fmt;

use crate::addr::Host;
use crate::params::RawParams;
use crate::prelude::*;
use crate::secret::Secret;

/// A carriage for a protocol's stream.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Transport {
    /// Plain TCP. The default when a link says nothing, and it is the same as saying `tcp`.
    #[default]
    Tcp,
    /// WebSocket.
    Ws(Ws),
    /// gRPC.
    Grpc(Grpc),
    /// HTTP/2.
    Http2(Http2),
    /// HTTP upgrade, which Xray writes as its own carriage.
    HttpUpgrade(HttpUpgrade),
    /// QUIC.
    Quic(Quic),
    /// A transport this build does not model, kept whole.
    #[cfg_attr(feature = "serde", serde(rename = "other"))]
    Other(Other),
}

impl Transport {
    /// The name a link uses for this transport.
    pub fn name(&self) -> &str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws(_) => "ws",
            Self::Grpc(_) => "grpc",
            Self::Http2(_) => "h2",
            Self::HttpUpgrade(_) => "httpupgrade",
            Self::Quic(_) => "quic",
            Self::Other(other) => &other.name,
        }
    }

    /// Whether this is plain TCP, which most consumers spell by saying nothing.
    pub const fn is_plain_tcp(&self) -> bool {
        matches!(self, Self::Tcp)
    }

    /// The parameters this transport does not model.
    pub fn extra(&self) -> &RawParams {
        match self {
            Self::Tcp => &EMPTY,
            Self::Ws(ws) => &ws.extra,
            Self::Grpc(grpc) => &grpc.extra,
            Self::Http2(http) => &http.extra,
            Self::HttpUpgrade(upgrade) => &upgrade.extra,
            Self::Quic(quic) => &quic.extra,
            Self::Other(other) => &other.extra,
        }
    }
}

/// Parameters for the transport-free case.
static EMPTY: RawParams = RawParams::new();

/// WebSocket.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ws {
    /// The request path.
    pub path: Box<str>,
    /// The `Host` header, when the link sets one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub host: Option<Host>,
    /// Early data length, in bytes, when the link asks for it.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub early_data: Option<u32>,
    /// The header early data travels in, when the link names one (`eh`).
    ///
    /// Modelled because the two ends have to agree on it, which makes it part of what the node is:
    /// Xray sends early data in a header, sing-box sends it in the path unless it is told the name.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub header_name: Option<Box<str>>,
    /// Anything the link carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

/// gRPC.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Grpc {
    /// The service name.
    pub service_name: Box<str>,
    /// The authority, when the link sets one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub authority: Option<Host>,
    /// Whether the client should use gRPC's multi-connection mode.
    pub multi_mode: bool,
    /// Anything the link carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

/// HTTP/2.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Http2 {
    /// The `Host` header.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub host: Option<Host>,
    /// The request path.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub path: Option<Box<str>>,
    /// Anything the link carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

/// HTTP upgrade: a carriage Xray spells `httpupgrade`, where the request is upgraded in place.
///
/// Modelled rather than kept whole as [`Other`]: its host and path decide what the node dials, so they
/// belong in the model and in the identity.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpUpgrade {
    /// The `Host` header, when the link sets one.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub host: Option<Host>,
    /// The request path. Xray writes `/` when a link says nothing.
    pub path: Box<str>,
    /// Anything the link carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

/// QUIC.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Quic {
    /// The header protection.
    pub security: QuicSecurity,
    /// The key. A credential, so it is a [`Secret`].
    pub key: Secret<Box<str>>,
    /// The header type.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub header: Option<Box<str>>,
    /// Anything the link carried that is not named above.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

impl Default for Quic {
    fn default() -> Self {
        Self {
            security: QuicSecurity::None,
            key: Secret::new(Box::from("")),
            header: None,
            extra: RawParams::new(),
        }
    }
}

/// QUIC's header protection, spelled the way Xray spells it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum QuicSecurity {
    /// No header protection.
    #[default]
    None,
    /// AES-128-GCM.
    #[cfg_attr(feature = "serde", serde(rename = "aes-128-gcm"))]
    Aes128Gcm,
    /// ChaCha20-Poly1305.
    #[cfg_attr(feature = "serde", serde(rename = "chacha20-poly1305"))]
    Chacha20Poly1305,
}

impl QuicSecurity {
    /// The name Xray uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Parse Xray's name.
    pub fn parse(input: &str) -> Option<Self> {
        match input {
            "none" => Some(Self::None),
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
}

/// A transport this build does not model.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Other {
    /// The name from the link.
    pub name: Box<str>,
    /// Everything else the link said.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "RawParams::is_empty")
    )]
    pub extra: RawParams,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Transport::{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_tcp_is_the_default_and_says_nothing() {
        assert_eq!(Transport::default(), Transport::Tcp);
        assert!(Transport::default().is_plain_tcp());
        assert_eq!(Transport::default().name(), "tcp");
    }

    #[test]
    fn an_unknown_transport_keeps_its_parameters() {
        let transport = Transport::Other(Other {
            name: "splithttp".into(),
            extra: RawParams::new(),
        });

        assert_eq!(transport.name(), "splithttp");
        assert!(!transport.is_plain_tcp());
    }
}
