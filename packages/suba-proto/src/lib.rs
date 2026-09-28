//! The protocol core of SubA, on its own.
//!
//! This crate is a proxy protocol library before it is part of anything: it models what a proxy node
//! *is*, in both directions, and it reads and writes the share links that carry one. It has no
//! opinion about subscriptions, storage, HTTP or sing-box.
//!
//! # The scope, drawn once
//!
//! A **peer**, and the dialects that describe one. The crate models what a proxy endpoint is and how it
//! is spelled; it never models how traffic flows. A client owns listeners, routing, DNS, sniffing and
//! time, and "the same shape as a node" is not a reason for one of those to become a node here:
//!
//! * A **local-only listener** with no upstream — a `mixed` inbound, a `tun` — is a client feature. A
//!   `socks5://` or `http://` link is in the corpus as the peer it is, not as a listener.
//! * **Composition** — WireGuard, ShadowTLS — has no share-link dialect, and arrives as
//!   [`protocol::Opaque`]: kept whole and carried through, which is the honest answer. A model that
//!   expressed "a node that is two nodes" would be the universal client IR this boundary rejects.
//! * **Opaque input** is a payload, not an error: an unknown scheme parses, its link is preserved, and
//!   an [`Outbound`](protocol::Outbound) can write it back.
//!
//! # What is here
//!
//! * [`protocol`] — one struct per protocol, one enum to hold them, and the share-link codec.
//! * [`node`] — [`Node`] parameterised over its direction: [`Client`] dials, [`Server`] listens.
//! * [`addr`], [`tls`], [`transport`] — address, TLS and carriage, modelled once.
//! * [`convert`] — the same node in the other direction, for a listener or a client.
//! * [`secret`] — credentials that cannot be printed.
//!
//! # Properties the crate holds itself to
//!
//! * **No `unsafe`.** `#![forbid(unsafe_code)]` covers everything but `sha2`'s own internals.
//! * **`no_std` when asked.** `--no-default-features` leaves the standard library out entirely; the
//!   model is `alloc`-only, which is what a client on a router or an embedded box wants.
//! * **Parsing allocates once per stored field, and nothing for a failure.** [`percent::decode`]
//!   borrows when there is nothing to unescape; an [`Error`] carries a static reason unless it has
//!   to quote a provider. `tests/allocations.rs` counts the allocations of every parse path and
//!   fails if one grows.
//! * **Nothing a provider sends is dropped.** A parameter the model does not name ends up in
//!   [`RawParams`] and is written back in the shape it arrived in; so does one the model does name and
//!   cannot interpret. Two cases sit outside that promise and say so: a dialect whose link is a whole
//!   object rather than a parameter list ([`protocol::vmess`]) holds its unmodelled keys in the raw
//!   link the record keeps, and a link with no address for the node — no port — is refused by name
//!   rather than half-read, even for a scheme this build does not model ([`protocol::Opaque`]).
//! * **Credentials are [`Secret`].** A whole node tree can be logged; the passwords and keys print
//!   as placeholders.
//!
//! # Layout
//!
//! ```text
//! addr.rs       Host, Port, Endpoint
//! uuid.rs       a UUID in sixteen bytes
//! secret.rs     credentials that print as placeholders
//! params.rs     parameters the model does not name
//! percent.rs    percent decoding that borrows
//! tls.rs        TlsClient / TlsServer and Reality, in both directions
//! transport.rs  Tcp, Ws, Grpc, Http2, HttpUpgrade, Quic, Other
//! node.rs       Direction, Node<D>, identity
//! link.rs       the share-link grammar, borrowed
//! protocol/     one module per protocol
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

/// The README is compiled as documentation, so its examples cannot rot.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;

mod prelude;

#[cfg(feature = "serde")]
mod serde_str;

pub mod addr;
pub mod convert;
pub mod error;
pub mod identity;
pub mod link;
pub mod node;
pub mod params;
pub mod percent;
pub mod protocol;
pub mod secret;
pub mod tls;
pub mod transport;
pub mod uuid;

pub use addr::{Endpoint, Host, Port};
pub use convert::ListenerMaterial;
pub use error::{Error, ErrorKind, Result};
pub use identity::NodeFingerprint;
pub use link::{Link, Reader};
pub use node::{Client, Direction, Name, Node, Role, Server};
pub use params::RawParams;
pub use protocol::{parse_link, write_link, write_link_into, Inbound, Kind, Outbound, Protocol};
pub use secret::Secret;
pub use tls::{TlsClient, TlsOptions, TlsServer};
pub use transport::Transport;
pub use uuid::Uuid;
