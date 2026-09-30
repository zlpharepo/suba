//! Writing nodes as the documents sing-box reads, and installing the core that
//! runs them.
//!
//! Two things about sing-box are often mistaken for one, and they are two
//! features here for that reason:
//!
//! * **`render`** — writing nodes as the documents sing-box reads. A pure
//!   function of the nodes: no clock, no file, no socket, and **no installed
//!   core**. A build that can serve a sing-box subscription needs nothing else.
//! * **`core`** — knowing and installing the sing-box versions this machine
//!   can run. Network, files and processes, and none of it is needed to write a
//!   document.
//!
//! Neither implies the other: a host can hand out sing-box subscriptions
//! without ever installing a core, and a host can run a core with a
//! hand-written configuration without this build rendering anything. What needs
//! both is a core fed by a collection.

#[cfg(feature = "core")]
pub mod core;

#[cfg(feature = "render")]
mod render;

#[cfg(feature = "render")]
pub use render::{client_config, outbound, Reason, Refused, PROTOCOLS};
