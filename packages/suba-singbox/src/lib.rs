//! Writing nodes as the documents sing-box reads.
//!
//! One of the two things sing-box means here, and the one that needs nothing
//! from the machine it runs on: the mapping is a pure function of the nodes, so
//! a build that serves a sing-box subscription needs no installed core, no
//! network and no process. Running a core — installing it, assembling for it,
//! starting it — is a separate matter and, when it lands, a separate feature.

#[cfg(feature = "render")]
mod render;

#[cfg(feature = "render")]
pub use render::{client_config, outbound, Reason, Refused, PROTOCOLS};
