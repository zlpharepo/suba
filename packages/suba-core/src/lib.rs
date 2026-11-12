//! The core of SubA: the model and the computation over it.
//!
//! It is **pure computation**. Reading a subscription into nodes, deciding what
//! a fetch means, assembling current provider snapshots — none of it touches a filesystem,
//! a socket or a clock, and none of it reads the environment. Everything that
//! reaches outside belongs to `suba-server`, which owns those and hands the
//! result in.
//!
//! That boundary is what lets the whole of the interesting logic be tested
//! without a temp directory or a network, and it is why nothing here returns a
//! `std::io::Error`: there is no IO to fail.
//!
//! Layering, bottom up:
//!
//! * [`proto`] — the model itself: one struct per protocol, the share-link
//!   codecs, the node, the identity hash.
//! * [`node`] / [`observation`] — what a hub adds: provenance, and what was
//!   observed from a provider.
//! * [`subscription`] — the container formats a provider serves.
//! * [`index`] — every provider's nodes, merged into one view.
//! * [`collection`] — a subscription assembled out of providers.
//! * [`target`] — the documents a collection can be served as.
//! * [`provider`] — what a fetch means for what is kept.
//! * [`filter`] — which nodes survive.

pub mod checksum;
pub mod collection;
pub mod filter;
pub mod index;
pub mod node;
pub mod observation;
pub mod provider;
pub mod subscription;
pub mod target;

/// The protocol model, under the name this crate refers to it by.
pub use suba_proto as proto;

pub use collection::{Collection, Resolved};
pub use filter::{FilterError, NodeFilter, Pattern, PatternReason};
pub use index::{name_conflicts, IndexEntry, NodeIndex, Source};
pub use node::{NodeRecord, Provenance};
pub use observation::Observation;
pub use provider::{decide, record_failure, Fetched, PayloadReport, RefreshPlan, RefreshStatus};
pub use subscription::{SourceFormat, Subscription};
#[cfg(feature = "singbox")]
pub use target::outbounds;
pub use target::{
    ProtocolSupport, RenderError, RenderIntent, Rendered, SkipReason, Skipped, Target,
    TargetDescriptor,
};
