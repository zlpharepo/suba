//! The latest successful provider snapshot and its cache metadata.
//!
//! One document keeps the payload and its validators consistent across atomic
//! store replacements. Nodes are derived only from this payload; synchronization
//! failures retain it and do not advance its successful synchronization time.

use serde::{Deserialize, Serialize};

/// What a provider served, and what this hub knows about it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// The ETag the provider served, sent back as `If-None-Match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,

    /// The `Last-Modified` the provider served, sent back as
    /// `If-Modified-Since`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,

    /// When the payload was last replaced, in seconds since the epoch.
    ///
    /// A `304` does not move it: the payload did not change, so its age is
    /// still its age.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<i64>,

    /// Last recorded fetch attempt, in seconds since the epoch, including
    /// unsuccessful attempts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,

    /// The sha256 of the payload as it arrived.
    ///
    /// Identical bytes keep their payload replacement time even when a provider
    /// has no validators. Successful synchronization metadata still advances.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// The last failure, kept so that a provider that has been failing is
    /// visible without reading the log of a process that tried hours ago.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// The payload, byte for byte as the provider served it.
    ///
    /// Parsing is the job of whatever consumes it: an upstream format this
    /// build does not understand is still cached faithfully, and a new reader
    /// can be pointed at what is already stored without a second fetch.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub payload: String,

    /// Last successful synchronization, in seconds since the epoch. Changed
    /// payloads, identical payloads and `304` confirmations all advance it;
    /// failures leave it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
}

impl Observation {
    /// Whether nothing has ever been observed from this provider.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty() && self.updated_at.is_none() && self.error.is_none()
    }

    /// The conditional-request material, for a fetch that has something to
    /// compare against.
    ///
    /// A client with no payload must not ask conditionally: a `304` would tell
    /// it that the version it does not have is current.
    pub fn conditions(&self) -> Option<(&str, Option<&str>)> {
        self.etag
            .as_deref()
            .map(|etag| (etag, self.last_modified.as_deref()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditions_are_absent_until_there_is_something_to_compare_against() {
        // A client with nothing cached must not ask conditionally.
        assert_eq!(Observation::default().conditions(), None);

        let with_etag = Observation {
            etag: Some("\"v1\"".to_string()),
            ..Observation::default()
        };
        assert_eq!(with_etag.conditions(), Some(("\"v1\"", None)));

        let with_both = Observation {
            etag: Some("\"v1\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
            ..Observation::default()
        };
        assert_eq!(
            with_both.conditions(),
            Some(("\"v1\"", Some("Wed, 21 Oct 2015 07:28:00 GMT")))
        );
    }

    #[test]
    fn a_failure_is_visible_without_the_payload_being_touched() {
        let observation = Observation {
            error: Some("the provider refused the connection".to_string()),
            payload: "still here".to_string(),
            ..Observation::default()
        };

        assert!(!observation.is_empty(), "a failure is something observed");
        assert_eq!(observation.payload, "still here");
    }

    #[test]
    fn an_observation_with_nothing_in_it_is_empty() {
        assert!(Observation::default().is_empty());
        assert!(!Observation {
            payload: "payload".to_string(),
            ..Observation::default()
        }
        .is_empty());
    }
}
