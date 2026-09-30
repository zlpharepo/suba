//! How often one delivery token may be used.
//!
//! A token is the whole of a delivery's authorization, so a leaked one is
//! bounded by this and by nothing else. A fixed one-minute window per token is
//! enough for that: a client asks a few times an hour, and anything past the
//! limit is a script, not a subscriber.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Requests one token may make per window.
pub(crate) const LIMIT: u32 = 60;

/// The window the limit applies to.
const WINDOW: Duration = Duration::from_secs(60);

/// Past this many tracked tokens, expired windows are dropped.
const PRUNE_AT: usize = 1024;

pub(crate) struct Limiter {
    windows: Mutex<HashMap<String, (Instant, u32)>>,
}

impl Limiter {
    pub(crate) fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Count one request against `key`, or answer how many seconds to wait.
    pub(crate) fn check(&self, key: &str) -> Result<(), u64> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), u64> {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if windows.len() >= PRUNE_AT {
            windows.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
        }

        let (start, count) = windows.entry(key.to_owned()).or_insert((now, 0));

        if now.duration_since(*start) >= WINDOW {
            *start = now;
            *count = 0;
        }

        if *count >= LIMIT {
            let left = WINDOW.saturating_sub(now.duration_since(*start));

            return Err(left.as_secs().max(1));
        }

        *count += 1;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_past_its_limit_waits_for_the_next_window() {
        let limiter = Limiter::new();
        let start = Instant::now();

        for _ in 0..LIMIT {
            assert!(limiter.check_at("main/phone", start).is_ok());
        }

        let wait = limiter
            .check_at("main/phone", start + Duration::from_secs(20))
            .unwrap_err();
        assert_eq!(wait, 40);

        // Another token is counted on its own.
        assert!(limiter.check_at("main/laptop", start).is_ok());

        assert!(limiter.check_at("main/phone", start + WINDOW).is_ok());
    }
}
