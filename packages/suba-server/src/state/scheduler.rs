//! Background refreshing of provider subscriptions.

use std::{sync::Arc, time::Duration};

use reqwest::Client;
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{self, Instant},
};

use crate::{error::Error, tracing};

use super::providers::ProviderStore;

/// Refreshes providers on their configured interval.
///
/// A provider carries its own interval, so there is no single clock to drive:
/// the refresher owns one worker per enabled provider instead. A configuration
/// change restarts the whole set, which is what makes an added provider start
/// working immediately and a removed one stop.
pub(crate) struct Refresher {
    providers: Arc<ProviderStore>,
    http: Client,
    changes: watch::Receiver<u64>,
}

impl Refresher {
    pub(crate) fn new(providers: Arc<ProviderStore>, http: Client) -> Self {
        let changes = providers.subscribe();

        Self {
            providers,
            http,
            changes,
        }
    }

    /// Refresh the enabled providers, then wait for the next configuration
    /// change.
    ///
    /// Returns only when the server is shutting down: an unreachable
    /// subscription is logged and retried, never fatal.
    pub async fn run(mut self) {
        let mut workers: JoinSet<()> = JoinSet::new();

        loop {
            workers.abort_all();
            while workers.join_next().await.is_some() {}

            for (name, provider) in self.providers.refreshable().await {
                // `refreshable` answers only providers that have an interval to
                // follow, so this cannot skip one.
                let Some(interval) = provider.interval() else {
                    continue;
                };

                let providers = Arc::clone(&self.providers);
                let http = self.http.clone();
                workers.spawn(async move {
                    worker(providers, http, name, interval).await;
                });
            }

            // A dropped sender means the store is gone, so there is nothing
            // left to follow.
            if self.changes.changed().await.is_err() {
                break;
            }
        }

        workers.abort_all();
    }
}

/// Refresh one provider forever, on its own interval.
///
/// The first refresh happens straight away, so a provider added at runtime is
/// fetched without waiting a full interval.
async fn worker(providers: Arc<ProviderStore>, http: Client, name: String, interval: Duration) {
    // An interval of zero would spin, so a floor is applied to whatever the
    // configuration asked for.
    let interval = interval.max(Duration::from_secs(1));
    let mut ticks = time::interval_at(Instant::now(), interval);

    loop {
        ticks.tick().await;

        match providers.refresh(&name, &http).await {
            Ok(refreshed) => {
                tracing::debug!("Refreshed provider '{}': {}", refreshed.name, refreshed)
            }
            // A provider that vanished or was disabled has nothing to
            // refresh; the next configuration change will replace this worker.
            Err(error @ (Error::ProviderNotFound(_) | Error::ProviderDisabled(_))) => {
                tracing::debug!("Stopping refresher for provider '{name}': {error}");
                return;
            }
            Err(error) => {
                tracing::warn!("Failed to refresh provider '{name}': {error}");
            }
        }
    }
}
