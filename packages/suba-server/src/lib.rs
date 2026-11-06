mod agent;
mod config;
mod dto;
mod error;
pub mod fs;
mod handlers;
pub mod identity;
pub mod password;
pub mod provider;
mod routers;
mod state;
mod store;
pub mod tracing;

pub use agent::AgentOptions;
pub(crate) use config::Claims;
pub use config::{ConfigError, ListenAddr, ServerConfig};
pub use error::{Error, HttpError};
pub use identity::{Identity, Privileged, Source};
pub use state::AppState;

pub struct SubaServer {
    state: AppState,
    tcp: Option<tokio::net::TcpListener>,
}

impl SubaServer {
    pub async fn new(config: ServerConfig) -> Result<Self, Error> {
        let tcp = tokio::net::TcpListener::bind(config.listen_addr()).await?;
        let state = AppState::build(&config).await?;

        Ok(Self {
            state,
            tcp: Some(tcp),
        })
    }

    pub async fn edge_agent(config: ServerConfig, options: AgentOptions) -> Result<Self, Error> {
        let state = AppState::build_agent(&config).await?;
        agent::pair(&state, options).await?;
        #[cfg(feature = "singbox-core")]
        {
            let store = state.singbox();
            tokio::task::spawn_blocking(move || store.restore_deployment()).await??;
        }
        Ok(Self { state, tcp: None })
    }

    pub async fn serve(self) -> Result<(), Error> {
        use tokio::signal::unix::{signal, SignalKind};

        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        self.serve_until(
            async move {
                tokio::select! {
                    _ = interrupt.recv() => {},
                    _ = terminate.recv() => {},
                }
            },
            std::time::Duration::from_secs(10),
        )
        .await
    }

    async fn serve_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
        drain_timeout: std::time::Duration,
    ) -> Result<(), Error> {
        if self.state.is_agent() {
            return self.serve_agent_until(shutdown).await;
        }
        let tcp = self.tcp.expect("manager listener");
        let router = routers::AppRouter::route(self.state.web_dir()).with_state(self.state.clone());

        // Providers start refreshing as soon as the server does, so a
        // restart does not leave subscriptions stale until their next tick.
        let refresher = tokio::spawn(self.state.refresher().run());
        #[cfg(feature = "singbox-core")]
        let stopping = self.state.singbox();
        #[cfg(feature = "singbox-core")]
        let observing = tokio::spawn(self.state.observation().run(self.state.singbox()));

        // After the listeners and the observation loop are up, so a core that
        // starts here is one the rest of the instance can already serve.
        #[cfg(feature = "singbox-core")]
        let starting = tokio::spawn(handlers::singbox::autostart(self.state.clone()));

        tracing::info!("SubA server running on http://{}", tcp.local_addr()?);
        let (notified, signal) = tokio::sync::oneshot::channel();
        let serving = async move {
            axum::serve(tcp, router.into_make_service())
                .with_graceful_shutdown(async move {
                    shutdown.await;
                    #[cfg(feature = "singbox-core")]
                    stopping.begin_shutdown();
                    let _ = notified.send(());
                })
                .await
        };
        tokio::pin!(serving);
        let finished = tokio::select! {
            result = &mut serving => Some(result),
            _ = signal => None,
        };
        refresher.abort();
        let _ = refresher.await;
        self.state.peers().edge.shutdown();
        #[cfg(feature = "singbox-core")]
        {
            observing.abort();
            let _ = observing.await;
        }

        // An unfinished HTTP request must not keep the managed core alive.
        #[cfg(feature = "singbox-core")]
        let stopped = {
            let store = self.state.singbox();
            tokio::task::spawn_blocking(move || store.shutdown(std::time::Duration::from_secs(10)))
        };
        #[cfg(feature = "singbox-core")]
        let served = {
            // A start still in flight is joined first: `shutdown` sets a flag
            // that a start already past its check would otherwise ignore.
            if let Err(error) = starting.await {
                tracing::warn!("the core's autostart did not finish: {error}");
            }
            match finished {
                Some(result) => result,
                None => match tokio::time::timeout(drain_timeout, &mut serving).await {
                    Ok(result) => result,
                    Err(_) => {
                        tracing::warn!("HTTP shutdown grace period elapsed");
                        Ok(())
                    }
                },
            }
        };
        #[cfg(not(feature = "singbox-core"))]
        let served = match finished {
            Some(result) => result,
            None => match tokio::time::timeout(drain_timeout, &mut serving).await {
                Ok(result) => result,
                Err(_) => {
                    tracing::warn!("HTTP shutdown grace period elapsed");
                    Ok(())
                }
            },
        };
        #[cfg(feature = "singbox-core")]
        stopped.await??;
        Ok(served?)
    }

    async fn serve_agent_until(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), Error> {
        let edging = tokio::spawn(state::peers::edge::run(self.state.clone()));
        #[cfg(feature = "singbox-core")]
        let observing = tokio::spawn(self.state.observation().run(self.state.singbox()));
        #[cfg(feature = "singbox-core")]
        let starting = tokio::spawn(handlers::singbox::autostart(self.state.clone()));
        shutdown.await;
        self.state.peers().edge.shutdown();
        edging.abort();
        let _ = edging.await;
        #[cfg(feature = "singbox-core")]
        {
            self.state.singbox().begin_shutdown();
            observing.abort();
            let _ = observing.await;
            let _ = starting.await;
            let store = self.state.singbox();
            tokio::task::spawn_blocking(move || store.shutdown(std::time::Duration::from_secs(10)))
                .await??;
        }
        Ok(())
    }
}
