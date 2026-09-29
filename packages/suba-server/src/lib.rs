mod config;
mod dto;
mod error;
mod handlers;
pub mod password;
mod routers;
mod state;
pub mod tracing;

pub(crate) use config::Claims;
pub use config::{ConfigError, ListenAddr, ServerConfig};
pub use error::{Error, HttpError};
pub use state::AppState;

pub struct SubaServer {
    state: AppState,
    tcp: tokio::net::TcpListener,
}

impl SubaServer {
    pub async fn new(config: ServerConfig) -> Result<Self, Error> {
        let tcp = tokio::net::TcpListener::bind(config.listen_addr()).await?;
        let state = AppState::build(&config).await?;

        Ok(Self { state, tcp })
    }

    pub async fn serve(self) -> Result<(), Error> {
        let router = routers::AppRouter::route(self.state.web_dir()).with_state(self.state.clone());

        // Providers start refreshing as soon as the server does, so a
        // restart does not leave subscriptions stale until their next tick.
        tokio::spawn(self.state.refresher().run());

        tracing::info!("SubA server running on http://{}", self.tcp.local_addr()?);
        axum::serve(self.tcp, router.into_make_service()).await?;

        Ok(())
    }
}
