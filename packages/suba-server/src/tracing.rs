pub use tracing::*;
use tracing_subscriber::EnvFilter;

pub fn init() {
    let filter = EnvFilter::try_from_env("LOG_LEVEL").unwrap_or_else(|_| {
        EnvFilter::new("info,suba_server=debug,suba_core=debug,suba_proto=debug")
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
