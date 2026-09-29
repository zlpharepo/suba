use std::path::{Path, PathBuf};

use clap::Parser;

use suba_server::{tracing, ServerConfig, SubaServer};

#[derive(Parser)]
#[command(author = "ZLPHA")]
#[command(version)]
#[command(propagate_version = true)]
struct Cli {
    /// Specify hostname
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Specify port
    #[arg(short, long, default_value_t = 8090)]
    port: u16,

    /// Path to use for configurations
    #[arg(short, long, default_value = "config")]
    config: String,

    /// Path to use for the working directory
    #[arg(short, long, default_value = "data")]
    data: String,

    /// Run as a service
    #[arg(short, long, default_value = "false")]
    service: bool,
}

impl Cli {
    async fn serve(&self) {
        let listen = self.host.parse().unwrap_or_else(|error| {
            tracing::error!("Invalid host '{}': {}", self.host, error);
            std::process::exit(1);
        });
        let config = ServerConfig {
            listen,
            port: self.port,
            config_dir: PathBuf::from(self.resolve_path(&self.config)),
            data_dir: PathBuf::from(self.resolve_path(&self.data)),
        };

        let server = SubaServer::new(config).await.unwrap_or_else(|error| {
            tracing::error!("Failed to initialize server: {}", error);
            std::process::exit(1);
        });
        server.serve().await.unwrap_or_else(|error| {
            tracing::error!("Server encountered an error: {}", error);
            std::process::exit(1);
        });
    }

    fn resolve_path(&self, path: &str) -> String {
        let path = Path::new(path);

        if self.service && path.is_relative() {
            let base_dir = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| PathBuf::from("."));

            return base_dir.join(path).to_string_lossy().into_owned();
        }

        path.to_string_lossy().into_owned()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing::init();

    cli.serve().await;
}
