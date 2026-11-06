use std::path::{Path, PathBuf};

use clap::Parser;

use suba_server::{tracing, AgentOptions, Privileged, ServerConfig, SubaServer};

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

    /// Allow this instance to run as root, which a core that creates an
    /// interface needs (a `tun` inbound, or `tproxy`/`redirect` on Linux)
    #[arg(long, default_value = "false")]
    run_as_root: bool,

    /// The user whose files this instance is holding, for a run that is root:
    /// what it writes is theirs, and a core is dropped to them unless the
    /// module asks for root
    #[arg(long)]
    user: Option<u32>,

    /// The group those files belong to, when it is a different number
    #[arg(long)]
    group: Option<u32>,

    /// Run as an Edge Agent controlled by one manager
    #[arg(long, requires = "manager_api_url")]
    edge_agent: bool,

    /// Manager API base URL, including any reverse-proxy prefix and /api
    #[arg(long, requires = "edge_agent")]
    manager_api_url: Option<String>,

    /// One-time invitation token for initial Agent pairing
    #[arg(long, requires = "edge_agent")]
    agent_token: Option<String>,
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
            privileged: Privileged {
                acknowledged: self.run_as_root,
                user: self.user,
                group: self.group,
            },
        };

        let server = if self.edge_agent {
            SubaServer::edge_agent(
                config,
                AgentOptions {
                    manager_api_url: self.manager_api_url.clone().expect("required by clap"),
                    token: self.agent_token.clone(),
                },
            )
            .await
        } else {
            SubaServer::new(config).await
        }
        .unwrap_or_else(|error| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_mode_is_explicit_and_requires_its_manager() {
        let cli = Cli::try_parse_from(["suba"]).unwrap_or_else(|_| panic!("default CLI"));
        assert!(!cli.edge_agent);
        assert!(Cli::try_parse_from(["suba", "--edge-agent"]).is_err());
        assert!(Cli::try_parse_from([
            "suba",
            "--manager-api-url",
            "https://manager.example.invalid/api"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "suba",
            "--edge-agent",
            "--manager-api-url",
            "https://manager.example.invalid/api",
        ])
        .unwrap_or_else(|_| panic!("agent CLI"));
        assert!(cli.edge_agent);
        assert!(cli.agent_token.is_none());
        assert!(Cli::try_parse_from(["suba", "--agent-token", "fixture"]).is_err());
    }
}
