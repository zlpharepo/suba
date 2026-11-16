use std::path::{Path, PathBuf};

use clap::Parser;

use suba_server::{tracing, AgentOptions, Privileged, ServerConfig, SubaServer};

#[derive(Parser)]
#[command(author = "ZLPHA")]
#[command(version)]
#[command(propagate_version = true)]
struct Cli {
    /// Specify hostname
    #[arg(long, env = "SUBA_HOST", default_value = "127.0.0.1")]
    host: String,

    /// Specify port
    #[arg(short, long, env = "SUBA_PORT", default_value_t = 8090)]
    port: u16,

    /// Path to use for configurations
    #[arg(short, long, env = "SUBA_CONFIG", default_value = "config")]
    config: String,

    /// Path to use for the working directory
    #[arg(short, long, env = "SUBA_DATA", default_value = "data")]
    data: String,

    /// Run as a service
    #[arg(short, long, default_value = "false")]
    service: bool,

    /// Allow this instance to run as root, which a core that creates an
    /// interface needs (a `tun` inbound, or `tproxy`/`redirect` on Linux)
    #[arg(long, env = "SUBA_RUN_AS_ROOT", default_value = "false")]
    run_as_root: bool,

    /// The user whose files this instance is holding, for a run that is root:
    /// what it writes is theirs, and a core is dropped to them unless the
    /// module asks for root
    #[arg(long, env = "SUBA_USER")]
    user: Option<u32>,

    /// The group those files belong to, when it is a different number
    #[arg(long, env = "SUBA_GROUP")]
    group: Option<u32>,

    /// Run as an Edge Agent controlled by one manager
    #[arg(long, env = "SUBA_AGENT", requires = "manager_api_url")]
    agent: bool,

    /// Manager API base URL, including any reverse-proxy prefix and /api
    #[arg(long, env = "SUBA_MANAGER_API_URL", requires = "agent")]
    manager_api_url: Option<String>,

    /// One-time invitation token for initial Agent pairing
    #[arg(long, env = "SUBA_AGENT_TOKEN", requires = "agent")]
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

        let server = if self.agent {
            SubaServer::agent(
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

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl Drop for RestoreEnv {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    fn environment(values: &[(&'static str, &str)]) -> RestoreEnv {
        let old = values
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, value) in values {
            std::env::set_var(key, value);
        }
        RestoreEnv(old)
    }

    #[test]
    fn agent_mode_is_explicit_and_requires_its_manager() {
        let _lock = ENV_LOCK.lock().unwrap();
        let cli = Cli::try_parse_from(["suba"]).unwrap_or_else(|_| panic!("default CLI"));
        assert!(!cli.agent);
        assert!(Cli::try_parse_from(["suba", "--agent"]).is_err());
        assert!(Cli::try_parse_from([
            "suba",
            "--manager-api-url",
            "https://manager.example.invalid/api"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "suba",
            "--agent",
            "--manager-api-url",
            "https://manager.example.invalid/api",
        ])
        .unwrap_or_else(|_| panic!("agent CLI"));
        assert!(cli.agent);
        assert!(cli.agent_token.is_none());
        assert!(Cli::try_parse_from(["suba", "--agent-token", "fixture"]).is_err());
    }

    #[test]
    fn container_environment_configures_agent_and_cli_overrides_it() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _restore = environment(&[
            ("SUBA_HOST", "0.0.0.0"),
            ("SUBA_PORT", "18090"),
            ("SUBA_CONFIG", "/app/config"),
            ("SUBA_DATA", "/app/data"),
            ("SUBA_RUN_AS_ROOT", "true"),
            ("SUBA_USER", "10001"),
            ("SUBA_GROUP", "10002"),
            ("SUBA_AGENT", "true"),
            (
                "SUBA_MANAGER_API_URL",
                "https://manager.example.invalid/api",
            ),
            ("SUBA_AGENT_TOKEN", "fixture-token"),
        ]);
        let cli = Cli::try_parse_from(["suba"]).unwrap();
        assert!(cli.agent);
        assert_eq!(cli.host, "0.0.0.0");
        assert_eq!(cli.port, 18090);
        assert_eq!(cli.config, "/app/config");
        assert_eq!(cli.data, "/app/data");
        assert!(cli.run_as_root);
        assert_eq!(cli.user, Some(10001));
        assert_eq!(cli.group, Some(10002));
        assert_eq!(
            cli.manager_api_url.as_deref(),
            Some("https://manager.example.invalid/api")
        );
        assert_eq!(cli.agent_token.as_deref(), Some("fixture-token"));
        let override_cli = Cli::try_parse_from(["suba", "--host", "127.0.0.1"]).unwrap();
        assert_eq!(override_cli.host, "127.0.0.1");
    }
}
