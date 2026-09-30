mod administrator;
pub(crate) mod codec;
mod error;
mod key_pair;
mod server;

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use administrator::*;
pub(crate) use codec::{config_name, config_path};
pub use error::ConfigError;
pub use key_pair::*;
pub use server::{ListenAddr, ServerConfig};

pub(crate) const APP_CONFIG_BASENAME: &str = "config";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppConfig {
    pub administrator: Option<Administrator>,
    #[serde(rename = "ed25519")]
    pub key_pair: Option<KeyPair>,
    pub subscription_prefix: Option<SubscriptionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SubscriptionConfig {
    pub prefix: Option<String>,
}

/// Read a configuration file, falling back to [`Default`] when it is missing or
/// empty.
pub(crate) fn read_config<T>(base: &str, basename: &str) -> Result<T, ConfigError>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let content = match crate::fs::read_to_string(Path::new(base), &config_name(basename))? {
        Some(content) if !content.trim().is_empty() => content,
        _ => return Ok(T::default()),
    };

    codec::decode(&content, &config_path(base, basename))
}

/// Write a configuration file.
///
/// The write is atomic and durable: it goes through [`crate::fs::write_atomic`],
/// which writes a sibling temp file, fsyncs it, renames it over the destination
/// and fsyncs the directory. A reader never observes a partial file, and the
/// rename survives a crash between the write and the next start.
pub(crate) async fn write_config<T>(
    base: &str,
    basename: &str,
    value: &T,
) -> Result<(), ConfigError>
where
    T: Serialize,
{
    // The path is for the error text; the write itself is by name, inside the
    // directory handle, so a name can never be a way out of it.
    let path = config_path(base, basename);
    let content = codec::encode(value, &path)?;
    let name = config_name(basename);
    let base = PathBuf::from(base);

    tokio::task::spawn_blocking(move || crate::fs::write_atomic(&base, &name, content.as_bytes()))
        .await
        .map_err(|error| ConfigError::Join(error.to_string()))??;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!("suba-config-{}", uuid::Uuid::now_v7()))
    }

    fn load_app(path: &Path) -> AppConfig {
        read_config(path.to_str().unwrap(), APP_CONFIG_BASENAME).unwrap()
    }

    #[tokio::test]
    async fn an_app_config_round_trips() {
        let path = test_path();
        let app = AppConfig {
            subscription_prefix: Some(SubscriptionConfig {
                prefix: Some("/s".to_string()),
            }),
            ..AppConfig::default()
        };

        write_config(path.to_str().unwrap(), APP_CONFIG_BASENAME, &app)
            .await
            .unwrap();

        assert!(config_path(&path, APP_CONFIG_BASENAME).is_file());
        assert_eq!(
            load_app(&path)
                .subscription_prefix
                .unwrap()
                .prefix
                .as_deref(),
            Some("/s")
        );

        tokio::fs::remove_dir_all(path).await.unwrap();
    }

    #[test]
    fn a_missing_config_loads_as_the_default() {
        assert!(load_app(&test_path()).administrator.is_none());
    }

    #[tokio::test]
    async fn malformed_config_is_returned_as_an_error() {
        let path = test_path();
        crate::fs::ensure_dir(&path).unwrap();
        fs::write(path.join(config_name(APP_CONFIG_BASENAME)), "[broken").unwrap();

        assert!(read_config::<AppConfig>(path.to_str().unwrap(), APP_CONFIG_BASENAME).is_err());
        tokio::fs::remove_dir_all(path).await.unwrap();
    }
}
