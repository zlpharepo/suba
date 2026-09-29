mod administrator;
mod error;
mod key_pair;
pub mod provider;
mod server;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

pub use administrator::*;
pub use error::ConfigError;
pub use key_pair::*;
pub use provider::Provider;
pub use server::{ListenAddr, ServerConfig};

#[cfg(not(any(feature = "toml", feature = "json")))]
compile_error!("Enable exactly one configuration format feature: toml or json");

#[cfg(all(feature = "toml", not(feature = "json")))]
const CONFIG_EXTENSION: &str = "toml";
#[cfg(feature = "json")]
const CONFIG_EXTENSION: &str = "json";

pub(crate) const APP_CONFIG_BASENAME: &str = "config";
pub(crate) const PROVIDERS_BASENAME: &str = "providers";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppConfig {
    pub administrator: Option<Administrator>,
    #[serde(rename = "ed25519")]
    pub key_pair: Option<KeyPair>,
    pub subscription_prefix: Option<SubscriptionConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvidersConfig {
    #[serde(flatten)]
    pub providers: HashMap<String, Provider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SubscriptionConfig {
    pub prefix: Option<String>,
}

/// The path of `basename` inside the configuration directory `base`.
pub(crate) fn config_path(base: impl AsRef<Path>, basename: &str) -> PathBuf {
    base.as_ref().join(format!("{basename}.{CONFIG_EXTENSION}"))
}

/// Read a configuration file, falling back to [`Default`] when it is missing or
/// empty.
pub(crate) fn read_config<T>(base: &str, basename: &str) -> Result<T, ConfigError>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let path = config_path(base, basename);
    let content = match fs::read_to_string(&path) {
        Ok(content) if !content.trim().is_empty() => content,
        Ok(_) => return Ok(T::default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(error) => return Err(error.into()),
    };

    #[cfg(feature = "toml")]
    let value = toml::from_str(&content).map_err(|error| ConfigError::decode(&path, error))?;
    #[cfg(feature = "json")]
    let value =
        serde_json::from_str(&content).map_err(|error| ConfigError::decode(&path, error))?;

    Ok(value)
}

/// Write a configuration file atomically.
///
/// The value is written beside the destination and renamed into place, so a
/// concurrent reader can never observe a partially written file.
pub(crate) async fn write_config<T>(
    base: &str,
    basename: &str,
    value: &T,
) -> Result<(), ConfigError>
where
    T: Serialize,
{
    let destination = config_path(base, basename);
    tokio::fs::create_dir_all(base).await?;

    #[cfg(all(feature = "toml", not(feature = "json")))]
    let content =
        toml::to_string_pretty(value).map_err(|error| ConfigError::encode(&destination, error))?;
    #[cfg(feature = "json")]
    let content = serde_json::to_string_pretty(value)
        .map_err(|error| ConfigError::encode(&destination, error))?;

    let temporary =
        destination.with_extension(format!("{CONFIG_EXTENSION}.{}.tmp", uuid::Uuid::now_v7()));
    if let Err(error) = write_atomically(&temporary, &destination, content.as_bytes()).await {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(error);
    }

    Ok(())
}

async fn write_atomically(
    temporary: &Path,
    destination: &Path,
    content: &[u8],
) -> Result<(), ConfigError> {
    use tokio::io::AsyncWriteExt;

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .await?;
    file.write_all(content).await?;
    file.sync_all().await?;
    drop(file);

    tokio::fs::rename(temporary, destination).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!("suba-config-{}", uuid::Uuid::now_v7()))
    }

    fn load_app(path: &Path) -> AppConfig {
        read_config(path.to_str().unwrap(), APP_CONFIG_BASENAME).unwrap()
    }

    fn load_providers(path: &Path) -> ProvidersConfig {
        read_config(path.to_str().unwrap(), PROVIDERS_BASENAME).unwrap()
    }

    #[tokio::test]
    async fn app_and_provider_configs_use_separate_files() {
        let path = test_path();
        let app = AppConfig {
            subscription_prefix: Some(SubscriptionConfig {
                prefix: Some("/s".to_string()),
            }),
            ..AppConfig::default()
        };
        let providers = ProvidersConfig::default();

        write_config(path.to_str().unwrap(), APP_CONFIG_BASENAME, &app)
            .await
            .unwrap();
        write_config(path.to_str().unwrap(), PROVIDERS_BASENAME, &providers)
            .await
            .unwrap();

        assert!(config_path(&path, APP_CONFIG_BASENAME).is_file());
        assert!(config_path(&path, PROVIDERS_BASENAME).is_file());
        assert_eq!(
            load_app(&path)
                .subscription_prefix
                .unwrap()
                .prefix
                .as_deref(),
            Some("/s")
        );
        assert!(load_providers(&path).providers.is_empty());

        tokio::fs::remove_dir_all(path).await.unwrap();
    }

    #[test]
    fn missing_configs_load_as_defaults() {
        let path = test_path();
        assert!(load_app(&path).administrator.is_none());
        assert!(load_providers(&path).providers.is_empty());
    }

    #[tokio::test]
    async fn malformed_config_is_returned_as_an_error() {
        let path = test_path();
        tokio::fs::create_dir_all(&path).await.unwrap();
        tokio::fs::write(config_path(&path, APP_CONFIG_BASENAME), "[broken")
            .await
            .unwrap();

        assert!(read_config::<AppConfig>(path.to_str().unwrap(), APP_CONFIG_BASENAME).is_err());
        tokio::fs::remove_dir_all(path).await.unwrap();
    }
}
