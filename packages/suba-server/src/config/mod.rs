mod administrator;
mod codec;
mod error;
mod key_pair;
pub mod provider;
mod server;

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

pub use administrator::*;
pub(crate) use codec::config_path;
pub use error::ConfigError;
pub use key_pair::*;
pub use provider::Provider;
pub use server::{ListenAddr, ServerConfig};

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

    codec::decode(&content, &path)
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
    let destination = config_path(base, basename);
    let content = codec::encode(value, &destination)?;

    let target = destination.clone();
    tokio::task::spawn_blocking(move || crate::fs::write_atomic(&target, content.as_bytes()))
        .await
        .map_err(|error| ConfigError::Join(error.to_string()))??;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

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

    /// A provider with its optional fields left unset must survive a write and
    /// a read in whichever format is compiled in.
    ///
    /// This is the round trip that used to fail under the JSON format:
    /// `http_serde`'s option serializer writes `None` as `null`, and its own
    /// deserializer then refuses that `null`, so what the store wrote it could
    /// not read back. Skipping the absent field is the fix, and this test holds
    /// it for every format.
    #[tokio::test]
    async fn a_provider_with_no_optional_fields_round_trips() {
        use crate::config::provider::{default_interval, Http, SharedFields};

        let path = test_path();
        let mut config = ProvidersConfig::default();
        config.providers.insert(
            "airport".to_string(),
            Provider::Http(Http {
                shared: SharedFields { disabled: false },
                url: "https://example.com/subscription".parse().unwrap(),
                headers: None,
                timeout: None,
                interval: default_interval(),
            }),
        );

        write_config(path.to_str().unwrap(), PROVIDERS_BASENAME, &config)
            .await
            .unwrap();

        let reloaded = load_providers(&path);
        let stored = reloaded.providers.get("airport").expect("the provider");

        assert!(stored.is_none_of_the_optional_fields());

        tokio::fs::remove_dir_all(path).await.unwrap();
    }
}
