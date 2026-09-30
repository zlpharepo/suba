use std::path::Path;

use crate::{
    config::{Administrator, AppConfig, ConfigError, KeyPair, APP_CONFIG_BASENAME},
    error::Error,
    tracing,
};

use super::persisted::Persisted;

/// Where a subscription URL starts when the operator has not said otherwise.
const DEFAULT_PREFIX: &str = "s";

/// The instance settings: the administrator account and the key pair that
/// signs sessions.
pub(crate) struct SettingsStore {
    file: Persisted<AppConfig>,
}

impl SettingsStore {
    pub(crate) fn load(config_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            file: Persisted::load(config_dir, APP_CONFIG_BASENAME)?,
        })
    }

    /// The path segment a subscription URL starts with.
    ///
    /// Written with or without its leading slash — `/s` and `s` are the same
    /// prefix — and `s` when the operator has not said, so a delivery is at
    /// `/s/<token>`. One segment, because a prefix with a slash in it addresses
    /// a path nothing routes to, and a URL that cannot work should be refused
    /// where it is configured rather than answered with a 404 nobody can explain.
    pub(crate) async fn subscription_prefix(&self) -> Result<String, Error> {
        let written = self
            .file
            .read(|config| config.subscription.clone())
            .await
            .and_then(|subscription| subscription.prefix)
            .unwrap_or_else(|| DEFAULT_PREFIX.to_string());
        let prefix = written.trim_matches('/').to_string();

        match prefix.is_empty() || prefix.contains('/') {
            true => Err(Error::Prefix {
                reason: "a prefix is one path segment",
            }),
            false => Ok(prefix),
        }
    }

    /// The registered administrator, if the instance has been claimed.
    pub(crate) async fn administrator(&self) -> Option<Administrator> {
        self.file.read(|config| config.administrator.clone()).await
    }

    /// Authenticate the administrator, registering the first caller as one when
    /// the instance is still unclaimed.
    pub(crate) async fn login_or_register(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Administrator, Error> {
        let locked = self.file.lock().await;
        if let Some(administrator) = locked.get().administrator.clone() {
            administrator.verify(username, password).await?;
            return Ok(administrator);
        }

        let administrator = Administrator::create(username, password).await?;
        let mut config = locked.get().clone();
        config.administrator = Some(administrator.clone());
        locked.commit(config).await?;
        tracing::info!("Administrator created: {}", administrator.username);

        Ok(administrator)
    }

    /// The instance key pair, generated and persisted on first use.
    pub(crate) async fn key_pair(&self) -> Result<KeyPair, Error> {
        let locked = self.file.lock().await;
        if let Some(key_pair) = locked.get().key_pair.clone() {
            return Ok(key_pair);
        }

        let key_pair = KeyPair::generate()?;
        let mut config = locked.get().clone();
        config.key_pair = Some(key_pair.clone());
        locked.commit(config).await?;
        tracing::info!("Generated a new instance key pair");

        Ok(key_pair)
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::config::SubscriptionConfig;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-settings-{}", uuid::Uuid::now_v7()))
    }

    /// Write the instance document with this delivery prefix in it.
    async fn write_prefix(dir: &Path, prefix: &str) {
        let app = AppConfig {
            subscription: Some(SubscriptionConfig {
                prefix: Some(prefix.to_string()),
            }),
            ..AppConfig::default()
        };

        crate::config::write_config(dir.to_str().unwrap(), APP_CONFIG_BASENAME, &app)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_prefix_is_read_with_or_without_its_leading_slash() {
        let dir = test_dir();

        assert_eq!(
            SettingsStore::load(&dir)
                .unwrap()
                .subscription_prefix()
                .await
                .unwrap(),
            "s",
            "where a delivery is when nobody has said"
        );

        for written in ["/s", "s", "/s/"] {
            write_prefix(&dir, written).await;

            assert_eq!(
                SettingsStore::load(&dir)
                    .unwrap()
                    .subscription_prefix()
                    .await
                    .unwrap(),
                "s",
                "{written} is the same prefix"
            );
        }
    }

    /// A prefix that is not one path segment addresses nothing, so it is refused
    /// where it is configured rather than answered with a 404 nobody can explain.
    #[tokio::test]
    async fn a_prefix_that_is_not_one_segment_is_refused() {
        let dir = test_dir();

        for written in ["", "/", "a/b", "//"] {
            write_prefix(&dir, written).await;

            assert!(
                matches!(
                    SettingsStore::load(&dir)
                        .unwrap()
                        .subscription_prefix()
                        .await,
                    Err(Error::Prefix { .. })
                ),
                "{written:?} was accepted"
            );
        }
    }

    #[tokio::test]
    async fn the_first_login_registers_the_administrator() {
        let dir = test_dir();
        let store = SettingsStore::load(&dir).unwrap();
        assert!(store.administrator().await.is_none());

        let registered = store
            .login_or_register("doge", "correct horse battery staple")
            .await
            .unwrap();

        assert_eq!(registered.username, "doge");
        assert!(store.administrator().await.is_some());

        let reloaded = SettingsStore::load(&dir).unwrap();
        assert!(reloaded.administrator().await.is_some());
        assert!(reloaded
            .login_or_register("doge", "correct horse battery staple")
            .await
            .is_ok());
        assert!(reloaded
            .login_or_register("doge", "wrong password")
            .await
            .is_err());
        assert!(reloaded
            .login_or_register("someone", "correct horse battery staple")
            .await
            .is_err());

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn the_key_pair_is_generated_once_and_kept() {
        let dir = test_dir();
        let store = SettingsStore::load(&dir).unwrap();

        let generated = store.key_pair().await.unwrap();
        assert_eq!(
            store.key_pair().await.unwrap().public_key,
            generated.public_key
        );
        assert_eq!(
            SettingsStore::load(&dir)
                .unwrap()
                .key_pair()
                .await
                .unwrap()
                .public_key,
            generated.public_key
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
