use std::path::Path;

use suba_core::tracing;

use crate::{
    config::{Administrator, AppConfig, ConfigError, KeyPair, APP_CONFIG_BASENAME},
    error::Error,
};

use super::persisted::Persisted;

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
    use std::path::PathBuf;

    use super::*;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-settings-{}", uuid::Uuid::now_v7()))
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
