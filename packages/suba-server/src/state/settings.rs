use std::path::Path;

use crate::{
    config::{Administrator, AppConfig, ConfigError, KeyPair, APP_CONFIG_BASENAME},
    error::Error,
    tracing,
};

use super::persisted::Persisted;
#[cfg(feature = "singbox-core")]
use suba_core::proto::Host;

/// Where a subscription URL starts when the operator has not said otherwise.
const DEFAULT_PREFIX: &str = "s";

/// The instance settings: administrator, stable identity, and the key pair
/// used by distinct login-token and peer-proof protocols.
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

    /// Where clients reach this machine, when the operator has said.
    ///
    /// Never guessed: a listen address, a private address and the address
    /// traffic leaves by all differ from the one a client can dial once a
    /// reverse proxy or a port forward sits in front.
    #[cfg(feature = "singbox-core")]
    pub(crate) async fn public_host(&self) -> Result<Option<Host>, Error> {
        let written = self.file.read(|config| config.public_host.clone()).await;

        match written
            .as_deref()
            .map(str::trim)
            .filter(|host| !host.is_empty())
        {
            None => Ok(None),
            Some(host) => Host::parse(host).map(Some).map_err(|_| Error::PublicHost {
                reason: "a public host is a domain name or an IP address",
            }),
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

    pub(crate) async fn existing_peer_signer(&self) -> Result<super::peers::IdentitySigner, Error> {
        let (id, pair) = self
            .file
            .read(|config| Some((config.instance_id?, config.key_pair.clone()?)))
            .await
            .ok_or(Error::Unauthorized)?;
        super::peers::IdentitySigner::new(id, &pair)
    }

    pub(crate) async fn peer_signer(&self) -> Result<super::peers::IdentitySigner, Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        let created = config.instance_id.is_none() || config.key_pair.is_none();
        let id = *config.instance_id.get_or_insert_with(uuid::Uuid::now_v7);
        if config.key_pair.is_none() {
            config.key_pair = Some(KeyPair::generate()?);
        }
        let signer =
            super::peers::IdentitySigner::new(id, config.key_pair.as_ref().expect("instance key"))?;
        if created {
            locked.commit(config).await?;
        }
        Ok(signer)
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

    #[tokio::test]
    async fn peer_identity_reuses_the_instance_key_and_persists_its_id() {
        let dir = test_dir();
        let store = SettingsStore::load(&dir).unwrap();
        let pair = store.key_pair().await.unwrap();
        let first = store.peer_signer().await.unwrap();
        assert_eq!(first.identity.public_key, pair.public_key);
        let again = SettingsStore::load(&dir)
            .unwrap()
            .peer_signer()
            .await
            .unwrap();
        assert_eq!(first.identity, again.identity);
        assert_eq!(
            store.key_pair().await.unwrap().private_key,
            pair.private_key
        );
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn invalid_peer_keys_are_not_silently_replaced_or_assigned_a_new_identity() {
        let dir = test_dir();
        let mut pair = KeyPair::generate().unwrap();
        pair.public_key = KeyPair::generate().unwrap().public_key;
        let app = AppConfig {
            key_pair: Some(pair.clone()),
            ..AppConfig::default()
        };
        crate::config::write_config(dir.to_str().unwrap(), APP_CONFIG_BASENAME, &app)
            .await
            .unwrap();
        let store = SettingsStore::load(&dir).unwrap();
        assert!(matches!(
            store.peer_signer().await,
            Err(Error::PeerIdentity)
        ));
        let held: AppConfig =
            crate::config::read_config(dir.to_str().unwrap(), APP_CONFIG_BASENAME).unwrap();
        assert!(held.instance_id.is_none());
        assert_eq!(held.key_pair.unwrap().private_key, pair.private_key);
        tokio::fs::remove_dir_all(dir).await.unwrap();
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

    #[cfg(feature = "singbox-core")]
    #[tokio::test]
    async fn the_public_host_is_read_as_written_and_refused_when_it_is_not_one() {
        let dir = test_dir();
        let store = SettingsStore::load(&dir).unwrap();
        assert_eq!(store.public_host().await.unwrap(), None, "never guessed");

        for (written, read) in [
            ("proxy.example.com", Some("proxy.example.com")),
            (" 192.0.2.7 ", Some("192.0.2.7")),
            ("", None),
        ] {
            let app = AppConfig {
                public_host: Some(written.to_string()),
                ..AppConfig::default()
            };
            crate::config::write_config(dir.to_str().unwrap(), APP_CONFIG_BASENAME, &app)
                .await
                .unwrap();

            let host = SettingsStore::load(&dir)
                .unwrap()
                .public_host()
                .await
                .unwrap();
            assert_eq!(
                host.map(|host| host.to_string()).as_deref(),
                read,
                "{written:?}"
            );
        }

        let app = AppConfig {
            public_host: Some("https://proxy.example.com/".to_string()),
            ..AppConfig::default()
        };
        crate::config::write_config(dir.to_str().unwrap(), APP_CONFIG_BASENAME, &app)
            .await
            .unwrap();
        assert!(matches!(
            SettingsStore::load(&dir).unwrap().public_host().await,
            Err(Error::PublicHost { .. })
        ));
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
