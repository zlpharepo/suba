use std::{borrow::Cow, path::Path};

use reqwest::{Client, RequestBuilder, Url};
use serde::Serialize;

use crate::{
    config::{
        Administrator, AppConfig, ConfigError, GitHubMirror, GitHubToken, KeyPair,
        APP_CONFIG_BASENAME,
    },
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

/// The settings a client may read back after saving.
#[derive(Serialize)]
pub(crate) struct InstanceSettings {
    subscription_prefix: String,
    github_token_configured: bool,
    github_mirror: Option<String>,
}

impl InstanceSettings {
    fn from_config(config: &AppConfig) -> Result<Self, Error> {
        Ok(Self {
            subscription_prefix: subscription_prefix(config)?,
            github_token_configured: config.github_token.is_some(),
            github_mirror: config
                .github_mirror
                .as_ref()
                .map(|mirror| mirror.as_str().to_owned()),
        })
    }
}

/// Keep the release source consistent throughout an installation.
pub(crate) struct GitHubReleaseSettings {
    token: Option<GitHubToken>,
    mirror: Option<GitHubMirror>,
}

impl GitHubReleaseSettings {
    pub(crate) fn mirror(&self) -> Option<&str> {
        self.mirror.as_ref().map(GitHubMirror::as_str)
    }

    pub(crate) fn url<'a>(&self, original: &'a str) -> Cow<'a, str> {
        match self.mirror() {
            Some(mirror) => Cow::Owned(format!("{mirror}{original}")),
            None => Cow::Borrowed(original),
        }
    }

    /// The mirror receives release URLs, never the GitHub API credential.
    pub(crate) fn metadata_request(&self, client: &Client, original: &str) -> RequestBuilder {
        let request = client
            .get(self.url(original).as_ref())
            .timeout(std::time::Duration::from_secs(10));
        if self.mirror.is_none()
            && Url::parse(original).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host_str() == Some("api.github.com")
                    && url.port_or_known_default() == Some(443)
            })
        {
            if let Some(token) = &self.token {
                return request.bearer_auth(token.as_str());
            }
        }
        request
    }
}

impl SettingsStore {
    pub(crate) fn load(config_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            file: Persisted::load(config_dir, APP_CONFIG_BASENAME).map_err(
                |error| match error {
                    ConfigError::Decode { path, .. } => ConfigError::InstanceDecode(path),
                    error => error,
                },
            )?,
        })
    }

    /// The path segment a subscription URL starts with.
    ///
    /// Written with or without its leading slash — `/s` and `s` are the same
    /// prefix — and `s` when the operator has not said, so a delivery is at
    /// `/s/<name>/<token>`. One segment, because a prefix with a slash in it
    /// addresses a path nothing routes to, and a URL that cannot work should be
    /// refused where it is configured rather than answered with a 404 nobody can
    /// explain.
    pub(crate) async fn subscription_prefix(&self) -> Result<String, Error> {
        self.file.read(subscription_prefix).await
    }

    pub(crate) async fn instance_settings(&self) -> Result<InstanceSettings, Error> {
        self.file.read(InstanceSettings::from_config).await
    }

    /// Validate all changes before making any visible to callers.
    pub(crate) async fn update_instance_settings(
        &self,
        prefix: Option<&str>,
        github_token: Option<Option<String>>,
        github_mirror: Option<Option<String>>,
    ) -> Result<(InstanceSettings, bool), Error> {
        let locked = self.file.lock().await;
        let mut config = locked.get().clone();
        if let Some(prefix) = prefix {
            config.subscription = Some(crate::config::SubscriptionConfig {
                prefix: Some(validate_prefix(prefix)?),
            });
        }
        if let Some(token) = github_token {
            config.github_token = token.map(GitHubToken::try_from).transpose()?;
        }
        if let Some(mirror) = github_mirror {
            config.github_mirror = mirror.map(GitHubMirror::try_from).transpose()?;
        }
        let github_changed = config.github_token != locked.get().github_token
            || config.github_mirror != locked.get().github_mirror;
        let settings = InstanceSettings::from_config(&config)?;
        if prefix.is_some() || github_changed {
            locked.commit(config).await?;
        }
        Ok((settings, github_changed))
    }

    pub(crate) async fn github(&self) -> GitHubReleaseSettings {
        self.file
            .read(|config| GitHubReleaseSettings {
                token: config.github_token.clone(),
                mirror: config.github_mirror.clone(),
            })
            .await
    }

    /// Sessions are revoked before the new hash is adopted, so a failed write
    /// cannot leave the old password paired with still-valid sessions.
    pub(crate) async fn change_password(
        &self,
        sessions: &super::sessions::SessionStore,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let administrator = locked
            .get()
            .administrator
            .as_ref()
            .ok_or(Error::Unauthorized)?;
        verify_current(administrator, username, current_password).await?;
        let replacement = Administrator::create(username, new_password).await?;
        let mut config = locked.get().clone();
        config.administrator = Some(replacement);
        sessions.clear().await?;
        locked.commit(config).await?;
        Ok(())
    }

    /// Keep the existing password hash and machine key while changing the login name.
    pub(crate) async fn change_username(
        &self,
        sessions: &super::sessions::SessionStore,
        current_username: &str,
        current_password: &str,
        new_username: &str,
    ) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let administrator = locked
            .get()
            .administrator
            .as_ref()
            .ok_or(Error::Unauthorized)?;
        verify_current(administrator, current_username, current_password).await?;
        if administrator.username == new_username {
            return Ok(());
        }
        let mut config = locked.get().clone();
        config
            .administrator
            .as_mut()
            .expect("verified administrator")
            .username = new_username.to_string();
        sessions.clear().await?;
        locked.commit(config).await?;
        Ok(())
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

async fn verify_current(
    administrator: &Administrator,
    username: &str,
    password: &str,
) -> Result<(), Error> {
    match administrator.verify(username, password).await {
        Err(Error::Password(crate::password::Error::Password(_))) => Err(Error::CurrentPassword),
        result => result,
    }
}

fn subscription_prefix(config: &AppConfig) -> Result<String, Error> {
    let written = config
        .subscription
        .as_ref()
        .and_then(|subscription| subscription.prefix.as_deref())
        .unwrap_or(DEFAULT_PREFIX);
    validate_prefix(written)
}

fn validate_prefix(written: &str) -> Result<String, Error> {
    let prefix = written.trim_matches('/');
    if prefix.is_empty()
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(Error::Prefix {
            reason: "use one URL segment with letters, digits, hyphens or underscores",
        });
    }
    if prefix.eq_ignore_ascii_case("api") || prefix.eq_ignore_ascii_case("assets") {
        return Err(Error::Prefix {
            reason: "this path is reserved",
        });
    }
    Ok(prefix.to_string())
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
    async fn github_credentials_only_authorize_the_https_api_origin() {
        let dir = test_dir();
        let store = SettingsStore::load(&dir).unwrap();
        store
            .update_instance_settings(None, Some(Some("fixture-token".to_owned())), None)
            .await
            .unwrap();
        let store = SettingsStore::load(&dir).unwrap();
        tokio::fs::remove_dir_all(dir).await.unwrap();
        let client = Client::new();
        let api = "https://api.github.com/repos/example/project/releases";
        let github = store.github().await;
        let authenticated = github.metadata_request(&client, api).build().unwrap();
        let bearer = &authenticated.headers()[reqwest::header::AUTHORIZATION];
        assert!(bearer.is_sensitive());
        assert_eq!(bearer, "Bearer fixture-token");

        for url in [
            "https://github.com/example/project/releases/download/v1/fixture",
            "https://api.github.com.example.com/releases",
            "https://api.github.com:8443/releases",
            "http://api.github.com/releases",
        ] {
            let request = github.metadata_request(&client, url).build().unwrap();
            assert!(!request
                .headers()
                .contains_key(reqwest::header::AUTHORIZATION));
        }
        let subscription = client
            .get("https://example.com/subscription")
            .build()
            .unwrap();
        assert!(!subscription
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION));
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
