//! Proxy users, the inbounds they may use, and the addresses clients dial.
//!
//! A user is a proxy identity, not a login: a name, the inbounds it may use,
//! the collections added to its subscription, the links that hand that
//! subscription out, and one secret. An inbound is named by its configuration
//! and tag.
//!
//! **One secret per user, one credential per inbound.** Every credential a
//! user has is derived from its secret and the inbound it is for (HMAC-SHA256),
//! so exposing one inbound's credential does not reveal another's. Changes
//! to grants persist their relationships without storing derived credentials.
//! A new secret replaces all of a user's credentials at once.
//!
//! **Addresses live beside the identity, not in the core's document.** sing-box
//! refuses a field it does not know, so the address a client dials is kept here
//! per configuration and inbound tag, and exported on the way out.

use std::collections::BTreeMap;
use std::path::Path;

use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use suba_core::checksum::sha256_hex;
use uuid::Uuid;

use crate::{config::ConfigError, error::Error};

use super::collections::{mint, token_name};
use super::persisted::Persisted;

pub(crate) const USERS_BASENAME: &str = "users";
pub(crate) const ENDPOINTS_BASENAME: &str = "endpoints";

/// The longest user name: it is the user name every server logs.
const NAME_MAX: usize = 32;
const SECRET_BYTES: usize = 32;

/// Every user, by name.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct UsersConfig {
    #[serde(flatten)]
    pub users: BTreeMap<String, User>,
}

/// One proxy identity.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct User {
    /// Inbounds this user may use, each named by configuration and tag.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<Entry>,
    /// Added to the user's subscription after its own servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collections: Vec<String>,
    /// Subscription link name to token.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tokens: BTreeMap<String, String>,
    /// Hex: what every credential of this user derives from.
    #[serde(default)]
    pub secret: String,
}

/// The address clients dial for one inbound, when the operator sets one.
///
/// Both halves are optional: an address without a port keeps the inbound's own
/// `listen_port`, and a port alone reuses the host it would otherwise inherit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl Endpoint {
    fn is_empty(&self) -> bool {
        self.address.is_none() && self.port.is_none()
    }
}

/// Every address override, by configuration and then inbound tag.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EndpointsConfig {
    #[serde(flatten)]
    pub configs: BTreeMap<String, BTreeMap<String, Endpoint>>,
}

/// One inbound a user may use: its tag, in one named configuration.
///
/// `host` is the instance that runs that inbound. An absent one is this
/// instance, which is what a file that never mentioned a host means and what a
/// host's own copy of a mirrored entry holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Uuid>,
    pub config: String,
    pub inbound: String,
}

impl Entry {
    /// One of this instance's own inbounds, which is what an address lookup and
    /// a plan over the local document are keyed by.
    pub(crate) fn local(config: &str, inbound: &str) -> Self {
        Self {
            host: None,
            config: config.to_owned(),
            inbound: inbound.to_owned(),
        }
    }
}

/// Users and addresses as one consistent picture, taken before any lock that
/// cannot wait for them.
#[derive(Clone, Default)]
pub(crate) struct Access {
    pub users: BTreeMap<String, User>,
    pub endpoints: BTreeMap<String, BTreeMap<String, Endpoint>>,
}

/// One inbound one user may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub user: String,
    pub entry: Entry,
}

impl Access {
    /// Every grant, user by user, each inbound once and in its listed order.
    pub(crate) fn grants(&self) -> Vec<Grant> {
        self.users
            .iter()
            .flat_map(|(name, user)| self.grants_of(name, user))
            .collect()
    }

    pub(crate) fn grants_of(&self, name: &str, user: &User) -> Vec<Grant> {
        let mut grants: Vec<Grant> = Vec::new();

        for entry in &user.inbounds {
            // A repeated entry grants nothing more, so it is collapsed here
            // rather than being exported twice.
            if grants.iter().any(|grant| &grant.entry == entry) {
                continue;
            }
            grants.push(Grant {
                user: name.to_owned(),
                entry: entry.clone(),
            });
        }

        grants
    }

    /// The address override for one inbound, when the operator set one.
    pub(crate) fn endpoint(&self, entry: &Entry) -> Option<&Endpoint> {
        self.endpoints
            .get(&entry.config)
            .and_then(|inbounds| inbounds.get(&entry.inbound))
    }

    /// The key material of one user's credential for one inbound.
    ///
    /// `None` for a user that does not exist or whose secret is not one.
    pub(crate) fn material(&self, user: &str, entry: &Entry) -> Option<[u8; 32]> {
        let secret = decode_hex(&self.users.get(user)?.secret)?;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&secret).ok()?;
        // Configuration names cannot contain NUL, making this separator unambiguous.
        mac.update(entry.config.as_bytes());
        mac.update(&[0]);
        mac.update(entry.inbound.as_bytes());

        Some(mac.finalize().into_bytes().into())
    }
}

/// The users and addresses of the instance.
pub(crate) struct AccessStore {
    users: Persisted<UsersConfig>,
    endpoints: Persisted<EndpointsConfig>,
}

impl AccessStore {
    pub(crate) fn load(config_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            users: Persisted::load(config_dir, USERS_BASENAME)?,
            endpoints: Persisted::load(config_dir, ENDPOINTS_BASENAME)?,
        })
    }

    pub(crate) async fn snapshot(&self) -> Access {
        Access {
            users: self.users.read(|config| config.users.clone()).await,
            endpoints: self.endpoints.read(|config| config.configs.clone()).await,
        }
    }

    /// Store which inbounds and collections a user has; a new user gets a secret.
    ///
    /// The secret and the links stay as they are: neither is something a form
    /// can name, and replacing either is its own request.
    pub(crate) async fn put_user(
        &self,
        name: &str,
        inbounds: Vec<Entry>,
        collections: Vec<String>,
    ) -> Result<(), Error> {
        user_name(name)?;
        for (index, entry) in inbounds.iter().enumerate() {
            crate::state::singbox::config_name(&entry.config).map_err(|_| {
                Error::Document(format!(
                    "inbounds[{index}].config: not a configuration name"
                ))
            })?;
            if entry.inbound.is_empty() {
                return Err(Error::Document(format!(
                    "inbounds[{index}].inbound: an inbound is named by its tag"
                )));
            }
        }

        let locked = self.users.lock().await;
        let mut config = locked.get().clone();
        let user = match config.users.remove(name) {
            Some(user) => user,
            None => User {
                secret: secret()?,
                ..User::default()
            },
        };
        config.users.insert(
            name.to_owned(),
            User {
                inbounds,
                collections,
                ..user
            },
        );
        locked.commit(config).await?;

        Ok(())
    }

    pub(crate) async fn remove_user(&self, name: &str) -> Result<(), Error> {
        let locked = self.users.lock().await;
        let mut config = locked.get().clone();
        if config.users.remove(name).is_some() {
            locked.commit(config).await?;
        }

        Ok(())
    }

    /// Replace every credential of a user at once; its links stay.
    pub(crate) async fn renew_secret(&self, name: &str) -> Result<(), Error> {
        let locked = self.users.lock().await;
        let mut config = locked.get().clone();
        config
            .users
            .get_mut(name)
            .ok_or_else(|| Error::UserNotFound(name.to_owned()))?
            .secret = secret()?;
        locked.commit(config).await?;

        Ok(())
    }

    /// Give a user a subscription link called `label`; an existing one is
    /// replaced, which is how a leaked link is taken out of service.
    pub(crate) async fn mint_token(&self, name: &str, label: &str) -> Result<String, Error> {
        token_name(label)?;
        let token = mint()?;

        let locked = self.users.lock().await;
        let mut config = locked.get().clone();
        config
            .users
            .get_mut(name)
            .ok_or_else(|| Error::UserNotFound(name.to_owned()))?
            .tokens
            .insert(label.to_owned(), token.clone());
        locked.commit(config).await?;

        Ok(token)
    }

    pub(crate) async fn revoke_token(&self, name: &str, label: &str) -> Result<(), Error> {
        let locked = self.users.lock().await;
        let mut config = locked.get().clone();
        let user = config
            .users
            .get_mut(name)
            .ok_or_else(|| Error::UserNotFound(name.to_owned()))?;
        if user.tokens.remove(label).is_some() {
            locked.commit(config).await?;
        }

        Ok(())
    }

    /// The user a token addresses and the token's name, compared as hashes so
    /// the time taken says nothing about a guess.
    pub(crate) async fn by_token(&self, token: &str) -> Option<(String, String)> {
        let hash = sha256_hex(token.as_bytes());

        self.users
            .read(|config| {
                config.users.iter().find_map(|(name, user)| {
                    user.tokens
                        .iter()
                        .find(|(_, held)| sha256_hex(held.as_bytes()) == hash)
                        .map(|(label, _)| (name.clone(), label.clone()))
                })
            })
            .await
    }

    /// Store, replace or clear the address override of one inbound.
    ///
    /// Clearing both halves removes the entry rather than keeping an empty one,
    /// so an override that says nothing is not mistaken for one that does.
    pub(crate) async fn put_endpoint(
        &self,
        config: &str,
        inbound: &str,
        endpoint: Endpoint,
    ) -> Result<(), Error> {
        crate::state::singbox::config_name(config)
            .map_err(|_| Error::Document("config: not a configuration name".to_string()))?;
        if inbound.is_empty() {
            return Err(Error::Document(
                "inbound: an inbound is named by its tag".to_string(),
            ));
        }
        if let Some(address) = &endpoint.address {
            endpoint_host(address)?;
        }

        let locked = self.endpoints.lock().await;
        let mut config_file = locked.get().clone();
        let inbounds = config_file.configs.entry(config.to_owned()).or_default();
        if endpoint.is_empty() {
            inbounds.remove(inbound);
        } else {
            inbounds.insert(inbound.to_owned(), endpoint);
        }
        if inbounds.is_empty() {
            config_file.configs.remove(config);
        }
        locked.commit(config_file).await?;

        Ok(())
    }

    pub(crate) async fn remove_endpoint(&self, config: &str, inbound: &str) -> Result<(), Error> {
        let locked = self.endpoints.lock().await;
        let mut config_file = locked.get().clone();
        let mut changed = false;
        if let Some(inbounds) = config_file.configs.get_mut(config) {
            changed = inbounds.remove(inbound).is_some();
            if inbounds.is_empty() {
                config_file.configs.remove(config);
            }
        }
        if changed {
            locked.commit(config_file).await?;
        }

        Ok(())
    }
}

/// A dialed address is a host or an IP literal, and nothing else: no scheme, no
/// port, no path. The port is stored apart from it, so the two cannot disagree.
fn endpoint_host(address: &str) -> Result<(), Error> {
    let reason = |reason: &'static str| Error::Document(format!("address: {reason}"));
    let trimmed = address.trim();
    if trimmed.is_empty() || trimmed.len() > 253 || trimmed != address {
        return Err(reason("expected a host name or IP address"));
    }
    if trimmed
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
        || trimmed.contains(['/', '?', '#', '@', '\\'])
    {
        return Err(reason(
            "expected a host name or IP address without a scheme, port or path",
        ));
    }
    // A bare IPv4, or a bracketed IPv6 literal, or a name of labels. A colon
    // anywhere else would be a port, which is stored apart from the address.
    if trimmed.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| reason("expected a bracketed IPv6 address"));
    }
    if trimmed.contains(':') {
        return Err(reason(
            "expected an IPv6 address in brackets, or a name without a port",
        ));
    }
    if trimmed.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    }) {
        return Ok(());
    }

    Err(reason("expected a host name or IP address"))
}

fn secret() -> Result<String, Error> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| Error::Entropy(error.to_string()))?;

    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != SECRET_BYTES * 2 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}

/// A user name is what every server logs and what `auth_user` matches, so it
/// is kept to what reads the same in a log line, a URL and a route rule.
fn user_name(name: &str) -> Result<(), Error> {
    match plain(name, NAME_MAX) {
        true => Ok(()),
        false => Err(Error::AccessName {
            reason: "a user name is 1 to 32 letters, digits, '.', '_' or '-'",
        }),
    }
}

fn plain(name: &str, longest: usize) -> bool {
    !name.is_empty()
        && name.len() <= longest
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{config_path, read_config};

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!("suba-access-{}", uuid::Uuid::now_v7()))
    }

    fn entry(config: &str, inbound: &str) -> Entry {
        Entry::local(config, inbound)
    }

    /// The host an entry belongs to is stored and read back in both
    /// configuration formats, and left out when it is this instance's own.
    #[tokio::test]
    async fn an_entry_says_which_host_runs_it_and_an_absent_one_is_this_instance() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        let elsewhere = Uuid::now_v7();

        store
            .put_user(
                "alice",
                vec![
                    entry("server", "vless-in"),
                    Entry {
                        host: Some(elsewhere),
                        config: "server".to_string(),
                        inbound: "vless-in".to_string(),
                    },
                ],
                Vec::new(),
            )
            .await
            .unwrap();

        let reloaded = AccessStore::load(&dir).unwrap().snapshot().await;
        assert_eq!(
            reloaded.users["alice"].inbounds,
            vec![
                Entry::local("server", "vless-in"),
                Entry {
                    host: Some(elsewhere),
                    config: "server".to_string(),
                    inbound: "vless-in".to_string(),
                },
            ]
        );

        let written = read_config::<UsersConfig>(&dir.to_string_lossy(), USERS_BASENAME).unwrap();
        let encoded = serde_json::to_value(&written).unwrap();
        assert!(
            encoded["alice"]["inbounds"][0].get("host").is_none(),
            "this instance's own entry carries no host"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn users_and_addresses_live_in_files_of_their_own_and_survive_a_reload() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();

        store
            .put_user(
                "alice",
                vec![entry("server", "vless-in")],
                vec!["family".into()],
            )
            .await
            .unwrap();
        store
            .put_endpoint(
                "server",
                "vless-in",
                Endpoint {
                    address: Some("cdn.example.com".into()),
                    port: Some(443),
                },
            )
            .await
            .unwrap();

        assert!(config_path(&dir, USERS_BASENAME).is_file());
        assert!(config_path(&dir, ENDPOINTS_BASENAME).is_file());

        let reloaded = AccessStore::load(&dir).unwrap().snapshot().await;
        assert_eq!(
            reloaded.users["alice"].inbounds,
            [entry("server", "vless-in")]
        );
        assert_eq!(reloaded.users["alice"].collections, ["family"]);
        assert_eq!(reloaded.users["alice"].secret.len(), 64);
        assert_eq!(
            reloaded.endpoint(&entry("server", "vless-in")),
            Some(&Endpoint {
                address: Some("cdn.example.com".into()),
                port: Some(443)
            })
        );

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn saving_a_user_keeps_its_secret_and_links() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        store
            .put_user("alice", vec![entry("server", "a")], vec![])
            .await
            .unwrap();
        store.mint_token("alice", "phone").await.unwrap();
        let secret = store.snapshot().await.users["alice"].secret.clone();

        // Changing the inbounds a user may use must not rotate an identity.
        store
            .put_user("alice", vec![entry("server", "b")], vec![])
            .await
            .unwrap();

        let user = store.snapshot().await.users["alice"].clone();
        assert_eq!(user.secret, secret);
        assert_eq!(user.inbounds, [entry("server", "b")]);
        assert!(user.tokens.contains_key("phone"));

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_credential_is_one_per_inbound_and_a_new_secret_replaces_them_all() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        store
            .put_user(
                "alice",
                vec![entry("server", "a"), entry("server", "b")],
                vec![],
            )
            .await
            .unwrap();

        let access = store.snapshot().await;
        let first = access.material("alice", &entry("server", "a")).unwrap();
        let second = access.material("alice", &entry("server", "b")).unwrap();
        assert_ne!(first, second, "one inbound's credential is not another's");
        assert_eq!(access.material("bob", &entry("server", "a")), None);

        store.renew_secret("alice").await.unwrap();
        let renewed = store.snapshot().await;
        assert_ne!(
            renewed.material("alice", &entry("server", "a")),
            Some(first)
        );
        assert_ne!(
            renewed.material("alice", &entry("server", "b")),
            Some(second)
        );

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_user_lists_each_inbound_once_in_the_order_it_was_given() {
        let access = Access {
            users: BTreeMap::from([(
                "alice".to_string(),
                User {
                    inbounds: vec![
                        entry("server", "b"),
                        entry("other", "a"),
                        entry("server", "b"),
                    ],
                    ..User::default()
                },
            )]),
            ..Access::default()
        };

        let granted: Vec<_> = access
            .grants_of("alice", &access.users["alice"])
            .into_iter()
            .map(|grant| (grant.entry.config, grant.entry.inbound))
            .collect();
        assert_eq!(
            granted,
            [
                ("server".to_string(), "b".to_string()),
                ("other".to_string(), "a".to_string())
            ],
            "a repeated entry is one grant"
        );
    }

    #[tokio::test]
    async fn an_address_override_is_stored_cleared_and_validated() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        let entry = entry("server", "vless-in");

        // Name, IPv4 and bracketed IPv6 are acceptable; anything with a scheme,
        // port, path or credentials is not.
        for address in ["cdn.example.com", "192.0.2.10", "[2001:db8::1]"] {
            store
                .put_endpoint(
                    "server",
                    "vless-in",
                    Endpoint {
                        address: Some(address.to_string()),
                        port: None,
                    },
                )
                .await
                .unwrap();
        }
        for address in [
            "https://cdn.example.com",
            "cdn.example.com:443",
            "cdn.example.com/path",
            "user@cdn.example.com",
            "cdn.example.com?token=example",
            " ",
            "cdn example.com",
            "2001:db8::1",
        ] {
            assert!(
                store
                    .put_endpoint(
                        "server",
                        "vless-in",
                        Endpoint {
                            address: Some(address.to_string()),
                            port: None
                        }
                    )
                    .await
                    .is_err(),
                "{address:?} was accepted as an address"
            );
        }

        // A port alone is an override in its own right, and clearing both
        // removes the entry rather than leaving an empty one.
        store
            .put_endpoint(
                "server",
                "vless-in",
                Endpoint {
                    address: None,
                    port: Some(8443),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            store.snapshot().await.endpoint(&entry),
            Some(&Endpoint {
                address: None,
                port: Some(8443)
            })
        );
        store
            .put_endpoint("server", "vless-in", Endpoint::default())
            .await
            .unwrap();
        assert_eq!(store.snapshot().await.endpoint(&entry), None);
        assert!(
            read_config::<EndpointsConfig>(dir.to_str().unwrap(), ENDPOINTS_BASENAME)
                .unwrap()
                .configs
                .is_empty(),
            "an emptied override does not leave a configuration behind"
        );

        store
            .put_endpoint(
                "server",
                "vless-in",
                Endpoint {
                    address: Some("cdn.example.com".into()),
                    port: None,
                },
            )
            .await
            .unwrap();
        store.remove_endpoint("server", "vless-in").await.unwrap();
        assert_eq!(store.snapshot().await.endpoint(&entry), None);
        // Removing what is not there is not an error: the caller asked for it.
        store.remove_endpoint("server", "vless-in").await.unwrap();

        assert!(store
            .put_endpoint("a/b", "vless-in", Endpoint::default())
            .await
            .is_err());
        assert!(store
            .put_endpoint("server", "", Endpoint::default())
            .await
            .is_err());

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_user_name_is_kept_to_what_reads_the_same_everywhere() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();

        let long = "x".repeat(32);
        for name in ["alice", "a.b_c-1", long.as_str()] {
            store.put_user(name, vec![], vec![]).await.unwrap();
        }
        let too_long = "x".repeat(33);
        for name in ["", too_long.as_str(), "a b", "alice/1", "zoë"] {
            assert!(
                store.put_user(name, vec![], vec![]).await.is_err(),
                "{name:?} was accepted as a user name"
            );
        }

        let listed = store.snapshot().await;
        assert_eq!(listed.users.len(), 3);

        store.remove_user("alice").await.unwrap();
        assert!(!store.snapshot().await.users.contains_key("alice"));

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_token_addresses_the_user_that_holds_it() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        store
            .put_user("alice", vec![entry("server", "a")], vec![])
            .await
            .unwrap();
        let token = store.mint_token("alice", "phone").await.unwrap();

        assert_eq!(
            store.by_token(&token).await,
            Some(("alice".to_string(), "phone".to_string()))
        );
        assert_eq!(store.by_token("not-a-token").await, None);

        store.revoke_token("alice", "phone").await.unwrap();
        assert_eq!(store.by_token(&token).await, None);

        let _ = tokio::fs::remove_dir_all(dir).await;
    }
}
