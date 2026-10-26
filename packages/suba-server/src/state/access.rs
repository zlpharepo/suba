//! Proxy users and the pools that grant them servers.
//!
//! A user is a proxy identity, not a login: a name, the pools that say which
//! inbounds it may use, the collections added to its subscription, the links
//! that hand that subscription out, and one secret. A pool is a list of
//! inbounds, each named by configuration and tag.
//!
//! **One secret per user, one credential per inbound.** Every credential a
//! user has is derived from its secret and the inbound it is for (HMAC-SHA256),
//! so exposing one inbound's credential does not reveal another's. Changes
//! to grants persist their relationships without storing derived credentials.
//! A new secret replaces all of a user's credentials at once.
//!
//! Like a collection naming a provider, a user naming a pool that does not
//! exist is stored anyway and reported when it is resolved; the order two
//! documents are written in is not something an operator should have to plan.

use std::collections::BTreeMap;
use std::path::Path;

use hmac::{KeyInit, Mac};
use serde::{Deserialize, Serialize};
use suba_core::checksum::sha256_hex;

use crate::{config::ConfigError, error::Error};

use super::collections::{mint, token_name};
use super::persisted::Persisted;

pub(crate) const USERS_BASENAME: &str = "users";
pub(crate) const POOLS_BASENAME: &str = "pools";

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<String>,
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

/// Every pool, by name.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PoolsConfig {
    #[serde(flatten)]
    pub pools: BTreeMap<String, Pool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pool {
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// One inbound a pool grants: its tag, in one named configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Entry {
    pub config: String,
    pub inbound: String,
}

/// Users and pools as one consistent picture, taken before any lock that
/// cannot wait for them.
#[derive(Clone, Default)]
pub(crate) struct Access {
    pub users: BTreeMap<String, User>,
    pub pools: BTreeMap<String, Pool>,
}

/// One inbound one user may use, and the pools that say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Grant {
    pub user: String,
    pub entry: Entry,
    pub via: Vec<String>,
}

impl Access {
    /// Every grant, user by user, each inbound once and in pool order.
    pub(crate) fn grants(&self) -> Vec<Grant> {
        self.users
            .iter()
            .flat_map(|(name, user)| self.grants_of(name, user))
            .collect()
    }

    pub(crate) fn grants_of(&self, name: &str, user: &User) -> Vec<Grant> {
        let mut grants: Vec<Grant> = Vec::new();

        for pool in &user.pools {
            for entry in self.pools.get(pool).map_or(&[][..], |pool| &pool.entries) {
                match grants.iter_mut().find(|grant| &grant.entry == entry) {
                    Some(grant) => grant.via.push(pool.clone()),
                    None => grants.push(Grant {
                        user: name.to_owned(),
                        entry: entry.clone(),
                        via: vec![pool.clone()],
                    }),
                }
            }
        }

        grants
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

/// The users and pools of the instance.
pub(crate) struct AccessStore {
    users: Persisted<UsersConfig>,
    pools: Persisted<PoolsConfig>,
}

impl AccessStore {
    pub(crate) fn load(config_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            users: Persisted::load(config_dir, USERS_BASENAME)?,
            pools: Persisted::load(config_dir, POOLS_BASENAME)?,
        })
    }

    pub(crate) async fn snapshot(&self) -> Access {
        Access {
            users: self.users.read(|config| config.users.clone()).await,
            pools: self.pools.read(|config| config.pools.clone()).await,
        }
    }

    /// Store which pools and collections a user has; a new user gets a secret.
    ///
    /// The secret and the links stay as they are: neither is something a form
    /// can name, and replacing either is its own request.
    pub(crate) async fn put_user(
        &self,
        name: &str,
        pools: Vec<String>,
        collections: Vec<String>,
    ) -> Result<(), Error> {
        user_name(name)?;

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
                pools,
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

    pub(crate) async fn put_pool(&self, name: &str, pool: Pool) -> Result<(), Error> {
        pool_name(name)?;
        for (index, entry) in pool.entries.iter().enumerate() {
            crate::state::singbox::config_name(&entry.config).map_err(|_| {
                Error::Document(format!("entries[{index}].config: not a configuration name"))
            })?;
            if entry.inbound.is_empty() {
                return Err(Error::Document(format!(
                    "entries[{index}].inbound: an inbound is named by its tag"
                )));
            }
            if pool.entries[..index].contains(entry) {
                return Err(Error::Document(format!(
                    "entries[{index}]: already in this pool"
                )));
            }
        }

        let locked = self.pools.lock().await;
        let mut config = locked.get().clone();
        config.pools.insert(name.to_owned(), pool);
        locked.commit(config).await?;

        Ok(())
    }

    pub(crate) async fn remove_pool(&self, name: &str) -> Result<(), Error> {
        let locked = self.pools.lock().await;
        let mut config = locked.get().clone();
        if config.pools.remove(name).is_some() {
            locked.commit(config).await?;
        }

        Ok(())
    }
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

fn pool_name(name: &str) -> Result<(), Error> {
    match plain(name, 64) {
        true => Ok(()),
        false => Err(Error::AccessName {
            reason: "a pool name is 1 to 64 letters, digits, '.', '_' or '-'",
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
        Entry {
            config: config.to_string(),
            inbound: inbound.to_string(),
        }
    }

    #[tokio::test]
    async fn users_and_pools_live_in_files_of_their_own_and_survive_a_reload() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();

        store
            .put_pool(
                "standard",
                Pool {
                    entries: vec![entry("server", "vless-in")],
                },
            )
            .await
            .unwrap();
        store
            .put_user("alice", vec!["standard".into()], vec!["family".into()])
            .await
            .unwrap();

        assert!(config_path(&dir, USERS_BASENAME).is_file());
        assert!(config_path(&dir, POOLS_BASENAME).is_file());

        let reloaded = AccessStore::load(&dir).unwrap().snapshot().await;
        assert_eq!(reloaded.users["alice"].pools, ["standard"]);
        assert_eq!(reloaded.users["alice"].collections, ["family"]);
        assert_eq!(reloaded.users["alice"].secret.len(), 64);
        assert_eq!(
            reloaded.pools["standard"].entries,
            [entry("server", "vless-in")]
        );

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn saving_a_user_keeps_its_secret_and_links() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        store.put_user("alice", vec![], vec![]).await.unwrap();
        let token = store.mint_token("alice", "phone").await.unwrap();
        let secret = store.snapshot().await.users["alice"].secret.clone();

        store
            .put_user("alice", vec!["standard".into()], vec![])
            .await
            .unwrap();

        let user = store.snapshot().await.users["alice"].clone();
        assert_eq!(user.secret, secret);
        assert_eq!(user.tokens["phone"], token);
        assert_eq!(
            store.by_token(&token).await,
            Some(("alice".to_string(), "phone".to_string()))
        );

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[tokio::test]
    async fn a_credential_is_one_per_inbound_and_a_new_secret_replaces_them_all() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();
        store.put_user("alice", vec![], vec![]).await.unwrap();
        store.put_user("bob", vec![], vec![]).await.unwrap();
        let first = entry("server", "vless-in");
        let second = entry("server", "trojan-in");

        let access = store.snapshot().await;
        let alice = access.material("alice", &first).unwrap();
        assert_eq!(access.material("alice", &first), Some(alice), "stable");
        assert_ne!(
            access.material("alice", &second),
            Some(alice),
            "per inbound"
        );
        assert_ne!(access.material("bob", &first), Some(alice), "per user");
        // The boundary between configuration and tag is not a place to hide one.
        assert_ne!(
            access.material("alice", &entry("serverv", "less-in")),
            Some(alice),
        );

        store.renew_secret("alice").await.unwrap();
        let renewed = store.snapshot().await;
        assert_ne!(renewed.material("alice", &first), Some(alice));
        assert_eq!(
            renewed.material("bob", &first),
            access.material("bob", &first),
            "another user's credentials stay"
        );

        let _ = tokio::fs::remove_dir_all(dir).await;
    }

    #[test]
    fn a_user_reaches_each_inbound_once_through_all_its_pools() {
        let shared = entry("server", "hy2");
        let access = Access {
            users: BTreeMap::from([(
                "bob".to_string(),
                User {
                    pools: vec!["standard".into(), "light".into(), "gone".into()],
                    ..User::default()
                },
            )]),
            pools: BTreeMap::from([
                (
                    "standard".to_string(),
                    Pool {
                        entries: vec![entry("server", "vless-in"), shared.clone()],
                    },
                ),
                (
                    "light".to_string(),
                    Pool {
                        entries: vec![shared.clone(), entry("server", "trojan-in")],
                    },
                ),
            ]),
        };

        let grants = access.grants();

        assert_eq!(
            grants
                .iter()
                .map(|grant| (grant.entry.inbound.as_str(), grant.via.join("+")))
                .collect::<Vec<_>>(),
            [
                ("vless-in", "standard".to_string()),
                ("hy2", "standard+light".to_string()),
                ("trojan-in", "light".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn names_and_entries_that_cannot_be_used_are_refused_where_they_are_written() {
        let dir = scratch();
        let store = AccessStore::load(&dir).unwrap();

        for name in ["", "a b", "a/b", &"x".repeat(33)] {
            assert!(
                matches!(
                    store.put_user(name, vec![], vec![]).await,
                    Err(Error::AccessName { .. })
                ),
                "{name:?}"
            );
        }
        for entries in [
            vec![entry("../etc", "x")],
            vec![entry("server", "")],
            vec![entry("server", "a"), entry("server", "a")],
        ] {
            assert!(matches!(
                store.put_pool("p", Pool { entries }).await,
                Err(Error::Document(_))
            ));
        }
        assert!(
            read_config::<PoolsConfig>(dir.to_str().unwrap(), POOLS_BASENAME)
                .unwrap()
                .pools
                .is_empty()
        );

        let _ = tokio::fs::remove_dir_all(dir).await;
    }
}
