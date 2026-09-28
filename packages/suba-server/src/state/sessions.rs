use std::{collections::VecDeque, path::Path};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{config::ConfigError, error::Error};

use super::persisted::Persisted;

/// How many sessions may be alive at once; the oldest is evicted to make room.
const MAX_SESSIONS: usize = 10;
const SESSION_FILE: &str = "sessions";

/// A session that was handed out to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    id: Uuid,
    exp: i64,
}

impl SessionRecord {
    /// A session lives until its expiry, as stamped by the issuer.
    fn is_expired(&self, now: i64) -> bool {
        self.exp <= now
    }
}

/// The on-disk representation of the session store, oldest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Sessions {
    sessions: VecDeque<SessionRecord>,
}

/// The sessions currently allowed to authenticate.
pub(crate) struct SessionStore {
    file: Persisted<Sessions>,
}

impl SessionStore {
    pub(crate) fn load(data_dir: &Path) -> Result<Self, ConfigError> {
        Ok(Self {
            file: Persisted::load(data_dir, SESSION_FILE)?,
        })
    }

    /// Record a new session, evicting the oldest one when full.
    pub(crate) async fn add(&self, id: Uuid, exp: i64) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let now = Utc::now().timestamp();
        let mut sessions = locked.get().clone();
        // Expired records must not occupy the bounded capacity.
        sessions.sessions.retain(|session| !session.is_expired(now));
        if sessions.sessions.len() >= MAX_SESSIONS {
            sessions.sessions.pop_front();
        }
        sessions.sessions.push_back(SessionRecord { id, exp });
        locked.commit(sessions).await?;

        Ok(())
    }

    /// Forget a session, so its token stops authenticating.
    pub(crate) async fn remove(&self, id: Uuid) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut sessions = locked.get().clone();
        sessions.sessions.retain(|session| session.id != id);
        locked.commit(sessions).await?;

        Ok(())
    }

    /// Whether `id` names a live session.
    pub(crate) async fn contains(&self, id: Uuid) -> bool {
        let now = Utc::now().timestamp();
        self.file
            .read(|sessions| {
                sessions
                    .sessions
                    .iter()
                    .any(|session| session.id == id && !session.is_expired(now))
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const HOUR: i64 = 60 * 60;

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("suba-sessions-{}", Uuid::now_v7()))
    }

    fn expired() -> i64 {
        Utc::now().timestamp() - HOUR
    }

    fn live() -> i64 {
        Utc::now().timestamp() + HOUR
    }

    #[tokio::test]
    async fn sessions_are_bounded_oldest_first() {
        let dir = test_dir();
        let store = SessionStore::load(&dir).unwrap();
        let ids: Vec<_> = (0..MAX_SESSIONS as u32).map(|_| Uuid::now_v7()).collect();

        for id in &ids {
            store.add(*id, live()).await.unwrap();
        }
        store.add(Uuid::now_v7(), live()).await.unwrap();

        assert!(
            !store.contains(ids[0]).await,
            "the oldest session is evicted"
        );
        assert!(store.contains(ids[1]).await);
        assert_eq!(
            SessionStore::load(&dir)
                .unwrap()
                .file
                .read(|sessions| sessions.sessions.len())
                .await,
            MAX_SESSIONS
        );

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn expired_sessions_do_not_authenticate() {
        let dir = test_dir();
        let store = SessionStore::load(&dir).unwrap();
        let id = Uuid::now_v7();
        store.add(id, expired()).await.unwrap();

        assert!(!store.contains(id).await);

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }

    #[tokio::test]
    async fn sessions_survive_a_reload_until_removed() {
        let dir = test_dir();
        let store = SessionStore::load(&dir).unwrap();
        let id = Uuid::now_v7();

        store.add(id, live()).await.unwrap();
        assert!(store.contains(id).await);

        let reloaded = SessionStore::load(&dir).unwrap();
        assert!(reloaded.contains(id).await);

        reloaded.remove(id).await.unwrap();
        assert!(!reloaded.contains(id).await);
        assert!(!SessionStore::load(&dir).unwrap().contains(id).await);

        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
