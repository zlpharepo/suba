//! Direct peer trust is separate from administrator sessions and remote data.
//!
//! Only public identities and connection addresses persist. Invitations and
//! replay challenges expire in memory; restarting invalidates them. A peer
//! proof authorizes a bounded resource router, never login or further delegation.

mod identity;
mod transport;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::persisted::Persisted;
use crate::error::Error;
use hmac::{KeyInit, Mac};
pub(crate) use identity::{Identity, IdentitySigner, Signed};
pub(crate) use transport::resource_allowed;

#[derive(Clone)]
pub(crate) struct PeerGrant {
    actor: Identity,
}

pub(crate) const BODY_LIMIT: usize = 2 * 1024 * 1024;
pub(crate) const REPLY_LIMIT: usize = 16 * 1024 * 1024;
const INVITE_TTL: Duration = Duration::from_secs(600);
const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const PENDING_LIMIT: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Host {
    pub id: Uuid,
    pub name: String,
    pub endpoint: String,
    pub identity: Identity,
    pub mode: Mode,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    Direct,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct TrustedPeer {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
}

impl TrustedPeer {
    fn identity(&self) -> Identity {
        Identity {
            id: self.id,
            public_key: self.public_key.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Configuration {
    #[serde(default)]
    hosts: BTreeMap<Uuid, Host>,
    #[serde(default)]
    trusted: BTreeMap<Uuid, TrustedPeer>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Invitation {
    pub version: u8,
    pub id: Uuid,
    pub endpoint: String,
    pub identity: Identity,
    pub secret: String,
    pub expires_at: i64,
}

struct PendingInvitation {
    name: String,
    secret: String,
    until: Instant,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Purpose {
    Pair,
    Request,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Challenge {
    pub nonce: String,
    pub actor: Identity,
    pub target: Identity,
    pub purpose: Purpose,
    pub expires_at: i64,
}

struct PendingChallenge {
    challenge: Challenge,
    invitation: Option<Uuid>,
    until: Instant,
}

#[derive(Default)]
struct Pending {
    invitations: BTreeMap<Uuid, PendingInvitation>,
    challenges: BTreeMap<String, PendingChallenge>,
}

impl Pending {
    fn prune(&mut self) {
        let now = Instant::now();
        self.invitations.retain(|_, value| value.until > now);
        self.challenges.retain(|_, value| value.until > now);
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ChallengeRequest {
    pub actor: Identity,
    pub invitation: Option<Uuid>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PairClaim {
    pub challenge: Challenge,
    pub invitation_proof: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct PairReceipt {
    pub nonce: String,
    pub actor: Uuid,
    pub target: Identity,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ResourceRequest {
    pub challenge: Challenge,
    pub method: String,
    pub path: String,
    pub if_match: Option<String>,
    pub body: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ResourceReply {
    pub nonce: String,
    pub actor: Uuid,
    pub target: Uuid,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub(crate) struct Peers {
    file: Persisted<Configuration>,
    pending: Mutex<Pending>,
    http: reqwest::Client,
}

impl Peers {
    pub(crate) fn load(config: &Path) -> Result<Self, Error> {
        Ok(Self {
            file: Persisted::load(config, "peers")?,
            pending: Mutex::new(Pending::default()),
            // Control must not depend on environment proxy settings or follow redirects with proofs.
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(30))
                .build()?,
        })
    }

    pub(crate) async fn hosts(&self) -> Vec<Host> {
        self.file
            .read(|file| file.hosts.values().cloned().collect())
            .await
    }

    pub(crate) async fn trusted(&self) -> Vec<TrustedPeer> {
        self.file
            .read(|file| file.trusted.values().cloned().collect())
            .await
    }

    pub(crate) async fn host(&self, id: Uuid) -> Result<Host, Error> {
        self.file
            .read(|file| file.hosts.get(&id).cloned())
            .await
            .ok_or(Error::PeerNotFound)
    }

    pub(crate) async fn update_host(
        &self,
        id: Uuid,
        name: String,
        url: String,
    ) -> Result<Host, Error> {
        valid_name(&name)?;
        let endpoint = endpoint(&url)?;
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let host = file.hosts.get_mut(&id).ok_or(Error::PeerNotFound)?;
        host.name = name;
        host.endpoint = endpoint;
        let result = host.clone();
        locked.commit(file).await?;
        Ok(result)
    }

    pub(crate) async fn remove_host(&self, id: Uuid) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        file.hosts.remove(&id).ok_or(Error::PeerNotFound)?;
        Ok(locked.commit(file).await?)
    }

    pub(crate) async fn revoke(&self, id: Uuid) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        file.trusted.remove(&id).ok_or(Error::PeerNotFound)?;
        Ok(locked.commit(file).await?)
    }

    pub(crate) async fn invite(
        &self,
        signer: &IdentitySigner,
        name: String,
        url: String,
    ) -> Result<Invitation, Error> {
        valid_name(&name)?;
        let endpoint = endpoint(&url)?;
        let mut pending = self.pending.lock().await;
        pending.prune();
        if pending.invitations.len() >= PENDING_LIMIT {
            return Err(Error::PeerBusy);
        }
        let id = Uuid::now_v7();
        let secret = random()?;
        let expires_at = chrono::Utc::now().timestamp() + INVITE_TTL.as_secs() as i64;
        pending.invitations.insert(
            id,
            PendingInvitation {
                name,
                secret: secret.clone(),
                until: Instant::now() + INVITE_TTL,
            },
        );
        Ok(Invitation {
            version: 1,
            id,
            endpoint,
            identity: signer.identity.clone(),
            secret,
            expires_at,
        })
    }

    pub(crate) async fn revoke_invitation(&self, id: Uuid) {
        self.pending.lock().await.invitations.remove(&id);
    }

    pub(crate) async fn challenge(
        &self,
        signer: &IdentitySigner,
        request: ChallengeRequest,
    ) -> Result<Signed<Challenge>, Error> {
        request.actor.key()?;
        if request.actor.id == signer.identity.id
            || request.actor.fingerprint == signer.identity.fingerprint
        {
            return Err(Error::Unauthorized);
        }
        let mut pending = self.pending.lock().await;
        pending.prune();
        let (purpose, invitation) = if let Some(invitation) = request.invitation {
            pending
                .invitations
                .get(&invitation)
                .ok_or(Error::Unauthorized)?;
            (Purpose::Pair, Some(invitation))
        } else {
            self.require_trusted(&request.actor).await?;
            (Purpose::Request, None)
        };
        if pending.challenges.len() >= PENDING_LIMIT {
            return Err(Error::PeerBusy);
        }
        let challenge = Challenge {
            nonce: random()?,
            actor: request.actor,
            target: signer.identity.clone(),
            purpose,
            expires_at: chrono::Utc::now().timestamp() + CHALLENGE_TTL.as_secs() as i64,
        };
        pending.challenges.insert(
            challenge.nonce.clone(),
            PendingChallenge {
                challenge: challenge.clone(),
                invitation,
                until: Instant::now() + CHALLENGE_TTL,
            },
        );
        signer.sign("challenge", challenge)
    }

    pub(crate) async fn accept(
        &self,
        signer: &IdentitySigner,
        proof: Signed<PairClaim>,
    ) -> Result<Signed<PairReceipt>, Error> {
        proof.verify("pair", &proof.payload.challenge.actor)?;
        let challenge = proof.payload.challenge;
        let mut pending = self.pending.lock().await;
        let held = consume(&mut pending, &challenge, &signer.identity, Purpose::Pair)?;
        let invitation_id = held.invitation.ok_or(Error::Unauthorized)?;
        let invitation = pending
            .invitations
            .get(&invitation_id)
            .ok_or(Error::Unauthorized)?;
        verify_invitation(
            &invitation.secret,
            &challenge,
            &proof.payload.invitation_proof,
        )?;
        let actor = &challenge.actor;
        let trusted = TrustedPeer {
            id: actor.id,
            name: invitation.name.clone(),
            public_key: actor.public_key.clone(),
            fingerprint: actor.fingerprint.clone(),
        };
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        file.trusted.insert(actor.id, trusted);
        locked.commit(file).await?;
        pending.invitations.remove(&invitation_id);
        signer.sign(
            "paired",
            PairReceipt {
                nonce: challenge.nonce,
                actor: actor.id,
                target: signer.identity.clone(),
            },
        )
    }

    pub(crate) async fn authorize(
        &self,
        signer: &IdentitySigner,
        proof: &Signed<ResourceRequest>,
    ) -> Result<PeerGrant, Error> {
        proof.verify("request", &proof.payload.challenge.actor)?;
        let mut pending = self.pending.lock().await;
        consume(
            &mut pending,
            &proof.payload.challenge,
            &signer.identity,
            Purpose::Request,
        )?;
        self.require_trusted(&proof.payload.challenge.actor).await?;
        Ok(PeerGrant {
            actor: proof.payload.challenge.actor.clone(),
        })
    }

    pub(crate) async fn allows(&self, grant: &PeerGrant) -> Result<(), Error> {
        self.require_trusted(&grant.actor).await
    }

    async fn require_trusted(&self, actor: &Identity) -> Result<(), Error> {
        let trusted = self
            .file
            .read(|file| file.trusted.get(&actor.id).map(TrustedPeer::identity))
            .await;
        if trusted.as_ref() != Some(actor) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

fn consume(
    pending: &mut Pending,
    challenge: &Challenge,
    target: &Identity,
    purpose: Purpose,
) -> Result<PendingChallenge, Error> {
    pending.prune();
    let held = pending
        .challenges
        .get(&challenge.nonce)
        .ok_or(Error::Unauthorized)?;
    if held.challenge != *challenge || &challenge.target != target || challenge.purpose != purpose {
        return Err(Error::Unauthorized);
    }
    pending
        .challenges
        .remove(&challenge.nonce)
        .ok_or(Error::Unauthorized)
}

fn valid_name(name: &str) -> Result<(), Error> {
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err(Error::PeerRequest {
            reason: "name: use 1 to 128 bytes without control characters",
        });
    }
    Ok(())
}

pub(crate) fn endpoint(value: &str) -> Result<String, Error> {
    let invalid = || {
        Error::PeerRequest { reason: "endpoint: use HTTPS, without credentials, query or fragment; HTTP is only allowed for a loopback IP" }
    };
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
        || value.len() > 2048
    {
        return Err(invalid());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn invitation_mac(secret: &str, challenge: &Challenge) -> Result<hmac::Hmac<sha2::Sha256>, Error> {
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| Error::Unauthorized)?;
    let bytes = serde_json::to_vec(&("suba-peer-invitation-v1", challenge))
        .map_err(|_| Error::Unauthorized)?;
    mac.update(&bytes);
    Ok(mac)
}

fn invitation_proof(secret: &str, challenge: &Challenge) -> Result<String, Error> {
    Ok(identity::hex(
        &invitation_mac(secret, challenge)?.finalize().into_bytes(),
    ))
}

fn verify_invitation(secret: &str, challenge: &Challenge, proof: &str) -> Result<(), Error> {
    if proof.len() != 64 {
        return Err(Error::Unauthorized);
    }
    let mut bytes = [0; 32];
    for (byte, pair) in bytes
        .iter_mut()
        .zip(proof.as_bytes().as_chunks::<2>().0.iter())
    {
        *byte = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| Error::Unauthorized)?,
            16,
        )
        .map_err(|_| Error::Unauthorized)?;
    }
    invitation_mac(secret, challenge)?
        .verify_slice(&bytes)
        .map_err(|_| Error::Unauthorized)
}

fn random() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| Error::Entropy("peer randomness unavailable".into()))?;
    Ok(identity::hex(&bytes))
}

#[cfg(test)]
mod tests;
