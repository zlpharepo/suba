//! Machine trust is separate from administrator sessions and resource ownership.
//!
//! Public identities and Direct connection addresses persist. Invitations and
//! replay challenges expire in memory; restarting invalidates them. A peer
//! proof authorizes a bounded resource router, never login or further delegation.
//! Agent identities can establish sessions but cannot operate manager resources.

pub(crate) mod agent;
mod identity;
mod transport;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use suba_core::checksum::sha256_hex;
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
    pub endpoint: Option<String>,
    pub identity: Identity,
    pub mode: Mode,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Mode {
    #[default]
    Direct,
    Agent,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AgentBinding {
    manager: Identity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_digest: Option<String>,
    // The binding is committed first, so a refused invitation cannot retire a live deployment.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    retire_deployment: bool,
}

#[derive(Serialize)]
pub(crate) struct HostView {
    #[serde(flatten)]
    pub host: Host,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<agent::AgentStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct TrustedPeer {
    pub id: Uuid,
    pub name: String,
    pub public_key: String,
    pub fingerprint: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Configuration {
    #[serde(default)]
    hosts: BTreeMap<Uuid, Host>,
    #[serde(default)]
    trusted: BTreeMap<Uuid, TrustedPeer>,
    #[serde(default)]
    agent: Option<AgentBinding>,
}

impl Configuration {
    fn is_agent_host(&self, id: &Uuid) -> bool {
        self.hosts
            .get(id)
            .is_some_and(|host| host.mode == Mode::Agent)
    }

    fn is_direct_trust(&self, id: &Uuid) -> bool {
        !self.is_agent_host(id)
            && self
                .agent
                .as_ref()
                .is_none_or(|upstream| &upstream.manager.id != id)
    }

    fn trusts(&self, actor: &Identity) -> bool {
        self.trusted.get(&actor.id).is_some_and(|peer| {
            peer.id == actor.id
                && peer.public_key == actor.public_key
                && peer.fingerprint == actor.fingerprint
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Invitation {
    pub version: u8,
    pub id: Uuid,
    pub endpoint: String,
    pub identity: Identity,
    pub secret: String,
    pub expires_at: i64,
    #[serde(default)]
    pub mode: Mode,
}

struct PendingInvitation {
    name: String,
    mode: Mode,
    secret: String,
    until: Instant,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Purpose {
    Pair,
    AgentPair,
    AgentSession,
    Request,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AgentSessionProof {
    pub challenge: Challenge,
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
    pub(crate) agent: agent::AgentHub,
}

impl Peers {
    /// Verify the invitation before changing the pinned Manager or its trust.
    pub(crate) async fn pair_agent(
        &self,
        client: &reqwest::Client,
        signer: &IdentitySigner,
        endpoint: &str,
        token: &str,
    ) -> Result<Identity, Error> {
        let (id, secret) = token.split_once('.').ok_or(Error::PeerRequest {
            reason: "agent-token: expected an invitation identifier and secret",
        })?;
        let id = Uuid::parse_str(id).map_err(|_| Error::PeerRequest {
            reason: "agent-token: invalid invitation identifier",
        })?;
        if secret.len() != 64 || !secret.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Error::PeerRequest {
                reason: "agent-token: invalid invitation secret",
            });
        }
        // The signed challenge supplies the identity pinned during pairing.
        let challenge: Signed<Challenge> = transport::post(
            client,
            endpoint,
            "challenges",
            &ChallengeRequest {
                actor: signer.identity.clone(),
                invitation: Some(id),
            },
        )
        .await?;
        challenge.verify("challenge", &challenge.payload.target)?;
        if challenge.payload.actor != signer.identity
            || challenge.payload.purpose != Purpose::AgentPair
            || challenge.payload.target.id == signer.identity.id
            || challenge.payload.target.fingerprint == signer.identity.fingerprint
        {
            return Err(Error::Unauthorized);
        }
        let challenge = challenge.payload;
        let receipt: Signed<PairReceipt> = transport::post(
            client,
            endpoint,
            "pairings",
            &signer.sign(
                "pair",
                PairClaim {
                    invitation_proof: invitation_proof(secret, &challenge)?,
                    challenge: challenge.clone(),
                },
            )?,
        )
        .await
        .map_err(|_| Error::PeerUncertain)?;
        let manager = challenge.target;
        receipt
            .verify("paired", &manager)
            .map_err(|_| Error::PeerUncertain)?;
        if receipt.payload.nonce != challenge.nonce
            || receipt.payload.actor != signer.identity.id
            || receipt.payload.target != manager
        {
            return Err(Error::PeerUncertain);
        }
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let retire_deployment = file
            .agent
            .as_ref()
            .is_none_or(|binding| binding.retire_deployment || binding.manager != manager);
        if let Some(previous) = file.agent.take() {
            file.trusted.remove(&previous.manager.id);
        }
        file.agent = Some(AgentBinding {
            manager: manager.clone(),
            token_digest: Some(sha256_hex(token.as_bytes())),
            retire_deployment,
        });
        file.trusted.insert(
            manager.id,
            TrustedPeer {
                id: manager.id,
                name: "Manager".to_string(),
                public_key: manager.public_key.clone(),
                fingerprint: manager.fingerprint.clone(),
            },
        );
        locked
            .commit(file)
            .await
            .map_err(|_| Error::PeerUncertain)?;
        Ok(manager)
    }

    pub(crate) fn load(config: &Path) -> Result<Self, Error> {
        Ok(Self {
            file: Persisted::load(config, "peers")?,
            pending: Mutex::new(Pending::default()),
            // Control must not depend on environment proxy settings or follow redirects with proofs.
            http: outbound_builder(None)?
                .timeout(Duration::from_secs(30))
                .build()?,
            agent: agent::AgentHub::new(),
        })
    }

    pub(crate) async fn hosts(&self) -> Vec<Host> {
        self.file
            .read(|file| file.hosts.values().cloned().collect())
            .await
    }

    pub(crate) fn host_view(&self, host: Host) -> HostView {
        let connection = (host.mode == Mode::Agent).then(|| self.agent.host_status(host.id));
        HostView { host, connection }
    }

    pub(crate) async fn reusable_agent_binding(
        &self,
        token: Option<&str>,
    ) -> Result<Option<Identity>, Error> {
        let locked = self.file.lock().await;
        let Some(binding) = locked.get().agent.as_ref() else {
            return Ok(None);
        };
        let digest = sha256_hex(token.unwrap_or_default().as_bytes());
        if binding
            .token_digest
            .as_ref()
            .is_some_and(|previous| token.is_some() && previous != &digest)
        {
            return Ok(None);
        }
        if !locked.get().trusts(&binding.manager) {
            return Err(Error::Unauthorized);
        }
        let manager = binding.manager.clone();
        if binding.token_digest.is_none() {
            // An older binding cannot tell a retained, consumed token from a new one.
            // Record the existing deployment as the baseline on its first startup.
            let mut file = locked.get().clone();
            file.agent = Some(AgentBinding {
                token_digest: Some(digest),
                ..binding.clone()
            });
            locked.commit(file).await?;
        }
        Ok(Some(manager))
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) async fn agent_deployment_needs_retirement(&self) -> bool {
        self.file
            .read(|file| {
                file.agent
                    .as_ref()
                    .is_some_and(|binding| binding.retire_deployment)
            })
            .await
    }

    #[cfg(feature = "singbox-core")]
    pub(crate) async fn finish_agent_deployment_retirement(&self) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let binding = file.agent.as_mut().ok_or(Error::Unauthorized)?;
        binding.retire_deployment = false;
        Ok(locked.commit(file).await?)
    }

    pub(crate) async fn agent_host(&self, id: Uuid) -> Result<Host, Error> {
        self.file
            .read(|file| {
                let host = file.hosts.get(&id).ok_or(Error::PeerNotFound)?;
                if host.mode != Mode::Agent || !file.trusts(&host.identity) {
                    return Err(Error::Unauthorized);
                }
                Ok(host.clone())
            })
            .await
    }

    pub(crate) async fn agent_manager_authorized(&self, manager: &Identity) -> Result<(), Error> {
        if self
            .file
            .read(|file| {
                file.agent
                    .as_ref()
                    .is_some_and(|link| &link.manager == manager)
                    && file.trusts(manager)
            })
            .await
        {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    pub(crate) async fn direct_trusted(&self) -> Vec<TrustedPeer> {
        self.file
            .read(|file| {
                file.trusted
                    .iter()
                    .filter(|(id, _)| file.is_direct_trust(id))
                    .map(|(_, peer)| peer.clone())
                    .collect()
            })
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
        url: Option<String>,
    ) -> Result<Host, Error> {
        valid_name(&name)?;
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let host = file.hosts.get_mut(&id).ok_or(Error::PeerNotFound)?;
        let endpoint = url
            .as_deref()
            .map(|url| endpoint(url, host.mode))
            .transpose()?;
        if host.mode == Mode::Direct && endpoint.is_none() {
            return Err(Error::PeerRequest {
                reason: "endpoint: a Direct host requires an address",
            });
        }
        host.name = name;
        host.endpoint = endpoint;
        let result = host.clone();
        locked.commit(file).await?;
        Ok(result)
    }

    pub(crate) async fn remove_host(&self, id: Uuid) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let host = file.hosts.remove(&id).ok_or(Error::PeerNotFound)?;
        if host.mode == Mode::Agent {
            file.trusted.remove(&id);
        }
        locked.commit(file).await?;
        self.agent.disconnect(id);
        Ok(())
    }

    pub(crate) async fn revoke_direct(&self, id: Uuid) -> Result<(), Error> {
        let locked = self.file.lock().await;
        if !locked.get().is_direct_trust(&id) {
            return Err(Error::PeerNotFound);
        }
        let mut file = locked.get().clone();
        file.trusted.remove(&id).ok_or(Error::PeerNotFound)?;
        Ok(locked.commit(file).await?)
    }

    pub(crate) async fn invite(
        &self,
        signer: &IdentitySigner,
        name: String,
        url: String,
        mode: Mode,
    ) -> Result<Invitation, Error> {
        valid_name(&name)?;
        let endpoint = endpoint(&url, mode)?;
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
                mode,
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
            mode,
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
            let held = pending
                .invitations
                .get(&invitation)
                .ok_or(Error::Unauthorized)?;
            let purpose = match held.mode {
                Mode::Agent => Purpose::AgentPair,
                Mode::Direct => Purpose::Pair,
            };
            (purpose, Some(invitation))
        } else {
            self.require_trusted(&request.actor).await?;
            (Purpose::Request, None)
        };
        if pending.challenges.len() >= PENDING_LIMIT {
            return Err(Error::PeerBusy);
        }
        drop(pending);
        self.challenge_actor(signer, request.actor, purpose, invitation)
            .await
    }

    pub(crate) async fn accept(
        &self,
        signer: &IdentitySigner,
        proof: Signed<PairClaim>,
    ) -> Result<Signed<PairReceipt>, Error> {
        proof.verify("pair", &proof.payload.challenge.actor)?;
        let challenge = proof.payload.challenge;
        if !matches!(challenge.purpose, Purpose::Pair | Purpose::AgentPair) {
            return Err(Error::Unauthorized);
        }
        let mut pending = self.pending.lock().await;
        let held = consume(
            &mut pending,
            &challenge,
            &signer.identity,
            challenge.purpose.clone(),
        )?;
        let invitation_id = held.invitation.ok_or(Error::Unauthorized)?;
        let invitation = pending
            .invitations
            .get(&invitation_id)
            .ok_or(Error::Unauthorized)?;
        let mode = invitation.mode;
        let label = invitation.name.clone();
        verify_invitation(
            &invitation.secret,
            &challenge,
            &proof.payload.invitation_proof,
        )?;
        let actor = &challenge.actor;
        let trusted = TrustedPeer {
            id: actor.id,
            name: label.clone(),
            public_key: actor.public_key.clone(),
            fingerprint: actor.fingerprint.clone(),
        };
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        if file
            .hosts
            .get(&actor.id)
            .is_some_and(|host| host.mode != mode)
        {
            return Err(Error::PeerConflict {
                reason: "host.mode: this identity is paired in another mode",
            });
        }
        file.trusted.insert(actor.id, trusted);
        if mode == Mode::Agent {
            // The manager keeps the node it invited so it can dial it back over
            // the session the node opens. It has no address of its own to reach.
            file.hosts.entry(actor.id).or_insert(Host {
                id: actor.id,
                name: label,
                endpoint: None,
                identity: actor.clone(),
                mode: Mode::Agent,
            });
        }
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
        self.require_resource_operator(&proof.payload.challenge.actor)
            .await?;
        Ok(PeerGrant {
            actor: proof.payload.challenge.actor.clone(),
        })
    }

    pub(crate) async fn allows(&self, grant: &PeerGrant) -> Result<(), Error> {
        self.require_resource_operator(&grant.actor).await
    }

    async fn require_resource_operator(&self, actor: &Identity) -> Result<(), Error> {
        if self
            .file
            .read(|file| !file.is_agent_host(&actor.id) && file.trusts(actor))
            .await
        {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    /// A manager's own inbound side: prove an agent is the one this instance invited,
    /// without granting it any authority over this instance's resources.
    pub(crate) async fn agent_challenge(
        &self,
        signer: &IdentitySigner,
        id: Uuid,
    ) -> Result<Signed<Challenge>, Error> {
        let host = self.agent_host(id).await?;
        if host.identity.id == signer.identity.id {
            return Err(Error::Unauthorized);
        }
        self.challenge_actor(signer, host.identity, Purpose::AgentSession, None)
            .await
    }

    pub(crate) async fn authorize_agent_session(
        &self,
        signer: &IdentitySigner,
        proof: &Signed<AgentSessionProof>,
    ) -> Result<Host, Error> {
        proof.verify("agent-session", &proof.payload.challenge.actor)?;
        let challenge = proof.payload.challenge.clone();
        let mut pending = self.pending.lock().await;
        consume(
            &mut pending,
            &challenge,
            &signer.identity,
            Purpose::AgentSession,
        )?;
        let host = self.agent_host(challenge.actor.id).await?;
        if host.identity != challenge.actor {
            return Err(Error::Unauthorized);
        }
        Ok(host)
    }

    /// Discard the pinned Manager when the operator explicitly unbinds.
    pub(crate) async fn unbind_agent(&self) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let Some(binding) = file.agent.take() else {
            return Ok(());
        };
        file.trusted.remove(&binding.manager.id);
        Ok(locked.commit(file).await?)
    }

    async fn challenge_actor(
        &self,
        signer: &IdentitySigner,
        actor: Identity,
        purpose: Purpose,
        invitation: Option<Uuid>,
    ) -> Result<Signed<Challenge>, Error> {
        let mut pending = self.pending.lock().await;
        pending.prune();
        if pending.challenges.len() >= PENDING_LIMIT {
            return Err(Error::PeerBusy);
        }
        let challenge = Challenge {
            nonce: random()?,
            actor,
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

    async fn require_trusted(&self, actor: &Identity) -> Result<(), Error> {
        if self.file.read(|file| file.trusts(actor)).await {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
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

/// An outbound client that never inherits the environment's proxy settings and
/// never follows a redirect with a proof attached. An explicit proxy is the only
/// way one is used, and it may carry credentials that are never logged.
pub(crate) fn outbound_builder(proxy: Option<&str>) -> Result<reqwest::ClientBuilder, Error> {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5));
    let Some(value) = proxy else {
        return Ok(builder);
    };
    let invalid = || Error::PeerRequest {
        reason: "agent-proxy: use an HTTP or HTTPS proxy URL without a path, query or fragment",
    };
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || value.contains('\\')
    {
        return Err(invalid());
    }
    let proxy = reqwest::Proxy::all(url).map_err(|_| invalid())?;
    Ok(builder.proxy(proxy))
}

pub(crate) fn manager_endpoint(value: &str) -> Result<String, Error> {
    let value = value.trim_end_matches('/');
    let base = value.strip_suffix("/api").ok_or(Error::PeerRequest {
        reason: "manager-api-url: expected an API base URL ending in /api",
    })?;
    endpoint(base, Mode::Agent)
}

pub(crate) fn endpoint(value: &str, mode: Mode) -> Result<String, Error> {
    let invalid = || {
        Error::PeerRequest { reason: match mode {
            Mode::Agent => "endpoint: use HTTP or HTTPS, without credentials, query or fragment",
            Mode::Direct => "endpoint: use HTTPS, without credentials, query or fragment; HTTP is only allowed for a loopback IP",
        } }
    };
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !(url.scheme() == "https" || url.scheme() == "http" && (mode == Mode::Agent || loopback))
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
