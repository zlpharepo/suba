//! Machine trust is separate from administrator sessions and resource ownership.
//!
//! Only public identities and connection addresses persist. Invitations and
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
pub(crate) struct AgentUpstream {
    pub manager: Identity,
    pub endpoint: String,
    pub proxy: Option<String>,
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
    agent: Option<AgentUpstream>,
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
    pub(crate) async fn pair_agent(
        &self,
        signer: &IdentitySigner,
        endpoint: &str,
        token: &str,
    ) -> Result<AgentUpstream, Error> {
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
        let challenge: Signed<Challenge> = self
            .post(
                endpoint,
                Mode::Agent,
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
        {
            return Err(Error::Unauthorized);
        }
        self.join_agent(
            signer,
            Invitation {
                version: 1,
                id,
                endpoint: endpoint.to_string(),
                identity: challenge.payload.target,
                secret: secret.to_string(),
                expires_at: challenge.payload.expires_at,
                mode: Mode::Agent,
            },
            None,
        )
        .await
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

    pub(crate) async fn agent_upstream(&self) -> Option<AgentUpstream> {
        self.file.read(|file| file.agent.clone()).await
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

    /// The Agent side of pairing: prove the invitation, then remember the
    /// manager this instance will dial. Only one upstream is kept, and pairing is
    /// never retried automatically.
    pub(crate) async fn join_agent(
        &self,
        signer: &IdentitySigner,
        invitation: Invitation,
        proxy: Option<String>,
    ) -> Result<AgentUpstream, Error> {
        if invitation.mode != Mode::Agent {
            return Err(Error::PeerRequest {
                reason: "invitation.mode: this invitation is for a Direct connection",
            });
        }
        let endpoint = endpoint(&invitation.endpoint, Mode::Agent)?;
        invitation.identity.key()?;
        if invitation.version != 1
            || invitation.identity.id == signer.identity.id
            || invitation.identity.fingerprint == signer.identity.fingerprint
            || invitation.secret.len() != 64
            || !invitation
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::PeerRequest {
                reason: "invitation: invalid invitation or the local instance",
            });
        }
        let proxy = proxy.map(|url| proxy_url(&url)).transpose()?.flatten();
        if self.agent_upstream().await.is_some() {
            return Err(Error::PeerConflict {
                reason: "agent: this instance already has an upstream manager; disconnect first",
            });
        }
        let challenge = self
            .remote_challenge(
                signer,
                &endpoint,
                &invitation.identity,
                Some(invitation.id),
                Purpose::AgentPair,
            )
            .await?;
        let receipt: Signed<PairReceipt> = self
            .post(
                &endpoint,
                Mode::Agent,
                "pairings",
                &signer.sign(
                    "pair",
                    PairClaim {
                        invitation_proof: invitation_proof(&invitation.secret, &challenge)?,
                        challenge: challenge.clone(),
                    },
                )?,
            )
            .await
            .map_err(|_| Error::PeerUncertain)?;
        receipt
            .verify("paired", &invitation.identity)
            .map_err(|_| Error::PeerUncertain)?;
        if receipt.payload.nonce != challenge.nonce
            || receipt.payload.actor != signer.identity.id
            || receipt.payload.target != invitation.identity
        {
            return Err(Error::PeerUncertain);
        }
        let link = AgentUpstream {
            manager: invitation.identity,
            endpoint,
            proxy,
        };
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        if file.agent.is_some() {
            return Err(Error::PeerConflict {
                reason: "agent: this instance already has an upstream manager; disconnect first",
            });
        }
        file.agent = Some(link.clone());
        // The manager that invited this instance is the one allowed to operate it.
        file.trusted.insert(
            link.manager.id,
            TrustedPeer {
                id: link.manager.id,
                name: "Manager".to_string(),
                public_key: link.manager.public_key.clone(),
                fingerprint: link.manager.fingerprint.clone(),
            },
        );
        locked
            .commit(file)
            .await
            .map_err(|_| Error::PeerUncertain)?;
        self.agent.reconnect();
        Ok(link)
    }

    pub(crate) async fn leave_agent(&self) -> Result<(), Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let link = file.agent.take().ok_or(Error::PeerNotFound)?;
        // Leaving also revokes the manager's incoming resource grant.
        file.trusted.remove(&link.manager.id);
        locked.commit(file).await?;
        // A configuration change, not a process shutdown: the loop stays alive to
        // notice the upstream is gone and to accept a new one later.
        self.agent.reconnect();
        Ok(())
    }

    pub(crate) async fn edit_agent_upstream(
        &self,
        endpoint: Option<String>,
        proxy: Option<Option<String>>,
    ) -> Result<AgentUpstream, Error> {
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        let link = file.agent.as_mut().ok_or(Error::PeerNotFound)?;
        if let Some(url) = endpoint {
            link.endpoint = super::peers::endpoint(&url, Mode::Agent)?;
        }
        if let Some(proxy) = proxy {
            link.proxy = proxy.map(|url| proxy_url(&url)).transpose()?.flatten();
        }
        let result = link.clone();
        locked.commit(file).await?;
        self.agent.reconnect();
        Ok(result)
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
    match proxy {
        None => Ok(builder),
        Some(url) => Ok(builder.proxy(
            reqwest::Proxy::all(proxy_url(url)?.ok_or(Error::PeerRequest {
                reason: "proxy: expected an HTTP or HTTPS proxy URL",
            })?)
            .map_err(|_| Error::PeerRequest {
                reason: "proxy: expected an HTTP or HTTPS proxy URL",
            })?,
        )),
    }
}

/// Validate an optional proxy URL: HTTP or HTTPS, a host and port, no path.
fn proxy_url(value: &str) -> Result<Option<String>, Error> {
    let invalid = || Error::PeerRequest {
        reason: "proxy: use an HTTP or HTTPS proxy URL without a path, query or fragment",
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    let url = url::Url::parse(value).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(Some(url.as_str().trim_end_matches('/').to_string()))
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
