use serde::{de::DeserializeOwned, Serialize};

use super::*;

const WIRE_LIMIT: usize = REPLY_LIMIT * 4 / 3 + 64 * 1024;

impl Peers {
    pub(crate) async fn pair(
        &self,
        signer: &IdentitySigner,
        name: String,
        invitation: Invitation,
    ) -> Result<Host, Error> {
        valid_name(&name)?;
        let endpoint = endpoint(&invitation.endpoint)?;
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
        if self
            .file
            .read(|file| file.hosts.contains_key(&invitation.identity.id))
            .await
        {
            return Err(Error::PeerConflict {
                reason: "host: this instance is already connected",
            });
        }
        let challenge = self
            .remote_challenge(
                signer,
                &endpoint,
                &invitation.identity,
                Some(invitation.id),
                Purpose::Pair,
            )
            .await?;
        let receipt: Signed<PairReceipt> = self
            .post(
                &endpoint,
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
        let host = Host {
            id: invitation.identity.id,
            name,
            endpoint: Some(endpoint),
            identity: invitation.identity,
            mode: invitation.mode,
        };
        let locked = self.file.lock().await;
        let mut file = locked.get().clone();
        if file.hosts.contains_key(&host.id) {
            return Err(Error::PeerConflict {
                reason: "host: this instance is already connected",
            });
        }
        file.hosts.insert(host.id, host.clone());
        locked
            .commit(file)
            .await
            .map_err(|_| Error::PeerUncertain)?;
        Ok(host)
    }

    pub(crate) async fn forward(
        &self,
        signer: &IdentitySigner,
        host: &Host,
        method: String,
        path: String,
        if_match: Option<String>,
        body: Option<String>,
    ) -> Result<ResourceReply, Error> {
        if !resource_allowed(&method, &path) {
            return Err(Error::PeerNotFound);
        }
        let address = host.endpoint.as_deref().ok_or(Error::PeerUnavailable)?;
        let challenge = self
            .remote_challenge(signer, address, &host.identity, None, Purpose::Request)
            .await?;
        let proof = signer.sign(
            "request",
            ResourceRequest {
                challenge: challenge.clone(),
                method: method.clone(),
                path,
                if_match,
                body,
            },
        )?;
        // Mutating operations are never retried: losing the reply does not prove failure.
        let outcome = || {
            if method == "GET" {
                Error::PeerUnavailable
            } else {
                Error::PeerUncertain
            }
        };
        let reply: Signed<ResourceReply> = self
            .post(address, "requests", &proof)
            .await
            .map_err(|_| outcome())?;
        reply
            .verify("response", &host.identity)
            .map_err(|_| outcome())?;
        if reply.payload.nonce != challenge.nonce
            || reply.payload.actor != signer.identity.id
            || reply.payload.target != host.identity.id
        {
            return Err(outcome());
        }
        Ok(reply.payload)
    }

    pub(super) async fn remote_challenge(
        &self,
        signer: &IdentitySigner,
        endpoint: &str,
        target: &Identity,
        invitation: Option<Uuid>,
        purpose: Purpose,
    ) -> Result<Challenge, Error> {
        let challenge: Signed<Challenge> = self
            .post(
                endpoint,
                "challenges",
                &ChallengeRequest {
                    actor: signer.identity.clone(),
                    invitation,
                },
            )
            .await?;
        challenge
            .verify("challenge", target)
            .map_err(|_| Error::PeerUnavailable)?;
        if challenge.payload.actor != signer.identity
            || &challenge.payload.target != target
            || challenge.payload.purpose != purpose
        {
            return Err(Error::PeerUnavailable);
        }
        Ok(challenge.payload)
    }

    pub(super) async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
        body: &T,
    ) -> Result<R, Error> {
        let endpoint = super::endpoint(endpoint)?;
        let mut response = self
            .http
            .post(format!("{endpoint}/api/peers/{path}"))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(body).map_err(|_| Error::PeerUnavailable)?)
            .send()
            .await
            .map_err(|_| Error::PeerUnavailable)?;
        if !response.status().is_success()
            || response
                .content_length()
                .is_some_and(|length| length > WIRE_LIMIT as u64)
        {
            return Err(Error::PeerUnavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::PeerUnavailable)? {
            if bytes.len().saturating_add(chunk.len()) > WIRE_LIMIT {
                return Err(Error::PeerUnavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::PeerUnavailable)
    }
}

pub(crate) fn resource_allowed(method: &str, path: &str) -> bool {
    if !matches!(method, "GET" | "POST" | "PUT" | "DELETE") || path.len() > 8192 {
        return false;
    }
    let Ok(uri) = path.parse::<http::Uri>() else {
        return false;
    };
    if uri.scheme().is_some() || uri.authority().is_some() {
        return false;
    }
    let path = uri.path();
    if matches!(
        path,
        "/system/status" | "/system/info" | "/system/metrics" | "/system/ping"
    ) {
        return method == "GET";
    }
    ["/providers", "/collections", "/cores/sing-box"]
        .iter()
        .any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('/'))
        })
}
