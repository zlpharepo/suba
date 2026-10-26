use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, DecodePrivateKey, DecodePublicKey, EncodePublicKey},
    Signature, Signer as _, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{config::KeyPair, error::Error};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub id: Uuid,
    pub public_key: String,
    pub fingerprint: String,
}

impl Identity {
    pub(super) fn key(&self) -> Result<VerifyingKey, Error> {
        if self.id.is_nil() || self.public_key.len() > 1024 {
            return Err(Error::Unauthorized);
        }
        let key =
            VerifyingKey::from_public_key_pem(&self.public_key).map_err(|_| Error::Unauthorized)?;
        if fingerprint(&key) != self.fingerprint {
            return Err(Error::Unauthorized);
        }
        Ok(key)
    }
}

pub(crate) struct IdentitySigner {
    pub identity: Identity,
    key: SigningKey,
}

impl IdentitySigner {
    pub(crate) fn new(id: Uuid, pair: &KeyPair) -> Result<Self, Error> {
        let key = SigningKey::from_pkcs8_pem(&pair.private_key).map_err(|_| Error::PeerIdentity)?;
        let public =
            VerifyingKey::from_public_key_pem(&pair.public_key).map_err(|_| Error::PeerIdentity)?;
        if id.is_nil() || key.verifying_key() != public {
            return Err(Error::PeerIdentity);
        }
        Ok(Self {
            identity: Identity {
                id,
                public_key: public
                    .to_public_key_pem(LineEnding::LF)
                    .map_err(|_| Error::PeerIdentity)?,
                fingerprint: fingerprint(&public),
            },
            key,
        })
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        purpose: &'static str,
        payload: T,
    ) -> Result<Signed<T>, Error> {
        let bytes = message(purpose, &payload)?;
        Ok(Signed {
            payload,
            signature: hex(&self.key.sign(&bytes).to_bytes()),
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Signed<T> {
    pub payload: T,
    pub signature: String,
}

impl<T: Serialize> Signed<T> {
    pub(super) fn verify(&self, purpose: &'static str, identity: &Identity) -> Result<(), Error> {
        if self.signature.len() != 128 {
            return Err(Error::Unauthorized);
        }
        let mut bytes = [0; 64];
        for (byte, pair) in bytes
            .iter_mut()
            .zip(self.signature.as_bytes().as_chunks::<2>().0.iter())
        {
            let pair = std::str::from_utf8(pair).map_err(|_| Error::Unauthorized)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| Error::Unauthorized)?;
        }
        identity
            .key()?
            .verify_strict(
                &message(purpose, &self.payload)?,
                &Signature::from_bytes(&bytes),
            )
            .map_err(|_| Error::Unauthorized)
    }
}

fn message<T: Serialize>(purpose: &str, payload: &T) -> Result<Vec<u8>, Error> {
    // Fixed protocol purpose and typed field order separate these proofs from login JWTs.
    serde_json::to_vec(&("suba-peer-v1", purpose, payload)).map_err(|_| Error::PeerRequest {
        reason: "peer.proof: could not encode the message",
    })
}

fn fingerprint(key: &VerifyingKey) -> String {
    format!("SHA256:{}", suba_core::checksum::sha256_hex(key.as_bytes()))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
