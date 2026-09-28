use std::fmt;

use ed25519_dalek::{
    pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey, EncodePublicKey},
    SecretKey, SigningKey,
};
use getrandom::fill;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl KeyPair {
    /// Generate a signing key pair.
    pub fn generate() -> Result<Self, KeyPairError> {
        let (private_key, public_key) = Self::generate_ed25519_keys()?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    fn generate_ed25519_keys() -> Result<(String, String), KeyPairError> {
        let mut secret = SecretKey::default();
        fill(&mut secret)?;

        let signing_key = SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();

        let private_key = signing_key.to_pkcs8_pem(LineEnding::default())?.to_string();
        let public_key = verifying_key
            .to_public_key_pem(LineEnding::default())
            .map_err(ed25519_dalek::pkcs8::Error::PublicKey)?;

        Ok((private_key, public_key))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyPairError {
    #[error(transparent)]
    Pkcs8(#[from] ed25519_dalek::pkcs8::Error),

    #[error(transparent)]
    Entropy(#[from] getrandom::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_key_is_never_printed() {
        let pair = KeyPair::generate().expect("a key pair");
        let printed = format!("{pair:?}");

        assert!(!printed.contains("PRIVATE KEY"), "{printed}");
        assert!(!printed.contains(&pair.private_key), "{printed}");
        assert!(
            printed.contains("BEGIN PUBLIC KEY"),
            "the public half is not a secret and stays readable: {printed}"
        );
    }
}
