use std::fmt;

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::KeyPair;

const TOKEN_EXPIRATION_DAYS: i64 = 30;

#[derive(Clone, Serialize, Deserialize)]
pub struct Administrator {
    pub username: String,

    pub shadow: String,
}

impl fmt::Debug for Administrator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Administrator")
            .field("username", &self.username)
            .field("shadow", &"[redacted]")
            .finish()
    }
}

impl Administrator {
    pub async fn create(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, crate::error::Error> {
        let shadow = crate::password::hash(password).await?;

        Ok(Self {
            username: username.as_ref().to_string(),
            shadow,
        })
    }

    pub async fn verify(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<(), crate::error::Error> {
        if self.username != username.as_ref() {
            return Err(crate::error::Error::Password(
                crate::password::Error::Password("Invalid username".to_string()),
            ));
        }
        crate::password::verify(password, &self.shadow).await?;

        Ok(())
    }
    pub fn create_session(
        &self,
        key_pair: &KeyPair,
    ) -> Result<(Claims, String), crate::error::Error> {
        let now = Utc::now();
        let exp = now + Duration::days(TOKEN_EXPIRATION_DAYS);
        let jti = uuid::Uuid::now_v7();

        let claims = Claims {
            exp: exp.timestamp(),
            iat: now.timestamp(),
            sub: self.username.clone(),
            jti,
        };
        let token = claims.encode(&key_pair.private_key)?;

        Ok((claims, token))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub exp: i64,
    pub iat: i64,
    pub sub: String,
    pub jti: Uuid,
}

impl Claims {
    pub fn encode(&self, key: impl AsRef<str>) -> Result<String, jsonwebtoken::errors::Error> {
        let key = EncodingKey::from_ed_pem(key.as_ref().as_bytes())?;
        let header = Header::new(Algorithm::EdDSA);

        jsonwebtoken::encode(&header, self, &key)
    }

    /// Verify a token with the public half of the instance key.
    ///
    /// Verification must never need the signing secret: only issuing a token does.
    pub fn decode(
        token: impl AsRef<str>,
        key_pair: &KeyPair,
    ) -> Result<Self, jsonwebtoken::errors::Error> {
        let key = DecodingKey::from_ed_pem(key_pair.public_key.as_bytes())?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;

        Ok(jsonwebtoken::decode(token.as_ref(), &key, &validation)?.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_password_hash_is_never_printed() {
        let administrator = Administrator::create("doge", "correct horse battery staple")
            .await
            .expect("an administrator");
        let printed = format!("{administrator:?}");

        assert!(!printed.contains(&administrator.shadow), "{printed}");
        assert!(!printed.contains("$argon2"), "{printed}");
        assert!(printed.contains("doge"), "{printed}");
    }

    #[tokio::test]
    async fn creates_and_verifies_credentials() {
        let administrator = Administrator::create("doge", "correct horse battery staple")
            .await
            .unwrap();

        assert!(administrator
            .verify("doge", "correct horse battery staple")
            .await
            .is_ok());
        assert!(administrator
            .verify("doge", "wrong password")
            .await
            .is_err());
        assert!(administrator
            .verify("someone", "correct horse battery staple")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn password_hash_is_salted_and_not_the_password() {
        let first = Administrator::create("doge", "correct horse battery staple")
            .await
            .unwrap();
        let second = Administrator::create("doge", "correct horse battery staple")
            .await
            .unwrap();

        assert_ne!(
            first.shadow, second.shadow,
            "each hash must use a fresh salt"
        );
        assert!(!first.shadow.contains("correct horse"));
        assert!(first.shadow.starts_with("$argon2"));
    }

    #[test]
    fn sessions_round_trip_through_the_public_key() {
        let key_pair = KeyPair::generate().expect("a key pair");
        let administrator = Administrator {
            username: "doge".to_string(),
            shadow: String::new(),
        };

        let (claims, token) = administrator.create_session(&key_pair).unwrap();
        let decoded = Claims::decode(&token, &key_pair).unwrap();

        assert_eq!(decoded.sub, "doge");
        assert_eq!(decoded.jti, claims.jti);
        assert_eq!(decoded.exp, claims.exp);
    }

    #[test]
    fn tokens_signed_by_another_instance_are_rejected() {
        let issuer = KeyPair::generate().expect("a key pair");
        let attacker = KeyPair::generate().expect("a key pair");
        let administrator = Administrator {
            username: "doge".to_string(),
            shadow: String::new(),
        };

        let (_, token) = administrator.create_session(&issuer).unwrap();

        assert!(Claims::decode(&token, &attacker).is_err());
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let key_pair = KeyPair::generate().expect("a key pair");
        // Beyond the verifier's leeway, so this is unambiguously expired.
        let claims = Claims {
            exp: Utc::now().timestamp() - 3600,
            iat: Utc::now().timestamp() - 7200,
            sub: "doge".to_string(),
            jti: Uuid::now_v7(),
        };

        let token = claims.encode(&key_pair.private_key).unwrap();

        assert!(Claims::decode(&token, &key_pair).is_err());
    }
}
