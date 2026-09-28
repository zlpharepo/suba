use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
    Argon2,
};
use http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Hash(#[from] HashError),

    #[error("{0}")]
    Password(String),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error(transparent)]
    Argon2(#[from] argon2::password_hash::Error),

    #[error(transparent)]
    Argon2Phc(#[from] argon2::password_hash::phc::Error),
}

impl crate::error::IntoHttpError for Error {
    fn into_http_error(self) -> crate::error::HttpError {
        match self {
            Error::Hash(_) => crate::error::HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error".to_string(),
            },
            Error::Password(_) => crate::error::HttpError {
                status_code: StatusCode::UNAUTHORIZED,
                message: "Wrong user credentials".to_string(),
            },
            Error::Join(_) => crate::error::HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error".to_string(),
            },
        }
    }
}

fn hash_password(password: impl AsRef<str>) -> Result<String, HashError> {
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_ref().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(HashError::Argon2)
}

fn verify_password(password: impl AsRef<str>, hash: impl AsRef<str>) -> Result<(), HashError> {
    let parsed_hash = PasswordHash::new(hash.as_ref())?;

    let argon2 = Argon2::default();

    argon2
        .verify_password(password.as_ref().as_bytes(), &parsed_hash)
        .map_err(HashError::Argon2)
}

pub async fn hash(password: impl AsRef<str>) -> Result<String, Error> {
    let password = password.as_ref().to_string();
    let hash = tokio::task::spawn_blocking(move || hash_password(password)).await??;

    Ok(hash)
}

pub async fn verify(password: impl AsRef<str>, hash: impl AsRef<str>) -> Result<(), Error> {
    let password = password.as_ref().to_string();
    let hash = hash.as_ref().to_string();
    tokio::task::spawn_blocking(move || {
        verify_password(password, hash).map_err(|e| Error::Password(e.to_string()))
    })
    .await??;

    Ok(())
}
