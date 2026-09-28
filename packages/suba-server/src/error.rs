use axum::{extract::rejection::JsonRejection, http::StatusCode};
use axum_extra::typed_header::TypedHeaderRejection;

use crate::config::{ConfigError, KeyPairError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unauthorized")]
    Unauthorized,
    #[error(transparent)]
    Core(#[from] suba_core::Error),

    #[error("proxy provider '{0}' not found")]
    ProviderNotFound(String),
    #[error("proxy provider '{0}' is disabled")]
    ProviderDisabled(String),
    #[error("proxy provider '{0}' has no cached contents yet")]
    ProviderNotCached(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    JsonRejection(#[from] JsonRejection),

    #[error(transparent)]
    TypedHeaderRejection(#[from] TypedHeaderRejection),

    #[error(transparent)]
    Validation(#[from] garde::Report),

    #[error(transparent)]
    KeyPair(#[from] KeyPairError),

    #[error(transparent)]
    Password(#[from] crate::password::Error),

    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    Request(#[from] reqwest::Error),
}

pub struct HttpError {
    pub status_code: StatusCode,
    pub message: String,
}

pub trait IntoHttpError {
    fn into_http_error(self) -> HttpError;
}

impl IntoHttpError for Error {
    fn into_http_error(self) -> HttpError {
        match self {
            Error::Unauthorized => HttpError {
                status_code: StatusCode::UNAUTHORIZED,
                message: "Unauthorized".to_string(),
            },
            Error::Core(_) => HttpError {
                status_code: StatusCode::BAD_REQUEST,
                message: "Invalid request".to_string(),
            },
            Error::ProviderNotFound(name) => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("Proxy provider '{name}' not found"),
            },
            Error::ProviderDisabled(name) => HttpError {
                status_code: StatusCode::CONFLICT,
                message: format!("Proxy provider '{name}' is disabled"),
            },
            Error::ProviderNotCached(name) => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("Proxy provider '{name}' has no cached contents yet"),
            },
            Error::Io(_) => HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error".to_string(),
            },
            Error::Config(_) => HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error".to_string(),
            },
            Error::JsonRejection(_) => HttpError {
                status_code: StatusCode::BAD_REQUEST,
                message: "Invalid request body".to_string(),
            },
            Error::TypedHeaderRejection(_) => HttpError {
                status_code: StatusCode::UNAUTHORIZED,
                message: "Unauthorized".to_string(),
            },
            Error::Validation(_) => HttpError {
                status_code: StatusCode::UNPROCESSABLE_ENTITY,
                message: "Invalid request".to_string(),
            },
            Error::KeyPair(_) => HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error".to_string(),
            },
            Error::Password(e) => e.into_http_error(),
            Error::Jwt(_) => HttpError {
                status_code: StatusCode::UNAUTHORIZED,
                message: "Unauthorized".to_string(),
            },
            Error::Request(_) => HttpError {
                status_code: StatusCode::BAD_GATEWAY,
                message: "Upstream request failed".to_string(),
            },
        }
    }
}
