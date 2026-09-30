use axum::{extract::rejection::JsonRejection, http::StatusCode};
use axum_extra::typed_header::TypedHeaderRejection;

use crate::config::{ConfigError, KeyPairError};
use crate::provider::FetchError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unauthorized")]
    Unauthorized,

    /// The runtime observation store failed.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),

    /// A blocking store call could not be joined.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    #[error("provider '{0}' not found")]
    ProviderNotFound(String),
    #[error("collection '{0}' not found")]
    CollectionNotFound(String),
    #[error("provider '{0}' is disabled")]
    ProviderDisabled(String),
    #[error("provider '{0}' serves no payload yet")]
    ProviderNoPayload(String),

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

    /// A provider's node filter cannot be compiled.
    ///
    /// The text is the field path and a static reason — `includes[1]: not a
    /// valid regular expression` — so the client is told what to fix without
    /// the pattern being quoted back at it.
    #[error(transparent)]
    Filter(#[from] suba_core::FilterError),

    #[error(transparent)]
    KeyPair(#[from] KeyPairError),

    #[error(transparent)]
    Password(#[from] crate::password::Error),

    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// A provider did not produce a payload.
    #[error(transparent)]
    Fetch(#[from] FetchError),

    #[error(transparent)]
    Request(#[from] reqwest::Error),

    /// A document this instance cannot write.
    ///
    /// Its own problem, not the caller's: the format and the direction are both
    /// this instance's choice, made where the collection is written.
    #[error(transparent)]
    Render(#[from] suba_core::RenderError),

    /// The operating system would not give random bytes.
    ///
    /// Its own problem: a token or a key pair cannot be made without entropy, and
    /// nothing a caller sent has anything to do with it.
    #[error("the operating system would not provide randomness: {0}")]
    Entropy(String),

    /// No delivery is addressed by this URL.
    ///
    /// One answer for every way that can be true — an unknown token, a revoked
    /// one, a prefix this instance does not use — and the text names nothing: a
    /// caller looking for a token that works learns nothing from a 404 that is
    /// the same everywhere.
    #[error("not found")]
    NoSuchDelivery,

    /// A delivery token name that cannot be used.
    #[error("token name: {reason}")]
    TokenName { reason: &'static str },

    /// A format this build does not serve was asked for by name.
    #[error("format: not a format this build serves")]
    UnknownFormat,

    /// A delivery token was used more often than it may be.
    #[error("too many requests")]
    TooManyRequests { retry_after: u64 },

    /// The configured delivery prefix cannot be used.
    ///
    /// Said out loud because an operator can fix it: a prefix that is not one
    /// path segment addresses nothing, and a URL that silently answers 404 for
    /// that reason is the kind of failure nobody can find.
    #[error("subscription prefix: {reason}")]
    Prefix { reason: &'static str },

    /// The sing-box module refused something.
    #[cfg(feature = "singbox-core")]
    #[error(transparent)]
    Singbox(#[from] suba_singbox::core::Error),

    /// A configuration document is wrong.
    ///
    /// The text is a field path and a static reason, and may name the section or
    /// the tag it is about — never a value, which is where credentials live.
    #[cfg(feature = "singbox-core")]
    #[error("{0}")]
    Document(String),

    /// A section the operator has not written yet.
    #[cfg(feature = "singbox-core")]
    #[error("section '{section}' is not there")]
    NoSection { section: String },

    /// An entry an array section does not hold.
    #[cfg(feature = "singbox-core")]
    #[error("{section} has no entry tagged '{tag}'")]
    NoEntry { section: String, tag: String },

    /// The document changed since the caller read it (`If-Match`).
    #[cfg(feature = "singbox-core")]
    #[error("the configuration changed since it was read")]
    Stale,

    /// There is no version to run.
    #[cfg(feature = "singbox-core")]
    #[error("no version is installed and current")]
    NoVersion,

    /// A schema this build cannot read.
    ///
    /// The text is a schema position and a static reason, never a value from a
    /// request, and it is logged rather than answered with.
    #[cfg(feature = "singbox-core")]
    #[error("the schema cannot be read: {0}")]
    Schema(String),

    /// A document that is not JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
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
            Error::Store(error) => {
                tracing::error!("store error: {error}");

                HttpError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Internal server error".to_string(),
                }
            }
            Error::Join(error) => {
                tracing::error!("background task error: {error}");

                HttpError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Internal server error".to_string(),
                }
            }
            Error::ProviderNotFound(name) => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("Provider '{name}' not found"),
            },
            Error::CollectionNotFound(name) => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("Collection '{name}' not found"),
            },
            Error::ProviderDisabled(name) => HttpError {
                status_code: StatusCode::CONFLICT,
                message: format!("Provider '{name}' is disabled"),
            },
            Error::ProviderNoPayload(name) => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("Provider '{name}' serves no payload yet"),
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
            Error::Filter(error) => HttpError {
                status_code: StatusCode::UNPROCESSABLE_ENTITY,
                message: error.to_string(),
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
            Error::Fetch(error) => {
                // A remote provider that refused is upstream's fault; a local
                // file that cannot be read is the operator's, and no status a
                // client can act on describes it better than a plain failure.
                let (status_code, message) = match error {
                    FetchError::Request { .. } => {
                        (StatusCode::BAD_GATEWAY, "Upstream request failed")
                    }
                    FetchError::TooLarge { .. } | FetchError::Read { .. } => {
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
                    }
                };

                tracing::warn!("provider fetch failed: {error}");

                HttpError {
                    status_code,
                    message: message.to_string(),
                }
            }
            Error::Render(error) => {
                tracing::error!("render error: {error}");

                HttpError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Internal server error".to_string(),
                }
            }
            Error::Prefix { reason } => HttpError {
                status_code: StatusCode::UNPROCESSABLE_ENTITY,
                message: format!("subscription prefix: {reason}"),
            },
            Error::TokenName { reason } => HttpError {
                status_code: StatusCode::UNPROCESSABLE_ENTITY,
                message: format!("token name: {reason}"),
            },
            Error::UnknownFormat => HttpError {
                status_code: StatusCode::UNPROCESSABLE_ENTITY,
                message: "format: not a format this build serves".to_string(),
            },
            Error::TooManyRequests { .. } => HttpError {
                status_code: StatusCode::TOO_MANY_REQUESTS,
                message: "Too many requests".to_string(),
            },
            Error::NoSuchDelivery => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: "Not found".to_string(),
            },
            Error::Entropy(reason) => {
                tracing::error!("entropy error: {reason}");

                HttpError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Internal server error".to_string(),
                }
            }
            Error::Request(_) => HttpError {
                status_code: StatusCode::BAD_GATEWAY,
                message: "Upstream request failed".to_string(),
            },
            #[cfg(feature = "singbox-core")]
            Error::Singbox(error) => {
                use suba_singbox::core::Error as Core;

                // What the client can act on is answered as itself; everything
                // else is this instance's own problem and stays internal.
                let status_code = match &error {
                    Core::NotInstalled { .. }
                    | Core::Unpublished { .. }
                    | Core::NoAsset { .. }
                    | Core::Platform { .. } => StatusCode::NOT_FOUND,
                    Core::Installed { .. }
                    | Core::Current { .. }
                    | Core::RunningVersion { .. }
                    | Core::Hash { .. }
                    | Core::Running { .. } => StatusCode::CONFLICT,
                    Core::Generate { .. } | Core::TooOld { .. } => StatusCode::UNPROCESSABLE_ENTITY,
                    Core::Refused { .. } | Core::Network { .. } => StatusCode::BAD_GATEWAY,
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                };

                let message = match status_code {
                    StatusCode::INTERNAL_SERVER_ERROR => {
                        tracing::error!("sing-box: {error}");

                        "Internal server error".to_string()
                    }
                    _ => error.to_string(),
                };

                HttpError {
                    status_code,
                    message,
                }
            }
            #[cfg(feature = "singbox-core")]
            Error::Document(message) => HttpError {
                status_code: StatusCode::UNPROCESSABLE_ENTITY,
                message,
            },
            #[cfg(feature = "singbox-core")]
            Error::NoSection { section } => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("Section '{section}' is not there"),
            },
            #[cfg(feature = "singbox-core")]
            Error::NoEntry { section, tag } => HttpError {
                status_code: StatusCode::NOT_FOUND,
                message: format!("{section} has no entry tagged '{tag}'"),
            },
            #[cfg(feature = "singbox-core")]
            Error::Stale => HttpError {
                status_code: StatusCode::PRECONDITION_FAILED,
                message: "The configuration changed since it was read".to_string(),
            },
            #[cfg(feature = "singbox-core")]
            Error::NoVersion => HttpError {
                status_code: StatusCode::CONFLICT,
                message: "No version is installed and current".to_string(),
            },
            #[cfg(feature = "singbox-core")]
            Error::Schema(text) => {
                tracing::error!("sing-box schema: {text}");

                HttpError {
                    status_code: StatusCode::INTERNAL_SERVER_ERROR,
                    message: "Internal server error".to_string(),
                }
            }
            Error::Json(_) => HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Internal server error".to_string(),
            },
        }
    }
}

#[cfg(all(test, feature = "singbox-core"))]
mod tests {
    use super::*;
    use suba_singbox::core::{Error as Core, Version};

    fn status(error: Error) -> StatusCode {
        error.into_http_error().status_code
    }

    #[test]
    fn what_a_caller_can_act_on_is_answered_as_itself() {
        let version = Version::from_tag("v1.14.2");

        // A version this instance does not have, a version nobody publishes,
        // and a platform nothing is built for are all "what you asked for is
        // not here".
        for absent in [
            Core::NotInstalled {
                version: version.clone(),
            },
            Core::Unpublished {
                version: version.clone(),
            },
            Core::NoAsset {
                name: "sing-box-1.14.2-linux-mips.tar.gz".to_string(),
            },
            Core::Platform {
                os: "linux",
                arch: "mips",
            },
        ] {
            assert_eq!(status(Error::Singbox(absent)), StatusCode::NOT_FOUND);
        }

        // Removing what is in use, or what is running, is refused rather than
        // done.
        for in_use in [
            Core::Current {
                version: version.clone(),
            },
            Core::RunningVersion {
                version: version.clone(),
            },
            Core::Installed {
                version: version.clone(),
            },
            Core::Running { pid: 1 },
        ] {
            assert_eq!(status(Error::Singbox(in_use)), StatusCode::CONFLICT);
        }

        assert_eq!(
            status(Error::Singbox(Core::Generate {
                command: "rand",
                reason: "the binary refused to generate anything",
            })),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status(Error::Singbox(Core::Refused {
                status: 403,
                hint: "the release server refused the request",
            })),
            StatusCode::BAD_GATEWAY
        );

        // Anything else is this instance's own problem, and its own text.
        let internal = Error::Singbox(Core::Files {
            at: "a file",
            reason: "the file could not be read",
        });
        let answer = internal.into_http_error();

        assert_eq!(answer.status_code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(answer.message, "Internal server error");
    }
}
