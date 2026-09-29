use std::path::{Path, PathBuf};

/// A failure to read or write a configuration file.
///
/// The offending path is part of the error: configuration problems are almost
/// always about *which* file, and the encoder/decoder source is kept for the
/// case where the format itself is at fault.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The file does not contain valid configuration.
    #[error("invalid configuration in `{}`: {source}", path.display())]
    Decode {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The value cannot be represented in the enabled format.
    #[error("cannot serialize configuration for `{}`: {source}", path.display())]
    Encode {
        path: PathBuf,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The blocking write task could not be joined.
    #[error("the configuration writer stopped unexpectedly: {0}")]
    Join(String),
}

impl ConfigError {
    /// A decoding failure for `path`.
    ///
    /// The format is a compile-time choice, so the source keeps its concrete
    /// type only here: every format-specific error is boxed into one variant.
    pub(crate) fn decode(
        path: &Path,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Decode {
            path: path.to_path_buf(),
            source: source.into(),
        }
    }

    /// An encoding failure for `path`.
    pub(crate) fn encode(
        path: &Path,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Encode {
            path: path.to_path_buf(),
            source: source.into(),
        }
    }
}
