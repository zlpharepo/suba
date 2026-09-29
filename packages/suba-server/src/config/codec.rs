//! The configuration format: which notation the documents are written in.
//!
//! The format is a compile-time choice between two notations of the same
//! documents. It is isolated here so that nothing else — the document types,
//! the stores, the server — carries a `#[cfg]` for it: they call
//! [`config_path`]/[`decode`]/[`encode`] and do not know which one is compiled
//! in.
//!
//! Exactly one format is required. A build with neither has nowhere to write,
//! and a build with both would have to pick one per file at runtime, which is
//! not a choice this program makes: the file extension would stop being an
//! answer.

#[cfg(not(any(feature = "toml", feature = "json")))]
compile_error!("Enable exactly one configuration format feature: toml or json");

#[cfg(all(feature = "toml", feature = "json"))]
compile_error!(
    "Enable exactly one configuration format feature, not both: toml and json are mutually exclusive"
);

use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};

use super::ConfigError;

/// The file extension the documents use.
#[cfg(all(feature = "toml", not(feature = "json")))]
pub(crate) const EXTENSION: &str = "toml";
#[cfg(feature = "json")]
pub(crate) const EXTENSION: &str = "json";

/// The file name a document with `basename` is stored in.
pub(crate) fn config_name(basename: &str) -> String {
    format!("{basename}.{EXTENSION}")
}

/// The path of `basename` inside the configuration directory `base`.
///
/// For diagnostics and tests: the write itself goes through the directory
/// handle in [`crate::fs`], which takes a name rather than a path.
pub(crate) fn config_path(base: impl AsRef<Path>, basename: &str) -> PathBuf {
    base.as_ref().join(config_name(basename))
}

/// Read a document from `content`, naming `path` if it cannot be read.
pub(crate) fn decode<T: DeserializeOwned>(content: &str, path: &Path) -> Result<T, ConfigError> {
    #[cfg(all(feature = "toml", not(feature = "json")))]
    {
        toml::from_str(content).map_err(|error| ConfigError::decode(path, error))
    }

    #[cfg(feature = "json")]
    {
        serde_json::from_str(content).map_err(|error| ConfigError::decode(path, error))
    }
}

/// Write a document to text, naming `path` if it cannot be written.
pub(crate) fn encode<T: Serialize>(value: &T, path: &Path) -> Result<String, ConfigError> {
    #[cfg(all(feature = "toml", not(feature = "json")))]
    {
        toml::to_string_pretty(value).map_err(|error| ConfigError::encode(path, error))
    }

    #[cfg(feature = "json")]
    {
        serde_json::to_string_pretty(value).map_err(|error| ConfigError::encode(path, error))
    }
}
