//! Credentials that refuse to be printed.
//!
//! Every credential in the model — passwords, UUIDs, keys — is wrapped in [`Secret`]. The wrapper
//! has no `Display` impl at all, so interpolating one does not compile, and its `Debug` prints a
//! placeholder. Logging a whole node tree therefore cannot leak a credential: the type system
//! enforces it instead of a convention.

use core::fmt;

use crate::prelude::*;

/// A credential, printed as a placeholder and read only through [`Secret::expose`].
///
/// `serde`-transparent when the feature is on: a wire format needs the real value, and writing a
/// wire format is a deliberate act.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Secret<S>(S);

impl<S> Secret<S> {
    /// Wrap a value.
    pub const fn new(value: S) -> Self {
        Self(value)
    }

    /// The credential itself. Call this where the value is genuinely needed, never to print it.
    pub const fn expose(&self) -> &S {
        &self.0
    }

    /// Unwrap.
    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S: AsRef<str>> Secret<S> {
    /// The credential as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    /// Whether the credential is empty, which for most protocols means the node is unusable.
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

impl<S: Default> Default for Secret<S> {
    fn default() -> Self {
        Self(S::default())
    }
}

impl<S> fmt::Debug for Secret<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl<S: From<String>> From<&str> for Secret<S> {
    fn from(value: &str) -> Self {
        Self(S::from(value.to_string()))
    }
}

impl<S: From<String>> From<String> for Secret<S> {
    fn from(value: String) -> Self {
        Self(S::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_prints_a_placeholder() {
        let secret = Secret::new(String::from("hunter2"));
        let rendered = format!("{secret:?}");

        assert_eq!(rendered, "Secret(<redacted>)");
        assert!(!rendered.contains("hunter2"));
        assert_eq!(secret.as_str(), "hunter2");
    }

    #[test]
    fn a_struct_holding_one_can_be_printed_whole() {
        #[derive(Debug)]
        struct Row {
            #[allow(dead_code)]
            password: Secret<Box<str>>,
        }

        let rendered = format!(
            "{:?}",
            Row {
                password: Secret::new("s3cr3t".into())
            }
        );

        assert!(!rendered.contains("s3cr3t"), "{rendered}");
    }
}
