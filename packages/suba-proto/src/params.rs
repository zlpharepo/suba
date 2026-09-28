//! Parameters the model does not name.
//!
//! Share links grow query parameters faster than any library can model them, and a converter that
//! drops what it does not know is a converter that silently changes a provider's node. Everything
//! unrecognised is kept here instead, in the order it arrived, so that writing the link back is
//! lossless.

use core::fmt;

use crate::prelude::*;

/// Unrecognised `key=value` pairs, in the order they appeared.
#[derive(Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct RawParams(Vec<(Box<str>, Box<str>)>);

impl RawParams {
    /// No parameters.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// The value of `name`, if it is present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key.as_ref() == name)
            .map(|(_, value)| value.as_ref())
    }

    /// Whether `name` is present at all, which distinguishes `?flag` from `?flag=`.
    pub fn contains(&self, name: &str) -> bool {
        self.0.iter().any(|(key, _)| key.as_ref() == name)
    }

    /// Record a parameter, replacing any earlier one with the same name.
    pub fn insert(&mut self, name: &str, value: &str) {
        match self.0.iter_mut().find(|(key, _)| key.as_ref() == name) {
            Some(slot) => slot.1 = value.into(),
            None => self.0.push((name.into(), value.into())),
        }
    }

    /// Append a parameter, keeping an earlier one with the same name.
    pub fn push(&mut self, name: &str, value: &str) {
        self.0.push((name.into(), value.into()));
    }

    /// Append a parameter that is already owned, without copying it again.
    pub fn push_owned(&mut self, name: Box<str>, value: Box<str>) {
        self.0.push((name, value));
    }

    /// Take a parameter that is spelled as a flag, under any of `names`.
    ///
    /// These dialects write a boolean either as a bare name or as `1`/`true`, so both are truthy and
    /// an explicit `0`/`false`/`no` is not.
    pub fn take_flag(&mut self, names: &[&str]) -> bool {
        names.iter().any(|name| match self.take(name) {
            None => false,
            Some(value) => !matches!(value.as_ref(), "" | "0" | "false" | "no"),
        })
    }

    /// Remove and return a parameter.
    pub fn take(&mut self, name: &str) -> Option<Box<str>> {
        let index = self.0.iter().position(|(key, _)| key.as_ref() == name)?;
        Some(self.0.remove(index).1)
    }

    /// The pairs, in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_ref(), value.as_ref()))
    }

    /// How many parameters are kept.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether anything is kept.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for RawParams {
    /// Names only.
    ///
    /// A parameter the model does not know is a parameter the model cannot vouch for: it may be a
    /// key, a token, or a password. A debug print lists the names so a real problem is visible
    /// without ever writing the values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = f.debug_list();

        for (name, _) in &self.0 {
            list.entry(&name.as_ref());
        }

        list.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_and_the_last_value() {
        let mut params = RawParams::new();
        params.push("a", "1");
        params.push("b", "2");
        params.insert("a", "3");

        assert_eq!(params.get("a"), Some("3"));
        assert_eq!(
            params.iter().collect::<Vec<_>>(),
            vec![("a", "3"), ("b", "2")]
        );
    }

    #[test]
    fn debug_lists_names_never_values() {
        let mut params = RawParams::new();
        params.push("secret-ish", "hunter2");

        let rendered = format!("{params:?}");

        assert_eq!(rendered, "[\"secret-ish\"]");
    }
}
