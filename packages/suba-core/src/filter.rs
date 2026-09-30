//! Node filtering: which of a provider's nodes survive.
//!
//! A filter is a list of patterns read against a node's name — the one field a
//! client displays and an operator recognises. The vocabulary is three shapes
//! rather than a bare regular expression:
//!
//! * A **bare** pattern is compared whole, so `US-LAX-01` does not also match
//!   `US-LAX-01-IPv6`. It is the default because it is the only shape an
//!   operator can read back from a node list without translating anything.
//! * `keyword:` is a literal substring, escaped before it becomes a pattern, so
//!   a name containing `.` or `+` matches itself.
//! * `regex:` is a regular expression, for what the other two cannot express.
//!
//! The bare form being the *strictest* is the point. A filter is written
//! against a subscription the operator does not control, and the default shape
//! must not turn a name into a pattern: `keyword:` and `regex:` are opt-in.
//!
//! Patterns inside one list are alternatives. [`NodeFilter`] holds the two
//! lists and applies them in one order: exclusion first, then inclusion. A name
//! the `exclude` list matches is dropped there and then, so a name matching both
//! lists is out — the lists are written for different reasons (one says what the
//! operator wants, the other what they never want), and "never" is the one that
//! has to survive a `keep` pattern that is broader than intended.
//!
//! Matching is case-sensitive, as the names are: two nodes differing only in
//! case are two names, and folding them would make the outcome depend on the
//! client's idea of case rather than on the configured pattern.

use regex::{Regex, RegexSet};

/// The two lists, compiled into one decision.
pub struct NodeFilter {
    /// `None` when the operator configured no allowlist, which admits every
    /// name. An empty list is not the same as "match nothing".
    include: Option<RegexSet>,
    /// `None` when the operator configured nothing to drop.
    exclude: Option<RegexSet>,
}

impl NodeFilter {
    /// Compile the configured lists.
    ///
    /// A pattern that cannot be used is an error rather than a silently skipped
    /// entry: a filter the operator believes is in force and is not would drop
    /// nodes they asked to keep, and the one thing worse than either is not
    /// knowing which happened.
    pub fn compile(include: &[String], exclude: &[String]) -> Result<Self, FilterError> {
        Ok(Self {
            include: compile_set(include, "include")?,
            exclude: compile_set(exclude, "exclude")?,
        })
    }

    /// Whether a node with this name survives the filter.
    ///
    /// Exclusion first, then inclusion: a name the operator asked to drop is
    /// dropped before the allowlist is even consulted, so a name matching both
    /// lists is out. The other order would let "keep" override "drop", which is
    /// the wrong way round for a list of things the operator never wants.
    pub fn admits(&self, name: &str) -> bool {
        if let Some(exclude) = &self.exclude {
            if exclude.is_match(name) {
                return false;
            }
        }

        match &self.include {
            Some(include) => include.is_match(name),
            None => true,
        }
    }

    /// Whether this filter keeps everything, so a caller can skip it.
    pub fn is_unfiltered(&self) -> bool {
        self.include.is_none() && self.exclude.is_none()
    }
}

impl std::fmt::Debug for NodeFilter {
    /// How many patterns each list holds, never the patterns themselves.
    ///
    /// A pattern is read against a node's name, and a name is operator data
    /// that has no business in a log line — an exact pattern often *is* the
    /// name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = |set: &Option<RegexSet>| set.as_ref().map_or(0, RegexSet::len);

        f.debug_struct("NodeFilter")
            .field("include", &count(&self.include))
            .field("exclude", &count(&self.exclude))
            .finish()
    }
}

/// A configured pattern that cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    /// One pattern in a list is not usable.
    ///
    /// Named by field and position, never by the pattern: the pattern is the
    /// operator's text, and an error is not the place to quote it back.
    #[error("{field}[{index}]: {reason}")]
    Pattern {
        field: &'static str,
        index: usize,
        reason: PatternReason,
    },

    /// Every pattern is valid on its own, but they do not fit in one compiled
    /// set.
    #[error("{field}: the patterns are too large to compile together")]
    TooLarge { field: &'static str },
}

/// Why a configured pattern cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum PatternReason {
    #[error("the pattern is empty; remove it instead")]
    Empty,

    #[error("not a valid regular expression")]
    Invalid,
}

/// Compile one list, or `None` when it is empty.
fn compile_set(patterns: &[String], field: &'static str) -> Result<Option<RegexSet>, FilterError> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let expressions = patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| {
            as_expression(pattern).map_err(|reason| FilterError::Pattern {
                field,
                index,
                reason,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    match RegexSet::new(&expressions) {
        Ok(set) => Ok(Some(set)),
        Err(_) => {
            // The set reports only that *something* did not compile, and an
            // error that does not say which pattern is a puzzle. Attribute it by
            // re-checking each one, which costs nothing on the happy path.
            for (index, expression) in expressions.iter().enumerate() {
                if Regex::new(expression).is_err() {
                    return Err(FilterError::Pattern {
                        field,
                        index,
                        reason: PatternReason::Invalid,
                    });
                }
            }

            // Each one compiles alone, so the compiled-size budget is what ran
            // out and no single pattern is at fault.
            Err(FilterError::TooLarge { field })
        }
    }
}

/// The regular expression one configured pattern means.
fn as_expression(pattern: &str) -> Result<String, PatternReason> {
    if let Some(literal) = pattern.strip_prefix("keyword:") {
        return match literal.is_empty() {
            true => Err(PatternReason::Empty),
            // Escaped, so the literal is matched as text: `keyword:a.b` must not
            // also match `axb`.
            false => Ok(regex::escape(literal)),
        };
    }

    if let Some(expression) = pattern.strip_prefix("regex:") {
        return match expression.is_empty() {
            true => Err(PatternReason::Empty),
            false => Ok(format!("(?:{expression})")),
        };
    }

    match pattern.is_empty() {
        true => Err(PatternReason::Empty),
        // Anchored, so a bare pattern is the whole name and nothing else.
        false => Ok(format!("^(?:{})$", regex::escape(pattern))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn include(patterns: &[&str]) -> NodeFilter {
        let patterns: Vec<String> = patterns.iter().map(|pattern| pattern.to_string()).collect();

        NodeFilter::compile(&patterns, &[]).unwrap()
    }

    fn both(include_patterns: &[&str], exclude_patterns: &[&str]) -> NodeFilter {
        let include_patterns = include_patterns
            .iter()
            .map(|pattern| pattern.to_string())
            .collect::<Vec<_>>();
        let exclude_patterns = exclude_patterns
            .iter()
            .map(|pattern| pattern.to_string())
            .collect::<Vec<_>>();

        NodeFilter::compile(&include_patterns, &exclude_patterns).unwrap()
    }

    #[test]
    fn a_bare_pattern_is_the_whole_name() {
        let filter = include(&["US-LAX-01"]);

        assert!(filter.admits("US-LAX-01"));
        assert!(!filter.admits("US-LAX-01-IPv6"), "not a prefix");
        assert!(!filter.admits("xUS-LAX-01"), "not a substring");
        assert!(!filter.admits("us-lax-01"), "not a case-folded match");
    }

    #[test]
    fn a_bare_pattern_is_text_and_not_a_pattern() {
        // The default shape must not turn a name into a regex: a dot in a node
        // name is a dot.
        let filter = include(&["a.b"]);

        assert!(filter.admits("a.b"));
        assert!(!filter.admits("axb"));
    }

    #[test]
    fn a_keyword_is_a_literal_substring() {
        let filter = include(&["keyword:LAX"]);

        assert!(filter.admits("US-LAX-01"), "anywhere in the name");
        assert!(filter.admits("LAX"));
        assert!(!filter.admits("US-SEA-01"));
    }

    #[test]
    fn a_keyword_that_looks_like_a_pattern_is_still_a_keyword() {
        let filter = include(&["keyword:1.1"]);

        assert!(filter.admits("relay-1.1-hk"), "the dot is a dot");
        assert!(!filter.admits("relay-1x1-hk"));
    }

    #[test]
    fn a_regex_is_a_regular_expression() {
        let filter = include(&["regex:-\\d+$"]);

        assert!(filter.admits("US-01"));
        assert!(!filter.admits("US-LAX"), "no digits at the end");
    }

    #[test]
    fn patterns_in_one_list_are_alternatives() {
        let filter = include(&["US-01", "regex:^HK"]);

        assert!(filter.admits("US-01"), "the first alternative");
        assert!(filter.admits("HK-9"), "the second alternative");
        assert!(!filter.admits("JP-01"), "neither");
    }

    #[test]
    fn a_filter_with_no_patterns_keeps_everything() {
        let filter = NodeFilter::compile(&[], &[]).unwrap();

        assert!(filter.is_unfiltered());
        assert!(filter.admits("anything at all"));
    }

    #[test]
    fn an_include_list_alone_drops_everything_it_does_not_name() {
        let filter = include(&["US-01"]);

        assert!(!filter.is_unfiltered());
        assert!(filter.admits("US-01"));
        assert!(!filter.admits("US-02"), "an allowlist is not a hint");
    }

    #[test]
    fn an_exclude_list_alone_drops_only_what_it_names() {
        let filter = both(&[], &["keyword:expired"]);

        assert!(filter.admits("US-01"));
        assert!(!filter.admits("US-01-expired"));
    }

    #[test]
    fn exclude_wins_over_include() {
        let filter = both(&["regex:^US"], &["keyword:LAX"]);

        assert!(
            filter.admits("US-SEA-01"),
            "the include list still admits this"
        );
        assert!(
            !filter.admits("US-LAX-01"),
            "both lists match, and the exclusion is the one that decides"
        );
    }

    #[test]
    fn an_invalid_pattern_names_its_position_and_not_its_text() {
        let patterns = vec!["US-01".to_string(), "regex:(".to_string()];
        let error = NodeFilter::compile(&patterns, &[]).expect_err("an unclosed group");

        match &error {
            FilterError::Pattern {
                field,
                index,
                reason,
            } => {
                assert_eq!(*field, "include");
                assert_eq!(*index, 1, "the second pattern");
                assert!(matches!(reason, PatternReason::Invalid));
            }
            other => panic!("expected a pattern failure, got {other}"),
        }

        let printed = error.to_string();
        assert!(printed.contains("include[1]"), "{printed}");
        assert!(
            !printed.contains("regex:(") && !printed.contains('('),
            "the operator's own text must not be echoed back: {printed}"
        );
    }

    #[test]
    fn an_empty_pattern_is_refused_rather_than_ignored() {
        // Skipping it would leave a filter that is not the one that was
        // configured, and the operator would have no way to tell.
        for patterns in [
            vec![String::new()],
            vec!["keyword:".to_string()],
            vec!["regex:".to_string()],
        ] {
            let error = NodeFilter::compile(&patterns, &[]).expect_err("an empty pattern");

            assert!(
                matches!(
                    error,
                    FilterError::Pattern {
                        index: 0,
                        reason: PatternReason::Empty,
                        ..
                    }
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn an_invalid_exclude_pattern_names_the_exclude_list() {
        let error = NodeFilter::compile(&[], &["regex:[".to_string()]).expect_err("unclosed class");

        assert!(error.to_string().starts_with("exclude[0]"), "{error}");
    }

    #[test]
    fn debug_counts_the_patterns_and_prints_none_of_them() {
        let filter = both(&["US-LAX-01"], &["keyword:expired"]);
        let printed = format!("{filter:?}");

        assert!(printed.contains("include: 1"), "{printed}");
        assert!(printed.contains("exclude: 1"), "{printed}");
        assert!(
            !printed.contains("US-LAX-01") && !printed.contains("expired"),
            "a pattern may be a node's name: {printed}"
        );
    }
}
