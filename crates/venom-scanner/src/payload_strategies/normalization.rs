//! Pure token-form normalization transforms for payload obfuscation.
//!
//! These are the corrected, relocated home for the case, comment, and whitespace
//! transforms that previously lived on the legacy [`crate::waf::PayloadEncoder`].
//! Each is a deterministic, pure function of its input and is behavior-equivalent
//! to the legacy transform it replaces. Nothing here selects a payload, issues a
//! request, or changes runtime behavior; these are building blocks only.

/// Alternates letter case by position: even indices upper-cased, odd unchanged.
///
/// Behavior-equivalent to `waf::PayloadEncoder::case_variation`.
pub fn case_variation(payload: &str) -> String {
    payload
        .chars()
        .enumerate()
        .map(|(index, character)| {
            if index % 2 == 0 {
                character.to_uppercase().to_string()
            } else {
                character.to_string()
            }
        })
        .collect()
}

/// Injects inline SQL comments into common keywords (case-sensitive).
///
/// Behavior-equivalent to `waf::PayloadEncoder::comment_injection_sql`.
pub fn sql_comment_injection(payload: &str) -> String {
    payload
        .replace("select", "sel/**/ect")
        .replace("SELECT", "SEL/**/ECT")
        .replace("union", "un/**/ion")
        .replace("UNION", "UN/**/ION")
}

/// Replaces each ASCII space with a tab.
///
/// Behavior-equivalent to the legacy `WhespaceVariation` transform.
pub fn whitespace_to_tab(payload: &str) -> String {
    payload.replace(' ', "\t")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_variation_alternates_and_is_deterministic() {
        assert_eq!(case_variation("select"), "SeLeCt");
        assert_eq!(case_variation("select"), case_variation("select"));
    }

    #[test]
    fn sql_comment_injection_breaks_keywords() {
        assert_eq!(
            sql_comment_injection("select * union all"),
            "sel/**/ect * un/**/ion all"
        );
        assert_eq!(sql_comment_injection("SELECT"), "SEL/**/ECT");
    }

    #[test]
    fn whitespace_to_tab_replaces_only_spaces() {
        assert_eq!(whitespace_to_tab("a b c"), "a\tb\tc");
        assert_eq!(whitespace_to_tab("a\tb"), "a\tb");
    }
}
