//! Non-executing JavaScript lexical-boundary probe pair.
//!
//! The seed is closed metadata only: one supported JavaScript source-context
//! code and one scanner-owned canonical lowercase hexadecimal identity. Target
//! values and surrounding script source never participate in derivation.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};
use std::fmt;

pub const XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID: &str =
    "web.review.xss.javascript-lexical-boundary-query-pair";
pub const XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION: u32 = 1;

/// Exact scanner-owned lexical tokens shared by payload derivation and
/// response correlation. The canonical case identity is accepted once here;
/// downstream code never rebuilds these comments independently.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct XssJavascriptLexicalProbeTokens {
    control: String,
    boundary_comment: String,
    tail_comment: String,
}

impl XssJavascriptLexicalProbeTokens {
    pub(crate) fn from_identity(identity: &str) -> Option<Self> {
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        Some(Self {
            control: format!("venom-xss-js-control-{identity}"),
            boundary_comment: format!("/*venom-xss-js-boundary-{identity}*/"),
            tail_comment: format!("/*venom-xss-js-tail-{identity}*/"),
        })
    }

    pub(crate) fn control(&self) -> &str {
        &self.control
    }

    pub(crate) fn boundary_comment(&self) -> &str {
        &self.boundary_comment
    }

    pub(crate) fn tail_comment(&self) -> &str {
        &self.tail_comment
    }
}

impl fmt::Debug for XssJavascriptLexicalProbeTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XssJavascriptLexicalProbeTokens")
            .field("control_bytes", &self.control.len())
            .field("boundary_bytes", &self.boundary_comment.len())
            .field("tail_bytes", &self.tail_comment.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct XssJavascriptLexicalBoundaryQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl XssJavascriptLexicalBoundaryQueryPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_ID,
                XSS_JAVASCRIPT_LEXICAL_BOUNDARY_QUERY_PAIR_REVISION,
            )
            .expect("the XSS JavaScript lexical-boundary strategy identity is static and valid"),
        }
    }

    fn derive_value(seed: &[u8], role: PayloadVariantRole) -> Option<String> {
        let seed = std::str::from_utf8(seed).ok()?;
        let (family, identity) = seed.split_once(':')?;
        if !matches!(family, "js-single" | "js-double" | "js-template") {
            return None;
        }
        let tokens = XssJavascriptLexicalProbeTokens::from_identity(identity)?;

        if role == PayloadVariantRole::Control {
            return Some(tokens.control().to_owned());
        }

        let boundary = tokens.boundary_comment();
        let tail = tokens.tail_comment();
        match family {
            "js-single" => Some(format!("'{boundary}+{tail}'")),
            "js-double" => Some(format!("\"{boundary}+{tail}\"")),
            "js-template" => Some(format!("`{boundary}+{tail}`")),
            _ => None,
        }
    }
}

impl Default for XssJavascriptLexicalBoundaryQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for XssJavascriptLexicalBoundaryQueryPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        let value = Self::derive_value(seed.as_bytes(), role)
            .ok_or(PayloadStrategyError::DerivationFailed)?;
        PayloadArtifact::new(self.reference.clone(), role, value.into_bytes(), limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    const IDENTITY: &str = "0123456789abcdef0123456789abcdef";

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::new(128, 256).unwrap()
    }

    fn derive(family: &str, role: PayloadVariantRole) -> String {
        let strategy = XssJavascriptLexicalBoundaryQueryPairStrategy::new();
        let seed = PayloadSeed::new(format!("{family}:{IDENTITY}").into_bytes(), limits()).unwrap();
        String::from_utf8(
            strategy
                .derive_one(role, &seed, limits())
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn strategy_identity_and_exact_inert_wire_shapes_are_versioned() {
        let strategy = XssJavascriptLexicalBoundaryQueryPairStrategy::new();
        assert_eq!(
            strategy.strategy_ref().id(),
            "web.review.xss.javascript-lexical-boundary-query-pair"
        );
        assert_eq!(strategy.strategy_ref().revision(), 1);

        let tokens = XssJavascriptLexicalProbeTokens::from_identity(IDENTITY).unwrap();
        let boundary = tokens.boundary_comment();
        let tail = tokens.tail_comment();
        assert_eq!(
            derive("js-single", PayloadVariantRole::Candidate),
            format!("'{boundary}+{tail}'")
        );
        assert_eq!(
            derive("js-double", PayloadVariantRole::Candidate),
            format!("\"{boundary}+{tail}\"")
        );
        assert_eq!(
            derive("js-template", PayloadVariantRole::Candidate),
            format!("`{boundary}+{tail}`")
        );
        let debug = format!("{tokens:?}");
        assert!(!debug.contains(IDENTITY));
        assert!(!debug.contains(boundary));
        assert!(!debug.contains(tail));
        assert_eq!(
            tokens.control(),
            derive("js-single", PayloadVariantRole::Control)
        );
    }

    #[test]
    fn controls_are_context_safe_and_candidates_contain_no_executable_tokens() {
        for family in ["js-single", "js-double", "js-template"] {
            let control = derive(family, PayloadVariantRole::Control);
            let candidate = derive(family, PayloadVariantRole::Candidate);
            assert_eq!(control, format!("venom-xss-js-control-{IDENTITY}"));
            assert_ne!(control, candidate);
            assert!(candidate.len() <= 256);
            assert!(!control.contains(['\'', '"', '`', '/', '+']));

            let normalized = candidate.to_ascii_lowercase();
            for forbidden in [
                "alert",
                "prompt",
                "confirm",
                "eval",
                "function",
                "fetch",
                "xmlhttprequest",
                "websocket",
                "import(",
                "document.",
                "window.",
                "cookie",
                "localstorage",
                "sessionstorage",
                "settimeout",
                "setinterval",
                "javascript:",
                "data:",
                "http://",
                "https://",
            ] {
                assert!(
                    !normalized.contains(forbidden),
                    "forbidden token {forbidden} in {candidate}"
                );
            }
        }
    }

    #[test]
    fn unknown_family_and_noncanonical_identity_fail_closed() {
        let strategy = XssJavascriptLexicalBoundaryQueryPairStrategy::new();
        for value in [
            format!("unknown:{IDENTITY}"),
            "js-single:short".to_owned(),
            "js-double:0123456789ABCDEF0123456789ABCDEF".to_owned(),
            "js-template:0123456789abcdef0123456789abcdeg".to_owned(),
            format!("js-single:{IDENTITY}:extra"),
            format!("js-single :{IDENTITY}"),
        ] {
            let seed = PayloadSeed::new(value.into_bytes(), limits()).unwrap();
            for role in [PayloadVariantRole::Control, PayloadVariantRole::Candidate] {
                assert!(matches!(
                    strategy.derive_one(role, &seed, limits()),
                    Err(PayloadStrategyError::DerivationFailed)
                ));
            }
        }
    }

    #[test]
    fn derivation_is_repeatable_and_concurrency_safe() {
        let strategy = Arc::new(XssJavascriptLexicalBoundaryQueryPairStrategy::new());
        let seed_value = format!("js-template:{IDENTITY}").into_bytes();
        let expected = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &PayloadSeed::new(seed_value.clone(), limits()).unwrap(),
                limits(),
            )
            .unwrap();

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let strategy = Arc::clone(&strategy);
                let seed_value = seed_value.clone();
                thread::spawn(move || {
                    strategy
                        .derive_one(
                            PayloadVariantRole::Candidate,
                            &PayloadSeed::new(seed_value, limits()).unwrap(),
                            limits(),
                        )
                        .unwrap()
                })
            })
            .collect();

        for handle in handles {
            let artifact = handle.join().unwrap();
            assert_eq!(artifact, expected);
            assert_eq!(artifact.receipt(), expected.receipt());
        }
    }
}
