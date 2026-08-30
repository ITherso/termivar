//! Non-executing context-specific structural XSS probe pair.
//!
//! The seed contains only a closed family code and a scanner-owned lowercase
//! hexadecimal identity. No target value participates in derivation.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub const XSS_STRUCTURAL_QUERY_PAIR_ID: &str = "web.review.xss.structural-query-pair";
pub const XSS_STRUCTURAL_QUERY_PAIR_REVISION: u32 = 1;

#[derive(Debug, Clone)]
pub struct XssStructuralQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl XssStructuralQueryPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                XSS_STRUCTURAL_QUERY_PAIR_ID,
                XSS_STRUCTURAL_QUERY_PAIR_REVISION,
            )
            .expect("the XSS structural strategy identity is static and valid"),
        }
    }

    fn derive_value(seed: &[u8], role: PayloadVariantRole) -> Option<String> {
        let seed = std::str::from_utf8(seed).ok()?;
        let (family, identity) = seed.split_once(':')?;
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        if role == PayloadVariantRole::Control {
            return Some(format!("venom-xss-control-{identity}-end"));
        }
        match family {
            "html" => Some(format!(
                "<venom-xss-boundary data-venom-token=\"{identity}\"></venom-xss-boundary>"
            )),
            "uri" => Some(format!(
                "venom-xss-{identity}/segment?probe={identity}#boundary"
            )),
            "handler" => Some(format!("/*venom-xss-handler-{identity}*/")),
            "script" => Some(format!("/*venom-xss-script-{identity}*/")),
            _ => None,
        }
    }
}

impl Default for XssStructuralQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for XssStructuralQueryPairStrategy {
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

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::new(256, 256).unwrap()
    }

    #[test]
    fn closed_families_create_distinct_bounded_non_networking_candidates() {
        let strategy = XssStructuralQueryPairStrategy::new();
        for family in ["html", "uri", "handler", "script"] {
            let seed = PayloadSeed::new(
                format!("{family}:0123456789abcdef0123456789abcdef").into_bytes(),
                limits(),
            )
            .unwrap();
            let control = strategy
                .derive_one(PayloadVariantRole::Control, &seed, limits())
                .unwrap();
            let candidate = strategy
                .derive_one(PayloadVariantRole::Candidate, &seed, limits())
                .unwrap();
            assert_ne!(control.as_bytes(), candidate.as_bytes());
            assert!(candidate.as_bytes().len() <= 160);
            let text = std::str::from_utf8(candidate.as_bytes()).unwrap();
            for forbidden in [
                "alert(",
                "javascript:",
                "data:",
                "http://",
                "https://",
                "//",
                "fetch(",
                "document.",
                "window.",
            ] {
                assert!(
                    !text.contains(forbidden),
                    "unsafe token {forbidden} in {text}"
                );
            }
        }
    }

    #[test]
    fn unknown_family_and_noncanonical_identity_fail_closed() {
        let strategy = XssStructuralQueryPairStrategy::new();
        for seed in [
            "unknown:0123456789abcdef0123456789abcdef",
            "html:short",
            "html:0123456789ABCDEF0123456789ABCDEF",
        ] {
            let seed = PayloadSeed::new(seed.as_bytes().to_vec(), limits()).unwrap();
            assert!(matches!(
                strategy.derive_one(PayloadVariantRole::Candidate, &seed, limits()),
                Err(PayloadStrategyError::DerivationFailed)
            ));
        }
    }
}
