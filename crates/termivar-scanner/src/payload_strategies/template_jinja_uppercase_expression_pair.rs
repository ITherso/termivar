//! Bounded Jinja-compatible uppercase-filter expression probes.
//!
//! This closed family applies only the `upper` filter to a scanner-owned
//! lowercase ASCII literal. It contains no calls, object traversal, indexing,
//! statement separators, paths, or I/O-capable syntax. A match establishes
//! only compatibility with the listed expression semantics, never engine
//! identity or code execution.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub const TEMPLATE_JINJA_UPPERCASE_EXPRESSION_PAIR_ID: &str =
    "web.review.template-evaluation.jinja-compatible-uppercase-expression-pair";
pub const TEMPLATE_JINJA_UPPERCASE_EXPRESSION_PAIR_REVISION: u32 = 1;
pub(crate) const TEMPLATE_JINJA_UPPERCASE_FAMILY_ID: &str =
    crate::template_evaluation_review::TEMPLATE_EVALUATION_REVIEW_FAMILY_ID;

/// One deterministic scanner-owned uppercase-filter probe and exact outcomes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TemplateJinjaUppercaseProbe {
    nonce: String,
}

impl std::fmt::Debug for TemplateJinjaUppercaseProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TemplateJinjaUppercaseProbe")
            .field("family", &TEMPLATE_JINJA_UPPERCASE_FAMILY_ID)
            .field("encoded_bytes", &self.seed().len())
            .finish()
    }
}

impl TemplateJinjaUppercaseProbe {
    pub(crate) fn new(nonce: String) -> Option<Self> {
        if !(16..=32).contains(&nonce.len())
            || !nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        Some(Self { nonce })
    }

    pub(crate) fn seed(&self) -> String {
        format!("v1-{}", self.nonce)
    }

    pub(crate) fn control_value(&self) -> String {
        format!("termivar-template-{}-control-end", self.nonce)
    }

    pub(crate) fn candidate_value(&self) -> String {
        format!(
            "termivar-template-{}-{{{{'termivar_{}'|upper}}}}-end",
            self.nonce, self.nonce
        )
    }

    pub(crate) fn expected_value(&self) -> String {
        let evaluated_literal = format!("termivar_{}", self.nonce).to_ascii_uppercase();
        format!("termivar-template-{}-{evaluated_literal}-end", self.nonce)
    }

    fn parse(seed: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(seed).ok()?;
        let nonce = text.strip_prefix("v1-")?;
        if nonce.contains('-') {
            return None;
        }
        Self::new(nonce.to_owned())
    }
}

#[derive(Debug, Clone)]
pub struct TemplateJinjaUppercaseExpressionPairStrategy {
    reference: PayloadStrategyRef,
}

impl TemplateJinjaUppercaseExpressionPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                TEMPLATE_JINJA_UPPERCASE_EXPRESSION_PAIR_ID,
                TEMPLATE_JINJA_UPPERCASE_EXPRESSION_PAIR_REVISION,
            )
            .expect("the template uppercase strategy identity is static and valid"),
        }
    }
}

impl Default for TemplateJinjaUppercaseExpressionPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for TemplateJinjaUppercaseExpressionPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        let probe = TemplateJinjaUppercaseProbe::parse(seed.as_bytes())
            .ok_or(PayloadStrategyError::DerivationFailed)?;
        let value = match role {
            PayloadVariantRole::Control => probe.control_value(),
            PayloadVariantRole::Candidate => probe.candidate_value(),
        };
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
    fn family_is_bounded_harmless_and_exactly_correlated() {
        let probe = TemplateJinjaUppercaseProbe::new("a1b2c3d4e5f60708".into()).unwrap();
        let seed = PayloadSeed::new(probe.seed().into_bytes(), limits()).unwrap();
        let strategy = TemplateJinjaUppercaseExpressionPairStrategy::new();
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits())
            .unwrap();
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits())
            .unwrap();
        assert_eq!(control.as_bytes(), probe.control_value().as_bytes());
        assert_eq!(candidate.as_bytes(), probe.candidate_value().as_bytes());
        assert_eq!(
            probe.expected_value(),
            "termivar-template-a1b2c3d4e5f60708-TERMIVAR_A1B2C3D4E5F60708-end"
        );
        for forbidden in [".", "[", "]", "(", ")", ";", "/", "\\"] {
            assert!(!probe.candidate_value().contains(forbidden));
        }
    }

    #[test]
    fn invalid_or_unbounded_seeds_fail_closed() {
        let strategy = TemplateJinjaUppercaseExpressionPairStrategy::new();
        for seed in [
            "v2-a1b2c3d4e5f60708",
            "v1-short",
            "v1-A1B2C3D4E5F60708",
            "v1-a1b2c3d4e5f6070x",
            "v1-a1b2c3d4e5f60708-extra",
        ] {
            let seed = PayloadSeed::new(seed.as_bytes().to_vec(), limits()).unwrap();
            assert!(matches!(
                strategy.derive_one(PayloadVariantRole::Candidate, &seed, limits()),
                Err(PayloadStrategyError::DerivationFailed)
            ));
        }
    }
}
