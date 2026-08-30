//! Bounded structural SSTI arithmetic probes.
//!
//! The initial closed family uses only small integer multiplication inside
//! brace-expression delimiters. It performs no calls, traversal, I/O, timing,
//! or access to runtime objects. Additional families can be added as catalog
//! entries without changing the differential runtime.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub const SSTI_ARITHMETIC_EXPRESSION_PAIR_ID: &str =
    "web.review.ssti.brace-arithmetic-expression-pair";
pub const SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION: u32 = 1;

/// Closed SSTI syntax-family catalog supported by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SstiProbeFamily {
    BraceArithmeticV1,
}

impl SstiProbeFamily {
    pub(crate) const fn stable_id(self) -> &'static str {
        match self {
            Self::BraceArithmeticV1 => "web.review.ssti.family.brace-arithmetic@1",
        }
    }
}

/// One deterministic, scanner-owned arithmetic probe and its exact outcomes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SstiArithmeticProbe {
    family: SstiProbeFamily,
    nonce: String,
    left: u8,
    right: u8,
}

impl std::fmt::Debug for SstiArithmeticProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SstiArithmeticProbe")
            .field("family", &self.family.stable_id())
            .field("encoded_bytes", &self.seed().len())
            .finish()
    }
}

impl SstiArithmeticProbe {
    pub(crate) fn new(nonce: String, left: u8, right: u8) -> Option<Self> {
        if !(8..=32).contains(&nonce.len())
            || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !(2..=12).contains(&left)
            || !(2..=12).contains(&right)
        {
            return None;
        }
        Some(Self {
            family: SstiProbeFamily::BraceArithmeticV1,
            nonce,
            left,
            right,
        })
    }

    pub(crate) fn seed(&self) -> String {
        format!("v1-{}-{}-{}", self.nonce, self.left, self.right)
    }

    pub(crate) fn control_value(&self) -> String {
        format!("venom-ssti-{}-control-end", self.nonce)
    }

    pub(crate) fn candidate_value(&self) -> String {
        format!(
            "venom-ssti-{}-{{{{{}*{}}}}}-end",
            self.nonce, self.left, self.right
        )
    }

    pub(crate) fn expected_value(&self) -> String {
        format!(
            "venom-ssti-{}-{}-end",
            self.nonce,
            u16::from(self.left) * u16::from(self.right)
        )
    }

    fn parse(seed: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(seed).ok()?;
        let mut parts = text.split('-');
        if parts.next()? != "v1" {
            return None;
        }
        let nonce = parts.next()?.to_owned();
        let left = parts.next()?.parse().ok()?;
        let right = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Self::new(nonce, left, right)
    }
}

#[derive(Debug, Clone)]
pub struct SstiArithmeticExpressionPairStrategy {
    reference: PayloadStrategyRef,
}

impl SstiArithmeticExpressionPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
                SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
            )
            .expect("the SSTI arithmetic strategy identity is static and valid"),
        }
    }
}

impl Default for SstiArithmeticExpressionPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for SstiArithmeticExpressionPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        let probe = SstiArithmeticProbe::parse(seed.as_bytes())
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
        PayloadStrategyLimits::new(128, 128).unwrap()
    }

    #[test]
    fn family_is_safe_bounded_and_exactly_correlated() {
        let probe = SstiArithmeticProbe::new("a1b2c3d4e5f60708".into(), 3, 11).unwrap();
        let seed = PayloadSeed::new(probe.seed().into_bytes(), limits()).unwrap();
        let strategy = SstiArithmeticExpressionPairStrategy::new();
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits())
            .unwrap();
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits())
            .unwrap();
        assert_eq!(control.as_bytes(), probe.control_value().as_bytes());
        assert_eq!(candidate.as_bytes(), probe.candidate_value().as_bytes());
        assert_eq!(probe.expected_value(), "venom-ssti-a1b2c3d4e5f60708-33-end");
        for forbidden in [".", "[", "]", "(", ")", "'", "\"", ";", "/"] {
            assert!(!probe.candidate_value().contains(forbidden));
        }
    }

    #[test]
    fn invalid_or_unbounded_catalog_seeds_fail_closed() {
        let strategy = SstiArithmeticExpressionPairStrategy::new();
        for seed in [
            "v2-a1b2c3d4-3-4",
            "v1-short-3-4",
            "v1-a1b2c3d4-1-4",
            "v1-a1b2c3d4-3-99",
            "v1-a1b2c3d4-3-4-extra",
        ] {
            let seed = PayloadSeed::new(seed.as_bytes().to_vec(), limits()).unwrap();
            assert!(matches!(
                strategy.derive_one(PayloadVariantRole::Candidate, &seed, limits()),
                Err(PayloadStrategyError::DerivationFailed)
            ));
        }
    }
}
