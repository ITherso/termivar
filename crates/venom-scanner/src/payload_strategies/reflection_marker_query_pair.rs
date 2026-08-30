//! Bounded scanner-owned reflection marker pair.
//!
//! Both values are inert visible ASCII. They contain no HTML, JavaScript, URI,
//! quote, or delimiter syntax, so the context parser observes server placement
//! rather than syntax introduced by the probe itself.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

pub const REFLECTION_MARKER_QUERY_PAIR_ID: &str = "web.review.reflection.marker-query-pair";
pub const REFLECTION_MARKER_QUERY_PAIR_REVISION: u32 = 1;

#[derive(Debug, Clone)]
pub struct ReflectionMarkerQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl ReflectionMarkerQueryPairStrategy {
    pub fn new() -> Self {
        Self {
            reference: PayloadStrategyRef::new(
                REFLECTION_MARKER_QUERY_PAIR_ID,
                REFLECTION_MARKER_QUERY_PAIR_REVISION,
            )
            .expect("the reflection marker strategy identity is static and valid"),
        }
    }

    fn marker(seed: &[u8], role: PayloadVariantRole) -> Option<String> {
        let identity = std::str::from_utf8(seed).ok()?;
        if identity.len() != 32
            || !identity
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        let leg = match role {
            PayloadVariantRole::Control => "control",
            PayloadVariantRole::Candidate => "candidate",
        };
        Some(format!("venom-reflection-{leg}-{identity}-end"))
    }
}

impl Default for ReflectionMarkerQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for ReflectionMarkerQueryPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        let value =
            Self::marker(seed.as_bytes(), role).ok_or(PayloadStrategyError::DerivationFailed)?;
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
    fn pair_is_distinct_inert_bounded_and_versioned() {
        let strategy = ReflectionMarkerQueryPairStrategy::new();
        let seed =
            PayloadSeed::new(b"0123456789abcdef0123456789abcdef".to_vec(), limits()).unwrap();
        let control = strategy
            .derive_one(PayloadVariantRole::Control, &seed, limits())
            .unwrap();
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed, limits())
            .unwrap();
        assert_eq!(
            strategy.strategy_ref().to_string(),
            "web.review.reflection.marker-query-pair@1"
        );
        assert_ne!(control.as_bytes(), candidate.as_bytes());
        for value in [control.as_bytes(), candidate.as_bytes()] {
            assert!(value.len() <= 80);
            assert!(value
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-'));
        }
    }

    #[test]
    fn unbounded_or_noncanonical_seed_fails_closed() {
        let strategy = ReflectionMarkerQueryPairStrategy::new();
        for value in [
            "short",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdef0",
        ] {
            let seed = PayloadSeed::new(value.as_bytes().to_vec(), limits()).unwrap();
            assert!(matches!(
                strategy.derive_one(PayloadVariantRole::Candidate, &seed, limits()),
                Err(PayloadStrategyError::DerivationFailed)
            ));
        }
    }
}
