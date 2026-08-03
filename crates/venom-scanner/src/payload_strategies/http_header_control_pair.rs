//! First production payload strategy: `http.header.control-pair@1`.
//!
//! This strategy derives a matched control/candidate pair for a single benign
//! request header so a strategy-aware capability executor can measure whether a
//! target responds differently to exactly one controlled header change. It is
//! deliberately the lowest-risk production strategy: it emits only visible ASCII
//! header-value bytes and can never introduce control characters, so it cannot
//! perform header injection or request splitting.
//!
//! The strategy operates on a fixed header for this revision. The control leg is
//! a conventional, seed-independent baseline (the "normal profile"); the
//! candidate leg is that baseline plus one controlled, seed-derived variation.
//! Derivation is a pure function of `(role, seed)` — no clocks, randomness,
//! knowledge state, or transport.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

/// Stable identity of this strategy, without its revision.
pub const HTTP_HEADER_CONTROL_PAIR_ID: &str = "http.header.control-pair";

/// Deterministic implementation revision materialized by this module.
pub const HTTP_HEADER_CONTROL_PAIR_REVISION: u32 = 1;

/// Request header this revision varies. A strategy-aware executor applies the
/// derived artifact bytes as the value of this header.
pub const HTTP_HEADER_CONTROL_PAIR_HEADER_NAME: &str = "accept";

/// Seed-independent baseline value used by the control leg.
const BASELINE_VALUE: &[u8] = b"*/*";

/// Prefix the candidate leg prepends before the controlled seed variation.
const CANDIDATE_PREFIX: &[u8] = b"*/*, ";

/// First production [`PayloadStrategy`]: a single-header control/candidate pair.
#[derive(Debug, Clone)]
pub struct HttpHeaderControlPairStrategy {
    reference: PayloadStrategyRef,
}

impl HttpHeaderControlPairStrategy {
    /// Creates the strategy bound to its stable reference and revision.
    ///
    /// The reference identity is a compile-time constant, so construction only
    /// fails if the shared [`PayloadStrategyRef`] validation contract changes;
    /// that is treated as an unrecoverable programmer error.
    pub fn new() -> Self {
        let reference = PayloadStrategyRef::new(
            HTTP_HEADER_CONTROL_PAIR_ID,
            HTTP_HEADER_CONTROL_PAIR_REVISION,
        )
        .expect("http.header.control-pair@1 is a valid strategy reference");
        Self { reference }
    }

    /// Returns whether `bytes` are a safe, non-empty HTTP header value.
    ///
    /// Accepts a single interior run of visible ASCII and spaces, rejecting
    /// empty values, leading or trailing spaces, control characters (including
    /// CR and LF), and any non-ASCII byte. This keeps every derived candidate a
    /// value a host transport can attach verbatim and forecloses request
    /// splitting at the derivation boundary.
    fn is_safe_header_value(bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') {
            return false;
        }
        bytes
            .iter()
            .all(|&byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
    }
}

impl Default for HttpHeaderControlPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for HttpHeaderControlPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        // Both legs require a valid candidate token up front so the pair is
        // rejected deterministically regardless of which leg is derived first.
        if !Self::is_safe_header_value(seed.as_bytes()) {
            return Err(PayloadStrategyError::DerivationFailed);
        }

        let bytes = match role {
            PayloadVariantRole::Control => BASELINE_VALUE.to_vec(),
            PayloadVariantRole::Candidate => {
                let mut bytes = Vec::with_capacity(CANDIDATE_PREFIX.len() + seed.len());
                bytes.extend_from_slice(CANDIDATE_PREFIX);
                bytes.extend_from_slice(seed.as_bytes());
                bytes
            },
        };

        PayloadArtifact::new(self.reference.clone(), role, bytes, limits)
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;
    use crate::payload_strategy::PayloadStrategyRegistry;

    fn limits() -> PayloadStrategyLimits {
        PayloadStrategyLimits::default()
    }

    fn seed(value: &[u8]) -> PayloadSeed {
        PayloadSeed::new(value.to_vec(), limits()).unwrap()
    }

    #[test]
    fn reference_is_stable_and_versioned() {
        let strategy = HttpHeaderControlPairStrategy::new();
        assert_eq!(strategy.strategy_ref().id(), HTTP_HEADER_CONTROL_PAIR_ID);
        assert_eq!(
            strategy.strategy_ref().revision(),
            HTTP_HEADER_CONTROL_PAIR_REVISION
        );
        assert_eq!(
            strategy.strategy_ref().to_string(),
            "http.header.control-pair@1"
        );
    }

    #[test]
    fn control_is_seed_independent_and_candidate_embeds_seed() {
        let strategy = HttpHeaderControlPairStrategy::new();

        let control_a = strategy
            .derive_one(PayloadVariantRole::Control, &seed(b"one"), limits())
            .unwrap();
        let control_b = strategy
            .derive_one(PayloadVariantRole::Control, &seed(b"different"), limits())
            .unwrap();
        assert_eq!(control_a.as_bytes(), b"*/*");
        assert_eq!(control_a.as_bytes(), control_b.as_bytes());

        let candidate = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"application/json"),
                limits(),
            )
            .unwrap();
        assert_eq!(candidate.as_bytes(), b"*/*, application/json");
        assert_ne!(candidate.as_bytes(), control_a.as_bytes());
    }

    #[test]
    fn same_input_is_deterministic_across_repeats() {
        let strategy = HttpHeaderControlPairStrategy::new();
        let first = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed(b"text/html"), limits())
            .unwrap();
        let second = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed(b"text/html"), limits())
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.receipt(), second.receipt());
    }

    #[test]
    fn derivation_is_deterministic_under_concurrency() {
        let strategy = Arc::new(HttpHeaderControlPairStrategy::new());
        let expected = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"probe-token"),
                limits(),
            )
            .unwrap();

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let strategy = Arc::clone(&strategy);
                thread::spawn(move || {
                    strategy
                        .derive_one(
                            PayloadVariantRole::Candidate,
                            &seed(b"probe-token"),
                            limits(),
                        )
                        .unwrap()
                        .receipt()
                })
            })
            .collect();

        for handle in handles {
            assert_eq!(handle.join().unwrap(), expected.receipt());
        }
    }

    #[test]
    fn unsafe_seeds_fail_closed_on_both_legs() {
        let strategy = HttpHeaderControlPairStrategy::new();
        for unsafe_seed in [
            b"".as_slice(),
            b" leading",
            b"trailing ",
            b"line\nbreak",
            b"carriage\rreturn",
            b"tab\ttoken",
            b"null\0byte",
        ] {
            let seed = PayloadSeed::new(unsafe_seed.to_vec(), limits()).unwrap();
            for role in [PayloadVariantRole::Control, PayloadVariantRole::Candidate] {
                assert!(
                    matches!(
                        strategy.derive_one(role, &seed, limits()),
                        Err(PayloadStrategyError::DerivationFailed)
                    ),
                    "expected fail-closed derivation for seed {unsafe_seed:?} role {role:?}"
                );
            }
        }
    }

    #[test]
    fn oversized_candidate_value_fails_closed() {
        let strategy = HttpHeaderControlPairStrategy::new();
        // Prefix is 5 bytes; a 4-byte artifact ceiling cannot hold prefix+seed.
        let tight = PayloadStrategyLimits::new(64, 4).unwrap();
        let seed = PayloadSeed::new(b"json".to_vec(), tight).unwrap();
        assert!(matches!(
            strategy.derive_one(PayloadVariantRole::Candidate, &seed, tight),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn resolves_and_revalidates_through_registry() {
        let strategy = HttpHeaderControlPairStrategy::new();
        let reference = strategy.strategy_ref().clone();
        let mut registry = PayloadStrategyRegistry::new();
        registry.register(Arc::new(strategy)).unwrap();

        let artifact = registry
            .derive_one(
                &reference,
                PayloadVariantRole::Candidate,
                &seed(b"application/json"),
                limits(),
            )
            .unwrap();
        assert_eq!(artifact.strategy(), &reference);
        assert_eq!(artifact.role(), PayloadVariantRole::Candidate);
        assert_eq!(artifact.as_bytes(), b"*/*, application/json");
    }

    #[test]
    fn raw_seed_never_enters_receipt_json() {
        let strategy = HttpHeaderControlPairStrategy::new();
        let artifact = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"secret-token-value"),
                limits(),
            )
            .unwrap();
        let receipt_json = serde_json::to_string(&artifact.receipt()).unwrap();
        let debug = format!("{artifact:?}");
        assert!(!receipt_json.contains("secret-token-value"));
        assert!(!debug.contains("secret-token-value"));
        assert_eq!(artifact.receipt().sha256().len(), 64);
    }
}
