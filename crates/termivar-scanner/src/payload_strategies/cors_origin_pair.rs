//! Native matched CORS-origin payload strategy.
//!
//! The control leg is an empty artifact, which tells the owning HTTP executor
//! to omit `Origin`. The candidate leg is one canonical ASCII HTTP(S) origin,
//! copied verbatim from the seed. Derivation is pure and performs no network or
//! knowledge-store work.

use url::Url;

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

/// Stable identity of this strategy, without its revision.
pub const CORS_ORIGIN_PAIR_ID: &str = "web.review.cors.origin-pair";

/// Deterministic implementation revision materialized by this module.
pub const CORS_ORIGIN_PAIR_REVISION: u32 = 1;

/// Header varied by the candidate leg. An empty control artifact omits it.
pub const CORS_ORIGIN_PAIR_HEADER_NAME: &str = "origin";

/// A no-Origin/candidate-Origin matched pair for bounded CORS review.
#[derive(Debug, Clone)]
pub struct CorsOriginPairStrategy {
    reference: PayloadStrategyRef,
}

impl CorsOriginPairStrategy {
    /// Creates the strategy bound to its stable reference and revision.
    pub fn new() -> Self {
        let reference = PayloadStrategyRef::new(CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION)
            .expect("web.review.cors.origin-pair@1 is a valid strategy reference");
        Self { reference }
    }

    /// Accepts only the canonical ASCII serialization of an HTTP(S) origin.
    ///
    /// Comparing against the URL implementation's origin serialization rejects
    /// paths, queries, fragments, credentials, control characters, and alternate
    /// representations while preserving one exact candidate byte sequence.
    fn is_valid_origin(bytes: &[u8]) -> bool {
        let Ok(raw) = std::str::from_utf8(bytes) else {
            return false;
        };
        if raw.is_empty() || !raw.is_ascii() {
            return false;
        }
        let Ok(parsed) = Url::parse(raw) else {
            return false;
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            return false;
        }
        parsed.origin().ascii_serialization() == raw
    }
}

impl Default for CorsOriginPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for CorsOriginPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        // Validate the candidate before deriving either leg so requesting the
        // control first cannot make an invalid pair appear usable.
        if !Self::is_valid_origin(seed.as_bytes()) {
            return Err(PayloadStrategyError::DerivationFailed);
        }

        let bytes = match role {
            PayloadVariantRole::Control => Vec::new(),
            PayloadVariantRole::Candidate => seed.as_bytes().to_vec(),
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
        let strategy = CorsOriginPairStrategy::new();
        assert_eq!(strategy.strategy_ref().id(), CORS_ORIGIN_PAIR_ID);
        assert_eq!(
            strategy.strategy_ref().revision(),
            CORS_ORIGIN_PAIR_REVISION
        );
        assert_eq!(
            strategy.strategy_ref().to_string(),
            "web.review.cors.origin-pair@1"
        );
        assert_eq!(CORS_ORIGIN_PAIR_HEADER_NAME, "origin");
    }

    #[test]
    fn control_omits_origin_and_candidate_is_the_exact_seed() {
        let strategy = CorsOriginPairStrategy::new();
        let candidate_seed = seed(b"https://nonce.review.invalid:8443");

        let control = strategy
            .derive_one(PayloadVariantRole::Control, &candidate_seed, limits())
            .unwrap();
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &candidate_seed, limits())
            .unwrap();

        assert!(control.as_bytes().is_empty());
        assert_eq!(candidate.as_bytes(), b"https://nonce.review.invalid:8443");
        assert_ne!(control.receipt().sha256(), candidate.receipt().sha256());
    }

    #[test]
    fn canonical_http_and_https_origins_are_accepted() {
        let strategy = CorsOriginPairStrategy::new();
        for valid in [
            b"http://example.test".as_slice(),
            b"https://example.test",
            b"https://example.test:8443",
            b"http://[2001:db8::1]:8080",
        ] {
            let artifact = strategy
                .derive_one(PayloadVariantRole::Candidate, &seed(valid), limits())
                .unwrap();
            assert_eq!(artifact.as_bytes(), valid);
        }
    }

    #[test]
    fn non_origins_fail_closed_on_both_legs() {
        let strategy = CorsOriginPairStrategy::new();
        let invalid_seeds: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"example.test".to_vec(),
            b"/relative".to_vec(),
            b"ftp://example.test".to_vec(),
            b"https://example.test/".to_vec(),
            b"https://example.test/path".to_vec(),
            b"https://example.test?q=1".to_vec(),
            b"https://example.test#fragment".to_vec(),
            b"https://user@example.test".to_vec(),
            b"https://example.test:443".to_vec(),
            b"HTTPS://example.test".to_vec(),
            b"https://EXAMPLE.test".to_vec(),
            b"https://example.test\r\nX-Test: injected".to_vec(),
            "https://exämple.test".as_bytes().to_vec(),
            vec![0xff],
        ];

        for invalid in invalid_seeds {
            let invalid = seed(&invalid);
            for role in [PayloadVariantRole::Control, PayloadVariantRole::Candidate] {
                assert!(matches!(
                    strategy.derive_one(role, &invalid, limits()),
                    Err(PayloadStrategyError::DerivationFailed)
                ));
            }
        }
    }

    #[test]
    fn output_envelope_is_enforced_after_validation() {
        let strategy = CorsOriginPairStrategy::new();
        let tight = PayloadStrategyLimits::new(128, 0).unwrap();
        let candidate_seed = PayloadSeed::new(b"https://probe.invalid".to_vec(), tight).unwrap();

        assert!(strategy
            .derive_one(PayloadVariantRole::Control, &candidate_seed, tight)
            .unwrap()
            .as_bytes()
            .is_empty());
        assert!(matches!(
            strategy.derive_one(PayloadVariantRole::Candidate, &candidate_seed, tight),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn derivation_is_repeatable_and_concurrency_safe() {
        let strategy = Arc::new(CorsOriginPairStrategy::new());
        let expected = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"https://parallel.invalid"),
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
                            &seed(b"https://parallel.invalid"),
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

    #[test]
    fn registry_resolution_preserves_the_pair_and_provenance() {
        let strategy = CorsOriginPairStrategy::new();
        let reference = strategy.strategy_ref().clone();
        let mut registry = PayloadStrategyRegistry::new();
        registry.register(Arc::new(strategy)).unwrap();
        let candidate_seed = seed(b"https://registry.invalid");

        let control = registry
            .derive_one(
                &reference,
                PayloadVariantRole::Control,
                &candidate_seed,
                limits(),
            )
            .unwrap();
        let candidate = registry
            .derive_one(
                &reference,
                PayloadVariantRole::Candidate,
                &candidate_seed,
                limits(),
            )
            .unwrap();
        assert!(control.as_bytes().is_empty());
        assert_eq!(candidate.as_bytes(), b"https://registry.invalid");
        assert_eq!(candidate.strategy(), &reference);
    }

    #[test]
    fn raw_seed_never_enters_debug_or_receipt_json() {
        let strategy = CorsOriginPairStrategy::new();
        let artifact = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"https://private-nonce.invalid"),
                limits(),
            )
            .unwrap();
        let output = format!(
            "{strategy:?} {artifact:?} {}",
            serde_json::to_string(&artifact.receipt()).unwrap()
        );
        assert!(!output.contains("private-nonce"));
        assert!(output.contains("<redacted>"));
        assert_eq!(artifact.receipt().sha256().len(), 64);
    }
}
