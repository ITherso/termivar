//! Native matched external-URL query payload strategy.
//!
//! The control leg is empty, while the candidate leg copies one validated
//! absolute HTTPS URL under the reserved `.invalid` top-level domain. This
//! keeps the strategy inert and deterministic: it derives bytes only and never
//! follows or contacts the destination.

use url::Url;

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

/// Stable identity of this strategy, without its revision.
pub const EXTERNAL_URL_QUERY_PAIR_ID: &str = "web.review.external-url.query-pair";

/// Deterministic implementation revision materialized by this module.
pub const EXTERNAL_URL_QUERY_PAIR_REVISION: u32 = 1;

/// A query-free control/external-URL candidate pair for redirect or reflection review.
#[derive(Debug, Clone)]
pub struct ExternalUrlQueryPairStrategy {
    reference: PayloadStrategyRef,
}

impl ExternalUrlQueryPairStrategy {
    /// Creates the strategy bound to its stable reference and revision.
    pub fn new() -> Self {
        let reference =
            PayloadStrategyRef::new(EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
                .expect("web.review.external-url.query-pair@1 is a valid strategy reference");
        Self { reference }
    }

    /// Accepts a visible-ASCII absolute HTTPS URL below `.invalid` with no
    /// credentials or fragment.
    fn is_valid_external_url(bytes: &[u8]) -> bool {
        let Ok(raw) = std::str::from_utf8(bytes) else {
            return false;
        };
        if raw.is_empty() || !raw.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return false;
        }
        let Ok(parsed) = Url::parse(raw) else {
            return false;
        };
        if parsed.scheme() != "https" || parsed.fragment().is_some() {
            return false;
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || Self::authority_contains_userinfo(raw)
        {
            return false;
        }
        parsed
            .domain()
            .is_some_and(|domain| domain.len() > ".invalid".len() && domain.ends_with(".invalid"))
    }

    /// Detects even empty user-info (`https://@host/`), which URL accessors
    /// otherwise represent as an empty username and absent password.
    fn authority_contains_userinfo(raw: &str) -> bool {
        let Some((_, remainder)) = raw.split_once("://") else {
            return false;
        };
        let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
        remainder[..authority_end].contains('@')
    }
}

impl Default for ExternalUrlQueryPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for ExternalUrlQueryPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        // A control leg is useful only when its paired candidate is valid, so
        // validate the seed before deriving either role.
        if !Self::is_valid_external_url(seed.as_bytes()) {
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
        let strategy = ExternalUrlQueryPairStrategy::new();
        assert_eq!(strategy.strategy_ref().id(), EXTERNAL_URL_QUERY_PAIR_ID);
        assert_eq!(
            strategy.strategy_ref().revision(),
            EXTERNAL_URL_QUERY_PAIR_REVISION
        );
        assert_eq!(
            strategy.strategy_ref().to_string(),
            "web.review.external-url.query-pair@1"
        );
    }

    #[test]
    fn control_is_empty_and_candidate_is_the_exact_seed() {
        let strategy = ExternalUrlQueryPairStrategy::new();
        let candidate_seed = seed(b"https://nonce.review.invalid/landing?case=7");

        let control = strategy
            .derive_one(PayloadVariantRole::Control, &candidate_seed, limits())
            .unwrap();
        let candidate = strategy
            .derive_one(PayloadVariantRole::Candidate, &candidate_seed, limits())
            .unwrap();

        assert!(control.as_bytes().is_empty());
        assert_eq!(
            candidate.as_bytes(),
            b"https://nonce.review.invalid/landing?case=7"
        );
        assert_ne!(control.receipt().sha256(), candidate.receipt().sha256());
    }

    #[test]
    fn safe_invalid_tld_urls_with_ports_paths_and_queries_are_accepted() {
        let strategy = ExternalUrlQueryPairStrategy::new();
        for valid in [
            b"https://probe.invalid".as_slice(),
            b"https://probe.invalid/",
            b"https://nonce.review.invalid:8443/path",
            b"https://nonce.review.invalid/path?q=one%20two&next=%2F",
            b"HTTPS://nonce.review.invalid/path",
        ] {
            let artifact = strategy
                .derive_one(PayloadVariantRole::Candidate, &seed(valid), limits())
                .unwrap();
            assert_eq!(artifact.as_bytes(), valid);
        }
    }

    #[test]
    fn unsafe_or_non_external_urls_fail_closed_on_both_legs() {
        let strategy = ExternalUrlQueryPairStrategy::new();
        let invalid_seeds: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"probe.invalid/path".to_vec(),
            b"/relative".to_vec(),
            b"http://probe.invalid/".to_vec(),
            b"ftp://probe.invalid/".to_vec(),
            b"https://invalid/".to_vec(),
            b"https://probe.example/".to_vec(),
            b"https://probe.invalid.example/".to_vec(),
            b"https://127.0.0.1/".to_vec(),
            b"https://[::1]/".to_vec(),
            b"https://user@probe.invalid/".to_vec(),
            b"https://user:pass@probe.invalid/".to_vec(),
            b"https://@probe.invalid/".to_vec(),
            b"https://probe.invalid/path#fragment".to_vec(),
            b"https://probe.invalid/a b".to_vec(),
            b"https://probe.invalid/\r\nX-Test: injected".to_vec(),
            "https://pröbe.invalid/".as_bytes().to_vec(),
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
        let strategy = ExternalUrlQueryPairStrategy::new();
        let tight = PayloadStrategyLimits::new(128, 0).unwrap();
        let candidate_seed = PayloadSeed::new(b"https://probe.invalid/".to_vec(), tight).unwrap();

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
        let strategy = Arc::new(ExternalUrlQueryPairStrategy::new());
        let expected = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"https://parallel.invalid/review"),
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
                            &seed(b"https://parallel.invalid/review"),
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
        let strategy = ExternalUrlQueryPairStrategy::new();
        let reference = strategy.strategy_ref().clone();
        let mut registry = PayloadStrategyRegistry::new();
        registry.register(Arc::new(strategy)).unwrap();
        let candidate_seed = seed(b"https://registry.invalid/review");

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
        assert_eq!(candidate.as_bytes(), b"https://registry.invalid/review");
        assert_eq!(candidate.strategy(), &reference);
    }

    #[test]
    fn raw_seed_never_enters_debug_or_receipt_json() {
        let strategy = ExternalUrlQueryPairStrategy::new();
        let artifact = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"https://private-nonce.invalid/landing"),
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
