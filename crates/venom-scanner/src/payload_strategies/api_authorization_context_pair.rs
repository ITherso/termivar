//! Second production payload strategy: `api.authorization.context-pair@1`.
//!
//! This strategy derives a matched control/candidate pair that varies only the
//! authorization context of an otherwise identical request, so a strategy-aware
//! capability executor can measure how the same resource's visibility differs
//! between an anonymous and an authorized principal.
//!
//! The control leg is deliberately empty: an empty artifact instructs the HTTP
//! executor to omit the `authorization` header entirely, representing the
//! anonymous context. The candidate leg is the seed verbatim — the complete
//! authorization header value the host wants to test (for example
//! `Bearer <token>`). Derivation is a pure function of `(role, seed)` — no
//! clocks, randomness, knowledge state, or transport.
//!
//! The strategy only accepts header-safe seed bytes and never introduces control
//! characters, so a derived candidate is always a valid header value and cannot
//! perform header injection or request splitting at the derivation boundary.

use crate::payload_strategy::{
    PayloadArtifact, PayloadSeed, PayloadStrategy, PayloadStrategyError, PayloadStrategyLimits,
    PayloadStrategyRef, PayloadVariantRole,
};

/// Stable identity of this strategy, without its revision.
pub const API_AUTHORIZATION_CONTEXT_PAIR_ID: &str = "api.authorization.context-pair";

/// Deterministic implementation revision materialized by this module.
pub const API_AUTHORIZATION_CONTEXT_PAIR_REVISION: u32 = 1;

/// Request header this revision varies. The candidate leg applies the derived
/// artifact as this header's value; the control leg omits it.
pub const API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME: &str = "authorization";

/// Second production [`PayloadStrategy`]: an anonymous/authorized context pair.
#[derive(Debug, Clone)]
pub struct ApiAuthorizationContextPairStrategy {
    reference: PayloadStrategyRef,
}

impl ApiAuthorizationContextPairStrategy {
    /// Creates the strategy bound to its stable reference and revision.
    ///
    /// The reference identity is a compile-time constant, so construction only
    /// fails if the shared [`PayloadStrategyRef`] validation contract changes;
    /// that is treated as an unrecoverable programmer error.
    pub fn new() -> Self {
        let reference = PayloadStrategyRef::new(
            API_AUTHORIZATION_CONTEXT_PAIR_ID,
            API_AUTHORIZATION_CONTEXT_PAIR_REVISION,
        )
        .expect("api.authorization.context-pair@1 is a valid strategy reference");
        Self { reference }
    }

    /// Returns whether `bytes` are a safe, non-empty HTTP header value.
    ///
    /// Accepts a single interior run of visible ASCII and spaces, rejecting
    /// empty values, leading or trailing spaces, control characters (including
    /// CR and LF), and any non-ASCII byte. The candidate credential must satisfy
    /// this before it can be applied verbatim as a header value.
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

impl Default for ApiAuthorizationContextPairStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadStrategy for ApiAuthorizationContextPairStrategy {
    fn strategy_ref(&self) -> &PayloadStrategyRef {
        &self.reference
    }

    fn derive_one(
        &self,
        role: PayloadVariantRole,
        seed: &PayloadSeed,
        limits: PayloadStrategyLimits,
    ) -> Result<PayloadArtifact, PayloadStrategyError> {
        // Both legs require a valid candidate credential up front so the pair is
        // rejected deterministically regardless of which leg is derived first.
        if !Self::is_safe_header_value(seed.as_bytes()) {
            return Err(PayloadStrategyError::DerivationFailed);
        }

        let bytes = match role {
            // Anonymous context: an empty artifact omits the header downstream.
            PayloadVariantRole::Control => Vec::new(),
            // Authorized context: the seed is the complete header value.
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
        let strategy = ApiAuthorizationContextPairStrategy::new();
        assert_eq!(
            strategy.strategy_ref().id(),
            API_AUTHORIZATION_CONTEXT_PAIR_ID
        );
        assert_eq!(
            strategy.strategy_ref().revision(),
            API_AUTHORIZATION_CONTEXT_PAIR_REVISION
        );
        assert_eq!(
            strategy.strategy_ref().to_string(),
            "api.authorization.context-pair@1"
        );
    }

    #[test]
    fn control_is_anonymous_and_candidate_is_the_credential() {
        let strategy = ApiAuthorizationContextPairStrategy::new();

        let control = strategy
            .derive_one(
                PayloadVariantRole::Control,
                &seed(b"Bearer token"),
                limits(),
            )
            .unwrap();
        assert!(
            control.as_bytes().is_empty(),
            "control leg must be an empty (anonymous) artifact"
        );

        let candidate = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"Bearer token"),
                limits(),
            )
            .unwrap();
        assert_eq!(candidate.as_bytes(), b"Bearer token");
        assert_ne!(control.receipt().sha256(), candidate.receipt().sha256());
    }

    #[test]
    fn control_is_seed_independent_but_still_requires_a_valid_seed() {
        let strategy = ApiAuthorizationContextPairStrategy::new();
        let first = strategy
            .derive_one(PayloadVariantRole::Control, &seed(b"Bearer one"), limits())
            .unwrap();
        let second = strategy
            .derive_one(PayloadVariantRole::Control, &seed(b"Basic two"), limits())
            .unwrap();
        assert!(first.as_bytes().is_empty());
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn same_input_is_deterministic_across_repeats() {
        let strategy = ApiAuthorizationContextPairStrategy::new();
        let first = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed(b"Bearer t"), limits())
            .unwrap();
        let second = strategy
            .derive_one(PayloadVariantRole::Candidate, &seed(b"Bearer t"), limits())
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.receipt(), second.receipt());
    }

    #[test]
    fn derivation_is_deterministic_under_concurrency() {
        let strategy = Arc::new(ApiAuthorizationContextPairStrategy::new());
        let expected = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"Bearer probe"),
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
                            &seed(b"Bearer probe"),
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
        let strategy = ApiAuthorizationContextPairStrategy::new();
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
        let strategy = ApiAuthorizationContextPairStrategy::new();
        let tight = PayloadStrategyLimits::new(64, 4).unwrap();
        let seed = PayloadSeed::new(b"Bearer token".to_vec(), tight).unwrap();
        assert!(matches!(
            strategy.derive_one(PayloadVariantRole::Candidate, &seed, tight),
            Err(PayloadStrategyError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn resolves_and_revalidates_through_registry() {
        let strategy = ApiAuthorizationContextPairStrategy::new();
        let reference = strategy.strategy_ref().clone();
        let mut registry = PayloadStrategyRegistry::new();
        registry.register(Arc::new(strategy)).unwrap();

        let control = registry
            .derive_one(
                &reference,
                PayloadVariantRole::Control,
                &seed(b"Bearer token"),
                limits(),
            )
            .unwrap();
        let candidate = registry
            .derive_one(
                &reference,
                PayloadVariantRole::Candidate,
                &seed(b"Bearer token"),
                limits(),
            )
            .unwrap();
        assert!(control.as_bytes().is_empty());
        assert_eq!(candidate.as_bytes(), b"Bearer token");
    }

    #[test]
    fn raw_seed_never_enters_receipt_json() {
        let strategy = ApiAuthorizationContextPairStrategy::new();
        let artifact = strategy
            .derive_one(
                PayloadVariantRole::Candidate,
                &seed(b"Bearer secret-token"),
                limits(),
            )
            .unwrap();
        let receipt_json = serde_json::to_string(&artifact.receipt()).unwrap();
        let debug = format!("{artifact:?}");
        assert!(!receipt_json.contains("secret-token"));
        assert!(!debug.contains("secret-token"));
        assert_eq!(artifact.receipt().sha256().len(), 64);
    }
}
