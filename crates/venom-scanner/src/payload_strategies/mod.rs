//! Native, production [`PayloadStrategy`] implementations and their registry.
//!
//! The contract module [`crate::payload_strategy`] defines the deterministic,
//! bounded, redacted boundary a planner-selected strategy must honor. This
//! module holds the concrete implementations of that contract and the builder
//! that registers the strategies a standard profile may resolve.
//!
//! Implementations here are pure functions of `(role, seed, limits)`. Adding a
//! strategy requires repeat and concurrency conformance tests before it is
//! registered by [`standard_payload_strategies`].

use std::sync::Arc;

use crate::payload_strategy::{PayloadStrategyError, PayloadStrategyRegistry};

pub mod api_authorization_context_pair;
pub mod encoding;
pub mod http_header_control_pair;
pub mod normalization;

pub use api_authorization_context_pair::{
    ApiAuthorizationContextPairStrategy, API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME,
    API_AUTHORIZATION_CONTEXT_PAIR_ID, API_AUTHORIZATION_CONTEXT_PAIR_REVISION,
};
pub use encoding::{apply_evasion, encode_into_artifact, EvasionTechnique};
pub use http_header_control_pair::{
    HttpHeaderControlPairStrategy, HTTP_HEADER_CONTROL_PAIR_HEADER_NAME,
    HTTP_HEADER_CONTROL_PAIR_ID, HTTP_HEADER_CONTROL_PAIR_REVISION,
};

/// Builds the registry of payload strategies a standard profile may resolve.
///
/// Every entry is a native, conformance-tested implementation. Registration is
/// deterministic and order-independent, and a duplicate identity is a
/// programmer error surfaced as [`PayloadStrategyError::StrategyIdentityConflict`].
pub fn standard_payload_strategies() -> Result<PayloadStrategyRegistry, PayloadStrategyError> {
    let mut registry = PayloadStrategyRegistry::new();
    registry.register(Arc::new(HttpHeaderControlPairStrategy::new()))?;
    registry.register(Arc::new(ApiAuthorizationContextPairStrategy::new()))?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_strategy::{
        PayloadSeed, PayloadStrategyLimits, PayloadStrategyRef, PayloadVariantRole,
    };

    #[test]
    fn standard_registry_registers_every_production_strategy() {
        let registry = standard_payload_strategies().unwrap();
        let header_pair = PayloadStrategyRef::new(
            HTTP_HEADER_CONTROL_PAIR_ID,
            HTTP_HEADER_CONTROL_PAIR_REVISION,
        )
        .unwrap();
        let authorization_pair = PayloadStrategyRef::new(
            API_AUTHORIZATION_CONTEXT_PAIR_ID,
            API_AUTHORIZATION_CONTEXT_PAIR_REVISION,
        )
        .unwrap();

        assert_eq!(registry.len(), 2);
        assert!(registry.contains(&header_pair));
        assert!(registry.contains(&authorization_pair));
    }

    #[test]
    fn standard_registry_can_derive_a_pair_for_its_strategy() {
        let registry = standard_payload_strategies().unwrap();
        let reference = PayloadStrategyRef::new(
            HTTP_HEADER_CONTROL_PAIR_ID,
            HTTP_HEADER_CONTROL_PAIR_REVISION,
        )
        .unwrap();
        let limits = PayloadStrategyLimits::default();
        let seed = PayloadSeed::new(b"application/json".to_vec(), limits).unwrap();

        let control = registry
            .derive_one(&reference, PayloadVariantRole::Control, &seed, limits)
            .unwrap();
        let candidate = registry
            .derive_one(&reference, PayloadVariantRole::Candidate, &seed, limits)
            .unwrap();

        assert_eq!(control.as_bytes(), b"*/*");
        assert_eq!(candidate.as_bytes(), b"*/*, application/json");
        assert_ne!(control.receipt().sha256(), candidate.receipt().sha256());
    }
}
