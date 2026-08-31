//! Native, built-in [`crate::payload_strategy::PayloadStrategy`]
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (concrete planner-selected payload strategies).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//! implementations and their registry.
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
pub mod cors_origin_pair;
pub mod encoding;
pub mod external_url_query_pair;
pub mod http_header_control_pair;
pub mod reflection_marker_query_pair;
pub mod sql_quote_balance_query_pair;
pub mod ssti_arithmetic_expression_pair;
pub mod xss_attribute_boundary_query_pair;
pub mod xss_structural_query_pair;

pub use api_authorization_context_pair::{
    ApiAuthorizationContextPairStrategy, API_AUTHORIZATION_CONTEXT_PAIR_HEADER_NAME,
    API_AUTHORIZATION_CONTEXT_PAIR_ID, API_AUTHORIZATION_CONTEXT_PAIR_REVISION,
};
pub use cors_origin_pair::{
    CorsOriginPairStrategy, CORS_ORIGIN_PAIR_HEADER_NAME, CORS_ORIGIN_PAIR_ID,
    CORS_ORIGIN_PAIR_REVISION,
};
pub use encoding::{encode_into_artifact, hex_encode, percent_encode, PayloadEncoding};
pub use external_url_query_pair::{
    ExternalUrlQueryPairStrategy, EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION,
};
pub use http_header_control_pair::{
    HttpHeaderControlPairStrategy, HTTP_HEADER_CONTROL_PAIR_HEADER_NAME,
    HTTP_HEADER_CONTROL_PAIR_ID, HTTP_HEADER_CONTROL_PAIR_REVISION,
};
pub use reflection_marker_query_pair::{
    ReflectionMarkerQueryPairStrategy, REFLECTION_MARKER_QUERY_PAIR_ID,
    REFLECTION_MARKER_QUERY_PAIR_REVISION,
};
pub use sql_quote_balance_query_pair::{
    SqlQuoteBalanceQueryPairStrategy, SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
    SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
};
pub use ssti_arithmetic_expression_pair::{
    SstiArithmeticExpressionPairStrategy, SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
    SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
};
pub use xss_attribute_boundary_query_pair::{
    XssAttributeBoundaryQueryPairStrategy, XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
    XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
};
pub use xss_structural_query_pair::{
    XssStructuralQueryPairStrategy, XSS_STRUCTURAL_QUERY_PAIR_ID,
    XSS_STRUCTURAL_QUERY_PAIR_REVISION,
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
    registry.register(Arc::new(CorsOriginPairStrategy::new()))?;
    registry.register(Arc::new(ExternalUrlQueryPairStrategy::new()))?;
    registry.register(Arc::new(ReflectionMarkerQueryPairStrategy::new()))?;
    registry.register(Arc::new(SqlQuoteBalanceQueryPairStrategy::new()))?;
    registry.register(Arc::new(SstiArithmeticExpressionPairStrategy::new()))?;
    registry.register(Arc::new(XssAttributeBoundaryQueryPairStrategy::new()))?;
    registry.register(Arc::new(XssStructuralQueryPairStrategy::new()))?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_strategy::{
        PayloadSeed, PayloadStrategyLimits, PayloadStrategyRef, PayloadVariantRole,
    };

    #[test]
    fn standard_registry_registers_every_built_in_strategy() {
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
        let cors_origin_pair =
            PayloadStrategyRef::new(CORS_ORIGIN_PAIR_ID, CORS_ORIGIN_PAIR_REVISION).unwrap();
        let external_url_query_pair =
            PayloadStrategyRef::new(EXTERNAL_URL_QUERY_PAIR_ID, EXTERNAL_URL_QUERY_PAIR_REVISION)
                .unwrap();
        let reflection_marker_pair = PayloadStrategyRef::new(
            REFLECTION_MARKER_QUERY_PAIR_ID,
            REFLECTION_MARKER_QUERY_PAIR_REVISION,
        )
        .unwrap();

        let sql_quote_pair = PayloadStrategyRef::new(
            SQL_QUOTE_BALANCE_QUERY_PAIR_ID,
            SQL_QUOTE_BALANCE_QUERY_PAIR_REVISION,
        )
        .unwrap();

        let ssti_arithmetic_pair = PayloadStrategyRef::new(
            SSTI_ARITHMETIC_EXPRESSION_PAIR_ID,
            SSTI_ARITHMETIC_EXPRESSION_PAIR_REVISION,
        )
        .unwrap();

        let xss_structural_pair = PayloadStrategyRef::new(
            XSS_STRUCTURAL_QUERY_PAIR_ID,
            XSS_STRUCTURAL_QUERY_PAIR_REVISION,
        )
        .unwrap();

        let xss_attribute_boundary_pair = PayloadStrategyRef::new(
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_ID,
            XSS_ATTRIBUTE_BOUNDARY_QUERY_PAIR_REVISION,
        )
        .unwrap();

        assert_eq!(registry.len(), 9);
        assert!(registry.contains(&header_pair));
        assert!(registry.contains(&authorization_pair));
        assert!(registry.contains(&cors_origin_pair));
        assert!(registry.contains(&external_url_query_pair));
        assert!(registry.contains(&reflection_marker_pair));
        assert!(registry.contains(&sql_quote_pair));
        assert!(registry.contains(&ssti_arithmetic_pair));
        assert!(registry.contains(&xss_attribute_boundary_pair));
        assert!(registry.contains(&xss_structural_pair));
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
