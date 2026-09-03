//! Transport-neutral contracts for bounded authorization differential review.
//!
//! This module owns no transport, request broker, runtime budget, credential
//! source, or report. It validates one declared policy and two host-supplied
//! principal contexts, captures four raw-value-free JSON views through the
//! existing API visibility comparator, and classifies their relationship.

use std::fmt;

use thiserror::Error;

use crate::{
    payload_strategies::ApiAuthorizationContextPairStrategy,
    payload_strategy::{PayloadSeed, PayloadStrategy, PayloadStrategyLimits, PayloadVariantRole},
};

mod comparison;
mod policy;

pub use comparison::{
    AuthorizationDifferentialError, AuthorizationDifferentialReceiptId,
    AuthorizationDifferentialResult, AuthorizationReviewBodyState, AuthorizationReviewMediaClass,
    AuthorizationReviewOutcome, AuthorizationReviewView, AuthorizationReviewViewError,
    AuthorizationViewReceiptId, AuthorizationViewRole, DimensionEquivalence,
};
pub use policy::{
    AuthorizationResourceScopeId, AuthorizationReviewExpectation, AuthorizationReviewMethod,
    AuthorizationReviewPolicy, AuthorizationReviewPolicyError, AuthorizationReviewPolicyId,
    AUTHORIZATION_REVIEW_ALGORITHM_VERSION, AUTHORIZATION_REVIEW_POLICY_SCHEMA,
    HARD_MAX_AUTHORIZATION_REVIEW_DIFF_PATHS, HARD_MAX_AUTHORIZATION_REVIEW_IGNORED_PATHS,
    HARD_MAX_AUTHORIZATION_REVIEW_PATH_BYTES, HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES,
    HARD_MAX_AUTHORIZATION_REVIEW_SELECTED_PATHS,
    HARD_MAX_AUTHORIZATION_REVIEW_UNORDERED_ARRAY_PATHS,
};

/// Host-supplied primary-principal `Authorization` header value.
///
/// The value is move-only, never serialized, and exposed only to the scanner's
/// request-composition boundary after a complete pair has been validated.
pub struct PrimaryAuthorizationPrincipal {
    value: String,
}

impl PrimaryAuthorizationPrincipal {
    /// Validates one complete bounded HTTP Authorization header value.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, AuthorizationPrincipalError> {
        Ok(Self {
            value: validate_authorization_header(value.into())?,
        })
    }
}

impl fmt::Debug for PrimaryAuthorizationPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrimaryAuthorizationPrincipal(<redacted>)")
    }
}

/// Host-supplied peer-principal `Authorization` header value.
///
/// The peer label denotes only a comparison role. It does not assert attacker,
/// privilege, ownership, tenant, or business-policy meaning.
pub struct PeerAuthorizationPrincipal {
    value: String,
}

impl PeerAuthorizationPrincipal {
    /// Validates one complete bounded HTTP Authorization header value.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, AuthorizationPrincipalError> {
        Ok(Self {
            value: validate_authorization_header(value.into())?,
        })
    }
}

impl fmt::Debug for PeerAuthorizationPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerAuthorizationPrincipal(<redacted>)")
    }
}

/// Exactly two distinct, role-bound principal contexts.
pub struct AuthorizationPrincipalPair {
    primary: PrimaryAuthorizationPrincipal,
    peer: PeerAuthorizationPrincipal,
}

/// Crate-private, move-only transfer into the native request-composition seam.
///
/// This type deliberately implements neither `Debug` nor serialization. The
/// role-bound values and their value-free distinctness proof move together, so
/// a runtime cannot accidentally detach the proof from the pair it validated.
pub(crate) struct AuthorizationPrincipalExecutionHandoff {
    pub(crate) primary_authorization: String,
    pub(crate) peer_authorization: String,
    pub(crate) proof: AuthorizationPrincipalPairProof,
}

impl AuthorizationPrincipalPair {
    /// Creates a pair and rejects identical credential bytes before any I/O.
    pub fn new(
        primary: PrimaryAuthorizationPrincipal,
        peer: PeerAuthorizationPrincipal,
    ) -> Result<Self, AuthorizationPrincipalError> {
        if primary.value.as_bytes() == peer.value.as_bytes() {
            return Err(AuthorizationPrincipalError::IdenticalCredentials);
        }
        Ok(Self { primary, peer })
    }

    /// Consumes both credentials and retains only the value-free proof.
    pub fn into_proof(self) -> AuthorizationPrincipalPairProof {
        let AuthorizationPrincipalExecutionHandoff {
            primary_authorization,
            peer_authorization,
            proof,
        } = self.into_execution_handoff();
        drop((primary_authorization, peer_authorization));
        proof
    }

    /// Atomically transfers both role-bound values and their distinctness proof
    /// to the crate-owned request-composition boundary.
    pub(crate) fn into_execution_handoff(self) -> AuthorizationPrincipalExecutionHandoff {
        AuthorizationPrincipalExecutionHandoff {
            primary_authorization: self.primary.value,
            peer_authorization: self.peer.value,
            proof: AuthorizationPrincipalPairProof { _private: () },
        }
    }
}

impl fmt::Debug for AuthorizationPrincipalPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationPrincipalPair(<redacted>)")
    }
}

/// Value-free evidence that a distinct primary/peer pair was checked.
///
/// Its field is private, so comparison authority cannot be minted with a
/// public struct literal. This proof carries no credential identity.
#[derive(PartialEq, Eq)]
pub struct AuthorizationPrincipalPairProof {
    _private: (),
}

impl fmt::Debug for AuthorizationPrincipalPairProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationPrincipalPairProof(<redacted>)")
    }
}

/// Static, value-free principal validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum AuthorizationPrincipalError {
    /// One value was empty, unsafe, non-ASCII, or above the shared ceiling.
    #[error("authorization principal is not a bounded safe HTTP header value")]
    InvalidValue,
    /// Distinct roles cannot disguise the same credential bytes.
    #[error("authorization review requires distinct principal credentials")]
    IdenticalCredentials,
}

fn validate_authorization_header(value: Vec<u8>) -> Result<String, AuthorizationPrincipalError> {
    let limits = PayloadStrategyLimits::default();
    let seed =
        PayloadSeed::new(value, limits).map_err(|_| AuthorizationPrincipalError::InvalidValue)?;
    let artifact = ApiAuthorizationContextPairStrategy::new()
        .derive_one(PayloadVariantRole::Candidate, &seed, limits)
        .map_err(|_| AuthorizationPrincipalError::InvalidValue)?;
    String::from_utf8(artifact.as_bytes().to_vec())
        .map_err(|_| AuthorizationPrincipalError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY_SECRET: &str = "PRIMARY-AUTHORIZATION-MUST-NOT-LEAK-7C3A19";
    const PEER_SECRET: &str = "PEER-AUTHORIZATION-MUST-NOT-LEAK-82FD44";

    fn principals() -> AuthorizationPrincipalPair {
        AuthorizationPrincipalPair::new(
            PrimaryAuthorizationPrincipal::new(format!("Bearer {PRIMARY_SECRET}")).unwrap(),
            PeerAuthorizationPrincipal::new(format!("Bearer {PEER_SECRET}")).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn principal_pair_is_distinct_move_only_and_value_free() {
        let pair = principals();
        let rendered = format!("{pair:?}");
        assert!(!rendered.contains(PRIMARY_SECRET));
        assert!(!rendered.contains(PEER_SECRET));
        assert_eq!(
            format!("{:?}", pair.into_proof()),
            "AuthorizationPrincipalPairProof(<redacted>)"
        );
    }

    #[test]
    fn execution_handoff_keeps_roles_and_proof_atomic() {
        let handoff = principals().into_execution_handoff();
        assert_eq!(
            handoff.primary_authorization,
            format!("Bearer {PRIMARY_SECRET}")
        );
        assert_eq!(handoff.peer_authorization, format!("Bearer {PEER_SECRET}"));
        assert_eq!(
            format!("{:?}", handoff.proof),
            "AuthorizationPrincipalPairProof(<redacted>)"
        );
    }

    #[test]
    fn identical_credentials_are_rejected_without_echoing_values() {
        let error = AuthorizationPrincipalPair::new(
            PrimaryAuthorizationPrincipal::new("Bearer same").unwrap(),
            PeerAuthorizationPrincipal::new("Bearer same").unwrap(),
        )
        .unwrap_err();
        assert_eq!(error, AuthorizationPrincipalError::IdenticalCredentials);
        assert!(!error.to_string().contains("Bearer"));
        assert!(!format!("{error:?}").contains("same"));
    }

    #[test]
    fn unsafe_and_oversized_credentials_fail_closed() {
        for invalid in [
            b"".as_slice(),
            b" leading",
            b"trailing ",
            b"line\nbreak",
            b"carriage\rreturn",
            b"tab\tvalue",
            b"null\0value",
            &[0xff],
        ] {
            assert_eq!(
                PrimaryAuthorizationPrincipal::new(invalid.to_vec()).unwrap_err(),
                AuthorizationPrincipalError::InvalidValue
            );
            assert_eq!(
                PeerAuthorizationPrincipal::new(invalid.to_vec()).unwrap_err(),
                AuthorizationPrincipalError::InvalidValue
            );
        }

        let oversized = vec![b'x'; crate::DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES as usize + 1];
        assert_eq!(
            PrimaryAuthorizationPrincipal::new(oversized.clone()).unwrap_err(),
            AuthorizationPrincipalError::InvalidValue
        );
        assert_eq!(
            PeerAuthorizationPrincipal::new(oversized).unwrap_err(),
            AuthorizationPrincipalError::InvalidValue
        );
    }

    #[test]
    fn role_debug_is_exactly_redacted() {
        let primary =
            PrimaryAuthorizationPrincipal::new(format!("Bearer {PRIMARY_SECRET}")).unwrap();
        let peer = PeerAuthorizationPrincipal::new(format!("Bearer {PEER_SECRET}")).unwrap();
        assert_eq!(
            format!("{primary:?}"),
            "PrimaryAuthorizationPrincipal(<redacted>)"
        );
        assert_eq!(
            format!("{peer:?}"),
            "PeerAuthorizationPrincipal(<redacted>)"
        );
    }
}
