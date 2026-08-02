//! Versioned, policy-projected API visibility comparison.
//!
//! This module is additive to the legacy comparator. It keeps the legacy wire
//! contract and signatures unchanged while giving replayable comparisons an
//! explicit projection policy, canonicalization version, and bounded path-only
//! explanation. Raw JSON values and clear-text observed paths are never stored.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use venom_core::{
    ApiSurfaceKind, ApiVisibilityComparison, ApiVisibilityDimension, ApiVisibilityObservation,
    ApiVisibilityPairKind, ApiVisibilityResult, ApiVocabularyError, ConfidenceScore, Evidence,
};

use crate::api_evidence::{
    canonical_signatures, opaque_handle, ApiVisibilityComparator, ApiVisibilityEvidenceError,
    ApiVisibilityLimits,
};

mod canonical;
mod diff;
mod policy;

use canonical::ProfiledCanonicalState;
use diff::{visibility_diff, PathFingerprint};
pub use diff::{PathDigest, RedactedVisibilityDiff};
use policy::{decode_digest, encode_digest, update_framed};
pub use policy::{
    ApiComparisonProfile, CanonicalizationVersion, ComparisonAlgorithmVersion, JsonPathPattern,
    ProjectionPolicyId, CURRENT_API_COMPARISON_ALGORITHM_VERSION,
    CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION, DEFAULT_API_VISIBILITY_DIFF_PATHS,
    HARD_MAX_API_COMPARISON_PATH_BYTES, HARD_MAX_API_COMPARISON_PATH_DEPTH,
    HARD_MAX_API_COMPARISON_PROFILE_PATHS, HARD_MAX_API_VISIBILITY_DIFF_PATHS,
};

const PROFILED_COMPARISON_ID_DOMAIN: &[u8] = b"venom.api-visibility.comparison-id.v3\0";

/// Availability of a bounded path explanation for one comparison result.
///
/// This derived disposition prevents consumers from treating an empty path
/// list as proof that two views were equivalent. Status-only differences and
/// structural changes that cannot be represented by the current path index
/// deliberately remain [`Self::DifferenceWithoutPathSummary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VisibilityExplanationDisposition {
    /// The selected comparison dimension was equivalent.
    NoDifference,
    /// At least one path difference was observed, retained, or quota-omitted.
    PathSummary {
        /// Number of redacted path digests retained by the comparison.
        retained: u16,
        /// Number of observed path differences omitted by the profile quota.
        omitted: u32,
    },
    /// The dimension differed without a representable path-level summary.
    DifferenceWithoutPathSummary,
}

/// Raw-value-free view captured under one explicit projection profile.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfiledApiVisibilityView {
    context_id: String,
    resource_scope_id: String,
    surface: ApiSurfaceKind,
    status: u16,
    resource_signature: [u8; 32],
    field_signature: [u8; 32],
    path_index: BTreeMap<PathDigest, PathFingerprint>,
    limits: ApiVisibilityLimits,
    comparator_version: ComparisonAlgorithmVersion,
    canonicalization_version: CanonicalizationVersion,
    projection_policy_id: ProjectionPolicyId,
}

impl ProfiledApiVisibilityView {
    /// Returns the opaque authorization or presentation context.
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the opaque logical-resource scope.
    pub fn resource_scope_id(&self) -> &str {
        &self.resource_scope_id
    }

    /// Returns the declared API surface.
    pub const fn surface(&self) -> ApiSurfaceKind {
        self.surface
    }

    /// Returns the exact validated HTTP response status.
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the capture resource envelope.
    pub const fn limits(&self) -> ApiVisibilityLimits {
        self.limits
    }

    /// Returns the comparator version used to capture this view.
    pub const fn comparator_version(&self) -> ComparisonAlgorithmVersion {
        self.comparator_version
    }

    /// Returns the canonicalization version used to capture this view.
    pub const fn canonicalization_version(&self) -> CanonicalizationVersion {
        self.canonicalization_version
    }

    /// Returns the projection policy digest used to capture this view.
    pub const fn projection_policy_id(&self) -> ProjectionPolicyId {
        self.projection_policy_id
    }
}

impl fmt::Debug for ProfiledApiVisibilityView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfiledApiVisibilityView")
            .field("context_id", &"<redacted>")
            .field("resource_scope_id", &"<redacted>")
            .field("surface", &self.surface)
            .field("status", &self.status)
            .field("resource_signature", &"<redacted>")
            .field("field_signature", &"<redacted>")
            .field("path_index", &"<redacted>")
            .field("limits", &self.limits)
            .field("comparator_version", &self.comparator_version)
            .field("canonicalization_version", &self.canonicalization_version)
            .field("projection_policy_id", &self.projection_policy_id)
            .finish()
    }
}

/// Replayable profiled-comparator envelope.
///
/// The nested `comparison` intentionally preserves the legacy nine-field core
/// contract. Version and projection metadata live beside it so a legacy
/// deserializer cannot silently discard them. Persist this envelope, not only
/// the nested comparison, when deterministic replay matters.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ProfiledApiVisibilityComparison {
    comparison: ApiVisibilityComparison,
    comparator_version: ComparisonAlgorithmVersion,
    canonicalization_version: CanonicalizationVersion,
    projection_policy_id: ProjectionPolicyId,
    limits: ApiVisibilityLimits,
    diff: RedactedVisibilityDiff,
}

impl ProfiledApiVisibilityComparison {
    /// Returns the legacy typed comparison nested in this envelope.
    pub const fn comparison(&self) -> &ApiVisibilityComparison {
        &self.comparison
    }

    /// Returns the deterministic comparator version.
    pub const fn comparator_version(&self) -> ComparisonAlgorithmVersion {
        self.comparator_version
    }

    /// Returns the deterministic canonicalization version.
    pub const fn canonicalization_version(&self) -> CanonicalizationVersion {
        self.canonicalization_version
    }

    /// Returns the exact projection policy digest.
    pub const fn projection_policy_id(&self) -> ProjectionPolicyId {
        self.projection_policy_id
    }

    /// Returns the resource envelope used for both captured views.
    pub const fn limits(&self) -> ApiVisibilityLimits {
        self.limits
    }

    /// Returns the bounded, raw-value-free explanation.
    pub const fn diff(&self) -> &RedactedVisibilityDiff {
        &self.diff
    }

    /// Classifies whether this result has a bounded path-level explanation.
    ///
    /// An empty [`RedactedVisibilityDiff`] is not equivalent to an equivalent
    /// comparison. For example, status differences and ordered-array reorders
    /// can be real differences without a path summary in the current model.
    pub fn explanation_disposition(&self) -> VisibilityExplanationDisposition {
        match self.comparison.result() {
            ApiVisibilityResult::Equivalent => VisibilityExplanationDisposition::NoDifference,
            ApiVisibilityResult::Different => {
                let retained = self.diff.retained_diff_count();
                let omitted = self.diff.omitted_diff_count();
                if retained == 0 && omitted == 0 {
                    VisibilityExplanationDisposition::DifferenceWithoutPathSummary
                } else {
                    VisibilityExplanationDisposition::PathSummary { retained, omitted }
                }
            },
            _ => VisibilityExplanationDisposition::DifferenceWithoutPathSummary,
        }
    }

    /// Consumes the envelope and returns its explicit components.
    pub fn into_parts(
        self,
    ) -> (
        ApiVisibilityComparison,
        ComparisonAlgorithmVersion,
        CanonicalizationVersion,
        ProjectionPolicyId,
        ApiVisibilityLimits,
        RedactedVisibilityDiff,
    ) {
        (
            self.comparison,
            self.comparator_version,
            self.canonicalization_version,
            self.projection_policy_id,
            self.limits,
            self.diff,
        )
    }

    /// Emits the legacy observation while the caller retains this envelope for replay.
    pub fn to_observation(
        &self,
        component: impl Into<String>,
        reliability: ConfidenceScore,
    ) -> Result<ApiVisibilityObservation, ApiVocabularyError> {
        self.comparison.to_observation(component, reliability)
    }

    /// Emits detached legacy evidence while the caller retains this envelope for replay.
    pub fn to_evidence(
        &self,
        component: impl Into<String>,
        reliability: ConfidenceScore,
    ) -> Result<Evidence, ApiVocabularyError> {
        self.comparison.to_evidence(component, reliability)
    }
}

impl fmt::Debug for ProfiledApiVisibilityComparison {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfiledApiVisibilityComparison")
            .field("comparison", &"<redacted>")
            .field("comparator_version", &self.comparator_version)
            .field("canonicalization_version", &self.canonicalization_version)
            .field("projection_policy_id", &self.projection_policy_id)
            .field("limits", &self.limits)
            .field("diff", &self.diff)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ProfiledApiVisibilityComparison {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireComparison {
            comparison: ApiVisibilityComparison,
            comparator_version: ComparisonAlgorithmVersion,
            canonicalization_version: CanonicalizationVersion,
            projection_policy_id: ProjectionPolicyId,
            limits: ApiVisibilityLimits,
            diff: RedactedVisibilityDiff,
        }

        let wire = WireComparison::deserialize(deserializer)?;
        if wire.comparator_version != CURRENT_API_COMPARISON_ALGORITHM_VERSION {
            return Err(serde::de::Error::custom(
                "persisted API comparison uses an unsupported comparator version",
            ));
        }
        if wire.canonicalization_version != CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION {
            return Err(serde::de::Error::custom(
                "persisted API comparison uses an unsupported canonicalization version",
            ));
        }
        if !comparison_id_matches_metadata(
            wire.comparison.comparison_id(),
            wire.comparator_version,
            wire.canonicalization_version,
            wire.projection_policy_id,
        ) {
            return Err(serde::de::Error::custom(
                "profiled API comparison identity is not bound to its replay metadata",
            ));
        }
        let diff_matches_semantics = match (wire.comparison.result(), wire.comparison.dimension()) {
            (ApiVisibilityResult::Equivalent, _) => wire.diff.is_empty(),
            (ApiVisibilityResult::Different, ApiVisibilityDimension::Status) => {
                wire.diff.is_empty()
            },
            (ApiVisibilityResult::Different, ApiVisibilityDimension::Fields) => {
                wire.diff.changed_value_path_hashes().is_empty()
            },
            (ApiVisibilityResult::Different, ApiVisibilityDimension::Resources) => true,
            _ => false,
        };
        if !diff_matches_semantics {
            return Err(serde::de::Error::custom(
                "profiled API comparison diff is incompatible with v3 result semantics",
            ));
        }
        Ok(Self {
            comparison: wire.comparison,
            comparator_version: wire.comparator_version,
            canonicalization_version: wire.canonicalization_version,
            projection_policy_id: wire.projection_policy_id,
            limits: wire.limits,
            diff: wire.diff,
        })
    }
}

/// Validation, capture, and comparison failures for the profiled comparator.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProfiledApiVisibilityError {
    /// A legacy capture invariant or bounded canonicalization check failed.
    #[error(transparent)]
    Evidence(#[from] ApiVisibilityEvidenceError),

    /// A JSON Pointer pattern was syntactically invalid.
    #[error("invalid API comparison path pattern: {reason}")]
    InvalidPathPattern {
        /// Stable reason without echoing the rejected path.
        reason: &'static str,
    },

    /// A path pattern exceeded the compiled byte ceiling.
    #[error("API comparison path pattern exceeds the {maximum}-byte limit")]
    PathTooLong {
        /// Inclusive compiled ceiling.
        maximum: usize,
    },

    /// A path pattern exceeded the compiled segment ceiling.
    #[error("API comparison path pattern exceeds the {maximum}-segment limit")]
    PathTooDeep {
        /// Inclusive compiled ceiling.
        maximum: usize,
    },

    /// A profile contained too many path patterns.
    #[error("API comparison profile exceeds the {maximum}-pattern limit")]
    TooManyProfilePaths {
        /// Inclusive compiled ceiling across all profile lists.
        maximum: usize,
    },

    /// A profile or persisted diff exceeded the compiled explanation ceiling.
    #[error("API visibility diff exceeds the {maximum}-path limit")]
    TooManyDiffPaths {
        /// Inclusive compiled ceiling.
        maximum: u16,
    },

    /// A selected subtree was already removed by an ignored ancestor.
    #[error("API comparison selected path is inside an ignored subtree")]
    ConflictingPathPolicy,

    /// A persisted diff vector was unsorted or contained duplicate digests.
    #[error("API visibility diff path lists must be sorted and unique")]
    NonCanonicalDiffPathOrder,

    /// Persisted diff categories reused one path digest ambiguously.
    #[error("API visibility diff categories must be mutually exclusive")]
    OverlappingDiffCategories,

    /// Views did not use the requested deterministic comparator version.
    #[error("API visibility comparator versions do not match")]
    ComparatorVersionMismatch,

    /// Views did not use the requested canonicalization version.
    #[error("API visibility canonicalization versions do not match")]
    CanonicalizationVersionMismatch,

    /// Views did not use the requested projection policy.
    #[error("API visibility projection policies do not match")]
    ProjectionPolicyMismatch,

    /// The nested core comparison rejected a typed value.
    #[error(transparent)]
    Vocabulary(#[from] ApiVocabularyError),
}

impl ApiVisibilityComparator {
    /// Captures a bounded view under one explicit projection profile.
    ///
    /// The legacy canonicalizer first validates the complete snapshot against
    /// this comparator's resource envelope. Projection therefore cannot hide
    /// oversized input. The second pass retains only signatures and a bounded
    /// digest/type/value index; raw values and clear-text observed paths are
    /// discarded before this method returns.
    #[allow(clippy::too_many_arguments)]
    pub fn capture_profiled_view(
        &self,
        profile: &ApiComparisonProfile,
        context_id: impl Into<String>,
        resource_scope_id: impl Into<String>,
        surface: ApiSurfaceKind,
        status: u16,
        snapshot: &Value,
    ) -> Result<ProfiledApiVisibilityView, ProfiledApiVisibilityError> {
        let context_id = opaque_handle(context_id, "context id")?;
        let resource_scope_id = opaque_handle(resource_scope_id, "resource scope id")?;
        if !(100..=599).contains(&status) {
            return Err(ApiVisibilityEvidenceError::InvalidHttpStatus { status }.into());
        }

        // This full-document pass makes selected/ignored paths incapable of
        // bypassing the existing depth, node, field, or canonical-byte limits.
        let _ = canonical_signatures(snapshot, self.limits())?;

        let canonical = ProfiledCanonicalState::new(profile, self.limits()).capture(snapshot)?;
        Ok(ProfiledApiVisibilityView {
            context_id,
            resource_scope_id,
            surface,
            status,
            resource_signature: canonical.resource,
            field_signature: canonical.fields,
            path_index: canonical.path_index,
            limits: self.limits(),
            comparator_version: CURRENT_API_COMPARISON_ALGORITHM_VERSION,
            canonicalization_version: CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION,
            projection_policy_id: profile.projection_policy_id(),
        })
    }

    /// Compares two profiled views and emits a replayable metadata envelope.
    ///
    /// Version, policy, and limit mismatches fail closed before a result is
    /// emitted. The caller-owned comparison handle is domain-hashed together
    /// with the complete metadata tuple before constructing the nested legacy
    /// comparison, preventing evidence identity aliases across profiles.
    #[allow(clippy::too_many_arguments)]
    pub fn compare_profiled(
        &self,
        profile: &ApiComparisonProfile,
        comparison_id: impl Into<String>,
        pair: ApiVisibilityPairKind,
        dimension: ApiVisibilityDimension,
        baseline: &ProfiledApiVisibilityView,
        candidate: &ProfiledApiVisibilityView,
        observed_at_ms: u64,
    ) -> Result<ProfiledApiVisibilityComparison, ProfiledApiVisibilityError> {
        for view in [baseline, candidate] {
            if view.comparator_version != CURRENT_API_COMPARISON_ALGORITHM_VERSION
                || view.comparator_version != profile.algorithm_version()
            {
                return Err(ProfiledApiVisibilityError::ComparatorVersionMismatch);
            }
            if view.canonicalization_version != CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION {
                return Err(ProfiledApiVisibilityError::CanonicalizationVersionMismatch);
            }
            if view.projection_policy_id != profile.projection_policy_id() {
                return Err(ProfiledApiVisibilityError::ProjectionPolicyMismatch);
            }
            if view.limits != self.limits() {
                return Err(ApiVisibilityEvidenceError::LimitsMismatch.into());
            }
        }
        if baseline.context_id == candidate.context_id {
            return Err(ApiVisibilityEvidenceError::IdenticalContexts.into());
        }
        if baseline.resource_scope_id != candidate.resource_scope_id {
            return Err(ApiVisibilityEvidenceError::ResourceScopeMismatch.into());
        }
        if baseline.surface != candidate.surface {
            return Err(ApiVisibilityEvidenceError::SurfaceMismatch.into());
        }

        let equivalent = match dimension {
            ApiVisibilityDimension::Fields => baseline.field_signature == candidate.field_signature,
            ApiVisibilityDimension::Resources => {
                baseline.resource_signature == candidate.resource_signature
            },
            ApiVisibilityDimension::Status => baseline.status == candidate.status,
            _ => return Err(ApiVisibilityEvidenceError::UnsupportedDimension.into()),
        };
        let result = if equivalent {
            ApiVisibilityResult::Equivalent
        } else {
            ApiVisibilityResult::Different
        };
        let diff = visibility_diff(
            dimension,
            &baseline.path_index,
            &candidate.path_index,
            profile.max_diff_paths(),
        )?;

        let comparison_id = profiled_comparison_id(
            comparison_id,
            profile.projection_policy_id(),
            CURRENT_API_COMPARISON_ALGORITHM_VERSION,
            CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION,
        )?;
        let comparison = ApiVisibilityComparison::new(
            comparison_id,
            baseline.surface,
            pair,
            result,
            dimension,
            baseline.context_id.clone(),
            candidate.context_id.clone(),
            baseline.resource_scope_id.clone(),
        )?
        .with_observed_at_ms(observed_at_ms);

        Ok(ProfiledApiVisibilityComparison {
            comparison,
            comparator_version: CURRENT_API_COMPARISON_ALGORITHM_VERSION,
            canonicalization_version: CURRENT_API_VISIBILITY_CANONICALIZATION_VERSION,
            projection_policy_id: profile.projection_policy_id(),
            limits: self.limits(),
            diff,
        })
    }
}

fn profiled_comparison_id(
    comparison_id: impl Into<String>,
    policy_id: ProjectionPolicyId,
    comparator_version: ComparisonAlgorithmVersion,
    canonicalization_version: CanonicalizationVersion,
) -> Result<String, ProfiledApiVisibilityError> {
    let comparison_id = opaque_handle(comparison_id, "comparison id")?;
    let mut hasher = Sha256::new();
    hasher.update(PROFILED_COMPARISON_ID_DOMAIN);
    update_framed(&mut hasher, comparison_id.as_bytes());
    Ok(format!(
        "profiled:{}:{}:{}:{}",
        comparator_version.as_str(),
        canonicalization_version.as_str(),
        policy_id,
        encode_digest(hasher.finalize().into())
    ))
}

fn comparison_id_matches_metadata(
    comparison_id: &str,
    comparator_version: ComparisonAlgorithmVersion,
    canonicalization_version: CanonicalizationVersion,
    policy_id: ProjectionPolicyId,
) -> bool {
    let prefix = format!(
        "profiled:{}:{}:{}:",
        comparator_version.as_str(),
        canonicalization_version.as_str(),
        policy_id
    );
    comparison_id
        .strip_prefix(&prefix)
        .is_some_and(|digest| digest.len() == 64 && decode_digest(digest).is_ok())
}

#[cfg(test)]
#[path = "profiled_tests.rs"]
mod tests;
