use serde::Serialize;
use std::fmt;
use termivar_core::{EntityId, EvidenceId, RelationId};
use thiserror::Error;

use crate::{
    knowledge::{KnowledgeBaseError, KnowledgeWrite},
    rules::{RuleApplication, RuleEngineError},
};

/// Receipt for an observation pair committed to one [`crate::KnowledgeBase`] instance.
///
/// Evidence and its resource-scope relation are committed atomically. Rule
/// application happens afterwards and is deliberately not part of that write
/// transaction. This receipt does not imply that the in-memory knowledge base
/// has been persisted by its host.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiObservationCommitReceipt {
    pub(super) comparison_subject: EntityId,
    pub(super) resource_scope: EntityId,
    pub(super) evidence_id: EvidenceId,
    pub(super) relation_id: RelationId,
    pub(super) evidence_write: KnowledgeWrite,
    pub(super) relation_write: KnowledgeWrite,
}

impl fmt::Debug for ApiObservationCommitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiObservationCommitReceipt")
            .field("comparison_subject", &"<redacted>")
            .field("resource_scope", &"<redacted>")
            .field("evidence_id", &"<redacted>")
            .field("relation_id", &"<redacted>")
            .field("evidence_write", &self.evidence_write)
            .field("relation_write", &self.relation_write)
            .finish()
    }
}

impl ApiObservationCommitReceipt {
    /// Returns the isolated subject on which comparison reasoning runs.
    pub fn comparison_subject(&self) -> &EntityId {
        &self.comparison_subject
    }

    /// Returns the host-declared logical resource that was compared.
    pub fn resource_scope(&self) -> &EntityId {
        &self.resource_scope
    }

    /// Returns the immutable comparison evidence identity.
    pub fn evidence_id(&self) -> &EvidenceId {
        &self.evidence_id
    }

    /// Returns the evidence-backed resource relation identity.
    pub fn relation_id(&self) -> &RelationId {
        &self.relation_id
    }

    /// Returns whether evidence was inserted or replayed unchanged.
    pub const fn evidence_write(&self) -> KnowledgeWrite {
        self.evidence_write
    }

    /// Returns whether the resource relation was inserted or replayed unchanged.
    pub const fn relation_write(&self) -> KnowledgeWrite {
        self.relation_write
    }
}

/// Complete successful observation and reasoning receipt.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApiObservationReceipt {
    pub(super) commit: ApiObservationCommitReceipt,
    pub(super) applications: Vec<RuleApplication>,
}

impl fmt::Debug for ApiObservationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiObservationReceipt")
            .field("commit", &self.commit)
            .field("application_count", &self.applications.len())
            .finish()
    }
}

impl ApiObservationReceipt {
    /// Returns the observation commit for the supplied knowledge-base instance.
    pub fn commit(&self) -> &ApiObservationCommitReceipt {
        &self.commit
    }

    /// Returns rule evaluations and hypothesis writes in stable rule-ID order.
    ///
    /// Materialized hypotheses retain their evaluation timestamps, so complete
    /// receipt bytes are not guaranteed to be identical across exact replays.
    /// Each application carries the evaluated snapshot candidate and its write
    /// status, not a fresh clone of committed state. If terminal-state
    /// preservation matters, re-read the hypothesis from the knowledge base.
    pub fn applications(&self) -> &[RuleApplication] {
        &self.applications
    }

    /// Splits the receipt into its observation commit and reasoning applications.
    pub fn into_parts(self) -> (ApiObservationCommitReceipt, Vec<RuleApplication>) {
        (self.commit, self.applications)
    }
}

/// Failure while accepting or reasoning over an API visibility observation.
#[derive(Error)]
#[non_exhaustive]
pub enum ApiObservationError {
    /// The observation described a resource outside the host-selected scope.
    #[error("API visibility observation resource does not match expected resource")]
    ResourceMismatch {
        /// Resource authorized by the caller.
        expected: EntityId,
        /// Resource declared by the observation.
        actual: EntityId,
    },

    /// A review query cannot make progress with an empty scan window.
    #[error("API visibility review scan limit must be greater than zero")]
    ZeroReviewScanLimit,

    /// A review query exceeded the compiled per-page scan ceiling.
    #[error("API visibility review scan limit {actual} exceeds hard ceiling {maximum}")]
    ReviewScanLimitExceeded {
        /// Rejected requested relation count.
        actual: u16,
        /// Inclusive compiled ceiling.
        maximum: u16,
    },

    /// A review cursor exceeded the relation-store identifier ceiling.
    #[error("API visibility review cursor is {actual} bytes, above hard ceiling {maximum}")]
    ReviewCursorTooLong {
        /// Rejected cursor byte length.
        actual: usize,
        /// Inclusive relation identifier ceiling.
        maximum: usize,
    },

    /// A serialized resource-bound review cursor exceeded its compiled ceiling.
    #[error("API visibility resource-bound review cursor is {actual} bytes, above hard ceiling {maximum}")]
    ResourceBoundReviewCursorTooLong {
        /// Rejected serialized cursor byte length.
        actual: usize,
        /// Inclusive compiled cursor ceiling.
        maximum: usize,
    },

    /// A serialized resource-bound review cursor was not canonical v2 syntax.
    #[error("invalid API visibility resource-bound review cursor: {reason}")]
    InvalidResourceBoundReviewCursor {
        /// Stable parse reason that never contains cursor input.
        reason: &'static str,
    },

    /// A resource-bound review cursor used an unsupported wire version.
    #[error("unsupported API visibility resource-bound review cursor version")]
    UnsupportedResourceBoundReviewCursorVersion,

    /// A resource-bound review cursor was replayed against another resource.
    #[error("API visibility resource-bound review cursor does not match requested resource")]
    ResourceBoundReviewCursorMismatch,

    /// An observation field exceeded the review model's storage ceiling.
    #[error("API visibility observation {field} size {actual} exceeds hard ceiling {maximum}")]
    ObservationLimitExceeded {
        /// Stable field name (`source.component`).
        field: &'static str,
        /// Rejected UTF-8 byte count.
        actual: usize,
        /// Inclusive compiled ceiling.
        maximum: usize,
    },

    /// The atomic evidence and relation write failed before anything committed.
    #[error(transparent)]
    Knowledge(#[from] KnowledgeBaseError),

    /// Reasoning failed after the observation pair had committed.
    #[error("API visibility observation committed before reasoning failed: {source}")]
    ReasoningAfterCommit {
        /// Committed observation that must not be retried as if no write occurred.
        commit: Box<ApiObservationCommitReceipt>,
        /// Rule evaluation or hypothesis-write failure.
        #[source]
        source: RuleEngineError,
    },
}

impl fmt::Debug for ApiObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceMismatch { .. } => formatter
                .debug_struct("ResourceMismatch")
                .field("expected", &"<redacted>")
                .field("actual", &"<redacted>")
                .finish(),
            Self::ZeroReviewScanLimit => formatter.write_str("ZeroReviewScanLimit"),
            Self::ReviewScanLimitExceeded { actual, maximum } => formatter
                .debug_struct("ReviewScanLimitExceeded")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::ReviewCursorTooLong { actual, maximum } => formatter
                .debug_struct("ReviewCursorTooLong")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::ResourceBoundReviewCursorTooLong { actual, maximum } => formatter
                .debug_struct("ResourceBoundReviewCursorTooLong")
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::InvalidResourceBoundReviewCursor { reason } => formatter
                .debug_struct("InvalidResourceBoundReviewCursor")
                .field("reason", reason)
                .finish(),
            Self::UnsupportedResourceBoundReviewCursorVersion => {
                formatter.write_str("UnsupportedResourceBoundReviewCursorVersion")
            },
            Self::ResourceBoundReviewCursorMismatch => {
                formatter.write_str("ResourceBoundReviewCursorMismatch")
            },
            Self::ObservationLimitExceeded {
                field,
                actual,
                maximum,
            } => formatter
                .debug_struct("ObservationLimitExceeded")
                .field("field", field)
                .field("actual", actual)
                .field("maximum", maximum)
                .finish(),
            Self::Knowledge(source) => formatter.debug_tuple("Knowledge").field(source).finish(),
            Self::ReasoningAfterCommit { commit, source } => formatter
                .debug_struct("ReasoningAfterCommit")
                .field("commit", commit)
                .field("source", source)
                .finish(),
        }
    }
}
