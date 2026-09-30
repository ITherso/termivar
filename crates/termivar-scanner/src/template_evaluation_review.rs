//! Raw-free contracts for one bounded benign template-evaluation review.
//!
//! The runtime owns request scheduling and evidence commitment. This module
//! records only closed classifications and reconciled counts; expressions,
//! query values, URLs, response bodies, template-engine errors, and other raw
//! transport values are deliberately absent.

use std::fmt;

use thiserror::Error;

/// Exact optional audit schema emitted by the central assessment renderer.
pub const TEMPLATE_EVALUATION_REVIEW_AUDIT_SCHEMA: &str =
    "security.template-evaluation-review-audit/v1";
/// Stable policy revision for the bounded primary/replay case pair.
pub const TEMPLATE_EVALUATION_REVIEW_POLICY_ID: &str = "termivar.template-evaluation-review/v1";
/// Stable family identity for the harmless Jinja-compatible case vocabulary.
pub const TEMPLATE_EVALUATION_REVIEW_FAMILY_ID: &str =
    "web.review.template-evaluation.family.jinja-compatible-benign-expression@1";
/// Stable knowledge-only capability projected by a complete positive review.
pub const TEMPLATE_EVALUATION_REVIEW_CAPABILITY_ID: &str =
    "web.review.template-evaluation.jinja-compatible-semantics@1";
/// Exact title for the optional positive assessment item.
pub(crate) const TEMPLATE_EVALUATION_REVIEW_TITLE: &str =
    "Candidate-specific behavior consistent with Jinja-compatible expression semantics";
/// Exact category for the optional positive assessment item.
pub(crate) const TEMPLATE_EVALUATION_REVIEW_CATEGORY: &str = "Template expression evaluation";
/// Exact value-free summary for the optional positive assessment item.
pub(crate) const TEMPLATE_EVALUATION_REVIEW_SUMMARY: &str = "Two bounded candidate/replay cases produced candidate-specific benign expression semantics while controls remained negative; template engine identity, operating-system execution, file access, outbound interaction, and impact remain unestablished.";
/// Stable remediation identity for the optional positive assessment item.
pub(crate) const TEMPLATE_EVALUATION_REVIEW_REMEDIATION_ID: &str =
    "web.remediation.template-evaluation-review@1";
/// Exact remediation guidance for the optional positive assessment item.
pub(crate) const TEMPLATE_EVALUATION_REVIEW_REMEDIATION_SUMMARY: &str = "Review server-side template construction and bind untrusted values as data rather than compiling them as template source.";

/// Stable audit value for deliberately unestablished engine identity.
pub const TEMPLATE_EVALUATION_ENGINE_IDENTITY: &str = "not_established";
/// Stable audit value for deliberately excluded operations.
pub const TEMPLATE_EVALUATION_OPERATION_NOT_PERFORMED: &str = "not_performed";
/// Primary plus replay are the exact selected semantic cases.
pub const TEMPLATE_EVALUATION_SELECTED_CASES: u8 = 2;
/// Each selected case owns one control and one candidate request.
pub const TEMPLATE_EVALUATION_MAX_REQUESTS: u8 = 4;
/// Candidate requests are the only active legs.
pub const TEMPLATE_EVALUATION_MAX_ACTIVE_REQUESTS: u8 = 2;

/// Fixed claim limits emitted in this exact order by every V1 audit.
pub const TEMPLATE_EVALUATION_REVIEW_CLAIM_LIMITS: [&str; 7] = [
    "engine_identity_not_established",
    "candidate_specific_evaluation_does_not_establish_template_engine_identity",
    "outbound_interaction_not_performed",
    "os_execution_not_performed",
    "file_access_not_performed",
    "impact_validation_not_performed",
    "vulnerability_confirmation_not_established",
];

/// Closed raw-free outcome vocabulary retained by V1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateEvaluationReviewOutcome {
    /// No eligible committed parent observation selected the two semantic cases.
    ParentNotObserved,
    /// The candidate remained literal or was escaped rather than evaluated.
    LiteralOrEscaped,
    /// The response representation could not support the bounded classifier.
    UnsupportedRepresentation,
    /// Primary and replay did not establish the same candidate-specific result.
    ReplayMismatch,
    /// Both independent cases established their exact benign candidate result.
    CandidateSpecificEvaluation,
    /// Scheduling, transport, commitment, or classification ended incompletely.
    Incomplete,
}

impl TemplateEvaluationReviewOutcome {
    /// Stable value-free wire token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParentNotObserved => "parent_not_observed",
            Self::LiteralOrEscaped => "literal_or_escaped",
            Self::UnsupportedRepresentation => "unsupported_representation",
            Self::ReplayMismatch => "replay_mismatch",
            Self::CandidateSpecificEvaluation => "candidate_specific_evaluation",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Reconciled runtime facts accepted by the V1 audit constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TemplateEvaluationReviewAuditFacts {
    pub(crate) outcome: TemplateEvaluationReviewOutcome,
    pub(crate) selected_case_count: u8,
    pub(crate) attempted_request_count: u8,
    pub(crate) active_request_count: u8,
    pub(crate) completed_response_count: u8,
    pub(crate) committed_response_count: u8,
    pub(crate) projected_item_count: u8,
}

/// Constructor failure for an internally inconsistent runtime summary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum TemplateEvaluationReviewAuditError {
    /// A counter exceeded the closed V1 plan.
    #[error("template-evaluation review count exceeds its compiled limit")]
    CountLimitExceeded,
    /// Completed, committed, or active work exceeded its prerequisite work.
    #[error("template-evaluation review counts are inconsistent")]
    CountOrderingMismatch,
    /// Counts and terminal outcome do not describe the same V1 state.
    #[error("template-evaluation review outcome is inconsistent with its counts")]
    OutcomeMismatch,
}

/// Value-free bounded audit retained by one composed assessment report.
#[derive(Clone, Eq, PartialEq)]
pub struct TemplateEvaluationReviewAudit {
    outcome: TemplateEvaluationReviewOutcome,
    selected_case_count: u8,
    attempted_request_count: u8,
    active_request_count: u8,
    completed_response_count: u8,
    committed_response_count: u8,
    projected_item_count: u8,
}

impl TemplateEvaluationReviewAudit {
    /// Constructs an audit only from counts that reconcile with the closed V1
    /// primary/replay schedule and terminal outcome.
    pub(crate) fn from_runtime(
        facts: TemplateEvaluationReviewAuditFacts,
    ) -> Result<Self, TemplateEvaluationReviewAuditError> {
        validate_facts(facts)?;
        Ok(Self {
            outcome: facts.outcome,
            selected_case_count: facts.selected_case_count,
            attempted_request_count: facts.attempted_request_count,
            active_request_count: facts.active_request_count,
            completed_response_count: facts.completed_response_count,
            committed_response_count: facts.committed_response_count,
            projected_item_count: facts.projected_item_count,
        })
    }

    /// Exact optional audit schema.
    pub const fn schema(&self) -> &'static str {
        TEMPLATE_EVALUATION_REVIEW_AUDIT_SCHEMA
    }

    /// Stable policy revision.
    pub const fn policy_id(&self) -> &'static str {
        TEMPLATE_EVALUATION_REVIEW_POLICY_ID
    }

    /// Stable harmless expression-family identity.
    pub const fn family_id(&self) -> &'static str {
        TEMPLATE_EVALUATION_REVIEW_FAMILY_ID
    }

    /// Stable capability identity for the optional projected item.
    pub const fn capability_id(&self) -> &'static str {
        TEMPLATE_EVALUATION_REVIEW_CAPABILITY_ID
    }

    /// Raw-free terminal outcome.
    pub const fn outcome(&self) -> TemplateEvaluationReviewOutcome {
        self.outcome
    }

    /// Number of selected semantic cases.
    pub const fn selected_case_count(&self) -> u8 {
        self.selected_case_count
    }

    /// Number of broker requests attempted by the review.
    pub const fn attempted_request_count(&self) -> u8 {
        self.attempted_request_count
    }

    /// Number of attempted requests charged as active review work.
    pub const fn active_request_count(&self) -> u8 {
        self.active_request_count
    }

    /// Number of requests that produced complete responses.
    pub const fn completed_response_count(&self) -> u8 {
        self.completed_response_count
    }

    /// Number of complete responses committed as usable evidence.
    pub const fn committed_response_count(&self) -> u8 {
        self.committed_response_count
    }

    /// Number of positive assessment items projected from this audit.
    pub const fn projected_item_count(&self) -> u8 {
        self.projected_item_count
    }

    /// Engine identity is deliberately not established by benign semantics.
    pub const fn engine_identity(&self) -> &'static str {
        TEMPLATE_EVALUATION_ENGINE_IDENTITY
    }

    /// Outbound interaction was deliberately not performed.
    pub const fn outbound_interaction(&self) -> &'static str {
        TEMPLATE_EVALUATION_OPERATION_NOT_PERFORMED
    }

    /// Operating-system execution was deliberately not performed.
    pub const fn os_execution(&self) -> &'static str {
        TEMPLATE_EVALUATION_OPERATION_NOT_PERFORMED
    }

    /// File access was deliberately not performed.
    pub const fn file_access(&self) -> &'static str {
        TEMPLATE_EVALUATION_OPERATION_NOT_PERFORMED
    }

    /// Impact validation was deliberately not performed.
    pub const fn impact_validation(&self) -> &'static str {
        TEMPLATE_EVALUATION_OPERATION_NOT_PERFORMED
    }

    /// Fixed claim limits for the V1 review.
    pub const fn claim_limits(&self) -> &'static [&'static str; 7] {
        &TEMPLATE_EVALUATION_REVIEW_CLAIM_LIMITS
    }
}

impl fmt::Debug for TemplateEvaluationReviewAudit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TemplateEvaluationReviewAudit")
            .field("schema", &self.schema())
            .field("policy_id", &self.policy_id())
            .field("family_id", &self.family_id())
            .field("outcome", &self.outcome)
            .field("selected_case_count", &self.selected_case_count)
            .field("attempted_request_count", &self.attempted_request_count)
            .field("active_request_count", &self.active_request_count)
            .field("completed_response_count", &self.completed_response_count)
            .field("committed_response_count", &self.committed_response_count)
            .field("projected_item_count", &self.projected_item_count)
            .field("engine_identity", &self.engine_identity())
            .field("operations", &TEMPLATE_EVALUATION_OPERATION_NOT_PERFORMED)
            .finish()
    }
}

fn validate_facts(
    facts: TemplateEvaluationReviewAuditFacts,
) -> Result<(), TemplateEvaluationReviewAuditError> {
    if !matches!(
        facts.selected_case_count,
        0 | TEMPLATE_EVALUATION_SELECTED_CASES
    ) || facts.attempted_request_count > TEMPLATE_EVALUATION_MAX_REQUESTS
        || facts.active_request_count > TEMPLATE_EVALUATION_MAX_ACTIVE_REQUESTS
        || facts.completed_response_count > TEMPLATE_EVALUATION_MAX_REQUESTS
        || facts.committed_response_count > TEMPLATE_EVALUATION_MAX_REQUESTS
        || facts.projected_item_count > 1
    {
        return Err(TemplateEvaluationReviewAuditError::CountLimitExceeded);
    }
    if facts.completed_response_count > facts.attempted_request_count
        || facts.committed_response_count > facts.completed_response_count
        || facts.active_request_count > facts.attempted_request_count
    {
        return Err(TemplateEvaluationReviewAuditError::CountOrderingMismatch);
    }

    let valid_outcome = match facts.outcome {
        TemplateEvaluationReviewOutcome::ParentNotObserved => {
            facts.selected_case_count == 0
                && facts.attempted_request_count == 0
                && facts.active_request_count == 0
                && facts.completed_response_count == 0
                && facts.committed_response_count == 0
                && facts.projected_item_count == 0
        },
        TemplateEvaluationReviewOutcome::CandidateSpecificEvaluation => {
            facts.selected_case_count == TEMPLATE_EVALUATION_SELECTED_CASES
                && facts.attempted_request_count == TEMPLATE_EVALUATION_MAX_REQUESTS
                && facts.active_request_count == TEMPLATE_EVALUATION_MAX_ACTIVE_REQUESTS
                && facts.completed_response_count == TEMPLATE_EVALUATION_MAX_REQUESTS
                && facts.committed_response_count == TEMPLATE_EVALUATION_MAX_REQUESTS
                && facts.projected_item_count == 1
        },
        TemplateEvaluationReviewOutcome::LiteralOrEscaped
        | TemplateEvaluationReviewOutcome::UnsupportedRepresentation
        | TemplateEvaluationReviewOutcome::ReplayMismatch => {
            facts.selected_case_count == TEMPLATE_EVALUATION_SELECTED_CASES
                && facts.attempted_request_count == TEMPLATE_EVALUATION_MAX_REQUESTS
                && facts.active_request_count == TEMPLATE_EVALUATION_MAX_ACTIVE_REQUESTS
                && facts.completed_response_count == TEMPLATE_EVALUATION_MAX_REQUESTS
                && facts.committed_response_count == TEMPLATE_EVALUATION_MAX_REQUESTS
                && facts.projected_item_count == 0
        },
        TemplateEvaluationReviewOutcome::Incomplete => {
            facts.selected_case_count == TEMPLATE_EVALUATION_SELECTED_CASES
                && facts.projected_item_count == 0
        },
    };
    if !valid_outcome {
        return Err(TemplateEvaluationReviewAuditError::OutcomeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(outcome: TemplateEvaluationReviewOutcome) -> TemplateEvaluationReviewAuditFacts {
        TemplateEvaluationReviewAuditFacts {
            outcome,
            selected_case_count: TEMPLATE_EVALUATION_SELECTED_CASES,
            attempted_request_count: TEMPLATE_EVALUATION_MAX_REQUESTS,
            active_request_count: TEMPLATE_EVALUATION_MAX_ACTIVE_REQUESTS,
            completed_response_count: TEMPLATE_EVALUATION_MAX_REQUESTS,
            committed_response_count: TEMPLATE_EVALUATION_MAX_REQUESTS,
            projected_item_count: 0,
        }
    }

    #[test]
    fn selected_empty_and_positive_states_are_exact() {
        let empty =
            TemplateEvaluationReviewAudit::from_runtime(TemplateEvaluationReviewAuditFacts {
                outcome: TemplateEvaluationReviewOutcome::ParentNotObserved,
                selected_case_count: 0,
                attempted_request_count: 0,
                active_request_count: 0,
                completed_response_count: 0,
                committed_response_count: 0,
                projected_item_count: 0,
            })
            .unwrap();
        assert_eq!(empty.outcome().as_str(), "parent_not_observed");
        assert_eq!(empty.selected_case_count(), 0);

        let mut positive = facts(TemplateEvaluationReviewOutcome::CandidateSpecificEvaluation);
        positive.projected_item_count = 1;
        let positive = TemplateEvaluationReviewAudit::from_runtime(positive).unwrap();
        assert_eq!(positive.projected_item_count(), 1);
        assert_eq!(positive.engine_identity(), "not_established");
        assert_eq!(positive.claim_limits().len(), 7);
    }

    #[test]
    fn all_nonpositive_outcomes_remain_item_free() {
        for outcome in [
            TemplateEvaluationReviewOutcome::LiteralOrEscaped,
            TemplateEvaluationReviewOutcome::UnsupportedRepresentation,
            TemplateEvaluationReviewOutcome::ReplayMismatch,
            TemplateEvaluationReviewOutcome::Incomplete,
        ] {
            let audit = TemplateEvaluationReviewAudit::from_runtime(facts(outcome)).unwrap();
            assert_eq!(audit.projected_item_count(), 0);
            assert_eq!(audit.outbound_interaction(), "not_performed");
            assert_eq!(audit.os_execution(), "not_performed");
            assert_eq!(audit.file_access(), "not_performed");
            assert_eq!(audit.impact_validation(), "not_performed");
        }

        let partial =
            TemplateEvaluationReviewAudit::from_runtime(TemplateEvaluationReviewAuditFacts {
                outcome: TemplateEvaluationReviewOutcome::Incomplete,
                selected_case_count: TEMPLATE_EVALUATION_SELECTED_CASES,
                attempted_request_count: 3,
                active_request_count: 1,
                completed_response_count: 2,
                committed_response_count: 2,
                projected_item_count: 0,
            })
            .unwrap();
        assert_eq!(
            partial.outcome(),
            TemplateEvaluationReviewOutcome::Incomplete
        );
    }

    #[test]
    fn invalid_limits_ordering_and_outcome_shapes_fail_closed() {
        let mut too_many = facts(TemplateEvaluationReviewOutcome::Incomplete);
        too_many.attempted_request_count = 5;
        assert_eq!(
            TemplateEvaluationReviewAudit::from_runtime(too_many),
            Err(TemplateEvaluationReviewAuditError::CountLimitExceeded)
        );

        let mut out_of_order = facts(TemplateEvaluationReviewOutcome::Incomplete);
        out_of_order.completed_response_count = 3;
        out_of_order.committed_response_count = 4;
        assert_eq!(
            TemplateEvaluationReviewAudit::from_runtime(out_of_order),
            Err(TemplateEvaluationReviewAuditError::CountOrderingMismatch)
        );

        let mut false_positive =
            facts(TemplateEvaluationReviewOutcome::CandidateSpecificEvaluation);
        false_positive.projected_item_count = 0;
        assert_eq!(
            TemplateEvaluationReviewAudit::from_runtime(false_positive),
            Err(TemplateEvaluationReviewAuditError::OutcomeMismatch)
        );

        let mut projected_negative = facts(TemplateEvaluationReviewOutcome::ReplayMismatch);
        projected_negative.projected_item_count = 1;
        assert_eq!(
            TemplateEvaluationReviewAudit::from_runtime(projected_negative),
            Err(TemplateEvaluationReviewAuditError::OutcomeMismatch)
        );

        for outcome in [
            TemplateEvaluationReviewOutcome::LiteralOrEscaped,
            TemplateEvaluationReviewOutcome::UnsupportedRepresentation,
            TemplateEvaluationReviewOutcome::ReplayMismatch,
        ] {
            let mut incomplete_terminal = facts(outcome);
            incomplete_terminal.attempted_request_count = 0;
            incomplete_terminal.active_request_count = 0;
            incomplete_terminal.completed_response_count = 0;
            incomplete_terminal.committed_response_count = 0;
            assert_eq!(
                TemplateEvaluationReviewAudit::from_runtime(incomplete_terminal),
                Err(TemplateEvaluationReviewAuditError::OutcomeMismatch)
            );
        }
    }
}
