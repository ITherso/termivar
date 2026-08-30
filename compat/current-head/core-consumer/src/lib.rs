//! Same-revision consumer of Venom's default transport-neutral core surface.

#![forbid(unsafe_code)]

use venom_core::{
    ConfidenceScore, EntityId, Outcome, OutcomeError, ReasoningModelError, RunReportError,
    RunStopCode, RunStopReason, VerificationStage,
};

/// Builds a validated identity through the default reasoning contract.
pub fn subject_identity() -> Result<EntityId, ReasoningModelError> {
    EntityId::new("endpoint:current-head-fixture")
}

/// Builds the canonical evidence-free outcome without implying confirmation.
pub fn unknown_outcome() -> Result<Outcome, OutcomeError> {
    let subject = subject_identity().expect("the static fixture identity is valid");
    Outcome::unknown(
        "case:current-head:unknown",
        subject,
        "observe.current-head",
        "hypothesis:current-head",
        VerificationStage::Passive,
        "the compile fixture supplies no verifier evidence",
    )
}

/// Builds a typed incomplete-run reason without transport or execution work.
pub fn budget_stop_reason() -> Result<RunStopReason, RunReportError> {
    RunStopReason::new(
        RunStopCode::BudgetExhausted,
        "the host-owned request budget was exhausted",
    )
}

/// Builds a bounded confidence value through the public reasoning model.
pub fn review_confidence() -> Result<ConfidenceScore, ReasoningModelError> {
    ConfidenceScore::from_basis_points(7_500)
}

#[cfg(test)]
mod tests {
    use venom_core::OutcomeStatus;

    use super::*;

    #[test]
    fn default_core_contracts_compile_and_retain_conservative_truth() {
        assert_eq!(
            subject_identity().unwrap().as_str(),
            "endpoint:current-head-fixture"
        );
        assert_eq!(unknown_outcome().unwrap().status(), OutcomeStatus::Unknown);
        assert_eq!(
            budget_stop_reason().unwrap().code(),
            RunStopCode::BudgetExhausted
        );
        assert_eq!(review_confidence().unwrap().basis_points(), 7_500);
    }
}
