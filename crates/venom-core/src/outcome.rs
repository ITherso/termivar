//! Transport-neutral verification outcomes.
//!
//! Outcomes are deterministic decision records. They reference immutable
//! evidence but contain no probing, scheduling, or plugin execution behavior.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::reasoning::{EntityId, EvidenceId, HypothesisState, Probability};

/// Validation errors for verification outcome contracts.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OutcomeError {
    /// A required identity or explanation was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// `Unknown` is reserved for the canonical evidence-free fallback.
    #[error("unknown outcomes must be created without a verifier rule or evidence")]
    InvalidUnknown,

    /// A trusted negative conclusion was emitted without an active control.
    #[error("confirmed negative outcomes require active verification evidence")]
    ConfirmedNegativeRequiresActive,

    /// A conclusive outcome did not reference any evidence.
    #[error("outcome {status:?} must reference at least one evidence record")]
    MissingEvidence { status: OutcomeStatus },

    /// A conclusive outcome had zero confidence.
    #[error("outcome {status:?} must have non-zero confidence")]
    ZeroConfidence { status: OutcomeStatus },
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, OutcomeError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(OutcomeError::EmptyValue { field });
    }
    Ok(value)
}

/// Evidence collection stage that produced a verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationStage {
    /// Existing evidence was evaluated without sending a new probe.
    Passive,
    /// Evidence produced by an explicit verification probe was evaluated.
    Active,
}

impl VerificationStage {
    /// Returns the stable wire name for the stage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
        }
    }
}

/// Final classification emitted by a verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OutcomeStatus {
    /// The hypothesis was verified.
    Success,
    /// Verification could not proceed because the target or a control blocked it.
    Blocked,
    /// Current evidence cannot support a deterministic conclusion.
    Unknown,
    /// Verification rejected the hypothesis.
    FalsePositive,
    /// Conflicting or incomplete evidence requires a human decision.
    NeedsReview,
    /// An audited negative control explicitly disproved the hypothesis.
    ///
    /// Unlike `FalsePositive`, this records a trusted negative result rather
    /// than a verifier rejecting the provenance or interpretation of a prior
    /// finding.
    ConfirmedNegative,
}

impl OutcomeStatus {
    /// Returns whether the verification pipeline should stop at this status.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Success | Self::Blocked | Self::FalsePositive | Self::ConfirmedNegative
        )
    }

    /// Maps conclusive verification results to verifier-owned hypothesis states.
    pub const fn hypothesis_state(self) -> Option<HypothesisState> {
        match self {
            Self::Success => Some(HypothesisState::Confirmed),
            Self::FalsePositive | Self::ConfirmedNegative => Some(HypothesisState::Rejected),
            Self::Blocked | Self::Unknown | Self::NeedsReview => None,
        }
    }
}

/// Immutable, evidence-backed result of verifying one planned action.
///
/// `Unknown` is canonical: it has zero confidence, no rule identity, and no
/// evidence. Every other status must identify the winning verifier rule and
/// carry at least one immutable evidence reference.
///
/// # Example
///
/// ```rust
/// use std::collections::BTreeSet;
/// use venom_core::{
///     EntityId, EvidenceId, Outcome, OutcomeStatus, Probability, VerificationStage,
/// };
///
/// let outcome = Outcome::verified(
///     "case:sqli:1",
///     EntityId::new("endpoint:https://example.test")?,
///     "sqli.verify",
///     "hypothesis:sqli:1",
///     "verify.boolean-difference",
///     VerificationStage::Passive,
///     OutcomeStatus::Success,
///     Probability::from_percent(95)?,
///     "Boolean responses diverged consistently",
///     BTreeSet::from([EvidenceId::parse("evidence:boolean-difference")?]),
/// )?;
///
/// assert_eq!(outcome.status(), OutcomeStatus::Success);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    case_id: String,
    subject: EntityId,
    action_id: String,
    hypothesis_id: String,
    verifier_rule_id: Option<String>,
    stage: VerificationStage,
    status: OutcomeStatus,
    confidence: Probability,
    rationale: String,
    evidence_ids: BTreeSet<EvidenceId>,
}

impl Outcome {
    /// Creates an evidence-backed non-unknown outcome.
    #[allow(clippy::too_many_arguments)]
    pub fn verified(
        case_id: impl Into<String>,
        subject: EntityId,
        action_id: impl Into<String>,
        hypothesis_id: impl Into<String>,
        verifier_rule_id: impl Into<String>,
        stage: VerificationStage,
        status: OutcomeStatus,
        confidence: Probability,
        rationale: impl Into<String>,
        evidence_ids: BTreeSet<EvidenceId>,
    ) -> Result<Self, OutcomeError> {
        if status == OutcomeStatus::Unknown {
            return Err(OutcomeError::InvalidUnknown);
        }
        if status == OutcomeStatus::ConfirmedNegative && stage != VerificationStage::Active {
            return Err(OutcomeError::ConfirmedNegativeRequiresActive);
        }
        if evidence_ids.is_empty() {
            return Err(OutcomeError::MissingEvidence { status });
        }
        if confidence == Probability::ZERO {
            return Err(OutcomeError::ZeroConfidence { status });
        }
        Ok(Self {
            case_id: non_empty(case_id, "verification case id")?,
            subject,
            action_id: non_empty(action_id, "verification action id")?,
            hypothesis_id: non_empty(hypothesis_id, "verification hypothesis id")?,
            verifier_rule_id: Some(non_empty(verifier_rule_id, "verifier rule id")?),
            stage,
            status,
            confidence,
            rationale: non_empty(rationale, "verification rationale")?,
            evidence_ids,
        })
    }

    /// Creates the canonical fallback used when no verifier rule is eligible.
    pub fn unknown(
        case_id: impl Into<String>,
        subject: EntityId,
        action_id: impl Into<String>,
        hypothesis_id: impl Into<String>,
        stage: VerificationStage,
        rationale: impl Into<String>,
    ) -> Result<Self, OutcomeError> {
        Ok(Self {
            case_id: non_empty(case_id, "verification case id")?,
            subject,
            action_id: non_empty(action_id, "verification action id")?,
            hypothesis_id: non_empty(hypothesis_id, "verification hypothesis id")?,
            verifier_rule_id: None,
            stage,
            status: OutcomeStatus::Unknown,
            confidence: Probability::ZERO,
            rationale: non_empty(rationale, "verification rationale")?,
            evidence_ids: BTreeSet::new(),
        })
    }

    /// Returns the stable verification case identity.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Returns the entity whose hypothesis was verified.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the planned action identity that opened this case.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the hypothesis affected by a conclusive result.
    pub fn hypothesis_id(&self) -> &str {
        &self.hypothesis_id
    }

    /// Returns the winning verifier rule, if one matched.
    pub fn verifier_rule_id(&self) -> Option<&str> {
        self.verifier_rule_id.as_deref()
    }

    /// Returns the evidence collection stage.
    pub fn stage(&self) -> VerificationStage {
        self.stage
    }

    /// Returns the final classification.
    pub fn status(&self) -> OutcomeStatus {
        self.status
    }

    /// Returns the rule-assigned calibrated confidence.
    pub fn confidence(&self) -> Probability {
        self.confidence
    }

    /// Returns the human-readable decision explanation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns immutable evidence supporting the decision.
    pub fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence_ids
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireOutcome {
            case_id: String,
            subject: EntityId,
            action_id: String,
            hypothesis_id: String,
            verifier_rule_id: Option<String>,
            stage: VerificationStage,
            status: OutcomeStatus,
            confidence: Probability,
            rationale: String,
            evidence_ids: BTreeSet<EvidenceId>,
        }

        let wire = WireOutcome::deserialize(deserializer)?;
        if wire.status == OutcomeStatus::Unknown {
            if wire.verifier_rule_id.is_some()
                || wire.confidence != Probability::ZERO
                || !wire.evidence_ids.is_empty()
            {
                return Err(serde::de::Error::custom(OutcomeError::InvalidUnknown));
            }
            return Self::unknown(
                wire.case_id,
                wire.subject,
                wire.action_id,
                wire.hypothesis_id,
                wire.stage,
                wire.rationale,
            )
            .map_err(serde::de::Error::custom);
        }

        let verifier_rule_id = wire.verifier_rule_id.ok_or_else(|| {
            serde::de::Error::custom("verified outcome is missing verifier rule id")
        })?;
        Self::verified(
            wire.case_id,
            wire.subject,
            wire.action_id,
            wire.hypothesis_id,
            verifier_rule_id,
            wire.stage,
            wire.status,
            wire.confidence,
            wire.rationale,
            wire.evidence_ids,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    #[test]
    fn verified_outcome_round_trips_with_evidence() {
        let outcome = Outcome::verified(
            "case:1",
            subject(),
            "sqli.verify",
            "hypothesis:sqli",
            "verify.boolean",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(95).unwrap(),
            "Boolean responses diverged",
            BTreeSet::from([EvidenceId::parse("evidence:1").unwrap()]),
        )
        .unwrap();

        let encoded = serde_json::to_value(&outcome).unwrap();
        assert_eq!(serde_json::from_value::<Outcome>(encoded).unwrap(), outcome);
        assert_eq!(
            outcome.status().hypothesis_state(),
            Some(HypothesisState::Confirmed)
        );
    }

    #[test]
    fn unknown_outcome_has_canonical_wire_shape() {
        let outcome = Outcome::unknown(
            "case:1",
            subject(),
            "sqli.verify",
            "hypothesis:sqli",
            VerificationStage::Passive,
            "No rule matched",
        )
        .unwrap();
        let mut encoded = serde_json::to_value(outcome).unwrap();
        encoded["confidence"] = serde_json::json!(1);

        assert!(serde_json::from_value::<Outcome>(encoded).is_err());
    }

    #[test]
    fn confirmed_negative_is_terminal_and_rejects_the_hypothesis() {
        let outcome = Outcome::verified(
            "case:negative-control",
            subject(),
            "sqli.verify",
            "hypothesis:sqli",
            "verify.negative-control",
            VerificationStage::Active,
            OutcomeStatus::ConfirmedNegative,
            Probability::from_percent(97).unwrap(),
            "The audited negative control disproved the hypothesis",
            BTreeSet::from([EvidenceId::parse("evidence:negative-control").unwrap()]),
        )
        .unwrap();

        assert!(outcome.status().is_terminal());
        assert_eq!(
            outcome.status().hypothesis_state(),
            Some(HypothesisState::Rejected)
        );
        let encoded = serde_json::to_value(&outcome).unwrap();
        assert_eq!(encoded["status"], serde_json::json!("confirmed_negative"));
        assert_eq!(
            serde_json::from_value::<Outcome>(encoded.clone()).unwrap(),
            outcome
        );

        let mut passive = encoded;
        passive["stage"] = serde_json::json!("passive");
        assert!(serde_json::from_value::<Outcome>(passive).is_err());
    }

    #[test]
    fn conclusive_outcomes_require_evidence_and_confidence() {
        assert!(matches!(
            Outcome::verified(
                "case:passive-negative",
                subject(),
                "sqli.verify",
                "hypothesis:sqli",
                "verify.negative-control",
                VerificationStage::Passive,
                OutcomeStatus::ConfirmedNegative,
                Probability::from_percent(95).unwrap(),
                "A passive observation cannot establish a trusted negative",
                BTreeSet::from([EvidenceId::parse("evidence:passive").unwrap()]),
            ),
            Err(OutcomeError::ConfirmedNegativeRequiresActive)
        ));
        assert!(matches!(
            Outcome::verified(
                "case:1",
                subject(),
                "sqli.verify",
                "hypothesis:sqli",
                "verify.boolean",
                VerificationStage::Active,
                OutcomeStatus::FalsePositive,
                Probability::from_percent(80).unwrap(),
                "Control response matched",
                BTreeSet::new(),
            ),
            Err(OutcomeError::MissingEvidence { .. })
        ));
        assert!(matches!(
            Outcome::verified(
                "case:1",
                subject(),
                "sqli.verify",
                "hypothesis:sqli",
                "verify.boolean",
                VerificationStage::Active,
                OutcomeStatus::Success,
                Probability::ZERO,
                "Timing delta repeated",
                BTreeSet::from([EvidenceId::parse("evidence:1").unwrap()]),
            ),
            Err(OutcomeError::ZeroConfidence { .. })
        ));
    }
}
