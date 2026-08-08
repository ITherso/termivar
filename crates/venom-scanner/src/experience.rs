//! Deterministic experience derived from verification outcomes.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** no.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The store records immutable outcomes and turns repeated, subject-scoped,
//! suppression-eligible negatives into explainable action recommendations.
//! Target blocks, policy blocks, operational failures, and inconclusive
//! verification remain visible without being treated as proof that an action
//! has no utility. The store does not execute an action, mutate knowledge, or
//! make planner and adaptive policy depend on its internal representation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{EntityId, Outcome, OutcomeStatus, VerificationStage};

/// Validation and consistency errors raised by the experience store.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ExperienceStoreError {
    /// A suppression threshold of zero would suppress an action before it ran.
    #[error("consecutive suppression-eligible failure limit must be greater than zero")]
    ZeroFailureLimit,

    /// The same subject, action, case, and stage identified a different
    /// outcome or disposition.
    #[error(
        "experience identity conflict for subject {subject}, action {action_id}, case {case_id}, stage {stage:?}"
    )]
    IdentityConflict {
        /// Subject whose history contained the conflict.
        subject: EntityId,
        /// Action whose history contained the conflict.
        action_id: String,
        /// Verification case whose result changed.
        case_id: String,
        /// Verification stage whose result changed.
        stage: VerificationStage,
    },

    /// The monotonically increasing observation sequence overflowed.
    #[error("experience observation sequence overflowed")]
    SequenceOverflow,

    /// Persisted experience records were not contiguous and ordered.
    #[error("invalid persisted experience sequence: expected {expected}, found {actual}")]
    InvalidSequence {
        /// Required sequence at this position.
        expected: u64,
        /// Sequence found in the archive.
        actual: u64,
    },

    /// Persisted next-sequence state did not follow the final record.
    #[error("invalid next experience sequence: expected {expected}, found {actual}")]
    InvalidNextSequence {
        /// Required next sequence.
        expected: u64,
        /// Persisted next sequence.
        actual: u64,
    },

    /// Persisted state contained the same immutable observation more than once.
    #[error("persisted experience contains a duplicate observation")]
    DuplicateObservation,

    /// A caller attached a disposition that contradicts the verifier outcome.
    #[error("experience disposition {disposition:?} is incompatible with outcome {status:?}")]
    IncompatibleDisposition {
        /// Verifier status carried by the outcome.
        status: OutcomeStatus,
        /// Experience classification rejected by the store.
        disposition: ExperienceDisposition,
    },
}

/// Result of recording an outcome identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExperienceWrite {
    /// A previously unseen outcome was appended.
    Inserted,
    /// The exact immutable outcome was already present.
    Unchanged,
}

/// Reason an observed attempt should or should not influence future planning.
///
/// This classification deliberately lives outside [`OutcomeStatus`]. Target,
/// host-policy, transport, and executor failures are operational facts rather
/// than verifier conclusions. Only [`Self::VerificationRejected`] and
/// [`Self::ConfirmedNegative`] contribute to the suppression streak; transient
/// or inconclusive dispositions remain neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExperienceDisposition {
    /// The verifier reported a successful outcome for the action.
    ///
    /// This resets the action-scoped negative suppression streak. It does not,
    /// by itself, prove that the associated hypothesis was authorized to
    /// transition or that its state changed; consult the knowledge base and the
    /// complete verification report for authoritative hypothesis state.
    ConfirmedPositive,
    /// The action does not apply to the observed subject.
    NotApplicable,
    /// The target denied, rate-limited, or otherwise blocked the attempt.
    BlockedByTarget,
    /// Host authorization or safety policy refused the attempt.
    BlockedByPolicy,
    /// Network transport failed before verification could conclude.
    TransportFailure,
    /// The selected executor failed independently of the target response.
    ExecutorFailure,
    /// A verifier rejected the tested hypothesis.
    VerificationRejected,
    /// Available evidence could not support a deterministic conclusion.
    VerificationInconclusive,
    /// A trusted active check explicitly confirmed a negative result.
    ConfirmedNegative,
}

impl ExperienceDisposition {
    /// Infers the conservative disposition used by [`ExperienceStore::observe`].
    ///
    /// `FalsePositive` remains `VerificationRejected`: an outcome alone does
    /// not prove that an audited active negative check was performed.
    /// `Success` remains the action-level [`Self::ConfirmedPositive`] even when
    /// case policy suppresses a hypothesis transition.
    pub fn from_outcome(outcome: &Outcome) -> Self {
        match outcome.status() {
            OutcomeStatus::Success => Self::ConfirmedPositive,
            OutcomeStatus::Blocked => Self::BlockedByTarget,
            OutcomeStatus::Unknown | OutcomeStatus::NeedsReview => Self::VerificationInconclusive,
            OutcomeStatus::FalsePositive => Self::VerificationRejected,
            OutcomeStatus::ConfirmedNegative => Self::ConfirmedNegative,
            _ => Self::VerificationInconclusive,
        }
    }

    const fn accepts(self, status: OutcomeStatus) -> bool {
        match self {
            Self::ConfirmedPositive => matches!(status, OutcomeStatus::Success),
            Self::VerificationRejected => matches!(status, OutcomeStatus::FalsePositive),
            Self::ConfirmedNegative => matches!(status, OutcomeStatus::ConfirmedNegative),
            Self::BlockedByTarget => matches!(status, OutcomeStatus::Blocked),
            Self::NotApplicable
            | Self::BlockedByPolicy
            | Self::TransportFailure
            | Self::ExecutorFailure
            | Self::VerificationInconclusive => {
                matches!(status, OutcomeStatus::Unknown | OutcomeStatus::NeedsReview)
            },
        }
    }

    const fn suppression_effect(self) -> SuppressionEffect {
        match self {
            Self::ConfirmedPositive => SuppressionEffect::Reset,
            Self::VerificationRejected | Self::ConfirmedNegative => SuppressionEffect::Increment,
            Self::NotApplicable
            | Self::BlockedByTarget
            | Self::BlockedByPolicy
            | Self::TransportFailure
            | Self::ExecutorFailure
            | Self::VerificationInconclusive => SuppressionEffect::Neutral,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuppressionEffect {
    Increment,
    Reset,
    Neutral,
}

/// Stable learning policy applied when assessing one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExperiencePolicy {
    consecutive_failure_limit: u16,
}

impl ExperiencePolicy {
    /// Creates a policy that suppresses an action after this many consecutive
    /// suppression-eligible verified negatives.
    pub fn new(consecutive_failure_limit: u16) -> Result<Self, ExperienceStoreError> {
        if consecutive_failure_limit == 0 {
            return Err(ExperienceStoreError::ZeroFailureLimit);
        }
        Ok(Self {
            consecutive_failure_limit,
        })
    }

    /// Returns the consecutive suppression-eligible negative threshold.
    ///
    /// This compatibility name is retained for the existing source and wire
    /// contract. Prefer [`Self::consecutive_suppressible_failure_limit`] in new
    /// integrations.
    pub fn consecutive_failure_limit(self) -> u16 {
        self.consecutive_failure_limit
    }

    /// Returns the consecutive suppression-eligible negative threshold.
    pub fn consecutive_suppressible_failure_limit(self) -> u16 {
        self.consecutive_failure_limit
    }
}

impl Default for ExperiencePolicy {
    fn default() -> Self {
        Self {
            consecutive_failure_limit: 10,
        }
    }
}

impl<'de> Deserialize<'de> for ExperiencePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WirePolicy {
            consecutive_failure_limit: u16,
        }

        let wire = WirePolicy::deserialize(deserializer)?;
        Self::new(wire.consecutive_failure_limit).map_err(serde::de::Error::custom)
    }
}

/// Recommendation derived from completed attempts for one subject and action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExperienceRecommendation {
    /// No completed attempt exists, so the action may be explored.
    Explore,
    /// History is insufficient to suppress another attempt.
    Continue,
    /// Repeating the action has no current utility for this subject.
    Suppress,
}

/// Immutable record stored in global observation order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExperienceRecord {
    sequence: u64,
    outcome: Outcome,
    disposition: ExperienceDisposition,
}

impl ExperienceRecord {
    /// Returns the global zero-based observation sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the immutable verification outcome.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Returns why this result may or may not influence future planning.
    pub fn disposition(&self) -> ExperienceDisposition {
        self.disposition
    }
}

impl<'de> Deserialize<'de> for ExperienceRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireRecord {
            sequence: u64,
            outcome: Outcome,
            #[serde(default)]
            disposition: Option<ExperienceDisposition>,
        }

        let wire = WireRecord::deserialize(deserializer)?;
        let disposition = wire
            .disposition
            .unwrap_or_else(|| ExperienceDisposition::from_outcome(&wire.outcome));
        validate_disposition(&wire.outcome, disposition).map_err(serde::de::Error::custom)?;
        Ok(Self {
            sequence: wire.sequence,
            outcome: wire.outcome,
            disposition,
        })
    }
}

/// Explainable assessment of action history for one subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExperienceAssessment {
    subject: EntityId,
    action_id: String,
    completed_attempts: usize,
    consecutive_failures: u16,
    last_status: Option<OutcomeStatus>,
    last_stage: Option<VerificationStage>,
    last_disposition: Option<ExperienceDisposition>,
    recommendation: ExperienceRecommendation,
    rationale: String,
}

impl ExperienceAssessment {
    /// Returns the subject whose history was assessed.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the assessed action identity.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the number of distinct cases with completed attempts.
    pub fn completed_attempts(&self) -> usize {
        self.completed_attempts
    }

    /// Returns suppression-eligible negatives since the most recent success.
    ///
    /// This compatibility name no longer counts target blocks, policy blocks,
    /// operational failures, or inconclusive verification.
    pub fn consecutive_failures(&self) -> u16 {
        self.consecutive_failures
    }

    /// Returns suppression-eligible verified negatives since the most recent success.
    pub fn consecutive_suppressible_failures(&self) -> u16 {
        self.consecutive_failures
    }

    /// Returns the latest completed status, if one exists.
    pub fn last_status(&self) -> Option<OutcomeStatus> {
        self.last_status
    }

    /// Returns the latest completed verification stage, if one exists.
    pub fn last_stage(&self) -> Option<VerificationStage> {
        self.last_stage
    }

    /// Returns the latest completed attempt classification, if one exists.
    pub fn last_disposition(&self) -> Option<ExperienceDisposition> {
        self.last_disposition
    }

    /// Returns the deterministic learning recommendation.
    pub fn recommendation(&self) -> ExperienceRecommendation {
        self.recommendation
    }

    /// Returns the human-readable recommendation explanation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns whether policy recommends excluding the action.
    pub fn is_suppressed(&self) -> bool {
        self.recommendation == ExperienceRecommendation::Suppress
    }
}

/// Replayable, target-scoped outcome experience.
///
/// Observation order is represented by a monotonic integer rather than wall
/// clock time. Recording an identical outcome is idempotent. Passive
/// inconclusive results do not count as completed attempts; a later active
/// result for the same case replaces them during assessment.
///
/// This store is action-outcome learning history. It does not receive or
/// preserve [`crate::VerificationCase`] transition authorization, so an
/// [`ExperienceDisposition::ConfirmedPositive`] is not evidence that a
/// hypothesis state changed. The [`KnowledgeBase`](crate::KnowledgeBase) and
/// complete [`VerificationReport`](crate::VerificationReport) remain
/// authoritative for hypothesis state and transition audit.
///
/// # Example
///
/// ```rust
/// use venom_scanner::{ExperiencePolicy, ExperienceStore};
///
/// let store = ExperienceStore::new();
/// assert_eq!(store.len(), 0);
/// assert_eq!(ExperiencePolicy::default().consecutive_failure_limit(), 10);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExperienceStore {
    next_sequence: u64,
    records: Vec<ExperienceRecord>,
}

impl ExperienceStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one immutable outcome in deterministic call order.
    pub fn observe(&mut self, outcome: Outcome) -> Result<ExperienceWrite, ExperienceStoreError> {
        let disposition = ExperienceDisposition::from_outcome(&outcome);
        self.observe_with_disposition(outcome, disposition)
    }

    /// Records an outcome with an explicit, status-compatible disposition.
    ///
    /// Callers should use this only when structured policy or an audited
    /// verifier can distinguish the conservative classification produced by
    /// [`Self::observe`]. Operational failures should not be converted into a
    /// synthetic successful or negative verifier result.
    pub fn observe_with_disposition(
        &mut self,
        outcome: Outcome,
        disposition: ExperienceDisposition,
    ) -> Result<ExperienceWrite, ExperienceStoreError> {
        validate_disposition(&outcome, disposition)?;
        if let Some(existing) = self
            .records
            .iter()
            .find(|record| same_identity(record.outcome(), &outcome))
        {
            return if existing.outcome == outcome && existing.disposition == disposition {
                Ok(ExperienceWrite::Unchanged)
            } else {
                Err(ExperienceStoreError::IdentityConflict {
                    subject: outcome.subject().clone(),
                    action_id: outcome.action_id().to_owned(),
                    case_id: outcome.case_id().to_owned(),
                    stage: outcome.stage(),
                })
            };
        }

        let following = self
            .next_sequence
            .checked_add(1)
            .ok_or(ExperienceStoreError::SequenceOverflow)?;
        self.records.push(ExperienceRecord {
            sequence: self.next_sequence,
            outcome,
            disposition,
        });
        self.next_sequence = following;
        Ok(ExperienceWrite::Inserted)
    }

    /// Returns the number of unique stage outcomes.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether no outcomes have been observed.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Returns all records in stable global observation order.
    pub fn records(&self) -> &[ExperienceRecord] {
        &self.records
    }

    /// Returns records for one subject and action in observation order.
    pub fn history<'a>(
        &'a self,
        subject: &'a EntityId,
        action_id: &'a str,
    ) -> impl Iterator<Item = &'a ExperienceRecord> + 'a {
        self.records.iter().filter(move |record| {
            record.outcome.subject() == subject && record.outcome.action_id() == action_id
        })
    }

    /// Assesses the latest completed result for each distinct verification case.
    pub fn assess(
        &self,
        subject: &EntityId,
        action_id: &str,
        policy: ExperiencePolicy,
    ) -> ExperienceAssessment {
        let mut latest_by_case = BTreeMap::<&str, &ExperienceRecord>::new();
        for record in self.history(subject, action_id) {
            latest_by_case
                .entry(record.outcome.case_id())
                .and_modify(|existing| {
                    if existing.outcome.stage() == VerificationStage::Passive
                        && record.outcome.stage() == VerificationStage::Active
                    {
                        *existing = record;
                    }
                })
                .or_insert(record);
        }
        let mut completed: Vec<_> = latest_by_case
            .values()
            .copied()
            .filter(|record| is_completed_attempt(record.outcome()))
            .collect();
        completed.sort_by_key(|record| record.sequence);

        let mut consecutive_failures = 0_u16;
        for record in completed.iter().rev() {
            match record.disposition.suppression_effect() {
                SuppressionEffect::Increment => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                },
                SuppressionEffect::Reset => break,
                SuppressionEffect::Neutral => {},
            }
        }

        let last = completed.last().map(|record| record.outcome());
        let last_disposition = completed.last().map(|record| record.disposition());
        let recommendation = if consecutive_failures >= policy.consecutive_failure_limit {
            ExperienceRecommendation::Suppress
        } else if completed.is_empty() {
            ExperienceRecommendation::Explore
        } else {
            ExperienceRecommendation::Continue
        };
        let rationale = match recommendation {
            ExperienceRecommendation::Explore => {
                "no completed experience exists for this subject and action".to_owned()
            },
            ExperienceRecommendation::Continue => format!(
                "{consecutive_failures} suppression-eligible verified negatives remain below the policy limit of {}",
                policy.consecutive_failure_limit
            ),
            ExperienceRecommendation::Suppress => format!(
                "{consecutive_failures} suppression-eligible verified negatives reached the policy limit of {}",
                policy.consecutive_failure_limit
            ),
        };

        ExperienceAssessment {
            subject: subject.clone(),
            action_id: action_id.to_owned(),
            completed_attempts: completed.len(),
            consecutive_failures,
            last_status: last.map(Outcome::status),
            last_stage: last.map(Outcome::stage),
            last_disposition,
            recommendation,
            rationale,
        }
    }

    /// Returns policy-suppressed action IDs for one subject in stable order.
    pub fn suppressed_actions(
        &self,
        subject: &EntityId,
        policy: ExperiencePolicy,
    ) -> BTreeSet<String> {
        let action_ids: BTreeSet<_> = self
            .records
            .iter()
            .filter(|record| record.outcome.subject() == subject)
            .map(|record| record.outcome.action_id().to_owned())
            .collect();
        action_ids
            .into_iter()
            .filter(|action_id| self.assess(subject, action_id, policy).is_suppressed())
            .collect()
    }
}

impl<'de> Deserialize<'de> for ExperienceStore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireStore {
            next_sequence: u64,
            records: Vec<ExperienceRecord>,
        }

        let wire = WireStore::deserialize(deserializer)?;
        for (expected, record) in wire.records.iter().enumerate() {
            let expected = u64::try_from(expected).map_err(serde::de::Error::custom)?;
            if record.sequence != expected {
                return Err(serde::de::Error::custom(
                    ExperienceStoreError::InvalidSequence {
                        expected,
                        actual: record.sequence,
                    },
                ));
            }
        }
        let expected = u64::try_from(wire.records.len()).map_err(serde::de::Error::custom)?;
        if wire.next_sequence != expected {
            return Err(serde::de::Error::custom(
                ExperienceStoreError::InvalidNextSequence {
                    expected,
                    actual: wire.next_sequence,
                },
            ));
        }

        let mut store = Self::new();
        for record in wire.records {
            let write = store
                .observe_with_disposition(record.outcome, record.disposition)
                .map_err(serde::de::Error::custom)?;
            if write == ExperienceWrite::Unchanged {
                return Err(serde::de::Error::custom(
                    ExperienceStoreError::DuplicateObservation,
                ));
            }
        }
        Ok(store)
    }
}

fn same_identity(left: &Outcome, right: &Outcome) -> bool {
    left.subject() == right.subject()
        && left.action_id() == right.action_id()
        && left.case_id() == right.case_id()
        && left.stage() == right.stage()
}

fn validate_disposition(
    outcome: &Outcome,
    disposition: ExperienceDisposition,
) -> Result<(), ExperienceStoreError> {
    if disposition.accepts(outcome.status()) {
        Ok(())
    } else {
        Err(ExperienceStoreError::IncompatibleDisposition {
            status: outcome.status(),
            disposition,
        })
    }
}

fn is_completed_attempt(outcome: &Outcome) -> bool {
    match outcome.status() {
        OutcomeStatus::Success
        | OutcomeStatus::Blocked
        | OutcomeStatus::FalsePositive
        | OutcomeStatus::ConfirmedNegative => true,
        OutcomeStatus::Unknown | OutcomeStatus::NeedsReview => {
            outcome.stage() == VerificationStage::Active
        },
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use venom_core::{EvidenceId, Probability};

    fn subject(value: &str) -> EntityId {
        EntityId::new(value).unwrap()
    }

    fn verified(
        case_number: usize,
        subject: EntityId,
        action_id: &str,
        stage: VerificationStage,
        status: OutcomeStatus,
    ) -> Outcome {
        if status == OutcomeStatus::Unknown {
            return Outcome::unknown(
                format!("case:{case_number}"),
                subject,
                action_id,
                "hypothesis:http-control",
                stage,
                "deterministic fixture is inconclusive",
            )
            .unwrap();
        }
        Outcome::verified(
            format!("case:{case_number}"),
            subject,
            action_id,
            "hypothesis:http-control",
            "verify.http-control",
            stage,
            status,
            Probability::from_percent(90).unwrap(),
            "deterministic fixture outcome",
            BTreeSet::from([EvidenceId::parse(format!("evidence:{case_number}")).unwrap()]),
        )
        .unwrap()
    }

    #[test]
    fn repeated_confirmed_negatives_suppress_only_the_scoped_action() {
        let target = subject("endpoint:https://example.test");
        let other = subject("endpoint:https://other.test");
        let mut store = ExperienceStore::new();
        for case in 0..10 {
            store
                .observe(verified(
                    case,
                    target.clone(),
                    "http.x-forwarded-host",
                    VerificationStage::Active,
                    OutcomeStatus::ConfirmedNegative,
                ))
                .unwrap();
        }

        let assessment = store.assess(
            &target,
            "http.x-forwarded-host",
            ExperiencePolicy::default(),
        );
        assert_eq!(assessment.completed_attempts(), 10);
        assert_eq!(assessment.consecutive_failures(), 10);
        assert_eq!(
            assessment.recommendation(),
            ExperienceRecommendation::Suppress
        );
        assert_eq!(
            store.suppressed_actions(&target, ExperiencePolicy::default()),
            BTreeSet::from(["http.x-forwarded-host".to_owned()])
        );
        assert!(store
            .suppressed_actions(&other, ExperiencePolicy::default())
            .is_empty());
    }

    #[test]
    fn operational_and_applicability_dispositions_are_neutral() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();

        let observations = [
            (
                OutcomeStatus::Blocked,
                ExperienceDisposition::BlockedByTarget,
            ),
            (
                OutcomeStatus::Unknown,
                ExperienceDisposition::BlockedByPolicy,
            ),
            (
                OutcomeStatus::Unknown,
                ExperienceDisposition::TransportFailure,
            ),
            (
                OutcomeStatus::Unknown,
                ExperienceDisposition::ExecutorFailure,
            ),
            (
                OutcomeStatus::Unknown,
                ExperienceDisposition::VerificationInconclusive,
            ),
            (OutcomeStatus::Unknown, ExperienceDisposition::NotApplicable),
        ];
        for (case, (status, disposition)) in observations.into_iter().enumerate() {
            store
                .observe_with_disposition(
                    verified(
                        case,
                        target.clone(),
                        "http.enumeration",
                        VerificationStage::Active,
                        status,
                    ),
                    disposition,
                )
                .unwrap();
        }

        let assessment = store.assess(
            &target,
            "http.enumeration",
            ExperiencePolicy::new(1).unwrap(),
        );
        assert_eq!(assessment.completed_attempts(), observations.len());
        assert_eq!(assessment.consecutive_suppressible_failures(), 0);
        assert_eq!(
            assessment.last_disposition(),
            Some(ExperienceDisposition::NotApplicable)
        );
        assert_eq!(
            assessment.recommendation(),
            ExperienceRecommendation::Continue
        );
    }

    #[test]
    fn neutral_observations_do_not_add_to_or_erase_negative_history() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();
        store
            .observe(verified(
                0,
                target.clone(),
                "http.enumeration",
                VerificationStage::Passive,
                OutcomeStatus::FalsePositive,
            ))
            .unwrap();
        store
            .observe(verified(
                1,
                target.clone(),
                "http.enumeration",
                VerificationStage::Active,
                OutcomeStatus::Blocked,
            ))
            .unwrap();
        store
            .observe(verified(
                2,
                target.clone(),
                "http.enumeration",
                VerificationStage::Active,
                OutcomeStatus::ConfirmedNegative,
            ))
            .unwrap();

        let assessment = store.assess(
            &target,
            "http.enumeration",
            ExperiencePolicy::new(2).unwrap(),
        );
        assert_eq!(assessment.consecutive_suppressible_failures(), 2);
        assert!(assessment.is_suppressed());
    }

    #[test]
    fn success_resets_the_suppressible_failure_streak() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();
        for case in 0..3 {
            store
                .observe(verified(
                    case,
                    target.clone(),
                    "http.enumeration",
                    VerificationStage::Active,
                    OutcomeStatus::ConfirmedNegative,
                ))
                .unwrap();
        }
        store
            .observe(verified(
                3,
                target.clone(),
                "http.enumeration",
                VerificationStage::Active,
                OutcomeStatus::Success,
            ))
            .unwrap();

        let assessment = store.assess(&target, "http.enumeration", ExperiencePolicy::default());
        assert_eq!(assessment.consecutive_failures(), 0);
        assert_eq!(assessment.last_status(), Some(OutcomeStatus::Success));
        assert_eq!(
            assessment.recommendation(),
            ExperienceRecommendation::Continue
        );
    }

    #[test]
    fn active_result_supersedes_passive_inconclusive_result_for_one_case() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();
        store
            .observe(
                Outcome::unknown(
                    "case:0",
                    target.clone(),
                    "sqli.boolean",
                    "hypothesis:sqli",
                    VerificationStage::Passive,
                    "passive evidence is inconclusive",
                )
                .unwrap(),
            )
            .unwrap();
        store
            .observe(verified(
                0,
                target.clone(),
                "sqli.boolean",
                VerificationStage::Active,
                OutcomeStatus::ConfirmedNegative,
            ))
            .unwrap();

        let assessment = store.assess(&target, "sqli.boolean", ExperiencePolicy::new(1).unwrap());
        assert_eq!(assessment.completed_attempts(), 1);
        assert_eq!(assessment.last_stage(), Some(VerificationStage::Active));
        assert_eq!(
            assessment.last_disposition(),
            Some(ExperienceDisposition::ConfirmedNegative)
        );
        assert!(assessment.is_suppressed());
    }

    #[test]
    fn writes_are_idempotent_and_identity_conflicts_are_rejected() {
        let target = subject("endpoint:https://example.test");
        let original = verified(
            0,
            target.clone(),
            "http.403-bypass",
            VerificationStage::Active,
            OutcomeStatus::Blocked,
        );
        let conflicting = verified(
            0,
            target,
            "http.403-bypass",
            VerificationStage::Active,
            OutcomeStatus::Success,
        );
        let mut store = ExperienceStore::new();

        assert_eq!(
            store.observe(original.clone()).unwrap(),
            ExperienceWrite::Inserted
        );
        assert_eq!(store.observe(original).unwrap(), ExperienceWrite::Unchanged);
        let reclassified = verified(
            1,
            subject("endpoint:https://example.test"),
            "http.403-bypass",
            VerificationStage::Active,
            OutcomeStatus::Unknown,
        );
        store
            .observe_with_disposition(
                reclassified.clone(),
                ExperienceDisposition::TransportFailure,
            )
            .unwrap();
        assert!(matches!(
            store.observe_with_disposition(reclassified, ExperienceDisposition::ExecutorFailure,),
            Err(ExperienceStoreError::IdentityConflict { .. })
        ));
        assert!(matches!(
            store.observe(conflicting),
            Err(ExperienceStoreError::IdentityConflict { .. })
        ));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn store_round_trips_and_rejects_invalid_sequences() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();
        store
            .observe_with_disposition(
                verified(
                    0,
                    target,
                    "http.enumeration",
                    VerificationStage::Passive,
                    OutcomeStatus::Unknown,
                ),
                ExperienceDisposition::BlockedByPolicy,
            )
            .unwrap();
        let encoded = serde_json::to_value(&store).unwrap();
        assert_eq!(
            serde_json::from_value::<ExperienceStore>(encoded.clone()).unwrap(),
            store
        );
        assert_eq!(
            encoded["records"][0]["disposition"],
            serde_json::json!("blocked_by_policy")
        );

        let mut legacy = encoded.clone();
        legacy["records"][0]
            .as_object_mut()
            .unwrap()
            .remove("disposition");
        let migrated = serde_json::from_value::<ExperienceStore>(legacy).unwrap();
        assert_eq!(
            migrated.records()[0].disposition(),
            ExperienceDisposition::VerificationInconclusive
        );

        let mut incompatible = encoded.clone();
        incompatible["records"][0]["disposition"] = serde_json::json!("confirmed_positive");
        assert!(serde_json::from_value::<ExperienceStore>(incompatible).is_err());

        let mut invalid_record = encoded.clone();
        invalid_record["records"][0]["sequence"] = serde_json::json!(1);
        assert!(serde_json::from_value::<ExperienceStore>(invalid_record).is_err());

        let mut invalid_next = encoded;
        invalid_next["next_sequence"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ExperienceStore>(invalid_next).is_err());

        let mut duplicate = serde_json::to_value(&store).unwrap();
        let repeated = duplicate["records"][0].clone();
        duplicate["records"].as_array_mut().unwrap().push(repeated);
        duplicate["records"][1]["sequence"] = serde_json::json!(1);
        duplicate["next_sequence"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ExperienceStore>(duplicate).is_err());
        assert!(
            serde_json::from_value::<ExperiencePolicy>(serde_json::json!({
                "consecutive_failure_limit": 0
            }))
            .is_err()
        );
    }
}
