//! Deterministic experience derived from verification outcomes.
//!
//! The store records immutable outcomes and turns repeated, subject-scoped
//! failures into explainable action recommendations. It does not execute an
//! action, mutate knowledge, or make planner and adaptive policy depend on its
//! internal representation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{EntityId, Outcome, OutcomeStatus, VerificationStage};

/// Validation and consistency errors raised by the experience store.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ExperienceStoreError {
    /// A suppression threshold of zero would suppress an action before it ran.
    #[error("consecutive failure limit must be greater than zero")]
    ZeroFailureLimit,

    /// The same subject, action, case, and stage identified a different outcome.
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

/// Stable learning policy applied when assessing one action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExperiencePolicy {
    consecutive_failure_limit: u16,
}

impl ExperiencePolicy {
    /// Creates a policy that suppresses an action after this many consecutive failures.
    pub fn new(consecutive_failure_limit: u16) -> Result<Self, ExperienceStoreError> {
        if consecutive_failure_limit == 0 {
            return Err(ExperienceStoreError::ZeroFailureLimit);
        }
        Ok(Self {
            consecutive_failure_limit,
        })
    }

    /// Returns the consecutive completed-failure threshold.
    pub fn consecutive_failure_limit(self) -> u16 {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperienceRecord {
    sequence: u64,
    outcome: Outcome,
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

    /// Returns failures since the most recent success.
    pub fn consecutive_failures(&self) -> u16 {
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
        if let Some(existing) = self
            .records
            .iter()
            .find(|record| same_identity(record.outcome(), &outcome))
        {
            return if existing.outcome == outcome {
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
            if record.outcome.status() == OutcomeStatus::Success {
                break;
            }
            consecutive_failures = consecutive_failures.saturating_add(1);
        }

        let last = completed.last().map(|record| record.outcome());
        let rejected = last.is_some_and(|outcome| outcome.status() == OutcomeStatus::FalsePositive);
        let recommendation = if rejected || consecutive_failures >= policy.consecutive_failure_limit
        {
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
                "{consecutive_failures} consecutive failures remain below the policy limit of {}",
                policy.consecutive_failure_limit
            ),
            ExperienceRecommendation::Suppress if rejected => {
                "the latest completed outcome rejected the action hypothesis".to_owned()
            },
            ExperienceRecommendation::Suppress => format!(
                "{consecutive_failures} consecutive failures reached the policy limit of {}",
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
                .observe(record.outcome)
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

fn is_completed_attempt(outcome: &Outcome) -> bool {
    match outcome.status() {
        OutcomeStatus::Success | OutcomeStatus::Blocked | OutcomeStatus::FalsePositive => true,
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
    fn ten_repeated_failures_suppress_only_the_scoped_action() {
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
                    OutcomeStatus::Blocked,
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
    fn success_resets_the_failure_streak() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();
        for case in 0..10 {
            store
                .observe(verified(
                    case,
                    target.clone(),
                    "http.enumeration",
                    VerificationStage::Active,
                    OutcomeStatus::Unknown,
                ))
                .unwrap();
        }
        store
            .observe(verified(
                10,
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
            .observe(verified(
                0,
                target.clone(),
                "sqli.boolean",
                VerificationStage::Active,
                OutcomeStatus::FalsePositive,
            ))
            .unwrap();
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

        let assessment = store.assess(&target, "sqli.boolean", ExperiencePolicy::default());
        assert_eq!(assessment.completed_attempts(), 1);
        assert_eq!(assessment.last_stage(), Some(VerificationStage::Active));
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
        assert!(matches!(
            store.observe(conflicting),
            Err(ExperienceStoreError::IdentityConflict { .. })
        ));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_round_trips_and_rejects_invalid_sequences() {
        let target = subject("endpoint:https://example.test");
        let mut store = ExperienceStore::new();
        store
            .observe(verified(
                0,
                target,
                "http.enumeration",
                VerificationStage::Passive,
                OutcomeStatus::Blocked,
            ))
            .unwrap();
        let encoded = serde_json::to_value(&store).unwrap();
        assert_eq!(
            serde_json::from_value::<ExperienceStore>(encoded.clone()).unwrap(),
            store
        );

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
