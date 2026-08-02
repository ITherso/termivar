//! Deterministic passive and active verification.
//!
//! Verifiers consume immutable knowledge snapshots and never execute probes.
//! Passive rules may use existing evidence. Active rules are eligible only
//! when their expression cites evidence added after the passive snapshot, so
//! probe execution remains an explicit boundary outside the decision engine.

use std::collections::{BTreeMap, BTreeSet};

use serde::{de::IgnoredAny, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{
    EntityId, EvidenceId, HypothesisState, Outcome, OutcomeError, OutcomeStatus, Probability,
    VerificationStage,
};

use crate::{
    knowledge::{
        HypothesisStateTransition, KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot,
        KnowledgeWrite,
    },
    payload_strategy::PayloadStrategyRef,
    rules::{Expression, ExpressionEvaluation, RuleEngineError},
};

/// Validation and evaluation errors raised by verification components.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerificationError {
    /// A required case, rule, or explanation value was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// A rule attempted to explicitly emit the evidence-free fallback status.
    #[error("verification rule {rule_id} cannot emit the reserved unknown status")]
    ReservedUnknownStatus { rule_id: String },

    /// A conclusive rule was configured with zero confidence.
    #[error("verification rule {rule_id} must have non-zero confidence")]
    ZeroConfidence { rule_id: String },

    /// A confirmed-negative rule was configured for passive evaluation.
    #[error("verification rule {rule_id} must use the active stage for confirmed negatives")]
    ConfirmedNegativeRequiresActive { rule_id: String },

    /// Case-correlated evaluation was requested for a non-evidence expression.
    #[error(
        "verification rule {rule_id} must use only raw evidence when case correlation is required"
    )]
    CaseCorrelationRequiresEvidenceOnly { rule_id: String },

    /// A verifier was given a rule for the other evidence collection stage.
    #[error("verification rule {rule_id} belongs to {actual:?}, expected {expected:?}")]
    WrongStage {
        /// Rule with the incompatible stage.
        rule_id: String,
        /// Stage owned by the verifier.
        expected: VerificationStage,
        /// Stage declared by the rule.
        actual: VerificationStage,
    },

    /// A rule identity was reused with different semantics.
    #[error("verification rule identity {id} already has a different definition")]
    RuleIdentityConflict { id: String },

    /// The case and snapshot refer to different subjects.
    #[error("verification case subject {expected} does not match snapshot subject {actual}")]
    SnapshotSubjectMismatch {
        /// Subject declared by the verification case.
        expected: EntityId,
        /// Subject captured by the snapshot.
        actual: EntityId,
    },

    /// The case references a hypothesis absent from the snapshot or knowledge base.
    #[error("verification hypothesis {hypothesis_id} was not found")]
    UnknownHypothesis { hypothesis_id: String },

    /// A matched rule relied only on absence or ontology and cited no observation.
    #[error("matched verification rule {rule_id} did not cite any evidence")]
    MissingContributingEvidence { rule_id: String },

    /// An active snapshot omitted evidence that existed before the probe.
    #[error("active snapshot is missing baseline evidence {evidence_id}")]
    NonMonotonicSnapshot { evidence_id: EvidenceId },

    /// A persisted outcome referenced evidence absent from the knowledge base.
    #[error("verification evidence {evidence_id} was not found")]
    UnknownEvidence { evidence_id: EvidenceId },

    /// Outcome evidence belongs to a different subject.
    #[error("verification evidence {evidence_id} does not belong to subject {subject}")]
    EvidenceSubjectMismatch {
        /// Evidence with incompatible provenance.
        evidence_id: EvidenceId,
        /// Subject declared by the outcome.
        subject: EntityId,
    },

    /// A verifier attempted to reverse an existing terminal conclusion.
    #[error(
        "verification cannot change terminal hypothesis {hypothesis_id} from {current:?} to {attempted:?}"
    )]
    ConflictingTerminalState {
        /// Hypothesis protected by the terminal transition.
        hypothesis_id: String,
        /// Terminal state already stored.
        current: HypothesisState,
        /// Opposite terminal state requested by the outcome.
        attempted: HypothesisState,
    },

    /// Expression evaluation failed.
    #[error(transparent)]
    Rule(#[from] RuleEngineError),

    /// Outcome construction failed.
    #[error(transparent)]
    Outcome(#[from] OutcomeError),

    /// A hypothesis update conflicted with stored knowledge.
    #[error(transparent)]
    Knowledge(#[from] KnowledgeBaseError),
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, VerificationError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(VerificationError::EmptyValue { field });
    }
    Ok(value)
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Stable identity linking a planned action to the hypothesis it verifies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationCase {
    id: String,
    subject: EntityId,
    action_id: String,
    hypothesis_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_strategy: Option<PayloadStrategyRef>,
}

impl VerificationCase {
    /// Creates a validated verification case.
    pub fn new(
        id: impl Into<String>,
        subject: EntityId,
        action_id: impl Into<String>,
        hypothesis_id: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        Ok(Self {
            id: non_empty(id, "verification case id")?,
            subject,
            action_id: non_empty(action_id, "verification action id")?,
            hypothesis_id: non_empty(hypothesis_id, "verification hypothesis id")?,
            payload_strategy: None,
        })
    }

    /// Attaches the exact planner-selected strategy revision to this case.
    pub fn with_payload_strategy(mut self, strategy: Option<PayloadStrategyRef>) -> Self {
        self.payload_strategy = strategy;
        self
    }

    /// Returns the stable case identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the subject being verified.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the planner action that opened the case.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the hypothesis affected by a conclusive outcome.
    pub fn hypothesis_id(&self) -> &str {
        &self.hypothesis_id
    }

    /// Returns the payload strategy selected for this case, when present.
    pub const fn payload_strategy(&self) -> Option<&PayloadStrategyRef> {
        self.payload_strategy.as_ref()
    }
}

impl<'de> Deserialize<'de> for VerificationCase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireCase {
            id: String,
            subject: EntityId,
            action_id: String,
            hypothesis_id: String,
            #[serde(default)]
            payload_strategy: Option<PayloadStrategyRef>,
            #[serde(flatten)]
            extensions: BTreeMap<String, IgnoredAny>,
        }

        let wire = WireCase::deserialize(deserializer)?;
        if wire
            .extensions
            .keys()
            .any(|field| field.starts_with("payload_"))
        {
            return Err(serde::de::Error::custom(
                "unknown reserved payload strategy field",
            ));
        }
        Self::new(wire.id, wire.subject, wire.action_id, wire.hypothesis_id)
            .map(|case| case.with_payload_strategy(wire.payload_strategy))
            .map_err(serde::de::Error::custom)
    }
}

/// Declarative evidence expression mapped to one non-unknown outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationRule {
    id: String,
    stage: VerificationStage,
    priority: u16,
    condition: Expression,
    outcome: OutcomeStatus,
    confidence: Probability,
    rationale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    case_correlated_evidence: bool,
}

impl VerificationRule {
    /// Creates a validated verifier rule.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        stage: VerificationStage,
        priority: u16,
        condition: Expression,
        outcome: OutcomeStatus,
        confidence: Probability,
        rationale: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        let id = non_empty(id, "verification rule id")?;
        if outcome == OutcomeStatus::Unknown {
            return Err(VerificationError::ReservedUnknownStatus { rule_id: id });
        }
        if outcome == OutcomeStatus::ConfirmedNegative && stage != VerificationStage::Active {
            return Err(VerificationError::ConfirmedNegativeRequiresActive { rule_id: id });
        }
        if confidence == Probability::ZERO {
            return Err(VerificationError::ZeroConfidence { rule_id: id });
        }
        Ok(Self {
            id,
            stage,
            priority,
            condition,
            outcome,
            confidence,
            rationale: non_empty(rationale, "verification rule rationale")?,
            action_id: None,
            case_correlated_evidence: false,
        })
    }

    /// Restricts this rule to verification cases opened by one action.
    pub fn scoped_to_action(
        mut self,
        action_id: impl Into<String>,
    ) -> Result<Self, VerificationError> {
        self.action_id = Some(non_empty(action_id, "verification rule action id")?);
        Ok(self)
    }

    /// Restricts raw evidence evaluation to the current case correlation ID.
    ///
    /// Case correlation is valid only for evidence-layer expressions. Facts,
    /// hypotheses, and ontology claims are not produced by one executor case.
    pub fn with_case_correlated_evidence(mut self) -> Result<Self, VerificationError> {
        if !self.condition.uses_only_evidence() {
            return Err(VerificationError::CaseCorrelationRequiresEvidenceOnly {
                rule_id: self.id.clone(),
            });
        }
        self.case_correlated_evidence = true;
        Ok(self)
    }

    /// Returns the stable rule identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the evidence collection stage owned by this rule.
    pub fn stage(&self) -> VerificationStage {
        self.stage
    }

    /// Returns the deterministic conflict-resolution priority.
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the evidence expression.
    pub fn condition(&self) -> &Expression {
        &self.condition
    }

    /// Returns the classification emitted when the expression wins.
    pub fn outcome(&self) -> OutcomeStatus {
        self.outcome
    }

    /// Returns the calibrated confidence assigned to this rule.
    pub fn confidence(&self) -> Probability {
        self.confidence
    }

    /// Returns the rule's human-readable explanation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns the action identity required by this rule, if scoped.
    pub fn action_id(&self) -> Option<&str> {
        self.action_id.as_deref()
    }

    /// Returns whether raw evidence is limited to the current case correlation.
    pub fn requires_case_correlated_evidence(&self) -> bool {
        self.case_correlated_evidence
    }
}

impl<'de> Deserialize<'de> for VerificationRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireRule {
            id: String,
            stage: VerificationStage,
            priority: u16,
            condition: Expression,
            outcome: OutcomeStatus,
            confidence: Probability,
            rationale: String,
            #[serde(default)]
            action_id: Option<String>,
            #[serde(default)]
            case_correlated_evidence: bool,
        }

        let wire = WireRule::deserialize(deserializer)?;
        let mut rule = Self::new(
            wire.id,
            wire.stage,
            wire.priority,
            wire.condition,
            wire.outcome,
            wire.confidence,
            wire.rationale,
        )
        .map_err(serde::de::Error::custom)?;
        if let Some(action_id) = wire.action_id {
            rule = rule
                .scoped_to_action(action_id)
                .map_err(serde::de::Error::custom)?;
        }
        if wire.case_correlated_evidence {
            rule = rule
                .with_case_correlated_evidence()
                .map_err(serde::de::Error::custom)?;
        }
        Ok(rule)
    }
}

/// Result of registering a verifier rule identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerifierWrite {
    /// A new rule was registered.
    Inserted,
    /// The identical rule was already registered.
    Unchanged,
}

/// Explainable evaluation of one verifier rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationRuleEvaluation {
    rule_id: String,
    stage: VerificationStage,
    priority: u16,
    condition: ExpressionEvaluation,
    fresh_evidence_ids: BTreeSet<EvidenceId>,
    action_matched: bool,
    eligible: bool,
    selected: bool,
}

impl VerificationRuleEvaluation {
    /// Returns the evaluated rule identity.
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns the rule's evidence collection stage.
    pub fn stage(&self) -> VerificationStage {
        self.stage
    }

    /// Returns the rule priority used for conflict resolution.
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the complete expression evaluation trace.
    pub fn condition(&self) -> &ExpressionEvaluation {
        &self.condition
    }

    /// Returns contributing evidence absent from the passive baseline.
    pub fn fresh_evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.fresh_evidence_ids
    }

    /// Returns whether the case action satisfied this rule's action scope.
    pub fn action_matched(&self) -> bool {
        self.action_matched
    }

    /// Returns whether this rule could participate in winner selection.
    pub fn eligible(&self) -> bool {
        self.eligible
    }

    /// Returns whether this rule produced the report outcome.
    pub fn selected(&self) -> bool {
        self.selected
    }
}

/// Outcome and audit trail for one verification stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    case: VerificationCase,
    stage: VerificationStage,
    outcome: Outcome,
    evaluations: Vec<VerificationRuleEvaluation>,
    #[serde(skip)]
    commit_token: VerificationCommitToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerificationCommitToken {
    subject_revision: u64,
    ontology_revision: u64,
}

impl VerificationReport {
    /// Returns the verified case.
    pub fn case(&self) -> &VerificationCase {
        &self.case
    }

    /// Returns the evaluated evidence collection stage.
    pub fn stage(&self) -> VerificationStage {
        self.stage
    }

    /// Returns the stage outcome.
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }

    /// Returns rule evaluations in stable rule-ID order.
    pub fn evaluations(&self) -> &[VerificationRuleEvaluation] {
        &self.evaluations
    }

    /// Applies this report's conclusive state transition with snapshot CAS.
    ///
    /// The report is bound to the subject and ontology revisions used for its
    /// evaluation. If rule-visible knowledge changed before the transition, the
    /// complete state update is rejected as stale. Audit-only nonterminal reports
    /// are validated too, because their callers may still commit adaptive or
    /// session decisions. Replaying an already-applied terminal report is
    /// idempotent; an opposite terminal result is rejected.
    pub fn apply(
        &self,
        knowledge: &KnowledgeBase,
    ) -> Result<Option<KnowledgeWrite>, VerificationError> {
        apply_outcome_with_token(knowledge, &self.outcome, Some(self.commit_token))
    }
}

#[derive(Debug, Clone)]
struct RuleRegistry {
    stage: VerificationStage,
    rules: BTreeMap<String, VerificationRule>,
}

impl RuleRegistry {
    fn new(stage: VerificationStage) -> Self {
        Self {
            stage,
            rules: BTreeMap::new(),
        }
    }

    fn register(&mut self, rule: VerificationRule) -> Result<VerifierWrite, VerificationError> {
        if rule.stage != self.stage {
            return Err(VerificationError::WrongStage {
                rule_id: rule.id.clone(),
                expected: self.stage,
                actual: rule.stage,
            });
        }
        if let Some(existing) = self.rules.get(rule.id()) {
            return if existing == &rule {
                Ok(VerifierWrite::Unchanged)
            } else {
                Err(VerificationError::RuleIdentityConflict {
                    id: rule.id.clone(),
                })
            };
        }
        self.rules.insert(rule.id.clone(), rule);
        Ok(VerifierWrite::Inserted)
    }

    fn len(&self) -> usize {
        self.rules.len()
    }

    fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Pure verifier for evidence collected without an additional probe.
///
/// # Example
///
/// ```rust
/// use venom_core::{
///     EvidenceValue, KnowledgePredicate, OutcomeStatus, Probability, VerificationStage,
/// };
/// use venom_scanner::{
///     Expression, KnowledgeLayer, PassiveVerifier, VerificationRule, VerifierWrite,
/// };
///
/// let rule = VerificationRule::new(
///     "verify.boolean-difference",
///     VerificationStage::Passive,
///     100,
///     Expression::equals(
///         KnowledgeLayer::Evidence,
///         KnowledgePredicate::new("verification", "boolean_difference")?,
///         EvidenceValue::Boolean(true),
///     ),
///     OutcomeStatus::Success,
///     Probability::from_percent(95)?,
///     "Boolean responses diverged consistently",
/// )?;
/// let mut verifier = PassiveVerifier::new();
///
/// assert_eq!(verifier.register(rule)?, VerifierWrite::Inserted);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct PassiveVerifier {
    registry: RuleRegistry,
}

impl PassiveVerifier {
    /// Creates an empty passive verifier.
    pub fn new() -> Self {
        Self {
            registry: RuleRegistry::new(VerificationStage::Passive),
        }
    }

    /// Registers one passive rule idempotently.
    pub fn register(&mut self, rule: VerificationRule) -> Result<VerifierWrite, VerificationError> {
        self.registry.register(rule)
    }

    /// Returns the number of passive rules.
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Returns whether no passive rules are registered.
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Verifies a case from one internally consistent knowledge snapshot.
    pub fn verify(
        &self,
        knowledge: &KnowledgeBase,
        case: &VerificationCase,
    ) -> Result<VerificationReport, VerificationError> {
        let snapshot = knowledge.snapshot_for_subject(case.subject());
        self.verify_snapshot(case, &snapshot)
    }

    /// Verifies a case against an explicit immutable snapshot.
    pub fn verify_snapshot(
        &self,
        case: &VerificationCase,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<VerificationReport, VerificationError> {
        evaluate_registry(&self.registry, case, snapshot, None)
    }
}

impl Default for PassiveVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure verifier for evidence collected by an explicit active probe.
///
/// This type does not send traffic. The caller executes a planned probe,
/// records its observations through the evidence engine, and supplies the
/// before/after snapshots. A matching active rule must cite at least one new
/// evidence ID.
#[derive(Debug, Clone)]
pub struct ActiveVerifier {
    registry: RuleRegistry,
}

impl ActiveVerifier {
    /// Creates an empty active verifier.
    pub fn new() -> Self {
        Self {
            registry: RuleRegistry::new(VerificationStage::Active),
        }
    }

    /// Registers one active rule idempotently.
    pub fn register(&mut self, rule: VerificationRule) -> Result<VerifierWrite, VerificationError> {
        self.registry.register(rule)
    }

    /// Returns the number of active rules.
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Returns whether no active rules are registered.
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Verifies a case using a baseline and post-probe snapshot.
    pub fn verify_snapshots(
        &self,
        case: &VerificationCase,
        baseline: &KnowledgeSnapshot,
        after_probe: &KnowledgeSnapshot,
    ) -> Result<VerificationReport, VerificationError> {
        validate_snapshot(case, baseline)?;
        validate_monotonic(baseline, after_probe)?;
        evaluate_registry(&self.registry, case, after_probe, Some(baseline))
    }
}

impl Default for ActiveVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordered passive-to-active verification pipeline.
#[derive(Debug, Clone, Default)]
pub struct VerificationPipeline {
    passive: PassiveVerifier,
    active: ActiveVerifier,
}

impl VerificationPipeline {
    /// Creates a pipeline from independently configured verifiers.
    pub fn new(passive: PassiveVerifier, active: ActiveVerifier) -> Self {
        Self { passive, active }
    }

    /// Returns the passive verifier registry.
    pub fn passive(&self) -> &PassiveVerifier {
        &self.passive
    }

    /// Returns the mutable passive verifier registry.
    pub fn passive_mut(&mut self) -> &mut PassiveVerifier {
        &mut self.passive
    }

    /// Returns the active verifier registry.
    pub fn active(&self) -> &ActiveVerifier {
        &self.active
    }

    /// Returns the mutable active verifier registry.
    pub fn active_mut(&mut self) -> &mut ActiveVerifier {
        &mut self.active
    }

    /// Evaluates passive rules and optionally a post-probe active snapshot.
    ///
    /// Terminal passive outcomes never reach the active verifier. `Unknown`
    /// and `NeedsReview` request active verification when no active snapshot is
    /// supplied.
    pub fn verify_snapshots(
        &self,
        case: &VerificationCase,
        passive_snapshot: &KnowledgeSnapshot,
        active_snapshot: Option<&KnowledgeSnapshot>,
    ) -> Result<VerificationPipelineReport, VerificationError> {
        let passive = self.passive.verify_snapshot(case, passive_snapshot)?;
        let active = if passive.outcome().status().is_terminal() {
            None
        } else {
            active_snapshot
                .map(|snapshot| {
                    self.active
                        .verify_snapshots(case, passive_snapshot, snapshot)
                })
                .transpose()?
        };
        Ok(VerificationPipelineReport { passive, active })
    }
}

/// Full passive/active audit trail for one verification case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationPipelineReport {
    passive: VerificationReport,
    active: Option<VerificationReport>,
}

impl VerificationPipelineReport {
    /// Returns the passive stage report.
    pub fn passive(&self) -> &VerificationReport {
        &self.passive
    }

    /// Returns the active report when post-probe evidence was evaluated.
    pub fn active(&self) -> Option<&VerificationReport> {
        self.active.as_ref()
    }

    /// Returns the most recent outcome in the pipeline.
    pub fn final_outcome(&self) -> &Outcome {
        self.active
            .as_ref()
            .map_or_else(|| self.passive.outcome(), VerificationReport::outcome)
    }

    /// Returns whether an unresolved passive result still needs active evidence.
    pub fn requires_active(&self) -> bool {
        !self.passive.outcome().status().is_terminal() && self.active.is_none()
    }
}

/// Applies verifier-owned hypothesis state transitions to the knowledge base.
///
/// `Success` confirms a hypothesis. `FalsePositive` and `ConfirmedNegative`
/// reject it. Other outcomes are audit records only and leave hypothesis state
/// unchanged.
///
/// This compatibility entry point has no snapshot token and therefore cannot
/// detect recalibration between verification and application. It still makes
/// terminal transitions monotonic: same-state replay is idempotent and an
/// opposite terminal transition is rejected. Prefer [`VerificationReport::apply`]
/// whenever the report is available.
pub fn apply_outcome(
    knowledge: &KnowledgeBase,
    outcome: &Outcome,
) -> Result<Option<KnowledgeWrite>, VerificationError> {
    apply_outcome_with_token(knowledge, outcome, None)
}

fn apply_outcome_with_token(
    knowledge: &KnowledgeBase,
    outcome: &Outcome,
    commit_token: Option<VerificationCommitToken>,
) -> Result<Option<KnowledgeWrite>, VerificationError> {
    let Some(state) = outcome.status().hypothesis_state() else {
        if let Some(commit_token) = commit_token {
            validate_commit_token(knowledge, outcome.subject(), commit_token)?;
        }
        return Ok(None);
    };
    let hypothesis = knowledge
        .hypothesis(outcome.hypothesis_id())
        .ok_or_else(|| VerificationError::UnknownHypothesis {
            hypothesis_id: outcome.hypothesis_id().to_owned(),
        })?;
    if hypothesis.subject() != outcome.subject() {
        return Err(VerificationError::SnapshotSubjectMismatch {
            expected: outcome.subject().clone(),
            actual: hypothesis.subject().clone(),
        });
    }
    for evidence_id in outcome.evidence_ids() {
        let evidence =
            knowledge
                .evidence(evidence_id)
                .ok_or_else(|| VerificationError::UnknownEvidence {
                    evidence_id: evidence_id.clone(),
                })?;
        if evidence.subject() != outcome.subject() {
            return Err(VerificationError::EvidenceSubjectMismatch {
                evidence_id: evidence_id.clone(),
                subject: outcome.subject().clone(),
            });
        }
    }
    let expected_revisions =
        commit_token.map(|token| (token.subject_revision, token.ontology_revision));
    match knowledge.transition_hypothesis_state(
        outcome.hypothesis_id(),
        outcome.subject(),
        state,
        expected_revisions,
    ) {
        HypothesisStateTransition::Missing => Err(VerificationError::UnknownHypothesis {
            hypothesis_id: outcome.hypothesis_id().to_owned(),
        }),
        HypothesisStateTransition::SubjectMismatch { actual } => {
            Err(VerificationError::SnapshotSubjectMismatch {
                expected: outcome.subject().clone(),
                actual,
            })
        },
        HypothesisStateTransition::StaleSnapshot(error) => Err(error.into()),
        HypothesisStateTransition::TerminalConflict { current, attempted } => {
            Err(VerificationError::ConflictingTerminalState {
                hypothesis_id: outcome.hypothesis_id().to_owned(),
                current,
                attempted,
            })
        },
        HypothesisStateTransition::Written(write) => Ok(Some(write)),
    }
}

fn validate_commit_token(
    knowledge: &KnowledgeBase,
    subject: &EntityId,
    commit_token: VerificationCommitToken,
) -> Result<(), VerificationError> {
    knowledge
        .validate_snapshot_revisions(
            subject,
            commit_token.subject_revision,
            commit_token.ontology_revision,
        )
        .map_err(Into::into)
}

fn evaluate_registry(
    registry: &RuleRegistry,
    case: &VerificationCase,
    snapshot: &KnowledgeSnapshot,
    baseline: Option<&KnowledgeSnapshot>,
) -> Result<VerificationReport, VerificationError> {
    validate_snapshot(case, snapshot)?;
    let baseline_ids: BTreeSet<_> = baseline
        .map(|snapshot| {
            snapshot
                .evidence()
                .iter()
                .map(|evidence| evidence.id().clone())
                .collect()
        })
        .unwrap_or_default();

    let mut evaluations = Vec::with_capacity(registry.rules.len());
    for rule in registry.rules.values() {
        let scoped_snapshot = rule
            .case_correlated_evidence
            .then(|| snapshot.with_evidence_correlation(case.id()));
        let condition = rule
            .condition
            .evaluate(scoped_snapshot.as_ref().unwrap_or(snapshot))?;
        if condition.matched() && condition.evidence_ids().is_empty() {
            return Err(VerificationError::MissingContributingEvidence {
                rule_id: rule.id.clone(),
            });
        }
        let fresh_evidence_ids = condition
            .evidence_ids()
            .difference(&baseline_ids)
            .cloned()
            .collect::<BTreeSet<_>>();
        let action_matched = rule
            .action_id
            .as_deref()
            .is_none_or(|action_id| action_id == case.action_id());
        let eligible = action_matched
            && condition.matched()
            && (registry.stage == VerificationStage::Passive || !fresh_evidence_ids.is_empty());
        evaluations.push(VerificationRuleEvaluation {
            rule_id: rule.id.clone(),
            stage: rule.stage,
            priority: rule.priority,
            condition,
            fresh_evidence_ids,
            action_matched,
            eligible,
            selected: false,
        });
    }

    let mut candidates: Vec<_> = evaluations
        .iter()
        .filter(|evaluation| evaluation.eligible)
        .map(|evaluation| evaluation.rule_id.clone())
        .collect();
    candidates.sort_by(|left, right| {
        let left_rule = &registry.rules[left];
        let right_rule = &registry.rules[right];
        right_rule
            .priority
            .cmp(&left_rule.priority)
            .then_with(|| right_rule.confidence.cmp(&left_rule.confidence))
            .then_with(|| left.cmp(right))
    });
    let selected_id = candidates.first().cloned();
    if let Some(selected_id) = &selected_id {
        if let Some(evaluation) = evaluations
            .iter_mut()
            .find(|evaluation| &evaluation.rule_id == selected_id)
        {
            evaluation.selected = true;
        }
    }

    let outcome = if let Some(selected_id) = selected_id {
        let rule = &registry.rules[&selected_id];
        let evidence_ids = evaluations
            .iter()
            .find(|evaluation| evaluation.rule_id == selected_id)
            .map(|evaluation| evaluation.condition.evidence_ids().clone())
            .unwrap_or_default();
        Outcome::verified(
            case.id.clone(),
            case.subject.clone(),
            case.action_id.clone(),
            case.hypothesis_id.clone(),
            rule.id.clone(),
            registry.stage,
            rule.outcome,
            rule.confidence,
            rule.rationale.clone(),
            evidence_ids,
        )?
    } else {
        Outcome::unknown(
            case.id.clone(),
            case.subject.clone(),
            case.action_id.clone(),
            case.hypothesis_id.clone(),
            registry.stage,
            format!(
                "no eligible {} verification rule matched current evidence",
                registry.stage.as_str()
            ),
        )?
    };

    Ok(VerificationReport {
        case: case.clone(),
        stage: registry.stage,
        outcome,
        evaluations,
        commit_token: VerificationCommitToken {
            subject_revision: snapshot.subject_revision(),
            ontology_revision: snapshot.ontology_revision(),
        },
    })
}

fn validate_snapshot(
    case: &VerificationCase,
    snapshot: &KnowledgeSnapshot,
) -> Result<(), VerificationError> {
    if snapshot.subject() != case.subject() {
        return Err(VerificationError::SnapshotSubjectMismatch {
            expected: case.subject().clone(),
            actual: snapshot.subject().clone(),
        });
    }
    if !snapshot
        .hypotheses()
        .iter()
        .any(|hypothesis| hypothesis.id() == case.hypothesis_id())
    {
        return Err(VerificationError::UnknownHypothesis {
            hypothesis_id: case.hypothesis_id().to_owned(),
        });
    }
    Ok(())
}

fn validate_monotonic(
    baseline: &KnowledgeSnapshot,
    after_probe: &KnowledgeSnapshot,
) -> Result<(), VerificationError> {
    let after_ids: BTreeSet<_> = after_probe
        .evidence()
        .iter()
        .map(|evidence| evidence.id())
        .collect();
    for evidence in baseline.evidence() {
        if !after_ids.contains(evidence.id()) {
            return Err(VerificationError::NonMonotonicSnapshot {
                evidence_id: evidence.id().clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KnowledgeLayer;
    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue,
        Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate,
    };

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn boolean_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("verification", "boolean_difference").unwrap()
    }

    fn timing_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("verification", "timing_difference").unwrap()
    }

    fn evidence(predicate: KnowledgePredicate, method: &str, value: bool) -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Custom("verification".into()),
            predicate,
            EvidenceValue::Boolean(value),
            EvidenceSource::new("verifier", method).unwrap(),
            ConfidenceScore::from_percent(95).unwrap(),
        )
    }

    fn knowledge() -> KnowledgeBase {
        let knowledge = KnowledgeBase::new();
        let observation = evidence(boolean_predicate(), "boolean-control", true);
        knowledge.insert_evidence(observation.clone()).unwrap();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:sqli",
            subject(),
            KnowledgePredicate::new("vulnerability", "sqli").unwrap(),
            EvidenceValue::Boolean(true),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    observation.id().clone(),
                    Probability::from_percent(80).unwrap(),
                    Probability::from_percent(20).unwrap(),
                    "Boolean response difference",
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        knowledge
    }

    #[test]
    fn verification_case_preserves_optional_strategy_with_legacy_wire_compatibility() {
        let legacy = VerificationCase::new(
            "case:legacy",
            subject(),
            "legacy.observe",
            "hypothesis:sqli",
        )
        .unwrap();
        let legacy_wire = serde_json::to_value(&legacy).unwrap();
        assert!(legacy_wire.get("payload_strategy").is_none());
        assert!(serde_json::from_value::<VerificationCase>(legacy_wire)
            .unwrap()
            .payload_strategy()
            .is_none());
        let mut misspelled = serde_json::to_value(&legacy).unwrap();
        misspelled["payload_stratgey"] = serde_json::json!({
            "id": "visibility.control-pair",
            "revision": 1
        });
        assert!(serde_json::from_value::<VerificationCase>(misspelled).is_err());
        let mut extended = serde_json::to_value(&legacy).unwrap();
        extended["future_extension"] = serde_json::json!({"accepted": true});
        assert!(serde_json::from_value::<VerificationCase>(extended).is_ok());

        let strategy = PayloadStrategyRef::new("visibility.control-pair", 1).unwrap();
        let selected = legacy.clone().with_payload_strategy(Some(strategy.clone()));
        let restored: VerificationCase =
            serde_json::from_value(serde_json::to_value(&selected).unwrap()).unwrap();
        assert_eq!(restored, selected);
        assert_eq!(restored.payload_strategy(), Some(&strategy));
    }

    fn case() -> VerificationCase {
        VerificationCase::new("case:sqli:1", subject(), "sqli.verify", "hypothesis:sqli").unwrap()
    }

    fn rule(
        id: &str,
        stage: VerificationStage,
        priority: u16,
        predicate: KnowledgePredicate,
        outcome: OutcomeStatus,
    ) -> VerificationRule {
        VerificationRule::new(
            id,
            stage,
            priority,
            Expression::equals(
                KnowledgeLayer::Evidence,
                predicate,
                EvidenceValue::Boolean(true),
            ),
            outcome,
            Probability::from_percent(90).unwrap(),
            format!("{id} matched"),
        )
        .unwrap()
    }

    #[test]
    fn scoped_rule_round_trips_and_rejects_non_evidence_case_scope() {
        let scoped = rule(
            "scoped",
            VerificationStage::Passive,
            10,
            boolean_predicate(),
            OutcomeStatus::Success,
        )
        .scoped_to_action("sqli.verify")
        .unwrap()
        .with_case_correlated_evidence()
        .unwrap();
        let serialized = serde_json::to_string(&scoped).unwrap();
        let restored: VerificationRule = serde_json::from_str(&serialized).unwrap();

        assert_eq!(restored, scoped);
        assert_eq!(restored.action_id(), Some("sqli.verify"));
        assert!(restored.requires_case_correlated_evidence());

        let hypothesis_rule = VerificationRule::new(
            "hypothesis-scoped",
            VerificationStage::Passive,
            10,
            Expression::exists(
                KnowledgeLayer::Hypothesis,
                KnowledgePredicate::new("vulnerability", "sqli").unwrap(),
            ),
            OutcomeStatus::Success,
            Probability::from_percent(90).unwrap(),
            "hypothesis exists",
        )
        .unwrap();
        assert!(matches!(
            hypothesis_rule.with_case_correlated_evidence(),
            Err(VerificationError::CaseCorrelationRequiresEvidenceOnly { .. })
        ));
    }

    #[test]
    fn passive_verification_is_deterministic_and_uses_stable_ties() {
        let knowledge = knowledge();
        let mut verifier = PassiveVerifier::new();
        verifier
            .register(rule(
                "zeta",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::NeedsReview,
            ))
            .unwrap();
        verifier
            .register(rule(
                "alpha",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();

        let first = verifier.verify(&knowledge, &case()).unwrap();
        let second = verifier.verify(&knowledge, &case()).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.outcome().verifier_rule_id(), Some("alpha"));
        assert_eq!(first.outcome().status(), OutcomeStatus::Success);
        assert_eq!(
            first
                .evaluations()
                .iter()
                .filter(|evaluation| evaluation.selected())
                .count(),
            1
        );
    }

    #[test]
    fn higher_priority_rule_resolves_conflicting_outcomes() {
        let knowledge = knowledge();
        let mut verifier = PassiveVerifier::new();
        verifier
            .register(rule(
                "success",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();
        verifier
            .register(rule(
                "review",
                VerificationStage::Passive,
                20,
                boolean_predicate(),
                OutcomeStatus::NeedsReview,
            ))
            .unwrap();

        let report = verifier.verify(&knowledge, &case()).unwrap();

        assert_eq!(report.outcome().status(), OutcomeStatus::NeedsReview);
        assert_eq!(report.outcome().verifier_rule_id(), Some("review"));
    }

    #[test]
    fn active_verifier_requires_fresh_contributing_evidence() {
        let knowledge = knowledge();
        let baseline = knowledge.snapshot_for_subject(&subject());
        let mut verifier = ActiveVerifier::new();
        verifier
            .register(rule(
                "active.boolean",
                VerificationStage::Active,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();

        let stale = verifier
            .verify_snapshots(&case(), &baseline, &baseline)
            .unwrap();
        assert_eq!(stale.outcome().status(), OutcomeStatus::Unknown);
        assert!(stale.evaluations()[0].condition().matched());
        assert!(!stale.evaluations()[0].eligible());

        knowledge
            .insert_evidence(evidence(
                boolean_predicate(),
                "active-boolean-control",
                true,
            ))
            .unwrap();
        let after_probe = knowledge.snapshot_for_subject(&subject());
        let verified = verifier
            .verify_snapshots(&case(), &baseline, &after_probe)
            .unwrap();

        assert_eq!(verified.outcome().status(), OutcomeStatus::Success);
        assert_eq!(verified.evaluations()[0].fresh_evidence_ids().len(), 1);
    }

    #[test]
    fn pipeline_escalates_review_to_active_confirmed_negative() {
        let knowledge = knowledge();
        let baseline = knowledge.snapshot_for_subject(&subject());
        let mut pipeline = VerificationPipeline::default();
        pipeline
            .passive_mut()
            .register(rule(
                "passive.review",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::NeedsReview,
            ))
            .unwrap();
        pipeline
            .active_mut()
            .register(rule(
                "active.reject",
                VerificationStage::Active,
                10,
                timing_predicate(),
                OutcomeStatus::ConfirmedNegative,
            ))
            .unwrap();

        let pending = pipeline.verify_snapshots(&case(), &baseline, None).unwrap();
        assert!(pending.requires_active());
        assert_eq!(pending.final_outcome().status(), OutcomeStatus::NeedsReview);

        knowledge
            .insert_evidence(evidence(timing_predicate(), "time-control", true))
            .unwrap();
        let after_probe = knowledge.snapshot_for_subject(&subject());
        let completed = pipeline
            .verify_snapshots(&case(), &baseline, Some(&after_probe))
            .unwrap();

        assert!(!completed.requires_active());
        assert_eq!(
            completed.final_outcome().status(),
            OutcomeStatus::ConfirmedNegative
        );
        assert_eq!(
            completed.active().unwrap().stage(),
            VerificationStage::Active
        );
        assert_eq!(
            apply_outcome(&knowledge, completed.final_outcome()).unwrap(),
            Some(KnowledgeWrite::Updated)
        );
        assert_eq!(
            knowledge.hypothesis("hypothesis:sqli").unwrap().state(),
            HypothesisState::Rejected
        );
    }

    #[test]
    fn terminal_passive_outcome_skips_active_verifier() {
        let knowledge = knowledge();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut pipeline = VerificationPipeline::default();
        pipeline
            .passive_mut()
            .register(rule(
                "passive.success",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();

        let report = pipeline
            .verify_snapshots(&case(), &snapshot, Some(&snapshot))
            .unwrap();

        assert_eq!(report.final_outcome().status(), OutcomeStatus::Success);
        assert!(report.active().is_none());
        assert!(!report.requires_active());
    }

    #[test]
    fn applying_conclusive_outcome_updates_hypothesis_once() {
        let knowledge = knowledge();
        let mut verifier = PassiveVerifier::new();
        verifier
            .register(rule(
                "passive.success",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();
        let report = verifier.verify(&knowledge, &case()).unwrap();

        assert_eq!(
            apply_outcome(&knowledge, report.outcome()).unwrap(),
            Some(KnowledgeWrite::Updated)
        );
        assert_eq!(
            knowledge.hypothesis("hypothesis:sqli").unwrap().state(),
            HypothesisState::Confirmed
        );
        assert_eq!(
            apply_outcome(&knowledge, report.outcome()).unwrap(),
            Some(KnowledgeWrite::Unchanged)
        );
    }

    #[test]
    fn report_application_rejects_a_stale_hypothesis_evaluation() {
        let knowledge = knowledge();
        let mut verifier = PassiveVerifier::new();
        verifier
            .register(rule(
                "passive.success",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();
        let report = verifier.verify(&knowledge, &case()).unwrap();
        let serialized = serde_json::to_value(&report).unwrap();
        assert!(serialized.get("commit_token").is_none());

        let mut recalibrated = knowledge.hypothesis("hypothesis:sqli").unwrap();
        recalibrated.set_strength(HypothesisStrength::Weak);
        knowledge.upsert_hypothesis(recalibrated).unwrap();

        assert!(matches!(
            report.apply(&knowledge),
            Err(VerificationError::Knowledge(
                KnowledgeBaseError::StaleSnapshot { .. }
            ))
        ));
        let stored = knowledge.hypothesis("hypothesis:sqli").unwrap();
        assert_eq!(stored.state(), HypothesisState::Supported);
        assert_eq!(stored.strength(), HypothesisStrength::Weak);
    }

    #[test]
    fn nonterminal_report_application_still_rejects_stale_knowledge() {
        let knowledge = knowledge();
        let report = PassiveVerifier::new().verify(&knowledge, &case()).unwrap();
        assert_eq!(report.outcome().status(), OutcomeStatus::Unknown);
        assert_eq!(report.apply(&knowledge).unwrap(), None);

        knowledge
            .insert_evidence(evidence(timing_predicate(), "late-observation", true))
            .unwrap();

        assert!(matches!(
            report.apply(&knowledge),
            Err(VerificationError::Knowledge(
                KnowledgeBaseError::StaleSnapshot { .. }
            ))
        ));
    }

    #[test]
    fn report_application_is_idempotent_and_rejects_opposite_terminal_state() {
        let knowledge = knowledge();
        let mut confirming = PassiveVerifier::new();
        confirming
            .register(rule(
                "passive.success",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::Success,
            ))
            .unwrap();
        let mut rejecting = PassiveVerifier::new();
        rejecting
            .register(rule(
                "passive.false-positive",
                VerificationStage::Passive,
                10,
                boolean_predicate(),
                OutcomeStatus::FalsePositive,
            ))
            .unwrap();
        let confirmed = confirming.verify(&knowledge, &case()).unwrap();
        let rejected = rejecting.verify(&knowledge, &case()).unwrap();

        assert_eq!(
            confirmed.apply(&knowledge).unwrap(),
            Some(KnowledgeWrite::Updated)
        );
        assert_eq!(
            confirmed.apply(&knowledge).unwrap(),
            Some(KnowledgeWrite::Unchanged)
        );
        assert!(matches!(
            rejected.apply(&knowledge),
            Err(VerificationError::ConflictingTerminalState {
                hypothesis_id,
                current: HypothesisState::Confirmed,
                attempted: HypothesisState::Rejected,
            }) if hypothesis_id == "hypothesis:sqli"
        ));
        assert_eq!(
            knowledge.hypothesis("hypothesis:sqli").unwrap().state(),
            HypothesisState::Confirmed
        );
    }

    #[test]
    fn rule_wire_and_stage_invariants_are_enforced() {
        assert!(matches!(
            VerificationRule::new(
                "passive.negative",
                VerificationStage::Passive,
                10,
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    boolean_predicate(),
                    EvidenceValue::Boolean(true),
                ),
                OutcomeStatus::ConfirmedNegative,
                Probability::from_percent(95).unwrap(),
                "Passive evidence cannot establish a confirmed negative",
            ),
            Err(VerificationError::ConfirmedNegativeRequiresActive { .. })
        ));
        let rule = rule(
            "passive.success",
            VerificationStage::Passive,
            10,
            boolean_predicate(),
            OutcomeStatus::Success,
        );
        let mut encoded = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            serde_json::from_value::<VerificationRule>(encoded.clone()).unwrap(),
            rule
        );
        encoded["outcome"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<VerificationRule>(encoded).is_err());

        let mut active = ActiveVerifier::new();
        assert!(matches!(
            active.register(rule),
            Err(VerificationError::WrongStage { .. })
        ));
    }

    #[test]
    fn active_snapshot_must_preserve_baseline_evidence() {
        let baseline_knowledge = knowledge();
        let after_knowledge = knowledge();
        let baseline = baseline_knowledge.snapshot_for_subject(&subject());
        let after = after_knowledge.snapshot_for_subject(&subject());
        let verifier = ActiveVerifier::new();

        assert!(matches!(
            verifier.verify_snapshots(&case(), &baseline, &after),
            Err(VerificationError::NonMonotonicSnapshot { .. })
        ));
    }
}
