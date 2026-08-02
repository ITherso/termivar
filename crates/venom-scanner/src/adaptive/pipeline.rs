//! Outcome-driven adaptive pipeline decisions.
//!
//! This module converts immutable verification outcomes and knowledge
//! snapshots into declarative runner directives. It does not execute plugins,
//! send probes, sleep, or mutate the knowledge base.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{
    EntityId, EvidenceId, EvidenceValue, HttpEvidencePredicate, Outcome, OutcomeStatus,
    ReasoningModelError, VerificationStage,
};

use crate::{Expression, ExpressionEvaluation, KnowledgeLayer, KnowledgeSnapshot, RuleEngineError};

/// Validation and consistency errors raised by adaptive decisions.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AdaptivePipelineError {
    /// A required rule, action, or explanation value was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// An outcome selector contained no statuses.
    #[error("outcome selector must contain at least one status")]
    EmptyStatuses,

    /// An outcome selector contained no verification stages.
    #[error("outcome selector must contain at least one verification stage")]
    EmptyStages,

    /// A rule application limit was zero.
    #[error("adaptation rule {rule_id} must allow at least one application")]
    ZeroRuleApplications { rule_id: String },

    /// An invalid schedule directive contained no action identity.
    #[error("scheduled action id must not be empty")]
    EmptyScheduledAction,

    /// A throttle directive had no delay.
    #[error("throttle delay must be greater than zero")]
    ZeroThrottleDelay,

    /// A rule identity was reused with different semantics.
    #[error("adaptation rule identity {id} already has a different definition")]
    RuleIdentityConflict { id: String },

    /// The outcome and knowledge snapshot refer to different subjects.
    #[error("adaptive outcome subject {expected} does not match snapshot subject {actual}")]
    SnapshotSubjectMismatch {
        /// Subject declared by the outcome.
        expected: EntityId,
        /// Subject captured by the snapshot.
        actual: EntityId,
    },

    /// Outcome provenance was absent from the supplied snapshot.
    #[error("adaptive snapshot is missing outcome evidence {evidence_id}")]
    MissingOutcomeEvidence { evidence_id: EvidenceId },

    /// A matched conditional rule cited no immutable evidence.
    #[error("matched adaptation rule {rule_id} did not cite any evidence")]
    MissingContributingEvidence { rule_id: String },

    /// Global transition limits must be positive.
    #[error("maximum adaptive transitions must be greater than zero")]
    ZeroTransitions,

    /// Per-action scheduling limits must be positive.
    #[error("maximum action schedules must be greater than zero")]
    ZeroActionSchedules,

    /// A decision was recorded twice or out of order.
    #[error("adaptive decision sequence {actual} does not match ledger sequence {expected}")]
    DecisionSequenceMismatch { expected: u32, actual: u32 },

    /// A ledger counter could not be incremented safely.
    #[error("adaptive ledger counter overflowed")]
    CounterOverflow,

    /// Persisted ledger state contained an invalid identity or counter.
    #[error("invalid adaptive ledger entry for {field}")]
    InvalidLedgerEntry { field: &'static str },

    /// Expression evaluation failed.
    #[error(transparent)]
    Rule(#[from] RuleEngineError),

    /// A core reasoning-domain value was invalid.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),
}

fn non_empty(
    value: impl Into<String>,
    field: &'static str,
) -> Result<String, AdaptivePipelineError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(AdaptivePipelineError::EmptyValue { field });
    }
    Ok(value)
}

/// Outcome statuses and verification stages accepted by one policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutcomeSelector {
    statuses: BTreeSet<OutcomeStatus>,
    stages: BTreeSet<VerificationStage>,
}

impl OutcomeSelector {
    /// Creates a non-empty status and stage selector.
    pub fn new(
        statuses: BTreeSet<OutcomeStatus>,
        stages: BTreeSet<VerificationStage>,
    ) -> Result<Self, AdaptivePipelineError> {
        if statuses.is_empty() {
            return Err(AdaptivePipelineError::EmptyStatuses);
        }
        if stages.is_empty() {
            return Err(AdaptivePipelineError::EmptyStages);
        }
        Ok(Self { statuses, stages })
    }

    /// Selects statuses produced by either verification stage.
    pub fn any_stage(statuses: BTreeSet<OutcomeStatus>) -> Result<Self, AdaptivePipelineError> {
        Self::new(
            statuses,
            BTreeSet::from([VerificationStage::Passive, VerificationStage::Active]),
        )
    }

    /// Returns accepted outcome statuses.
    pub fn statuses(&self) -> &BTreeSet<OutcomeStatus> {
        &self.statuses
    }

    /// Returns accepted verification stages.
    pub fn stages(&self) -> &BTreeSet<VerificationStage> {
        &self.stages
    }

    /// Returns whether this selector accepts an outcome.
    pub fn matches(&self, outcome: &Outcome) -> bool {
        self.statuses.contains(&outcome.status()) && self.stages.contains(&outcome.stage())
    }
}

impl<'de> Deserialize<'de> for OutcomeSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireSelector {
            statuses: BTreeSet<OutcomeStatus>,
            stages: BTreeSet<VerificationStage>,
        }

        let wire = WireSelector::deserialize(deserializer)?;
        Self::new(wire.statuses, wire.stages).map_err(serde::de::Error::custom)
    }
}

/// Side-effect-free command emitted for the runner or scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "directive", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PipelineDirective {
    /// The verified action completed the current objective.
    Complete,
    /// Add a named planner or plugin action to the execution queue.
    ScheduleAction {
        /// Stable action identity understood by the runner.
        action_id: String,
    },
    /// Re-run planning, optionally excluding the action that produced the outcome.
    Replan {
        /// Whether the source action should be suppressed in the next plan.
        suppress_current_action: bool,
    },
    /// Apply backpressure before optionally retrying the source action.
    Throttle {
        /// Required delay in milliseconds.
        delay_ms: u64,
        /// Whether the runner should retry the source action after the delay.
        retry_current_action: bool,
    },
    /// Collect active verification evidence before another decision.
    AwaitActiveVerification,
    /// Preserve the case for a human decision.
    AwaitHumanReview,
    /// Stop adaptation because the global transition budget was exhausted.
    Halt,
}

impl PipelineDirective {
    fn validate(&self) -> Result<(), AdaptivePipelineError> {
        match self {
            Self::ScheduleAction { action_id } if action_id.trim().is_empty() => {
                Err(AdaptivePipelineError::EmptyScheduledAction)
            },
            Self::Throttle { delay_ms: 0, .. } => Err(AdaptivePipelineError::ZeroThrottleDelay),
            Self::Complete
            | Self::ScheduleAction { .. }
            | Self::Replan { .. }
            | Self::Throttle { .. }
            | Self::AwaitActiveVerification
            | Self::AwaitHumanReview
            | Self::Halt => Ok(()),
        }
    }

    /// Returns the explicitly scheduled action, if any.
    pub fn scheduled_action_id(&self) -> Option<&str> {
        match self {
            Self::ScheduleAction { action_id } => Some(action_id),
            _ => None,
        }
    }

    fn repeated_action_id<'a>(&'a self, source_action_id: &'a str) -> Option<&'a str> {
        match self {
            Self::ScheduleAction { action_id } => Some(action_id),
            Self::Throttle {
                retry_current_action: true,
                ..
            } => Some(source_action_id),
            _ => None,
        }
    }
}

/// Declarative mapping from an outcome and optional evidence expression to a directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdaptationRule {
    id: String,
    selector: OutcomeSelector,
    priority: u16,
    condition: Option<Expression>,
    directive: PipelineDirective,
    rationale: String,
    max_applications: u16,
}

impl AdaptationRule {
    /// Creates a validated adaptation rule.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        selector: OutcomeSelector,
        priority: u16,
        condition: Option<Expression>,
        directive: PipelineDirective,
        rationale: impl Into<String>,
        max_applications: u16,
    ) -> Result<Self, AdaptivePipelineError> {
        let id = non_empty(id, "adaptation rule id")?;
        if max_applications == 0 {
            return Err(AdaptivePipelineError::ZeroRuleApplications { rule_id: id });
        }
        directive.validate()?;
        Ok(Self {
            id,
            selector,
            priority,
            condition,
            directive,
            rationale: non_empty(rationale, "adaptation rationale")?,
            max_applications,
        })
    }

    /// Returns the stable rule identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the accepted outcome selector.
    pub fn selector(&self) -> &OutcomeSelector {
        &self.selector
    }

    /// Returns the deterministic conflict-resolution priority.
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the optional evidence condition.
    pub fn condition(&self) -> Option<&Expression> {
        self.condition.as_ref()
    }

    /// Returns the emitted directive template.
    pub fn directive(&self) -> &PipelineDirective {
        &self.directive
    }

    /// Returns the human-readable policy explanation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns the maximum number of times this rule may win in one ledger.
    pub fn max_applications(&self) -> u16 {
        self.max_applications
    }
}

impl<'de> Deserialize<'de> for AdaptationRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireRule {
            id: String,
            selector: OutcomeSelector,
            priority: u16,
            condition: Option<Expression>,
            directive: PipelineDirective,
            rationale: String,
            max_applications: u16,
        }

        let wire = WireRule::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.selector,
            wire.priority,
            wire.condition,
            wire.directive,
            wire.rationale,
            wire.max_applications,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Result of registering an adaptation rule identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AdaptiveRuleWrite {
    /// A new policy rule was registered.
    Inserted,
    /// The identical policy rule was already registered.
    Unchanged,
}

/// Limits applied across an adaptive decision ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AdaptationLimits {
    max_transitions: u32,
    max_action_schedules: u16,
}

impl AdaptationLimits {
    /// Creates positive global transition and action scheduling limits.
    pub fn new(
        max_transitions: u32,
        max_action_schedules: u16,
    ) -> Result<Self, AdaptivePipelineError> {
        if max_transitions == 0 {
            return Err(AdaptivePipelineError::ZeroTransitions);
        }
        if max_action_schedules == 0 {
            return Err(AdaptivePipelineError::ZeroActionSchedules);
        }
        Ok(Self {
            max_transitions,
            max_action_schedules,
        })
    }

    /// Returns the maximum recorded directives.
    pub fn max_transitions(self) -> u32 {
        self.max_transitions
    }

    /// Returns the maximum times one action may be scheduled.
    pub fn max_action_schedules(self) -> u16 {
        self.max_action_schedules
    }
}

impl Default for AdaptationLimits {
    fn default() -> Self {
        Self {
            max_transitions: 64,
            max_action_schedules: 3,
        }
    }
}

impl<'de> Deserialize<'de> for AdaptationLimits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireLimits {
            max_transitions: u32,
            max_action_schedules: u16,
        }

        let wire = WireLimits::deserialize(deserializer)?;
        Self::new(wire.max_transitions, wire.max_action_schedules).map_err(serde::de::Error::custom)
    }
}

/// Replayable counters and suppressions for one adaptive scan session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdaptationLedger {
    transitions: u32,
    rule_applications: BTreeMap<String, u16>,
    action_schedules: BTreeMap<String, u16>,
    suppressed_actions: BTreeSet<String>,
}

impl AdaptationLedger {
    /// Creates an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of recorded directives.
    pub fn transitions(&self) -> u32 {
        self.transitions
    }

    /// Returns how often a rule produced a directive.
    pub fn rule_applications(&self, rule_id: &str) -> u16 {
        self.rule_applications.get(rule_id).copied().unwrap_or(0)
    }

    /// Returns how often an explicit action was scheduled.
    pub fn action_schedules(&self, action_id: &str) -> u16 {
        self.action_schedules.get(action_id).copied().unwrap_or(0)
    }

    /// Returns action identities suppressed from subsequent replanning.
    pub fn suppressed_actions(&self) -> &BTreeSet<String> {
        &self.suppressed_actions
    }

    /// Records one decision exactly once and in sequence order.
    pub fn record(&mut self, decision: &AdaptiveDecision) -> Result<(), AdaptivePipelineError> {
        if decision.sequence != self.transitions {
            return Err(AdaptivePipelineError::DecisionSequenceMismatch {
                expected: self.transitions,
                actual: decision.sequence,
            });
        }
        if decision.transition_limit_reached {
            return Ok(());
        }
        let mut candidate = self.clone();
        candidate.transitions = candidate
            .transitions
            .checked_add(1)
            .ok_or(AdaptivePipelineError::CounterOverflow)?;
        if let Some(rule_id) = decision.selected_rule_id() {
            increment(&mut candidate.rule_applications, rule_id)?;
        }
        if let Some(action_id) = decision.directive().scheduled_action_id() {
            increment(&mut candidate.action_schedules, action_id)?;
        }
        if matches!(
            decision.directive(),
            PipelineDirective::Replan {
                suppress_current_action: true
            }
        ) {
            candidate
                .suppressed_actions
                .insert(decision.source_action_id.clone());
        }
        *self = candidate;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AdaptationLedger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireLedger {
            transitions: u32,
            rule_applications: BTreeMap<String, u16>,
            action_schedules: BTreeMap<String, u16>,
            suppressed_actions: BTreeSet<String>,
        }

        let wire = WireLedger::deserialize(deserializer)?;
        validate_counter_map(&wire.rule_applications, "rule applications")
            .map_err(serde::de::Error::custom)?;
        validate_counter_map(&wire.action_schedules, "action schedules")
            .map_err(serde::de::Error::custom)?;
        let transitions = u64::from(wire.transitions);
        let rule_applications: u64 = wire
            .rule_applications
            .values()
            .map(|count| u64::from(*count))
            .sum();
        let action_schedules: u64 = wire
            .action_schedules
            .values()
            .map(|count| u64::from(*count))
            .sum();
        if rule_applications > transitions
            || action_schedules > transitions
            || wire.suppressed_actions.len() as u64 > transitions
        {
            return Err(serde::de::Error::custom(
                AdaptivePipelineError::InvalidLedgerEntry {
                    field: "counters exceed transitions",
                },
            ));
        }
        if wire
            .suppressed_actions
            .iter()
            .any(|action_id| action_id.trim().is_empty())
        {
            return Err(serde::de::Error::custom(
                AdaptivePipelineError::InvalidLedgerEntry {
                    field: "suppressed actions",
                },
            ));
        }
        Ok(Self {
            transitions: wire.transitions,
            rule_applications: wire.rule_applications,
            action_schedules: wire.action_schedules,
            suppressed_actions: wire.suppressed_actions,
        })
    }
}

fn validate_counter_map(
    counters: &BTreeMap<String, u16>,
    field: &'static str,
) -> Result<(), AdaptivePipelineError> {
    if counters
        .iter()
        .any(|(identity, count)| identity.trim().is_empty() || *count == 0)
    {
        return Err(AdaptivePipelineError::InvalidLedgerEntry { field });
    }
    Ok(())
}

fn increment(
    counters: &mut BTreeMap<String, u16>,
    identity: &str,
) -> Result<(), AdaptivePipelineError> {
    let next = counters
        .get(identity)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(AdaptivePipelineError::CounterOverflow)?;
    counters.insert(identity.to_owned(), next);
    Ok(())
}

/// Explainable evaluation of one adaptation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdaptationRuleEvaluation {
    rule_id: String,
    selector_matched: bool,
    condition: Option<ExpressionEvaluation>,
    outcome_evidence_matched: bool,
    rule_limit_exhausted: bool,
    action_limit_exhausted: bool,
    policy_suppressed: bool,
    eligible: bool,
    selected: bool,
}

impl AdaptationRuleEvaluation {
    /// Returns the evaluated rule identity.
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns whether outcome status and stage matched.
    pub fn selector_matched(&self) -> bool {
        self.selector_matched
    }

    /// Returns the optional evidence expression trace.
    pub fn condition(&self) -> Option<&ExpressionEvaluation> {
        self.condition.as_ref()
    }

    /// Returns whether conditional evidence belongs to the source outcome.
    pub fn outcome_evidence_matched(&self) -> bool {
        self.outcome_evidence_matched
    }

    /// Returns whether the rule's retry budget was exhausted.
    pub fn rule_limit_exhausted(&self) -> bool {
        self.rule_limit_exhausted
    }

    /// Returns whether the scheduled action reached its global limit.
    pub fn action_limit_exhausted(&self) -> bool {
        self.action_limit_exhausted
    }

    /// Returns whether learned, adaptive, or operator policy suppressed the repeated action.
    pub fn policy_suppressed(&self) -> bool {
        self.policy_suppressed
    }

    /// Returns whether the rule could participate in winner selection.
    pub fn eligible(&self) -> bool {
        self.eligible
    }

    /// Returns whether this rule produced the directive.
    pub fn selected(&self) -> bool {
        self.selected
    }
}

/// Immutable adaptive decision for one verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdaptiveDecision {
    sequence: u32,
    subject: EntityId,
    case_id: String,
    source_action_id: String,
    outcome_status: OutcomeStatus,
    outcome_stage: VerificationStage,
    selected_rule_id: Option<String>,
    directive: PipelineDirective,
    rationale: String,
    evaluations: Vec<AdaptationRuleEvaluation>,
    transition_limit_reached: bool,
}

impl AdaptiveDecision {
    /// Returns the zero-based ledger sequence.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Returns the decision subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the verification case that triggered adaptation.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Returns the action that produced the source outcome.
    pub fn source_action_id(&self) -> &str {
        &self.source_action_id
    }

    /// Returns the source outcome classification.
    pub fn outcome_status(&self) -> OutcomeStatus {
        self.outcome_status
    }

    /// Returns the source verification stage.
    pub fn outcome_stage(&self) -> VerificationStage {
        self.outcome_stage
    }

    /// Returns the winning policy identity, if a policy matched.
    pub fn selected_rule_id(&self) -> Option<&str> {
        self.selected_rule_id.as_deref()
    }

    /// Returns the side-effect-free runner directive.
    pub fn directive(&self) -> &PipelineDirective {
        &self.directive
    }

    /// Returns the decision explanation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns policy evaluations in stable rule-ID order.
    pub fn evaluations(&self) -> &[AdaptationRuleEvaluation] {
        &self.evaluations
    }

    /// Returns whether the global transition budget forced a halt.
    pub fn transition_limit_reached(&self) -> bool {
        self.transition_limit_reached
    }
}

/// Deterministic outcome-to-directive policy engine.
///
/// # Example
///
/// ```rust
/// use venom_scanner::AdaptivePipeline;
///
/// let pipeline = AdaptivePipeline::with_standard_policies()?;
/// assert_eq!(pipeline.len(), 3);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct AdaptivePipeline {
    rules: BTreeMap<String, AdaptationRule>,
}

impl AdaptivePipeline {
    /// Creates an empty policy engine with deterministic fallback behavior.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates policies for common HTTP control-flow signals.
    ///
    /// - `403` schedules `http.403-bypass`;
    /// - `404` schedules `http.enumeration`;
    /// - `429` throttles for two seconds and retries the current action.
    pub fn with_standard_policies() -> Result<Self, AdaptivePipelineError> {
        let mut pipeline = Self::new();
        let unresolved = OutcomeSelector::any_stage(BTreeSet::from([
            OutcomeStatus::Blocked,
            OutcomeStatus::Unknown,
            OutcomeStatus::NeedsReview,
        ]))?;
        let status = HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge();
        pipeline.register(AdaptationRule::new(
            "http.429.throttle",
            unresolved.clone(),
            300,
            Some(Expression::equals(
                KnowledgeLayer::Evidence,
                status.clone(),
                EvidenceValue::Unsigned(429),
            )),
            PipelineDirective::Throttle {
                delay_ms: 2_000,
                retry_current_action: true,
            },
            "rate limiting requires backpressure before retry",
            3,
        )?)?;
        pipeline.register(AdaptationRule::new(
            "http.403.bypass",
            unresolved.clone(),
            200,
            Some(Expression::equals(
                KnowledgeLayer::Evidence,
                status.clone(),
                EvidenceValue::Unsigned(403),
            )),
            PipelineDirective::ScheduleAction {
                action_id: "http.403-bypass".into(),
            },
            "access control response requires a dedicated bypass action",
            2,
        )?)?;
        pipeline.register(AdaptationRule::new(
            "http.404.enumerate",
            unresolved,
            100,
            Some(Expression::equals(
                KnowledgeLayer::Evidence,
                status,
                EvidenceValue::Unsigned(404),
            )),
            PipelineDirective::ScheduleAction {
                action_id: "http.enumeration".into(),
            },
            "missing resource response redirects discovery to enumeration",
            1,
        )?)?;
        Ok(pipeline)
    }

    /// Registers an idempotent policy rule.
    pub fn register(
        &mut self,
        rule: AdaptationRule,
    ) -> Result<AdaptiveRuleWrite, AdaptivePipelineError> {
        if let Some(existing) = self.rules.get(rule.id()) {
            return if existing == &rule {
                Ok(AdaptiveRuleWrite::Unchanged)
            } else {
                Err(AdaptivePipelineError::RuleIdentityConflict {
                    id: rule.id.clone(),
                })
            };
        }
        self.rules.insert(rule.id.clone(), rule);
        Ok(AdaptiveRuleWrite::Inserted)
    }

    /// Returns the number of registered policies.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether no policies are registered.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Produces a pure decision without changing the supplied ledger.
    pub fn decide(
        &self,
        outcome: &Outcome,
        snapshot: &KnowledgeSnapshot,
        ledger: &AdaptationLedger,
        limits: AdaptationLimits,
    ) -> Result<AdaptiveDecision, AdaptivePipelineError> {
        self.decide_with_suppressed_actions(outcome, snapshot, ledger, limits, &BTreeSet::new())
    }

    /// Produces a pure decision while excluding actions suppressed by external policy.
    ///
    /// The set may be derived from an [`crate::ExperienceStore`], operator
    /// policy, or another scheduler concern. Ledger suppressions are always
    /// merged with the supplied set.
    pub fn decide_with_suppressed_actions(
        &self,
        outcome: &Outcome,
        snapshot: &KnowledgeSnapshot,
        ledger: &AdaptationLedger,
        limits: AdaptationLimits,
        suppressed_actions: &BTreeSet<String>,
    ) -> Result<AdaptiveDecision, AdaptivePipelineError> {
        validate_snapshot(outcome, snapshot)?;
        if ledger.transitions >= limits.max_transitions {
            return Ok(AdaptiveDecision {
                sequence: ledger.transitions,
                subject: outcome.subject().clone(),
                case_id: outcome.case_id().to_owned(),
                source_action_id: outcome.action_id().to_owned(),
                outcome_status: outcome.status(),
                outcome_stage: outcome.stage(),
                selected_rule_id: None,
                directive: PipelineDirective::Halt,
                rationale: "adaptive transition budget exhausted".into(),
                evaluations: Vec::new(),
                transition_limit_reached: true,
            });
        }

        let mut evaluations = Vec::with_capacity(self.rules.len());
        for rule in self.rules.values() {
            let selector_matched = rule.selector.matches(outcome);
            let condition = if selector_matched {
                rule.condition
                    .as_ref()
                    .map(|condition| condition.evaluate(snapshot))
                    .transpose()?
            } else {
                None
            };
            if condition
                .as_ref()
                .is_some_and(|condition| condition.matched() && condition.evidence_ids().is_empty())
            {
                return Err(AdaptivePipelineError::MissingContributingEvidence {
                    rule_id: rule.id.clone(),
                });
            }
            let condition_matched = condition
                .as_ref()
                .map_or(rule.condition.is_none(), ExpressionEvaluation::matched);
            let outcome_evidence_matched = condition.as_ref().is_none_or(|condition| {
                !condition.evidence_ids().is_disjoint(outcome.evidence_ids())
            });
            let rule_limit_exhausted = ledger.rule_applications(rule.id()) >= rule.max_applications;
            let action_limit_exhausted =
                rule.directive
                    .scheduled_action_id()
                    .is_some_and(|action_id| {
                        ledger.action_schedules(action_id) >= limits.max_action_schedules
                    });
            let policy_suppressed = rule
                .directive
                .repeated_action_id(outcome.action_id())
                .is_some_and(|action_id| {
                    suppressed_actions.contains(action_id)
                        || ledger.suppressed_actions().contains(action_id)
                });
            let eligible = selector_matched
                && condition_matched
                && outcome_evidence_matched
                && !rule_limit_exhausted
                && !action_limit_exhausted
                && !policy_suppressed;
            evaluations.push(AdaptationRuleEvaluation {
                rule_id: rule.id.clone(),
                selector_matched,
                condition,
                outcome_evidence_matched,
                rule_limit_exhausted,
                action_limit_exhausted,
                policy_suppressed,
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
            self.rules[right]
                .priority
                .cmp(&self.rules[left].priority)
                .then_with(|| left.cmp(right))
        });
        let selected_rule_id = candidates.first().cloned();
        if let Some(selected) = &selected_rule_id {
            if let Some(evaluation) = evaluations
                .iter_mut()
                .find(|evaluation| &evaluation.rule_id == selected)
            {
                evaluation.selected = true;
            }
        }

        let (directive, rationale) = selected_rule_id
            .as_ref()
            .map(|rule_id| {
                let rule = &self.rules[rule_id];
                (rule.directive.clone(), rule.rationale.clone())
            })
            .unwrap_or_else(|| fallback(outcome));

        Ok(AdaptiveDecision {
            sequence: ledger.transitions,
            subject: outcome.subject().clone(),
            case_id: outcome.case_id().to_owned(),
            source_action_id: outcome.action_id().to_owned(),
            outcome_status: outcome.status(),
            outcome_stage: outcome.stage(),
            selected_rule_id,
            directive,
            rationale,
            evaluations,
            transition_limit_reached: false,
        })
    }

    /// Produces and atomically records one in-order adaptive decision.
    pub fn decide_and_record(
        &self,
        outcome: &Outcome,
        snapshot: &KnowledgeSnapshot,
        ledger: &mut AdaptationLedger,
        limits: AdaptationLimits,
    ) -> Result<AdaptiveDecision, AdaptivePipelineError> {
        self.decide_and_record_with_suppressed_actions(
            outcome,
            snapshot,
            ledger,
            limits,
            &BTreeSet::new(),
        )
    }

    /// Produces and records a decision with explicit policy suppressions.
    pub fn decide_and_record_with_suppressed_actions(
        &self,
        outcome: &Outcome,
        snapshot: &KnowledgeSnapshot,
        ledger: &mut AdaptationLedger,
        limits: AdaptationLimits,
        suppressed_actions: &BTreeSet<String>,
    ) -> Result<AdaptiveDecision, AdaptivePipelineError> {
        let decision = self.decide_with_suppressed_actions(
            outcome,
            snapshot,
            ledger,
            limits,
            suppressed_actions,
        )?;
        ledger.record(&decision)?;
        Ok(decision)
    }
}

fn fallback(outcome: &Outcome) -> (PipelineDirective, String) {
    match outcome.status() {
        OutcomeStatus::Success => (
            PipelineDirective::Complete,
            "verified objective completed".into(),
        ),
        OutcomeStatus::FalsePositive | OutcomeStatus::ConfirmedNegative => (
            PipelineDirective::Replan {
                suppress_current_action: true,
            },
            "negative conclusion suppresses the source action before replanning".into(),
        ),
        OutcomeStatus::Unknown | OutcomeStatus::NeedsReview
            if outcome.stage() == VerificationStage::Passive =>
        {
            (
                PipelineDirective::AwaitActiveVerification,
                "passive evidence is inconclusive".into(),
            )
        },
        OutcomeStatus::Blocked | OutcomeStatus::Unknown | OutcomeStatus::NeedsReview => (
            PipelineDirective::AwaitHumanReview,
            "no eligible automated adaptation policy remains".into(),
        ),
        _ => (
            PipelineDirective::AwaitHumanReview,
            "outcome status is not covered by the current adaptation policy".into(),
        ),
    }
}

fn validate_snapshot(
    outcome: &Outcome,
    snapshot: &KnowledgeSnapshot,
) -> Result<(), AdaptivePipelineError> {
    if outcome.subject() != snapshot.subject() {
        return Err(AdaptivePipelineError::SnapshotSubjectMismatch {
            expected: outcome.subject().clone(),
            actual: snapshot.subject().clone(),
        });
    }
    let evidence_ids: BTreeSet<_> = snapshot
        .evidence()
        .iter()
        .map(|evidence| evidence.id())
        .collect();
    for evidence_id in outcome.evidence_ids() {
        if !evidence_ids.contains(evidence_id) {
            return Err(AdaptivePipelineError::MissingOutcomeEvidence {
                evidence_id: evidence_id.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExperiencePolicy, ExperienceStore, PassiveVerifier, VerificationCase, VerificationRule,
        VerifierWrite,
    };
    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, Hypothesis,
        HypothesisState, HypothesisStrength, KnowledgePredicate, Probability,
    };

    struct Fixture {
        knowledge: crate::KnowledgeBase,
        evidence_id: EvidenceId,
    }

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn status_predicate() -> KnowledgePredicate {
        HttpEvidencePredicate::RESPONSE_STATUS.into_knowledge()
    }

    fn fixture(status: u64) -> Fixture {
        let knowledge = crate::KnowledgeBase::new();
        let evidence = Evidence::new(
            subject(),
            EvidenceKind::Http,
            status_predicate(),
            EvidenceValue::Unsigned(status),
            EvidenceSource::new("http.executor", "response-status").unwrap(),
            ConfidenceScore::MAX,
        );
        let evidence_id = evidence.id().clone();
        knowledge.insert_evidence(evidence).unwrap();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:http",
            subject(),
            KnowledgePredicate::new("vulnerability", "candidate").unwrap(),
            EvidenceValue::Boolean(true),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence_id.clone(),
                    Probability::from_percent(80).unwrap(),
                    Probability::from_percent(20).unwrap(),
                    "HTTP response contributes to the candidate",
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        Fixture {
            knowledge,
            evidence_id,
        }
    }

    fn verified_outcome(
        status: OutcomeStatus,
        stage: VerificationStage,
        evidence_id: EvidenceId,
    ) -> Outcome {
        Outcome::verified(
            "case:http:1",
            subject(),
            "http.probe",
            "hypothesis:http",
            "verify.http-status",
            stage,
            status,
            Probability::from_percent(90).unwrap(),
            "HTTP status verification",
            BTreeSet::from([evidence_id]),
        )
        .unwrap()
    }

    fn unknown_outcome(stage: VerificationStage) -> Outcome {
        Outcome::unknown(
            "case:http:1",
            subject(),
            "http.probe",
            "hypothesis:http",
            stage,
            "No verifier rule matched",
        )
        .unwrap()
    }

    #[test]
    fn verifier_blocked_403_schedules_bypass_action() {
        let fixture = fixture(403);
        let mut verifier = PassiveVerifier::new();
        assert_eq!(
            verifier
                .register(
                    VerificationRule::new(
                        "verify.403",
                        VerificationStage::Passive,
                        100,
                        Expression::equals(
                            KnowledgeLayer::Evidence,
                            status_predicate(),
                            EvidenceValue::Unsigned(403),
                        ),
                        OutcomeStatus::Blocked,
                        Probability::from_percent(95).unwrap(),
                        "Access was blocked",
                    )
                    .unwrap(),
                )
                .unwrap(),
            VerifierWrite::Inserted
        );
        let outcome = verifier
            .verify(
                &fixture.knowledge,
                &VerificationCase::new("case:http:1", subject(), "http.probe", "hypothesis:http")
                    .unwrap(),
            )
            .unwrap();
        let pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let decision = pipeline
            .decide(
                outcome.outcome(),
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            )
            .unwrap();

        assert_eq!(decision.selected_rule_id(), Some("http.403.bypass"));
        assert_eq!(
            decision.directive(),
            &PipelineDirective::ScheduleAction {
                action_id: "http.403-bypass".into()
            }
        );
    }

    #[test]
    fn review_404_redirects_to_enumeration() {
        let fixture = fixture(404);
        let pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let outcome = verified_outcome(
            OutcomeStatus::NeedsReview,
            VerificationStage::Passive,
            fixture.evidence_id,
        );
        let decision = pipeline
            .decide(
                &outcome,
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            )
            .unwrap();

        assert_eq!(decision.selected_rule_id(), Some("http.404.enumerate"));
        assert_eq!(
            decision.directive().scheduled_action_id(),
            Some("http.enumeration")
        );
    }

    #[test]
    fn stale_status_evidence_cannot_redirect_a_new_outcome() {
        let fixture = fixture(403);
        let current = Evidence::new(
            subject(),
            EvidenceKind::Http,
            status_predicate(),
            EvidenceValue::Unsigned(200),
            EvidenceSource::new("http.executor", "current-response-status").unwrap(),
            ConfidenceScore::MAX,
        );
        let current_id = current.id().clone();
        fixture.knowledge.insert_evidence(current).unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let outcome = verified_outcome(
            OutcomeStatus::NeedsReview,
            VerificationStage::Passive,
            current_id,
        );
        let pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        let decision = pipeline
            .decide(
                &outcome,
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            )
            .unwrap();

        assert!(decision.selected_rule_id().is_none());
        assert_eq!(
            decision.directive(),
            &PipelineDirective::AwaitActiveVerification
        );
        let stale = decision
            .evaluations()
            .iter()
            .find(|evaluation| evaluation.rule_id() == "http.403.bypass")
            .unwrap();
        assert!(stale.condition().unwrap().matched());
        assert!(!stale.outcome_evidence_matched());
        assert!(!stale.eligible());
    }

    #[test]
    fn blocked_429_throttles_and_retries() {
        let fixture = fixture(429);
        let pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let outcome = verified_outcome(
            OutcomeStatus::Blocked,
            VerificationStage::Active,
            fixture.evidence_id,
        );
        let decision = pipeline
            .decide(
                &outcome,
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            )
            .unwrap();

        assert_eq!(decision.selected_rule_id(), Some("http.429.throttle"));
        assert_eq!(
            decision.directive(),
            &PipelineDirective::Throttle {
                delay_ms: 2_000,
                retry_current_action: true
            }
        );
    }

    #[test]
    fn learned_suppression_prevents_repeating_a_scheduled_action() {
        let fixture = fixture(403);
        let mut experience = ExperienceStore::new();
        for attempt in 0..10 {
            experience
                .observe(
                    Outcome::verified(
                        format!("case:bypass:{attempt}"),
                        subject(),
                        "http.403-bypass",
                        "hypothesis:http",
                        "verify.403-bypass",
                        VerificationStage::Active,
                        OutcomeStatus::ConfirmedNegative,
                        Probability::from_percent(90).unwrap(),
                        "active negative control rejected the bypass",
                        BTreeSet::from([fixture.evidence_id.clone()]),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let suppressed = experience.suppressed_actions(&subject(), ExperiencePolicy::default());
        let outcome = verified_outcome(
            OutcomeStatus::Blocked,
            VerificationStage::Passive,
            fixture.evidence_id,
        );
        let decision = AdaptivePipeline::with_standard_policies()
            .unwrap()
            .decide_with_suppressed_actions(
                &outcome,
                &fixture.knowledge.snapshot_for_subject(&subject()),
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
                &suppressed,
            )
            .unwrap();

        assert_eq!(decision.directive(), &PipelineDirective::AwaitHumanReview);
        let bypass = decision
            .evaluations()
            .iter()
            .find(|evaluation| evaluation.rule_id() == "http.403.bypass")
            .unwrap();
        assert!(bypass.policy_suppressed());
        assert!(!bypass.eligible());
    }

    #[test]
    fn rule_application_limit_prevents_adaptation_loops() {
        let fixture = fixture(403);
        let pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let outcome = verified_outcome(
            OutcomeStatus::Blocked,
            VerificationStage::Passive,
            fixture.evidence_id,
        );
        let mut ledger = AdaptationLedger::new();

        for _ in 0..2 {
            let decision = pipeline
                .decide_and_record(
                    &outcome,
                    &snapshot,
                    &mut ledger,
                    AdaptationLimits::default(),
                )
                .unwrap();
            assert_eq!(decision.selected_rule_id(), Some("http.403.bypass"));
        }
        let exhausted = pipeline
            .decide(&outcome, &snapshot, &ledger, AdaptationLimits::default())
            .unwrap();

        assert_eq!(ledger.rule_applications("http.403.bypass"), 2);
        assert_eq!(ledger.action_schedules("http.403-bypass"), 2);
        assert_eq!(
            serde_json::from_value::<AdaptationLedger>(serde_json::to_value(&ledger).unwrap())
                .unwrap(),
            ledger
        );
        assert_eq!(exhausted.directive(), &PipelineDirective::AwaitHumanReview);
        let evaluation = exhausted
            .evaluations()
            .iter()
            .find(|evaluation| evaluation.rule_id() == "http.403.bypass")
            .unwrap();
        assert!(evaluation.rule_limit_exhausted());
        assert!(!evaluation.eligible());
    }

    #[test]
    fn action_schedule_limit_applies_across_policy_rules() {
        let fixture = fixture(403);
        let mut pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        pipeline
            .register(
                AdaptationRule::new(
                    "http.403.alternate",
                    OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Blocked])).unwrap(),
                    250,
                    Some(Expression::equals(
                        KnowledgeLayer::Evidence,
                        status_predicate(),
                        EvidenceValue::Unsigned(403),
                    )),
                    PipelineDirective::ScheduleAction {
                        action_id: "http.403-bypass".into(),
                    },
                    "alternate policy schedules the same bounded action",
                    2,
                )
                .unwrap(),
            )
            .unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let outcome = verified_outcome(
            OutcomeStatus::Blocked,
            VerificationStage::Passive,
            fixture.evidence_id,
        );
        let limits = AdaptationLimits::new(64, 1).unwrap();
        let mut ledger = AdaptationLedger::new();
        pipeline
            .decide_and_record(&outcome, &snapshot, &mut ledger, limits)
            .unwrap();
        let exhausted = pipeline
            .decide(&outcome, &snapshot, &ledger, limits)
            .unwrap();

        assert_eq!(ledger.action_schedules("http.403-bypass"), 1);
        assert_eq!(exhausted.directive(), &PipelineDirective::AwaitHumanReview);
        assert!(exhausted
            .evaluations()
            .iter()
            .filter(|evaluation| {
                evaluation
                    .condition()
                    .is_some_and(ExpressionEvaluation::matched)
            })
            .all(|evaluation| evaluation.action_limit_exhausted()));
    }

    #[test]
    fn global_transition_limit_emits_unrecorded_halt() {
        let fixture = fixture(404);
        let pipeline = AdaptivePipeline::with_standard_policies().unwrap();
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let outcome = unknown_outcome(VerificationStage::Passive);
        let limits = AdaptationLimits::new(1, 3).unwrap();
        let mut ledger = AdaptationLedger::new();
        pipeline
            .decide_and_record(&outcome, &snapshot, &mut ledger, limits)
            .unwrap();
        let halted = pipeline
            .decide_and_record(&outcome, &snapshot, &mut ledger, limits)
            .unwrap();

        assert_eq!(halted.directive(), &PipelineDirective::Halt);
        assert!(halted.transition_limit_reached());
        assert_eq!(ledger.transitions(), 1);
    }

    #[test]
    fn fallback_transitions_cover_outcome_lifecycle() {
        let fixture = fixture(200);
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let pipeline = AdaptivePipeline::new();
        let ledger = AdaptationLedger::new();
        let limits = AdaptationLimits::default();

        let success = verified_outcome(
            OutcomeStatus::Success,
            VerificationStage::Passive,
            fixture.evidence_id.clone(),
        );
        assert_eq!(
            pipeline
                .decide(&success, &snapshot, &ledger, limits)
                .unwrap()
                .directive(),
            &PipelineDirective::Complete
        );
        let false_positive = verified_outcome(
            OutcomeStatus::FalsePositive,
            VerificationStage::Active,
            fixture.evidence_id.clone(),
        );
        let mut replanning_ledger = AdaptationLedger::new();
        let replan = pipeline
            .decide_and_record(&false_positive, &snapshot, &mut replanning_ledger, limits)
            .unwrap();
        assert_eq!(
            replan.directive(),
            &PipelineDirective::Replan {
                suppress_current_action: true
            }
        );
        assert!(replanning_ledger
            .suppressed_actions()
            .contains("http.probe"));
        let confirmed_negative = verified_outcome(
            OutcomeStatus::ConfirmedNegative,
            VerificationStage::Active,
            fixture.evidence_id,
        );
        assert_eq!(
            pipeline
                .decide(&confirmed_negative, &snapshot, &ledger, limits)
                .unwrap()
                .directive(),
            &PipelineDirective::Replan {
                suppress_current_action: true
            }
        );
        assert_eq!(
            pipeline
                .decide(
                    &unknown_outcome(VerificationStage::Passive),
                    &snapshot,
                    &ledger,
                    limits,
                )
                .unwrap()
                .directive(),
            &PipelineDirective::AwaitActiveVerification
        );
        assert_eq!(
            pipeline
                .decide(
                    &unknown_outcome(VerificationStage::Active),
                    &snapshot,
                    &ledger,
                    limits,
                )
                .unwrap()
                .directive(),
            &PipelineDirective::AwaitHumanReview
        );
    }

    #[test]
    fn equal_priority_rules_use_stable_identity_order() {
        let fixture = fixture(200);
        let snapshot = fixture.knowledge.snapshot_for_subject(&subject());
        let mut pipeline = AdaptivePipeline::new();
        let selector =
            OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Blocked])).unwrap();
        for id in ["zeta", "alpha"] {
            pipeline
                .register(
                    AdaptationRule::new(
                        id,
                        selector.clone(),
                        10,
                        None,
                        PipelineDirective::AwaitHumanReview,
                        format!("{id} rationale"),
                        1,
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let outcome = verified_outcome(
            OutcomeStatus::Blocked,
            VerificationStage::Passive,
            fixture.evidence_id,
        );

        let first = pipeline
            .decide(
                &outcome,
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            )
            .unwrap();
        let second = pipeline
            .decide(
                &outcome,
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            )
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.selected_rule_id(), Some("alpha"));
    }

    #[test]
    fn wire_invariants_reject_invalid_rules_limits_and_ledgers() {
        let rule = AdaptationRule::new(
            "schedule",
            OutcomeSelector::any_stage(BTreeSet::from([OutcomeStatus::Blocked])).unwrap(),
            10,
            None,
            PipelineDirective::ScheduleAction {
                action_id: "http.bypass".into(),
            },
            "schedule bypass",
            1,
        )
        .unwrap();
        let mut encoded = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            serde_json::from_value::<AdaptationRule>(encoded.clone()).unwrap(),
            rule
        );
        encoded["directive"]["action_id"] = serde_json::json!("");
        assert!(serde_json::from_value::<AdaptationRule>(encoded).is_err());

        assert!(
            serde_json::from_value::<OutcomeSelector>(serde_json::json!({
                "statuses": [],
                "stages": ["passive"]
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AdaptationLimits>(serde_json::json!({
                "max_transitions": 0,
                "max_action_schedules": 1
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AdaptationLedger>(serde_json::json!({
                "transitions": 1,
                "rule_applications": {"": 1},
                "action_schedules": {},
                "suppressed_actions": []
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AdaptationLedger>(serde_json::json!({
                "transitions": 1,
                "rule_applications": {"rule": 2},
                "action_schedules": {},
                "suppressed_actions": []
            }))
            .is_err()
        );
    }

    #[test]
    fn outcome_provenance_must_exist_in_snapshot() {
        let outcome_fixture = fixture(403);
        let snapshot_fixture = fixture(403);
        let outcome = verified_outcome(
            OutcomeStatus::Blocked,
            VerificationStage::Passive,
            outcome_fixture.evidence_id,
        );
        let snapshot = snapshot_fixture.knowledge.snapshot_for_subject(&subject());

        assert!(matches!(
            AdaptivePipeline::new().decide(
                &outcome,
                &snapshot,
                &AdaptationLedger::new(),
                AdaptationLimits::default(),
            ),
            Err(AdaptivePipelineError::MissingOutcomeEvidence { .. })
        ));
    }
}
