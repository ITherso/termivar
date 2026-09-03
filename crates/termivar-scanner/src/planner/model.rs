use std::collections::{BTreeMap, BTreeSet};

use serde::{de::IgnoredAny, Deserialize, Deserializer, Serialize};
use termivar_core::{
    EntityId, EvidenceValue, Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate,
    Probability,
};

use crate::{
    payload_strategy::PayloadStrategyRef,
    rules::{Expression, ExpressionEvaluation},
};

use crate::planner::{
    scoring::{ActionCost, BenefitScore, RiskScore, UtilityBreakdown, UtilityScore},
    PlannerError,
};

fn is_false(value: &bool) -> bool {
    !*value
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, PlannerError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(PlannerError::EmptyValue { field });
    }
    Ok(value)
}

/// Required qualitative strength for an action's confidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequiredStrength {
    /// A weak or strong supported hypothesis is acceptable.
    Any,
    /// Only a strong supported hypothesis is acceptable.
    Strong,
}

/// Selects the Bayesian hypothesis that supplies action confidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypothesisSelector {
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    minimum_posterior: Probability,
    required_strength: RequiredStrength,
}

impl HypothesisSelector {
    /// Creates an exact claim selector and minimum confidence threshold.
    pub fn new(
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        minimum_posterior: Probability,
        required_strength: RequiredStrength,
    ) -> Self {
        Self {
            predicate,
            value,
            minimum_posterior,
            required_strength,
        }
    }

    /// Returns the selected claim predicate.
    pub fn predicate(&self) -> &KnowledgePredicate {
        &self.predicate
    }

    /// Returns the selected claim value.
    pub fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Returns the minimum accepted posterior.
    pub fn minimum_posterior(&self) -> Probability {
        self.minimum_posterior
    }

    /// Returns the required rule-assigned strength.
    pub fn required_strength(&self) -> RequiredStrength {
        self.required_strength
    }

    pub(crate) fn select<'a>(&self, hypotheses: &'a [Hypothesis]) -> Option<&'a Hypothesis> {
        let mut selected: Option<&Hypothesis> = None;
        for hypothesis in hypotheses.iter().filter(|hypothesis| {
            hypothesis.predicate() == &self.predicate
                && hypothesis.value() == &self.value
                && matches!(
                    hypothesis.state(),
                    HypothesisState::Supported | HypothesisState::Confirmed
                )
                && hypothesis.posterior() >= self.minimum_posterior
                && matches!(
                    (self.required_strength, hypothesis.strength()),
                    (RequiredStrength::Any, _)
                        | (RequiredStrength::Strong, HypothesisStrength::Strong)
                )
        }) {
            if selected.is_none_or(|current| hypothesis.posterior() > current.posterior()) {
                selected = Some(hypothesis);
            }
        }
        selected
    }
}

/// What a conclusive outcome may transition, kept distinct from the confidence
/// hypothesis that motivated planning the action.
///
/// The default, [`Self::Motivation`], preserves the historical behavior where a
/// `Success` confirms the same hypothesis the planner used for confidence. The
/// other variants let an action's *justification for running* differ from the
/// *claim its result verifies* — the core of claim discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VerificationTarget {
    /// Confirm the confidence (motivation) hypothesis. Historical default.
    #[default]
    Motivation,
    /// Confirm a distinct, already-supported result hypothesis instead of the
    /// motivation hypothesis.
    Distinct(HypothesisSelector),
    /// Record the outcome (which may be `Success`) without transitioning any
    /// hypothesis state. "The action's objective was achieved" is not "the
    /// motivating hypothesis was conclusively verified".
    KnowledgeOnly,
}

impl VerificationTarget {
    fn is_motivation(&self) -> bool {
        matches!(self, Self::Motivation)
    }

    pub(crate) fn resolve(
        &self,
        hypotheses: &[Hypothesis],
        motivation_hypothesis_id: &str,
    ) -> Option<ResolvedVerificationTarget> {
        match self {
            Self::Motivation => Some(ResolvedVerificationTarget::Hypothesis(
                motivation_hypothesis_id.to_owned(),
            )),
            Self::Distinct(selector) => selector
                .select(hypotheses)
                .filter(|hypothesis| hypothesis.id() != motivation_hypothesis_id)
                .map(|hypothesis| {
                    ResolvedVerificationTarget::Hypothesis(hypothesis.id().to_owned())
                }),
            Self::KnowledgeOnly => Some(ResolvedVerificationTarget::KnowledgeOnly),
        }
    }
}

/// Plan-time resolution of the claim an action outcome may transition.
///
/// The planner resolves both [`VerificationTarget::Motivation`] and
/// [`VerificationTarget::Distinct`] to an existing hypothesis identity.
/// [`Self::KnowledgeOnly`] deliberately resolves to no transition target; the
/// motivating hypothesis remains available separately on [`PlanStep`] for
/// utility provenance and audit correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResolvedVerificationTarget {
    /// A conclusive outcome may transition this pre-existing hypothesis.
    Hypothesis(String),
    /// The action outcome is auditable but cannot transition a hypothesis.
    KnowledgeOnly,
}

impl ResolvedVerificationTarget {
    /// Returns the hypothesis a conclusive outcome may transition, if any.
    pub fn hypothesis_id(&self) -> Option<&str> {
        match self {
            Self::Hypothesis(id) => Some(id),
            Self::KnowledgeOnly => None,
        }
    }

    /// Returns whether this target authorizes a hypothesis-state transition.
    pub fn applies_hypothesis_transition(&self) -> bool {
        matches!(self, Self::Hypothesis(_))
    }
}

/// Declarative executable candidate considered by the planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttackAction {
    pub(super) id: String,
    pub(super) executor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) payload_strategy: Option<PayloadStrategyRef>,
    pub(super) requirements: Expression,
    pub(super) confidence_source: HypothesisSelector,
    pub(super) gain: BenefitScore,
    pub(super) cost: ActionCost,
    pub(super) risk: RiskScore,
    pub(super) prerequisites: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "VerificationTarget::is_motivation")]
    pub(super) verification_target: VerificationTarget,
    // This sentinel deliberately uses the only namespace that legacy readers
    // already reject. It prevents an older binary from silently discarding a
    // non-default verification target and reconstructing it as Motivation.
    #[serde(
        default,
        rename = "payload_claim_policy_guard",
        skip_serializing_if = "is_false"
    )]
    claim_policy_guard: bool,
}

impl AttackAction {
    /// Creates a validated action without executing or resolving dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        executor: impl Into<String>,
        requirements: Expression,
        confidence_source: HypothesisSelector,
        gain: BenefitScore,
        cost: ActionCost,
        risk: RiskScore,
        prerequisites: BTreeSet<String>,
    ) -> Result<Self, PlannerError> {
        let id = non_empty(id, "action id")?;
        let executor = non_empty(executor, "action executor")?;
        for prerequisite in &prerequisites {
            non_empty(prerequisite.clone(), "action prerequisite")?;
            if prerequisite == &id {
                return Err(PlannerError::SelfDependency {
                    action_id: id.clone(),
                });
            }
        }
        Ok(Self {
            id,
            executor,
            payload_strategy: None,
            requirements,
            confidence_source,
            gain,
            cost,
            risk,
            prerequisites,
            verification_target: VerificationTarget::Motivation,
            claim_policy_guard: false,
        })
    }

    /// Sets what a conclusive outcome may transition. Defaults to
    /// [`VerificationTarget::Motivation`] (confirm the confidence hypothesis).
    pub fn with_verification_target(mut self, target: VerificationTarget) -> Self {
        self.claim_policy_guard = !target.is_motivation();
        self.verification_target = target;
        self
    }

    /// Returns what a conclusive outcome may transition.
    pub fn verification_target(&self) -> &VerificationTarget {
        &self.verification_target
    }

    /// Returns the stable action identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the plugin or module executor identity.
    pub fn executor(&self) -> &str {
        &self.executor
    }

    /// Selects a versioned payload strategy without exposing its implementation.
    pub fn with_payload_strategy(mut self, strategy: PayloadStrategyRef) -> Self {
        self.payload_strategy = Some(strategy);
        self
    }

    /// Returns the planner-selected payload strategy, when this action uses one.
    pub const fn payload_strategy(&self) -> Option<&PayloadStrategyRef> {
        self.payload_strategy.as_ref()
    }

    /// Returns the rule expression gating this action.
    pub fn requirements(&self) -> &Expression {
        &self.requirements
    }

    /// Returns the hypothesis selector supplying Bayesian confidence.
    pub fn confidence_source(&self) -> &HypothesisSelector {
        &self.confidence_source
    }

    /// Returns expected gain.
    pub fn gain(&self) -> BenefitScore {
        self.gain
    }

    /// Returns estimated execution cost.
    pub fn cost(&self) -> ActionCost {
        self.cost
    }

    /// Returns operational risk.
    pub fn risk(&self) -> RiskScore {
        self.risk
    }

    /// Returns prerequisite action identities in stable order.
    pub fn prerequisites(&self) -> &BTreeSet<String> {
        &self.prerequisites
    }
}

impl<'de> Deserialize<'de> for AttackAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireAction {
            id: String,
            executor: String,
            #[serde(default)]
            payload_strategy: Option<PayloadStrategyRef>,
            requirements: Expression,
            confidence_source: HypothesisSelector,
            gain: BenefitScore,
            cost: ActionCost,
            risk: RiskScore,
            prerequisites: BTreeSet<String>,
            #[serde(default)]
            verification_target: VerificationTarget,
            #[serde(default)]
            payload_claim_policy_guard: bool,
            #[serde(flatten)]
            extensions: BTreeMap<String, IgnoredAny>,
        }

        let wire = WireAction::deserialize(deserializer)?;
        if wire
            .extensions
            .keys()
            .any(|field| field.starts_with("payload_") || field.starts_with("verification_"))
        {
            return Err(serde::de::Error::custom("unknown reserved action field"));
        }
        if wire.payload_claim_policy_guard == wire.verification_target.is_motivation() {
            return Err(serde::de::Error::custom(
                "verification target compatibility guard is missing or inconsistent",
            ));
        }
        let action = Self::new(
            wire.id,
            wire.executor,
            wire.requirements,
            wire.confidence_source,
            wire.gain,
            wire.cost,
            wire.risk,
            wire.prerequisites,
        )
        .map_err(serde::de::Error::custom)?;
        let action = action.with_verification_target(wire.verification_target);
        Ok(match wire.payload_strategy {
            Some(strategy) => action.with_payload_strategy(strategy),
            None => action,
        })
    }
}

/// Inputs shared by every candidate in one planning cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanningContext {
    pub(super) business_value: BenefitScore,
    pub(super) budget: u64,
    pub(super) maximum_risk: RiskScore,
    pub(super) minimum_utility: UtilityScore,
}

impl PlanningContext {
    /// Creates a planning context requiring positive utility.
    pub fn new(business_value: BenefitScore, budget: u64, maximum_risk: RiskScore) -> Self {
        Self {
            business_value,
            budget,
            maximum_risk,
            minimum_utility: UtilityScore::MIN_POSITIVE,
        }
    }

    /// Sets the minimum utility required for a candidate and its dependencies.
    pub fn with_minimum_utility(mut self, minimum_utility: UtilityScore) -> Self {
        self.minimum_utility = minimum_utility;
        self
    }

    /// Returns target business value.
    pub fn business_value(&self) -> BenefitScore {
        self.business_value
    }

    /// Returns the maximum total action cost.
    pub fn budget(&self) -> u64 {
        self.budget
    }

    /// Returns the maximum accepted action risk.
    pub fn maximum_risk(&self) -> RiskScore {
        self.maximum_risk
    }

    /// Returns the minimum accepted utility.
    pub fn minimum_utility(&self) -> UtilityScore {
        self.minimum_utility
    }
}

/// Reason a registered action was not selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExclusionReason {
    /// An adaptive or operator policy suppressed this action.
    PolicySuppressed,
    /// Observed defensive posture suppressed this action, distinct from an
    /// adaptive or operator policy suppression so the two never conflate.
    DefenseSuppressed,
    /// The action's expression did not match the snapshot.
    RequirementsNotMet,
    /// No supported hypothesis met the selector threshold.
    NoEligibleHypothesis,
    /// A distinct verification target did not resolve to a pre-existing,
    /// supported hypothesis in the planning snapshot.
    NoEligibleVerificationTarget,
    /// Action risk exceeded the planning context limit.
    RiskLimitExceeded {
        /// Action risk.
        actual: RiskScore,
        /// Maximum accepted risk.
        maximum: RiskScore,
    },
    /// Calculated utility was below the context threshold.
    BelowMinimumUtility {
        /// Calculated action utility.
        actual: UtilityScore,
        /// Minimum accepted utility.
        minimum: UtilityScore,
    },
    /// A prerequisite was not eligible for selection.
    DependencyUnavailable {
        /// Unavailable prerequisite identity.
        prerequisite: String,
    },
    /// The action and its unselected dependencies did not fit the budget.
    BudgetExceeded {
        /// Additional cost needed to select the dependency closure.
        required: u64,
        /// Budget remaining when the action was considered.
        remaining: u64,
    },
}

/// Explainable record for a candidate omitted from the plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExcludedAction {
    pub(super) action_id: String,
    pub(super) reason: ExclusionReason,
}

impl ExcludedAction {
    /// Returns the omitted action identity.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns why the planner omitted the action.
    pub fn reason(&self) -> &ExclusionReason {
        &self.reason
    }
}

/// One dependency-safe step selected for execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanStep {
    pub(super) position: usize,
    pub(super) action_id: String,
    pub(super) executor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) payload_strategy: Option<PayloadStrategyRef>,
    pub(super) prerequisites: BTreeSet<String>,
    pub(super) confidence_hypothesis_id: String,
    #[serde(skip)]
    pub(super) verification_target: ResolvedVerificationTarget,
    pub(super) requirements: ExpressionEvaluation,
    pub(super) utility: UtilityBreakdown,
}

impl PlanStep {
    /// Returns the zero-based execution position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the selected action identity.
    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    /// Returns the plugin or module executor identity.
    pub fn executor(&self) -> &str {
        &self.executor
    }

    /// Returns the exact payload strategy revision selected with this action.
    pub const fn payload_strategy(&self) -> Option<&PayloadStrategyRef> {
        self.payload_strategy.as_ref()
    }

    /// Returns prerequisite action identities.
    pub fn prerequisites(&self) -> &BTreeSet<String> {
        &self.prerequisites
    }

    /// Returns the hypothesis selected as the confidence source.
    pub fn confidence_hypothesis_id(&self) -> &str {
        &self.confidence_hypothesis_id
    }

    /// Returns the separately resolved claim this step may transition.
    pub fn verification_target(&self) -> &ResolvedVerificationTarget {
        &self.verification_target
    }

    /// Returns the requirement evaluation trace.
    pub fn requirements(&self) -> &ExpressionEvaluation {
        &self.requirements
    }

    /// Returns the complete utility calculation.
    pub fn utility(&self) -> &UtilityBreakdown {
        &self.utility
    }
}

/// Immutable output of one deterministic planning cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttackPlan {
    pub(super) subject: EntityId,
    pub(super) context: PlanningContext,
    pub(super) total_cost: u64,
    pub(super) steps: Vec<PlanStep>,
    pub(super) excluded: Vec<ExcludedAction>,
}

impl AttackPlan {
    /// Returns the planned subject.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns the context used to score and constrain candidates.
    pub fn context(&self) -> PlanningContext {
        self.context
    }

    /// Returns the sum of selected action costs.
    pub fn total_cost(&self) -> u64 {
        self.total_cost
    }

    /// Returns selected actions in dependency-safe execution order.
    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    /// Returns omitted actions in stable action-ID order.
    pub fn excluded(&self) -> &[ExcludedAction] {
        &self.excluded
    }

    /// Removes defense-suppressed steps from this already-authorized plan.
    ///
    /// This is deliberately a filter, not a second planning pass. Retained
    /// steps preserve their exact metadata and relative order; removing a
    /// prerequisite also removes every dependent step so the result remains a
    /// dependency-safe subsequence. Candidates excluded from the baseline can
    /// never enter through budget freed by defense suppression.
    pub(crate) fn into_defense_filtered(
        self,
        defense_suppressed_actions: &BTreeSet<String>,
    ) -> Self {
        if defense_suppressed_actions.is_empty() {
            return self;
        }
        let affects_step = self
            .steps
            .iter()
            .any(|step| defense_suppressed_actions.contains(step.action_id()));
        if !affects_step {
            return self;
        }

        let mut retained_ids = BTreeSet::new();
        let mut retained_steps = Vec::new();
        let mut removed = BTreeMap::new();
        for mut step in self.steps {
            let reason = if defense_suppressed_actions.contains(step.action_id()) {
                Some(ExclusionReason::DefenseSuppressed)
            } else {
                step.prerequisites
                    .iter()
                    .find(|prerequisite| !retained_ids.contains(*prerequisite))
                    .map(|prerequisite| ExclusionReason::DependencyUnavailable {
                        prerequisite: prerequisite.clone(),
                    })
            };
            if let Some(reason) = reason {
                removed.insert(step.action_id.clone(), reason);
                continue;
            }
            step.position = retained_steps.len();
            retained_ids.insert(step.action_id.clone());
            retained_steps.push(step);
        }

        let mut excluded: BTreeMap<String, ExclusionReason> = self
            .excluded
            .into_iter()
            .map(|excluded| (excluded.action_id, excluded.reason))
            .collect();
        excluded.extend(removed);
        let total_cost = retained_steps
            .iter()
            .map(|step| u64::from(step.utility.cost.units()))
            .sum();

        Self {
            subject: self.subject,
            context: self.context,
            total_cost,
            steps: retained_steps,
            excluded: excluded
                .into_iter()
                .map(|(action_id, reason)| ExcludedAction { action_id, reason })
                .collect(),
        }
    }
}

/// Result of registering an action identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PlannerWrite {
    /// A new action was registered.
    Inserted,
    /// The identical action was already registered.
    Unchanged,
}
