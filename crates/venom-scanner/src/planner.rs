//! Deterministic, budget-aware attack planning.
//!
//! The planner ranks declarative actions but never executes them. It consumes
//! one immutable knowledge snapshot, evaluates action requirements, derives
//! confidence from Bayesian hypotheses, and emits an explainable plan.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{
    EntityId, EvidenceValue, Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate,
    Probability,
};

use crate::{Expression, ExpressionEvaluation, KnowledgeBase, KnowledgeSnapshot, RuleEngineError};

const MAX_BASIS_POINTS: u16 = 10_000;

/// Validation and consistency failures raised by the attack planner.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlannerError {
    /// A required identifier or executor name was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// A normalized benefit exceeded 10,000 basis points.
    #[error("benefit score {0} exceeds 10,000 basis points")]
    BenefitOutOfRange(u16),

    /// Risk must be in the inclusive `1..=10_000` range.
    #[error("risk score {0} must be between 1 and 10,000 basis points")]
    RiskOutOfRange(u16),

    /// Estimated action cost must be positive.
    #[error("action cost must be greater than zero")]
    ZeroCost,

    /// An action listed itself as a prerequisite.
    #[error("action {action_id} cannot depend on itself")]
    SelfDependency { action_id: String },

    /// An action referenced a prerequisite that is not registered.
    #[error("action {action_id} references unknown prerequisite {prerequisite}")]
    UnknownPrerequisite {
        /// Action containing the reference.
        action_id: String,
        /// Missing action identity.
        prerequisite: String,
    },

    /// The action dependency graph contains a cycle.
    #[error("action dependency cycle includes {action_id}")]
    DependencyCycle { action_id: String },

    /// An action identity was reused with different semantics.
    #[error("action identity {id} already has a different definition")]
    ActionIdentityConflict { id: String },

    /// Internal selection accounting omitted a registered action.
    #[error("planner produced no selection decision for action {action_id}")]
    IncompleteDecision { action_id: String },

    /// Expression evaluation failed.
    #[error(transparent)]
    Rule(#[from] RuleEngineError),
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, PlannerError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(PlannerError::EmptyValue { field });
    }
    Ok(value)
}

/// Normalized gain or business-value score in basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct BenefitScore(u16);

impl BenefitScore {
    /// No expected benefit.
    pub const NONE: Self = Self(0);

    /// Maximum normalized benefit.
    pub const MAX: Self = Self(MAX_BASIS_POINTS);

    /// Creates a benefit score from basis points.
    pub fn from_basis_points(value: u16) -> Result<Self, PlannerError> {
        if value > MAX_BASIS_POINTS {
            return Err(PlannerError::BenefitOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// Creates a benefit score from an integer percentage.
    pub fn from_percent(value: u8) -> Result<Self, PlannerError> {
        Self::from_basis_points(u16::from(value) * 100)
    }

    /// Returns the normalized score in basis points.
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for BenefitScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::from_basis_points(value).map_err(serde::de::Error::custom)
    }
}

/// Normalized operational risk in non-zero basis points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RiskScore(u16);

impl RiskScore {
    /// Maximum normalized risk.
    pub const MAX: Self = Self(MAX_BASIS_POINTS);

    /// Creates a non-zero risk score from basis points.
    pub fn from_basis_points(value: u16) -> Result<Self, PlannerError> {
        if value == 0 || value > MAX_BASIS_POINTS {
            return Err(PlannerError::RiskOutOfRange(value));
        }
        Ok(Self(value))
    }

    /// Creates a non-zero risk score from an integer percentage.
    pub fn from_percent(value: u8) -> Result<Self, PlannerError> {
        Self::from_basis_points(u16::from(value) * 100)
    }

    /// Returns the normalized score in basis points.
    pub const fn basis_points(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for RiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::from_basis_points(value).map_err(serde::de::Error::custom)
    }
}

/// Positive estimated execution cost in planner-defined units.
///
/// A deployment may define one unit as one request, one second, or another
/// consistent resource measure. Actions in one planner must use the same unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionCost(u32);

impl ActionCost {
    /// Creates a positive execution cost.
    pub fn new(units: u32) -> Result<Self, PlannerError> {
        if units == 0 {
            return Err(PlannerError::ZeroCost);
        }
        Ok(Self(units))
    }

    /// Returns the estimated cost units.
    pub const fn units(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ActionCost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Fixed-point utility used only for deterministic ordering.
///
/// The value is not a probability. It is calculated as
/// `gain * confidence * business_value / cost / risk` using the integer units
/// exposed by each input type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UtilityScore(u64);

impl UtilityScore {
    /// Zero utility.
    pub const ZERO: Self = Self(0);

    /// Smallest positive utility accepted by a default planning context.
    pub const MIN_POSITIVE: Self = Self(1);

    /// Creates a threshold or persisted score from raw utility units.
    pub const fn from_units(units: u64) -> Self {
        Self(units)
    }

    /// Returns raw fixed-point utility units.
    pub const fn units(self) -> u64 {
        self.0
    }
}

/// Explainable inputs and result of one utility calculation.
///
/// # Example
///
/// ```rust
/// use venom_core::Probability;
/// use venom_scanner::{ActionCost, BenefitScore, RiskScore, UtilityBreakdown};
///
/// let utility = UtilityBreakdown::calculate(
///     BenefitScore::from_percent(80)?,
///     Probability::from_percent(75)?,
///     BenefitScore::from_percent(90)?,
///     ActionCost::new(100)?,
///     RiskScore::from_percent(20)?,
/// );
///
/// assert_eq!(utility.score().units(), 270_000_000);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct UtilityBreakdown {
    gain: BenefitScore,
    confidence: Probability,
    business_value: BenefitScore,
    cost: ActionCost,
    risk: RiskScore,
    score: UtilityScore,
}

impl<'de> Deserialize<'de> for UtilityBreakdown {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireUtility {
            gain: BenefitScore,
            confidence: Probability,
            business_value: BenefitScore,
            cost: ActionCost,
            risk: RiskScore,
            score: UtilityScore,
        }

        let wire = WireUtility::deserialize(deserializer)?;
        let utility = Self::calculate(
            wire.gain,
            wire.confidence,
            wire.business_value,
            wire.cost,
            wire.risk,
        );
        if utility.score != wire.score {
            return Err(serde::de::Error::custom(format!(
                "serialized utility {} does not match computed utility {}",
                wire.score.units(),
                utility.score.units()
            )));
        }
        Ok(utility)
    }
}

impl UtilityBreakdown {
    /// Calculates utility with integer arithmetic and half-up rounding.
    pub fn calculate(
        gain: BenefitScore,
        confidence: Probability,
        business_value: BenefitScore,
        cost: ActionCost,
        risk: RiskScore,
    ) -> Self {
        let numerator = u128::from(gain.basis_points())
            * u128::from(confidence.parts_per_million())
            * u128::from(business_value.basis_points());
        let denominator = u128::from(cost.units()) * u128::from(risk.basis_points());
        let rounded = (numerator + denominator / 2) / denominator;
        let score = u64::try_from(rounded).expect("validated utility factors fit in u64");
        Self {
            gain,
            confidence,
            business_value,
            cost,
            risk,
            score: UtilityScore(score),
        }
    }

    /// Returns expected information or security gain.
    pub fn gain(&self) -> BenefitScore {
        self.gain
    }

    /// Returns the selected Bayesian hypothesis posterior.
    pub fn confidence(&self) -> Probability {
        self.confidence
    }

    /// Returns target business value.
    pub fn business_value(&self) -> BenefitScore {
        self.business_value
    }

    /// Returns estimated execution cost.
    pub fn cost(&self) -> ActionCost {
        self.cost
    }

    /// Returns normalized operational risk.
    pub fn risk(&self) -> RiskScore {
        self.risk
    }

    /// Returns the final fixed-point utility.
    pub fn score(&self) -> UtilityScore {
        self.score
    }
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

    fn select<'a>(&self, hypotheses: &'a [Hypothesis]) -> Option<&'a Hypothesis> {
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

/// Declarative executable candidate considered by the planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttackAction {
    id: String,
    executor: String,
    requirements: Expression,
    confidence_source: HypothesisSelector,
    gain: BenefitScore,
    cost: ActionCost,
    risk: RiskScore,
    prerequisites: BTreeSet<String>,
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
            requirements,
            confidence_source,
            gain,
            cost,
            risk,
            prerequisites,
        })
    }

    /// Returns the stable action identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the plugin or module executor identity.
    pub fn executor(&self) -> &str {
        &self.executor
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
            requirements: Expression,
            confidence_source: HypothesisSelector,
            gain: BenefitScore,
            cost: ActionCost,
            risk: RiskScore,
            prerequisites: BTreeSet<String>,
        }

        let wire = WireAction::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.executor,
            wire.requirements,
            wire.confidence_source,
            wire.gain,
            wire.cost,
            wire.risk,
            wire.prerequisites,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Inputs shared by every candidate in one planning cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanningContext {
    business_value: BenefitScore,
    budget: u64,
    maximum_risk: RiskScore,
    minimum_utility: UtilityScore,
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
    /// The action's expression did not match the snapshot.
    RequirementsNotMet,
    /// No supported hypothesis met the selector threshold.
    NoEligibleHypothesis,
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
    action_id: String,
    reason: ExclusionReason,
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
    position: usize,
    action_id: String,
    executor: String,
    prerequisites: BTreeSet<String>,
    confidence_hypothesis_id: String,
    requirements: ExpressionEvaluation,
    utility: UtilityBreakdown,
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

    /// Returns prerequisite action identities.
    pub fn prerequisites(&self) -> &BTreeSet<String> {
        &self.prerequisites
    }

    /// Returns the hypothesis selected as the confidence source.
    pub fn confidence_hypothesis_id(&self) -> &str {
        &self.confidence_hypothesis_id
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
    subject: EntityId,
    context: PlanningContext,
    total_cost: u64,
    steps: Vec<PlanStep>,
    excluded: Vec<ExcludedAction>,
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

#[derive(Debug, Clone)]
struct EligibleCandidate {
    action: AttackAction,
    confidence_hypothesis_id: String,
    requirements: ExpressionEvaluation,
    utility: UtilityBreakdown,
}

/// Deterministic utility planner for declarative attack actions.
#[derive(Debug, Clone, Default)]
pub struct AttackPlanner {
    actions: BTreeMap<String, AttackAction>,
}

impl AttackPlanner {
    /// Creates an empty planner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an idempotent action definition.
    pub fn register(&mut self, action: AttackAction) -> Result<PlannerWrite, PlannerError> {
        if let Some(existing) = self.actions.get(action.id()) {
            return if existing == &action {
                Ok(PlannerWrite::Unchanged)
            } else {
                Err(PlannerError::ActionIdentityConflict {
                    id: action.id().to_owned(),
                })
            };
        }
        self.actions.insert(action.id().to_owned(), action);
        Ok(PlannerWrite::Inserted)
    }

    /// Returns the number of registered action identities.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Returns whether no actions are registered.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Produces a plan from one internally consistent knowledge snapshot.
    pub fn plan(
        &self,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        context: PlanningContext,
    ) -> Result<AttackPlan, PlannerError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        self.plan_snapshot(&snapshot, context)
    }

    /// Produces a plan from an explicit immutable snapshot.
    pub fn plan_snapshot(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
    ) -> Result<AttackPlan, PlannerError> {
        self.validate_dependencies()?;

        let mut eligible = BTreeMap::<String, EligibleCandidate>::new();
        let mut exclusions = BTreeMap::<String, ExclusionReason>::new();
        for action in self.actions.values() {
            let requirements = action.requirements.evaluate(snapshot)?;
            if !requirements.matched() {
                exclusions.insert(action.id.clone(), ExclusionReason::RequirementsNotMet);
                continue;
            }
            if action.risk > context.maximum_risk {
                exclusions.insert(
                    action.id.clone(),
                    ExclusionReason::RiskLimitExceeded {
                        actual: action.risk,
                        maximum: context.maximum_risk,
                    },
                );
                continue;
            }
            let Some(hypothesis) = action.confidence_source.select(snapshot.hypotheses()) else {
                exclusions.insert(action.id.clone(), ExclusionReason::NoEligibleHypothesis);
                continue;
            };
            let utility = UtilityBreakdown::calculate(
                action.gain,
                hypothesis.posterior(),
                context.business_value,
                action.cost,
                action.risk,
            );
            if utility.score < context.minimum_utility {
                exclusions.insert(
                    action.id.clone(),
                    ExclusionReason::BelowMinimumUtility {
                        actual: utility.score,
                        minimum: context.minimum_utility,
                    },
                );
                continue;
            }
            eligible.insert(
                action.id.clone(),
                EligibleCandidate {
                    action: action.clone(),
                    confidence_hypothesis_id: hypothesis.id().to_owned(),
                    requirements,
                    utility,
                },
            );
        }

        let mut ranked: Vec<String> = eligible.keys().cloned().collect();
        ranked.sort_by(|left, right| {
            eligible[right]
                .utility
                .score
                .cmp(&eligible[left].utility.score)
                .then_with(|| left.cmp(right))
        });

        let mut selected = BTreeSet::<String>::new();
        let mut ordered = Vec::<String>::new();
        let mut total_cost = 0_u64;
        for action_id in ranked {
            if selected.contains(&action_id) {
                continue;
            }
            let mut closure = Vec::new();
            let mut visiting = BTreeSet::new();
            if let Some(unavailable) = build_eligible_closure(
                &action_id,
                &eligible,
                &selected,
                &mut visiting,
                &mut closure,
            ) {
                exclusions.insert(
                    action_id.clone(),
                    ExclusionReason::DependencyUnavailable {
                        prerequisite: unavailable,
                    },
                );
                continue;
            }
            let required = closure.iter().fold(0_u64, |sum, id| {
                sum + u64::from(eligible[id].action.cost.units())
            });
            let remaining = context.budget.saturating_sub(total_cost);
            if required > remaining {
                exclusions.insert(
                    action_id,
                    ExclusionReason::BudgetExceeded {
                        required,
                        remaining,
                    },
                );
                continue;
            }
            for id in closure {
                if selected.insert(id.clone()) {
                    total_cost += u64::from(eligible[&id].action.cost.units());
                    ordered.push(id);
                }
            }
        }

        let steps = ordered
            .into_iter()
            .enumerate()
            .map(|(position, id)| {
                let candidate = &eligible[&id];
                PlanStep {
                    position,
                    action_id: candidate.action.id.clone(),
                    executor: candidate.action.executor.clone(),
                    prerequisites: candidate.action.prerequisites.clone(),
                    confidence_hypothesis_id: candidate.confidence_hypothesis_id.clone(),
                    requirements: candidate.requirements.clone(),
                    utility: candidate.utility,
                }
            })
            .collect();
        let mut excluded = Vec::new();
        for id in self.actions.keys().filter(|id| !selected.contains(*id)) {
            let reason = exclusions
                .remove(id)
                .ok_or_else(|| PlannerError::IncompleteDecision {
                    action_id: id.clone(),
                })?;
            excluded.push(ExcludedAction {
                action_id: id.clone(),
                reason,
            });
        }

        Ok(AttackPlan {
            subject: snapshot.subject().clone(),
            context,
            total_cost,
            steps,
            excluded,
        })
    }

    fn validate_dependencies(&self) -> Result<(), PlannerError> {
        for action in self.actions.values() {
            for prerequisite in &action.prerequisites {
                if !self.actions.contains_key(prerequisite) {
                    return Err(PlannerError::UnknownPrerequisite {
                        action_id: action.id.clone(),
                        prerequisite: prerequisite.clone(),
                    });
                }
            }
        }
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for action_id in self.actions.keys() {
            visit_dependency(action_id, &self.actions, &mut visiting, &mut visited)?;
        }
        Ok(())
    }
}

fn visit_dependency(
    action_id: &str,
    actions: &BTreeMap<String, AttackAction>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Result<(), PlannerError> {
    if visited.contains(action_id) {
        return Ok(());
    }
    if !visiting.insert(action_id.to_owned()) {
        return Err(PlannerError::DependencyCycle {
            action_id: action_id.to_owned(),
        });
    }
    for prerequisite in &actions[action_id].prerequisites {
        visit_dependency(prerequisite, actions, visiting, visited)?;
    }
    visiting.remove(action_id);
    visited.insert(action_id.to_owned());
    Ok(())
}

fn build_eligible_closure(
    action_id: &str,
    eligible: &BTreeMap<String, EligibleCandidate>,
    selected: &BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
    ordered: &mut Vec<String>,
) -> Option<String> {
    if selected.contains(action_id) || ordered.iter().any(|id| id == action_id) {
        return None;
    }
    let Some(candidate) = eligible.get(action_id) else {
        return Some(action_id.to_owned());
    };
    visiting.insert(action_id.to_owned());
    for prerequisite in &candidate.action.prerequisites {
        if !eligible.contains_key(prerequisite) {
            return Some(prerequisite.clone());
        }
        if !visiting.contains(prerequisite) {
            if let Some(unavailable) =
                build_eligible_closure(prerequisite, eligible, selected, visiting, ordered)
            {
                return Some(unavailable);
            }
        }
    }
    visiting.remove(action_id);
    ordered.push(action_id.to_owned());
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EvidenceCalibration, EvidenceSelector, HypothesisConclusion, KnowledgeLayer, ReasoningRule,
        RuleEngine,
    };
    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, HypothesisState,
        KnowledgePredicate,
    };

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn stack_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("stack", "framework").unwrap()
    }

    fn stack_value() -> EvidenceValue {
        EvidenceValue::Text("Laravel".into())
    }

    fn knowledge_with_hypothesis(posterior_signal: (u8, u8)) -> KnowledgeBase {
        let knowledge = KnowledgeBase::new();
        let evidence = Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new("technology", "framework").unwrap(),
            stack_value(),
            EvidenceSource::new("discovery", "framework-header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );
        knowledge.insert_evidence(evidence.clone()).unwrap();
        let mut hypothesis = Hypothesis::with_id(
            "hypothesis:laravel",
            subject(),
            stack_predicate(),
            stack_value(),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence.id().clone(),
                    Probability::from_percent(posterior_signal.0).unwrap(),
                    Probability::from_percent(posterior_signal.1).unwrap(),
                    "framework fingerprint",
                )
                .unwrap(),
            )
            .unwrap();
        hypothesis.set_strength(HypothesisStrength::Strong);
        hypothesis.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        knowledge
    }

    fn action(id: &str, gain: u8, cost: u32, risk: u8, prerequisites: &[&str]) -> AttackAction {
        AttackAction::new(
            id,
            format!("plugin.{id}"),
            Expression::equals(KnowledgeLayer::Hypothesis, stack_predicate(), stack_value()),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(gain).unwrap(),
            ActionCost::new(cost).unwrap(),
            RiskScore::from_percent(risk).unwrap(),
            prerequisites.iter().map(|value| (*value).into()).collect(),
        )
        .unwrap()
    }

    fn context(budget: u64) -> PlanningContext {
        PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            budget,
            RiskScore::from_percent(80).unwrap(),
        )
    }

    #[test]
    fn utility_uses_fixed_point_formula() {
        let utility = UtilityBreakdown::calculate(
            BenefitScore::from_percent(80).unwrap(),
            Probability::from_percent(75).unwrap(),
            BenefitScore::from_percent(90).unwrap(),
            ActionCost::new(100).unwrap(),
            RiskScore::from_percent(20).unwrap(),
        );

        assert_eq!(utility.score().units(), 270_000_000);
        let encoded = serde_json::to_value(utility).unwrap();
        assert_eq!(
            serde_json::from_value::<UtilityBreakdown>(encoded.clone()).unwrap(),
            utility
        );
        let mut tampered = encoded;
        tampered["score"] = serde_json::json!(1);
        assert!(serde_json::from_value::<UtilityBreakdown>(tampered).is_err());
    }

    #[test]
    fn planner_orders_equal_utility_by_action_id() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("zeta", 80, 10, 20, &[])).unwrap();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();

        let first = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        let second = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.steps()[0].action_id(), "alpha");
        assert_eq!(first.steps()[1].action_id(), "zeta");
        assert_eq!(first.total_cost(), 20);
    }

    #[test]
    fn planner_places_prerequisites_before_high_utility_action() {
        let knowledge = knowledge_with_hypothesis((90, 10));
        let mut planner = AttackPlanner::new();
        planner
            .register(action("discovery", 10, 10, 40, &[]))
            .unwrap();
        planner
            .register(action("active.verify", 95, 30, 10, &["discovery"]))
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(40)).unwrap();

        assert_eq!(plan.steps()[0].action_id(), "discovery");
        assert_eq!(plan.steps()[1].action_id(), "active.verify");
        assert_eq!(plan.total_cost(), 40);
    }

    #[test]
    fn budget_exclusion_includes_dependency_closure_cost() {
        let knowledge = knowledge_with_hypothesis((90, 10));
        let mut planner = AttackPlanner::new();
        planner
            .register(action("discovery", 10, 10, 40, &[]))
            .unwrap();
        planner
            .register(action("active.verify", 95, 30, 10, &["discovery"]))
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(35)).unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "discovery");
        let active = plan
            .excluded()
            .iter()
            .find(|excluded| excluded.action_id() == "active.verify")
            .unwrap();
        assert_eq!(
            active.reason(),
            &ExclusionReason::BudgetExceeded {
                required: 40,
                remaining: 35,
            }
        );
    }

    #[test]
    fn risk_and_confidence_filters_are_explainable() {
        let knowledge = knowledge_with_hypothesis((60, 40));
        let mut planner = AttackPlanner::new();
        planner.register(action("risky", 90, 10, 90, &[])).unwrap();
        let strict_confidence = AttackAction::new(
            "uncertain",
            "plugin.uncertain",
            Expression::equals(KnowledgeLayer::Hypothesis, stack_predicate(), stack_value()),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(90).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        planner.register(strict_confidence).unwrap();
        let unmet = AttackAction::new(
            "unmet",
            "plugin.unmet",
            Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("authentication", "mfa").unwrap(),
            ),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        planner.register(unmet).unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert!(plan.steps().is_empty());
        assert!(matches!(
            plan.excluded()[0].reason(),
            ExclusionReason::RiskLimitExceeded { .. } | ExclusionReason::NoEligibleHypothesis
        ));
        assert!(plan
            .excluded()
            .iter()
            .any(|excluded| matches!(excluded.reason(), ExclusionReason::NoEligibleHypothesis)));
        assert!(plan.excluded().iter().any(|excluded| matches!(
            excluded.reason(),
            ExclusionReason::RiskLimitExceeded { .. }
        )));
        assert!(plan
            .excluded()
            .iter()
            .any(|excluded| matches!(excluded.reason(), ExclusionReason::RequirementsNotMet)));
    }

    #[test]
    fn dependency_validation_rejects_unknown_and_cycles() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut unknown = AttackPlanner::new();
        unknown
            .register(action("dependent", 80, 10, 20, &["missing"]))
            .unwrap();
        assert!(matches!(
            unknown.plan(&knowledge, &subject(), context(100)),
            Err(PlannerError::UnknownPrerequisite { .. })
        ));

        let mut cyclic = AttackPlanner::new();
        cyclic.register(action("a", 80, 10, 20, &["b"])).unwrap();
        cyclic.register(action("b", 80, 10, 20, &["a"])).unwrap();
        assert!(matches!(
            cyclic.plan(&knowledge, &subject(), context(100)),
            Err(PlannerError::DependencyCycle { .. })
        ));
    }

    #[test]
    fn ineligible_dependency_blocks_dependent_action() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let blocked = AttackAction::new(
            "blocked",
            "plugin.blocked",
            Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("authentication", "mfa").unwrap(),
            ),
            HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        let mut planner = AttackPlanner::new();
        planner.register(blocked).unwrap();
        planner
            .register(action("dependent", 90, 10, 10, &["blocked"]))
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert!(plan.steps().is_empty());
        let dependent = plan
            .excluded()
            .iter()
            .find(|excluded| excluded.action_id() == "dependent")
            .unwrap();
        assert_eq!(
            dependent.reason(),
            &ExclusionReason::DependencyUnavailable {
                prerequisite: "blocked".into(),
            }
        );
    }

    #[test]
    fn action_registration_and_wire_invariants_are_enforced() {
        let action = action("sqli.verify", 80, 10, 20, &[]);
        let encoded = serde_json::to_value(&action).unwrap();
        assert_eq!(
            serde_json::from_value::<AttackAction>(encoded).unwrap(),
            action
        );
        assert!(ActionCost::new(0).is_err());
        assert!(RiskScore::from_basis_points(0).is_err());
        assert!(BenefitScore::from_basis_points(10_001).is_err());

        let mut planner = AttackPlanner::new();
        assert_eq!(
            planner.register(action.clone()).unwrap(),
            PlannerWrite::Inserted
        );
        assert_eq!(
            planner.register(action.clone()).unwrap(),
            PlannerWrite::Unchanged
        );
        let conflicting = AttackAction::new(
            action.id(),
            "plugin.other",
            action.requirements.clone(),
            action.confidence_source.clone(),
            action.gain,
            action.cost,
            action.risk,
            BTreeSet::new(),
        )
        .unwrap();
        assert!(matches!(
            planner.register(conflicting),
            Err(PlannerError::ActionIdentityConflict { .. })
        ));
    }

    #[test]
    fn planner_accepts_hypotheses_materialized_by_rule_contracts() {
        let knowledge = KnowledgeBase::new();
        let evidence_predicate = KnowledgePredicate::new("technology", "framework").unwrap();
        knowledge
            .insert_evidence(Evidence::new(
                subject(),
                EvidenceKind::Technology,
                evidence_predicate.clone(),
                stack_value(),
                EvidenceSource::new("discovery", "framework-header").unwrap(),
                ConfidenceScore::from_percent(90).unwrap(),
            ))
            .unwrap();
        let calibration = EvidenceCalibration::new(
            EvidenceSelector::equals(evidence_predicate.clone(), stack_value()),
            Probability::from_percent(80).unwrap(),
            Probability::from_percent(20).unwrap(),
            "framework fingerprint",
        )
        .unwrap();
        let conclusion = HypothesisConclusion::new(
            stack_predicate(),
            stack_value(),
            Probability::from_percent(50).unwrap(),
            HypothesisStrength::Strong,
            HypothesisState::Supported,
            vec![calibration],
        )
        .unwrap();
        let rule = ReasoningRule::new(
            "detect.laravel",
            Expression::equals(KnowledgeLayer::Evidence, evidence_predicate, stack_value()),
            conclusion,
        )
        .unwrap();
        let mut rules = RuleEngine::new();
        rules.register(rule).unwrap();
        rules.apply(&knowledge, &subject()).unwrap();

        let mut planner = AttackPlanner::new();
        planner
            .register(action("laravel.verify", 80, 10, 20, &[]))
            .unwrap();
        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "laravel.verify");
        assert_eq!(
            plan.steps()[0].confidence_hypothesis_id(),
            "rule:14:detect.laravel:endpoint:https://example.test"
        );
    }
}
