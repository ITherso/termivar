//! Deterministic, budget-aware attack planning.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B (deterministic decision runtime).
//! - **Default `venom scan`:** yes, through `StandardWebDecisionRuntime`.
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! The planner ranks declarative actions but never executes them. It consumes
//! one immutable knowledge snapshot, evaluates action requirements, derives
//! confidence from Bayesian hypotheses, and emits an explainable plan.

use std::collections::{BTreeMap, BTreeSet};

use serde::{de::IgnoredAny, Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{
    EntityId, EvidenceValue, Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate,
    Probability,
};

use crate::{
    knowledge::{KnowledgeBase, KnowledgeSnapshot},
    payload_strategy::PayloadStrategyRef,
    rules::{Expression, ExpressionEvaluation, RuleEngineError},
};

const MAX_BASIS_POINTS: u16 = 10_000;

fn is_false(value: &bool) -> bool {
    !*value
}

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
    id: String,
    executor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_strategy: Option<PayloadStrategyRef>,
    requirements: Expression,
    confidence_source: HypothesisSelector,
    gain: BenefitScore,
    cost: ActionCost,
    risk: RiskScore,
    prerequisites: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "VerificationTarget::is_motivation")]
    verification_target: VerificationTarget,
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
        if wire.payload_claim_policy_guard != !wire.verification_target.is_motivation() {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_strategy: Option<PayloadStrategyRef>,
    prerequisites: BTreeSet<String>,
    confidence_hypothesis_id: String,
    #[serde(skip)]
    verification_target: ResolvedVerificationTarget,
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

#[derive(Debug, Clone)]
struct EligibleCandidate {
    action: AttackAction,
    confidence_hypothesis_id: String,
    verification_target: ResolvedVerificationTarget,
    requirements: ExpressionEvaluation,
    utility: UtilityBreakdown,
}

type CandidateEligibility = Result<EligibleCandidate, ExclusionReason>;

/// Current host-owned action suppressions, preserving their authority source.
///
/// This stays crate-private until the assessment/profile contract settles. The
/// existing public APIs remain compatibility wrappers that populate only the
/// policy set, while runtime composition can carry defense suppressions without
/// conflating them with operator, experience, or adaptive policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActionSuppressionContext {
    policy_suppressed_actions: BTreeSet<String>,
    defense_suppressed_actions: BTreeSet<String>,
}

impl ActionSuppressionContext {
    pub(crate) fn new(
        policy_suppressed_actions: BTreeSet<String>,
        defense_suppressed_actions: BTreeSet<String>,
    ) -> Self {
        Self {
            policy_suppressed_actions,
            defense_suppressed_actions,
        }
    }

    pub(crate) fn policy_only(policy_suppressed_actions: &BTreeSet<String>) -> Self {
        Self::new(policy_suppressed_actions.clone(), BTreeSet::new())
    }

    pub(crate) fn policy_suppressed_actions(&self) -> &BTreeSet<String> {
        &self.policy_suppressed_actions
    }

    pub(crate) fn defense_suppressed_actions(&self) -> &BTreeSet<String> {
        &self.defense_suppressed_actions
    }
}

/// Why a registered action could not be authorized for immediate adaptive
/// dispatch.
///
/// This stays crate-private because it is an orchestration boundary between the
/// planner and decision loop, not a second public planning API.
#[derive(Debug, Error)]
pub(crate) enum ScheduledActionAuthorizationError {
    /// The registered action graph was invalid or requirement evaluation failed.
    #[error(transparent)]
    Planner(#[from] PlannerError),

    /// Adaptive policy referenced an action outside the planner registry.
    #[error("scheduled action {action_id} is not registered")]
    Unregistered {
        /// Unknown action identity.
        action_id: String,
    },

    /// Immediate dispatch cannot prove that prerequisites have already run.
    #[error("scheduled action {action_id} has prerequisites and cannot be dispatched directly")]
    HasPrerequisites {
        /// Registered action identity.
        action_id: String,
    },

    /// The normal planner eligibility policy excluded the requested action.
    #[error("scheduled action {action_id} is not authorized: {reason:?}")]
    Excluded {
        /// Registered action identity.
        action_id: String,
        /// Exact planner exclusion that denied authority.
        reason: ExclusionReason,
    },
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

    /// Returns a registered action definition by stable identity.
    pub fn action(&self, action_id: &str) -> Option<&AttackAction> {
        self.actions.get(action_id)
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

    /// Produces a plan while excluding actions suppressed by adaptive policy.
    pub fn plan_with_suppressed(
        &self,
        knowledge: &KnowledgeBase,
        subject: &EntityId,
        context: PlanningContext,
        suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        self.plan_snapshot_with_suppressed(&snapshot, context, suppressed_actions)
    }

    /// Produces a plan from an explicit immutable snapshot.
    pub fn plan_snapshot(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_suppressed(snapshot, context, &BTreeSet::new())
    }

    /// Produces a plan from a snapshot and an explicit policy suppression set.
    pub fn plan_snapshot_with_suppressed(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_action_suppressions(
            snapshot,
            context,
            &ActionSuppressionContext::policy_only(suppressed_actions),
        )
    }

    /// Produces a plan distinguishing policy suppression from defense suppression.
    ///
    /// A defense-suppressed action is excluded with
    /// [`ExclusionReason::DefenseSuppressed`], never conflated with an adaptive
    /// or operator [`ExclusionReason::PolicySuppressed`]. A defense-suppressed
    /// action never becomes a plan step, so it never reaches an executor. The
    /// defense set filters the policy-authorized baseline and cannot refill
    /// budget with a candidate that baseline excluded.
    pub fn plan_snapshot_with_defense_suppressed(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        policy_suppressed_actions: &BTreeSet<String>,
        defense_suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_action_suppressions(
            snapshot,
            context,
            &ActionSuppressionContext::new(
                policy_suppressed_actions.clone(),
                defense_suppressed_actions.clone(),
            ),
        )
    }

    pub(crate) fn plan_snapshot_with_action_suppressions(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressions: &ActionSuppressionContext,
    ) -> Result<AttackPlan, PlannerError> {
        self.plan_snapshot_with_action_suppressions_and_baseline(snapshot, context, suppressions)
            .map(|(_, filtered)| filtered)
    }

    pub(crate) fn plan_snapshot_with_action_suppressions_and_baseline(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressions: &ActionSuppressionContext,
    ) -> Result<(AttackPlan, AttackPlan), PlannerError> {
        let baseline = self.plan_snapshot_with_policy_suppressed(
            snapshot,
            context,
            suppressions.policy_suppressed_actions(),
        )?;
        let filtered = baseline
            .clone()
            .into_defense_filtered(suppressions.defense_suppressed_actions());
        Ok((baseline, filtered))
    }

    fn plan_snapshot_with_policy_suppressed(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        policy_suppressed_actions: &BTreeSet<String>,
    ) -> Result<AttackPlan, PlannerError> {
        self.validate_dependencies()?;

        let mut eligible = BTreeMap::<String, EligibleCandidate>::new();
        let mut exclusions = BTreeMap::<String, ExclusionReason>::new();
        for action in self.actions.values() {
            let suppression = policy_suppressed_actions
                .contains(action.id())
                .then_some(ExclusionReason::PolicySuppressed);
            match evaluate_candidate(action, snapshot, context, suppression)? {
                Ok(candidate) => {
                    eligible.insert(action.id.clone(), candidate);
                },
                Err(reason) => {
                    exclusions.insert(action.id.clone(), reason);
                },
            }
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
            .map(|(position, id)| plan_step(position, &eligible[&id]))
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

    /// Re-applies planner authority to one registered action before immediate
    /// adaptive dispatch.
    ///
    /// Unlike normal planning this does not rank the action against unrelated
    /// candidates. It does validate the complete registered graph, then applies
    /// the same suppression, requirement, risk, confidence, verification-target,
    /// and minimum-utility checks as [`Self::plan_snapshot_with_suppressed`]. A
    /// direct adaptive dispatch cannot safely satisfy a prerequisite closure,
    /// because the session does not preserve proof that those actions completed;
    /// such actions therefore fail closed. The requested action's own cost must
    /// fit the complete planning budget.
    #[cfg(test)]
    pub(crate) fn authorize_scheduled_action(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        policy_suppressed_actions: &BTreeSet<String>,
        action_id: &str,
    ) -> Result<PlanStep, ScheduledActionAuthorizationError> {
        self.authorize_scheduled_action_with_context(
            snapshot,
            context,
            &ActionSuppressionContext::policy_only(policy_suppressed_actions),
            action_id,
        )
    }

    pub(crate) fn authorize_scheduled_action_with_context(
        &self,
        snapshot: &KnowledgeSnapshot,
        context: PlanningContext,
        suppressions: &ActionSuppressionContext,
        action_id: &str,
    ) -> Result<PlanStep, ScheduledActionAuthorizationError> {
        self.validate_dependencies()?;
        let action = self.actions.get(action_id).ok_or_else(|| {
            ScheduledActionAuthorizationError::Unregistered {
                action_id: action_id.to_owned(),
            }
        })?;
        let suppression = if suppressions
            .defense_suppressed_actions()
            .contains(action_id)
        {
            Some(ExclusionReason::DefenseSuppressed)
        } else if suppressions.policy_suppressed_actions().contains(action_id) {
            Some(ExclusionReason::PolicySuppressed)
        } else {
            None
        };
        let candidate = match evaluate_candidate(action, snapshot, context, suppression)? {
            Ok(candidate) => candidate,
            Err(reason) => {
                return Err(ScheduledActionAuthorizationError::Excluded {
                    action_id: action_id.to_owned(),
                    reason,
                })
            },
        };
        if !candidate.action.prerequisites.is_empty() {
            return Err(ScheduledActionAuthorizationError::HasPrerequisites {
                action_id: action_id.to_owned(),
            });
        }
        let required = u64::from(candidate.action.cost.units());
        if required > context.budget {
            return Err(ScheduledActionAuthorizationError::Excluded {
                action_id: action_id.to_owned(),
                reason: ExclusionReason::BudgetExceeded {
                    required,
                    remaining: context.budget,
                },
            });
        }
        Ok(plan_step(0, &candidate))
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

fn evaluate_candidate(
    action: &AttackAction,
    snapshot: &KnowledgeSnapshot,
    context: PlanningContext,
    suppression: Option<ExclusionReason>,
) -> Result<CandidateEligibility, PlannerError> {
    if let Some(reason) = suppression {
        return Ok(Err(reason));
    }
    let requirements = action.requirements.evaluate(snapshot)?;
    if !requirements.matched() {
        return Ok(Err(ExclusionReason::RequirementsNotMet));
    }
    if action.risk > context.maximum_risk {
        return Ok(Err(ExclusionReason::RiskLimitExceeded {
            actual: action.risk,
            maximum: context.maximum_risk,
        }));
    }
    let Some(hypothesis) = action.confidence_source.select(snapshot.hypotheses()) else {
        return Ok(Err(ExclusionReason::NoEligibleHypothesis));
    };
    let Some(verification_target) = action
        .verification_target
        .resolve(snapshot.hypotheses(), hypothesis.id())
    else {
        return Ok(Err(ExclusionReason::NoEligibleVerificationTarget));
    };
    let utility = UtilityBreakdown::calculate(
        action.gain,
        hypothesis.posterior(),
        context.business_value,
        action.cost,
        action.risk,
    );
    if utility.score < context.minimum_utility {
        return Ok(Err(ExclusionReason::BelowMinimumUtility {
            actual: utility.score,
            minimum: context.minimum_utility,
        }));
    }
    Ok(Ok(EligibleCandidate {
        action: action.clone(),
        confidence_hypothesis_id: hypothesis.id().to_owned(),
        verification_target,
        requirements,
        utility,
    }))
}

fn plan_step(position: usize, candidate: &EligibleCandidate) -> PlanStep {
    PlanStep {
        position,
        action_id: candidate.action.id.clone(),
        executor: candidate.action.executor.clone(),
        payload_strategy: candidate.action.payload_strategy.clone(),
        prerequisites: candidate.action.prerequisites.clone(),
        confidence_hypothesis_id: candidate.confidence_hypothesis_id.clone(),
        verification_target: candidate.verification_target.clone(),
        requirements: candidate.requirements.clone(),
        utility: candidate.utility,
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
        EvidenceCalibration, EvidenceSelector, ExperiencePolicy, ExperienceStore,
        HypothesisConclusion, KnowledgeLayer, ReasoningRule, RuleEngine,
    };
    use venom_core::{
        BayesianEvidence, ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, HypothesisState,
        KnowledgePredicate, Outcome, OutcomeStatus, VerificationStage,
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
    fn registration_order_cannot_change_dependency_or_suppression_semantics() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let actions = [
            action("root", 60, 10, 20, &[]),
            action("dependent", 90, 10, 20, &["root"]),
            action("independent", 70, 10, 20, &[]),
            action("knowledge-only", 50, 10, 20, &[])
                .with_verification_target(VerificationTarget::KnowledgeOnly),
        ];
        let mut forward = AttackPlanner::new();
        let mut reverse = AttackPlanner::new();
        for action in &actions {
            forward.register(action.clone()).unwrap();
        }
        for action in actions.iter().rev() {
            reverse.register(action.clone()).unwrap();
        }
        let suppressions = BTreeSet::from(["independent".to_owned()]);

        let forward_plan = forward
            .plan_with_suppressed(&knowledge, &subject(), context(100), &suppressions)
            .unwrap();
        let reverse_plan = reverse
            .plan_with_suppressed(&knowledge, &subject(), context(100), &suppressions)
            .unwrap();

        assert_eq!(forward_plan, reverse_plan);
        let positions: BTreeMap<_, _> = forward_plan
            .steps()
            .iter()
            .map(|step| (step.action_id(), step.position()))
            .collect();
        assert!(positions["root"] < positions["dependent"]);
        assert!(!positions.contains_key("independent"));
        assert_eq!(
            forward_plan
                .excluded()
                .iter()
                .find(|excluded| excluded.action_id() == "independent")
                .unwrap()
                .reason(),
            &ExclusionReason::PolicySuppressed
        );
    }

    #[test]
    fn defense_filter_is_exact_baseline_subsequence_without_budget_refill() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        for id in ["alpha", "beta", "gamma"] {
            planner.register(action(id, 80, 10, 20, &[])).unwrap();
        }
        let baseline = planner.plan_snapshot(&snapshot, context(20)).unwrap();
        assert_eq!(
            baseline
                .steps()
                .iter()
                .map(PlanStep::action_id)
                .collect::<Vec<_>>(),
            ["alpha", "beta"]
        );
        assert_eq!(baseline.excluded()[0].action_id(), "gamma");
        let expected_beta = baseline.steps()[1].clone();

        let budget_only_suppression = baseline
            .clone()
            .into_defense_filtered(&BTreeSet::from(["gamma".to_owned()]));
        assert_eq!(budget_only_suppression, baseline);
        assert_eq!(
            serde_json::to_vec(&budget_only_suppression).unwrap(),
            serde_json::to_vec(&baseline).unwrap()
        );

        let suppressions =
            ActionSuppressionContext::new(BTreeSet::new(), BTreeSet::from(["alpha".to_owned()]));
        let filtered = planner
            .plan_snapshot_with_action_suppressions(&snapshot, context(20), &suppressions)
            .unwrap();

        assert_eq!(
            filtered
                .steps()
                .iter()
                .map(PlanStep::action_id)
                .collect::<Vec<_>>(),
            ["beta"]
        );
        assert_eq!(filtered.total_cost(), 10);
        assert_eq!(filtered.steps()[0].position(), 0);
        assert_eq!(filtered.steps()[0].executor(), expected_beta.executor());
        assert_eq!(filtered.steps()[0].utility(), expected_beta.utility());
        assert_eq!(
            filtered.steps()[0].requirements(),
            expected_beta.requirements()
        );
        assert!(filtered
            .excluded()
            .iter()
            .any(|entry| entry.action_id() == "alpha"
                && entry.reason() == &ExclusionReason::DefenseSuppressed));
        assert!(filtered
            .excluded()
            .iter()
            .any(|entry| entry.action_id() == "gamma"
                && matches!(entry.reason(), ExclusionReason::BudgetExceeded { .. })));
    }

    #[test]
    fn defense_filter_cascades_dependencies_and_preserves_retained_metadata() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let strategy = PayloadStrategyRef::new("independent.strategy", 4).unwrap();
        let mut planner = AttackPlanner::new();
        planner.register(action("root", 80, 10, 20, &[])).unwrap();
        planner
            .register(action("dependent", 90, 10, 20, &["root"]))
            .unwrap();
        planner
            .register(
                action("independent", 70, 10, 20, &[]).with_payload_strategy(strategy.clone()),
            )
            .unwrap();
        let baseline = planner.plan_snapshot(&snapshot, context(100)).unwrap();
        let expected = baseline
            .steps()
            .iter()
            .find(|step| step.action_id() == "independent")
            .unwrap()
            .clone();

        let filtered = baseline
            .clone()
            .into_defense_filtered(&BTreeSet::from(["root".to_owned()]));

        assert_eq!(
            filtered
                .steps()
                .iter()
                .map(PlanStep::action_id)
                .collect::<Vec<_>>(),
            ["independent"]
        );
        let retained = &filtered.steps()[0];
        assert_eq!(retained.executor(), expected.executor());
        assert_eq!(retained.payload_strategy(), Some(&strategy));
        assert_eq!(retained.prerequisites(), expected.prerequisites());
        assert_eq!(
            retained.confidence_hypothesis_id(),
            expected.confidence_hypothesis_id()
        );
        assert_eq!(
            retained.verification_target(),
            expected.verification_target()
        );
        assert_eq!(retained.requirements(), expected.requirements());
        assert_eq!(retained.utility(), expected.utility());
        assert!(filtered.excluded().iter().any(|entry| {
            entry.action_id() == "dependent"
                && entry.reason()
                    == &ExclusionReason::DependencyUnavailable {
                        prerequisite: "root".to_owned(),
                    }
        }));
    }

    #[test]
    fn empty_defense_context_is_exact_planner_compatibility_path() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();

        let baseline = planner.plan_snapshot(&snapshot, context(100)).unwrap();
        let compatibility = planner
            .plan_snapshot_with_action_suppressions(
                &snapshot,
                context(100),
                &ActionSuppressionContext::default(),
            )
            .unwrap();

        assert_eq!(compatibility, baseline);
        assert_eq!(
            serde_json::to_vec(&compatibility).unwrap(),
            serde_json::to_vec(&baseline).unwrap()
        );
    }

    #[test]
    fn defense_precedes_policy_for_scheduled_authorization() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("direct", 80, 10, 20, &[])).unwrap();
        let both = BTreeSet::from(["direct".to_owned()]);

        let policy_baseline = planner
            .plan_snapshot_with_defense_suppressed(&snapshot, context(100), &both, &BTreeSet::new())
            .unwrap();
        let defense_filtered = planner
            .plan_snapshot_with_defense_suppressed(&snapshot, context(100), &both, &both)
            .unwrap();
        assert_eq!(defense_filtered, policy_baseline);
        assert_eq!(
            serde_json::to_vec(&defense_filtered).unwrap(),
            serde_json::to_vec(&policy_baseline).unwrap()
        );
        assert_eq!(
            defense_filtered.excluded()[0].reason(),
            &ExclusionReason::PolicySuppressed
        );

        let denied = planner
            .authorize_scheduled_action_with_context(
                &snapshot,
                context(100),
                &ActionSuppressionContext::new(both.clone(), both),
                "direct",
            )
            .unwrap_err();

        assert!(matches!(
            denied,
            ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::DefenseSuppressed,
                ..
            }
        ));
    }

    #[test]
    fn scheduled_action_authorization_reuses_exact_planner_eligibility_and_policy() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let selected = action("direct", 80, 10, 20, &[])
            .with_payload_strategy(PayloadStrategyRef::new("direct.strategy", 2).unwrap())
            .with_verification_target(VerificationTarget::KnowledgeOnly);
        let mut planner = AttackPlanner::new();
        planner.register(selected).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let exact_context = PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            10,
            RiskScore::from_percent(20).unwrap(),
        );

        let planned = planner.plan_snapshot(&snapshot, exact_context).unwrap();
        let authorized = planner
            .authorize_scheduled_action(&snapshot, exact_context, &BTreeSet::new(), "direct")
            .unwrap();

        assert_eq!(&authorized, &planned.steps()[0]);
        assert_eq!(authorized.executor(), "plugin.direct");
        assert_eq!(
            authorized.payload_strategy(),
            Some(&PayloadStrategyRef::new("direct.strategy", 2).unwrap())
        );
        assert_eq!(
            authorized.verification_target(),
            &ResolvedVerificationTarget::KnowledgeOnly
        );
        assert!(!authorized
            .verification_target()
            .applies_hypothesis_transition());
    }

    #[test]
    fn minimum_utility_exact_boundary_remains_eligible() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("direct", 80, 10, 20, &[])).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let base_context = context(100);
        let score = planner
            .authorize_scheduled_action(&snapshot, base_context, &BTreeSet::new(), "direct")
            .unwrap()
            .utility()
            .score();

        planner
            .authorize_scheduled_action(
                &snapshot,
                base_context.with_minimum_utility(score),
                &BTreeSet::new(),
                "direct",
            )
            .unwrap();
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                base_context.with_minimum_utility(UtilityScore::from_units(
                    score.units().checked_add(1).unwrap(),
                )),
                &BTreeSet::new(),
                "direct",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::BelowMinimumUtility { .. },
                ..
            })
        ));
    }

    #[test]
    fn scheduled_action_authorization_enforces_suppression_budget_and_risk_boundaries() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("direct", 80, 10, 20, &[])).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let exact_context = PlanningContext::new(
            BenefitScore::from_percent(90).unwrap(),
            10,
            RiskScore::from_percent(20).unwrap(),
        );

        planner
            .authorize_scheduled_action(&snapshot, exact_context, &BTreeSet::new(), "direct")
            .unwrap();
        let suppressed = planner
            .authorize_scheduled_action(
                &snapshot,
                exact_context,
                &BTreeSet::from(["direct".to_owned()]),
                "direct",
            )
            .unwrap_err();
        assert!(matches!(
            suppressed,
            ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::PolicySuppressed,
            } if action_id == "direct"
        ));

        let budget = planner
            .authorize_scheduled_action(
                &snapshot,
                PlanningContext::new(
                    BenefitScore::from_percent(90).unwrap(),
                    9,
                    RiskScore::from_percent(20).unwrap(),
                ),
                &BTreeSet::new(),
                "direct",
            )
            .unwrap_err();
        assert!(matches!(
            budget,
            ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::BudgetExceeded {
                    required: 10,
                    remaining: 9,
                },
            } if action_id == "direct"
        ));

        let risk = planner
            .authorize_scheduled_action(
                &snapshot,
                PlanningContext::new(
                    BenefitScore::from_percent(90).unwrap(),
                    10,
                    RiskScore::from_percent(19).unwrap(),
                ),
                &BTreeSet::new(),
                "direct",
            )
            .unwrap_err();
        assert!(matches!(
            risk,
            ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::RiskLimitExceeded { .. },
            } if action_id == "direct"
        ));
    }

    #[test]
    fn scheduled_action_authorization_fails_closed_on_registry_and_dependency_graphs() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
        let mut planner = AttackPlanner::new();
        planner.register(action("base", 40, 5, 10, &[])).unwrap();
        planner
            .register(action("dependent", 80, 5, 10, &["base"]))
            .unwrap();

        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(10),
                &BTreeSet::new(),
                "unknown",
            ),
            Err(ScheduledActionAuthorizationError::Unregistered { action_id })
                if action_id == "unknown"
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(10),
                &BTreeSet::new(),
                "dependent",
            ),
            Err(ScheduledActionAuthorizationError::HasPrerequisites { action_id })
                if action_id == "dependent"
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(10),
                &BTreeSet::from(["dependent".to_owned()]),
                "dependent",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                action_id,
                reason: ExclusionReason::PolicySuppressed,
            }) if action_id == "dependent"
        ));

        let mut invalid = AttackPlanner::new();
        invalid
            .register(action("invalid", 80, 5, 10, &["missing"]))
            .unwrap();
        invalid.register(action("direct", 80, 5, 10, &[])).unwrap();
        assert!(matches!(
            invalid.authorize_scheduled_action(&snapshot, context(10), &BTreeSet::new(), "direct",),
            Err(ScheduledActionAuthorizationError::Planner(
                PlannerError::UnknownPrerequisite { .. }
            ))
        ));
    }

    #[test]
    fn scheduled_action_authorization_reuses_requirement_target_and_utility_checks() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let snapshot = knowledge.snapshot_for_subject(&subject());
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
        let missing_motivation = AttackAction::new(
            "missing-motivation",
            "plugin.missing-motivation",
            Expression::equals(KnowledgeLayer::Hypothesis, stack_predicate(), stack_value()),
            HypothesisSelector::new(
                KnowledgePredicate::new("auth", "missing-motivation").unwrap(),
                EvidenceValue::Boolean(true),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Any,
            ),
            BenefitScore::from_percent(80).unwrap(),
            ActionCost::new(10).unwrap(),
            RiskScore::from_percent(10).unwrap(),
            BTreeSet::new(),
        )
        .unwrap();
        let missing_target = action("missing-target", 80, 10, 10, &[]).with_verification_target(
            VerificationTarget::Distinct(HypothesisSelector::new(
                KnowledgePredicate::new("auth", "mechanism").unwrap(),
                EvidenceValue::Text("missing".to_owned()),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Any,
            )),
        );
        let mut planner = AttackPlanner::new();
        planner.register(unmet).unwrap();
        planner.register(missing_motivation).unwrap();
        planner.register(missing_target).unwrap();
        planner
            .register(action("low-utility", 80, 10, 10, &[]))
            .unwrap();

        assert!(matches!(
            planner.authorize_scheduled_action(&snapshot, context(100), &BTreeSet::new(), "unmet",),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::RequirementsNotMet,
                ..
            })
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(100),
                &BTreeSet::new(),
                "missing-motivation",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::NoEligibleHypothesis,
                ..
            })
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(100),
                &BTreeSet::new(),
                "missing-target",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::NoEligibleVerificationTarget,
                ..
            })
        ));
        assert!(matches!(
            planner.authorize_scheduled_action(
                &snapshot,
                context(100).with_minimum_utility(UtilityScore::from_units(u64::MAX)),
                &BTreeSet::new(),
                "low-utility",
            ),
            Err(ScheduledActionAuthorizationError::Excluded {
                reason: ExclusionReason::BelowMinimumUtility { .. },
                ..
            })
        ));
    }

    #[test]
    fn replanning_excludes_policy_suppressed_actions() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let mut planner = AttackPlanner::new();
        planner.register(action("zeta", 80, 10, 20, &[])).unwrap();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();

        let plan = planner
            .plan_with_suppressed(
                &knowledge,
                &subject(),
                context(100),
                &BTreeSet::from(["alpha".into()]),
            )
            .unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "zeta");
        assert_eq!(plan.excluded()[0].action_id(), "alpha");
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::PolicySuppressed
        );
    }

    #[test]
    fn planner_consumes_suppressions_derived_from_experience() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let evidence_id = knowledge.snapshot_for_subject(&subject()).evidence()[0]
            .id()
            .clone();
        let mut experience = ExperienceStore::new();
        for attempt in 0..10 {
            experience
                .observe(
                    Outcome::verified(
                        format!("case:alpha:{attempt}"),
                        subject(),
                        "alpha",
                        "hypothesis:laravel",
                        "verify.alpha",
                        VerificationStage::Active,
                        OutcomeStatus::ConfirmedNegative,
                        Probability::from_percent(80).unwrap(),
                        "active negative control rejected alpha",
                        BTreeSet::from([evidence_id.clone()]),
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        let suppressed = experience.suppressed_actions(&subject(), ExperiencePolicy::default());
        let mut planner = AttackPlanner::new();
        planner.register(action("alpha", 80, 10, 20, &[])).unwrap();
        planner.register(action("zeta", 80, 10, 20, &[])).unwrap();

        let plan = planner
            .plan_with_suppressed(&knowledge, &subject(), context(100), &suppressed)
            .unwrap();

        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].action_id(), "zeta");
        assert_eq!(plan.excluded()[0].action_id(), "alpha");
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::PolicySuppressed
        );
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
        assert!(encoded.get("verification_target").is_none());
        assert!(encoded.get("payload_claim_policy_guard").is_none());
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
        assert!(matches!(
            planner.register(
                action
                    .clone()
                    .with_verification_target(VerificationTarget::KnowledgeOnly)
            ),
            Err(PlannerError::ActionIdentityConflict { .. })
        ));
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
    fn verification_targets_round_trip_and_reserved_typos_fail_closed() {
        let knowledge_only = action("form.discover", 80, 10, 20, &[])
            .with_verification_target(VerificationTarget::KnowledgeOnly);
        let encoded = serde_json::to_value(&knowledge_only).unwrap();
        assert_eq!(encoded["verification_target"], "knowledge_only");
        assert_eq!(encoded["payload_claim_policy_guard"], true);
        let mut unguarded = encoded.clone();
        unguarded
            .as_object_mut()
            .unwrap()
            .remove("payload_claim_policy_guard");
        assert!(serde_json::from_value::<AttackAction>(unguarded).is_err());
        assert_eq!(
            serde_json::from_value::<AttackAction>(encoded).unwrap(),
            knowledge_only
        );

        let distinct_selector = HypothesisSelector::new(
            KnowledgePredicate::new("auth", "mechanism").unwrap(),
            EvidenceValue::Text("http-basic".to_owned()),
            Probability::from_percent(60).unwrap(),
            RequiredStrength::Any,
        );
        let distinct = action("auth.verify", 80, 10, 20, &[])
            .with_verification_target(VerificationTarget::Distinct(distinct_selector));
        assert_eq!(
            serde_json::from_value::<AttackAction>(serde_json::to_value(&distinct).unwrap())
                .unwrap(),
            distinct
        );

        let mut misspelled = serde_json::to_value(action("typo", 80, 10, 20, &[])).unwrap();
        misspelled["verification_targte"] = serde_json::json!("knowledge_only");
        assert!(serde_json::from_value::<AttackAction>(misspelled).is_err());
    }

    #[test]
    fn planner_separates_confidence_from_resolved_verification_target() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let target_predicate = KnowledgePredicate::new("auth", "mechanism").unwrap();
        let target_value = EvidenceValue::Text("http-basic".to_owned());
        let mut target = Hypothesis::with_id(
            "hypothesis:http-basic",
            subject(),
            target_predicate.clone(),
            target_value.clone(),
            Probability::from_percent(80).unwrap(),
        )
        .unwrap();
        target.set_strength(HypothesisStrength::Strong);
        target.set_state(HypothesisState::Supported);
        knowledge.upsert_hypothesis(target).unwrap();

        let mut planner = AttackPlanner::new();
        planner
            .register(action("motivation", 80, 10, 20, &[]))
            .unwrap();
        planner
            .register(
                action("distinct", 80, 10, 20, &[]).with_verification_target(
                    VerificationTarget::Distinct(HypothesisSelector::new(
                        target_predicate,
                        target_value,
                        Probability::from_percent(60).unwrap(),
                        RequiredStrength::Any,
                    )),
                ),
            )
            .unwrap();
        planner
            .register(
                action("knowledge-only", 80, 10, 20, &[])
                    .with_verification_target(VerificationTarget::KnowledgeOnly),
            )
            .unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        let step = |action_id| {
            plan.steps()
                .iter()
                .find(|step| step.action_id() == action_id)
                .unwrap()
        };

        for action_id in ["motivation", "distinct", "knowledge-only"] {
            assert_eq!(
                step(action_id).confidence_hypothesis_id(),
                "hypothesis:laravel"
            );
        }
        assert_eq!(
            step("motivation").verification_target().hypothesis_id(),
            Some("hypothesis:laravel")
        );
        assert_eq!(
            step("distinct").verification_target().hypothesis_id(),
            Some("hypothesis:http-basic")
        );
        assert_eq!(
            step("knowledge-only").verification_target(),
            &ResolvedVerificationTarget::KnowledgeOnly
        );
        assert!(!step("knowledge-only")
            .verification_target()
            .applies_hypothesis_transition());
    }

    #[test]
    fn missing_distinct_verification_target_is_excluded_fail_closed() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let distinct_action = action("distinct", 80, 10, 20, &[]).with_verification_target(
            VerificationTarget::Distinct(HypothesisSelector::new(
                KnowledgePredicate::new("auth", "mechanism").unwrap(),
                EvidenceValue::Text("http-basic".to_owned()),
                Probability::from_percent(60).unwrap(),
                RequiredStrength::Any,
            )),
        );
        let mut planner = AttackPlanner::new();
        planner.register(distinct_action).unwrap();

        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();

        assert!(plan.steps().is_empty());
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::NoEligibleVerificationTarget
        );

        let same_as_motivation = action("same-target", 80, 10, 20, &[]).with_verification_target(
            VerificationTarget::Distinct(HypothesisSelector::new(
                stack_predicate(),
                stack_value(),
                Probability::from_percent(50).unwrap(),
                RequiredStrength::Strong,
            )),
        );
        let mut planner = AttackPlanner::new();
        planner.register(same_as_motivation).unwrap();
        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        assert!(plan.steps().is_empty());
        assert_eq!(
            plan.excluded()[0].reason(),
            &ExclusionReason::NoEligibleVerificationTarget
        );
    }

    #[test]
    fn planner_carries_exact_strategy_revision_without_exposing_payloads() {
        let knowledge = knowledge_with_hypothesis((80, 20));
        let strategy = PayloadStrategyRef::new("visibility.control-pair", 2).unwrap();
        let selected =
            action("visibility.compare", 80, 10, 20, &[]).with_payload_strategy(strategy.clone());
        let legacy = action("legacy.observe", 70, 10, 20, &[]);

        let legacy_wire = serde_json::to_value(&legacy).unwrap();
        assert!(legacy_wire.get("payload_strategy").is_none());
        assert!(serde_json::from_value::<AttackAction>(legacy_wire)
            .unwrap()
            .payload_strategy()
            .is_none());
        let mut misspelled = serde_json::to_value(&legacy).unwrap();
        misspelled["payload_stratgey"] = serde_json::json!({
            "id": "visibility.control-pair",
            "revision": 1
        });
        assert!(serde_json::from_value::<AttackAction>(misspelled).is_err());
        let mut extended = serde_json::to_value(&legacy).unwrap();
        extended["future_extension"] = serde_json::json!({"accepted": true});
        assert!(serde_json::from_value::<AttackAction>(extended).is_ok());

        let selected_wire = serde_json::to_value(&selected).unwrap();
        assert_eq!(selected_wire["payload_strategy"]["revision"], 2);
        assert_eq!(
            serde_json::from_value::<AttackAction>(selected_wire).unwrap(),
            selected
        );

        let mut planner = AttackPlanner::new();
        planner.register(selected.clone()).unwrap();
        let plan = planner.plan(&knowledge, &subject(), context(100)).unwrap();
        assert_eq!(plan.steps()[0].payload_strategy(), Some(&strategy));
        assert_eq!(
            planner
                .action("visibility.compare")
                .and_then(AttackAction::payload_strategy),
            Some(&strategy)
        );

        let conflicting = action("visibility.compare", 80, 10, 20, &[])
            .with_payload_strategy(PayloadStrategyRef::new("visibility.control-pair", 3).unwrap());
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
