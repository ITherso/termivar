use serde::{Deserialize, Deserializer, Serialize};
use std::num::NonZeroU32;
use termivar_core::{
    EvidenceValue, HypothesisState, HypothesisStrength, KnowledgePredicate, Probability,
};

use crate::rules::{
    expression::{
        evidence_value_texts, is_false, text_contains, text_list_contains_exact, Expression,
        RequiredNullable,
    },
    non_empty, RuleEngineError,
};

/// Selects raw evidence for one Bayesian calibration.
///
/// The wire contract requires an explicit nullable `value` field. Canonical
/// constrained selectors also carry a compatibility guard, so losing one text
/// matcher cannot silently reconstruct the selector as predicate existence.
/// Guardless constrained selectors emitted by earlier Venom releases remain
/// readable and are canonicalized when serialized again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceSelector {
    predicate: KnowledgePredicate,
    value: Option<EvidenceValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_contains_ascii_case_insensitive: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_list_contains_exact: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    matcher_policy_guard: bool,
}

impl EvidenceSelector {
    /// Selects evidence with an exact predicate and value.
    pub fn equals(predicate: KnowledgePredicate, value: EvidenceValue) -> Self {
        Self {
            predicate,
            value: Some(value),
            text_contains_ascii_case_insensitive: None,
            text_list_contains_exact: None,
            matcher_policy_guard: true,
        }
    }

    /// Selects any evidence with this predicate.
    pub fn exists(predicate: KnowledgePredicate) -> Self {
        Self {
            predicate,
            value: None,
            text_contains_ascii_case_insensitive: None,
            text_list_contains_exact: None,
            matcher_policy_guard: false,
        }
    }

    /// Selects text evidence containing a locale-independent protocol token.
    pub fn text_contains_ascii_case_insensitive(
        predicate: KnowledgePredicate,
        needle: impl Into<String>,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self {
            predicate,
            value: None,
            text_contains_ascii_case_insensitive: Some(non_empty(
                needle,
                "evidence-selector text needle",
            )?),
            text_list_contains_exact: None,
            matcher_policy_guard: true,
        })
    }

    /// Selects evidence whose [`EvidenceValue::TextList`] contains an exact
    /// element. This is the calibration companion to
    /// [`Expression::text_list_contains_exact`]: it attributes the likelihood
    /// only to a record carrying the exact element, never a substring match and
    /// never a scalar text value — so convention provenance stays truthful.
    pub fn text_list_contains_exact(
        predicate: KnowledgePredicate,
        value: impl Into<String>,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self {
            predicate,
            value: None,
            text_contains_ascii_case_insensitive: None,
            text_list_contains_exact: Some(non_empty(
                value,
                "evidence-selector text-list exact value",
            )?),
            matcher_policy_guard: true,
        })
    }

    /// Returns the selected predicate.
    pub fn predicate(&self) -> &KnowledgePredicate {
        &self.predicate
    }

    /// Returns an optional exact-value constraint.
    pub fn value(&self) -> Option<&EvidenceValue> {
        self.value.as_ref()
    }

    /// Returns the optional ASCII case-insensitive text constraint.
    pub fn text_needle(&self) -> Option<&str> {
        self.text_contains_ascii_case_insensitive.as_deref()
    }

    /// Returns the optional exact text-list membership constraint.
    pub fn text_list_exact_value(&self) -> Option<&str> {
        self.text_list_contains_exact.as_deref()
    }

    pub(super) fn matches(&self, evidence: &termivar_core::Evidence) -> bool {
        evidence.predicate() == &self.predicate
            && self
                .value
                .as_ref()
                .is_none_or(|expected| evidence.value() == expected)
            && self
                .text_contains_ascii_case_insensitive
                .as_ref()
                .is_none_or(|needle| {
                    evidence_value_texts(evidence.value())
                        .any(|text| text_contains(text, needle, true))
                })
            && self
                .text_list_contains_exact
                .as_ref()
                .is_none_or(|value| text_list_contains_exact(evidence.value(), value))
    }
}

impl<'de> Deserialize<'de> for EvidenceSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireSelector {
            predicate: KnowledgePredicate,
            #[serde(default)]
            value: RequiredNullable<EvidenceValue>,
            #[serde(default)]
            text_contains_ascii_case_insensitive: Option<String>,
            #[serde(default)]
            text_list_contains_exact: Option<String>,
            #[serde(default)]
            matcher_policy_guard: Option<bool>,
        }

        let wire = WireSelector::deserialize(deserializer)?;
        if !wire.value.is_present() {
            return Err(serde::de::Error::custom(
                "evidence selector value field must be present; use null for predicate existence",
            ));
        }
        let value = wire.value.into_inner();
        let matchers = usize::from(value.is_some())
            + usize::from(wire.text_contains_ascii_case_insensitive.is_some())
            + usize::from(wire.text_list_contains_exact.is_some());
        if matchers > 1 {
            return Err(serde::de::Error::custom(
                "evidence selector cannot combine exact, text, and text-list matching",
            ));
        }
        if wire
            .matcher_policy_guard
            .is_some_and(|guard| !guard || matchers != 1)
        {
            return Err(serde::de::Error::custom(
                "evidence selector matcher compatibility guard is inconsistent",
            ));
        }
        if wire
            .text_contains_ascii_case_insensitive
            .as_ref()
            .is_some_and(|needle| needle.trim().is_empty())
        {
            return Err(serde::de::Error::custom(RuleEngineError::EmptyValue {
                field: "evidence-selector text needle",
            }));
        }
        if wire
            .text_list_contains_exact
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(serde::de::Error::custom(RuleEngineError::EmptyValue {
                field: "evidence-selector text-list exact value",
            }));
        }
        Ok(Self {
            predicate: wire.predicate,
            value,
            text_contains_ascii_case_insensitive: wire.text_contains_ascii_case_insensitive,
            text_list_contains_exact: wire.text_list_contains_exact,
            matcher_policy_guard: matchers == 1,
        })
    }
}

/// How matching observations contribute to one Bayesian calibration.
///
/// The default preserves independent contribution semantics. A bounded policy
/// is explicit and local to one calibration; it never infers independence from
/// producer names or other forgeable provenance strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum EvidenceAggregation {
    /// Every distinct matching evidence ID contributes once.
    #[default]
    Independent,
    /// Only the strongest `limit` matches contribute.
    ///
    /// Selection is deterministic: reliability, then observation time, then
    /// evidence ID. The expression trace still retains every candidate match.
    MaxContributions {
        /// Non-zero maximum number of observations.
        limit: NonZeroU32,
    },
}

impl EvidenceAggregation {
    /// Creates an explicit non-zero contribution cap.
    pub fn max_contributions(limit: u32) -> Result<Self, RuleEngineError> {
        Ok(Self::MaxContributions {
            limit: NonZeroU32::new(limit).ok_or(RuleEngineError::InvalidAggregationLimit)?,
        })
    }

    pub(super) fn limit(self) -> Option<usize> {
        match self {
            Self::Independent => None,
            Self::MaxContributions { limit } => {
                Some(usize::try_from(limit.get()).unwrap_or(usize::MAX))
            },
        }
    }

    fn is_independent(&self) -> bool {
        matches!(self, Self::Independent)
    }
}

/// Bayesian likelihoods assigned to evidence selected by a rule.
///
/// Missing aggregation remains the historical independent policy. Canonical
/// bounded calibrations carry a compatibility guard; losing their aggregation
/// field therefore fails closed instead of removing the contribution cap.
/// Guardless bounded calibrations emitted by earlier releases remain readable
/// and are canonicalized when serialized again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceCalibration {
    pub(super) selector: EvidenceSelector,
    pub(super) likelihood_if_true: Probability,
    pub(super) likelihood_if_false: Probability,
    pub(super) rationale: String,
    #[serde(default, skip_serializing_if = "EvidenceAggregation::is_independent")]
    pub(super) aggregation: EvidenceAggregation,
    #[serde(default, skip_serializing_if = "is_false")]
    aggregation_policy_guard: bool,
}

impl EvidenceCalibration {
    /// Creates a calibrated evidence binding with an explanation.
    pub fn new(
        selector: EvidenceSelector,
        likelihood_if_true: Probability,
        likelihood_if_false: Probability,
        rationale: impl Into<String>,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self {
            selector,
            likelihood_if_true,
            likelihood_if_false,
            rationale: non_empty(rationale, "evidence calibration rationale")?,
            aggregation: EvidenceAggregation::Independent,
            aggregation_policy_guard: false,
        })
    }

    /// Applies an explicit contribution policy to this calibration.
    pub fn with_aggregation(mut self, aggregation: EvidenceAggregation) -> Self {
        self.aggregation_policy_guard = !aggregation.is_independent();
        self.aggregation = aggregation;
        self
    }

    /// Returns the raw-evidence selector.
    pub fn selector(&self) -> &EvidenceSelector {
        &self.selector
    }

    /// Returns `P(E|H)`.
    pub fn likelihood_if_true(&self) -> Probability {
        self.likelihood_if_true
    }

    /// Returns `P(E|not H)`.
    pub fn likelihood_if_false(&self) -> Probability {
        self.likelihood_if_false
    }

    /// Returns the calibration explanation.
    pub fn rationale(&self) -> &str {
        &self.rationale
    }

    /// Returns how repeated selector matches contribute to the posterior.
    pub const fn aggregation(&self) -> EvidenceAggregation {
        self.aggregation
    }
}

impl<'de> Deserialize<'de> for EvidenceCalibration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireCalibration {
            selector: EvidenceSelector,
            likelihood_if_true: Probability,
            likelihood_if_false: Probability,
            rationale: String,
            #[serde(default)]
            aggregation: EvidenceAggregation,
            #[serde(default)]
            aggregation_policy_guard: Option<bool>,
        }

        let wire = WireCalibration::deserialize(deserializer)?;
        let bounded = !wire.aggregation.is_independent();
        if wire
            .aggregation_policy_guard
            .is_some_and(|guard| !guard || !bounded)
        {
            return Err(serde::de::Error::custom(
                "evidence aggregation compatibility guard is inconsistent",
            ));
        }
        Self::new(
            wire.selector,
            wire.likelihood_if_true,
            wire.likelihood_if_false,
            wire.rationale,
        )
        .map(|calibration| calibration.with_aggregation(wire.aggregation))
        .map_err(serde::de::Error::custom)
    }
}

/// Data needed to materialize one Bayesian hypothesis after a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HypothesisConclusion {
    pub(super) predicate: KnowledgePredicate,
    pub(super) value: EvidenceValue,
    pub(super) prior: Probability,
    pub(super) strength: HypothesisStrength,
    pub(super) state: HypothesisState,
    pub(super) calibrations: Vec<EvidenceCalibration>,
}

impl HypothesisConclusion {
    /// Creates a conclusion backed by one or more calibrated observations.
    pub fn new(
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        prior: Probability,
        strength: HypothesisStrength,
        state: HypothesisState,
        calibrations: Vec<EvidenceCalibration>,
    ) -> Result<Self, RuleEngineError> {
        if calibrations.is_empty() {
            return Err(RuleEngineError::EmptyCalibrations);
        }
        if matches!(
            state,
            HypothesisState::Confirmed | HypothesisState::Rejected
        ) {
            return Err(RuleEngineError::VerifierOnlyState { state });
        }
        Ok(Self {
            predicate,
            value,
            prior,
            strength,
            state,
            calibrations,
        })
    }

    /// Returns the conclusion predicate.
    pub fn predicate(&self) -> &KnowledgePredicate {
        &self.predicate
    }

    /// Returns the conclusion value.
    pub fn value(&self) -> &EvidenceValue {
        &self.value
    }

    /// Returns the calibrated prior.
    pub fn prior(&self) -> Probability {
        self.prior
    }

    /// Returns the rule-assigned evidence strength.
    pub fn strength(&self) -> HypothesisStrength {
        self.strength
    }

    /// Returns the non-verifier lifecycle state.
    pub fn state(&self) -> HypothesisState {
        self.state
    }

    /// Returns evidence calibrations in declared rule order.
    pub fn calibrations(&self) -> &[EvidenceCalibration] {
        &self.calibrations
    }
}

impl<'de> Deserialize<'de> for HypothesisConclusion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireConclusion {
            predicate: KnowledgePredicate,
            value: EvidenceValue,
            prior: Probability,
            strength: HypothesisStrength,
            state: HypothesisState,
            calibrations: Vec<EvidenceCalibration>,
        }

        let wire = WireConclusion::deserialize(deserializer)?;
        Self::new(
            wire.predicate,
            wire.value,
            wire.prior,
            wire.strength,
            wire.state,
            wire.calibrations,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Stable declarative rule from an expression to a Bayesian conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReasoningRule {
    pub(super) id: String,
    pub(super) condition: Expression,
    pub(super) conclusion: HypothesisConclusion,
}

impl ReasoningRule {
    /// Creates a rule with a stable, non-empty identity.
    pub fn new(
        id: impl Into<String>,
        condition: Expression,
        conclusion: HypothesisConclusion,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self {
            id: non_empty(id, "rule id")?,
            condition,
            conclusion,
        })
    }

    /// Returns the stable rule identity.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the declarative condition.
    pub fn condition(&self) -> &Expression {
        &self.condition
    }

    /// Returns the Bayesian conclusion template.
    pub fn conclusion(&self) -> &HypothesisConclusion {
        &self.conclusion
    }
}

impl<'de> Deserialize<'de> for ReasoningRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRule {
            id: String,
            condition: Expression,
            conclusion: HypothesisConclusion,
        }

        let wire = WireRule::deserialize(deserializer)?;
        Self::new(wire.id, wire.condition, wire.conclusion).map_err(serde::de::Error::custom)
    }
}

/// Result of registering a rule identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RuleWrite {
    /// A new rule was registered.
    Inserted,
    /// The identical rule was already registered.
    Unchanged,
}
