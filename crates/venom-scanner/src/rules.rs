//! Deterministic expression evaluation and Bayesian reasoning rules.
//!
//! Rules consume an immutable [`KnowledgeSnapshot`]. They never execute
//! plugins, schedule scans, or mutate evidence. A matched rule may materialize
//! one stable, evidence-backed [`Hypothesis`].

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{
    BayesianEvidence, ConceptId, EvidenceId, EvidenceValue, Hypothesis, HypothesisState,
    HypothesisStrength, KnowledgePredicate, OntologyError, Probability, ReasoningModelError,
    RelationTypeId,
};

use crate::knowledge::{KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite};

/// Errors raised while validating or evaluating deterministic rules.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuleEngineError {
    /// A required rule identifier or explanation was empty.
    #[error("{field} must not be empty")]
    EmptyValue { field: &'static str },

    /// A logical group did not contain any child expression.
    #[error("{operator} expression must contain at least one child")]
    EmptyExpression { operator: &'static str },

    /// A hypothesis conclusion did not define any evidence calibration.
    #[error("hypothesis conclusion must contain at least one evidence calibration")]
    EmptyCalibrations,

    /// A rule attempted to assign a state reserved for a verifier.
    #[error("hypothesis state {state:?} can only be assigned by a verifier")]
    VerifierOnlyState { state: HypothesisState },

    /// A rule identity was reused with different semantics.
    #[error("rule identity {id} already has a different definition")]
    RuleIdentityConflict { id: String },

    /// A matched rule could not bind any contributing evidence.
    #[error("matched rule {rule_id} has no calibrated contributing evidence")]
    MissingCalibratedEvidence { rule_id: String },

    /// Two calibrations assigned different likelihoods to one observation.
    #[error("rule {rule_id} assigns ambiguous calibration to evidence {evidence_id}")]
    AmbiguousEvidenceCalibration {
        /// Rule containing the conflicting calibration.
        rule_id: String,
        /// Evidence that matched more than one incompatible selector.
        evidence_id: EvidenceId,
    },

    /// Ontology evaluation failed.
    #[error(transparent)]
    Ontology(#[from] OntologyError),

    /// A reasoning-domain invariant failed.
    #[error(transparent)]
    Reasoning(#[from] ReasoningModelError),

    /// A materialized hypothesis conflicted with stored knowledge.
    #[error(transparent)]
    Knowledge(#[from] KnowledgeBaseError),
}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, RuleEngineError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(RuleEngineError::EmptyValue { field });
    }
    Ok(value)
}

/// Knowledge record layer queried by a claim expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KnowledgeLayer {
    /// Immutable observations from the evidence engine.
    Evidence,
    /// Materialized facts.
    Fact,
    /// Bayesian hypotheses produced by earlier decision cycles.
    Hypothesis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ExpressionNode {
    All {
        expressions: Vec<Expression>,
    },
    Any {
        expressions: Vec<Expression>,
    },
    Not {
        expression: Box<Expression>,
    },
    Claim {
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        value: Option<EvidenceValue>,
    },
    TextContains {
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        needle: String,
        ascii_case_insensitive: bool,
    },
    OntologyRelation {
        subject: ConceptId,
        relation: RelationTypeId,
        object: ConceptId,
    },
}

/// Typed, serializable condition evaluated against a knowledge snapshot.
///
/// Empty `all` and `any` groups are rejected, avoiding vacuous truth and
/// configuration mistakes. Negated branches never contribute evidence to a
/// Bayesian conclusion because absence is not an immutable observation.
///
/// # Example
///
/// ```rust
/// use venom_core::{EvidenceValue, KnowledgePredicate};
/// use venom_scanner::{Expression, KnowledgeLayer};
///
/// let condition = Expression::all(vec![
///     Expression::equals(
///         KnowledgeLayer::Evidence,
///         KnowledgePredicate::new("technology", "framework")?,
///         EvidenceValue::Text("Laravel".into()),
///     ),
///     Expression::equals(
///         KnowledgeLayer::Evidence,
///         KnowledgePredicate::new("authentication", "mechanism")?,
///         EvidenceValue::Text("Sanctum".into()),
///     ),
/// ])?;
///
/// assert!(serde_json::to_string(&condition)?.contains("all"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Expression(ExpressionNode);

impl Expression {
    /// Requires every child expression to match.
    pub fn all(expressions: Vec<Self>) -> Result<Self, RuleEngineError> {
        if expressions.is_empty() {
            return Err(RuleEngineError::EmptyExpression { operator: "all" });
        }
        Ok(Self(ExpressionNode::All { expressions }))
    }

    /// Requires at least one child expression to match.
    pub fn any(expressions: Vec<Self>) -> Result<Self, RuleEngineError> {
        if expressions.is_empty() {
            return Err(RuleEngineError::EmptyExpression { operator: "any" });
        }
        Ok(Self(ExpressionNode::Any { expressions }))
    }

    /// Inverts a child condition without treating absence as evidence.
    pub fn negate(expression: Self) -> Self {
        Self(ExpressionNode::Not {
            expression: Box::new(expression),
        })
    }

    /// Matches a predicate and exact typed value in one knowledge layer.
    pub fn equals(
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
    ) -> Self {
        Self(ExpressionNode::Claim {
            layer,
            predicate,
            value: Some(value),
        })
    }

    /// Matches the existence of a predicate in one knowledge layer.
    pub fn exists(layer: KnowledgeLayer, predicate: KnowledgePredicate) -> Self {
        Self(ExpressionNode::Claim {
            layer,
            predicate,
            value: None,
        })
    }

    /// Matches a substring in a text or text-list claim value.
    pub fn text_contains(
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        needle: impl Into<String>,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self(ExpressionNode::TextContains {
            layer,
            predicate,
            needle: non_empty(needle, "text-match needle")?,
            ascii_case_insensitive: false,
        }))
    }

    /// Matches an ASCII case-insensitive substring in a text claim value.
    ///
    /// This comparison is deterministic and locale-independent, making it
    /// suitable for protocol tokens and product fingerprints.
    pub fn text_contains_ascii_case_insensitive(
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        needle: impl Into<String>,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self(ExpressionNode::TextContains {
            layer,
            predicate,
            needle: non_empty(needle, "text-match needle")?,
            ascii_case_insensitive: true,
        }))
    }

    /// Matches one semantic relationship in the captured ontology.
    pub fn ontology_relation(
        subject: ConceptId,
        relation: RelationTypeId,
        object: ConceptId,
    ) -> Self {
        Self(ExpressionNode::OntologyRelation {
            subject,
            relation,
            object,
        })
    }

    /// Evaluates the expression and returns an explainable trace.
    pub fn evaluate(
        &self,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<ExpressionEvaluation, RuleEngineError> {
        Ok(ExpressionEvaluation {
            trace: evaluate_node(&self.0, snapshot)?,
        })
    }

    pub(crate) fn uses_only_evidence(&self) -> bool {
        match &self.0 {
            ExpressionNode::All { expressions } | ExpressionNode::Any { expressions } => {
                expressions.iter().all(Self::uses_only_evidence)
            },
            ExpressionNode::Not { expression } => expression.uses_only_evidence(),
            ExpressionNode::Claim { layer, .. } | ExpressionNode::TextContains { layer, .. } => {
                matches!(layer, KnowledgeLayer::Evidence)
            },
            ExpressionNode::OntologyRelation { .. } => false,
        }
    }
}

impl<'de> Deserialize<'de> for Expression {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let node = ExpressionNode::deserialize(deserializer)?;
        match &node {
            ExpressionNode::All { expressions } if expressions.is_empty() => {
                return Err(serde::de::Error::custom(RuleEngineError::EmptyExpression {
                    operator: "all",
                }));
            },
            ExpressionNode::Any { expressions } if expressions.is_empty() => {
                return Err(serde::de::Error::custom(RuleEngineError::EmptyExpression {
                    operator: "any",
                }));
            },
            ExpressionNode::TextContains { needle, .. } if needle.trim().is_empty() => {
                return Err(serde::de::Error::custom(RuleEngineError::EmptyValue {
                    field: "text-match needle",
                }));
            },
            _ => {},
        }
        Ok(Self(node))
    }
}

/// Explainable result of one expression tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpressionEvaluation {
    trace: ExpressionTrace,
}

impl ExpressionEvaluation {
    /// Returns whether the root expression matched.
    pub fn matched(&self) -> bool {
        self.trace.matched
    }

    /// Returns evidence that positively contributed to the match.
    pub fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.trace.evidence_ids
    }

    /// Returns the complete expression tree trace.
    pub fn trace(&self) -> &ExpressionTrace {
        &self.trace
    }
}

/// One node in an expression evaluation trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpressionTrace {
    label: String,
    matched: bool,
    evidence_ids: BTreeSet<EvidenceId>,
    children: Vec<ExpressionTrace>,
}

impl ExpressionTrace {
    /// Returns a stable human-readable description of this operation.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns whether this operation matched.
    pub fn matched(&self) -> bool {
        self.matched
    }

    /// Returns positively contributing evidence at this node.
    pub fn evidence_ids(&self) -> &BTreeSet<EvidenceId> {
        &self.evidence_ids
    }

    /// Returns child operations in declared expression order.
    pub fn children(&self) -> &[ExpressionTrace] {
        &self.children
    }
}

fn evaluate_node(
    node: &ExpressionNode,
    snapshot: &KnowledgeSnapshot,
) -> Result<ExpressionTrace, RuleEngineError> {
    match node {
        ExpressionNode::All { expressions } => {
            let children = evaluate_children(expressions, snapshot)?;
            let matched = children.iter().all(ExpressionTrace::matched);
            let evidence_ids = if matched {
                collect_trace_evidence(&children)
            } else {
                BTreeSet::new()
            };
            Ok(ExpressionTrace {
                label: "all".into(),
                matched,
                evidence_ids,
                children,
            })
        },
        ExpressionNode::Any { expressions } => {
            let children = evaluate_children(expressions, snapshot)?;
            let matched = children.iter().any(ExpressionTrace::matched);
            let evidence_ids = children
                .iter()
                .filter(|child| child.matched)
                .flat_map(|child| child.evidence_ids.iter().cloned())
                .collect();
            Ok(ExpressionTrace {
                label: "any".into(),
                matched,
                evidence_ids,
                children,
            })
        },
        ExpressionNode::Not { expression } => {
            let child = evaluate_node(&expression.0, snapshot)?;
            Ok(ExpressionTrace {
                label: "not".into(),
                matched: !child.matched,
                evidence_ids: BTreeSet::new(),
                children: vec![child],
            })
        },
        ExpressionNode::Claim {
            layer,
            predicate,
            value,
        } => Ok(evaluate_claim(*layer, predicate, value.as_ref(), snapshot)),
        ExpressionNode::TextContains {
            layer,
            predicate,
            needle,
            ascii_case_insensitive,
        } => Ok(evaluate_text_contains(
            *layer,
            predicate,
            needle,
            *ascii_case_insensitive,
            snapshot,
        )),
        ExpressionNode::OntologyRelation {
            subject,
            relation,
            object,
        } => Ok(ExpressionTrace {
            label: format!("ontology:{subject}:{relation}:{object}"),
            matched: snapshot.ontology().is_related(subject, relation, object)?,
            evidence_ids: BTreeSet::new(),
            children: Vec::new(),
        }),
    }
}

fn evaluate_text_contains(
    layer: KnowledgeLayer,
    predicate: &KnowledgePredicate,
    needle: &str,
    ascii_case_insensitive: bool,
    snapshot: &KnowledgeSnapshot,
) -> ExpressionTrace {
    let matches_text = |value: &EvidenceValue| {
        evidence_value_texts(value).any(|text| text_contains(text, needle, ascii_case_insensitive))
    };
    let mut evidence_ids = BTreeSet::new();
    let matched = match layer {
        KnowledgeLayer::Evidence => {
            let matches: Vec<_> = snapshot
                .evidence()
                .iter()
                .filter(|evidence| {
                    evidence.predicate() == predicate && matches_text(evidence.value())
                })
                .collect();
            evidence_ids.extend(matches.iter().map(|evidence| evidence.id().clone()));
            !matches.is_empty()
        },
        KnowledgeLayer::Fact => {
            let matches: Vec<_> = snapshot
                .facts()
                .iter()
                .filter(|fact| fact.predicate() == predicate && matches_text(fact.value()))
                .collect();
            evidence_ids.extend(
                matches
                    .iter()
                    .flat_map(|fact| fact.evidence_ids().iter().cloned()),
            );
            !matches.is_empty()
        },
        KnowledgeLayer::Hypothesis => {
            let matches: Vec<_> = snapshot
                .hypotheses()
                .iter()
                .filter(|hypothesis| {
                    hypothesis.predicate() == predicate && matches_text(hypothesis.value())
                })
                .collect();
            evidence_ids.extend(matches.iter().flat_map(|hypothesis| {
                hypothesis
                    .belief()
                    .evidence()
                    .iter()
                    .map(|observation| observation.evidence_id().clone())
            }));
            !matches.is_empty()
        },
    };

    let comparison = if ascii_case_insensitive {
        "contains-ascii-ci"
    } else {
        "contains"
    };
    ExpressionTrace {
        label: format!("{layer:?}:{}:{comparison}:{needle}", predicate.dotted()),
        matched,
        evidence_ids,
        children: Vec::new(),
    }
}

fn evidence_value_texts(value: &EvidenceValue) -> Box<dyn Iterator<Item = &str> + '_> {
    match value {
        EvidenceValue::Text(text) => Box::new(std::iter::once(text.as_str())),
        EvidenceValue::TextList(values) => Box::new(values.iter().map(String::as_str)),
        _ => Box::new(std::iter::empty()),
    }
}

fn text_contains(value: &str, needle: &str, ascii_case_insensitive: bool) -> bool {
    if ascii_case_insensitive {
        value
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    } else {
        value.contains(needle)
    }
}

fn evaluate_children(
    expressions: &[Expression],
    snapshot: &KnowledgeSnapshot,
) -> Result<Vec<ExpressionTrace>, RuleEngineError> {
    expressions
        .iter()
        .map(|expression| evaluate_node(&expression.0, snapshot))
        .collect()
}

fn collect_trace_evidence(children: &[ExpressionTrace]) -> BTreeSet<EvidenceId> {
    children
        .iter()
        .flat_map(|child| child.evidence_ids.iter().cloned())
        .collect()
}

fn evaluate_claim(
    layer: KnowledgeLayer,
    predicate: &KnowledgePredicate,
    value: Option<&EvidenceValue>,
    snapshot: &KnowledgeSnapshot,
) -> ExpressionTrace {
    let mut evidence_ids = BTreeSet::new();
    let matched = match layer {
        KnowledgeLayer::Evidence => {
            let matches: Vec<_> = snapshot
                .evidence()
                .iter()
                .filter(|evidence| {
                    evidence.predicate() == predicate
                        && value.is_none_or(|expected| evidence.value() == expected)
                })
                .collect();
            evidence_ids.extend(matches.iter().map(|evidence| evidence.id().clone()));
            !matches.is_empty()
        },
        KnowledgeLayer::Fact => {
            let matches: Vec<_> = snapshot
                .facts()
                .iter()
                .filter(|fact| {
                    fact.predicate() == predicate
                        && value.is_none_or(|expected| fact.value() == expected)
                })
                .collect();
            evidence_ids.extend(
                matches
                    .iter()
                    .flat_map(|fact| fact.evidence_ids().iter().cloned()),
            );
            !matches.is_empty()
        },
        KnowledgeLayer::Hypothesis => {
            let matches: Vec<_> = snapshot
                .hypotheses()
                .iter()
                .filter(|hypothesis| {
                    hypothesis.predicate() == predicate
                        && value.is_none_or(|expected| hypothesis.value() == expected)
                })
                .collect();
            evidence_ids.extend(matches.iter().flat_map(|hypothesis| {
                hypothesis
                    .belief()
                    .evidence()
                    .iter()
                    .map(|observation| observation.evidence_id().clone())
            }));
            !matches.is_empty()
        },
    };

    let comparison = value.map_or_else(|| "exists".into(), |value| format!("equals:{value:?}"));
    ExpressionTrace {
        label: format!("{layer:?}:{}:{comparison}", predicate.dotted()),
        matched,
        evidence_ids,
        children: Vec::new(),
    }
}

/// Selects raw evidence for one Bayesian calibration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceSelector {
    predicate: KnowledgePredicate,
    value: Option<EvidenceValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_contains_ascii_case_insensitive: Option<String>,
}

impl EvidenceSelector {
    /// Selects evidence with an exact predicate and value.
    pub fn equals(predicate: KnowledgePredicate, value: EvidenceValue) -> Self {
        Self {
            predicate,
            value: Some(value),
            text_contains_ascii_case_insensitive: None,
        }
    }

    /// Selects any evidence with this predicate.
    pub fn exists(predicate: KnowledgePredicate) -> Self {
        Self {
            predicate,
            value: None,
            text_contains_ascii_case_insensitive: None,
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

    fn matches(&self, evidence: &venom_core::Evidence) -> bool {
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
    }
}

impl<'de> Deserialize<'de> for EvidenceSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireSelector {
            predicate: KnowledgePredicate,
            value: Option<EvidenceValue>,
            #[serde(default)]
            text_contains_ascii_case_insensitive: Option<String>,
        }

        let wire = WireSelector::deserialize(deserializer)?;
        if wire.value.is_some() && wire.text_contains_ascii_case_insensitive.is_some() {
            return Err(serde::de::Error::custom(
                "evidence selector cannot combine exact and text matching",
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
        Ok(Self {
            predicate: wire.predicate,
            value: wire.value,
            text_contains_ascii_case_insensitive: wire.text_contains_ascii_case_insensitive,
        })
    }
}

/// Bayesian likelihoods assigned to evidence selected by a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceCalibration {
    selector: EvidenceSelector,
    likelihood_if_true: Probability,
    likelihood_if_false: Probability,
    rationale: String,
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
        })
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
}

impl<'de> Deserialize<'de> for EvidenceCalibration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireCalibration {
            selector: EvidenceSelector,
            likelihood_if_true: Probability,
            likelihood_if_false: Probability,
            rationale: String,
        }

        let wire = WireCalibration::deserialize(deserializer)?;
        Self::new(
            wire.selector,
            wire.likelihood_if_true,
            wire.likelihood_if_false,
            wire.rationale,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Data needed to materialize one Bayesian hypothesis after a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HypothesisConclusion {
    predicate: KnowledgePredicate,
    value: EvidenceValue,
    prior: Probability,
    strength: HypothesisStrength,
    state: HypothesisState,
    calibrations: Vec<EvidenceCalibration>,
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
    id: String,
    condition: Expression,
    conclusion: HypothesisConclusion,
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

/// Pure result of evaluating one rule against one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleEvaluation {
    rule_id: String,
    condition: ExpressionEvaluation,
    hypothesis: Option<Hypothesis>,
}

impl RuleEvaluation {
    /// Returns the evaluated rule identity.
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Returns whether the condition matched.
    pub fn matched(&self) -> bool {
        self.condition.matched()
    }

    /// Returns the expression result and trace.
    pub fn condition(&self) -> &ExpressionEvaluation {
        &self.condition
    }

    /// Returns the materialized hypothesis when the condition matched.
    pub fn hypothesis(&self) -> Option<&Hypothesis> {
        self.hypothesis.as_ref()
    }
}

/// Result of evaluating and atomically writing one rule conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleApplication {
    evaluation: RuleEvaluation,
    write: Option<KnowledgeWrite>,
}

impl RuleApplication {
    /// Returns the pure evaluation that preceded the write.
    pub fn evaluation(&self) -> &RuleEvaluation {
        &self.evaluation
    }

    /// Returns the knowledge write, or `None` for an unmatched rule.
    pub fn write(&self) -> Option<KnowledgeWrite> {
        self.write
    }
}

/// Deterministic registry and evaluator for declarative reasoning rules.
///
/// Rules are always evaluated in stable rule-ID order against one shared
/// snapshot. Conclusions are written only after every rule has been evaluated,
/// preventing earlier rules from changing later conditions in the same cycle.
#[derive(Debug, Clone, Default)]
pub struct RuleEngine {
    rules: BTreeMap<String, ReasoningRule>,
}

impl RuleEngine {
    /// Creates an empty engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an idempotent rule definition.
    pub fn register(&mut self, rule: ReasoningRule) -> Result<RuleWrite, RuleEngineError> {
        if let Some(existing) = self.rules.get(rule.id()) {
            return if existing == &rule {
                Ok(RuleWrite::Unchanged)
            } else {
                Err(RuleEngineError::RuleIdentityConflict {
                    id: rule.id().to_owned(),
                })
            };
        }
        self.rules.insert(rule.id().to_owned(), rule);
        Ok(RuleWrite::Inserted)
    }

    /// Returns the number of registered rule identities.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns whether no rules are registered.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Evaluates all rules without mutating the knowledge base.
    pub fn evaluate(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
    ) -> Result<Vec<RuleEvaluation>, RuleEngineError> {
        let snapshot = knowledge.snapshot_for_subject(subject);
        self.evaluate_snapshot(&snapshot)
    }

    /// Evaluates all rules against one immutable snapshot.
    pub fn evaluate_snapshot(
        &self,
        snapshot: &KnowledgeSnapshot,
    ) -> Result<Vec<RuleEvaluation>, RuleEngineError> {
        self.rules
            .values()
            .map(|rule| evaluate_rule(rule, snapshot))
            .collect()
    }

    /// Evaluates one decision cycle and writes matched hypotheses.
    ///
    /// Existing verifier-owned `Confirmed` and `Rejected` states survive
    /// recalibration, so a reasoning pass cannot reverse a verification result.
    pub fn apply(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
    ) -> Result<Vec<RuleApplication>, RuleEngineError> {
        let evaluations = self.evaluate(knowledge, subject)?;
        evaluations
            .into_iter()
            .map(|evaluation| {
                let write = evaluation
                    .hypothesis()
                    .cloned()
                    .map(|mut hypothesis| {
                        if let Some(existing) = knowledge.hypothesis(hypothesis.id()) {
                            if matches!(
                                existing.state(),
                                HypothesisState::Confirmed | HypothesisState::Rejected
                            ) {
                                hypothesis.set_state(existing.state());
                            }
                        }
                        knowledge.upsert_hypothesis(hypothesis)
                    })
                    .transpose()?;
                Ok(RuleApplication { evaluation, write })
            })
            .collect()
    }
}

fn evaluate_rule(
    rule: &ReasoningRule,
    snapshot: &KnowledgeSnapshot,
) -> Result<RuleEvaluation, RuleEngineError> {
    let condition = rule.condition.evaluate(snapshot)?;
    let hypothesis = if condition.matched() {
        Some(materialize_hypothesis(rule, snapshot, &condition)?)
    } else {
        None
    };
    Ok(RuleEvaluation {
        rule_id: rule.id.clone(),
        condition,
        hypothesis,
    })
}

fn materialize_hypothesis(
    rule: &ReasoningRule,
    snapshot: &KnowledgeSnapshot,
    condition: &ExpressionEvaluation,
) -> Result<Hypothesis, RuleEngineError> {
    let mut observations = BTreeMap::<EvidenceId, BayesianEvidence>::new();
    for calibration in &rule.conclusion.calibrations {
        for evidence in snapshot.evidence().iter().filter(|evidence| {
            condition.evidence_ids().contains(evidence.id())
                && calibration.selector.matches(evidence)
        }) {
            let observation = BayesianEvidence::new(
                evidence.id().clone(),
                calibration.likelihood_if_true,
                calibration.likelihood_if_false,
                calibration.rationale.clone(),
            )?;
            if let Some(existing) = observations.get(evidence.id()) {
                if existing != &observation {
                    return Err(RuleEngineError::AmbiguousEvidenceCalibration {
                        rule_id: rule.id.clone(),
                        evidence_id: evidence.id().clone(),
                    });
                }
            } else {
                observations.insert(evidence.id().clone(), observation);
            }
        }
    }

    if observations.is_empty() {
        return Err(RuleEngineError::MissingCalibratedEvidence {
            rule_id: rule.id.clone(),
        });
    }

    let stable_id = format!("rule:{}:{}:{}", rule.id.len(), rule.id, snapshot.subject());
    let mut hypothesis = Hypothesis::with_id(
        stable_id,
        snapshot.subject().clone(),
        rule.conclusion.predicate.clone(),
        rule.conclusion.value.clone(),
        rule.conclusion.prior,
    )?;
    for observation in observations.into_values() {
        hypothesis.observe(observation)?;
    }
    hypothesis.set_strength(rule.conclusion.strength);
    hypothesis.set_state(rule.conclusion.state);
    Ok(hypothesis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use venom_core::{
        ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource, Fact, Ontology,
        OntologyAxiom, OntologyConcept,
    };

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test").unwrap()
    }

    fn framework_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("technology", "framework").unwrap()
    }

    fn auth_predicate() -> KnowledgePredicate {
        KnowledgePredicate::new("authentication", "mechanism").unwrap()
    }

    fn evidence(predicate: KnowledgePredicate, value: EvidenceValue) -> Evidence {
        Evidence::new(
            subject(),
            EvidenceKind::Technology,
            predicate,
            value,
            EvidenceSource::new("discovery", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        )
    }

    fn calibration(
        predicate: KnowledgePredicate,
        value: EvidenceValue,
        likelihood_if_true: u8,
        likelihood_if_false: u8,
    ) -> EvidenceCalibration {
        EvidenceCalibration::new(
            EvidenceSelector::equals(predicate, value),
            Probability::from_percent(likelihood_if_true).unwrap(),
            Probability::from_percent(likelihood_if_false).unwrap(),
            "test calibration",
        )
        .unwrap()
    }

    fn laravel_rule(id: &str) -> ReasoningRule {
        let framework = framework_predicate();
        let auth = auth_predicate();
        let laravel = EvidenceValue::Text("Laravel".into());
        let sanctum = EvidenceValue::Text("Sanctum".into());
        ReasoningRule::new(
            id,
            Expression::all(vec![
                Expression::equals(KnowledgeLayer::Evidence, framework.clone(), laravel.clone()),
                Expression::equals(KnowledgeLayer::Evidence, auth.clone(), sanctum.clone()),
            ])
            .unwrap(),
            HypothesisConclusion::new(
                KnowledgePredicate::new("stack", "framework").unwrap(),
                laravel.clone(),
                Probability::from_percent(10).unwrap(),
                HypothesisStrength::Strong,
                HypothesisState::Supported,
                vec![
                    calibration(framework, laravel, 80, 20),
                    calibration(auth, sanctum, 90, 10),
                ],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn expression_composition_tracks_only_positive_matching_evidence() {
        let knowledge = KnowledgeBase::new();
        let framework_evidence =
            evidence(framework_predicate(), EvidenceValue::Text("Laravel".into()));
        let framework_id = framework_evidence.id().clone();
        knowledge.insert_evidence(framework_evidence).unwrap();
        let expression = Expression::all(vec![
            Expression::equals(
                KnowledgeLayer::Evidence,
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ),
            Expression::negate(Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("security", "waf").unwrap(),
            )),
        ])
        .unwrap();

        let evaluation = expression
            .evaluate(&knowledge.snapshot_for_subject(&subject()))
            .unwrap();

        assert!(evaluation.matched());
        assert_eq!(evaluation.evidence_ids(), &BTreeSet::from([framework_id]));
        assert_eq!(evaluation.trace().children().len(), 2);
        assert!(evaluation.trace().children()[1].evidence_ids().is_empty());
    }

    #[test]
    fn expression_wire_format_rejects_empty_groups() {
        assert!(Expression::all(Vec::new()).is_err());
        assert!(serde_json::from_value::<Expression>(serde_json::json!({
            "op": "any",
            "expressions": []
        }))
        .is_err());
    }

    #[test]
    fn text_expression_matches_ascii_case_insensitively_with_provenance() {
        let knowledge = KnowledgeBase::new();
        let server = KnowledgePredicate::new("http.header", "server").unwrap();
        let observation = evidence(server.clone(), EvidenceValue::Text("NGINX/1.26".into()));
        let evidence_id = observation.id().clone();
        knowledge.insert_evidence(observation).unwrap();
        let expression = Expression::text_contains_ascii_case_insensitive(
            KnowledgeLayer::Evidence,
            server,
            "nginx",
        )
        .unwrap();

        let evaluation = expression
            .evaluate(&knowledge.snapshot_for_subject(&subject()))
            .unwrap();

        assert!(evaluation.matched());
        assert_eq!(evaluation.evidence_ids(), &BTreeSet::from([evidence_id]));
        assert!(evaluation.trace().label().contains("contains-ascii-ci"));
        let encoded = serde_json::to_value(&expression).unwrap();
        assert_eq!(
            serde_json::from_value::<Expression>(encoded).unwrap(),
            expression
        );
        assert!(
            Expression::text_contains(KnowledgeLayer::Evidence, framework_predicate(), " ")
                .is_err()
        );
    }

    #[test]
    fn text_evidence_selector_validates_and_round_trips() {
        let selector = EvidenceSelector::text_contains_ascii_case_insensitive(
            KnowledgePredicate::new("http.header", "x-powered-by").unwrap(),
            "php",
        )
        .unwrap();
        let encoded = serde_json::to_value(&selector).unwrap();

        assert_eq!(
            serde_json::from_value::<EvidenceSelector>(encoded).unwrap(),
            selector
        );
        assert_eq!(selector.text_needle(), Some("php"));
        assert!(
            EvidenceSelector::text_contains_ascii_case_insensitive(framework_predicate(), " ")
                .is_err()
        );
        assert!(
            serde_json::from_value::<EvidenceSelector>(serde_json::json!({
                "predicate": framework_predicate(),
                "value": { "type": "text", "value": "Laravel" },
                "text_contains_ascii_case_insensitive": "laravel"
            }))
            .is_err()
        );
    }

    #[test]
    fn fact_and_hypothesis_expressions_preserve_evidence_provenance() {
        let knowledge = KnowledgeBase::new();
        let observation = evidence(framework_predicate(), EvidenceValue::Text("Laravel".into()));
        let evidence_id = observation.id().clone();
        knowledge.insert_evidence(observation).unwrap();
        knowledge
            .upsert_fact(Fact::new(
                subject(),
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
                ConfidenceScore::from_percent(90).unwrap(),
                evidence_id.clone(),
            ))
            .unwrap();
        let mut hypothesis = Hypothesis::new(
            subject(),
            KnowledgePredicate::new("stack", "framework").unwrap(),
            EvidenceValue::Text("Laravel".into()),
            Probability::from_percent(10).unwrap(),
        );
        hypothesis
            .observe(
                BayesianEvidence::new(
                    evidence_id.clone(),
                    Probability::from_percent(80).unwrap(),
                    Probability::from_percent(20).unwrap(),
                    "fact provenance",
                )
                .unwrap(),
            )
            .unwrap();
        knowledge.upsert_hypothesis(hypothesis).unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());

        let fact_match = Expression::equals(
            KnowledgeLayer::Fact,
            framework_predicate(),
            EvidenceValue::Text("Laravel".into()),
        )
        .evaluate(&snapshot)
        .unwrap();
        let hypothesis_match = Expression::equals(
            KnowledgeLayer::Hypothesis,
            KnowledgePredicate::new("stack", "framework").unwrap(),
            EvidenceValue::Text("Laravel".into()),
        )
        .evaluate(&snapshot)
        .unwrap();

        assert_eq!(
            fact_match.evidence_ids(),
            &BTreeSet::from([evidence_id.clone()])
        );
        assert_eq!(
            hypothesis_match.evidence_ids(),
            &BTreeSet::from([evidence_id])
        );
    }

    #[test]
    fn ontology_expression_uses_snapshot_semantics() {
        let knowledge = KnowledgeBase::new();
        let framework = ConceptId::new("framework").unwrap();
        let laravel = ConceptId::new("laravel").unwrap();
        knowledge
            .register_concept(OntologyConcept::new(framework.clone(), "Framework").unwrap())
            .unwrap();
        knowledge
            .register_concept(OntologyConcept::new(laravel.clone(), "Laravel").unwrap())
            .unwrap();
        knowledge
            .register_axiom(OntologyAxiom::new(
                laravel.clone(),
                RelationTypeId::new(Ontology::IS_A).unwrap(),
                framework.clone(),
            ))
            .unwrap();
        let expression = Expression::ontology_relation(
            laravel,
            RelationTypeId::new(Ontology::IS_A).unwrap(),
            framework,
        );

        assert!(expression
            .evaluate(&knowledge.snapshot_for_subject(&subject()))
            .unwrap()
            .matched());
    }

    #[test]
    fn rule_engine_materializes_stable_bayesian_hypothesis() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence(
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ))
            .unwrap();
        knowledge
            .insert_evidence(evidence(
                auth_predicate(),
                EvidenceValue::Text("Sanctum".into()),
            ))
            .unwrap();
        let mut engine = RuleEngine::new();
        assert_eq!(
            engine.register(laravel_rule("framework.laravel")).unwrap(),
            RuleWrite::Inserted
        );

        let first = engine.apply(&knowledge, &subject()).unwrap();
        let hypothesis = first[0].evaluation().hypothesis().unwrap();
        assert_eq!(first[0].write(), Some(KnowledgeWrite::Inserted));
        assert_eq!(hypothesis.belief().evidence().len(), 2);
        assert_eq!(hypothesis.strength(), HypothesisStrength::Strong);
        assert_eq!(hypothesis.state(), HypothesisState::Supported);
        assert!(hypothesis.posterior() > Probability::from_percent(50).unwrap());
        assert!(serde_json::to_value(&first[0]).is_ok());
        let stable_id = hypothesis.id().to_owned();

        let second = engine.apply(&knowledge, &subject()).unwrap();
        assert_eq!(second[0].write(), Some(KnowledgeWrite::Unchanged));
        assert_eq!(second[0].evaluation().hypothesis().unwrap().id(), stable_id);
        assert_eq!(knowledge.stats().hypotheses, 1);
    }

    #[test]
    fn rules_evaluate_in_id_order_not_registration_order() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence(
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ))
            .unwrap();
        knowledge
            .insert_evidence(evidence(
                auth_predicate(),
                EvidenceValue::Text("Sanctum".into()),
            ))
            .unwrap();
        let mut engine = RuleEngine::new();
        engine.register(laravel_rule("rule.z")).unwrap();
        engine.register(laravel_rule("rule.a")).unwrap();

        let evaluations = engine.evaluate(&knowledge, &subject()).unwrap();
        assert_eq!(evaluations[0].rule_id(), "rule.a");
        assert_eq!(evaluations[1].rule_id(), "rule.z");
    }

    #[test]
    fn rule_registration_and_wire_invariants_are_enforced() {
        let rule = laravel_rule("framework.laravel");
        let encoded = serde_json::to_value(&rule).unwrap();
        assert_eq!(
            serde_json::from_value::<ReasoningRule>(encoded).unwrap(),
            rule
        );
        assert!(ReasoningRule::new(" ", rule.condition.clone(), rule.conclusion.clone()).is_err());
        assert!(HypothesisConclusion::new(
            framework_predicate(),
            EvidenceValue::Text("Laravel".into()),
            Probability::from_percent(10).unwrap(),
            HypothesisStrength::Strong,
            HypothesisState::Confirmed,
            rule.conclusion.calibrations.clone(),
        )
        .is_err());

        let mut engine = RuleEngine::new();
        assert_eq!(engine.register(rule.clone()).unwrap(), RuleWrite::Inserted);
        assert_eq!(engine.register(rule.clone()).unwrap(), RuleWrite::Unchanged);
        let conflicting = ReasoningRule::new(
            rule.id(),
            Expression::exists(KnowledgeLayer::Evidence, framework_predicate()),
            rule.conclusion.clone(),
        )
        .unwrap();
        assert!(matches!(
            engine.register(conflicting),
            Err(RuleEngineError::RuleIdentityConflict { .. })
        ));
    }

    #[test]
    fn ambiguous_calibration_fails_before_writing() {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence(
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ))
            .unwrap();
        let exact = calibration(
            framework_predicate(),
            EvidenceValue::Text("Laravel".into()),
            80,
            20,
        );
        let overlapping = EvidenceCalibration::new(
            EvidenceSelector::exists(framework_predicate()),
            Probability::from_percent(90).unwrap(),
            Probability::from_percent(10).unwrap(),
            "different calibration",
        )
        .unwrap();
        let rule = ReasoningRule::new(
            "ambiguous",
            Expression::equals(
                KnowledgeLayer::Evidence,
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ),
            HypothesisConclusion::new(
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
                Probability::from_percent(10).unwrap(),
                HypothesisStrength::Weak,
                HypothesisState::Supported,
                vec![exact, overlapping],
            )
            .unwrap(),
        )
        .unwrap();
        let mut engine = RuleEngine::new();
        engine.register(rule).unwrap();

        assert!(matches!(
            engine.apply(&knowledge, &subject()),
            Err(RuleEngineError::AmbiguousEvidenceCalibration { .. })
        ));
        assert_eq!(knowledge.stats().hypotheses, 0);
    }
}
