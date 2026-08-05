//! Deterministic expression evaluation and Bayesian reasoning rules.
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
//! Rules consume an immutable [`KnowledgeSnapshot`]. They never execute
//! plugins, schedule scans, or mutate evidence. A matched rule may materialize
//! one stable, evidence-backed [`Hypothesis`].

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use venom_core::{
    BayesianEvidence, ConceptId, EntityId, EvidenceId, EvidenceValue, Hypothesis, HypothesisState,
    HypothesisStrength, KnowledgePredicate, OntologyError, Probability, ReasoningModelError,
    RelationTypeId,
};

use crate::knowledge::{KnowledgeBase, KnowledgeBaseError, KnowledgeSnapshot, KnowledgeWrite};

const MAX_STALE_SNAPSHOT_RETRIES: u8 = 3;
const MAX_REASONING_APPLY_ATTEMPTS: u8 = MAX_STALE_SNAPSHOT_RETRIES + 1;

/// Returns the stable identity materialized by a rule for one knowledge subject.
///
/// Keeping this legacy format in one place ensures projections can locate the
/// canonical hypothesis without depending on a private `RuleEngine` detail.
pub(crate) fn hypothesis_id_for_rule(rule_id: &str, subject: &EntityId) -> String {
    format!("rule:{}:{rule_id}:{subject}", rule_id.len())
}

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

    /// A bounded evidence aggregation requested zero contributions.
    #[error("evidence aggregation limit must be greater than zero")]
    InvalidAggregationLimit,

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

    /// Concurrent rule-visible writes prevented a stable reasoning commit.
    #[error("reasoning snapshot stayed stale after {attempts} commit attempts")]
    StaleSnapshotRetriesExhausted { attempts: u8 },
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

    fn limit(self) -> Option<usize> {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceCalibration {
    selector: EvidenceSelector,
    likelihood_if_true: Probability,
    likelihood_if_false: Probability,
    rationale: String,
    #[serde(default, skip_serializing_if = "EvidenceAggregation::is_independent")]
    aggregation: EvidenceAggregation,
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
        })
    }

    /// Applies an explicit contribution policy to this calibration.
    pub fn with_aggregation(mut self, aggregation: EvidenceAggregation) -> Self {
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
        }

        let wire = WireCalibration::deserialize(deserializer)?;
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

/// Result of evaluating one rule and committing its conclusion in a reasoning batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleApplication {
    evaluation: RuleEvaluation,
    write: Option<KnowledgeWrite>,
}

impl RuleApplication {
    /// Returns the pure evaluation that preceded the committed batch.
    ///
    /// This is the snapshot candidate, not a fresh read of committed state.
    /// Terminal-state preservation can therefore make the stored lifecycle
    /// state differ from this hypothesis; query the knowledge base when the
    /// post-commit record is required.
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

    /// Evaluates one decision cycle and atomically writes matched hypotheses.
    ///
    /// All rules first evaluate in stable rule-ID order against one immutable
    /// snapshot. Every matched hypothesis is then preflighted and committed in
    /// one knowledge-base write transaction, so one late identity conflict
    /// cannot leave earlier conclusions stored. Existing verifier-owned
    /// `Confirmed` and `Rejected` states are preserved under that same write
    /// lock, so a concurrent reasoning pass cannot reverse a verification result.
    pub fn apply(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
    ) -> Result<Vec<RuleApplication>, RuleEngineError> {
        self.apply_with_before_commit(knowledge, subject, |_, _| {})
    }

    fn apply_with_before_commit<F>(
        &self,
        knowledge: &KnowledgeBase,
        subject: &venom_core::EntityId,
        mut before_commit: F,
    ) -> Result<Vec<RuleApplication>, RuleEngineError>
    where
        F: FnMut(u8, &KnowledgeSnapshot),
    {
        for attempt in 1..=MAX_REASONING_APPLY_ATTEMPTS {
            let snapshot = knowledge.snapshot_for_subject(subject);
            let evaluations = self.evaluate_snapshot(&snapshot)?;
            let hypotheses = evaluations
                .iter()
                .filter_map(|evaluation| evaluation.hypothesis().cloned())
                .collect();
            before_commit(attempt, &snapshot);

            let writes = match knowledge.upsert_reasoning_hypothesis_batch(&snapshot, hypotheses) {
                Ok(writes) => writes,
                Err(KnowledgeBaseError::StaleSnapshot { .. })
                    if attempt < MAX_REASONING_APPLY_ATTEMPTS =>
                {
                    continue;
                },
                Err(KnowledgeBaseError::StaleSnapshot { .. }) => {
                    return Err(RuleEngineError::StaleSnapshotRetriesExhausted {
                        attempts: attempt,
                    });
                },
                Err(error) => return Err(error.into()),
            };

            let mut writes = writes.into_iter().peekable();
            let applications = evaluations
                .into_iter()
                .map(|evaluation| {
                    let write = evaluation.hypothesis().map(|_| {
                        writes
                            .next()
                            .expect("matched hypotheses and writes stay aligned")
                    });
                    RuleApplication { evaluation, write }
                })
                .collect();
            debug_assert!(writes.peek().is_none());
            return Ok(applications);
        }

        unreachable!("bounded reasoning attempts always return or retry")
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
        let mut matches = snapshot
            .evidence()
            .iter()
            .filter(|evidence| {
                condition.evidence_ids().contains(evidence.id())
                    && calibration.selector.matches(evidence)
            })
            .collect::<Vec<_>>();
        if let Some(limit) = calibration.aggregation.limit() {
            matches.sort_by(|left, right| {
                right
                    .reliability()
                    .cmp(&left.reliability())
                    .then_with(|| right.observed_at_ms().cmp(&left.observed_at_ms()))
                    .then_with(|| left.id().cmp(right.id()))
            });
            matches.truncate(limit);
        }
        for evidence in matches {
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

    let stable_id = hypothesis_id_for_rule(&rule.id, snapshot.subject());
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
        ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, Fact,
        Ontology, OntologyAxiom, OntologyConcept,
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
    fn hypothesis_id_helper_preserves_legacy_format() {
        let subject = subject();

        assert_eq!(
            hypothesis_id_for_rule("framework.laravel", &subject),
            "rule:17:framework.laravel:endpoint:https://example.test"
        );
        assert_eq!(
            hypothesis_id_for_rule("rüle", &subject),
            "rule:5:rüle:endpoint:https://example.test"
        );
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
        assert_eq!(
            stable_id,
            hypothesis_id_for_rule("framework.laravel", &subject())
        );

        let second = engine.apply(&knowledge, &subject()).unwrap();
        assert_eq!(second[0].write(), Some(KnowledgeWrite::Unchanged));
        assert_eq!(second[0].evaluation().hypothesis().unwrap().id(), stable_id);
        assert_eq!(knowledge.stats().hypotheses, 1);
    }

    #[test]
    fn rule_engine_retries_a_controllably_stale_snapshot() {
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
        engine.register(laravel_rule("framework.laravel")).unwrap();

        let applications = engine
            .apply_with_before_commit(&knowledge, &subject(), |attempt, _| {
                if attempt == 1 {
                    knowledge
                        .insert_evidence(evidence(
                            framework_predicate(),
                            EvidenceValue::Text("Laravel".into()),
                        ))
                        .unwrap();
                }
            })
            .unwrap();

        let committed_id = applications[0].evaluation().hypothesis().unwrap().id();
        let stored = knowledge.hypothesis(committed_id).unwrap();
        assert_eq!(stored.belief().evidence().len(), 3);
        assert_eq!(applications[0].write(), Some(KnowledgeWrite::Inserted));
    }

    #[test]
    fn empty_apply_validates_revisions_and_reports_retry_exhaustion() {
        let knowledge = KnowledgeBase::new();
        let engine = RuleEngine::new();

        let error = engine
            .apply_with_before_commit(&knowledge, &subject(), |attempt, _| {
                knowledge
                    .insert_evidence(evidence(
                        framework_predicate(),
                        EvidenceValue::Text(format!("stale-attempt-{attempt}")),
                    ))
                    .unwrap();
            })
            .unwrap_err();

        assert!(matches!(
            error,
            RuleEngineError::StaleSnapshotRetriesExhausted {
                attempts: MAX_REASONING_APPLY_ATTEMPTS
            }
        ));
        assert_eq!(knowledge.stats().hypotheses, 0);
    }

    #[test]
    fn delayed_reasoning_batch_cannot_overwrite_a_newer_belief() {
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
        engine.register(laravel_rule("framework.laravel")).unwrap();
        let stale_snapshot = knowledge.snapshot_for_subject(&subject());
        let stale_hypotheses = engine
            .evaluate_snapshot(&stale_snapshot)
            .unwrap()
            .into_iter()
            .filter_map(|evaluation| evaluation.hypothesis().cloned())
            .collect();

        knowledge
            .insert_evidence(evidence(
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ))
            .unwrap();
        let current = engine.apply(&knowledge, &subject()).unwrap();
        let hypothesis_id = current[0].evaluation().hypothesis().unwrap().id();
        assert_eq!(
            knowledge
                .hypothesis(hypothesis_id)
                .unwrap()
                .belief()
                .evidence()
                .len(),
            3
        );

        assert!(matches!(
            knowledge.upsert_reasoning_hypothesis_batch(&stale_snapshot, stale_hypotheses),
            Err(KnowledgeBaseError::StaleSnapshot { .. })
        ));
        assert_eq!(
            knowledge
                .hypothesis(hypothesis_id)
                .unwrap()
                .belief()
                .evidence()
                .len(),
            3
        );
    }

    #[test]
    fn rule_engine_rolls_back_every_hypothesis_on_a_late_identity_conflict() {
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
        engine.register(laravel_rule("rule.a")).unwrap();
        engine.register(laravel_rule("rule.b")).unwrap();

        let evaluations = engine.evaluate(&knowledge, &subject()).unwrap();
        let first_id = evaluations[0].hypothesis().unwrap().id().to_owned();
        let second_id = evaluations[1].hypothesis().unwrap().id().to_owned();
        let conflicting = Hypothesis::with_id(
            second_id.clone(),
            subject(),
            auth_predicate(),
            EvidenceValue::Text("conflicting-claim".into()),
            Probability::from_percent(50).unwrap(),
        )
        .unwrap();
        knowledge.upsert_hypothesis(conflicting).unwrap();

        assert!(matches!(
            engine.apply(&knowledge, &subject()),
            Err(RuleEngineError::Knowledge(
                KnowledgeBaseError::IdentityConflict {
                    kind: crate::KnowledgeRecordKind::Hypothesis,
                    id,
                }
            )) if id == second_id
        ));
        assert!(knowledge.hypothesis(&first_id).is_none());
        assert_eq!(knowledge.stats().hypotheses, 1);
    }

    #[test]
    fn rule_engine_recalibration_preserves_verifier_terminal_states() {
        for terminal_state in [HypothesisState::Confirmed, HypothesisState::Rejected] {
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
            engine.register(laravel_rule("framework.laravel")).unwrap();
            let initial = engine.apply(&knowledge, &subject()).unwrap();
            let hypothesis_id = initial[0].evaluation().hypothesis().unwrap().id();
            let mut verified = knowledge.hypothesis(hypothesis_id).unwrap();
            verified.set_state(terminal_state);
            knowledge.upsert_hypothesis(verified).unwrap();

            knowledge
                .insert_evidence(evidence(
                    framework_predicate(),
                    EvidenceValue::Text("Laravel".into()),
                ))
                .unwrap();
            let recalibrated = engine.apply(&knowledge, &subject()).unwrap();

            assert_eq!(recalibrated[0].write(), Some(KnowledgeWrite::Updated));
            let stored = knowledge.hypothesis(hypothesis_id).unwrap();
            assert_eq!(stored.state(), terminal_state);
            assert_eq!(stored.belief().evidence().len(), 3);
        }
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
    fn rule_applications_keep_evaluation_order_and_unmatched_write_slots() {
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
        let template = laravel_rule("template");
        let unmatched = ReasoningRule::new(
            "rule.b",
            Expression::exists(
                KnowledgeLayer::Evidence,
                KnowledgePredicate::new("security", "waf").unwrap(),
            ),
            template.conclusion.clone(),
        )
        .unwrap();
        let mut engine = RuleEngine::new();
        engine.register(laravel_rule("rule.c")).unwrap();
        engine.register(unmatched).unwrap();
        engine.register(laravel_rule("rule.a")).unwrap();

        let applications = engine.apply(&knowledge, &subject()).unwrap();

        assert_eq!(
            applications
                .iter()
                .map(|application| application.evaluation().rule_id())
                .collect::<Vec<_>>(),
            vec!["rule.a", "rule.b", "rule.c"]
        );
        assert_eq!(
            applications
                .iter()
                .map(RuleApplication::write)
                .collect::<Vec<_>>(),
            vec![
                Some(KnowledgeWrite::Inserted),
                None,
                Some(KnowledgeWrite::Inserted),
            ]
        );
        assert_eq!(knowledge.stats().hypotheses, 2);
    }

    #[test]
    fn calibration_contribution_caps_are_explicit_and_round_trip() {
        let knowledge = KnowledgeBase::new();
        let predicate = framework_predicate();
        let value = EvidenceValue::Text("Laravel".into());
        let weak_id = EvidenceId::parse("signal:weak").unwrap();
        let strong_id = EvidenceId::parse("signal:strong").unwrap();
        knowledge
            .insert_evidence_batch(vec![
                Evidence::with_id_at(
                    weak_id.clone(),
                    subject(),
                    EvidenceKind::Technology,
                    predicate.clone(),
                    value.clone(),
                    EvidenceSource::new("discovery", "test").unwrap(),
                    ConfidenceScore::from_percent(50).unwrap(),
                    2_000,
                ),
                Evidence::with_id_at(
                    strong_id.clone(),
                    subject(),
                    EvidenceKind::Technology,
                    predicate.clone(),
                    value.clone(),
                    EvidenceSource::new("discovery", "test").unwrap(),
                    ConfidenceScore::from_percent(90).unwrap(),
                    1_000,
                ),
            ])
            .unwrap();

        let independent = EvidenceCalibration::new(
            EvidenceSelector::equals(predicate.clone(), value.clone()),
            Probability::from_percent(90).unwrap(),
            Probability::from_percent(10).unwrap(),
            "one semantic fingerprint contribution",
        )
        .unwrap();
        let legacy_wire = serde_json::to_value(&independent).unwrap();
        assert!(legacy_wire.get("aggregation").is_none());
        assert_eq!(
            serde_json::from_value::<EvidenceCalibration>(legacy_wire)
                .unwrap()
                .aggregation(),
            EvidenceAggregation::Independent
        );
        let mut misspelled_wire = serde_json::to_value(&independent).unwrap();
        misspelled_wire["aggregaton"] = serde_json::json!({
            "mode": "max_contributions",
            "limit": 1
        });
        assert!(serde_json::from_value::<EvidenceCalibration>(misspelled_wire).is_err());
        let bounded =
            independent.with_aggregation(EvidenceAggregation::max_contributions(1).unwrap());
        let mut malformed_aggregation = serde_json::to_value(&bounded).unwrap();
        malformed_aggregation["aggregation"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EvidenceCalibration>(malformed_aggregation).is_err());
        let bounded_rule = ReasoningRule::new(
            "framework.bounded-signal",
            Expression::equals(KnowledgeLayer::Evidence, predicate.clone(), value.clone()),
            HypothesisConclusion::new(
                KnowledgePredicate::new("stack", "bounded-framework").unwrap(),
                value.clone(),
                Probability::from_percent(10).unwrap(),
                HypothesisStrength::Weak,
                HypothesisState::Supported,
                vec![bounded],
            )
            .unwrap(),
        )
        .unwrap();
        let encoded = serde_json::to_value(&bounded_rule).unwrap();
        assert_eq!(
            serde_json::from_value::<ReasoningRule>(encoded).unwrap(),
            bounded_rule
        );

        let mut engine = RuleEngine::new();
        engine.register(bounded_rule).unwrap();
        let bounded_result = engine.evaluate(&knowledge, &subject()).unwrap();
        assert_eq!(bounded_result[0].condition().evidence_ids().len(), 2);
        assert_eq!(
            bounded_result[0]
                .hypothesis()
                .unwrap()
                .belief()
                .evidence()
                .len(),
            1
        );
        assert_eq!(
            bounded_result[0].hypothesis().unwrap().belief().evidence()[0].evidence_id(),
            &strong_id
        );
        assert!(matches!(
            EvidenceAggregation::max_contributions(0),
            Err(RuleEngineError::InvalidAggregationLimit)
        ));
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
