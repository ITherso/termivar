use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use venom_core::{ConceptId, EvidenceId, EvidenceValue, KnowledgePredicate, RelationTypeId};

use crate::knowledge::KnowledgeSnapshot;

use crate::rules::{non_empty, RuleEngineError};

pub(super) fn is_false(value: &bool) -> bool {
    !*value
}

/// A nullable wire value whose field must nevertheless be present.
///
/// Serde treats a missing `Option<T>` field as `None`, which is unsafe where
/// `null` has an explicit meaning distinct from an omitted semantic field. The
/// transparent wrapper preserves the historical JSON shape while making field
/// omission a deserialization error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(super) struct RequiredNullable<T> {
    value: Option<T>,
    #[serde(skip)]
    present: bool,
}

impl<T> RequiredNullable<T> {
    fn present(value: Option<T>) -> Self {
        Self {
            value,
            present: true,
        }
    }

    fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub(super) fn is_present(&self) -> bool {
        self.present
    }

    pub(super) fn into_inner(self) -> Option<T> {
        self.value
    }
}

impl<T> Default for RequiredNullable<T> {
    fn default() -> Self {
        Self {
            value: None,
            present: false,
        }
    }
}

impl<'de, T> Deserialize<'de> for RequiredNullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self::present)
    }
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
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
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
        #[serde(default)]
        value: RequiredNullable<EvidenceValue>,
    },
    TextContains {
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        needle: String,
        ascii_case_insensitive: bool,
    },
    TextListContainsExact {
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        value: String,
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
/// Claim wire objects require `value` to be present: exact claims carry a typed
/// value and existence claims carry explicit `null`. Unknown fields reject, so
/// a misspelled exact value cannot broaden into existence.
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
            value: RequiredNullable::present(Some(value)),
        })
    }

    /// Matches the existence of a predicate in one knowledge layer.
    pub fn exists(layer: KnowledgeLayer, predicate: KnowledgePredicate) -> Self {
        Self(ExpressionNode::Claim {
            layer,
            predicate,
            value: RequiredNullable::present(None),
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

    /// Matches exact membership of a value in an [`EvidenceValue::TextList`].
    ///
    /// Unlike [`Self::text_contains`], this compares complete list elements with
    /// exact, case-sensitive string equality. It never performs substring
    /// matching and never falls back to a scalar [`EvidenceValue::Text`]: a
    /// record whose value is `Text("_token")` does not match, and a list element
    /// `"_token_old"` does not match the value `"_token"`. This keeps typed
    /// inventory reasoning fail-closed — only a record carrying the exact element
    /// contributes.
    pub fn text_list_contains_exact(
        layer: KnowledgeLayer,
        predicate: KnowledgePredicate,
        value: impl Into<String>,
    ) -> Result<Self, RuleEngineError> {
        Ok(Self(ExpressionNode::TextListContainsExact {
            layer,
            predicate,
            value: non_empty(value, "text-list exact value")?,
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
            ExpressionNode::Claim { layer, .. }
            | ExpressionNode::TextContains { layer, .. }
            | ExpressionNode::TextListContainsExact { layer, .. } => {
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
            ExpressionNode::Claim { value, .. } if !value.is_present() => {
                return Err(serde::de::Error::custom(
                    "claim expression value field must be present; use null for existence",
                ));
            },
            ExpressionNode::TextContains { needle, .. } if needle.trim().is_empty() => {
                return Err(serde::de::Error::custom(RuleEngineError::EmptyValue {
                    field: "text-match needle",
                }));
            },
            ExpressionNode::TextListContainsExact { value, .. } if value.trim().is_empty() => {
                return Err(serde::de::Error::custom(RuleEngineError::EmptyValue {
                    field: "text-list exact value",
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
        ExpressionNode::TextListContainsExact {
            layer,
            predicate,
            value,
        } => Ok(evaluate_text_list_contains_exact(
            *layer, predicate, value, snapshot,
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

pub(super) fn evidence_value_texts(value: &EvidenceValue) -> Box<dyn Iterator<Item = &str> + '_> {
    match value {
        EvidenceValue::Text(text) => Box::new(std::iter::once(text.as_str())),
        EvidenceValue::TextList(values) => Box::new(values.iter().map(String::as_str)),
        _ => Box::new(std::iter::empty()),
    }
}

pub(super) fn text_contains(value: &str, needle: &str, ascii_case_insensitive: bool) -> bool {
    if ascii_case_insensitive {
        value
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    } else {
        value.contains(needle)
    }
}

fn evaluate_text_list_contains_exact(
    layer: KnowledgeLayer,
    predicate: &KnowledgePredicate,
    value: &str,
    snapshot: &KnowledgeSnapshot,
) -> ExpressionTrace {
    let matches_list = |candidate: &EvidenceValue| text_list_contains_exact(candidate, value);
    let mut evidence_ids = BTreeSet::new();
    let matched = match layer {
        KnowledgeLayer::Evidence => {
            let matches: Vec<_> = snapshot
                .evidence()
                .iter()
                .filter(|evidence| {
                    evidence.predicate() == predicate && matches_list(evidence.value())
                })
                .collect();
            evidence_ids.extend(matches.iter().map(|evidence| evidence.id().clone()));
            !matches.is_empty()
        },
        KnowledgeLayer::Fact => {
            let matches: Vec<_> = snapshot
                .facts()
                .iter()
                .filter(|fact| fact.predicate() == predicate && matches_list(fact.value()))
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
                    hypothesis.predicate() == predicate && matches_list(hypothesis.value())
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

    ExpressionTrace {
        label: format!(
            "{layer:?}:{}:list-contains-exact:{value}",
            predicate.dotted()
        ),
        matched,
        evidence_ids,
        children: Vec::new(),
    }
}

/// Exact membership in a text list. Matches only [`EvidenceValue::TextList`]
/// with element-wise, case-sensitive equality — never a scalar text value and
/// never a substring.
pub(super) fn text_list_contains_exact(value: &EvidenceValue, target: &str) -> bool {
    matches!(
        value,
        EvidenceValue::TextList(values) if values.iter().any(|element| element == target)
    )
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
