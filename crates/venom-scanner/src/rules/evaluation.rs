use serde::Serialize;
use std::collections::BTreeMap;
use venom_core::{BayesianEvidence, EvidenceId, Hypothesis};

use crate::knowledge::{KnowledgeSnapshot, KnowledgeWrite};

use crate::rules::{
    expression::ExpressionEvaluation, hypothesis_id_for_rule, registry::ReasoningRule,
    RuleEngineError,
};

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
    pub(super) evaluation: RuleEvaluation,
    pub(super) write: Option<KnowledgeWrite>,
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

pub(super) fn evaluate_rule(
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
