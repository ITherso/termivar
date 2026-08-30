//! Deterministic expression evaluation and Bayesian reasoning rules.
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
//! Rules consume an immutable [`crate::KnowledgeSnapshot`]. They never execute
//! plugins, schedule scans, or mutate evidence. A matched rule may materialize
//! one stable, evidence-backed [`venom_core::Hypothesis`].

use thiserror::Error;
use venom_core::{EntityId, EvidenceId, HypothesisState, OntologyError, ReasoningModelError};

use crate::knowledge::KnowledgeBaseError;

mod engine;
mod evaluation;
mod expression;
mod registry;

pub use engine::RuleEngine;
pub use evaluation::{RuleApplication, RuleEvaluation};
pub use expression::{Expression, ExpressionEvaluation, ExpressionTrace, KnowledgeLayer};
pub use registry::{
    EvidenceAggregation, EvidenceCalibration, EvidenceSelector, HypothesisConclusion,
    ReasoningRule, RuleWrite,
};

#[cfg(test)]
use crate::knowledge::{KnowledgeBase, KnowledgeWrite};
#[cfg(test)]
use engine::MAX_REASONING_APPLY_ATTEMPTS;
#[cfg(test)]
use std::collections::BTreeSet;
#[cfg(test)]
use venom_core::{
    BayesianEvidence, ConceptId, EvidenceValue, Hypothesis, HypothesisStrength, KnowledgePredicate,
    Probability, RelationTypeId,
};

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

pub(super) fn non_empty(
    value: impl Into<String>,
    field: &'static str,
) -> Result<String, RuleEngineError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(RuleEngineError::EmptyValue { field });
    }
    Ok(value)
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
    fn all_and_any_preserve_truth_and_root_provenance() {
        let knowledge = KnowledgeBase::new();
        let matching = evidence(framework_predicate(), EvidenceValue::Text("Laravel".into()));
        let matching_id = matching.id().clone();
        knowledge.insert_evidence(matching).unwrap();
        let missing = KnowledgePredicate::new("security", "waf").unwrap();
        let snapshot = knowledge.snapshot_for_subject(&subject());

        let any = Expression::any(vec![
            Expression::equals(
                KnowledgeLayer::Evidence,
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ),
            Expression::exists(KnowledgeLayer::Evidence, missing.clone()),
        ])
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
        assert!(any.matched());
        assert_eq!(any.evidence_ids(), &BTreeSet::from([matching_id.clone()]));

        let all = Expression::all(vec![
            Expression::equals(
                KnowledgeLayer::Evidence,
                framework_predicate(),
                EvidenceValue::Text("Laravel".into()),
            ),
            Expression::exists(KnowledgeLayer::Evidence, missing),
        ])
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
        assert!(!all.matched());
        assert!(all.evidence_ids().is_empty());
        assert_eq!(
            all.trace().children()[0].evidence_ids(),
            &BTreeSet::from([matching_id])
        );
    }

    #[test]
    fn expression_wire_format_rejects_empty_groups() {
        assert!(Expression::all(Vec::new()).is_err());
        for operator in ["all", "any"] {
            assert!(serde_json::from_value::<Expression>(serde_json::json!({
                "op": operator,
                "expressions": []
            }))
            .is_err());
        }

        let leaf = Expression::exists(KnowledgeLayer::Evidence, framework_predicate());
        for expression in [
            Expression::all(vec![leaf.clone()]).unwrap(),
            Expression::any(vec![leaf]).unwrap(),
        ] {
            let wire = serde_json::to_value(&expression).unwrap();
            assert_eq!(
                serde_json::from_value::<Expression>(wire).unwrap(),
                expression
            );
        }
    }

    #[test]
    fn malformed_expression_wire_cannot_broaden_equals_to_exists() {
        let expression = Expression::equals(
            KnowledgeLayer::Evidence,
            framework_predicate(),
            EvidenceValue::Text("Laravel".into()),
        );
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence(
                framework_predicate(),
                EvidenceValue::Text("Apache".into()),
            ))
            .unwrap();
        assert!(!expression
            .evaluate(&knowledge.snapshot_for_subject(&subject()))
            .unwrap()
            .matched());
        let mut encoded = serde_json::to_value(&expression).unwrap();
        let value = encoded.as_object_mut().unwrap().remove("value").unwrap();
        let missing = encoded.clone();
        encoded["vlaue"] = value;

        assert!(serde_json::from_value::<Expression>(missing).is_err());
        assert!(serde_json::from_value::<Expression>(encoded).is_err());
    }

    #[test]
    fn expression_wire_requires_explicit_null_for_historical_exists() {
        let expression = Expression::exists(KnowledgeLayer::Evidence, framework_predicate());
        let encoded = serde_json::to_value(&expression).unwrap();
        assert!(encoded.get("value").is_some_and(serde_json::Value::is_null));
        assert_eq!(
            serde_json::from_value::<Expression>(encoded.clone()).unwrap(),
            expression
        );

        let mut missing = encoded.clone();
        missing.as_object_mut().unwrap().remove("value");
        assert!(serde_json::from_value::<Expression>(missing).is_err());

        let mut extended = encoded;
        extended["matcher_future"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Expression>(extended).is_err());
    }

    #[test]
    fn malformed_nested_expressions_cannot_broaden_a_reasoning_rule() {
        let mut encoded = serde_json::to_value(laravel_rule("wire.expression.strict")).unwrap();
        let first_claim = &mut encoded["condition"]["expressions"][0];
        let value = first_claim
            .as_object_mut()
            .unwrap()
            .remove("value")
            .unwrap();
        first_claim["vlaue"] = value;

        assert!(serde_json::from_value::<ReasoningRule>(encoded).is_err());

        let mut empty_all =
            serde_json::to_value(laravel_rule("wire.expression.empty-all")).unwrap();
        empty_all["condition"] = serde_json::json!({
            "op": "all",
            "expressions": []
        });
        assert!(serde_json::from_value::<ReasoningRule>(empty_all).is_err());

        let mut empty_contains =
            serde_json::to_value(laravel_rule("wire.expression.empty-contains")).unwrap();
        empty_contains["condition"] = serde_json::json!({
            "op": "text_contains",
            "layer": "evidence",
            "predicate": framework_predicate(),
            "needle": " ",
            "ascii_case_insensitive": false
        });
        assert!(serde_json::from_value::<ReasoningRule>(empty_contains).is_err());
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

        let mut empty_wire = serde_json::to_value(&expression).unwrap();
        empty_wire["needle"] = serde_json::json!(" ");
        assert!(serde_json::from_value::<Expression>(empty_wire).is_err());
    }

    fn form_controls() -> KnowledgePredicate {
        KnowledgePredicate::new("http.response", "form-control-names").unwrap()
    }

    fn evaluate_exact(value: EvidenceValue, target: &str) -> ExpressionEvaluation {
        let knowledge = KnowledgeBase::new();
        knowledge
            .insert_evidence(evidence(form_controls(), value))
            .unwrap();
        Expression::text_list_contains_exact(KnowledgeLayer::Evidence, form_controls(), target)
            .unwrap()
            .evaluate(&knowledge.snapshot_for_subject(&subject()))
            .unwrap()
    }

    fn list(values: &[&str]) -> EvidenceValue {
        EvidenceValue::TextList(values.iter().map(|value| (*value).to_owned()).collect())
    }

    #[test]
    fn text_list_contains_exact_matches_only_whole_elements() {
        // Exact element membership: the value equals a complete list element,
        // never a substring and never a scalar text fallback.
        assert!(evaluate_exact(list(&["_token", "email"]), "_token").matched());
        assert!(evaluate_exact(list(&["_method"]), "_method").matched());

        for (value, target) in [
            (list(&["_token_backup"]), "_token"),
            (list(&["_token_old"]), "_token"),
            (list(&["my_token"]), "_token"),
            (list(&[" _token "]), "_token"),
            (list(&["_METHOD"]), "_method"),
            (list(&[]), "_token"),
            // A scalar Text value never satisfies a list-membership predicate.
            (EvidenceValue::Text("_token".to_owned()), "_token"),
        ] {
            assert!(
                !evaluate_exact(value.clone(), target).matched(),
                "`{value:?}` must not contain-exact `{target}`"
            );
        }
    }

    #[test]
    fn text_list_contains_exact_attributes_only_the_contributing_evidence() {
        let knowledge = KnowledgeBase::new();
        let matching = evidence(form_controls(), list(&["email", "_token"]));
        let matching_id = matching.id().clone();
        let other = evidence(form_controls(), list(&["username", "_token_old"]));
        let other_id = other.id().clone();
        knowledge
            .insert_evidence_batch(vec![matching, other])
            .unwrap();

        let evaluation = Expression::text_list_contains_exact(
            KnowledgeLayer::Evidence,
            form_controls(),
            "_token",
        )
        .unwrap()
        .evaluate(&knowledge.snapshot_for_subject(&subject()))
        .unwrap();

        assert!(evaluation.matched());
        assert_eq!(evaluation.evidence_ids(), &BTreeSet::from([matching_id]));
        assert!(!evaluation.evidence_ids().contains(&other_id));
        assert!(evaluation.trace().label().contains("list-contains-exact"));
    }

    #[test]
    fn text_list_contains_exact_validates_and_round_trips() {
        let expression = Expression::text_list_contains_exact(
            KnowledgeLayer::Evidence,
            form_controls(),
            "_token",
        )
        .unwrap();
        let encoded = serde_json::to_value(&expression).unwrap();
        assert_eq!(encoded["op"], "text_list_contains_exact");
        assert_eq!(
            serde_json::from_value::<Expression>(encoded).unwrap(),
            expression
        );

        // Empty / whitespace-only values are rejected at both construction and
        // deserialization; values are never silently trimmed.
        assert!(Expression::text_list_contains_exact(
            KnowledgeLayer::Evidence,
            form_controls(),
            " "
        )
        .is_err());
        assert!(serde_json::from_value::<Expression>(serde_json::json!({
            "op": "text_list_contains_exact",
            "layer": "evidence",
            "predicate": form_controls(),
            "value": "   "
        }))
        .is_err());
    }

    #[test]
    fn text_list_evidence_selector_matches_validates_and_round_trips() {
        let selector =
            EvidenceSelector::text_list_contains_exact(form_controls(), "_token").unwrap();
        assert_eq!(selector.text_list_exact_value(), Some("_token"));

        // Exact element membership only: a list with the exact element matches; a
        // substring-only element and a scalar Text value do not.
        assert!(selector.matches(&evidence(form_controls(), list(&["_token", "email"]))));
        assert!(!selector.matches(&evidence(form_controls(), list(&["_token_old"]))));
        assert!(!selector.matches(&evidence(
            form_controls(),
            EvidenceValue::Text("_token".to_owned())
        )));

        let encoded = serde_json::to_value(&selector).unwrap();
        assert_eq!(encoded["text_list_contains_exact"], "_token");
        assert_eq!(
            serde_json::from_value::<EvidenceSelector>(encoded).unwrap(),
            selector
        );

        // Empty value rejected, and matchers are mutually exclusive on the wire.
        assert!(EvidenceSelector::text_list_contains_exact(form_controls(), " ").is_err());
        assert!(
            serde_json::from_value::<EvidenceSelector>(serde_json::json!({
                "predicate": form_controls(),
                "value": { "type": "text", "value": "_token" },
                "text_list_contains_exact": "_token"
            }))
            .is_err()
        );
    }

    #[test]
    fn malformed_evidence_selector_cannot_broaden_exact_matching_to_exists() {
        let selector =
            EvidenceSelector::text_list_contains_exact(form_controls(), "_token").unwrap();
        let mut encoded = serde_json::to_value(selector).unwrap();
        let matcher = encoded
            .as_object_mut()
            .unwrap()
            .remove("text_list_contains_exact")
            .unwrap();
        encoded["text_list_contians_exact"] = matcher;

        assert!(serde_json::from_value::<EvidenceSelector>(encoded).is_err());
    }

    #[test]
    fn selector_guard_preserves_history_and_rejects_tampering() {
        let selector =
            EvidenceSelector::text_list_contains_exact(form_controls(), "_token").unwrap();
        let encoded = serde_json::to_value(&selector).unwrap();
        assert_eq!(encoded["matcher_policy_guard"], true);

        let mut current_history = encoded.clone();
        current_history
            .as_object_mut()
            .unwrap()
            .remove("matcher_policy_guard");
        let restored: EvidenceSelector = serde_json::from_value(current_history).unwrap();
        assert_eq!(restored, selector);
        assert_eq!(
            serde_json::to_value(&restored).unwrap()["matcher_policy_guard"],
            true
        );

        let mut false_guard = encoded.clone();
        false_guard["matcher_policy_guard"] = serde_json::json!(false);
        assert!(serde_json::from_value::<EvidenceSelector>(false_guard).is_err());

        let mut missing_matcher = encoded.clone();
        missing_matcher
            .as_object_mut()
            .unwrap()
            .remove("text_list_contains_exact");
        assert!(serde_json::from_value::<EvidenceSelector>(missing_matcher).is_err());

        let exists = EvidenceSelector::exists(form_controls());
        let exists_wire = serde_json::to_value(&exists).unwrap();
        assert!(exists_wire.get("matcher_policy_guard").is_none());
        assert!(exists_wire
            .get("value")
            .is_some_and(serde_json::Value::is_null));
        assert_eq!(
            serde_json::from_value::<EvidenceSelector>(exists_wire.clone()).unwrap(),
            exists
        );

        let mut guarded_exists = exists_wire.clone();
        guarded_exists["matcher_policy_guard"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EvidenceSelector>(guarded_exists).is_err());

        let mut missing_nullable = exists_wire.clone();
        missing_nullable.as_object_mut().unwrap().remove("value");
        assert!(serde_json::from_value::<EvidenceSelector>(missing_nullable).is_err());

        let mut unknown_matcher = exists_wire;
        unknown_matcher["matcher_future"] = serde_json::json!("_token");
        assert!(serde_json::from_value::<EvidenceSelector>(unknown_matcher).is_err());
    }

    #[test]
    fn malformed_calibration_selector_cannot_gain_unrelated_provenance() {
        let mut encoded = serde_json::to_value(laravel_rule("wire.selector.strict")).unwrap();
        let selector = &mut encoded["conclusion"]["calibrations"][0]["selector"];
        let value = selector.as_object_mut().unwrap().remove("value").unwrap();
        selector["vlaue"] = value;

        assert!(serde_json::from_value::<ReasoningRule>(encoded).is_err());
    }

    #[test]
    fn exact_calibration_attributes_only_matching_condition_evidence() {
        let knowledge = KnowledgeBase::new();
        let predicate = framework_predicate();
        let laravel = evidence(predicate.clone(), EvidenceValue::Text("Laravel".into()));
        let laravel_id = laravel.id().clone();
        let apache = evidence(predicate.clone(), EvidenceValue::Text("Apache".into()));
        let apache_id = apache.id().clone();
        knowledge
            .insert_evidence_batch(vec![laravel, apache])
            .unwrap();

        let rule = ReasoningRule::new(
            "wire.selector.provenance",
            Expression::exists(KnowledgeLayer::Evidence, predicate.clone()),
            HypothesisConclusion::new(
                KnowledgePredicate::new("audit", "exact-selector").unwrap(),
                EvidenceValue::Boolean(true),
                Probability::from_percent(50).unwrap(),
                HypothesisStrength::Weak,
                HypothesisState::Supported,
                vec![EvidenceCalibration::new(
                    EvidenceSelector::equals(predicate, EvidenceValue::Text("Laravel".into())),
                    Probability::from_percent(90).unwrap(),
                    Probability::from_percent(10).unwrap(),
                    "exact framework",
                )
                .unwrap()],
            )
            .unwrap(),
        )
        .unwrap();
        let mut engine = RuleEngine::new();
        engine.register(rule).unwrap();

        let evaluations = engine.evaluate(&knowledge, &subject()).unwrap();
        let observations = evaluations[0].hypothesis().unwrap().belief().evidence();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].evidence_id(), &laravel_id);
        assert_ne!(observations[0].evidence_id(), &apache_id);
    }

    #[test]
    fn bounded_aggregation_wire_detects_single_field_policy_loss() {
        let bounded = calibration(
            framework_predicate(),
            EvidenceValue::Text("Laravel".into()),
            80,
            20,
        )
        .with_aggregation(EvidenceAggregation::max_contributions(1).unwrap());
        let encoded = serde_json::to_value(&bounded).unwrap();
        assert_eq!(encoded["aggregation_policy_guard"], true);

        let mut current_history = encoded.clone();
        current_history
            .as_object_mut()
            .unwrap()
            .remove("aggregation_policy_guard");
        let restored = serde_json::from_value::<EvidenceCalibration>(current_history).unwrap();
        assert_eq!(
            restored.aggregation(),
            EvidenceAggregation::max_contributions(1).unwrap()
        );
        assert_eq!(
            serde_json::to_value(restored).unwrap()["aggregation_policy_guard"],
            true
        );

        let mut false_guard = encoded.clone();
        false_guard["aggregation_policy_guard"] = serde_json::json!(false);
        assert!(serde_json::from_value::<EvidenceCalibration>(false_guard).is_err());

        let mut corrupted = encoded;
        corrupted.as_object_mut().unwrap().remove("aggregation");
        assert!(serde_json::from_value::<EvidenceCalibration>(corrupted).is_err());

        let independent = calibration(
            framework_predicate(),
            EvidenceValue::Text("Laravel".into()),
            80,
            20,
        );
        let mut guarded_independent = serde_json::to_value(independent).unwrap();
        assert!(guarded_independent
            .get("aggregation_policy_guard")
            .is_none());
        guarded_independent["aggregation_policy_guard"] = serde_json::json!(true);
        assert!(serde_json::from_value::<EvidenceCalibration>(guarded_independent).is_err());
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
    fn reasoning_rule_and_conclusion_reject_unknown_semantic_fields() {
        let rule = laravel_rule("wire.strict-container");

        let mut unknown_rule_field = serde_json::to_value(&rule).unwrap();
        unknown_rule_field["scope_future"] = serde_json::json!("global");
        assert!(serde_json::from_value::<ReasoningRule>(unknown_rule_field).is_err());

        let mut unknown_conclusion_field = serde_json::to_value(&rule).unwrap();
        unknown_conclusion_field["conclusion"]["transition_future"] =
            serde_json::json!("confirmed");
        assert!(serde_json::from_value::<ReasoningRule>(unknown_conclusion_field).is_err());

        assert_eq!(
            serde_json::from_value::<ReasoningRule>(serde_json::to_value(&rule).unwrap()).unwrap(),
            rule
        );
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
