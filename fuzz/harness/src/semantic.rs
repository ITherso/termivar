use std::collections::BTreeSet;

use serde_json::Value;
use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    HypothesisState, HypothesisStrength, KnowledgePredicate, OutcomeStatus, Probability,
    VerificationStage,
};
use termivar_scanner::{
    AdaptationRule, EvidenceAggregation, EvidenceCalibration, EvidenceSelector, Expression,
    HypothesisConclusion, KnowledgeBase, KnowledgeLayer, OutcomeSelector, PipelineDirective,
    ReasoningRule, RuleEngine, RuleEngineError, VerificationCase, VerificationRule,
};

/// Maximum byte buffer accepted by either declarative-semantic harness.
pub const MAX_SEMANTIC_FUZZ_INPUT_BYTES: usize = 16 * 1024;
/// Maximum expression-operator depth generated or accepted by the harness.
pub const MAX_EXPRESSION_FUZZ_DEPTH: usize = 32;
/// Maximum expression operators accepted from a structured JSON candidate.
pub const MAX_EXPRESSION_FUZZ_NODES: usize = 64;
/// Maximum byte length of a generated or accepted semantic string.
pub const MAX_SEMANTIC_FUZZ_STRING_BYTES: usize = 256;

const MAX_LIST_RECORDS: usize = 8;
const MAX_VALUES_PER_LIST: usize = 8;

macro_rules! assert_round_trip {
    ($type:ty, $value:expr) => {{
        let source = &$value;
        let wire = serde_json::to_value(source).expect("canonical policy serialization failed");
        let decoded: $type =
            serde_json::from_value(wire.clone()).expect("canonical policy deserialization failed");
        assert_eq!(&decoded, source, "wire round trip changed policy semantics");
        assert_eq!(
            serde_json::to_value(&decoded).expect("round-tripped policy serialization failed"),
            wire,
            "canonical wire round trip was unstable"
        );
    }};
}

macro_rules! assert_rejected {
    ($type:ty, $wire:expr, $reason:expr) => {{
        let wire = $wire;
        assert!(
            serde_json::from_value::<$type>(wire.clone()).is_err(),
            "{} must fail closed, but was accepted: {}",
            $reason,
            wire
        );
    }};
}

macro_rules! assert_equivalent {
    ($type:ty, $source:expr, $wire:expr, $reason:expr) => {{
        let wire = $wire;
        let decoded: $type = serde_json::from_value(wire.clone()).unwrap_or_else(|error| {
            panic!(
                "{} should remain historically readable: {error}: {wire}",
                $reason
            )
        });
        assert_eq!(
            decoded, $source,
            "{} changed policy semantics instead of remaining equivalent",
            $reason
        );
    }};
}

/// Exercises exact expression/list semantics, deterministic evaluation, honest
/// evidence attribution, and accepted-wire round trips on bounded input.
pub fn check_expression_semantics(data: &[u8]) {
    if data.len() > MAX_SEMANTIC_FUZZ_INPUT_BYTES {
        return;
    }

    let root = bounded_json(data);
    let model = ExpressionModel::from_input(root.as_ref(), data);
    let fixture = EvidenceFixture::new(&model);
    let snapshot = fixture.knowledge.snapshot_for_subject(&fixture.subject);
    let expression = Expression::text_list_contains_exact(
        KnowledgeLayer::Evidence,
        fixture.predicate.clone(),
        model.needle.clone(),
    )
    .expect("bounded non-empty fuzz needle must construct");

    let first = expression
        .evaluate(&snapshot)
        .expect("evidence-only exact expression evaluation must succeed");
    let repeated = expression
        .evaluate(&snapshot)
        .expect("repeated exact expression evaluation must succeed");
    assert_eq!(
        first, repeated,
        "identical snapshots must evaluate identically"
    );
    assert_eq!(first.matched(), !fixture.expected_ids.is_empty());
    assert_eq!(
        first.evidence_ids(),
        &fixture.expected_ids,
        "only TextList records containing a complete, case-sensitive element may contribute"
    );
    assert!(!first.evidence_ids().contains(&fixture.scalar_id));
    assert!(!first.evidence_ids().contains(&fixture.other_predicate_id));

    let wire = serde_json::to_value(&expression).expect("expression serialization must succeed");
    let decoded: Expression =
        serde_json::from_value(wire.clone()).expect("canonical expression must deserialize");
    assert_eq!(
        decoded, expression,
        "expression round trip changed semantics"
    );
    assert_eq!(
        decoded
            .evaluate(&snapshot)
            .expect("round-tripped expression evaluation must succeed"),
        first
    );
    for group in [
        Expression::all(vec![expression.clone()]).expect("non-empty all must construct"),
        Expression::any(vec![expression.clone()]).expect("non-empty any must construct"),
    ] {
        let wire = serde_json::to_value(&group).expect("expression group must serialize");
        let decoded: Expression =
            serde_json::from_value(wire).expect("non-empty expression group must deserialize");
        assert_eq!(decoded, group, "group round trip changed semantics");
    }

    check_bounded_nested_expression(&expression, &snapshot, model.depth);
    check_selector_oracle(&fixture, &model);
    check_expression_corruption(&expression, root.as_ref(), data);
    check_embedded_expression(root.as_ref(), &snapshot);

    assert!(Expression::text_list_contains_exact(
        KnowledgeLayer::Evidence,
        fixture.predicate.clone(),
        ""
    )
    .is_err());
    assert!(Expression::text_list_contains_exact(
        KnowledgeLayer::Evidence,
        fixture.predicate.clone(),
        "   "
    )
    .is_err());
}

/// Exercises fail-closed compatibility guards and strict semantic fields by
/// corrupting one field of known-valid declarative objects. Every accepted
/// historical form must deserialize to semantics exactly equal to the source.
pub fn check_declarative_policy_wire(data: &[u8]) {
    if data.len() > MAX_SEMANTIC_FUZZ_INPUT_BYTES {
        return;
    }

    let root = bounded_json(data);
    let token = input_token(root.as_ref(), data);
    let predicate = KnowledgePredicate::new("fuzz.form", "control_names")
        .expect("fixed predicate must be valid");
    let expression = Expression::text_list_contains_exact(
        KnowledgeLayer::Evidence,
        predicate.clone(),
        token.clone(),
    )
    .expect("bounded non-empty fuzz token must construct");

    let selector = EvidenceSelector::text_list_contains_exact(predicate.clone(), token.clone())
        .expect("bounded non-empty selector token must construct");
    let calibration = EvidenceCalibration::new(
        selector.clone(),
        Probability::from_percent(80).expect("fixed probability must be valid"),
        Probability::from_percent(20).expect("fixed probability must be valid"),
        "exact list calibration",
    )
    .expect("fixed calibration must be valid")
    .with_aggregation(
        EvidenceAggregation::max_contributions(1).expect("fixed aggregation limit must be valid"),
    );
    let reasoning_rule = ReasoningRule::new(
        "fuzz.reasoning",
        expression.clone(),
        HypothesisConclusion::new(
            KnowledgePredicate::new("fuzz.profile", "detected")
                .expect("fixed conclusion predicate must be valid"),
            EvidenceValue::Boolean(true),
            Probability::from_percent(50).expect("fixed prior must be valid"),
            HypothesisStrength::Strong,
            HypothesisState::Supported,
            vec![calibration.clone()],
        )
        .expect("fixed conclusion must be valid"),
    )
    .expect("fixed reasoning rule must be valid");
    let action_id = format!("action.{token}");
    let verification_rule = VerificationRule::new(
        "fuzz.verification",
        VerificationStage::Passive,
        100,
        expression.clone(),
        OutcomeStatus::Success,
        Probability::from_percent(90).expect("fixed confidence must be valid"),
        "exact evidence verifies the action",
    )
    .expect("fixed verification rule must be valid")
    .scoped_to_action(action_id.clone())
    .expect("bounded action identity must be valid")
    .with_case_correlated_evidence()
    .expect("evidence-only condition supports case correlation");
    let verification_case = VerificationCase::new(
        "fuzz.case",
        EntityId::new("endpoint:https://fuzz.invalid").expect("fixed subject must be valid"),
        action_id.clone(),
        "hypothesis:fuzz",
    )
    .expect("fixed verification case must be valid")
    .without_hypothesis_transition();
    let outcome_selector = OutcomeSelector::new(
        BTreeSet::from([OutcomeStatus::Success]),
        BTreeSet::from([VerificationStage::Passive]),
    )
    .expect("fixed outcome selector must be valid");
    let adaptation_rule = AdaptationRule::new(
        "fuzz.adaptation",
        outcome_selector,
        100,
        Some(expression),
        PipelineDirective::ScheduleAction {
            action_id: format!("next.{token}"),
        },
        "schedule only when the exact condition matches",
        2,
    )
    .expect("fixed adaptation rule must be valid");

    assert_round_trip!(EvidenceSelector, selector);
    assert_round_trip!(EvidenceCalibration, calibration);
    assert_round_trip!(ReasoningRule, reasoning_rule);
    assert_round_trip!(VerificationRule, verification_rule);
    assert_round_trip!(VerificationCase, verification_case);
    assert_round_trip!(AdaptationRule, adaptation_rule);

    let scenario = policy_scenario(root.as_ref(), data);
    match scenario {
        PolicyScenario::SelectorMatcherDeleted => {
            let mut wire = serde_json::to_value(&selector).unwrap();
            object_mut(&mut wire).remove("text_list_contains_exact");
            assert_rejected!(EvidenceSelector, wire, "deleting an exact matcher");
        },
        PolicyScenario::SelectorMatcherTypo => {
            let mut wire = serde_json::to_value(&selector).unwrap();
            rename_field(
                &mut wire,
                "text_list_contains_exact",
                "text_list_contians_exact",
            );
            assert_rejected!(EvidenceSelector, wire, "misspelling an exact matcher");
        },
        PolicyScenario::SelectorMatcherNull => {
            let exact =
                EvidenceSelector::equals(predicate.clone(), EvidenceValue::Text(token.clone()));
            let mut wire = serde_json::to_value(&exact).unwrap();
            object_mut(&mut wire).insert("value".into(), Value::Null);
            assert_rejected!(EvidenceSelector, wire, "replacing exact equality with null");
        },
        PolicyScenario::SelectorMatchersConflict => {
            let mut wire = serde_json::to_value(&selector).unwrap();
            object_mut(&mut wire).insert(
                "value".into(),
                serde_json::to_value(EvidenceValue::Text(token.clone())).unwrap(),
            );
            assert_rejected!(EvidenceSelector, wire, "combining incompatible matchers");
        },
        PolicyScenario::SelectorValueTypo => {
            let exact =
                EvidenceSelector::equals(predicate.clone(), EvidenceValue::Text(token.clone()));
            let mut wire = serde_json::to_value(&exact).unwrap();
            rename_field(&mut wire, "value", "vlaue");
            assert_rejected!(EvidenceSelector, wire, "misspelling an exact value");
        },
        PolicyScenario::AggregationDeleted => {
            let mut wire = serde_json::to_value(&calibration).unwrap();
            object_mut(&mut wire).remove("aggregation");
            assert_rejected!(
                EvidenceCalibration,
                wire,
                "deleting a bounded aggregation policy"
            );
        },
        PolicyScenario::AggregationTypo => {
            let mut wire = serde_json::to_value(&calibration).unwrap();
            rename_field(&mut wire, "aggregation", "aggregration");
            assert_rejected!(
                EvidenceCalibration,
                wire,
                "misspelling a bounded aggregation policy"
            );
        },
        PolicyScenario::AggregationGuardDeleted => {
            let mut wire = serde_json::to_value(&calibration).unwrap();
            object_mut(&mut wire).remove("aggregation_policy_guard");
            assert_equivalent!(
                EvidenceCalibration,
                calibration,
                wire,
                "guardless historical bounded calibration"
            );
        },
        PolicyScenario::ReasoningConditionDeleted => {
            let mut wire = serde_json::to_value(&reasoning_rule).unwrap();
            object_mut(&mut wire).remove("condition");
            assert_rejected!(ReasoningRule, wire, "deleting a reasoning condition");
        },
        PolicyScenario::ReasoningConditionTypo => {
            let mut wire = serde_json::to_value(&reasoning_rule).unwrap();
            rename_field(&mut wire, "condition", "conditon");
            assert_rejected!(ReasoningRule, wire, "misspelling a reasoning condition");
        },
        PolicyScenario::VerificationActionDeleted => {
            let mut wire = serde_json::to_value(&verification_rule).unwrap();
            object_mut(&mut wire).remove("action_id");
            assert_rejected!(
                VerificationRule,
                wire,
                "deleting a verification action restriction"
            );
        },
        PolicyScenario::VerificationActionTypo => {
            let mut wire = serde_json::to_value(&verification_rule).unwrap();
            rename_field(&mut wire, "action_id", "actoin_id");
            assert_rejected!(
                VerificationRule,
                wire,
                "misspelling a verification action restriction"
            );
        },
        PolicyScenario::VerificationCorrelationDeleted => {
            let mut wire = serde_json::to_value(&verification_rule).unwrap();
            object_mut(&mut wire).remove("case_correlated_evidence");
            assert_rejected!(
                VerificationRule,
                wire,
                "deleting a verification case-correlation restriction"
            );
        },
        PolicyScenario::VerificationGuardDeleted => {
            let mut wire = serde_json::to_value(&verification_rule).unwrap();
            object_mut(&mut wire).remove("verification_scope_guard");
            assert_equivalent!(
                VerificationRule,
                verification_rule,
                wire,
                "guardless historical scoped verification rule"
            );
        },
        PolicyScenario::VerificationCaseTargetUnknown => {
            let mut wire = serde_json::to_value(&verification_case).unwrap();
            object_mut(&mut wire).insert(
                "verification_target".into(),
                Value::String("knowledge_only".into()),
            );
            assert_rejected!(
                VerificationCase,
                wire,
                "unknown verification policy field on a case"
            );
        },
        PolicyScenario::VerificationCaseGuardDeleted => {
            let mut wire = serde_json::to_value(&verification_case).unwrap();
            object_mut(&mut wire).remove("payload_claim_policy_guard");
            assert_rejected!(
                VerificationCase,
                wire,
                "deleting a knowledge-only case guard"
            );
        },
        PolicyScenario::AdaptationConditionDeleted => {
            let mut wire = serde_json::to_value(&adaptation_rule).unwrap();
            object_mut(&mut wire).remove("condition");
            assert_rejected!(AdaptationRule, wire, "deleting an adaptation condition");
        },
        PolicyScenario::AdaptationConditionTypo => {
            let mut wire = serde_json::to_value(&adaptation_rule).unwrap();
            rename_field(&mut wire, "condition", "conditon");
            assert_rejected!(AdaptationRule, wire, "misspelling an adaptation condition");
        },
        PolicyScenario::AdaptationConditionNull => {
            let mut wire = serde_json::to_value(&adaptation_rule).unwrap();
            object_mut(&mut wire).insert("condition".into(), Value::Null);
            assert_rejected!(
                AdaptationRule,
                wire,
                "replacing a guarded adaptation condition with null"
            );
        },
        PolicyScenario::AdaptationGuardDeleted => {
            let mut wire = serde_json::to_value(&adaptation_rule).unwrap();
            object_mut(&mut wire).remove("condition_policy_guard");
            assert_equivalent!(
                AdaptationRule,
                adaptation_rule,
                wire,
                "guardless historical conditional adaptation rule"
            );
        },
        PolicyScenario::PipelineScheduleEmpty => {
            let wire = serde_json::json!({
                "directive": "schedule_action",
                "action_id": ""
            });
            assert_rejected!(PipelineDirective, wire, "empty scheduled action identity");
        },
        PolicyScenario::PipelineDirectiveUnknown => {
            let wire = serde_json::json!({
                "directive": "schedule_actoin",
                "action_id": action_id
            });
            assert_rejected!(PipelineDirective, wire, "unknown adaptation directive");
        },
    }
}

fn check_bounded_nested_expression(
    expression: &Expression,
    snapshot: &termivar_scanner::KnowledgeSnapshot,
    depth: usize,
) {
    let mut nested = expression.clone();
    for _ in 0..depth.min(MAX_EXPRESSION_FUZZ_DEPTH) {
        nested = Expression::negate(nested);
    }
    let first = nested.evaluate(snapshot);
    let second = nested.evaluate(snapshot);
    assert_same_evaluation(first, second);

    let wire = serde_json::to_value(&nested).expect("bounded nested expression must serialize");
    let decoded: Expression =
        serde_json::from_value(wire).expect("bounded nested expression must deserialize");
    assert_eq!(decoded, nested);
    assert_same_evaluation(nested.evaluate(snapshot), decoded.evaluate(snapshot));
}

fn assert_same_evaluation(
    left: Result<termivar_scanner::ExpressionEvaluation, RuleEngineError>,
    right: Result<termivar_scanner::ExpressionEvaluation, RuleEngineError>,
) {
    match (left, right) {
        (Ok(left), Ok(right)) => assert_eq!(left, right),
        (Err(left), Err(right)) => assert_eq!(left.to_string(), right.to_string()),
        (left, right) => panic!("identical expression evaluations diverged: {left:?} vs {right:?}"),
    }
}

fn check_selector_oracle(fixture: &EvidenceFixture, model: &ExpressionModel) {
    let condition = Expression::exists(KnowledgeLayer::Evidence, fixture.predicate.clone());
    let selector =
        EvidenceSelector::text_list_contains_exact(fixture.predicate.clone(), model.needle.clone())
            .expect("bounded selector needle must construct");
    let calibration = EvidenceCalibration::new(
        selector,
        Probability::from_percent(80).unwrap(),
        Probability::from_percent(20).unwrap(),
        "exact list membership",
    )
    .unwrap();
    let conclusion = HypothesisConclusion::new(
        KnowledgePredicate::new("fuzz.profile", "exact_list_seen").unwrap(),
        EvidenceValue::Boolean(true),
        Probability::from_percent(50).unwrap(),
        HypothesisStrength::Strong,
        HypothesisState::Supported,
        vec![calibration],
    )
    .unwrap();
    let rule = ReasoningRule::new("fuzz.exact-list", condition, conclusion).unwrap();
    let mut engine = RuleEngine::new();
    engine.register(rule).unwrap();

    let result = engine.evaluate(&fixture.knowledge, &fixture.subject);
    if fixture.expected_ids.is_empty() {
        assert!(
            matches!(
                result,
                Err(RuleEngineError::MissingCalibratedEvidence { .. })
            ),
            "substring/scalar-only evidence must not materialize an exact-list hypothesis"
        );
        return;
    }

    let evaluations = result.expect("exact-list contributors must materialize a hypothesis");
    let hypothesis = evaluations[0]
        .hypothesis()
        .expect("matched exact-list rule must have a hypothesis");
    let actual_ids: BTreeSet<_> = hypothesis
        .belief()
        .evidence()
        .iter()
        .map(|observation| observation.evidence_id().clone())
        .collect();
    assert_eq!(
        actual_ids, fixture.expected_ids,
        "calibration provenance must cite exactly the matching TextList records"
    );
}

fn check_expression_corruption(expression: &Expression, root: Option<&Value>, data: &[u8]) {
    let scenario = root
        .and_then(|value| value.get("scenario"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let choice = match scenario {
        "claim_value_deleted" => 0,
        "claim_value_typo" => 1,
        "claim_unknown_field" => 2,
        "claim_value_type_changed" => 3,
        "empty_all" => 4,
        "empty_any" => 5,
        "blank_text_contains" => 6,
        _ => usize::from(data.first().copied().unwrap_or(0)) % 7,
    };
    let exact = Expression::equals(
        KnowledgeLayer::Evidence,
        KnowledgePredicate::new("fuzz", "claim").unwrap(),
        EvidenceValue::Text("expected".into()),
    );
    let mut wire = serde_json::to_value(exact).unwrap();
    match choice {
        0 => {
            object_mut(&mut wire).remove("value");
        },
        1 => rename_field(&mut wire, "value", "vlaue"),
        2 => {
            object_mut(&mut wire).insert("value_typo".into(), Value::Bool(true));
        },
        3 => {
            object_mut(&mut wire).insert("value".into(), Value::Bool(true));
        },
        4 => {
            wire = serde_json::json!({
                "op": "all",
                "expressions": []
            });
        },
        5 => {
            wire = serde_json::json!({
                "op": "any",
                "expressions": []
            });
        },
        6 => {
            wire = serde_json::json!({
                "op": "text_contains",
                "layer": "evidence",
                "predicate": {
                    "namespace": "fuzz",
                    "name": "claim"
                },
                "needle": " ",
                "ascii_case_insensitive": false
            });
        },
        _ => unreachable!(),
    }
    assert_rejected!(Expression, wire, "corrupting an exact expression claim");

    let canonical = serde_json::to_value(expression).unwrap();
    let decoded: Expression = serde_json::from_value(canonical).unwrap();
    assert_eq!(&decoded, expression);
}

fn check_embedded_expression(root: Option<&Value>, snapshot: &termivar_scanner::KnowledgeSnapshot) {
    let Some(candidate) = root.and_then(|value| value.get("expression")) else {
        return;
    };
    if !expression_shape_within_limits(candidate) {
        return;
    }
    let Ok(expression) = serde_json::from_value::<Expression>(candidate.clone()) else {
        return;
    };
    let wire = serde_json::to_value(&expression).expect("accepted expression must serialize");
    let decoded: Expression =
        serde_json::from_value(wire).expect("accepted expression must round trip");
    assert_eq!(decoded, expression);
    assert_same_evaluation(expression.evaluate(snapshot), decoded.evaluate(snapshot));
}

#[derive(Debug)]
struct ExpressionModel {
    needle: String,
    lists: Vec<Vec<String>>,
    depth: usize,
}

impl ExpressionModel {
    fn from_input(root: Option<&Value>, data: &[u8]) -> Self {
        let needle = root
            .and_then(|value| value.get("needle"))
            .and_then(Value::as_str)
            .map(bounded_string)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| derived_token(data));
        let lists = root
            .and_then(|value| value.get("lists"))
            .and_then(Value::as_array)
            .map(|lists| {
                lists
                    .iter()
                    .take(MAX_LIST_RECORDS)
                    .filter_map(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .take(MAX_VALUES_PER_LIST)
                            .filter_map(Value::as_str)
                            .map(bounded_string)
                            .collect()
                    })
                    .collect()
            })
            .unwrap_or_else(|| derived_lists(data, &needle));
        let depth = root
            .and_then(|value| value.get("depth"))
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or_else(|| usize::from(data.first().copied().unwrap_or(0)))
            .min(MAX_EXPRESSION_FUZZ_DEPTH);
        Self {
            needle,
            lists,
            depth,
        }
    }
}

struct EvidenceFixture {
    knowledge: KnowledgeBase,
    subject: EntityId,
    predicate: KnowledgePredicate,
    expected_ids: BTreeSet<EvidenceId>,
    scalar_id: EvidenceId,
    other_predicate_id: EvidenceId,
}

impl EvidenceFixture {
    fn new(model: &ExpressionModel) -> Self {
        let knowledge = KnowledgeBase::new();
        let subject = EntityId::new("endpoint:https://fuzz.invalid").unwrap();
        let predicate = KnowledgePredicate::new("fuzz.form", "control_names").unwrap();
        let mut expected_ids = BTreeSet::new();

        for (index, values) in model.lists.iter().enumerate() {
            let id = EvidenceId::parse(format!("fuzz-list-{index}")).unwrap();
            if values.iter().any(|value| value == &model.needle) {
                expected_ids.insert(id.clone());
            }
            insert_evidence(
                &knowledge,
                id,
                subject.clone(),
                predicate.clone(),
                EvidenceValue::TextList(values.clone()),
            );
        }

        let scalar_id = EvidenceId::parse("fuzz-scalar-exact").unwrap();
        insert_evidence(
            &knowledge,
            scalar_id.clone(),
            subject.clone(),
            predicate.clone(),
            EvidenceValue::Text(model.needle.clone()),
        );
        let other_predicate_id = EvidenceId::parse("fuzz-other-predicate").unwrap();
        insert_evidence(
            &knowledge,
            other_predicate_id.clone(),
            subject.clone(),
            KnowledgePredicate::new("fuzz.form", "other_control_names").unwrap(),
            EvidenceValue::TextList(vec![model.needle.clone()]),
        );

        Self {
            knowledge,
            subject,
            predicate,
            expected_ids,
            scalar_id,
            other_predicate_id,
        }
    }
}

fn insert_evidence(
    knowledge: &KnowledgeBase,
    id: EvidenceId,
    subject: EntityId,
    predicate: KnowledgePredicate,
    value: EvidenceValue,
) {
    let evidence = Evidence::with_id_at(
        id,
        subject,
        EvidenceKind::Http,
        predicate,
        value,
        EvidenceSource::new("fuzz.semantic", "structured-model").unwrap(),
        ConfidenceScore::from_percent(90).unwrap(),
        1,
    );
    knowledge
        .insert_evidence(evidence)
        .expect("unique deterministic fuzz evidence must insert");
}

#[derive(Debug, Clone, Copy)]
enum PolicyScenario {
    SelectorMatcherDeleted,
    SelectorMatcherTypo,
    SelectorMatcherNull,
    SelectorMatchersConflict,
    SelectorValueTypo,
    AggregationDeleted,
    AggregationTypo,
    AggregationGuardDeleted,
    ReasoningConditionDeleted,
    ReasoningConditionTypo,
    VerificationActionDeleted,
    VerificationActionTypo,
    VerificationCorrelationDeleted,
    VerificationGuardDeleted,
    VerificationCaseTargetUnknown,
    VerificationCaseGuardDeleted,
    AdaptationConditionDeleted,
    AdaptationConditionTypo,
    AdaptationConditionNull,
    AdaptationGuardDeleted,
    PipelineScheduleEmpty,
    PipelineDirectiveUnknown,
}

const POLICY_SCENARIOS: [PolicyScenario; 22] = [
    PolicyScenario::SelectorMatcherDeleted,
    PolicyScenario::SelectorMatcherTypo,
    PolicyScenario::SelectorMatcherNull,
    PolicyScenario::SelectorMatchersConflict,
    PolicyScenario::SelectorValueTypo,
    PolicyScenario::AggregationDeleted,
    PolicyScenario::AggregationTypo,
    PolicyScenario::AggregationGuardDeleted,
    PolicyScenario::ReasoningConditionDeleted,
    PolicyScenario::ReasoningConditionTypo,
    PolicyScenario::VerificationActionDeleted,
    PolicyScenario::VerificationActionTypo,
    PolicyScenario::VerificationCorrelationDeleted,
    PolicyScenario::VerificationGuardDeleted,
    PolicyScenario::VerificationCaseTargetUnknown,
    PolicyScenario::VerificationCaseGuardDeleted,
    PolicyScenario::AdaptationConditionDeleted,
    PolicyScenario::AdaptationConditionTypo,
    PolicyScenario::AdaptationConditionNull,
    PolicyScenario::AdaptationGuardDeleted,
    PolicyScenario::PipelineScheduleEmpty,
    PolicyScenario::PipelineDirectiveUnknown,
];

fn policy_scenario(root: Option<&Value>, data: &[u8]) -> PolicyScenario {
    let named = root
        .and_then(|value| value.get("scenario"))
        .and_then(Value::as_str);
    match named {
        Some("selector_matcher_deleted") => PolicyScenario::SelectorMatcherDeleted,
        Some("selector_matcher_typo") => PolicyScenario::SelectorMatcherTypo,
        Some("selector_matcher_null") => PolicyScenario::SelectorMatcherNull,
        Some("selector_matchers_conflict") => PolicyScenario::SelectorMatchersConflict,
        Some("selector_value_typo") => PolicyScenario::SelectorValueTypo,
        Some("aggregation_deleted") => PolicyScenario::AggregationDeleted,
        Some("aggregation_typo") => PolicyScenario::AggregationTypo,
        Some("aggregation_guard_deleted") => PolicyScenario::AggregationGuardDeleted,
        Some("reasoning_condition_deleted") => PolicyScenario::ReasoningConditionDeleted,
        Some("reasoning_condition_typo") => PolicyScenario::ReasoningConditionTypo,
        Some("verification_action_deleted") => PolicyScenario::VerificationActionDeleted,
        Some("verification_action_typo") => PolicyScenario::VerificationActionTypo,
        Some("verification_correlation_deleted") => PolicyScenario::VerificationCorrelationDeleted,
        Some("verification_guard_deleted") => PolicyScenario::VerificationGuardDeleted,
        Some("verification_case_target_unknown") => PolicyScenario::VerificationCaseTargetUnknown,
        Some("verification_case_guard_deleted") => PolicyScenario::VerificationCaseGuardDeleted,
        Some("adaptation_condition_deleted") => PolicyScenario::AdaptationConditionDeleted,
        Some("adaptation_condition_typo") => PolicyScenario::AdaptationConditionTypo,
        Some("adaptation_condition_null") => PolicyScenario::AdaptationConditionNull,
        Some("adaptation_guard_deleted") => PolicyScenario::AdaptationGuardDeleted,
        Some("pipeline_schedule_empty") => PolicyScenario::PipelineScheduleEmpty,
        Some("pipeline_directive_unknown") => PolicyScenario::PipelineDirectiveUnknown,
        _ => {
            POLICY_SCENARIOS
                [usize::from(data.first().copied().unwrap_or(0)) % POLICY_SCENARIOS.len()]
        },
    }
}

fn bounded_json(data: &[u8]) -> Option<Value> {
    let value = serde_json::from_slice::<Value>(data).ok()?;
    json_shape_within_limits(&value).then_some(value)
}

fn json_shape_within_limits(root: &Value) -> bool {
    let mut nodes = 0usize;
    let mut pending = vec![(root, 1usize)];
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_EXPRESSION_FUZZ_NODES || depth > MAX_EXPRESSION_FUZZ_DEPTH * 2 {
            return false;
        }
        match value {
            Value::String(value) => {
                if value.len() > MAX_SEMANTIC_FUZZ_STRING_BYTES {
                    return false;
                }
            },
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            },
            Value::Object(values) => {
                if values
                    .keys()
                    .any(|key| key.len() > MAX_SEMANTIC_FUZZ_STRING_BYTES)
                {
                    return false;
                }
                pending.extend(values.values().map(|value| (value, depth + 1)));
            },
            Value::Null | Value::Bool(_) | Value::Number(_) => {},
        }
    }
    true
}

fn expression_shape_within_limits(root: &Value) -> bool {
    if !json_shape_within_limits(root) {
        return false;
    }
    let mut nodes = 0usize;
    let mut pending = vec![(root, 1usize)];
    while let Some((value, depth)) = pending.pop() {
        let Some(object) = value.as_object() else {
            return false;
        };
        if object.get("op").and_then(Value::as_str).is_none() {
            return false;
        }
        nodes += 1;
        if nodes > MAX_EXPRESSION_FUZZ_NODES || depth > MAX_EXPRESSION_FUZZ_DEPTH {
            return false;
        }
        if let Some(children) = object.get("expressions").and_then(Value::as_array) {
            pending.extend(children.iter().map(|child| (child, depth + 1)));
        }
        if let Some(child) = object.get("expression") {
            pending.push((child, depth + 1));
        }
    }
    true
}

fn input_token(root: Option<&Value>, data: &[u8]) -> String {
    let token = root
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .map(bounded_string)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| derived_token(data));
    bounded_string_to(&token, MAX_SEMANTIC_FUZZ_STRING_BYTES - 32)
}

fn derived_token(data: &[u8]) -> String {
    let source = data.get(1..).unwrap_or_default();
    let mut token: String = source
        .iter()
        .take(64)
        .map(|byte| match byte % 39 {
            0 => '_',
            1 => '-',
            2 => ' ',
            3 => '\u{00e9}',
            4 => '\u{540d}',
            value @ 5..=14 => char::from(b'0' + (value - 5)),
            value => char::from(b'a' + (value - 15)),
        })
        .collect();
    if token.trim().is_empty() {
        token = "_token".into();
    }
    bounded_string(&token)
}

fn derived_lists(data: &[u8], needle: &str) -> Vec<Vec<String>> {
    let mut lists = vec![
        vec![format!("{needle}_backup")],
        vec![format!(" {needle} ")],
        vec![needle.to_ascii_uppercase()],
    ];
    if data.first().copied().unwrap_or(0) & 1 == 0 {
        lists.push(vec![needle.to_owned(), needle.to_owned()]);
    }
    lists
        .into_iter()
        .map(|values| {
            values
                .into_iter()
                .map(|value| bounded_string(&value))
                .collect()
        })
        .collect()
}

fn bounded_string(value: &str) -> String {
    bounded_string_to(value, MAX_SEMANTIC_FUZZ_STRING_BYTES)
}

fn bounded_string_to(value: &str, maximum_bytes: usize) -> String {
    let mut bounded = String::new();
    for character in value.chars() {
        if bounded.len() + character.len_utf8() > maximum_bytes {
            break;
        }
        bounded.push(character);
    }
    bounded
}

fn object_mut(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    value
        .as_object_mut()
        .expect("canonical policy wire must be a JSON object")
}

fn rename_field(value: &mut Value, old: &str, new: &str) {
    let object = object_mut(value);
    let field = object
        .remove(old)
        .unwrap_or_else(|| panic!("canonical wire is missing field {old}"));
    object.insert(new.into(), field);
}
