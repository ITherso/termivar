use std::collections::BTreeSet;

#[cfg(feature = "scanning")]
use std::sync::Arc;

#[cfg(feature = "scanning")]
use async_trait::async_trait;

use termivar_core::{
    ConfidenceScore, EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceSource, EvidenceValue,
    Hypothesis, HypothesisState, HypothesisStrength, KnowledgePredicate, Probability,
};

use super::*;

#[cfg(feature = "scanning")]
use crate::{
    ActionCost, AdaptationLimits, AttackAction, BenefitScore, DecisionActionExecutor,
    DecisionActionOrigin, DecisionExecutionRequest, DecisionExecutorError,
    DecisionExecutorRegistry, DecisionLoop, DecisionLoopCommand, DecisionLoopConfig,
    DecisionRunnerAdapter, DecisionRunnerTurn, DecisionSession, ExperiencePolicy, ExperienceStore,
    Expression, HypothesisSelector, KnowledgeLayer, PlanningContext, RequiredStrength, RiskScore,
    VerificationCase, VerificationRule, VerificationTarget,
};

const TEST_REMEDIATION: AssessmentRemediation = AssessmentRemediation {
    id: "test.remediation@1",
    summary: "Use the bounded test remediation.",
};

const OBSERVATION_DESCRIPTOR: AssessmentCapabilityDescriptor = AssessmentCapabilityDescriptor::new(
    "test.observation@1",
    "Observation fixture",
    "test",
    "A redacted observation fixture.",
    Some(SecuritySeverity::Info),
    900_000,
    None,
    TEST_REMEDIATION,
    AssessmentClaimPolicy::ObservationOnly,
);

const REVIEW_DESCRIPTOR: AssessmentCapabilityDescriptor =
    AssessmentCapabilityDescriptor::differential_review(
        "test.review@1",
        "Review fixture",
        "test",
        "A redacted review fixture.",
        None,
        750_000,
        None,
        "test.remediation@1",
        "Use the bounded test remediation.",
    );

const CONFIRMED_DESCRIPTOR: AssessmentCapabilityDescriptor = AssessmentCapabilityDescriptor::new(
    "test.confirmed@1",
    "Confirmed fixture",
    "test-vulnerability",
    "A verifier-authorized test fixture.",
    Some(SecuritySeverity::Low),
    990_000,
    None,
    TEST_REMEDIATION,
    AssessmentClaimPolicy::VerifierTransition(VerifierClaimPolicy {
        action_id: "test.verify",
        hypothesis_namespace: "vulnerability",
        hypothesis_name: "test",
        hypothesis_value: StaticEvidenceValue::Text("present"),
        verifier_rule_id: "test.verify.confirmed",
        stage: VerificationStage::Passive,
    }),
);

fn test_scope_id() -> StableAssessmentScopeId {
    StableAssessmentScopeId::from_exact_origin("https://assessment-tests.test").unwrap()
}

fn discovered_subject_id(
    url: &str,
    method: crate::web_runtime::WebAssessmentMethod,
    names: &[&str],
) -> StableAssessmentSubjectId {
    let mut url = Url::parse(url).unwrap();
    url.set_query(None);
    url.set_fragment(None);
    StableAssessmentSubjectId::from_discovered_resource(
        &test_scope_id(),
        method,
        &url,
        &names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

#[test]
fn versioned_discovered_subject_identity_is_deterministic_structural_and_private() {
    use crate::web_runtime::WebAssessmentMethod;

    assert_eq!(
        StableAssessmentSubjectId::new("authorized-root@1")
            .unwrap()
            .as_str(),
        "authorized-root@1"
    );

    let first = discovered_subject_id(
        "https://assessment-tests.test/account/./profile?tab=VENOM-MUST-NOT-LEAK-QUERY-SECRET-123&page=1#secret",
        WebAssessmentMethod::Get,
        &["tab", "page", "tab"],
    );
    let repeated = discovered_subject_id(
        "https://ASSESSMENT-TESTS.test:443/account/profile?page=999&tab=other",
        WebAssessmentMethod::Get,
        &["page", "tab"],
    );
    assert_eq!(first, repeated);
    assert!(first.as_str().starts_with("discovered-resource@1:"));
    assert_eq!(first.as_str().len(), "discovered-resource@1:".len() + 64);
    assert!(!first
        .as_str()
        .contains("VENOM-MUST-NOT-LEAK-QUERY-SECRET-123"));
    assert!(!format!("{first:?}").contains("VENOM-MUST-NOT-LEAK-QUERY-SECRET-123"));

    assert_ne!(
        first,
        discovered_subject_id(
            "https://assessment-tests.test/account/other",
            WebAssessmentMethod::Get,
            &["page", "tab"],
        )
    );
    assert_ne!(
        first,
        discovered_subject_id(
            "https://assessment-tests.test/account/profile",
            WebAssessmentMethod::Head,
            &["page", "tab"],
        )
    );
    assert_ne!(
        first,
        discovered_subject_id(
            "https://assessment-tests.test/account/profile",
            WebAssessmentMethod::Get,
            &["tab"],
        )
    );
}

#[test]
fn discovered_subject_identity_fails_closed_for_unapproved_structure() {
    use crate::web_runtime::WebAssessmentMethod;

    for invalid in [
        "https://other.test/account",
        "https://user:secret@assessment-tests.test/account",
        "https://assessment-tests.test/account?secret=raw",
        "https://assessment-tests.test/account#fragment",
    ] {
        assert_eq!(
            StableAssessmentSubjectId::from_discovered_resource(
                &test_scope_id(),
                WebAssessmentMethod::Get,
                &Url::parse(invalid).unwrap(),
                &[],
            ),
            Err(AssessmentItemProjectionError::InvalidStableSubjectIdentity)
        );
    }
    assert_eq!(
        StableAssessmentSubjectId::from_discovered_resource(
            &test_scope_id(),
            WebAssessmentMethod::Get,
            &Url::parse("https://assessment-tests.test/account").unwrap(),
            &["x".repeat(MAX_QUERY_PARAMETER_NAME_BYTES + 1)],
        ),
        Err(AssessmentItemProjectionError::InvalidStableSubjectIdentity)
    );
}

fn references(values: &[u32]) -> Vec<AssessmentEvidenceReference> {
    values
        .iter()
        .copied()
        .map(AssessmentEvidenceReference::new)
        .collect()
}

fn mapped_context(
    subject: &EntityId,
    stable_id: &str,
    query_parameter_names: &[&str],
    evidence_ids: &[&str],
) -> (AssessmentProjectionContext, Vec<EvidenceId>, KnowledgeBase) {
    let knowledge = KnowledgeBase::new();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new(stable_id).unwrap(),
            query_parameter_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let evidence_ids = evidence_ids
        .iter()
        .map(|id| {
            let evidence = test_evidence(id, subject.clone(), "case:observation");
            knowledge.insert_evidence(evidence.clone()).unwrap();
            context
                .register_evidence(&knowledge, evidence.id())
                .unwrap();
            evidence.id().clone()
        })
        .collect();
    (context, evidence_ids, knowledge)
}

fn valid_confirmation_proof() -> ConfirmationProof {
    ConfirmationProof {
        capability_policy: true,
        action_matches: true,
        hypothesis_claim_matches: true,
        outcome_success: true,
        transition_authorized: true,
        hypothesis_write: true,
        final_hypothesis_confirmed: true,
        case_matches: true,
        selected_verifier_matches: true,
        evidence_nonempty: true,
        evidence_resolved: true,
        evidence_subject_matches: true,
        evidence_case_matches: true,
        receipt_case_matches: true,
        receipt_stage_matches: true,
        receipt_contributed: true,
        receipt_evidence_matches: true,
    }
}

fn denial(proof: ConfirmationProof) -> AssessmentConfirmationDenial {
    match proof.authorize() {
        Err(AssessmentItemProjectionError::ConfirmationDenied(reason)) => reason,
        result => panic!("expected confirmation denial, received {result:?}"),
    }
}

#[test]
fn disposition_and_opaque_reference_tokens_are_stable() {
    assert_eq!(
        AssessmentDisposition::Informational.as_str(),
        "informational"
    );
    assert_eq!(AssessmentDisposition::NeedsReview.as_str(), "needs_review");
    assert_eq!(AssessmentDisposition::Confirmed.as_str(), "confirmed");
    assert_eq!(
        AssessmentSubjectReference::new(7).to_string(),
        "subject-0007"
    );
    assert_eq!(
        AssessmentEvidenceReference::new(8).to_string(),
        "evidence-0008"
    );
    assert_eq!(AssessmentCaseReference::new(9).to_string(), "case-0009");
    assert_eq!(
        AssessmentOutcomeReference::new(10).to_string(),
        "outcome-0010"
    );
    assert_eq!(AssessmentSubjectReference::new(7).ordinal(), 7);
}

#[test]
fn claim_policy_derives_capability_maximum_without_a_raw_disposition_field() {
    for (capability, maximum) in [
        (
            &OBSERVATION_DESCRIPTOR,
            AssessmentDisposition::Informational,
        ),
        (&REVIEW_DESCRIPTOR, AssessmentDisposition::NeedsReview),
        (&CONFIRMED_DESCRIPTOR, AssessmentDisposition::Confirmed),
    ] {
        assert_eq!(capability.maximum_disposition(), maximum);
        for value in [
            capability.id,
            capability.title,
            capability.category,
            capability.redacted_summary,
            capability.remediation.id,
            capability.remediation.summary,
        ] {
            assert!(!value.is_empty());
            assert!(value.len() <= MAX_ASSESSMENT_DISPLAY_BYTES);
        }
    }
    assert!(OBSERVATION_DESCRIPTOR.verifier_policy().is_none());
    assert!(REVIEW_DESCRIPTOR.verifier_policy().is_none());
    assert!(CONFIRMED_DESCRIPTOR.verifier_policy().is_some());
}

#[test]
fn item_is_read_only_and_exposes_only_static_or_opaque_fields() {
    let subject = test_subject("subject:item-read-only");
    let knowledge = KnowledgeBase::new();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            test_subject("subject:unrelated"),
            StableAssessmentSubjectId::new("route.unrelated@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.item-read-only@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    let evidence_ids = ["evidence:item-4", "evidence:item-1"]
        .into_iter()
        .map(|id| {
            let evidence = test_evidence(id, subject.clone(), "case:observation");
            knowledge.insert_evidence(evidence.clone()).unwrap();
            context
                .register_evidence(&knowledge, evidence.id())
                .unwrap();
            evidence.id().clone()
        })
        .collect::<Vec<_>>();
    let item = AssessmentItem::from_observation(
        &OBSERVATION_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &AssessmentItemTarget::subject(),
        &evidence_ids,
    )
    .unwrap();

    assert_eq!(item.schema(), ASSESSMENT_ITEM_SCHEMA);
    assert_eq!(item.capability_id(), "test.observation@1");
    assert_eq!(item.subject_reference().ordinal(), 1);
    assert_eq!(item.disposition(), AssessmentDisposition::Informational);
    assert_eq!(item.severity(), Some(SecuritySeverity::Info));
    assert_eq!(item.evidence_count(), 2);
    assert_eq!(item.category(), "test");
    assert_eq!(item.cwe(), None);
    assert_eq!(item.remediation().id(), "test.remediation@1");
    assert!(item.fingerprint().starts_with("sha256:"));
    assert_eq!(item.fingerprint().len(), "sha256:".len() + 64);
    let AssessmentBasis::Observation(basis) = item.basis() else {
        panic!("expected observation basis")
    };
    assert_eq!(basis.evidence(), references(&[0, 1]));
    assert_eq!(item.basis().case_reference(), None);
}

#[test]
fn observation_and_differential_references_fail_closed() {
    let subject = test_subject("subject:fail-closed");
    let (mut context, ids, knowledge) = mapped_context(
        &subject,
        "route.fail-closed@1",
        &[],
        &["evidence:one", "evidence:two"],
    );
    let target = AssessmentItemTarget::subject();
    assert_eq!(
        AssessmentItem::from_observation(
            &OBSERVATION_DESCRIPTOR,
            &context,
            &knowledge,
            &subject,
            &target,
            &[],
        ),
        Err(AssessmentItemProjectionError::MissingEvidence)
    );
    assert_eq!(
        AssessmentItem::from_observation(
            &OBSERVATION_DESCRIPTOR,
            &context,
            &knowledge,
            &subject,
            &target,
            &[ids[0].clone(), ids[0].clone()],
        ),
        Err(AssessmentItemProjectionError::DuplicateEvidenceReference)
    );
    assert_eq!(
        context.project_differential(
            &OBSERVATION_DESCRIPTOR,
            &knowledge,
            &subject,
            &target,
            &[ids[0].clone()],
            &[ids[1].clone()],
        ),
        Err(AssessmentItemProjectionError::DispositionDenied {
            requested: AssessmentDisposition::NeedsReview,
        })
    );
    assert_eq!(context.items.len(), 0);
    assert_eq!(
        context.project_differential(
            &REVIEW_DESCRIPTOR,
            &knowledge,
            &subject,
            &target,
            &[],
            &[ids[1].clone()],
        ),
        Err(AssessmentItemProjectionError::MissingEvidence)
    );
    assert_eq!(
        context.project_differential(
            &REVIEW_DESCRIPTOR,
            &knowledge,
            &subject,
            &target,
            &[ids[0].clone()],
            &[],
        ),
        Err(AssessmentItemProjectionError::MissingEvidence)
    );
    assert_eq!(
        context.project_differential(
            &REVIEW_DESCRIPTOR,
            &knowledge,
            &subject,
            &target,
            &[ids[0].clone()],
            &[ids[0].clone()],
        ),
        Err(AssessmentItemProjectionError::OverlappingDifferentialEvidence)
    );
    assert_eq!(context.items.len(), 0);
}

#[test]
fn differential_projection_rejects_cross_subject_and_uncommitted_evidence() {
    let subject = test_subject("subject:differential-authority");
    let other_subject = test_subject("subject:differential-authority-other");
    let control = test_evidence(
        "evidence:differential-control",
        subject.clone(),
        "case:differential",
    );
    let cross_subject = test_evidence(
        "evidence:differential-cross-subject",
        other_subject.clone(),
        "case:differential",
    );
    let knowledge = KnowledgeBase::new();
    knowledge.insert_evidence(control.clone()).unwrap();
    knowledge.insert_evidence(cross_subject.clone()).unwrap();

    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.differential-authority@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_subject(
            other_subject,
            StableAssessmentSubjectId::new("route.differential-authority-other@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context.register_evidence(&knowledge, control.id()).unwrap();
    context
        .register_evidence(&knowledge, cross_subject.id())
        .unwrap();

    assert_eq!(
        context.project_differential(
            &REVIEW_DESCRIPTOR,
            &knowledge,
            &subject,
            &AssessmentItemTarget::subject(),
            &[control.id().clone()],
            &[cross_subject.id().clone()],
        ),
        Err(AssessmentItemProjectionError::EvidenceSubjectMappingMismatch)
    );

    let uncommitted_id = EvidenceId::parse("evidence:differential-uncommitted").unwrap();
    context.evidence.insert(
        uncommitted_id.clone(),
        EvidenceProjection {
            reference: AssessmentEvidenceReference::new(2),
            subject: subject.clone(),
        },
    );
    assert_eq!(
        context.project_differential(
            &REVIEW_DESCRIPTOR,
            &knowledge,
            &subject,
            &AssessmentItemTarget::subject(),
            &[control.id().clone()],
            &[uncommitted_id],
        ),
        Err(AssessmentItemProjectionError::EvidenceNotCommitted)
    );
    assert!(context.items.is_empty());
}

#[test]
fn evidence_reference_preflight_enforces_exact_limits_before_projection() {
    let maximum = (0..MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES)
        .map(|index| EvidenceId::parse(format!("evidence:preflight:{index:04}")).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(preflight_evidence_ids(&maximum), Ok(()));

    let mut over_limit = maximum.clone();
    over_limit.push(EvidenceId::parse("evidence:preflight:over").unwrap());
    assert_eq!(
        preflight_evidence_ids(&over_limit),
        Err(AssessmentItemProjectionError::TooManyEvidenceReferences)
    );
    assert_eq!(
        preflight_evidence_ids(&[maximum[0].clone(), maximum[0].clone()]),
        Err(AssessmentItemProjectionError::DuplicateEvidenceReference)
    );
    assert_eq!(
        preflight_evidence_ids(&[EvidenceId::parse(
            "x".repeat(MAX_PROJECTION_RUNTIME_ID_BYTES + 1)
        )
        .unwrap()]),
        Err(AssessmentItemProjectionError::InvalidRuntimeIdentity)
    );
}

#[test]
fn projection_runtime_identity_limits_accept_exact_boundaries_and_reject_overflow() {
    let maximum_subject = EntityId::new("s".repeat(MAX_PROJECTION_SUBJECT_ID_BYTES)).unwrap();
    let knowledge = KnowledgeBase::new();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            maximum_subject.clone(),
            StableAssessmentSubjectId::new("route.maximum-subject@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_case(
            &maximum_subject,
            "c".repeat(MAX_PROJECTION_RUNTIME_ID_BYTES),
        )
        .unwrap();

    assert_eq!(
        context.register_case(
            &maximum_subject,
            "c".repeat(MAX_PROJECTION_RUNTIME_ID_BYTES + 1),
        ),
        Err(AssessmentItemProjectionError::InvalidRuntimeIdentity)
    );
    let oversized_subject = EntityId::new("s".repeat(MAX_PROJECTION_SUBJECT_ID_BYTES + 1)).unwrap();
    assert_eq!(
        context.register_subject(
            oversized_subject,
            StableAssessmentSubjectId::new("route.oversized-subject@1").unwrap(),
            Vec::new(),
        ),
        Err(AssessmentItemProjectionError::InvalidRuntimeIdentity)
    );
}

#[test]
fn informational_confidence_is_capped_by_committed_evidence_reliability() {
    let subject = test_subject("subject:bounded-confidence");
    let evidence = Evidence::with_id(
        EvidenceId::parse("evidence:bounded-confidence").unwrap(),
        subject.clone(),
        EvidenceKind::Http,
        KnowledgePredicate::new("test", "bounded-confidence").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new("test.executor", "fixture").unwrap(),
        ConfidenceScore::from_percent(42).unwrap(),
    );
    let knowledge = KnowledgeBase::new();
    knowledge.insert_evidence(evidence.clone()).unwrap();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.bounded-confidence@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_evidence(&knowledge, evidence.id())
        .unwrap();

    let item = AssessmentItem::from_observation(
        &OBSERVATION_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &AssessmentItemTarget::subject(),
        &[evidence.id().clone()],
    )
    .unwrap();
    assert_eq!(item.confidence(), Probability::from_percent(42).unwrap());
}

#[test]
fn direct_duplicate_evidence_registration_remains_strict() {
    let subject = test_subject("subject:strict-evidence-registration");
    let evidence = test_evidence(
        "evidence:strict-evidence-registration",
        subject.clone(),
        "case:strict-evidence-registration",
    );
    let knowledge = KnowledgeBase::new();
    knowledge.insert_evidence(evidence.clone()).unwrap();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject,
            StableAssessmentSubjectId::new("route.strict-evidence-registration@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_evidence(&knowledge, evidence.id())
        .unwrap();
    assert_eq!(
        context.register_evidence(&knowledge, evidence.id()),
        Err(AssessmentItemProjectionError::DuplicateEvidenceMapping)
    );
}

#[test]
fn context_owned_item_set_is_bounded_and_consumes_one_reference_authority() {
    let subject = test_subject("subject:context-owned-items");
    let (mut context, ids, knowledge) = mapped_context(
        &subject,
        "route.context-owned-items@1",
        &[],
        &["evidence:context-owned-items"],
    );
    let target = AssessmentItemTarget::subject();
    for _ in 0..MAX_ASSESSMENT_ITEM_SET_ITEMS {
        context
            .project_observation(&OBSERVATION_DESCRIPTOR, &knowledge, &subject, &target, &ids)
            .unwrap();
    }
    assert_eq!(
        context.project_observation(&OBSERVATION_DESCRIPTOR, &knowledge, &subject, &target, &ids,),
        Err(AssessmentItemProjectionError::ProjectionContextLimit {
            dimension: "items",
            maximum: MAX_ASSESSMENT_ITEM_SET_ITEMS,
        })
    );
    assert!(format!("{context:?}").contains("item_count: 4096"));

    let set = context.finish();
    let set_debug = format!("{set:?}");
    assert!(set_debug.contains("subject_count: 1"));
    assert!(set_debug.contains("item_count: 4096"));
    assert!(!set_debug.contains("context-owned-items"));
    let (subjects, items) = set.into_parts();
    assert_eq!(subjects.len(), 1);
    assert_eq!(subjects[0].reference(), AssessmentSubjectReference::new(0));
    assert!(subjects[0].fingerprint().starts_with("sha256:"));
    assert_eq!(items.len(), MAX_ASSESSMENT_ITEM_SET_ITEMS);
    assert!(items
        .iter()
        .all(|item| item.disposition() == AssessmentDisposition::Informational));
}

#[test]
fn differential_basis_stays_visibly_needs_review() {
    let subject = test_subject("subject:differential");
    let (mut context, ids, knowledge) = mapped_context(
        &subject,
        "route.differential@1",
        &[],
        &["evidence:d1", "evidence:d2", "evidence:d3", "evidence:d4"],
    );
    let item = AssessmentItem::from_differential(
        &REVIEW_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &AssessmentItemTarget::subject(),
        &[ids[0].clone(), ids[1].clone()],
        &[ids[3].clone(), ids[2].clone()],
    )
    .unwrap();
    assert_eq!(item.disposition(), AssessmentDisposition::NeedsReview);
    let AssessmentBasis::Differential(basis) = item.basis() else {
        panic!("expected differential basis")
    };
    assert_eq!(basis.control(), references(&[0, 1]));
    assert_eq!(basis.candidate(), references(&[2, 3]));
    assert_eq!(item.evidence_count(), 4);
    assert_eq!(item.basis().case_reference(), None);

    context
        .project_differential(
            &REVIEW_DESCRIPTOR,
            &knowledge,
            &subject,
            &AssessmentItemTarget::subject(),
            &[ids[0].clone(), ids[1].clone()],
            &[ids[2].clone(), ids[3].clone()],
        )
        .unwrap();
    let (_, projected) = context.finish().into_parts();
    assert_eq!(projected.len(), 1);
    assert_eq!(
        projected[0].disposition(),
        AssessmentDisposition::NeedsReview
    );
    assert_eq!(projected[0].fingerprint(), item.fingerprint());
}

#[test]
fn confirmation_classifier_accepts_only_the_complete_proof() {
    assert_eq!(valid_confirmation_proof().authorize(), Ok(()));
}

#[test]
fn only_success_is_a_confirmation_outcome() {
    assert!(is_confirmation_outcome(OutcomeStatus::Success));
    for status in [
        OutcomeStatus::Blocked,
        OutcomeStatus::Unknown,
        OutcomeStatus::FalsePositive,
        OutcomeStatus::NeedsReview,
        OutcomeStatus::ConfirmedNegative,
    ] {
        assert!(!is_confirmation_outcome(status), "{status:?}");
    }
}

macro_rules! denial_case {
    ($name:ident, $field:ident, $reason:expr) => {
        #[test]
        fn $name() {
            let mut proof = valid_confirmation_proof();
            proof.$field = false;
            assert_eq!(denial(proof), $reason);
        }
    };
}

denial_case!(
    review_only_capability_cannot_confirm,
    capability_policy,
    AssessmentConfirmationDenial::CapabilityPolicy
);
denial_case!(
    action_mismatch_cannot_confirm,
    action_matches,
    AssessmentConfirmationDenial::ActionMismatch
);
denial_case!(
    hypothesis_predicate_or_value_mismatch_cannot_confirm,
    hypothesis_claim_matches,
    AssessmentConfirmationDenial::HypothesisClaimMismatch
);
denial_case!(
    blocked_unknown_or_needs_review_cannot_confirm,
    outcome_success,
    AssessmentConfirmationDenial::OutcomeNotSuccess
);
denial_case!(
    knowledge_only_success_cannot_confirm,
    transition_authorized,
    AssessmentConfirmationDenial::KnowledgeOnly
);
denial_case!(
    action_success_without_hypothesis_write_cannot_confirm,
    hypothesis_write,
    AssessmentConfirmationDenial::MissingHypothesisWrite
);
denial_case!(
    nonconfirmed_final_state_cannot_confirm,
    final_hypothesis_confirmed,
    AssessmentConfirmationDenial::FinalHypothesisNotConfirmed
);
denial_case!(
    case_identity_mismatch_cannot_confirm,
    case_matches,
    AssessmentConfirmationDenial::CaseMismatch
);
denial_case!(
    verifier_rule_mismatch_cannot_confirm,
    selected_verifier_matches,
    AssessmentConfirmationDenial::SelectedVerifierMismatch
);
denial_case!(
    missing_evidence_cannot_confirm,
    evidence_nonempty,
    AssessmentConfirmationDenial::MissingEvidence
);
denial_case!(
    unavailable_evidence_cannot_confirm,
    evidence_resolved,
    AssessmentConfirmationDenial::EvidenceUnavailable
);
denial_case!(
    cross_subject_evidence_cannot_confirm,
    evidence_subject_matches,
    AssessmentConfirmationDenial::EvidenceSubjectMismatch
);
denial_case!(
    cross_case_evidence_cannot_confirm,
    evidence_case_matches,
    AssessmentConfirmationDenial::EvidenceCaseMismatch
);
denial_case!(
    mismatched_execution_receipt_cannot_confirm,
    receipt_case_matches,
    AssessmentConfirmationDenial::ReceiptCaseMismatch
);
denial_case!(
    mismatched_execution_stage_cannot_confirm,
    receipt_stage_matches,
    AssessmentConfirmationDenial::ReceiptStageMismatch
);
denial_case!(
    execution_receipt_without_contributing_evidence_cannot_confirm,
    receipt_contributed,
    AssessmentConfirmationDenial::ReceiptDidNotContribute
);
denial_case!(
    receipt_evidence_must_match_committed_knowledge,
    receipt_evidence_matches,
    AssessmentConfirmationDenial::ReceiptEvidenceMismatch
);

#[test]
fn denial_order_fails_closed_at_the_first_authority_boundary() {
    let proof = ConfirmationProof {
        capability_policy: false,
        action_matches: false,
        ..valid_confirmation_proof()
    };
    assert_eq!(
        denial(proof),
        AssessmentConfirmationDenial::CapabilityPolicy
    );
}

fn test_subject(value: &str) -> EntityId {
    EntityId::new(value).unwrap()
}

fn test_evidence(id: &str, subject: EntityId, case_id: &str) -> Evidence {
    Evidence::with_id(
        EvidenceId::parse(id).unwrap(),
        subject,
        EvidenceKind::Http,
        KnowledgePredicate::new("test", "signal").unwrap(),
        EvidenceValue::Boolean(true),
        EvidenceSource::new("test.executor", "fixture")
            .unwrap()
            .with_correlation_id(case_id)
            .unwrap(),
        ConfidenceScore::MAX,
    )
}

#[test]
fn evidence_extraction_requires_same_subject_and_case() {
    let expected = test_subject("subject:expected");
    let other = test_subject("subject:other");
    let knowledge = KnowledgeBase::new();
    let matching = test_evidence("evidence:matching", expected.clone(), "case:expected");
    let wrong_case = test_evidence("evidence:wrong-case", expected.clone(), "case:other");
    let wrong_subject = test_evidence("evidence:wrong-subject", other, "case:expected");
    for evidence in [&matching, &wrong_case, &wrong_subject] {
        knowledge.insert_evidence(evidence.clone()).unwrap();
    }

    assert_eq!(
        validate_correlated_evidence(
            &knowledge,
            &BTreeSet::from([matching.id().clone()]),
            &expected,
            "case:expected",
        ),
        (true, true, true)
    );
    assert_eq!(
        validate_correlated_evidence(
            &knowledge,
            &BTreeSet::from([wrong_case.id().clone()]),
            &expected,
            "case:expected",
        ),
        (true, true, false)
    );
    assert_eq!(
        validate_correlated_evidence(
            &knowledge,
            &BTreeSet::from([wrong_subject.id().clone()]),
            &expected,
            "case:expected",
        ),
        (true, false, true)
    );
    assert_eq!(
        validate_correlated_evidence(
            &knowledge,
            &BTreeSet::from([EvidenceId::parse("evidence:missing").unwrap()]),
            &expected,
            "case:expected",
        ),
        (false, false, false)
    );
}

#[test]
fn final_hypothesis_semantics_are_exact_and_typed() {
    let subject = test_subject("subject:hypothesis");
    let predicate = KnowledgePredicate::new("vulnerability", "test").unwrap();
    let mut hypothesis = Hypothesis::with_id(
        "hypothesis:test",
        subject.clone(),
        predicate.clone(),
        EvidenceValue::Text("present".to_owned()),
        Probability::from_percent(90).unwrap(),
    )
    .unwrap();
    hypothesis.set_strength(HypothesisStrength::Strong);
    hypothesis.set_state(HypothesisState::Confirmed);
    let knowledge = KnowledgeBase::new();
    knowledge.upsert_hypothesis(hypothesis).unwrap();

    let policy = CONFIRMED_DESCRIPTOR.verifier_policy().unwrap();
    let stored = knowledge.hypothesis("hypothesis:test").unwrap();
    assert_eq!(stored.state(), HypothesisState::Confirmed);
    assert!(predicate_matches(
        stored.predicate(),
        policy.hypothesis_namespace,
        policy.hypothesis_name,
    ));
    assert!(policy.hypothesis_value.matches(stored.value()));
    assert!(!policy
        .hypothesis_value
        .matches(&EvidenceValue::Text("different".to_owned())));
    assert!(!predicate_matches(
        &KnowledgePredicate::new("technology", "test").unwrap(),
        policy.hypothesis_namespace,
        policy.hypothesis_name,
    ));
}

#[test]
fn execution_and_verification_stages_must_match() {
    assert!(execution_stage_matches(
        DecisionExecutionStage::Passive,
        VerificationStage::Passive
    ));
    assert!(execution_stage_matches(
        DecisionExecutionStage::Active,
        VerificationStage::Active
    ));
    assert!(!execution_stage_matches(
        DecisionExecutionStage::Passive,
        VerificationStage::Active
    ));
    assert!(!execution_stage_matches(
        DecisionExecutionStage::Active,
        VerificationStage::Passive
    ));
}

#[test]
fn stable_fingerprint_excludes_basis_evidence_confidence_summary_and_disposition() {
    const ALTERNATE_DESCRIPTOR: AssessmentCapabilityDescriptor =
        AssessmentCapabilityDescriptor::differential_review(
            "test.review@1",
            "Changed title",
            "changed-category",
            "Changed redacted summary.",
            Some(SecuritySeverity::High),
            123_456,
            None,
            "test.remediation@1",
            "Use the bounded test remediation.",
        );
    let subject = test_subject("subject:fingerprint");
    let (context, ids, knowledge) = mapped_context(
        &subject,
        "route.fingerprint@1",
        &["id"],
        &["evidence:fingerprint-1", "evidence:fingerprint-2"],
    );
    let target = AssessmentItemTarget::subject();
    let observation = AssessmentItem::from_observation(
        &REVIEW_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &target,
        &[ids[0].clone()],
    )
    .unwrap();
    assert_eq!(
        observation.fingerprint(),
        "sha256:400a1146bdcc9b51ebfc699ccffeeba37deb5482d2418e8af0e33ba4ae0979d3"
    );
    let differential = AssessmentItem::from_differential(
        &ALTERNATE_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &target,
        &[ids[0].clone()],
        &[ids[1].clone()],
    )
    .unwrap();
    let subject_projection = context.subject(&subject, &target).unwrap();
    let verifier_shaped = AssessmentItem::build(
        &ALTERNATE_DESCRIPTOR,
        context.stable_scope_id(),
        subject_projection,
        &target,
        Probability::ONE,
        AssessmentBasis::Verifier(AssessmentVerifierBasis {
            case_reference: AssessmentCaseReference::new(999),
            outcome_reference: AssessmentOutcomeReference::new(998),
            verifier_rule_id: "changed.rule",
            stage: VerificationStage::Active,
            evidence: references(&[997]),
        }),
    );

    assert_eq!(observation.fingerprint(), differential.fingerprint());
    assert_eq!(observation.fingerprint(), verifier_shaped.fingerprint());
    assert_ne!(observation.confidence(), differential.confidence());
    assert_ne!(observation.disposition(), differential.disposition());
    assert!(!format!("{verifier_shaped:?}").contains("EvidenceId"));
    assert!(!verifier_shaped.fingerprint().contains("changed.rule"));

    let mut reordered = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    reordered
        .register_subject(
            test_subject("subject:sorts-first"),
            StableAssessmentSubjectId::new("route.sorts-first@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    reordered
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.fingerprint@1").unwrap(),
            vec!["id".to_owned()],
        )
        .unwrap();
    for id in &ids {
        reordered.register_evidence(&knowledge, id).unwrap();
    }
    let reordered_item = AssessmentItem::from_observation(
        &REVIEW_DESCRIPTOR,
        &reordered,
        &knowledge,
        &subject,
        &target,
        &[ids[0].clone()],
    )
    .unwrap();
    assert_ne!(
        observation.subject_reference(),
        reordered_item.subject_reference()
    );
    assert_eq!(observation.fingerprint(), reordered_item.fingerprint());

    let parameter_item = AssessmentItem::from_observation(
        &REVIEW_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &AssessmentItemTarget::query_parameter("id").unwrap(),
        &[ids[0].clone()],
    )
    .unwrap();
    let other_capability = AssessmentItem::from_observation(
        &OBSERVATION_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &target,
        &[ids[0].clone()],
    )
    .unwrap();
    assert_ne!(observation.fingerprint(), parameter_item.fingerprint());
    assert_ne!(observation.fingerprint(), other_capability.fingerprint());

    let mut renamed = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    renamed
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.different@1").unwrap(),
            vec!["id".to_owned()],
        )
        .unwrap();
    for id in &ids {
        renamed.register_evidence(&knowledge, id).unwrap();
    }
    let renamed_item = AssessmentItem::from_observation(
        &REVIEW_DESCRIPTOR,
        &renamed,
        &knowledge,
        &subject,
        &target,
        &[ids[0].clone()],
    )
    .unwrap();
    assert_ne!(observation.fingerprint(), renamed_item.fingerprint());

    let mut rescoped = AssessmentProjectionContext::new(
        &knowledge,
        StableAssessmentScopeId::from_exact_origin("https://other-origin.test").unwrap(),
    );
    rescoped
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.fingerprint@1").unwrap(),
            vec!["id".to_owned()],
        )
        .unwrap();
    for id in &ids {
        rescoped.register_evidence(&knowledge, id).unwrap();
    }
    let rescoped_item = AssessmentItem::from_observation(
        &REVIEW_DESCRIPTOR,
        &rescoped,
        &knowledge,
        &subject,
        &target,
        &[ids[0].clone()],
    )
    .unwrap();
    assert_ne!(observation.fingerprint(), rescoped_item.fingerprint());
}

#[test]
fn host_identity_and_projection_maps_fail_closed_without_hashing_raw_paths() {
    for invalid in [
        "",
        " https://example.test/private ",
        "https://example.test/private",
        "route/private",
        "route?token=secret",
    ] {
        assert_eq!(
            StableAssessmentSubjectId::new(invalid),
            Err(AssessmentItemProjectionError::InvalidStableSubjectIdentity)
        );
    }
    for invalid in [
        "",
        " https://example.test ",
        "https://example.test/",
        "https://example.test/private",
        "https://example.test?token=secret",
        "https://user:secret@example.test",
        "HTTPS://EXAMPLE.TEST",
        "https://example.test:443",
        "ftp://example.test",
    ] {
        assert_eq!(
            StableAssessmentScopeId::from_exact_origin(invalid),
            Err(AssessmentItemProjectionError::InvalidStableScopeIdentity)
        );
    }
    for valid in [
        "http://example.test",
        "https://example.test",
        "https://example.test:8443",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ] {
        assert!(StableAssessmentScopeId::from_exact_origin(valid).is_ok());
    }
    assert_eq!(
        test_scope_id().as_str(),
        "origin-sha256:3fa15420d758edb6d53af0c8e9e66c4a90c02e5e7124a2da58593300132fd5fb"
    );
    assert_eq!(
        AssessmentItemTarget::query_parameter("bad\nname"),
        Err(AssessmentItemProjectionError::InvalidQueryParameterTarget)
    );

    let subject = test_subject("subject:mapped");
    let evidence = test_evidence("evidence:mapped", subject.clone(), "case:mapped");
    let knowledge = KnowledgeBase::new();
    knowledge.insert_evidence(evidence.clone()).unwrap();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.mapped@1").unwrap(),
            vec!["id".to_owned()],
        )
        .unwrap();
    context
        .register_evidence(&knowledge, evidence.id())
        .unwrap();

    assert_eq!(
        AssessmentItem::from_observation(
            &OBSERVATION_DESCRIPTOR,
            &context,
            &knowledge,
            &test_subject("subject:unknown"),
            &AssessmentItemTarget::subject(),
            &[evidence.id().clone()],
        ),
        Err(AssessmentItemProjectionError::UnknownSubjectMapping)
    );
    assert_eq!(
        AssessmentItem::from_observation(
            &OBSERVATION_DESCRIPTOR,
            &context,
            &knowledge,
            &subject,
            &AssessmentItemTarget::query_parameter("other").unwrap(),
            &[evidence.id().clone()],
        ),
        Err(AssessmentItemProjectionError::UnknownQueryParameterTarget)
    );
    assert_eq!(
        AssessmentItem::from_observation(
            &OBSERVATION_DESCRIPTOR,
            &context,
            &knowledge,
            &subject,
            &AssessmentItemTarget::subject(),
            &[EvidenceId::parse("evidence:unknown").unwrap()],
        ),
        Err(AssessmentItemProjectionError::UnknownEvidenceMapping)
    );

    let foreign_knowledge = KnowledgeBase::new();
    foreign_knowledge.insert_evidence(evidence).unwrap();
    assert_eq!(
        AssessmentItem::from_observation(
            &OBSERVATION_DESCRIPTOR,
            &context,
            &foreign_knowledge,
            &subject,
            &AssessmentItemTarget::subject(),
            &[EvidenceId::parse("evidence:mapped").unwrap()],
        ),
        Err(AssessmentItemProjectionError::KnowledgeAuthorityMismatch)
    );
}

#[test]
fn case_references_are_scoped_to_runtime_subjects() {
    let first = test_subject("subject:first-case");
    let second = test_subject("subject:second-case");
    let knowledge = KnowledgeBase::new();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            first.clone(),
            StableAssessmentSubjectId::new("route.first-case@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_subject(
            second.clone(),
            StableAssessmentSubjectId::new("route.second-case@1").unwrap(),
            Vec::new(),
        )
        .unwrap();

    let first_reference = context.register_case(&first, "case:reused").unwrap();
    let second_reference = context.register_case(&second, "case:reused").unwrap();
    assert_ne!(first_reference, second_reference);
    assert_eq!(
        context.register_case(&first, "case:reused"),
        Err(AssessmentItemProjectionError::DuplicateCaseMapping)
    );
}

#[test]
fn outcome_registration_caps_evidence_before_identity_projection() {
    let subject = test_subject("subject:outcome-evidence-cap");
    let knowledge = KnowledgeBase::new();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.outcome-evidence-cap@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_case(&subject, "case:outcome-evidence-cap")
        .unwrap();
    let evidence_ids = (0..=MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES)
        .map(|index| EvidenceId::parse(format!("evidence:outcome-cap-{index:03}")).unwrap())
        .collect();
    let outcome = Outcome::verified(
        "case:outcome-evidence-cap",
        subject,
        "action:outcome-evidence-cap",
        "hypothesis:outcome-evidence-cap",
        "verifier:outcome-evidence-cap",
        VerificationStage::Passive,
        OutcomeStatus::Success,
        Probability::from_percent(90).unwrap(),
        "bounded fixture",
        evidence_ids,
    )
    .unwrap();

    assert_eq!(
        context.register_outcome(&outcome),
        Err(AssessmentItemProjectionError::TooManyEvidenceReferences)
    );
}

#[test]
fn outcome_reference_binds_status_confidence_and_exact_evidence_identity() {
    let subject = test_subject("subject:exact-outcome-reference");
    let knowledge = KnowledgeBase::new();
    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.exact-outcome-reference@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_case(&subject, "case:exact-outcome-reference")
        .unwrap();
    let make_outcome = |evidence: &str, confidence: u8| {
        Outcome::verified(
            "case:exact-outcome-reference",
            subject.clone(),
            "action:exact-outcome-reference",
            "hypothesis:exact-outcome-reference",
            "verifier:exact-outcome-reference",
            VerificationStage::Passive,
            OutcomeStatus::Success,
            Probability::from_percent(confidence).unwrap(),
            "bounded fixture",
            BTreeSet::from([EvidenceId::parse(evidence).unwrap()]),
        )
        .unwrap()
    };
    let registered = make_outcome("evidence:exact-outcome-a", 90);
    assert_eq!(
        context.register_outcome(&registered).unwrap(),
        AssessmentOutcomeReference::new(0)
    );
    assert_eq!(
        context.outcome_reference(&make_outcome("evidence:exact-outcome-b", 90)),
        Err(AssessmentItemProjectionError::UnknownOutcomeMapping)
    );
    assert_eq!(
        context.outcome_reference(&make_outcome("evidence:exact-outcome-a", 89)),
        Err(AssessmentItemProjectionError::UnknownOutcomeMapping)
    );
}

#[test]
fn static_evidence_value_matching_is_variant_exact() {
    assert!(StaticEvidenceValue::Boolean(true).matches(&EvidenceValue::Boolean(true)));
    assert!(!StaticEvidenceValue::Boolean(true).matches(&EvidenceValue::Unsigned(1)));
    assert!(StaticEvidenceValue::Unsigned(7).matches(&EvidenceValue::Unsigned(7)));
    assert!(!StaticEvidenceValue::Unsigned(7).matches(&EvidenceValue::Signed(7)));
    assert!(StaticEvidenceValue::Text("x").matches(&EvidenceValue::Text("x".to_owned())));
}

#[cfg(feature = "scanning")]
const PROJECTION_ACTION_ID: &str = "test.verify";
#[cfg(feature = "scanning")]
const PROJECTION_EXECUTOR_ID: &str = "test.projection-executor";
#[cfg(feature = "scanning")]
const PROJECTION_HYPOTHESIS_ID: &str = "hypothesis:test-assessment-projection";
#[cfg(feature = "scanning")]
const PROJECTION_CONTROL_EVIDENCE_ID: &str = "evidence:test-assessment-control";
#[cfg(feature = "scanning")]
const PROJECTION_CANDIDATE_EVIDENCE_ID: &str = "evidence:test-assessment-candidate";
#[cfg(feature = "scanning")]
const PROJECTION_REPLAY_EVIDENCE_ID: &str = "evidence:test-assessment-replay";
#[cfg(feature = "scanning")]
const SECRET_ACTION_ID: &str = "test.observe-secret";
#[cfg(feature = "scanning")]
const SECRET_EXECUTOR_ID: &str = "test.secret-executor";
#[cfg(feature = "scanning")]
const SECRET_EVIDENCE_ID: &str = "evidence:test-secret-observation";
#[cfg(feature = "scanning")]
const SECRET_SENTINEL: &str = "secret-sentinel-7b1e4a9c";

#[cfg(feature = "scanning")]
struct ProjectionExecutor {
    reliability: ConfidenceScore,
}

#[cfg(feature = "scanning")]
struct FailingProjectionExecutor;

#[cfg(feature = "scanning")]
struct SecretProjectionExecutor;

#[cfg(feature = "scanning")]
#[async_trait]
impl DecisionActionExecutor for ProjectionExecutor {
    fn id(&self) -> &str {
        PROJECTION_EXECUTOR_ID
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        let source = EvidenceSource::new(PROJECTION_EXECUTOR_ID, "deterministic-fixture")
            .unwrap()
            .with_correlation_id(request.case().id())
            .unwrap();
        Ok([
            (
                PROJECTION_CONTROL_EVIDENCE_ID,
                projection_control_predicate(),
                false,
            ),
            (
                PROJECTION_CANDIDATE_EVIDENCE_ID,
                projection_candidate_predicate(),
                true,
            ),
            (
                PROJECTION_REPLAY_EVIDENCE_ID,
                projection_replay_predicate(),
                true,
            ),
        ]
        .into_iter()
        .map(|(id, predicate, value)| {
            Evidence::with_id_at(
                EvidenceId::parse(id).unwrap(),
                request.case().subject().clone(),
                EvidenceKind::Http,
                predicate,
                EvidenceValue::Boolean(value),
                source.clone(),
                self.reliability,
                0,
            )
        })
        .collect())
    }
}

#[cfg(feature = "scanning")]
#[async_trait]
impl DecisionActionExecutor for FailingProjectionExecutor {
    fn id(&self) -> &str {
        PROJECTION_EXECUTOR_ID
    }

    async fn execute(
        &self,
        _request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        Err(DecisionExecutorError::new("deterministic executor failure"))
    }
}

#[cfg(feature = "scanning")]
#[async_trait]
impl DecisionActionExecutor for SecretProjectionExecutor {
    fn id(&self) -> &str {
        SECRET_EXECUTOR_ID
    }

    async fn execute(
        &self,
        request: &DecisionExecutionRequest,
    ) -> Result<Vec<Evidence>, DecisionExecutorError> {
        Ok(vec![Evidence::with_id_at(
            EvidenceId::parse(SECRET_EVIDENCE_ID).unwrap(),
            request.case().subject().clone(),
            EvidenceKind::Http,
            KnowledgePredicate::new("test.secret", "opaque_value").unwrap(),
            EvidenceValue::Text(SECRET_SENTINEL.to_owned()),
            EvidenceSource::new(SECRET_EXECUTOR_ID, "deterministic-fixture")
                .unwrap()
                .with_correlation_id(request.case().id())
                .unwrap(),
            ConfidenceScore::MAX,
            0,
        )])
    }
}

#[cfg(feature = "scanning")]
struct RuntimeProjectionFixture {
    knowledge: KnowledgeBase,
    receipt: DecisionEvidenceReceipt,
    decision: DecisionOutcomeReport,
}

#[cfg(feature = "scanning")]
fn projection_subject() -> EntityId {
    EntityId::new("endpoint:https://assessment.test/review").unwrap()
}

#[cfg(feature = "scanning")]
fn projection_hypothesis_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("vulnerability", "test").unwrap()
}

#[cfg(feature = "scanning")]
fn projection_control_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("test.differential", "control_matched").unwrap()
}

#[cfg(feature = "scanning")]
fn projection_candidate_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("test.differential", "candidate_changed").unwrap()
}

#[cfg(feature = "scanning")]
fn projection_replay_predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("test.differential", "replay_correlated").unwrap()
}

#[cfg(feature = "scanning")]
fn projection_registry() -> DecisionExecutorRegistry {
    projection_registry_with_reliability(ConfidenceScore::MAX)
}

#[cfg(feature = "scanning")]
fn projection_registry_with_reliability(reliability: ConfidenceScore) -> DecisionExecutorRegistry {
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(ProjectionExecutor { reliability }))
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Passive,
            PROJECTION_ACTION_ID,
            PROJECTION_EXECUTOR_ID,
        )
        .unwrap();
    registry
}

#[cfg(feature = "scanning")]
fn projection_loop(
    status: Option<OutcomeStatus>,
    target: VerificationTarget,
) -> (DecisionLoop, KnowledgeBase) {
    let planning = PlanningContext::new(
        BenefitScore::from_percent(90).unwrap(),
        100,
        RiskScore::from_percent(50).unwrap(),
    );
    let mut decision_loop = DecisionLoop::new(
        DecisionLoopConfig::new(
            planning,
            AdaptationLimits::default(),
            ExperiencePolicy::default(),
            4,
        )
        .unwrap(),
    );
    let predicate = projection_hypothesis_predicate();
    let value = EvidenceValue::Text("present".to_owned());
    decision_loop
        .planner_mut()
        .register(
            AttackAction::new(
                PROJECTION_ACTION_ID,
                PROJECTION_EXECUTOR_ID,
                Expression::equals(KnowledgeLayer::Hypothesis, predicate.clone(), value.clone()),
                HypothesisSelector::new(
                    predicate.clone(),
                    value.clone(),
                    Probability::from_percent(50).unwrap(),
                    RequiredStrength::Strong,
                ),
                BenefitScore::from_percent(80).unwrap(),
                ActionCost::new(10).unwrap(),
                RiskScore::from_percent(10).unwrap(),
                BTreeSet::new(),
            )
            .unwrap()
            .with_verification_target(target),
        )
        .unwrap();
    if let Some(status) = status {
        let verifier = VerificationRule::new(
            "test.verify.confirmed",
            VerificationStage::Passive,
            100,
            Expression::all(vec![
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    projection_control_predicate(),
                    EvidenceValue::Boolean(false),
                ),
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    projection_candidate_predicate(),
                    EvidenceValue::Boolean(true),
                ),
                Expression::equals(
                    KnowledgeLayer::Evidence,
                    projection_replay_predicate(),
                    EvidenceValue::Boolean(true),
                ),
            ])
            .unwrap(),
            status,
            Probability::from_percent(99).unwrap(),
            "Deterministic fixture classification",
        )
        .unwrap()
        .scoped_to_action(PROJECTION_ACTION_ID)
        .unwrap()
        .with_case_correlated_evidence()
        .unwrap();
        decision_loop
            .verification_mut()
            .passive_mut()
            .register(verifier)
            .unwrap();
    }

    let knowledge = KnowledgeBase::new();
    let mut hypothesis = Hypothesis::with_id(
        PROJECTION_HYPOTHESIS_ID,
        projection_subject(),
        predicate,
        value,
        Probability::from_percent(90).unwrap(),
    )
    .unwrap();
    hypothesis.set_strength(HypothesisStrength::Strong);
    hypothesis.set_state(HypothesisState::Supported);
    knowledge.upsert_hypothesis(hypothesis).unwrap();
    (decision_loop, knowledge)
}

#[cfg(feature = "scanning")]
async fn runtime_projection_fixture(
    status: Option<OutcomeStatus>,
    target: VerificationTarget,
) -> RuntimeProjectionFixture {
    runtime_projection_fixture_with_reliability(status, target, ConfidenceScore::MAX).await
}

#[cfg(feature = "scanning")]
async fn runtime_projection_fixture_with_reliability(
    status: Option<OutcomeStatus>,
    target: VerificationTarget,
    reliability: ConfidenceScore,
) -> RuntimeProjectionFixture {
    let (decision_loop, knowledge) = projection_loop(status, target);
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(projection_subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let command = planning.command().clone();
    let turn = DecisionRunnerAdapter::new(projection_registry_with_reliability(reliability))
        .drive_command(
            &decision_loop,
            &command,
            &knowledge,
            &mut experience,
            &mut session,
        )
        .await
        .unwrap();
    let DecisionRunnerTurn::Outcome { evidence, decision } = turn else {
        panic!("fixture command did not produce an outcome")
    };
    RuntimeProjectionFixture {
        knowledge,
        receipt: *evidence,
        decision: *decision,
    }
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn executor_failure_produces_no_outcome_evidence_or_confirmation_input() {
    let (decision_loop, knowledge) =
        projection_loop(Some(OutcomeStatus::Success), VerificationTarget::Motivation);
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(FailingProjectionExecutor))
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Passive,
            PROJECTION_ACTION_ID,
            PROJECTION_EXECUTOR_ID,
        )
        .unwrap();
    let mut experience = ExperienceStore::new();
    let mut session = DecisionSession::new(projection_subject());
    let planning = decision_loop
        .plan_next(&knowledge, &experience, &mut session)
        .unwrap();
    let command = planning.command().clone();

    let result = DecisionRunnerAdapter::new(registry)
        .drive_command(
            &decision_loop,
            &command,
            &knowledge,
            &mut experience,
            &mut session,
        )
        .await;
    let error = result.expect_err("failing executor must not return a runner outcome turn");

    assert!(error.execution_failure().is_some());
    assert!(error.committed_evidence().is_none());
    assert!(knowledge
        .evidence_for_subject(&projection_subject())
        .is_empty());
    assert_eq!(
        knowledge
            .hypothesis(PROJECTION_HYPOTHESIS_ID)
            .unwrap()
            .state(),
        HypothesisState::Supported
    );
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn informational_projection_never_exposes_committed_secret_evidence_value() {
    let subject = test_subject("endpoint:https://assessment.test/private");
    let case = VerificationCase::new(
        "case:secret-observation",
        subject.clone(),
        SECRET_ACTION_ID,
        "hypothesis:secret-observation",
    )
    .unwrap()
    .without_hypothesis_transition();
    let command = DecisionLoopCommand::ExecuteAction {
        case,
        executor: Some(SECRET_EXECUTOR_ID.to_owned()),
        origin: DecisionActionOrigin::Bootstrap,
        delay_ms: None,
    };
    let mut registry = DecisionExecutorRegistry::new();
    registry
        .register(Arc::new(SecretProjectionExecutor))
        .unwrap();
    registry
        .route_action(
            DecisionExecutionStage::Passive,
            SECRET_ACTION_ID,
            SECRET_EXECUTOR_ID,
        )
        .unwrap();
    let knowledge = KnowledgeBase::new();
    let receipt = DecisionRunnerAdapter::new(registry)
        .execute_command(&command, &knowledge)
        .await
        .unwrap();
    assert_eq!(
        receipt.evidence()[0].value(),
        &EvidenceValue::Text(SECRET_SENTINEL.to_owned())
    );
    assert_eq!(
        knowledge
            .evidence(&EvidenceId::parse(SECRET_EVIDENCE_ID).unwrap())
            .unwrap()
            .value(),
        &EvidenceValue::Text(SECRET_SENTINEL.to_owned())
    );

    let mut context = AssessmentProjectionContext::new(&knowledge, test_scope_id());
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("route.secret-observation@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_evidence(&knowledge, receipt.evidence()[0].id())
        .unwrap();
    let item = AssessmentItem::from_observation(
        &OBSERVATION_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &AssessmentItemTarget::subject(),
        &[receipt.evidence()[0].id().clone()],
    )
    .unwrap();
    let error = AssessmentItem::from_observation(
        &OBSERVATION_DESCRIPTOR,
        &context,
        &knowledge,
        &subject,
        &AssessmentItemTarget::subject(),
        &[EvidenceId::parse("evidence:not-mapped").unwrap()],
    )
    .unwrap_err();

    let renderings = [
        format!("{context:?}"),
        format!("{item:?}"),
        format!("{:?}", item.basis()),
        format!("{error:?}"),
        error.to_string(),
        item.fingerprint().to_owned(),
        item.subject_reference().to_string(),
        item.redacted_summary().to_owned(),
        item.title().to_owned(),
        item.category().to_owned(),
        item.remediation().summary().to_owned(),
    ];
    assert!(renderings
        .iter()
        .all(|rendered| !rendered.contains(SECRET_SENTINEL)));
    assert_eq!(item.disposition(), AssessmentDisposition::Informational);
    assert_eq!(item.evidence_count(), 1);
    let AssessmentBasis::Observation(basis) = item.basis() else {
        panic!("expected informational observation basis")
    };
    assert_eq!(basis.evidence(), references(&[0]));
}

#[cfg(feature = "scanning")]
fn projection_context(fixture: &RuntimeProjectionFixture) -> AssessmentProjectionContext {
    let outcome = fixture.decision.verification().outcome();
    let mut context = AssessmentProjectionContext::new(&fixture.knowledge, test_scope_id());
    context
        .register_subject(
            outcome.subject().clone(),
            StableAssessmentSubjectId::new("route.runtime-projection@1").unwrap(),
            Vec::new(),
        )
        .unwrap();
    context
        .register_case(outcome.subject(), outcome.case_id())
        .unwrap();
    context.register_outcome(outcome).unwrap();
    for evidence_id in outcome.evidence_ids() {
        context
            .register_evidence(&fixture.knowledge, evidence_id)
            .unwrap();
    }
    context
}

#[cfg(feature = "scanning")]
fn projection_error(
    capability: &'static AssessmentCapabilityDescriptor,
    fixture: &RuntimeProjectionFixture,
    receipt: &DecisionEvidenceReceipt,
    knowledge: &KnowledgeBase,
) -> AssessmentItemProjectionError {
    let context = projection_context(fixture);
    AssessmentItem::from_verifier_projection(
        capability,
        &context,
        &AssessmentItemTarget::subject(),
        receipt,
        &fixture.decision,
        knowledge,
    )
    .unwrap_err()
}

#[cfg(feature = "scanning")]
fn confirmation_denial(error: AssessmentItemProjectionError) -> AssessmentConfirmationDenial {
    let AssessmentItemProjectionError::ConfirmationDenied(reason) = error else {
        panic!("expected confirmation denial, got {error:?}")
    };
    reason
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn real_runtime_truth_projects_confirmed_only_through_the_verifier_path() {
    let fixture =
        runtime_projection_fixture(Some(OutcomeStatus::Success), VerificationTarget::Motivation)
            .await;
    assert!(fixture.decision.hypothesis_write().is_some());
    assert_eq!(
        fixture
            .knowledge
            .hypothesis(PROJECTION_HYPOTHESIS_ID)
            .unwrap()
            .state(),
        HypothesisState::Confirmed
    );

    let mut context = projection_context(&fixture);
    context
        .project_verifier(
            &CONFIRMED_DESCRIPTOR,
            &AssessmentItemTarget::subject(),
            &fixture.receipt,
            &fixture.decision,
            &fixture.knowledge,
        )
        .unwrap();
    let (_, items) = context.finish().into_parts();
    assert_eq!(items.len(), 1);
    let item = &items[0];

    assert_eq!(item.disposition(), AssessmentDisposition::Confirmed);
    assert_eq!(item.evidence_count(), 3);
    assert_eq!(
        item.basis().case_reference(),
        Some(AssessmentCaseReference::new(0))
    );
    let AssessmentBasis::Verifier(basis) = item.basis() else {
        panic!("expected verifier basis")
    };
    assert_eq!(basis.verifier_rule_id(), "test.verify.confirmed");
    assert_eq!(basis.stage(), VerificationStage::Passive);
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn confirmed_confidence_is_capped_by_correlated_evidence_reliability() {
    let fixture = runtime_projection_fixture_with_reliability(
        Some(OutcomeStatus::Success),
        VerificationTarget::Motivation,
        ConfidenceScore::from_percent(1).unwrap(),
    )
    .await;
    let item = AssessmentItem::from_verifier_projection(
        &CONFIRMED_DESCRIPTOR,
        &projection_context(&fixture),
        &AssessmentItemTarget::subject(),
        &fixture.receipt,
        &fixture.decision,
        &fixture.knowledge,
    )
    .unwrap();

    assert_eq!(item.disposition(), AssessmentDisposition::Confirmed);
    assert_eq!(item.confidence(), Probability::from_percent(1).unwrap());
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn real_knowledge_only_success_and_review_only_capability_cannot_confirm() {
    let knowledge_only = runtime_projection_fixture(
        Some(OutcomeStatus::Success),
        VerificationTarget::KnowledgeOnly,
    )
    .await;
    assert_eq!(
        confirmation_denial(projection_error(
            &CONFIRMED_DESCRIPTOR,
            &knowledge_only,
            &knowledge_only.receipt,
            &knowledge_only.knowledge,
        )),
        AssessmentConfirmationDenial::KnowledgeOnly
    );

    let confirmed =
        runtime_projection_fixture(Some(OutcomeStatus::Success), VerificationTarget::Motivation)
            .await;
    assert_eq!(
        confirmation_denial(projection_error(
            &REVIEW_DESCRIPTOR,
            &confirmed,
            &confirmed.receipt,
            &confirmed.knowledge,
        )),
        AssessmentConfirmationDenial::CapabilityPolicy
    );
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn real_projection_rejects_missing_and_cross_case_knowledge_evidence() {
    let fixture =
        runtime_projection_fixture(Some(OutcomeStatus::Success), VerificationTarget::Motivation)
            .await;
    let final_hypothesis = fixture
        .knowledge
        .hypothesis(PROJECTION_HYPOTHESIS_ID)
        .unwrap();

    let missing = KnowledgeBase::new();
    missing.upsert_hypothesis(final_hypothesis.clone()).unwrap();
    assert_eq!(
        confirmation_denial(projection_error(
            &CONFIRMED_DESCRIPTOR,
            &fixture,
            &fixture.receipt,
            &missing,
        )),
        AssessmentConfirmationDenial::EvidenceUnavailable
    );

    let cross_case = KnowledgeBase::new();
    cross_case.upsert_hypothesis(final_hypothesis).unwrap();
    for (id, predicate, value) in [
        (
            PROJECTION_CONTROL_EVIDENCE_ID,
            projection_control_predicate(),
            false,
        ),
        (
            PROJECTION_CANDIDATE_EVIDENCE_ID,
            projection_candidate_predicate(),
            true,
        ),
        (
            PROJECTION_REPLAY_EVIDENCE_ID,
            projection_replay_predicate(),
            true,
        ),
    ] {
        cross_case
            .insert_evidence(Evidence::with_id_at(
                EvidenceId::parse(id).unwrap(),
                projection_subject(),
                EvidenceKind::Http,
                predicate,
                EvidenceValue::Boolean(value),
                EvidenceSource::new(PROJECTION_EXECUTOR_ID, "deterministic-fixture")
                    .unwrap()
                    .with_correlation_id("case:foreign")
                    .unwrap(),
                ConfidenceScore::MAX,
                0,
            ))
            .unwrap();
    }
    assert_eq!(
        confirmation_denial(projection_error(
            &CONFIRMED_DESCRIPTOR,
            &fixture,
            &fixture.receipt,
            &cross_case,
        )),
        AssessmentConfirmationDenial::EvidenceCaseMismatch
    );
}

#[cfg(feature = "scanning")]
async fn mismatched_receipt() -> DecisionEvidenceReceipt {
    let case = VerificationCase::new(
        "case:mismatched-receipt",
        projection_subject(),
        PROJECTION_ACTION_ID,
        PROJECTION_HYPOTHESIS_ID,
    )
    .unwrap();
    let command = DecisionLoopCommand::ExecuteAction {
        case,
        executor: Some(PROJECTION_EXECUTOR_ID.to_owned()),
        origin: DecisionActionOrigin::Bootstrap,
        delay_ms: None,
    };
    DecisionRunnerAdapter::new(projection_registry())
        .execute_command(&command, &KnowledgeBase::new())
        .await
        .unwrap()
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn real_projection_rejects_a_receipt_from_another_case() {
    let fixture =
        runtime_projection_fixture(Some(OutcomeStatus::Success), VerificationTarget::Motivation)
            .await;
    let receipt = mismatched_receipt().await;
    assert_eq!(
        confirmation_denial(projection_error(
            &CONFIRMED_DESCRIPTOR,
            &fixture,
            &receipt,
            &fixture.knowledge,
        )),
        AssessmentConfirmationDenial::ReceiptCaseMismatch
    );
}

#[cfg(feature = "scanning")]
#[tokio::test]
async fn real_projection_rejects_receipt_evidence_that_differs_from_knowledge() {
    let fixture =
        runtime_projection_fixture(Some(OutcomeStatus::Success), VerificationTarget::Motivation)
            .await;
    let original = &fixture.receipt.evidence()[0];
    let mismatched = Evidence::with_id_at(
        original.id().clone(),
        original.subject().clone(),
        original.kind().clone(),
        original.predicate().clone(),
        EvidenceValue::Boolean(true),
        original.source().clone(),
        original.reliability(),
        original.observed_at_ms(),
    );
    let mut evidence = fixture.receipt.evidence().to_vec();
    evidence[0] = mismatched;
    let receipt = fixture.receipt.with_test_committed_batch(
        evidence,
        fixture.receipt.writes().to_vec(),
        fixture.receipt.after_execution().clone(),
    );

    assert_eq!(
        confirmation_denial(projection_error(
            &CONFIRMED_DESCRIPTOR,
            &fixture,
            &receipt,
            &fixture.knowledge,
        )),
        AssessmentConfirmationDenial::ReceiptEvidenceMismatch
    );
}
