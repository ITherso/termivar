use venom_core::{
    ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue, KnowledgePredicate,
};

use super::*;
use crate::web_runtime::assessment_item::{
    AssessmentBasis, AssessmentDisposition, StableAssessmentScopeId, StableAssessmentSubjectId,
};
use crate::web_runtime::AssessmentItem;

const QUERY_PARAMETER: &str = "return_to";

fn root_subject() -> EntityId {
    EntityId::new("endpoint:https://review-projection.test/").unwrap()
}

fn evidence(id: &str, subject: &EntityId) -> Evidence {
    Evidence::with_id(
        EvidenceId::parse(id).unwrap(),
        subject.clone(),
        EvidenceKind::Http,
        KnowledgePredicate::new("web.review.observation", "response-marker").unwrap(),
        EvidenceValue::Text("bounded-relation".to_owned()),
        EvidenceSource::new("web.review.fixture", "projection")
            .unwrap()
            .with_correlation_id("case:projection")
            .unwrap(),
        ConfidenceScore::MAX,
    )
}

fn projection_context(
    knowledge: &KnowledgeBase,
    subject: &EntityId,
) -> AssessmentProjectionContext {
    let scope =
        StableAssessmentScopeId::from_exact_origin("https://review-projection.test").unwrap();
    let mut context = AssessmentProjectionContext::new(knowledge, scope);
    context
        .register_subject(
            subject.clone(),
            StableAssessmentSubjectId::new("authorized-root@1").unwrap(),
            [QUERY_PARAMETER.to_owned()],
        )
        .unwrap();
    context
}

fn plan(
    kind: NativeReviewProjectionKind,
    subject: &EntityId,
    control: &[&str],
    candidate: &[&str],
) -> PlannedAssessmentReviewItem {
    PlannedAssessmentReviewItem {
        kind,
        subject: subject.clone(),
        target: match kind {
            NativeReviewProjectionKind::CorsCredentialedExternalOrigin => {
                AssessmentItemTarget::subject()
            },
            NativeReviewProjectionKind::CandidateSpecificExternalRedirect
            | NativeReviewProjectionKind::InertReflection
            | NativeReviewProjectionKind::TextReflection
            | NativeReviewProjectionKind::AttributeReflection
            | NativeReviewProjectionKind::UriAttributeReflection
            | NativeReviewProjectionKind::StyleReflection
            | NativeReviewProjectionKind::EventHandlerReflection
            | NativeReviewProjectionKind::ScriptElementReflection
            | NativeReviewProjectionKind::EmbeddedHtmlReflection
            | NativeReviewProjectionKind::SqlStructuralDifferential
            | NativeReviewProjectionKind::SstiStructuralEvaluation => {
                AssessmentItemTarget::query_parameter(QUERY_PARAMETER).unwrap()
            },
            NativeReviewProjectionKind::XssStructuralBoundary => {
                AssessmentItemTarget::query_parameter(QUERY_PARAMETER).unwrap()
            },
        },
        control_evidence_ids: control
            .iter()
            .map(|id| EvidenceId::parse(*id).unwrap())
            .collect(),
        candidate_evidence_ids: candidate
            .iter()
            .map(|id| EvidenceId::parse(*id).unwrap())
            .collect(),
    }
}

fn project_one(kind: NativeReviewProjectionKind) -> AssessmentItem {
    let subject = root_subject();
    let knowledge = KnowledgeBase::new();
    let planned = plan(
        kind,
        &subject,
        &["evidence:review:control"],
        &["evidence:review:candidate"],
    );
    for evidence_id in planned
        .control_evidence_ids
        .iter()
        .chain(&planned.candidate_evidence_ids)
    {
        knowledge
            .insert_evidence(evidence(evidence_id.as_str(), &subject))
            .unwrap();
    }
    let mut context = projection_context(&knowledge, &subject);
    project_plans(&mut context, &knowledge, &subject, &[planned]).unwrap();
    let (_, mut items) = context.finish().into_parts();
    assert_eq!(items.len(), 1);
    items.pop().unwrap()
}

#[test]
fn closed_capability_mapping_never_projects_confirmed() {
    for kind in [
        NativeReviewProjectionKind::CorsCredentialedExternalOrigin,
        NativeReviewProjectionKind::CandidateSpecificExternalRedirect,
        NativeReviewProjectionKind::InertReflection,
        NativeReviewProjectionKind::TextReflection,
        NativeReviewProjectionKind::AttributeReflection,
        NativeReviewProjectionKind::UriAttributeReflection,
        NativeReviewProjectionKind::StyleReflection,
        NativeReviewProjectionKind::EventHandlerReflection,
        NativeReviewProjectionKind::ScriptElementReflection,
        NativeReviewProjectionKind::EmbeddedHtmlReflection,
    ] {
        let item = project_one(kind);
        assert_ne!(item.disposition(), AssessmentDisposition::Confirmed);
        assert_eq!(item.basis().case_reference(), None);
        match kind.basis() {
            NativeReviewProjectionBasis::Observation => {
                assert_eq!(item.disposition(), AssessmentDisposition::Informational);
                let AssessmentBasis::Observation(basis) = item.basis() else {
                    panic!("informational native reflection must use observation basis");
                };
                assert_eq!(basis.evidence().len(), 1);
                assert!(!item.redacted_summary().contains("control"));
                assert_eq!(item.cwe(), None);
            },
            NativeReviewProjectionBasis::Differential => {
                assert_eq!(item.disposition(), AssessmentDisposition::NeedsReview);
                assert!(matches!(item.basis(), AssessmentBasis::Differential(_)));
            },
        }
    }
}

#[test]
fn cors_and_redirect_attach_only_semantically_valid_cwe_metadata() {
    let cors = project_one(NativeReviewProjectionKind::CorsCredentialedExternalOrigin);
    assert_eq!(cors.cwe(), Some("CWE-942"));
    assert_eq!(cors.severity(), None);

    let redirect = project_one(NativeReviewProjectionKind::CandidateSpecificExternalRedirect);
    assert_eq!(redirect.cwe(), Some("CWE-601"));
    assert_eq!(redirect.severity(), None);

    let reflection = project_one(NativeReviewProjectionKind::ScriptElementReflection);
    assert_eq!(reflection.cwe(), None);
    assert_eq!(reflection.severity(), None);
    assert!(reflection.redacted_summary().contains("not tested"));
}

#[test]
fn redirect_and_reflection_share_one_registered_evidence_inventory() {
    let subject = root_subject();
    let knowledge = KnowledgeBase::new();
    for id in [
        "evidence:shared:control:marker",
        "evidence:shared:control:relation",
        "evidence:shared:candidate:marker",
        "evidence:shared:candidate:relation",
    ] {
        knowledge.insert_evidence(evidence(id, &subject)).unwrap();
    }
    let control = [
        "evidence:shared:control:marker",
        "evidence:shared:control:relation",
    ];
    let candidate = [
        "evidence:shared:candidate:marker",
        "evidence:shared:candidate:relation",
    ];
    let plans = [
        plan(
            NativeReviewProjectionKind::CandidateSpecificExternalRedirect,
            &subject,
            &control,
            &candidate,
        ),
        plan(
            NativeReviewProjectionKind::ScriptElementReflection,
            &subject,
            &control,
            &candidate,
        ),
    ];
    let mut context = projection_context(&knowledge, &subject);
    project_plans(&mut context, &knowledge, &subject, &plans).unwrap();
    let (_, items) = context.finish().into_parts();
    assert_eq!(items.len(), 2);
    assert!(items
        .iter()
        .all(|item| item.disposition() == AssessmentDisposition::NeedsReview));
    assert!(items
        .iter()
        .all(|item| item.evidence_count() == control.len() + candidate.len()));
}

#[test]
fn malformed_pair_and_cross_subject_plan_fail_closed() {
    let subject = root_subject();
    let other = EntityId::new("endpoint:https://review-projection.test/other").unwrap();
    let knowledge = KnowledgeBase::new();
    let overlapping = plan(
        NativeReviewProjectionKind::ScriptElementReflection,
        &subject,
        &["evidence:overlap"],
        &["evidence:overlap"],
    );
    let mut context = projection_context(&knowledge, &subject);
    assert_eq!(
        project_plans(&mut context, &knowledge, &subject, &[overlapping]),
        Err(AssessmentReviewItemProjectionError::CandidateContract)
    );

    let cross_subject = plan(
        NativeReviewProjectionKind::CorsCredentialedExternalOrigin,
        &other,
        &["evidence:control"],
        &["evidence:candidate"],
    );
    assert_eq!(
        project_plans(&mut context, &knowledge, &subject, &[cross_subject]),
        Err(AssessmentReviewItemProjectionError::CandidateContract)
    );
}

#[test]
fn unavailable_committed_evidence_cannot_produce_an_item() {
    let subject = root_subject();
    let knowledge = KnowledgeBase::new();
    let planned = plan(
        NativeReviewProjectionKind::CorsCredentialedExternalOrigin,
        &subject,
        &["evidence:missing:control"],
        &["evidence:missing:candidate"],
    );
    let mut context = projection_context(&knowledge, &subject);
    assert_eq!(
        project_plans(&mut context, &knowledge, &subject, &[planned]),
        Err(AssessmentReviewItemProjectionError::Item(
            AssessmentItemProjectionError::EvidenceNotCommitted,
        ))
    );
    assert!(context.finish().items().is_empty());
}
