use termivar_core::{
    ConfidenceScore, Evidence, EvidenceKind, EvidenceSource, EvidenceValue, KnowledgePredicate,
};

use super::*;
use crate::web_runtime::assessment_item::{
    AssessmentBasis, AssessmentDisposition, AssessmentEvidenceReference, StableAssessmentScopeId,
    StableAssessmentSubjectId,
};
use crate::web_runtime::AssessmentItem;

const QUERY_PARAMETER: &str = "return_to";
const SHARED_SOURCE_EVIDENCE: [&str; 11] = [
    "evidence:shared-source:00",
    "evidence:shared-source:01",
    "evidence:shared-source:02",
    "evidence:shared-source:03",
    "evidence:shared-source:04",
    "evidence:shared-source:05",
    "evidence:shared-source:06",
    "evidence:shared-source:07",
    "evidence:shared-source:08",
    "evidence:shared-source:09",
    "evidence:shared-source:10",
];

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
            #[cfg(feature = "normalization-resilience")]
            NativeReviewProjectionKind::NormalizationHtmlTextTokenCase
            | NativeReviewProjectionKind::NormalizationAttributeValueInterTokenTab
            | NativeReviewProjectionKind::NormalizationUriAttributeInterTokenTab
            | NativeReviewProjectionKind::NormalizationEventHandlerAttributeInterTokenTab => {
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

fn shared_review_batches(subject: &EntityId) -> Vec<PlannedAssessmentReviewLedgerBatch> {
    let reflection = plan(
        NativeReviewProjectionKind::ScriptElementReflection,
        subject,
        &[
            "evidence:reflection:control:marker",
            "evidence:reflection:control:context",
        ],
        &SHARED_SOURCE_EVIDENCE,
    );
    let mut xss_candidate = vec![
        "evidence:xss:candidate:marker",
        "evidence:xss:candidate:family",
        "evidence:xss:candidate:variant",
        "evidence:xss:candidate:relation",
    ];
    xss_candidate.extend(SHARED_SOURCE_EVIDENCE);
    let xss = plan(
        NativeReviewProjectionKind::XssStructuralBoundary,
        subject,
        &[
            "evidence:xss:control:marker",
            "evidence:xss:control:family",
            "evidence:xss:control:variant",
            "evidence:xss:control:relation",
        ],
        &xss_candidate,
    );
    vec![
        PlannedAssessmentReviewLedgerBatch {
            expected_subject: subject.clone(),
            plans: vec![reflection],
        },
        PlannedAssessmentReviewLedgerBatch {
            expected_subject: subject.clone(),
            plans: vec![xss],
        },
    ]
}

fn product_visible_ids(batches: &[PlannedAssessmentReviewLedgerBatch]) -> BTreeSet<EvidenceId> {
    batches
        .iter()
        .flat_map(|batch| {
            batch.plans.iter().flat_map(|plan| {
                let control =
                    matches!(plan.kind.basis(), NativeReviewProjectionBasis::Differential)
                        .then_some(plan.control_evidence_ids.as_slice())
                        .unwrap_or_default();
                control.iter().chain(&plan.candidate_evidence_ids)
            })
        })
        .cloned()
        .collect()
}

fn item_references(item: &AssessmentItem) -> BTreeSet<AssessmentEvidenceReference> {
    match item.basis() {
        AssessmentBasis::Observation(basis) => basis.evidence().iter().copied().collect(),
        AssessmentBasis::Differential(basis) => basis
            .control()
            .iter()
            .chain(basis.candidate())
            .copied()
            .collect(),
        AssessmentBasis::Verifier(_) => panic!("native review cannot project Confirmed"),
    }
}

fn shared_projection_snapshot(
    reverse_batches: bool,
) -> (
    Vec<(EvidenceId, AssessmentEvidenceReference)>,
    BTreeSet<AssessmentEvidenceReference>,
    Vec<AssessmentItem>,
) {
    let subject = root_subject();
    let mut batches = shared_review_batches(&subject);
    if reverse_batches {
        batches.reverse();
    }
    let all_ids = product_visible_ids(&batches);
    assert_eq!(all_ids.len(), 21);
    let knowledge = KnowledgeBase::new();
    for id in &all_ids {
        knowledge
            .insert_evidence(evidence(id.as_str(), &subject))
            .unwrap();
    }
    let mut context = projection_context(&knowledge, &subject);
    assert_eq!(project_batches(&mut context, &knowledge, &batches), Ok(2));
    assert_eq!(context.registered_evidence_count(), all_ids.len());
    let mapping = all_ids
        .iter()
        .map(|id| (id.clone(), context.evidence_reference_for(id).unwrap()))
        .collect::<Vec<_>>();
    let shared = SHARED_SOURCE_EVIDENCE
        .iter()
        .map(|id| {
            context
                .evidence_reference_for(&EvidenceId::parse(*id).unwrap())
                .unwrap()
        })
        .collect::<BTreeSet<_>>();
    let (_, items) = context.finish().into_parts();
    (mapping, shared, items)
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
        #[cfg(feature = "normalization-resilience")]
        NativeReviewProjectionKind::NormalizationHtmlTextTokenCase,
        #[cfg(feature = "normalization-resilience")]
        NativeReviewProjectionKind::NormalizationAttributeValueInterTokenTab,
        #[cfg(feature = "normalization-resilience")]
        NativeReviewProjectionKind::NormalizationUriAttributeInterTokenTab,
        #[cfg(feature = "normalization-resilience")]
        NativeReviewProjectionKind::NormalizationEventHandlerAttributeInterTokenTab,
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

#[cfg(feature = "normalization-resilience")]
#[test]
fn normalization_projection_kinds_are_exact_differential_knowledge_only_reviews() {
    for (kind, expected_capability) in [
        (
            NativeReviewProjectionKind::NormalizationHtmlTextTokenCase,
            "web.review.normalization-resilience.xss.html-text-boundary.html-token-case@1",
        ),
        (
            NativeReviewProjectionKind::NormalizationAttributeValueInterTokenTab,
            "web.review.normalization-resilience.xss.attribute-value-boundary.html-inter-token-tab@1",
        ),
        (
            NativeReviewProjectionKind::NormalizationUriAttributeInterTokenTab,
            "web.review.normalization-resilience.xss.uri-attribute-boundary.html-inter-token-tab@1",
        ),
        (
            NativeReviewProjectionKind::NormalizationEventHandlerAttributeInterTokenTab,
            "web.review.normalization-resilience.xss.event-handler-attribute-boundary.html-inter-token-tab@1",
        ),
    ] {
        let item = project_one(kind);
        assert_eq!(item.capability_id(), expected_capability);
        assert_eq!(item.disposition(), AssessmentDisposition::NeedsReview);
        assert!(matches!(item.basis(), AssessmentBasis::Differential(_)));
        assert_eq!(item.basis().case_reference(), None);
        assert_eq!(item.cwe(), None);
        assert_eq!(item.severity(), None);
        assert_ne!(item.disposition(), AssessmentDisposition::Confirmed);
        assert!(!item.capability_id().contains("bypass-confirmed"));
    }
}

#[cfg(feature = "normalization-resilience")]
#[test]
fn normalization_item_identity_binds_parent_family_and_is_rerun_stable() {
    let kinds = [
        NativeReviewProjectionKind::NormalizationAttributeValueInterTokenTab,
        NativeReviewProjectionKind::NormalizationUriAttributeInterTokenTab,
        NativeReviewProjectionKind::NormalizationEventHandlerAttributeInterTokenTab,
    ];
    let first = kinds.map(project_one);
    let replayed = kinds.map(project_one);
    for (original, replay) in first.iter().zip(&replayed) {
        assert_eq!(original.fingerprint(), replay.fingerprint());
    }
    let fingerprints = first
        .iter()
        .map(|item| item.fingerprint())
        .collect::<BTreeSet<_>>();
    assert_eq!(fingerprints.len(), kinds.len());
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
fn aggregate_native_review_projection_reuses_shared_source_references() {
    let (mapping, expected_shared, items) = shared_projection_snapshot(false);
    assert_eq!(mapping.len(), 21);
    assert_eq!(expected_shared.len(), SHARED_SOURCE_EVIDENCE.len());
    assert_eq!(items.len(), 2);
    assert!(items
        .iter()
        .all(|item| item.disposition() == AssessmentDisposition::NeedsReview));
    assert!(items
        .iter()
        .all(|item| item.disposition() != AssessmentDisposition::Confirmed));

    let reflection = items
        .iter()
        .find(|item| item.capability_id() == "web.review.reflection.script-element-context@1")
        .unwrap();
    let xss = items
        .iter()
        .find(|item| item.capability_id() == "web.review.xss.structural-boundary@1")
        .unwrap();
    assert_eq!(reflection.evidence_count(), 13);
    assert_eq!(xss.evidence_count(), 19);
    assert_eq!(
        item_references(reflection).len(),
        reflection.evidence_count()
    );
    assert_eq!(item_references(xss).len(), xss.evidence_count());
    let shared = item_references(reflection)
        .intersection(&item_references(xss))
        .copied()
        .collect::<BTreeSet<_>>();
    assert_eq!(shared, expected_shared);
}

#[test]
fn aggregate_native_review_projection_is_ledger_order_independent() {
    let (forward_mapping, _, mut forward_items) = shared_projection_snapshot(false);
    let (reverse_mapping, _, mut reverse_items) = shared_projection_snapshot(true);
    assert_eq!(forward_mapping, reverse_mapping);

    let item_key = |item: &AssessmentItem| {
        (
            item.capability_id(),
            item.fingerprint().to_owned(),
            item.disposition(),
            item_references(item),
        )
    };
    forward_items.sort_by_key(&item_key);
    reverse_items.sort_by_key(&item_key);
    assert_eq!(
        forward_items.iter().map(&item_key).collect::<Vec<_>>(),
        reverse_items.iter().map(&item_key).collect::<Vec<_>>()
    );
}

#[test]
fn aggregate_native_review_limit_remains_per_ledger() {
    let subject = root_subject();
    let kinds = [
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
    ];
    let knowledge = KnowledgeBase::new();
    let mut plans = Vec::new();
    for (index, kind) in kinds.into_iter().enumerate() {
        let control = format!("evidence:per-ledger:{index}:control");
        let candidate = format!("evidence:per-ledger:{index}:candidate");
        knowledge
            .insert_evidence(evidence(&control, &subject))
            .unwrap();
        knowledge
            .insert_evidence(evidence(&candidate, &subject))
            .unwrap();
        plans.push(plan(kind, &subject, &[&control], &[&candidate]));
    }
    let batches = vec![
        PlannedAssessmentReviewLedgerBatch {
            expected_subject: subject.clone(),
            plans: plans.drain(..MAX_NATIVE_REVIEW_PROJECTION_ITEMS).collect(),
        },
        PlannedAssessmentReviewLedgerBatch {
            expected_subject: subject.clone(),
            plans,
        },
    ];
    let mut context = projection_context(&knowledge, &subject);
    assert_eq!(
        project_batches(&mut context, &knowledge, &batches),
        Ok(kinds.len())
    );
    assert_eq!(context.finish().items().len(), kinds.len());
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

#[test]
fn zero_native_review_batches_are_a_noop() {
    let subject = root_subject();
    let knowledge = KnowledgeBase::new();
    let mut context = projection_context(&knowledge, &subject);
    assert_eq!(project_batches(&mut context, &knowledge, &[]), Ok(0));
    assert_eq!(context.registered_evidence_count(), 0);
    assert!(context.finish().items().is_empty());
}
