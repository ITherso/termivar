use super::*;
use termivar_core::{
    BayesianEvidence, ConceptId, ConfidenceScore, DerivationAlgorithm, EntityKind,
    EvidenceDerivation, EvidenceKind, EvidenceSource, EvidenceValue, HypothesisState,
    HypothesisStrength, OntologyAxiom, OntologyConcept, Probability, RelationKind,
};

fn derivation_algorithm() -> DerivationAlgorithm {
    DerivationAlgorithm::new("http.form-control-names", 1).unwrap()
}

fn derived(child: Evidence, parents: impl IntoIterator<Item = EvidenceId>) -> Evidence {
    child.derived_from(EvidenceDerivation::new(parents, derivation_algorithm()).unwrap())
}

fn subject(id: usize) -> EntityId {
    EntityId::new(format!("endpoint:https://example.test/{id}")).unwrap()
}

fn predicate() -> KnowledgePredicate {
    KnowledgePredicate::new("technology", "framework").unwrap()
}

fn evidence_for(subject: EntityId, value: &str) -> Evidence {
    Evidence::new(
        subject,
        EvidenceKind::Technology,
        predicate(),
        EvidenceValue::Text(value.into()),
        EvidenceSource::new("fingerprint.headers", "x-powered-by").unwrap(),
        ConfidenceScore::from_percent(85).unwrap(),
    )
}

fn hypothesis_for(id: &str, subject: EntityId, value: &str) -> Hypothesis {
    Hypothesis::with_id(
        id,
        subject,
        predicate(),
        EvidenceValue::Text(value.into()),
        Probability::from_percent(20).unwrap(),
    )
    .unwrap()
}

#[test]
fn evidence_writes_are_idempotent_and_identity_safe() {
    let store = KnowledgeBase::new();
    let evidence = evidence_for(subject(1), "Laravel");

    assert_eq!(
        store.insert_evidence(evidence.clone()).unwrap(),
        KnowledgeWrite::Inserted
    );
    assert_eq!(
        store.insert_evidence(evidence.clone()).unwrap(),
        KnowledgeWrite::Unchanged
    );

    let mut conflicting_wire = serde_json::to_value(&evidence).unwrap();
    conflicting_wire["value"] = serde_json::json!({
        "type": "text",
        "value": "Symfony"
    });
    let conflicting: Evidence = serde_json::from_value(conflicting_wire).unwrap();
    assert_eq!(
        store.insert_evidence(conflicting),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Evidence,
            id: evidence.id().to_string(),
        })
    );
    assert_eq!(store.stats().evidence, 1);
}

#[test]
fn derived_evidence_retains_exact_parent_forward_and_reverse() {
    let store = KnowledgeBase::new();
    let parent = evidence_for(subject(1), "body-sample");
    let parent_id = parent.id().clone();
    store.insert_evidence(parent).unwrap();

    let child = derived(
        evidence_for(subject(1), "form-controls"),
        [parent_id.clone()],
    );
    let child_id = child.id().clone();
    assert_eq!(
        store.insert_evidence(child).unwrap(),
        KnowledgeWrite::Inserted
    );

    let stored = store.evidence(&child_id).unwrap();
    assert_eq!(
        stored.origin().derivation().unwrap().parents(),
        std::slice::from_ref(&parent_id)
    );
    assert!(store.derivation_children(&parent_id).contains(&child_id));
    // A direct sibling has no lineage.
    assert!(store.derivation_children(&child_id).is_empty());
}

#[test]
fn same_batch_parent_after_child_in_order_is_valid() {
    let store = KnowledgeBase::new();
    let parent = evidence_for(subject(1), "body-sample");
    let parent_id = parent.id().clone();
    let child = derived(
        evidence_for(subject(1), "form-controls"),
        [parent_id.clone()],
    );
    let child_id = child.id().clone();

    // Child appears BEFORE its parent in input order; acceptance must not
    // depend on order.
    let writes = store.insert_evidence_batch(vec![child, parent]).unwrap();
    assert_eq!(
        writes,
        vec![KnowledgeWrite::Inserted, KnowledgeWrite::Inserted]
    );
    assert!(store.derivation_children(&parent_id).contains(&child_id));
}

#[test]
fn missing_parent_rejects_the_whole_batch_without_writing() {
    let store = KnowledgeBase::new();
    let ghost = EvidenceId::parse("does-not-exist").unwrap();
    let child = derived(evidence_for(subject(1), "form-controls"), [ghost]);
    let sibling = evidence_for(subject(1), "sibling");
    assert!(matches!(
        store.insert_evidence_batch(vec![sibling, child]),
        Err(KnowledgeBaseError::MissingDerivationParent { .. })
    ));
    assert_eq!(store.stats().evidence, 0);
}

#[test]
fn self_referencing_derivation_is_rejected() {
    let store = KnowledgeBase::new();
    let base = evidence_for(subject(1), "self");
    let id = base.id().clone();
    let child = derived(base, [id]);
    assert!(matches!(
        store.insert_evidence(child),
        Err(KnowledgeBaseError::SelfDerivation { .. })
    ));
    assert_eq!(store.stats().evidence, 0);
}

#[test]
fn two_node_cycle_in_one_batch_is_rejected_atomically() {
    let store = KnowledgeBase::new();
    let a = evidence_for(subject(1), "a");
    let b = evidence_for(subject(1), "b");
    let a_id = a.id().clone();
    let b_id = b.id().clone();
    let a_cyclic = derived(a, [b_id]);
    let b_cyclic = derived(b, [a_id]);
    assert!(matches!(
        store.insert_evidence_batch(vec![a_cyclic, b_cyclic]),
        Err(KnowledgeBaseError::DerivationCycle { .. })
    ));
    assert_eq!(store.stats().evidence, 0);
}

#[test]
fn cross_subject_parent_is_rejected() {
    let store = KnowledgeBase::new();
    let parent = evidence_for(subject(1), "body-sample");
    let parent_id = parent.id().clone();
    store.insert_evidence(parent).unwrap();

    let child = derived(evidence_for(subject(2), "form-controls"), [parent_id]);
    assert!(matches!(
        store.insert_evidence(child),
        Err(KnowledgeBaseError::DerivationSubjectMismatch { .. })
    ));
    assert_eq!(store.stats().evidence, 1);
}

#[test]
fn conflicting_lineage_for_existing_child_is_an_identity_conflict() {
    let store = KnowledgeBase::new();
    let p1 = evidence_for(subject(1), "p1");
    let p2 = evidence_for(subject(1), "p2");
    let p1_id = p1.id().clone();
    let p2_id = p2.id().clone();
    store.insert_evidence_batch(vec![p1, p2]).unwrap();

    let base = evidence_for(subject(1), "child");
    let child_id = base.id().clone();
    let via_p1 = base
        .clone()
        .derived_from(EvidenceDerivation::new([p1_id], derivation_algorithm()).unwrap());
    let via_p2 =
        base.derived_from(EvidenceDerivation::new([p2_id], derivation_algorithm()).unwrap());

    assert_eq!(
        store.insert_evidence(via_p1).unwrap(),
        KnowledgeWrite::Inserted
    );
    assert_eq!(
        store.insert_evidence(via_p2),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Evidence,
            id: child_id.to_string(),
        })
    );
}

#[test]
fn reusing_a_direct_id_as_derived_is_an_identity_conflict() {
    let store = KnowledgeBase::new();
    let parent = evidence_for(subject(1), "parent");
    let parent_id = parent.id().clone();
    store.insert_evidence(parent).unwrap();

    let direct = evidence_for(subject(1), "record");
    let id = direct.id().clone();
    store.insert_evidence(direct.clone()).unwrap();

    let as_derived =
        direct.derived_from(EvidenceDerivation::new([parent_id], derivation_algorithm()).unwrap());
    assert_eq!(
        store.insert_evidence(as_derived),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Evidence,
            id: id.to_string(),
        })
    );
}

#[test]
fn exact_derived_record_reinserts_idempotently() {
    let store = KnowledgeBase::new();
    let parent = evidence_for(subject(1), "parent");
    let parent_id = parent.id().clone();
    store.insert_evidence(parent).unwrap();

    let child = derived(evidence_for(subject(1), "child"), [parent_id]);
    assert_eq!(
        store.insert_evidence(child.clone()).unwrap(),
        KnowledgeWrite::Inserted
    );
    assert_eq!(
        store.insert_evidence(child).unwrap(),
        KnowledgeWrite::Unchanged
    );
}

#[test]
fn evidence_batches_are_atomic_and_preserve_input_order() {
    let store = KnowledgeBase::new();
    let first = evidence_for(subject(1), "Laravel");
    let second = evidence_for(subject(1), "Livewire");

    assert_eq!(
        store
            .insert_evidence_batch(vec![first.clone(), first.clone(), second.clone()])
            .unwrap(),
        vec![
            KnowledgeWrite::Inserted,
            KnowledgeWrite::Unchanged,
            KnowledgeWrite::Inserted,
        ]
    );

    let third = evidence_for(subject(1), "Sanctum");
    let mut conflicting_wire = serde_json::to_value(&first).unwrap();
    conflicting_wire["value"] = serde_json::json!({
        "type": "text",
        "value": "Symfony"
    });
    let conflicting: Evidence = serde_json::from_value(conflicting_wire).unwrap();

    assert!(matches!(
        store.insert_evidence_batch(vec![third.clone(), conflicting]),
        Err(KnowledgeBaseError::IdentityConflict { .. })
    ));
    assert!(store
        .evidence_for_subject(third.subject())
        .iter()
        .all(|item| item.id() != third.id()));
    assert_eq!(store.stats().evidence, 2);
}

#[test]
fn evidence_relation_bundles_are_atomic_and_idempotent() {
    let store = KnowledgeBase::new();
    let observation = evidence_for(subject(1), "visibility-difference");
    let resource = EntityId::new("resource:account-42").unwrap();
    let relation = KnowledgeRelation::with_id(
        RelationId::parse("relation:comparison-scope-1").unwrap(),
        observation.subject().clone(),
        resource.clone(),
        RelationKind::RelatedTo,
        ConfidenceScore::from_percent(95).unwrap(),
        observation.id().clone(),
    );

    assert_eq!(
        store
            .insert_evidence_with_relation(observation.clone(), relation.clone())
            .unwrap(),
        (KnowledgeWrite::Inserted, KnowledgeWrite::Inserted)
    );
    assert_eq!(
        store
            .insert_evidence_with_relation(observation.clone(), relation.clone())
            .unwrap(),
        (KnowledgeWrite::Unchanged, KnowledgeWrite::Unchanged)
    );
    assert_eq!(
        store.relations_from(observation.subject()),
        vec![relation.clone()]
    );
    assert_eq!(store.relations_to(&resource).len(), 1);

    let updated_relation = KnowledgeRelation::with_id(
        relation.id().clone(),
        relation.from().clone(),
        relation.to().clone(),
        relation.kind().clone(),
        ConfidenceScore::from_percent(90).unwrap(),
        observation.id().clone(),
    );
    assert_eq!(
        store
            .insert_evidence_with_relation(observation.clone(), updated_relation.clone())
            .unwrap(),
        (KnowledgeWrite::Unchanged, KnowledgeWrite::Updated)
    );
    assert_eq!(
        store.relations_from(observation.subject()),
        vec![updated_relation.clone()]
    );
    assert_eq!(
        store.relations_to(&resource),
        vec![updated_relation.clone()]
    );
    assert_eq!(
        store.relation(updated_relation.id()),
        Some(updated_relation)
    );

    let unrelated = evidence_for(subject(2), "other");
    let mismatched = KnowledgeRelation::new(
        observation.subject().clone(),
        resource,
        RelationKind::RelatedTo,
        ConfidenceScore::MAX,
        observation.id().clone(),
    );
    assert!(matches!(
        store.insert_evidence_with_relation(unrelated.clone(), mismatched),
        Err(KnowledgeBaseError::RelationEvidenceMismatch { .. })
    ));
    assert!(store.evidence(unrelated.id()).is_none());
    assert_eq!(store.stats().relations, 1);

    let wrong_subject = KnowledgeRelation::new(
        subject(999),
        EntityId::new("resource:other").unwrap(),
        RelationKind::RelatedTo,
        ConfidenceScore::MAX,
        unrelated.id().clone(),
    );
    assert!(matches!(
        store.insert_evidence_with_relation(unrelated.clone(), wrong_subject),
        Err(KnowledgeBaseError::RelationSubjectMismatch { .. })
    ));
    assert!(store.evidence(unrelated.id()).is_none());
    assert_eq!(store.stats().relations, 1);
}

#[test]
fn evidence_relation_identity_conflicts_roll_back_the_complete_bundle() {
    let evidence_conflict_store = KnowledgeBase::new();
    let existing = evidence_for(subject(1), "existing");
    evidence_conflict_store
        .insert_evidence(existing.clone())
        .unwrap();
    let mut conflicting_wire = serde_json::to_value(&existing).unwrap();
    conflicting_wire["value"] = serde_json::json!({
        "type": "text",
        "value": "conflicting"
    });
    let conflicting: Evidence = serde_json::from_value(conflicting_wire).unwrap();
    let absent_relation = KnowledgeRelation::with_id(
        RelationId::parse("relation:must-stay-absent").unwrap(),
        conflicting.subject().clone(),
        EntityId::new("resource:one").unwrap(),
        RelationKind::RelatedTo,
        ConfidenceScore::MAX,
        conflicting.id().clone(),
    );
    let absent_relation_id = absent_relation.id().clone();

    assert!(matches!(
        evidence_conflict_store.insert_evidence_with_relation(conflicting, absent_relation),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Evidence,
            ..
        })
    ));
    assert!(evidence_conflict_store
        .relation(&absent_relation_id)
        .is_none());
    assert_eq!(evidence_conflict_store.stats().evidence, 1);
    assert_eq!(evidence_conflict_store.stats().relations, 0);

    let relation_conflict_store = KnowledgeBase::new();
    let reserved_evidence = evidence_for(subject(10), "reserved");
    let reserved_relation = KnowledgeRelation::with_id(
        RelationId::parse("relation:reserved").unwrap(),
        reserved_evidence.subject().clone(),
        EntityId::new("resource:reserved").unwrap(),
        RelationKind::RelatedTo,
        ConfidenceScore::MAX,
        reserved_evidence.id().clone(),
    );
    relation_conflict_store
        .upsert_relation(reserved_relation.clone())
        .unwrap();
    let new_evidence = evidence_for(subject(20), "new");
    let conflicting_relation = KnowledgeRelation::with_id(
        reserved_relation.id().clone(),
        new_evidence.subject().clone(),
        EntityId::new("resource:new").unwrap(),
        RelationKind::RelatedTo,
        ConfidenceScore::MAX,
        new_evidence.id().clone(),
    );

    assert!(matches!(
        relation_conflict_store
            .insert_evidence_with_relation(new_evidence.clone(), conflicting_relation),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Relation,
            ..
        })
    ));
    assert!(relation_conflict_store
        .evidence(new_evidence.id())
        .is_none());
    assert_eq!(relation_conflict_store.stats().evidence, 0);
    assert_eq!(relation_conflict_store.stats().relations, 1);
}

#[test]
fn evidence_is_indexed_by_subject_and_predicate() {
    let store = KnowledgeBase::new();
    let first_subject = subject(1);
    let second_subject = subject(2);
    store
        .insert_evidence(evidence_for(first_subject.clone(), "Laravel"))
        .unwrap();
    store
        .insert_evidence(evidence_for(second_subject.clone(), "Django"))
        .unwrap();

    assert_eq!(store.evidence_for_subject(&first_subject).len(), 1);
    assert_eq!(store.evidence_for_subject(&second_subject).len(), 1);
    assert_eq!(store.evidence_for_predicate(&predicate()).len(), 2);
    assert!(store.evidence_for_subject(&subject(3)).is_empty());
}

#[test]
fn subject_snapshot_is_consistent_and_immutable() {
    let store = KnowledgeBase::new();
    let shared_subject = subject(1);
    store
        .insert_evidence(evidence_for(shared_subject.clone(), "Laravel"))
        .unwrap();
    let snapshot = store.snapshot_for_subject(&shared_subject);

    store
        .insert_evidence(evidence_for(shared_subject.clone(), "Livewire"))
        .unwrap();

    assert_eq!(snapshot.subject(), &shared_subject);
    assert_eq!(snapshot.evidence().len(), 1);
    assert_eq!(
        store.snapshot_for_subject(&shared_subject).evidence().len(),
        2
    );
}

#[test]
fn revisions_track_rule_visible_writes_and_guard_empty_reasoning_batches() {
    let store = KnowledgeBase::new();
    let shared_subject = subject(1);
    let stable = store.snapshot_for_subject(&shared_subject);
    assert_eq!(stable.subject_revision(), 0);
    assert_eq!(stable.ontology_revision(), 0);

    let entity = KnowledgeEntity::new(
        EntityId::new("resource:revision-test").unwrap(),
        EntityKind::Custom("resource".into()),
        "revision test",
    )
    .unwrap();
    store.insert_entity(entity.clone()).unwrap();
    let relation_evidence = evidence_for(shared_subject.clone(), "relation-only");
    store
        .upsert_relation(KnowledgeRelation::new(
            shared_subject.clone(),
            entity.id().clone(),
            RelationKind::RelatedTo,
            ConfidenceScore::MAX,
            relation_evidence.id().clone(),
        ))
        .unwrap();
    assert!(store
        .upsert_reasoning_hypothesis_batch(&stable, Vec::new())
        .unwrap()
        .is_empty());

    store
        .insert_evidence(evidence_for(subject(2), "other-subject"))
        .unwrap();
    assert_eq!(
        store
            .snapshot_for_subject(&shared_subject)
            .subject_revision(),
        0
    );

    let observation = evidence_for(shared_subject.clone(), "Laravel");
    store.insert_evidence(observation.clone()).unwrap();
    let after_evidence = store.snapshot_for_subject(&shared_subject);
    assert_eq!(after_evidence.subject_revision(), 1);
    store.insert_evidence(observation.clone()).unwrap();
    assert_eq!(
        store
            .snapshot_for_subject(&shared_subject)
            .subject_revision(),
        1
    );
    assert!(matches!(
        store.upsert_reasoning_hypothesis_batch(&stable, Vec::new()),
        Err(KnowledgeBaseError::StaleSnapshot { .. })
    ));

    let fact = Fact::new(
        shared_subject.clone(),
        predicate(),
        EvidenceValue::Text("Laravel".into()),
        ConfidenceScore::from_percent(80).unwrap(),
        observation.id().clone(),
    );
    store.upsert_fact(fact).unwrap();
    assert_eq!(
        store
            .snapshot_for_subject(&shared_subject)
            .subject_revision(),
        2
    );
    store
        .upsert_hypothesis(hypothesis_for(
            "hypothesis:revision-test",
            shared_subject.clone(),
            "Laravel",
        ))
        .unwrap();
    assert_eq!(
        store
            .snapshot_for_subject(&shared_subject)
            .subject_revision(),
        3
    );

    let before_ontology = store.snapshot_for_subject(&shared_subject);
    let concept = OntologyConcept::new(
        ConceptId::new("revision-test-concept").unwrap(),
        "Revision test concept",
    )
    .unwrap();
    store.register_concept(concept.clone()).unwrap();
    let after_ontology = store.snapshot_for_subject(&shared_subject);
    assert_eq!(after_ontology.ontology_revision(), 1);
    store.register_concept(concept).unwrap();
    assert_eq!(
        store
            .snapshot_for_subject(&shared_subject)
            .ontology_revision(),
        1
    );
    assert!(matches!(
        store.upsert_reasoning_hypothesis_batch(&before_ontology, Vec::new()),
        Err(KnowledgeBaseError::StaleSnapshot { .. })
    ));
}

#[test]
fn reasoning_batch_rejects_another_subject_in_release_semantics() {
    let store = KnowledgeBase::new();
    let snapshot = store.snapshot_for_subject(&subject(1));
    let foreign = hypothesis_for("hypothesis:foreign", subject(2), "Laravel");

    assert!(matches!(
        store.upsert_reasoning_hypothesis_batch(&snapshot, vec![foreign]),
        Err(KnowledgeBaseError::ReasoningSubjectMismatch {
            hypothesis_id,
            expected,
            actual,
        }) if hypothesis_id == "hypothesis:foreign"
            && expected == subject(1)
            && actual == subject(2)
    ));
    assert_eq!(store.stats().hypotheses, 0);
}

#[test]
fn fact_updates_preserve_claim_identity_and_index_cardinality() {
    let store = KnowledgeBase::new();
    let evidence = evidence_for(subject(1), "Laravel");
    let fact = Fact::new(
        evidence.subject().clone(),
        evidence.predicate().clone(),
        evidence.value().clone(),
        ConfidenceScore::from_percent(70).unwrap(),
        evidence.id().clone(),
    );

    assert_eq!(
        store.upsert_fact(fact.clone()).unwrap(),
        KnowledgeWrite::Inserted
    );
    let updated = fact
        .clone()
        .with_confidence(ConfidenceScore::from_percent(90).unwrap());
    assert_eq!(store.upsert_fact(updated).unwrap(), KnowledgeWrite::Updated);

    assert_eq!(store.facts_for_subject(evidence.subject()).len(), 1);
    assert_eq!(store.facts_for_predicate(evidence.predicate()).len(), 1);
    assert_eq!(
        store.fact(fact.id()).unwrap().confidence().basis_points(),
        9_000
    );
}

#[test]
fn hypothesis_updates_replace_evaluation_without_duplicate_indexes() {
    let store = KnowledgeBase::new();
    let evidence = evidence_for(subject(1), "Laravel");
    let mut hypothesis = Hypothesis::new(
        evidence.subject().clone(),
        evidence.predicate().clone(),
        evidence.value().clone(),
        Probability::from_percent(10).unwrap(),
    );

    assert_eq!(
        store.upsert_hypothesis(hypothesis.clone()).unwrap(),
        KnowledgeWrite::Inserted
    );
    hypothesis
        .observe(
            BayesianEvidence::new(
                evidence.id().clone(),
                Probability::from_percent(90).unwrap(),
                Probability::from_percent(10).unwrap(),
                "framework header and cookie agree",
            )
            .unwrap(),
        )
        .unwrap();
    hypothesis.set_strength(HypothesisStrength::Strong);
    hypothesis.set_state(HypothesisState::Supported);
    assert_eq!(
        store.upsert_hypothesis(hypothesis.clone()).unwrap(),
        KnowledgeWrite::Updated
    );

    assert_eq!(store.hypotheses_for_subject(evidence.subject()).len(), 1);
    assert_eq!(
        store
            .hypothesis(hypothesis.id())
            .unwrap()
            .posterior()
            .parts_per_million(),
        500_000
    );
}

#[test]
fn hypothesis_batches_are_atomic_idempotent_and_input_ordered() {
    let store = KnowledgeBase::new();
    let first = hypothesis_for("hypothesis:first", subject(1), "Laravel");
    let second = hypothesis_for("hypothesis:second", subject(1), "Livewire");

    assert_eq!(
        store
            .upsert_hypothesis_batch(vec![first.clone(), first.clone(), second.clone()])
            .unwrap(),
        vec![
            KnowledgeWrite::Inserted,
            KnowledgeWrite::Unchanged,
            KnowledgeWrite::Inserted,
        ]
    );
    let mut updated_second = second.clone();
    updated_second.set_strength(HypothesisStrength::Strong);
    assert_eq!(
        store
            .upsert_hypothesis_batch(vec![first.clone(), updated_second.clone(), updated_second,])
            .unwrap(),
        vec![
            KnowledgeWrite::Unchanged,
            KnowledgeWrite::Updated,
            KnowledgeWrite::Unchanged,
        ]
    );

    let third = hypothesis_for("hypothesis:third", subject(1), "Sanctum");
    let conflicting = hypothesis_for(first.id(), subject(2), "Laravel");
    assert!(matches!(
        store.upsert_hypothesis_batch(vec![third.clone(), conflicting]),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Hypothesis,
            ..
        })
    ));
    assert!(store.hypothesis(third.id()).is_none());
    assert_eq!(store.stats().hypotheses, 2);

    let duplicate_store = KnowledgeBase::new();
    let duplicate = hypothesis_for("hypothesis:duplicate", subject(3), "Laravel");
    let mut conflicting_evaluation = duplicate.clone();
    conflicting_evaluation.set_strength(HypothesisStrength::Strong);
    assert!(matches!(
        duplicate_store.upsert_hypothesis_batch(vec![duplicate.clone(), conflicting_evaluation]),
        Err(KnowledgeBaseError::IdentityConflict {
            kind: KnowledgeRecordKind::Hypothesis,
            ..
        })
    ));
    assert!(duplicate_store.hypothesis(duplicate.id()).is_none());
}

#[test]
fn reasoning_batch_preserves_verifier_terminal_states() {
    for terminal_state in [HypothesisState::Confirmed, HypothesisState::Rejected] {
        let store = KnowledgeBase::new();
        let mut terminal = hypothesis_for("hypothesis:terminal", subject(1), "Laravel");
        terminal.set_state(terminal_state);
        store.upsert_hypothesis(terminal.clone()).unwrap();
        let snapshot = store.snapshot_for_subject(terminal.subject());

        let mut recalibrated = terminal.clone();
        recalibrated.set_strength(HypothesisStrength::Strong);
        recalibrated.set_state(HypothesisState::Supported);
        assert_eq!(
            store
                .upsert_reasoning_hypothesis_batch(&snapshot, vec![recalibrated])
                .unwrap(),
            vec![KnowledgeWrite::Updated]
        );
        let stored = store.hypothesis(terminal.id()).unwrap();
        assert_eq!(stored.state(), terminal_state);
        assert_eq!(stored.strength(), HypothesisStrength::Strong);
    }
}

#[test]
fn atomic_state_transition_preserves_latest_recalibration() {
    let store = KnowledgeBase::new();
    let mut initial = hypothesis_for("hypothesis:atomic-transition", subject(1), "Laravel");
    initial.set_state(HypothesisState::Supported);
    store.upsert_hypothesis(initial.clone()).unwrap();
    let stale_clone = store.hypothesis(initial.id()).unwrap();

    let mut recalibrated = stale_clone.clone();
    recalibrated.set_strength(HypothesisStrength::Strong);
    recalibrated
        .observe(
            BayesianEvidence::new(
                EvidenceId::parse("evidence:latest-recalibration").unwrap(),
                Probability::from_percent(90).unwrap(),
                Probability::from_percent(10).unwrap(),
                "latest reasoning evidence",
            )
            .unwrap(),
        )
        .unwrap();
    store.upsert_hypothesis(recalibrated.clone()).unwrap();
    let before_transition = store.snapshot_for_subject(initial.subject());

    assert_eq!(
        store.transition_hypothesis_state(
            initial.id(),
            initial.subject(),
            HypothesisState::Confirmed,
            None,
        ),
        HypothesisStateTransition::Written(KnowledgeWrite::Updated)
    );
    let stored = store.hypothesis(initial.id()).unwrap();
    assert_eq!(stored.state(), HypothesisState::Confirmed);
    assert_eq!(stored.strength(), HypothesisStrength::Strong);
    assert_eq!(stored.belief(), recalibrated.belief());
    assert_ne!(stored.belief(), stale_clone.belief());
    assert_eq!(
        store
            .snapshot_for_subject(initial.subject())
            .subject_revision(),
        before_transition.subject_revision() + 1
    );

    assert_eq!(
        store.transition_hypothesis_state(
            initial.id(),
            initial.subject(),
            HypothesisState::Confirmed,
            None,
        ),
        HypothesisStateTransition::Written(KnowledgeWrite::Unchanged)
    );
    assert_eq!(
        store
            .snapshot_for_subject(initial.subject())
            .subject_revision(),
        before_transition.subject_revision() + 1
    );
}

#[test]
fn entities_and_relations_are_queryable_in_both_directions() {
    let store = KnowledgeBase::new();
    let host_id = EntityId::new("host:example.test").unwrap();
    let service_id = EntityId::new("service:https:example.test:443").unwrap();
    let host = KnowledgeEntity::new(host_id.clone(), EntityKind::Host, "example.test").unwrap();
    let service =
        KnowledgeEntity::new(service_id.clone(), EntityKind::Service, "HTTPS 443").unwrap();
    let evidence = evidence_for(subject(1), "nginx");
    let relation = KnowledgeRelation::new(
        host_id.clone(),
        service_id.clone(),
        RelationKind::Exposes,
        ConfidenceScore::from_percent(95).unwrap(),
        evidence.id().clone(),
    );

    assert_eq!(
        store.insert_entity(host.clone()).unwrap(),
        KnowledgeWrite::Inserted
    );
    store.insert_entity(service).unwrap();
    store.upsert_relation(relation.clone()).unwrap();

    assert_eq!(store.entity(&host_id), Some(host));
    assert_eq!(store.relations_from(&host_id), vec![relation.clone()]);
    assert_eq!(store.relations_to(&service_id), vec![relation]);
    assert!(store.relations_to(&host_id).is_empty());
}

#[test]
fn incoming_relation_pages_are_bounded_ordered_and_cursor_exclusive() {
    let store = KnowledgeBase::new();
    let destination = EntityId::new("resource:paged").unwrap();
    for suffix in ["c", "a", "b"] {
        store
            .upsert_relation(KnowledgeRelation::with_id(
                RelationId::parse(format!("relation:{suffix}")).unwrap(),
                subject(1),
                destination.clone(),
                RelationKind::RelatedTo,
                ConfidenceScore::MAX,
                EvidenceId::parse(format!("evidence:{suffix}")).unwrap(),
            ))
            .unwrap();
    }

    let ids = |relations: Vec<KnowledgeRelation>| {
        relations
            .into_iter()
            .map(|relation| relation.id().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(store.relations_to_page(&destination, None, 2)),
        vec!["relation:a", "relation:b"]
    );
    let (first_page, has_more) = store.relations_to_page_with_more(&destination, None, 2);
    assert_eq!(ids(first_page), vec!["relation:a", "relation:b"]);
    assert!(has_more);
    let (last_page, has_more) = store.relations_to_page_with_more(
        &destination,
        Some(&RelationId::parse("relation:b").unwrap()),
        2,
    );
    assert_eq!(ids(last_page), vec!["relation:c"]);
    assert!(!has_more);
    assert_eq!(
        ids(store.relations_to_page(
            &destination,
            Some(&RelationId::parse("relation:b").unwrap()),
            10,
        )),
        vec!["relation:c"]
    );
    assert_eq!(
        ids(store.relations_to_page(
            &destination,
            Some(&RelationId::parse("relation:ab").unwrap()),
            10,
        )),
        vec!["relation:b", "relation:c"]
    );
    assert!(store.relations_to_page(&destination, None, 0).is_empty());
    assert!(store
        .relations_to_page(
            &destination,
            Some(&RelationId::parse("relation:c").unwrap()),
            1,
        )
        .is_empty());
}

#[test]
fn relation_storage_rejects_oversized_fields_and_provenance_before_writing() {
    let store = KnowledgeBase::new();
    let from = subject(1);
    let to = EntityId::new("resource:bounded-relation").unwrap();
    let evidence_id = EvidenceId::parse("evidence:bounded-relation").unwrap();
    let relation = |id: RelationId,
                    from: EntityId,
                    to: EntityId,
                    kind: RelationKind,
                    evidence_id: EvidenceId| {
        KnowledgeRelation::with_id(id, from, to, kind, ConfidenceScore::MAX, evidence_id)
    };
    let assert_limit = |result: Result<KnowledgeWrite, KnowledgeBaseError>,
                        field: &'static str,
                        actual: usize,
                        maximum: usize| {
        assert_eq!(
            result,
            Err(KnowledgeBaseError::RelationLimitExceeded {
                field,
                actual,
                maximum,
            })
        );
    };

    assert_limit(
        store.upsert_relation(relation(
            RelationId::parse("r".repeat(MAX_KNOWLEDGE_RELATION_ID_BYTES + 1)).unwrap(),
            from.clone(),
            to.clone(),
            RelationKind::RelatedTo,
            evidence_id.clone(),
        )),
        "id",
        MAX_KNOWLEDGE_RELATION_ID_BYTES + 1,
        MAX_KNOWLEDGE_RELATION_ID_BYTES,
    );
    assert_limit(
        store.upsert_relation(relation(
            RelationId::parse("relation:oversized-from").unwrap(),
            EntityId::new("f".repeat(MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES + 1)).unwrap(),
            to.clone(),
            RelationKind::RelatedTo,
            evidence_id.clone(),
        )),
        "from",
        MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES + 1,
        MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES,
    );
    assert_limit(
        store.upsert_relation(relation(
            RelationId::parse("relation:oversized-to").unwrap(),
            from.clone(),
            EntityId::new("t".repeat(MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES + 1)).unwrap(),
            RelationKind::RelatedTo,
            evidence_id.clone(),
        )),
        "to",
        MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES + 1,
        MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES,
    );
    assert_limit(
        store.upsert_relation(relation(
            RelationId::parse("relation:oversized-kind").unwrap(),
            from.clone(),
            to.clone(),
            RelationKind::Custom("k".repeat(MAX_KNOWLEDGE_RELATION_KIND_BYTES + 1)),
            evidence_id.clone(),
        )),
        "kind",
        MAX_KNOWLEDGE_RELATION_KIND_BYTES + 1,
        MAX_KNOWLEDGE_RELATION_KIND_BYTES,
    );
    assert_limit(
        store.upsert_relation(relation(
            RelationId::parse("relation:oversized-evidence-id").unwrap(),
            from.clone(),
            to.clone(),
            RelationKind::RelatedTo,
            EvidenceId::parse("e".repeat(MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES + 1)).unwrap(),
        )),
        "evidence_id",
        MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES + 1,
        MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES,
    );

    let mut excessive_provenance = relation(
        RelationId::parse("relation:oversized-provenance").unwrap(),
        from.clone(),
        to.clone(),
        RelationKind::RelatedTo,
        evidence_id,
    );
    for index in 1..=MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS {
        excessive_provenance
            .add_evidence(EvidenceId::parse(format!("evidence:extra:{index}")).unwrap());
    }
    assert_limit(
        store.upsert_relation(excessive_provenance),
        "evidence_ids",
        MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS + 1,
        MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS,
    );

    let evidence = evidence_for(from, "bounded atomic relation");
    let oversized_atomic_relation = relation(
        RelationId::parse("r".repeat(MAX_KNOWLEDGE_RELATION_ID_BYTES + 1)).unwrap(),
        evidence.subject().clone(),
        to,
        RelationKind::RelatedTo,
        evidence.id().clone(),
    );
    assert!(matches!(
        store.insert_evidence_with_relation(evidence, oversized_atomic_relation),
        Err(KnowledgeBaseError::RelationLimitExceeded { field: "id", .. })
    ));
    assert_eq!(store.stats().evidence, 0);
    assert_eq!(store.stats().relations, 0);
}

#[test]
fn relation_provenance_updates_do_not_duplicate_edges() {
    let store = KnowledgeBase::new();
    let first_evidence = evidence_for(subject(1), "nginx");
    let second_evidence = evidence_for(subject(1), "HTTP/2");
    let from = EntityId::new("host:example.test").unwrap();
    let to = EntityId::new("service:https:example.test:443").unwrap();
    let mut relation = KnowledgeRelation::new(
        from.clone(),
        to,
        RelationKind::Exposes,
        ConfidenceScore::from_percent(90).unwrap(),
        first_evidence.id().clone(),
    );
    store.upsert_relation(relation.clone()).unwrap();
    relation.add_evidence(second_evidence.id().clone());

    assert_eq!(
        store.upsert_relation(relation.clone()).unwrap(),
        KnowledgeWrite::Updated
    );
    assert_eq!(store.relations_from(&from).len(), 1);
    assert_eq!(
        store.relation(relation.id()).unwrap().evidence_ids().len(),
        2
    );
}

#[test]
fn concurrent_writers_keep_primary_records_and_indexes_consistent() {
    let store = KnowledgeBase::new();
    let shared_subject = subject(1);
    let writers: Vec<_> = (0..16)
        .map(|writer| {
            let store = store.clone();
            let shared_subject = shared_subject.clone();
            std::thread::spawn(move || {
                store
                    .insert_evidence(evidence_for(
                        shared_subject,
                        &format!("technology-{writer}"),
                    ))
                    .unwrap()
            })
        })
        .collect();

    for writer in writers {
        assert_eq!(writer.join().unwrap(), KnowledgeWrite::Inserted);
    }

    assert_eq!(store.stats().evidence, 16);
    assert_eq!(store.evidence_for_subject(&shared_subject).len(), 16);
    assert_eq!(store.evidence_for_predicate(&predicate()).len(), 16);
}

#[test]
fn knowledge_base_keeps_ontology_separate_from_instance_graph() {
    let knowledge = KnowledgeBase::new();
    let laravel = ConceptId::new("laravel").unwrap();
    let framework = ConceptId::new("framework").unwrap();
    let technology = ConceptId::new("technology").unwrap();
    for (id, label) in [
        (laravel.clone(), "Laravel"),
        (framework.clone(), "Framework"),
        (technology.clone(), "Technology"),
    ] {
        knowledge
            .register_concept(OntologyConcept::new(id, label).unwrap())
            .unwrap();
    }
    knowledge
        .register_axiom(OntologyAxiom::new(
            laravel.clone(),
            Ontology::relation_id(Ontology::IS_A).unwrap(),
            framework.clone(),
        ))
        .unwrap();
    knowledge
        .register_axiom(OntologyAxiom::new(
            framework,
            Ontology::relation_id(Ontology::IS_A).unwrap(),
            technology.clone(),
        ))
        .unwrap();

    assert!(knowledge.ontology_is_a(&laravel, &technology).unwrap());
    assert_eq!(knowledge.stats().ontology.concepts, 3);
    assert_eq!(knowledge.stats().ontology.axioms, 2);
    assert_eq!(knowledge.stats().entities, 0);
    assert_eq!(knowledge.stats().relations, 0);
}
