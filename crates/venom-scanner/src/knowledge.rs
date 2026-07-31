//! Thread-safe in-memory knowledge base for evidence-driven reasoning.
//!
//! The base owns ontology, instance relationships, evidence, facts, and
//! hypotheses, but deliberately contains no detection, scoring, planning, or
//! persistence behavior. Producers can write observations in any order;
//! referential integrity is therefore eventual so discovery modules remain
//! independent from one another.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use serde::{Deserialize, Serialize};
use venom_core::{
    ConceptId, EntityId, Evidence, EvidenceId, Fact, Hypothesis, KnowledgeEntity,
    KnowledgePredicate, KnowledgeRelation, Ontology, OntologyAxiom, OntologyConcept, OntologyError,
    OntologyRelationType, OntologyStats, OntologyWrite, RelationId, RelationTypeId,
};

/// Result of an idempotent write to the knowledge base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KnowledgeWrite {
    /// A new identity was stored and indexed.
    Inserted,
    /// An existing mutable record was replaced with a newer evaluation.
    Updated,
    /// The store already contained the exact same record.
    Unchanged,
}

/// Record categories used in identity-conflict diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnowledgeRecordKind {
    /// Immutable evidence observation.
    Evidence,
    /// Materialized fact.
    Fact,
    /// Evaluated hypothesis.
    Hypothesis,
    /// Knowledge-graph entity.
    Entity,
    /// Knowledge-graph relation.
    Relation,
}

impl fmt::Display for KnowledgeRecordKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Evidence => "evidence",
            Self::Fact => "fact",
            Self::Hypothesis => "hypothesis",
            Self::Entity => "entity",
            Self::Relation => "relation",
        };
        formatter.write_str(name)
    }
}

/// Errors raised when a record attempts to reuse an identity for new meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnowledgeBaseError {
    /// The identity exists, but its immutable claim or graph identity differs.
    IdentityConflict {
        /// Category of the conflicting record.
        kind: KnowledgeRecordKind,
        /// Reused stable identifier.
        id: String,
    },
}

impl fmt::Display for KnowledgeBaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityConflict { kind, id } => {
                write!(
                    formatter,
                    "{kind} identity {id} already has different meaning"
                )
            },
        }
    }
}

impl std::error::Error for KnowledgeBaseError {}

/// Counts of records currently held by a [`KnowledgeBase`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct KnowledgeBaseStats {
    /// Number of immutable observations.
    pub evidence: usize,
    /// Number of materialized facts.
    pub facts: usize,
    /// Number of evaluated hypotheses.
    pub hypotheses: usize,
    /// Number of knowledge-graph entities.
    pub entities: usize,
    /// Number of evidence-backed graph relations.
    pub relations: usize,
    /// Counts for ontology concepts, relation types, and axioms.
    pub ontology: OntologyStats,
}

/// Consistent, immutable knowledge for one subject at one point in time.
///
/// Rule evaluation uses this snapshot so every expression in one decision
/// cycle observes the same ontology, evidence, facts, and hypotheses.
#[derive(Debug, Clone)]
pub struct KnowledgeSnapshot {
    subject: EntityId,
    ontology: Ontology,
    evidence: Vec<Evidence>,
    facts: Vec<Fact>,
    hypotheses: Vec<Hypothesis>,
}

impl KnowledgeSnapshot {
    /// Returns the subject captured by this snapshot.
    pub fn subject(&self) -> &EntityId {
        &self.subject
    }

    /// Returns evidence ordered by stable evidence ID.
    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }

    /// Returns facts ordered by stable fact ID.
    pub fn facts(&self) -> &[Fact] {
        &self.facts
    }

    /// Returns hypotheses ordered by stable hypothesis ID.
    pub fn hypotheses(&self) -> &[Hypothesis] {
        &self.hypotheses
    }

    /// Returns the ontology captured in the same read transaction.
    pub fn ontology(&self) -> &Ontology {
        &self.ontology
    }
}

#[derive(Debug, Default)]
struct KnowledgeState {
    ontology: Ontology,
    evidence: HashMap<EvidenceId, Evidence>,
    facts: HashMap<String, Fact>,
    hypotheses: HashMap<String, Hypothesis>,
    entities: HashMap<EntityId, KnowledgeEntity>,
    relations: HashMap<RelationId, KnowledgeRelation>,
    evidence_by_subject: HashMap<EntityId, BTreeSet<EvidenceId>>,
    evidence_by_predicate: HashMap<KnowledgePredicate, BTreeSet<EvidenceId>>,
    facts_by_subject: HashMap<EntityId, BTreeSet<String>>,
    facts_by_predicate: HashMap<KnowledgePredicate, BTreeSet<String>>,
    hypotheses_by_subject: HashMap<EntityId, BTreeSet<String>>,
    hypotheses_by_predicate: HashMap<KnowledgePredicate, BTreeSet<String>>,
    relations_from: HashMap<EntityId, BTreeSet<RelationId>>,
    relations_to: HashMap<EntityId, BTreeSet<RelationId>>,
}

/// Thread-safe, indexed knowledge shared by evidence and decision engines.
///
/// Writes are atomic across primary records and secondary indexes. Read methods
/// return owned snapshots, so callers never keep an internal lock while doing
/// asynchronous work.
///
/// Ontology definitions provide domain meaning, while entities and relations
/// form the instance graph. Evidence and entities are immutable once their IDs
/// are observed. Facts, hypotheses, and relations may be updated only while
/// their claim identity or graph identity remains unchanged.
///
/// # Examples
///
/// ```rust
/// use venom_core::{
///     ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource,
///     EvidenceValue, KnowledgePredicate,
/// };
/// use venom_scanner::{KnowledgeBase, KnowledgeWrite};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let knowledge = KnowledgeBase::new();
/// let subject = EntityId::new("endpoint:https://example.test")?;
/// let predicate = KnowledgePredicate::new("http.header", "server")?;
/// let evidence = Evidence::new(
///     subject.clone(),
///     EvidenceKind::Http,
///     predicate.clone(),
///     EvidenceValue::Text("nginx".into()),
///     EvidenceSource::new("discovery.headers", "server-header")?,
///     ConfidenceScore::from_percent(85)?,
/// );
///
/// assert_eq!(knowledge.insert_evidence(evidence)?, KnowledgeWrite::Inserted);
/// assert_eq!(knowledge.evidence_for_subject(&subject).len(), 1);
/// assert_eq!(knowledge.evidence_for_predicate(&predicate).len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct KnowledgeBase {
    state: Arc<RwLock<KnowledgeState>>,
}

impl KnowledgeBase {
    /// Creates an empty knowledge base with standard ontology relation types.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a domain concept in the ontology.
    pub fn register_concept(
        &self,
        concept: OntologyConcept,
    ) -> Result<OntologyWrite, OntologyError> {
        self.write_state().ontology.add_concept(concept)
    }

    /// Registers a custom semantic relation type in the ontology.
    pub fn register_relation_type(
        &self,
        relation_type: OntologyRelationType,
    ) -> Result<OntologyWrite, OntologyError> {
        self.write_state().ontology.add_relation_type(relation_type)
    }

    /// Registers a validated semantic axiom in the ontology.
    pub fn register_axiom(&self, axiom: OntologyAxiom) -> Result<OntologyWrite, OntologyError> {
        self.write_state().ontology.add_axiom(axiom)
    }

    /// Returns an owned, internally consistent ontology snapshot.
    pub fn ontology_snapshot(&self) -> Ontology {
        self.read_state().ontology.clone()
    }

    /// Evaluates a semantic relationship using the registered ontology.
    pub fn ontology_is_related(
        &self,
        subject: &ConceptId,
        relation: &RelationTypeId,
        object: &ConceptId,
    ) -> Result<bool, OntologyError> {
        self.read_state()
            .ontology
            .is_related(subject, relation, object)
    }

    /// Evaluates the canonical transitive ontology hierarchy.
    pub fn ontology_is_a(
        &self,
        child: &ConceptId,
        ancestor: &ConceptId,
    ) -> Result<bool, OntologyError> {
        self.read_state().ontology.is_a(child, ancestor)
    }

    /// Inserts one immutable observation.
    ///
    /// Repeating the exact record is idempotent. Reusing an evidence ID for a
    /// different observation is rejected because provenance IDs are immutable.
    pub fn insert_evidence(
        &self,
        evidence: Evidence,
    ) -> Result<KnowledgeWrite, KnowledgeBaseError> {
        let id = evidence.id().clone();
        let subject = evidence.subject().clone();
        let predicate = evidence.predicate().clone();
        let mut state = self.write_state();

        if let Some(existing) = state.evidence.get(&id) {
            return if existing == &evidence {
                Ok(KnowledgeWrite::Unchanged)
            } else {
                Err(identity_conflict(KnowledgeRecordKind::Evidence, &id))
            };
        }

        state.evidence.insert(id.clone(), evidence);
        index(&mut state.evidence_by_subject, subject, id.clone());
        index(&mut state.evidence_by_predicate, predicate, id);
        Ok(KnowledgeWrite::Inserted)
    }

    /// Inserts a materialized fact or updates its confidence and provenance.
    ///
    /// The subject, predicate, and value form the immutable claim identity for
    /// an existing fact ID.
    pub fn upsert_fact(&self, fact: Fact) -> Result<KnowledgeWrite, KnowledgeBaseError> {
        let id = fact.id().to_owned();
        let subject = fact.subject().clone();
        let predicate = fact.predicate().clone();
        let mut state = self.write_state();

        if let Some(existing) = state.facts.get(&id) {
            if existing == &fact {
                return Ok(KnowledgeWrite::Unchanged);
            }
            if existing.subject() != fact.subject()
                || existing.predicate() != fact.predicate()
                || existing.value() != fact.value()
            {
                return Err(identity_conflict(KnowledgeRecordKind::Fact, &id));
            }
            state.facts.insert(id, fact);
            return Ok(KnowledgeWrite::Updated);
        }

        state.facts.insert(id.clone(), fact);
        index(&mut state.facts_by_subject, subject, id.clone());
        index(&mut state.facts_by_predicate, predicate, id);
        Ok(KnowledgeWrite::Inserted)
    }

    /// Inserts a hypothesis or updates its Bayesian evaluation.
    ///
    /// The subject, predicate, and value form the immutable claim identity for
    /// an existing hypothesis ID.
    pub fn upsert_hypothesis(
        &self,
        hypothesis: Hypothesis,
    ) -> Result<KnowledgeWrite, KnowledgeBaseError> {
        let id = hypothesis.id().to_owned();
        let subject = hypothesis.subject().clone();
        let predicate = hypothesis.predicate().clone();
        let mut state = self.write_state();

        if let Some(existing) = state.hypotheses.get(&id) {
            if existing.same_evaluation_as(&hypothesis) {
                return Ok(KnowledgeWrite::Unchanged);
            }
            if existing.subject() != hypothesis.subject()
                || existing.predicate() != hypothesis.predicate()
                || existing.value() != hypothesis.value()
            {
                return Err(identity_conflict(KnowledgeRecordKind::Hypothesis, &id));
            }
            state.hypotheses.insert(id, hypothesis);
            return Ok(KnowledgeWrite::Updated);
        }

        state.hypotheses.insert(id.clone(), hypothesis);
        index(&mut state.hypotheses_by_subject, subject, id.clone());
        index(&mut state.hypotheses_by_predicate, predicate, id);
        Ok(KnowledgeWrite::Inserted)
    }

    /// Inserts one immutable knowledge-graph entity.
    pub fn insert_entity(
        &self,
        entity: KnowledgeEntity,
    ) -> Result<KnowledgeWrite, KnowledgeBaseError> {
        let id = entity.id().clone();
        let mut state = self.write_state();

        if let Some(existing) = state.entities.get(&id) {
            return if existing == &entity {
                Ok(KnowledgeWrite::Unchanged)
            } else {
                Err(identity_conflict(KnowledgeRecordKind::Entity, &id))
            };
        }

        state.entities.insert(id, entity);
        Ok(KnowledgeWrite::Inserted)
    }

    /// Inserts a relation or updates its confidence and provenance.
    ///
    /// The source, destination, and relation kind form the immutable graph
    /// identity for an existing relation ID.
    pub fn upsert_relation(
        &self,
        relation: KnowledgeRelation,
    ) -> Result<KnowledgeWrite, KnowledgeBaseError> {
        let id = relation.id().clone();
        let from = relation.from().clone();
        let to = relation.to().clone();
        let mut state = self.write_state();

        if let Some(existing) = state.relations.get(&id) {
            if existing == &relation {
                return Ok(KnowledgeWrite::Unchanged);
            }
            if existing.from() != relation.from()
                || existing.to() != relation.to()
                || existing.kind() != relation.kind()
            {
                return Err(identity_conflict(KnowledgeRecordKind::Relation, &id));
            }
            state.relations.insert(id, relation);
            return Ok(KnowledgeWrite::Updated);
        }

        state.relations.insert(id.clone(), relation);
        index(&mut state.relations_from, from, id.clone());
        index(&mut state.relations_to, to, id);
        Ok(KnowledgeWrite::Inserted)
    }

    /// Returns an evidence snapshot by ID.
    pub fn evidence(&self, id: &EvidenceId) -> Option<Evidence> {
        self.read_state().evidence.get(id).cloned()
    }

    /// Returns a fact snapshot by ID.
    pub fn fact(&self, id: &str) -> Option<Fact> {
        self.read_state().facts.get(id).cloned()
    }

    /// Returns a hypothesis snapshot by ID.
    pub fn hypothesis(&self, id: &str) -> Option<Hypothesis> {
        self.read_state().hypotheses.get(id).cloned()
    }

    /// Returns an entity snapshot by ID.
    pub fn entity(&self, id: &EntityId) -> Option<KnowledgeEntity> {
        self.read_state().entities.get(id).cloned()
    }

    /// Returns a relation snapshot by ID.
    pub fn relation(&self, id: &RelationId) -> Option<KnowledgeRelation> {
        self.read_state().relations.get(id).cloned()
    }

    /// Returns evidence describing a subject, ordered by evidence ID.
    pub fn evidence_for_subject(&self, subject: &EntityId) -> Vec<Evidence> {
        let state = self.read_state();
        collect_indexed(state.evidence_by_subject.get(subject), &state.evidence)
    }

    /// Returns evidence matching a predicate, ordered by evidence ID.
    pub fn evidence_for_predicate(&self, predicate: &KnowledgePredicate) -> Vec<Evidence> {
        let state = self.read_state();
        collect_indexed(state.evidence_by_predicate.get(predicate), &state.evidence)
    }

    /// Returns facts describing a subject, ordered by fact ID.
    pub fn facts_for_subject(&self, subject: &EntityId) -> Vec<Fact> {
        let state = self.read_state();
        collect_indexed(state.facts_by_subject.get(subject), &state.facts)
    }

    /// Returns facts matching a predicate, ordered by fact ID.
    pub fn facts_for_predicate(&self, predicate: &KnowledgePredicate) -> Vec<Fact> {
        let state = self.read_state();
        collect_indexed(state.facts_by_predicate.get(predicate), &state.facts)
    }

    /// Returns hypotheses describing a subject, ordered by hypothesis ID.
    pub fn hypotheses_for_subject(&self, subject: &EntityId) -> Vec<Hypothesis> {
        let state = self.read_state();
        collect_indexed(state.hypotheses_by_subject.get(subject), &state.hypotheses)
    }

    /// Returns hypotheses matching a predicate, ordered by hypothesis ID.
    pub fn hypotheses_for_predicate(&self, predicate: &KnowledgePredicate) -> Vec<Hypothesis> {
        let state = self.read_state();
        collect_indexed(
            state.hypotheses_by_predicate.get(predicate),
            &state.hypotheses,
        )
    }

    /// Returns outgoing graph relations, ordered by relation ID.
    pub fn relations_from(&self, entity_id: &EntityId) -> Vec<KnowledgeRelation> {
        let state = self.read_state();
        collect_indexed(state.relations_from.get(entity_id), &state.relations)
    }

    /// Returns incoming graph relations, ordered by relation ID.
    pub fn relations_to(&self, entity_id: &EntityId) -> Vec<KnowledgeRelation> {
        let state = self.read_state();
        collect_indexed(state.relations_to.get(entity_id), &state.relations)
    }

    /// Captures all rule-visible knowledge for a subject under one read lock.
    pub fn snapshot_for_subject(&self, subject: &EntityId) -> KnowledgeSnapshot {
        let state = self.read_state();
        KnowledgeSnapshot {
            subject: subject.clone(),
            ontology: state.ontology.clone(),
            evidence: collect_indexed(state.evidence_by_subject.get(subject), &state.evidence),
            facts: collect_indexed(state.facts_by_subject.get(subject), &state.facts),
            hypotheses: collect_indexed(
                state.hypotheses_by_subject.get(subject),
                &state.hypotheses,
            ),
        }
    }

    /// Returns a consistent count snapshot under one read lock.
    pub fn stats(&self) -> KnowledgeBaseStats {
        let state = self.read_state();
        KnowledgeBaseStats {
            evidence: state.evidence.len(),
            facts: state.facts.len(),
            hypotheses: state.hypotheses.len(),
            entities: state.entities.len(),
            relations: state.relations.len(),
            ontology: state.ontology.stats(),
        }
    }

    fn read_state(&self) -> RwLockReadGuard<'_, KnowledgeState> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, KnowledgeState> {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Compatibility alias for the original storage-oriented name.
#[deprecated(note = "use KnowledgeBase; the base also owns ontology semantics")]
pub type KnowledgeStore = KnowledgeBase;

/// Compatibility alias for [`KnowledgeBaseError`].
#[deprecated(note = "use KnowledgeBaseError")]
pub type KnowledgeStoreError = KnowledgeBaseError;

/// Compatibility alias for [`KnowledgeBaseStats`].
#[deprecated(note = "use KnowledgeBaseStats")]
pub type KnowledgeStoreStats = KnowledgeBaseStats;

fn identity_conflict(kind: KnowledgeRecordKind, id: &impl fmt::Display) -> KnowledgeBaseError {
    KnowledgeBaseError::IdentityConflict {
        kind,
        id: id.to_string(),
    }
}

fn index<K, I>(index: &mut HashMap<K, BTreeSet<I>>, key: K, id: I)
where
    K: Eq + Hash,
    I: Ord,
{
    index.entry(key).or_default().insert(id);
}

fn collect_indexed<K, V>(ids: Option<&BTreeSet<K>>, values: &HashMap<K, V>) -> Vec<V>
where
    K: Eq + Hash + Ord,
    V: Clone,
{
    ids.into_iter()
        .flatten()
        .filter_map(|id| values.get(id).cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use venom_core::{
        BayesianEvidence, ConfidenceScore, EntityKind, EvidenceKind, EvidenceSource, EvidenceValue,
        HypothesisState, HypothesisStrength, Probability, RelationKind,
    };

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
}
