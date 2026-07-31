//! Thread-safe in-memory storage for evidence-driven scan knowledge.
//!
//! The store owns indexing and identity rules, but deliberately contains no
//! detection, scoring, planning, or persistence behavior. Producers can write
//! observations in any order; referential integrity is therefore eventual so
//! discovery modules remain independent from one another.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use venom_core::{
    EntityId, Evidence, EvidenceId, Fact, Hypothesis, KnowledgeEntity, KnowledgePredicate,
    KnowledgeRelation, RelationId,
};

/// Result of an idempotent write to the knowledge store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
pub enum KnowledgeStoreError {
    /// The identity exists, but its immutable claim or graph identity differs.
    IdentityConflict {
        /// Category of the conflicting record.
        kind: KnowledgeRecordKind,
        /// Reused stable identifier.
        id: String,
    },
}

impl fmt::Display for KnowledgeStoreError {
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

impl std::error::Error for KnowledgeStoreError {}

/// Counts of records currently held by a [`KnowledgeStore`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct KnowledgeStoreStats {
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
}

#[derive(Debug, Default)]
struct KnowledgeState {
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

/// Thread-safe, indexed memory shared by discovery, reasoning, and execution.
///
/// Writes are atomic across primary records and secondary indexes. Read methods
/// return owned snapshots, so callers never keep an internal lock while doing
/// asynchronous work.
///
/// Evidence and entities are immutable once their IDs are observed. Facts,
/// hypotheses, and relations may be updated only while their claim identity or
/// graph identity remains unchanged.
///
/// # Examples
///
/// ```rust
/// use venom_core::{
///     ConfidenceScore, EntityId, Evidence, EvidenceKind, EvidenceSource,
///     EvidenceValue, KnowledgePredicate,
/// };
/// use venom_scanner::{KnowledgeStore, KnowledgeWrite};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = KnowledgeStore::new();
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
/// assert_eq!(store.insert_evidence(evidence)?, KnowledgeWrite::Inserted);
/// assert_eq!(store.evidence_for_subject(&subject).len(), 1);
/// assert_eq!(store.evidence_for_predicate(&predicate).len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct KnowledgeStore {
    state: Arc<RwLock<KnowledgeState>>,
}

impl KnowledgeStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts one immutable observation.
    ///
    /// Repeating the exact record is idempotent. Reusing an evidence ID for a
    /// different observation is rejected because provenance IDs are immutable.
    pub fn insert_evidence(
        &self,
        evidence: Evidence,
    ) -> Result<KnowledgeWrite, KnowledgeStoreError> {
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
    pub fn upsert_fact(&self, fact: Fact) -> Result<KnowledgeWrite, KnowledgeStoreError> {
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

    /// Inserts a hypothesis or updates its evaluation and contributions.
    ///
    /// The subject, predicate, and value form the immutable claim identity for
    /// an existing hypothesis ID.
    pub fn upsert_hypothesis(
        &self,
        hypothesis: Hypothesis,
    ) -> Result<KnowledgeWrite, KnowledgeStoreError> {
        let id = hypothesis.id().to_owned();
        let subject = hypothesis.subject().clone();
        let predicate = hypothesis.predicate().clone();
        let mut state = self.write_state();

        if let Some(existing) = state.hypotheses.get(&id) {
            if existing == &hypothesis {
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
    ) -> Result<KnowledgeWrite, KnowledgeStoreError> {
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
    ) -> Result<KnowledgeWrite, KnowledgeStoreError> {
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

    /// Returns a consistent count snapshot under one read lock.
    pub fn stats(&self) -> KnowledgeStoreStats {
        let state = self.read_state();
        KnowledgeStoreStats {
            evidence: state.evidence.len(),
            facts: state.facts.len(),
            hypotheses: state.hypotheses.len(),
            entities: state.entities.len(),
            relations: state.relations.len(),
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

fn identity_conflict(kind: KnowledgeRecordKind, id: &impl fmt::Display) -> KnowledgeStoreError {
    KnowledgeStoreError::IdentityConflict {
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
        ConfidenceScore, ContributionDirection, EntityKind, EvidenceContribution, EvidenceKind,
        EvidenceSource, EvidenceValue, HypothesisState, RelationKind,
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
        let store = KnowledgeStore::new();
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
            Err(KnowledgeStoreError::IdentityConflict {
                kind: KnowledgeRecordKind::Evidence,
                id: evidence.id().to_string(),
            })
        );
        assert_eq!(store.stats().evidence, 1);
    }

    #[test]
    fn evidence_is_indexed_by_subject_and_predicate() {
        let store = KnowledgeStore::new();
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
    fn fact_updates_preserve_claim_identity_and_index_cardinality() {
        let store = KnowledgeStore::new();
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
        let store = KnowledgeStore::new();
        let evidence = evidence_for(subject(1), "Laravel");
        let mut hypothesis = Hypothesis::new(
            evidence.subject().clone(),
            evidence.predicate().clone(),
            evidence.value().clone(),
        );

        assert_eq!(
            store.upsert_hypothesis(hypothesis.clone()).unwrap(),
            KnowledgeWrite::Inserted
        );
        hypothesis.add_contribution(
            EvidenceContribution::new(
                evidence.id().clone(),
                ContributionDirection::Supporting,
                ConfidenceScore::from_percent(82).unwrap(),
                "framework header and cookie agree",
            )
            .unwrap(),
        );
        hypothesis.set_confidence(ConfidenceScore::from_percent(82).unwrap());
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
                .confidence()
                .basis_points(),
            8_200
        );
    }

    #[test]
    fn entities_and_relations_are_queryable_in_both_directions() {
        let store = KnowledgeStore::new();
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
        let store = KnowledgeStore::new();
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
        let store = KnowledgeStore::new();
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
}
