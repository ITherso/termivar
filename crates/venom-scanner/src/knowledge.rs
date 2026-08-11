//! Thread-safe in-memory knowledge base for evidence-driven reasoning.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** `ScanContext` constructs and privately owns a `KnowledgeBase`
//!   on Surface A, but the current legacy phases do not consume it (construction
//!   is not active use); Surface B actively uses it as deterministic reasoning
//!   state.
//! - **Default `venom scan`:** no (constructed but not consumed by the phases).
//! - **Support:** implemented and tested.
//!
//! See `docs/internals/runtime-map.md`.
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
    ConceptId, EntityId, Evidence, EvidenceId, Fact, Hypothesis, HypothesisState, KnowledgeEntity,
    KnowledgePredicate, KnowledgeRelation, Ontology, OntologyAxiom, OntologyConcept, OntologyError,
    OntologyRelationType, OntologyStats, OntologyWrite, RelationId, RelationKind, RelationTypeId,
};

/// Hard byte ceiling for one stored knowledge-relation identifier.
pub const MAX_KNOWLEDGE_RELATION_ID_BYTES: usize = 512;
/// Hard byte ceiling for either entity identifier on a stored relation.
pub const MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES: usize = 2_048;
/// Hard byte ceiling for a stored custom relation-kind identifier.
pub const MAX_KNOWLEDGE_RELATION_KIND_BYTES: usize = 256;
/// Hard ceiling for distinct evidence records backing one stored relation.
pub const MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS: usize = 32;
/// Hard byte ceiling for each evidence identifier backing a stored relation.
pub const MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES: usize = 512;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HypothesisStateTransition {
    Missing,
    SubjectMismatch {
        actual: EntityId,
    },
    StaleSnapshot(KnowledgeBaseError),
    TerminalConflict {
        current: HypothesisState,
        attempted: HypothesisState,
    },
    Written(KnowledgeWrite),
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

/// Errors raised when a knowledge record violates storage or identity invariants.
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

    /// An atomic relation bundle did not reference exactly its supplied evidence.
    RelationEvidenceMismatch {
        /// Relation whose provenance was inconsistent.
        relation_id: String,
        /// Evidence expected to be the relation's sole provenance record.
        evidence_id: String,
    },

    /// An atomic relation did not originate at its evidence subject.
    RelationSubjectMismatch {
        /// Relation whose source entity was inconsistent.
        relation_id: String,
        /// Subject described by the evidence.
        evidence_subject: String,
        /// Source entity declared by the relation.
        relation_from: String,
    },

    /// A relation field or provenance collection exceeded its storage ceiling.
    RelationLimitExceeded {
        /// Stable field name (`id`, `from`, `to`, `kind`, `evidence_ids`, or
        /// `evidence_id`).
        field: &'static str,
        /// Rejected byte or item count.
        actual: usize,
        /// Inclusive compiled ceiling.
        maximum: usize,
    },

    /// A reasoning batch was evaluated against knowledge that has since changed.
    StaleSnapshot {
        /// Subject captured by the stale snapshot.
        subject: EntityId,
        /// Subject revision captured by the snapshot.
        expected_subject_revision: u64,
        /// Current subject revision.
        actual_subject_revision: u64,
        /// Ontology revision captured by the snapshot.
        expected_ontology_revision: u64,
        /// Current ontology revision.
        actual_ontology_revision: u64,
    },

    /// A reasoning batch contained a conclusion for another subject.
    ReasoningSubjectMismatch {
        /// Hypothesis whose subject violated the batch boundary.
        hypothesis_id: String,
        /// Subject captured by the reasoning snapshot.
        expected: EntityId,
        /// Subject declared by the hypothesis.
        actual: EntityId,
    },

    /// A derived evidence record referenced a parent that neither already
    /// exists nor appears in the same atomic batch.
    MissingDerivationParent {
        /// Derived child evidence ID.
        child: String,
        /// Referenced parent evidence ID that could not be resolved.
        parent: String,
    },

    /// A derived evidence record referenced itself as a parent.
    SelfDerivation {
        /// Evidence ID that referenced itself.
        evidence_id: String,
    },

    /// A derived evidence record referenced a parent recorded for a different
    /// subject.
    DerivationSubjectMismatch {
        /// Derived child evidence ID.
        child: String,
        /// Referenced parent evidence ID.
        parent: String,
    },

    /// The derivation edges in one atomic batch formed a cycle.
    DerivationCycle {
        /// One evidence ID participating in the detected cycle.
        evidence_id: String,
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
            Self::RelationEvidenceMismatch {
                relation_id,
                evidence_id,
            } => write!(
                formatter,
                "relation {relation_id} must be backed only by evidence {evidence_id}"
            ),
            Self::RelationSubjectMismatch {
                relation_id,
                evidence_subject,
                relation_from,
            } => write!(
                formatter,
                "relation {relation_id} starts at {relation_from}, not evidence subject {evidence_subject}"
            ),
            Self::RelationLimitExceeded {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "knowledge relation {field} size {actual} exceeds hard ceiling {maximum}"
            ),
            Self::StaleSnapshot {
                subject,
                expected_subject_revision,
                actual_subject_revision,
                expected_ontology_revision,
                actual_ontology_revision,
            } => write!(
                formatter,
                "knowledge snapshot for {subject} is stale (subject revision {expected_subject_revision}->{actual_subject_revision}, ontology revision {expected_ontology_revision}->{actual_ontology_revision})"
            ),
            Self::ReasoningSubjectMismatch {
                hypothesis_id,
                expected,
                actual,
            } => write!(
                formatter,
                "reasoning hypothesis {hypothesis_id} belongs to {actual}, expected snapshot subject {expected}"
            ),
            Self::MissingDerivationParent { child, parent } => write!(
                formatter,
                "derived evidence {child} references parent {parent} that is neither stored nor in the same batch"
            ),
            Self::SelfDerivation { evidence_id } => write!(
                formatter,
                "derived evidence {evidence_id} references itself as a parent"
            ),
            Self::DerivationSubjectMismatch { child, parent } => write!(
                formatter,
                "derived evidence {child} references parent {parent} recorded for a different subject"
            ),
            Self::DerivationCycle { evidence_id } => write!(
                formatter,
                "derivation lineage forms a cycle through evidence {evidence_id}"
            ),
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
    subject_revision: u64,
    ontology_revision: u64,
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

    /// Returns the subject-local knowledge revision captured by this snapshot.
    pub fn subject_revision(&self) -> u64 {
        self.subject_revision
    }

    /// Returns the global ontology revision captured by this snapshot.
    pub fn ontology_revision(&self) -> u64 {
        self.ontology_revision
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

    pub(crate) fn with_evidence_correlation(&self, correlation_id: &str) -> Self {
        Self {
            subject: self.subject.clone(),
            subject_revision: self.subject_revision,
            ontology_revision: self.ontology_revision,
            ontology: self.ontology.clone(),
            evidence: self
                .evidence
                .iter()
                .filter(|evidence| evidence.source().correlation_id() == Some(correlation_id))
                .cloned()
                .collect(),
            facts: self.facts.clone(),
            hypotheses: self.hypotheses.clone(),
        }
    }

    pub(crate) fn with_projected_hypothesis_state(
        &self,
        hypothesis_id: &str,
        state: HypothesisState,
    ) -> Option<Self> {
        let mut projected = self.clone();
        projected
            .hypotheses
            .iter_mut()
            .find(|hypothesis| hypothesis.id() == hypothesis_id)?
            .set_state(state);
        Some(projected)
    }
}

#[derive(Debug, Default)]
struct KnowledgeState {
    ontology: Ontology,
    ontology_revision: u64,
    subject_revisions: HashMap<EntityId, u64>,
    evidence: HashMap<EvidenceId, Evidence>,
    facts: HashMap<String, Fact>,
    hypotheses: HashMap<String, Hypothesis>,
    entities: HashMap<EntityId, KnowledgeEntity>,
    relations: HashMap<RelationId, KnowledgeRelation>,
    evidence_by_subject: HashMap<EntityId, BTreeSet<EvidenceId>>,
    evidence_by_predicate: HashMap<KnowledgePredicate, BTreeSet<EvidenceId>>,
    /// Reverse derivation lineage: parent evidence ID -> derived child IDs.
    /// Forward lineage (child -> parents) is carried by each record's origin.
    derivation_children: HashMap<EvidenceId, BTreeSet<EvidenceId>>,
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
        let mut state = self.write_state();
        let write = state.ontology.add_concept(concept)?;
        if write == OntologyWrite::Inserted {
            bump_ontology_revision(&mut state);
        }
        Ok(write)
    }

    /// Registers a custom semantic relation type in the ontology.
    pub fn register_relation_type(
        &self,
        relation_type: OntologyRelationType,
    ) -> Result<OntologyWrite, OntologyError> {
        let mut state = self.write_state();
        let write = state.ontology.add_relation_type(relation_type)?;
        if write == OntologyWrite::Inserted {
            bump_ontology_revision(&mut state);
        }
        Ok(write)
    }

    /// Registers a validated semantic axiom in the ontology.
    pub fn register_axiom(&self, axiom: OntologyAxiom) -> Result<OntologyWrite, OntologyError> {
        let mut state = self.write_state();
        let write = state.ontology.add_axiom(axiom)?;
        if write == OntologyWrite::Inserted {
            bump_ontology_revision(&mut state);
        }
        Ok(write)
    }

    pub(crate) fn install_ontology_definitions(
        &self,
        concepts: &[OntologyConcept],
        axioms: &[OntologyAxiom],
    ) -> Result<(usize, usize), OntologyError> {
        let mut state = self.write_state();
        let mut prospective = state.ontology.clone();
        let mut concepts_inserted = 0;
        let mut axioms_inserted = 0;

        for concept in concepts {
            concepts_inserted += usize::from(matches!(
                prospective.add_concept(concept.clone())?,
                OntologyWrite::Inserted
            ));
        }
        for axiom in axioms {
            axioms_inserted += usize::from(matches!(
                prospective.add_axiom(axiom.clone())?,
                OntologyWrite::Inserted
            ));
        }

        state.ontology = prospective;
        if concepts_inserted != 0 || axioms_inserted != 0 {
            bump_ontology_revision(&mut state);
        }
        Ok((concepts_inserted, axioms_inserted))
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

        if evidence.origin().derivation().is_some() {
            let mut pending = HashMap::with_capacity(1);
            pending.insert(id.clone(), evidence.clone());
            validate_batch_derivations(&state, &pending)?;
        }

        index_derivation(&mut state, &evidence);
        state.evidence.insert(id.clone(), evidence);
        bump_subject_revision(&mut state, &subject);
        index(&mut state.evidence_by_subject, subject, id.clone());
        index(&mut state.evidence_by_predicate, predicate, id);
        Ok(KnowledgeWrite::Inserted)
    }

    /// Inserts an evidence batch in one write transaction.
    ///
    /// Every identity is validated before the first record is written. If an
    /// existing record or another item in the batch reuses an evidence ID for
    /// different meaning, the complete batch is rejected without changing the
    /// knowledge base. Results preserve input order; exact duplicates are
    /// idempotent.
    pub fn insert_evidence_batch(
        &self,
        evidence: Vec<Evidence>,
    ) -> Result<Vec<KnowledgeWrite>, KnowledgeBaseError> {
        let mut state = self.write_state();
        let mut pending = HashMap::<EvidenceId, Evidence>::new();

        for observation in &evidence {
            let id = observation.id();
            if state
                .evidence
                .get(id)
                .is_some_and(|existing| existing != observation)
                || pending
                    .get(id)
                    .is_some_and(|existing| existing != observation)
            {
                return Err(identity_conflict(KnowledgeRecordKind::Evidence, id));
            }
            pending
                .entry(id.clone())
                .or_insert_with(|| observation.clone());
        }

        // Lineage is validated across the whole batch before any write, so a
        // missing parent, self-reference, cross-subject parent, or cycle rejects
        // the complete batch without leaving an orphaned child or index entry.
        validate_batch_derivations(&state, &pending)?;

        let mut writes = Vec::with_capacity(evidence.len());
        for observation in evidence {
            let id = observation.id().clone();
            if state.evidence.contains_key(&id) {
                writes.push(KnowledgeWrite::Unchanged);
                continue;
            }

            let subject = observation.subject().clone();
            let predicate = observation.predicate().clone();
            index_derivation(&mut state, &observation);
            state.evidence.insert(id.clone(), observation);
            bump_subject_revision(&mut state, &subject);
            index(&mut state.evidence_by_subject, subject, id.clone());
            index(&mut state.evidence_by_predicate, predicate, id);
            writes.push(KnowledgeWrite::Inserted);
        }
        Ok(writes)
    }

    /// Returns the derived evidence records computed directly from `parent`,
    /// ordered by evidence ID. Forward lineage (a derived record's exact
    /// parents) is read from that record's [`venom_core::EvidenceOrigin`].
    pub fn derivation_children(&self, parent: &EvidenceId) -> BTreeSet<EvidenceId> {
        self.read_state()
            .derivation_children
            .get(parent)
            .cloned()
            .unwrap_or_default()
    }

    /// Atomically inserts one immutable observation and its sole graph edge.
    ///
    /// The relation must cite exactly the supplied evidence ID. Both identity
    /// conflicts are checked before either record or secondary index changes,
    /// so callers never persist an orphaned half of the bundle. Relation IDs,
    /// endpoints, custom kinds, and provenance are checked against the compiled
    /// storage ceilings before either record is written.
    pub fn insert_evidence_with_relation(
        &self,
        evidence: Evidence,
        relation: KnowledgeRelation,
    ) -> Result<(KnowledgeWrite, KnowledgeWrite), KnowledgeBaseError> {
        validate_relation_bounds(&relation)?;
        let evidence_id = evidence.id().clone();
        let relation_id = relation.id().clone();
        if relation.evidence_ids().len() != 1 || !relation.evidence_ids().contains(&evidence_id) {
            return Err(KnowledgeBaseError::RelationEvidenceMismatch {
                relation_id: relation_id.to_string(),
                evidence_id: evidence_id.to_string(),
            });
        }
        if relation.from() != evidence.subject() {
            return Err(KnowledgeBaseError::RelationSubjectMismatch {
                relation_id: relation_id.to_string(),
                evidence_subject: evidence.subject().to_string(),
                relation_from: relation.from().to_string(),
            });
        }

        let evidence_subject = evidence.subject().clone();
        let evidence_predicate = evidence.predicate().clone();
        let relation_from = relation.from().clone();
        let relation_to = relation.to().clone();
        let mut state = self.write_state();

        let evidence_write = match state.evidence.get(&evidence_id) {
            Some(existing) if existing == &evidence => KnowledgeWrite::Unchanged,
            Some(_) => {
                return Err(identity_conflict(
                    KnowledgeRecordKind::Evidence,
                    &evidence_id,
                ));
            },
            None => KnowledgeWrite::Inserted,
        };
        let relation_write = match state.relations.get(&relation_id) {
            Some(existing) if existing == &relation => KnowledgeWrite::Unchanged,
            Some(existing)
                if existing.from() == relation.from()
                    && existing.to() == relation.to()
                    && existing.kind() == relation.kind() =>
            {
                KnowledgeWrite::Updated
            },
            Some(_) => {
                return Err(identity_conflict(
                    KnowledgeRecordKind::Relation,
                    &relation_id,
                ));
            },
            None => KnowledgeWrite::Inserted,
        };

        if evidence_write == KnowledgeWrite::Inserted {
            state.evidence.insert(evidence_id.clone(), evidence);
            bump_subject_revision(&mut state, &evidence_subject);
            index(
                &mut state.evidence_by_subject,
                evidence_subject,
                evidence_id.clone(),
            );
            index(
                &mut state.evidence_by_predicate,
                evidence_predicate,
                evidence_id,
            );
        }
        if relation_write != KnowledgeWrite::Unchanged {
            state.relations.insert(relation_id.clone(), relation);
            if relation_write == KnowledgeWrite::Inserted {
                index(
                    &mut state.relations_from,
                    relation_from,
                    relation_id.clone(),
                );
                index(&mut state.relations_to, relation_to, relation_id);
            }
        }

        Ok((evidence_write, relation_write))
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
            bump_subject_revision(&mut state, &subject);
            return Ok(KnowledgeWrite::Updated);
        }

        state.facts.insert(id.clone(), fact);
        bump_subject_revision(&mut state, &subject);
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
        self.upsert_hypothesis_batch(vec![hypothesis])
            .map(|writes| writes[0])
    }

    /// Inserts or updates a hypothesis batch in one write transaction.
    ///
    /// Every stored and intra-batch identity is validated before the first
    /// hypothesis or secondary index changes. Reusing an ID for a different
    /// claim, or supplying different evaluations for one ID in the same batch,
    /// rejects the complete batch. Results preserve input order; semantically
    /// exact duplicates are idempotent even when their update timestamps differ.
    pub fn upsert_hypothesis_batch(
        &self,
        hypotheses: Vec<Hypothesis>,
    ) -> Result<Vec<KnowledgeWrite>, KnowledgeBaseError> {
        self.upsert_hypothesis_batch_with_policy(hypotheses, false, None)
    }

    /// Atomically writes rule-produced hypotheses from a current snapshot.
    ///
    /// Snapshot validation, terminal state lookup, and every resulting write
    /// happen under the same knowledge-base write lock. A concurrent rule-visible
    /// write rejects the complete batch, including an empty unmatched batch.
    pub(crate) fn upsert_reasoning_hypothesis_batch(
        &self,
        snapshot: &KnowledgeSnapshot,
        hypotheses: Vec<Hypothesis>,
    ) -> Result<Vec<KnowledgeWrite>, KnowledgeBaseError> {
        if let Some(hypothesis) = hypotheses
            .iter()
            .find(|hypothesis| hypothesis.subject() != snapshot.subject())
        {
            return Err(KnowledgeBaseError::ReasoningSubjectMismatch {
                hypothesis_id: hypothesis.id().to_owned(),
                expected: snapshot.subject().clone(),
                actual: hypothesis.subject().clone(),
            });
        }
        self.upsert_hypothesis_batch_with_policy(hypotheses, true, Some(snapshot))
    }

    fn upsert_hypothesis_batch_with_policy(
        &self,
        hypotheses: Vec<Hypothesis>,
        preserve_terminal_state: bool,
        expected_snapshot: Option<&KnowledgeSnapshot>,
    ) -> Result<Vec<KnowledgeWrite>, KnowledgeBaseError> {
        let mut state = self.write_state();
        if let Some(snapshot) = expected_snapshot {
            let actual_subject_revision = subject_revision(&state, snapshot.subject());
            if actual_subject_revision != snapshot.subject_revision()
                || state.ontology_revision != snapshot.ontology_revision()
            {
                return Err(KnowledgeBaseError::StaleSnapshot {
                    subject: snapshot.subject().clone(),
                    expected_subject_revision: snapshot.subject_revision(),
                    actual_subject_revision,
                    expected_ontology_revision: snapshot.ontology_revision(),
                    actual_ontology_revision: state.ontology_revision,
                });
            }
        }
        let mut pending = HashMap::<String, Hypothesis>::new();

        for hypothesis in &hypotheses {
            let id = hypothesis.id();
            if state
                .hypotheses
                .get(id)
                .is_some_and(|existing| !same_hypothesis_claim(existing, hypothesis))
                || pending
                    .get(id)
                    .is_some_and(|existing| !existing.same_evaluation_as(hypothesis))
            {
                return Err(identity_conflict(KnowledgeRecordKind::Hypothesis, &id));
            }
            pending
                .entry(id.to_owned())
                .or_insert_with(|| hypothesis.clone());
        }

        let mut writes = Vec::with_capacity(hypotheses.len());
        for mut hypothesis in hypotheses {
            let id = hypothesis.id().to_owned();
            if preserve_terminal_state {
                let terminal_state = state.hypotheses.get(&id).and_then(|existing| {
                    matches!(
                        existing.state(),
                        HypothesisState::Confirmed | HypothesisState::Rejected
                    )
                    .then_some(existing.state())
                });
                if let Some(terminal_state) = terminal_state {
                    hypothesis.set_state(terminal_state);
                }
            }

            if let Some(existing) = state.hypotheses.get(&id) {
                if existing.same_evaluation_as(&hypothesis) {
                    writes.push(KnowledgeWrite::Unchanged);
                } else {
                    let subject = hypothesis.subject().clone();
                    state.hypotheses.insert(id, hypothesis);
                    bump_subject_revision(&mut state, &subject);
                    writes.push(KnowledgeWrite::Updated);
                }
                continue;
            }

            let subject = hypothesis.subject().clone();
            let predicate = hypothesis.predicate().clone();
            state.hypotheses.insert(id.clone(), hypothesis);
            bump_subject_revision(&mut state, &subject);
            index(&mut state.hypotheses_by_subject, subject, id.clone());
            index(&mut state.hypotheses_by_predicate, predicate, id);
            writes.push(KnowledgeWrite::Inserted);
        }
        Ok(writes)
    }

    /// Changes only the lifecycle state of the latest stored hypothesis.
    ///
    /// The update is performed in place under the knowledge-base write lock, so
    /// verifier state transitions cannot overwrite a concurrent recalibration's
    /// belief trail or strength with a stale cloned record.
    pub(crate) fn transition_hypothesis_state(
        &self,
        hypothesis_id: &str,
        expected_subject: &EntityId,
        new_state: HypothesisState,
        expected_revisions: Option<(u64, u64)>,
    ) -> HypothesisStateTransition {
        let mut state = self.write_state();
        let Some(hypothesis) = state.hypotheses.get(hypothesis_id) else {
            return HypothesisStateTransition::Missing;
        };
        if hypothesis.subject() != expected_subject {
            return HypothesisStateTransition::SubjectMismatch {
                actual: hypothesis.subject().clone(),
            };
        }
        if hypothesis.state() == new_state {
            return HypothesisStateTransition::Written(KnowledgeWrite::Unchanged);
        }
        if is_terminal_hypothesis_state(hypothesis.state())
            && is_terminal_hypothesis_state(new_state)
        {
            return HypothesisStateTransition::TerminalConflict {
                current: hypothesis.state(),
                attempted: new_state,
            };
        }
        if let Some((expected_subject_revision, expected_ontology_revision)) = expected_revisions {
            let actual_subject_revision = subject_revision(&state, expected_subject);
            if actual_subject_revision != expected_subject_revision
                || state.ontology_revision != expected_ontology_revision
            {
                return HypothesisStateTransition::StaleSnapshot(
                    KnowledgeBaseError::StaleSnapshot {
                        subject: expected_subject.clone(),
                        expected_subject_revision,
                        actual_subject_revision,
                        expected_ontology_revision,
                        actual_ontology_revision: state.ontology_revision,
                    },
                );
            }
        }

        let hypothesis = state
            .hypotheses
            .get_mut(hypothesis_id)
            .expect("validated hypothesis remains present under the write lock");
        hypothesis.set_state(new_state);
        bump_subject_revision(&mut state, expected_subject);
        HypothesisStateTransition::Written(KnowledgeWrite::Updated)
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
    /// identity for an existing relation ID. Every field and provenance ID is
    /// validated against the compiled relation storage ceilings first.
    pub fn upsert_relation(
        &self,
        relation: KnowledgeRelation,
    ) -> Result<KnowledgeWrite, KnowledgeBaseError> {
        validate_relation_bounds(&relation)?;
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

    /// Inspects one evidence record while it remains borrowed from the store.
    ///
    /// The callback runs under the knowledge-base read lock and therefore must
    /// remain short and must not attempt a write through this knowledge base.
    pub(crate) fn inspect_evidence<R>(
        &self,
        id: &EvidenceId,
        inspect: impl FnOnce(&Evidence) -> R,
    ) -> Option<R> {
        let state = self.read_state();
        state.evidence.get(id).map(inspect)
    }

    /// Returns a fact snapshot by ID.
    pub fn fact(&self, id: &str) -> Option<Fact> {
        self.read_state().facts.get(id).cloned()
    }

    /// Returns a hypothesis snapshot by ID.
    pub fn hypothesis(&self, id: &str) -> Option<Hypothesis> {
        self.read_state().hypotheses.get(id).cloned()
    }

    /// Inspects one hypothesis while it remains borrowed from the store.
    ///
    /// The callback runs under the knowledge-base read lock and therefore must
    /// remain short and must not attempt a write through this knowledge base.
    pub(crate) fn inspect_hypothesis<R>(
        &self,
        id: &str,
        inspect: impl FnOnce(&Hypothesis) -> R,
    ) -> Option<R> {
        let state = self.read_state();
        state.hypotheses.get(id).map(inspect)
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

    /// Returns one bounded page of incoming relations in stable ID order.
    ///
    /// `after_exclusive` is an exclusive cursor and does not need to identify a
    /// stored relation. At most `limit` indexed records are cloned. A zero limit
    /// returns immediately without reading the store.
    pub fn relations_to_page(
        &self,
        entity_id: &EntityId,
        after_exclusive: Option<&RelationId>,
        limit: usize,
    ) -> Vec<KnowledgeRelation> {
        self.relations_to_page_with_more(entity_id, after_exclusive, limit)
            .0
    }

    /// Returns a bounded relation page and whether another indexed ID exists.
    ///
    /// The look-ahead checks only the borrowed relation index; it never clones
    /// the record beyond this page's explicit `limit`.
    pub(crate) fn relations_to_page_with_more(
        &self,
        entity_id: &EntityId,
        after_exclusive: Option<&RelationId>,
        limit: usize,
    ) -> (Vec<KnowledgeRelation>, bool) {
        if limit == 0 {
            return (Vec::new(), false);
        }

        let state = self.read_state();
        let Some(ids) = state.relations_to.get(entity_id) else {
            return (Vec::new(), false);
        };
        let lower_bound = after_exclusive
            .cloned()
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut ids = ids.range((lower_bound, std::ops::Bound::Unbounded));
        let relations = ids
            .by_ref()
            .take(limit)
            .filter_map(|id| state.relations.get(id).cloned())
            .collect();
        let has_more = ids.next().is_some();
        (relations, has_more)
    }

    /// Captures all rule-visible knowledge for a subject under one read lock.
    pub fn snapshot_for_subject(&self, subject: &EntityId) -> KnowledgeSnapshot {
        let state = self.read_state();
        KnowledgeSnapshot {
            subject: subject.clone(),
            subject_revision: subject_revision(&state, subject),
            ontology_revision: state.ontology_revision,
            ontology: state.ontology.clone(),
            evidence: collect_indexed(state.evidence_by_subject.get(subject), &state.evidence),
            facts: collect_indexed(state.facts_by_subject.get(subject), &state.facts),
            hypotheses: collect_indexed(
                state.hypotheses_by_subject.get(subject),
                &state.hypotheses,
            ),
        }
    }

    /// Validates snapshot revisions without cloning rule-visible records.
    pub(crate) fn validate_snapshot_revisions(
        &self,
        subject: &EntityId,
        expected_subject_revision: u64,
        expected_ontology_revision: u64,
    ) -> Result<(), KnowledgeBaseError> {
        let state = self.read_state();
        validate_revisions(
            &state,
            subject,
            expected_subject_revision,
            expected_ontology_revision,
        )
    }

    /// Runs a short external commit only while a snapshot remains current.
    ///
    /// The read lock stays held for the callback, preventing knowledge writers
    /// from invalidating the snapshot between the revision check and the
    /// external state transition. The callback must not call back into this
    /// knowledge base.
    #[cfg(feature = "scanning")]
    pub(crate) fn commit_if_snapshot_current<T>(
        &self,
        snapshot: &KnowledgeSnapshot,
        commit: impl FnOnce() -> T,
    ) -> Result<T, KnowledgeBaseError> {
        let state = self.read_state();
        validate_revisions(
            &state,
            snapshot.subject(),
            snapshot.subject_revision(),
            snapshot.ontology_revision(),
        )?;
        Ok(commit())
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

/// Validates derivation lineage for one atomic batch before any record is
/// written. `pending` holds every distinct record in the batch keyed by ID; a
/// parent reference may resolve to `pending` (same batch) or to the committed
/// store. Structural validity (non-empty, de-duplicated, bounded parents) is
/// already guaranteed by [`venom_core::EvidenceDerivation`]; the checks that
/// require store context are enforced here: self-reference, parent existence,
/// subject agreement, and cycle freedom. Any violation returns before the write
/// phase, so the batch is rejected without mutating the knowledge base.
fn validate_batch_derivations(
    state: &KnowledgeState,
    pending: &HashMap<EvidenceId, Evidence>,
) -> Result<(), KnowledgeBaseError> {
    for (child_id, child) in pending {
        let Some(derivation) = child.origin().derivation() else {
            continue;
        };
        for parent in derivation.parents() {
            if parent == child_id {
                return Err(KnowledgeBaseError::SelfDerivation {
                    evidence_id: child_id.to_string(),
                });
            }
            let parent_subject = pending
                .get(parent)
                .map(Evidence::subject)
                .or_else(|| state.evidence.get(parent).map(Evidence::subject));
            let Some(parent_subject) = parent_subject else {
                return Err(KnowledgeBaseError::MissingDerivationParent {
                    child: child_id.to_string(),
                    parent: parent.to_string(),
                });
            };
            if parent_subject != child.subject() {
                return Err(KnowledgeBaseError::DerivationSubjectMismatch {
                    child: child_id.to_string(),
                    parent: parent.to_string(),
                });
            }
        }
    }
    detect_batch_derivation_cycles(pending)
}

/// Iterative three-color DFS over batch-local derivation edges. Committed store
/// records are terminals: the store is an immutable DAG whose records precede
/// every batch record, so a new cycle can only form among records in this
/// batch. Traversal is explicit-stack (never recursive) and bounded by the
/// batch size times the per-record parent bound.
fn detect_batch_derivation_cycles(
    pending: &HashMap<EvidenceId, Evidence>,
) -> Result<(), KnowledgeBaseError> {
    enum Color {
        White,
        Gray,
        Black,
    }
    let adjacency: HashMap<EvidenceId, Vec<EvidenceId>> = pending
        .iter()
        .map(|(id, evidence)| {
            let parents = evidence
                .origin()
                .derivation()
                .map(|derivation| {
                    derivation
                        .parents()
                        .iter()
                        .filter(|parent| pending.contains_key(*parent))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            (id.clone(), parents)
        })
        .collect();
    let mut color: HashMap<EvidenceId, Color> = pending
        .keys()
        .map(|id| (id.clone(), Color::White))
        .collect();
    for start in pending.keys() {
        if !matches!(color.get(start), Some(Color::White)) {
            continue;
        }
        color.insert(start.clone(), Color::Gray);
        let mut stack: Vec<(EvidenceId, usize)> = vec![(start.clone(), 0)];
        while let Some((node, index)) = stack.last().cloned() {
            let neighbors = &adjacency[&node];
            if index < neighbors.len() {
                stack.last_mut().unwrap().1 = index + 1;
                let next = neighbors[index].clone();
                match color.get(&next) {
                    Some(Color::Gray) => {
                        return Err(KnowledgeBaseError::DerivationCycle {
                            evidence_id: next.to_string(),
                        });
                    },
                    Some(Color::White) => {
                        color.insert(next.clone(), Color::Gray);
                        stack.push((next, 0));
                    },
                    _ => {},
                }
            } else {
                color.insert(node, Color::Black);
                stack.pop();
            }
        }
    }
    Ok(())
}

/// Records the reverse derivation edges for one newly inserted derived record.
fn index_derivation(state: &mut KnowledgeState, evidence: &Evidence) {
    if let Some(derivation) = evidence.origin().derivation() {
        let child = evidence.id().clone();
        for parent in derivation.parents() {
            state
                .derivation_children
                .entry(parent.clone())
                .or_default()
                .insert(child.clone());
        }
    }
}

fn validate_relation_bounds(relation: &KnowledgeRelation) -> Result<(), KnowledgeBaseError> {
    validate_relation_limit(
        "id",
        relation.id().as_str().len(),
        MAX_KNOWLEDGE_RELATION_ID_BYTES,
    )?;
    validate_relation_limit(
        "from",
        relation.from().as_str().len(),
        MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES,
    )?;
    validate_relation_limit(
        "to",
        relation.to().as_str().len(),
        MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES,
    )?;
    if let RelationKind::Custom(kind) = relation.kind() {
        validate_relation_limit("kind", kind.len(), MAX_KNOWLEDGE_RELATION_KIND_BYTES)?;
    }
    validate_relation_limit(
        "evidence_ids",
        relation.evidence_ids().len(),
        MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS,
    )?;
    for evidence_id in relation.evidence_ids() {
        validate_relation_limit(
            "evidence_id",
            evidence_id.as_str().len(),
            MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES,
        )?;
    }
    Ok(())
}

fn validate_relation_limit(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), KnowledgeBaseError> {
    if actual > maximum {
        return Err(KnowledgeBaseError::RelationLimitExceeded {
            field,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn subject_revision(state: &KnowledgeState, subject: &EntityId) -> u64 {
    state.subject_revisions.get(subject).copied().unwrap_or(0)
}

fn validate_revisions(
    state: &KnowledgeState,
    subject: &EntityId,
    expected_subject_revision: u64,
    expected_ontology_revision: u64,
) -> Result<(), KnowledgeBaseError> {
    let actual_subject_revision = subject_revision(state, subject);
    if actual_subject_revision != expected_subject_revision
        || state.ontology_revision != expected_ontology_revision
    {
        return Err(KnowledgeBaseError::StaleSnapshot {
            subject: subject.clone(),
            expected_subject_revision,
            actual_subject_revision,
            expected_ontology_revision,
            actual_ontology_revision: state.ontology_revision,
        });
    }
    Ok(())
}

fn bump_subject_revision(state: &mut KnowledgeState, subject: &EntityId) {
    let revision = state.subject_revisions.entry(subject.clone()).or_default();
    *revision = revision
        .checked_add(1)
        .expect("subject knowledge revision must not overflow");
}

fn bump_ontology_revision(state: &mut KnowledgeState) {
    state.ontology_revision = state
        .ontology_revision
        .checked_add(1)
        .expect("ontology knowledge revision must not overflow");
}

fn same_hypothesis_claim(left: &Hypothesis, right: &Hypothesis) -> bool {
    left.subject() == right.subject()
        && left.predicate() == right.predicate()
        && left.value() == right.value()
}

fn is_terminal_hypothesis_state(state: HypothesisState) -> bool {
    matches!(
        state,
        HypothesisState::Confirmed | HypothesisState::Rejected
    )
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
        BayesianEvidence, ConfidenceScore, DerivationAlgorithm, EntityKind, EvidenceDerivation,
        EvidenceKind, EvidenceSource, EvidenceValue, HypothesisState, HypothesisStrength,
        Probability, RelationKind,
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
            &[parent_id.clone()]
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

        let as_derived = direct
            .derived_from(EvidenceDerivation::new([parent_id], derivation_algorithm()).unwrap());
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
        assert_eq!(store.relations_from(observation.subject()), vec![relation]);
        assert_eq!(store.relations_to(&resource).len(), 1);

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
                .upsert_hypothesis_batch(vec![
                    first.clone(),
                    updated_second.clone(),
                    updated_second,
                ])
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
            duplicate_store
                .upsert_hypothesis_batch(vec![duplicate.clone(), conflicting_evaluation]),
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
                EvidenceId::parse("e".repeat(MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES + 1))
                    .unwrap(),
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
}
