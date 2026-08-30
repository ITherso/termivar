//! Knowledge-base ownership, ontology lifecycle, statistics, and lock boundaries.

use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use venom_core::{
    ConceptId, Ontology, OntologyAxiom, OntologyConcept, OntologyError, OntologyRelationType,
    OntologyWrite, RelationTypeId,
};

use super::{bump_ontology_revision, KnowledgeAuthority, KnowledgeBaseStats, KnowledgeState};

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
    pub(super) authority: KnowledgeAuthority,
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

    pub(super) fn read_state(&self) -> RwLockReadGuard<'_, KnowledgeState> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn write_state(&self) -> RwLockWriteGuard<'_, KnowledgeState> {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
