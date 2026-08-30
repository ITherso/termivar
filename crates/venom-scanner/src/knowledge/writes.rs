//! Atomic evidence, fact, and hypothesis write transactions.

use std::{collections::HashMap, fmt};

use serde::{Deserialize, Serialize};
use venom_core::{
    EntityId, Evidence, EvidenceId, Fact, Hypothesis, HypothesisState, OntologyStats,
};

use super::{index, KnowledgeBase, KnowledgeSnapshot, KnowledgeState};

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
    /// A snapshot or commit token was minted by another knowledge-base instance.
    SnapshotAuthorityMismatch {
        /// Subject whose snapshot authority did not match this knowledge base.
        subject: EntityId,
    },

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
            Self::SnapshotAuthorityMismatch { subject } => write!(
                formatter,
                "knowledge snapshot for {subject} belongs to a different knowledge base"
            ),
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

impl KnowledgeBase {
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
        if let Some(snapshot) = expected_snapshot {
            self.validate_snapshot_authority(snapshot.authority(), snapshot.subject())?;
        }
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
}

pub(super) fn identity_conflict(
    kind: KnowledgeRecordKind,
    id: &impl fmt::Display,
) -> KnowledgeBaseError {
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

pub(super) fn subject_revision(state: &KnowledgeState, subject: &EntityId) -> u64 {
    state.subject_revisions.get(subject).copied().unwrap_or(0)
}

pub(super) fn validate_revisions(
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

pub(super) fn bump_subject_revision(state: &mut KnowledgeState, subject: &EntityId) {
    let revision = state.subject_revisions.entry(subject.clone()).or_default();
    *revision = revision
        .checked_add(1)
        .expect("subject knowledge revision must not overflow");
}

pub(super) fn bump_ontology_revision(state: &mut KnowledgeState) {
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
