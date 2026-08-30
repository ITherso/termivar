//! Immutable subject snapshots and revision/authority guards.

use venom_core::{EntityId, Evidence, Fact, Hypothesis, HypothesisState, Ontology};

use crate::knowledge::{
    collect_indexed, subject_revision, validate_revisions, KnowledgeAuthority, KnowledgeBase,
    KnowledgeBaseError,
};

/// Consistent, immutable knowledge for one subject at one point in time.
///
/// Rule evaluation uses this snapshot so every expression in one decision
/// cycle observes the same ontology, evidence, facts, and hypotheses.
#[derive(Debug, Clone)]
pub struct KnowledgeSnapshot {
    authority: KnowledgeAuthority,
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

    pub(crate) fn authority(&self) -> &KnowledgeAuthority {
        &self.authority
    }

    pub(crate) fn with_evidence_correlation(&self, correlation_id: &str) -> Self {
        Self {
            authority: self.authority.clone(),
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

impl KnowledgeBase {
    /// Captures all rule-visible knowledge for a subject under one read lock.
    pub fn snapshot_for_subject(&self, subject: &EntityId) -> KnowledgeSnapshot {
        let state = self.read_state();
        KnowledgeSnapshot {
            authority: self.authority.clone(),
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

    /// Rejects a snapshot token minted by a different in-memory knowledge base.
    pub(crate) fn validate_snapshot_authority(
        &self,
        authority: &KnowledgeAuthority,
        subject: &EntityId,
    ) -> Result<(), KnowledgeBaseError> {
        if self.authority.is_same_as(authority) {
            Ok(())
        } else {
            Err(KnowledgeBaseError::SnapshotAuthorityMismatch {
                subject: subject.clone(),
            })
        }
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
        self.validate_snapshot_authority(snapshot.authority(), snapshot.subject())?;
        let state = self.read_state();
        validate_revisions(
            &state,
            snapshot.subject(),
            snapshot.subject_revision(),
            snapshot.ontology_revision(),
        )?;
        Ok(commit())
    }
}
