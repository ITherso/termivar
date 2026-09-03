//! Stable secondary indexes and owned read projections.

use std::{
    collections::{BTreeSet, HashMap},
    hash::Hash,
};

use termivar_core::{EntityId, Evidence, EvidenceId, Fact, Hypothesis, KnowledgePredicate};

use crate::knowledge::KnowledgeBase;

impl KnowledgeBase {
    /// Returns the derived evidence records computed directly from `parent`,
    /// ordered by evidence ID. Forward lineage (a derived record's exact
    /// parents) is read from that record's [`termivar_core::EvidenceOrigin`].
    pub fn derivation_children(&self, parent: &EvidenceId) -> BTreeSet<EvidenceId> {
        self.read_state()
            .derivation_children
            .get(parent)
            .cloned()
            .unwrap_or_default()
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
}

pub(super) fn index<K, I>(index: &mut HashMap<K, BTreeSet<I>>, key: K, id: I)
where
    K: Eq + Hash,
    I: Ord,
{
    index.entry(key).or_default().insert(id);
}

pub(super) fn collect_indexed<K, V>(ids: Option<&BTreeSet<K>>, values: &HashMap<K, V>) -> Vec<V>
where
    K: Eq + Hash + Ord,
    V: Clone,
{
    ids.into_iter()
        .flatten()
        .filter_map(|id| values.get(id).cloned())
        .collect()
}
