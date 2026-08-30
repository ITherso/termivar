//! Thread-safe in-memory knowledge base for evidence-driven reasoning.
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** Surface B uses the base as deterministic reasoning state.
//!   Surface A's opt-in legacy runner also records bounded probe receipts and
//!   verifier-owned manual-review outcomes from phases 5, 7, 8, and 9.
//! - **Default `venom scan`:** yes, through Surface B; legacy knowledge writes
//!   require the explicit `legacy-scan` path and its acknowledgement flag.
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
use std::sync::Arc;

use venom_core::{
    EntityId, Evidence, EvidenceId, Fact, Hypothesis, KnowledgeEntity, KnowledgePredicate,
    KnowledgeRelation, Ontology, RelationId,
};

/// Opaque, process-local identity shared by one knowledge base and its snapshots.
///
/// The identity is deliberately neither serialized nor exposed publicly. It
/// prevents a snapshot or verifier receipt produced by one in-memory authority
/// from being committed to a different authority that happens to contain the
/// same records and revision counters.
#[derive(Clone, Default)]
pub(crate) struct KnowledgeAuthority(Arc<()>);

impl KnowledgeAuthority {
    pub(crate) fn is_same_as(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for KnowledgeAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KnowledgeAuthority(<opaque>)")
    }
}

mod index;
mod relations;
mod snapshot;
mod store;
mod writes;

use index::{collect_indexed, index};
use writes::{
    bump_ontology_revision, bump_subject_revision, identity_conflict, subject_revision,
    validate_revisions,
};

pub use relations::{
    MAX_KNOWLEDGE_RELATION_ENTITY_ID_BYTES, MAX_KNOWLEDGE_RELATION_EVIDENCE_IDS,
    MAX_KNOWLEDGE_RELATION_EVIDENCE_ID_BYTES, MAX_KNOWLEDGE_RELATION_ID_BYTES,
    MAX_KNOWLEDGE_RELATION_KIND_BYTES,
};
pub use snapshot::KnowledgeSnapshot;
pub use store::KnowledgeBase;
pub(crate) use writes::HypothesisStateTransition;
pub use writes::{KnowledgeBaseError, KnowledgeBaseStats, KnowledgeRecordKind, KnowledgeWrite};

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

impl KnowledgeBase {
    /// Returns this store's opaque in-memory authority without taking the
    /// knowledge-state lock or cloning a subject snapshot.
    pub(crate) fn authority(&self) -> &KnowledgeAuthority {
        &self.authority
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

#[cfg(test)]
#[path = "knowledge/knowledge_tests.rs"]
mod tests;
