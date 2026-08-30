//! Bounded knowledge-graph entity and relation storage.

use venom_core::{
    EntityId, Evidence, KnowledgeEntity, KnowledgeRelation, RelationId, RelationKind,
};

use crate::knowledge::{
    bump_subject_revision, collect_indexed, identity_conflict, index, KnowledgeBase,
    KnowledgeBaseError, KnowledgeRecordKind, KnowledgeWrite,
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

impl KnowledgeBase {
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

    /// Returns an entity snapshot by ID.
    pub fn entity(&self, id: &EntityId) -> Option<KnowledgeEntity> {
        self.read_state().entities.get(id).cloned()
    }

    /// Returns a relation snapshot by ID.
    pub fn relation(&self, id: &RelationId) -> Option<KnowledgeRelation> {
        self.read_state().relations.get(id).cloned()
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
