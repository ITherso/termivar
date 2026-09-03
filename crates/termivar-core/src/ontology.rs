//! Domain ontology contracts for semantic reasoning.
//!
//! A knowledge graph records instance relationships. An [`Ontology`] defines
//! what conceptual relationships mean: whether they are transitive,
//! symmetric, reflexive, acyclic, or have a named inverse. This distinction
//! prevents a decision engine from treating every connected path as the same
//! kind of inference.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Validation and consistency errors for ontology operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OntologyError {
    /// A required identifier or label was empty.
    EmptyValue {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// An identity was reused with a different definition.
    IdentityConflict {
        /// Kind of ontology record that conflicted.
        kind: OntologyRecordKind,
        /// Reused identifier.
        id: String,
    },
    /// An axiom referenced a concept that has not been registered.
    UnknownConcept(ConceptId),
    /// An axiom or query referenced an unknown relation type.
    UnknownRelationType(RelationTypeId),
    /// An axiom would create a cycle in an acyclic relation.
    CycleDetected {
        /// Relation whose acyclic invariant would be broken.
        relation: RelationTypeId,
        /// Proposed axiom subject.
        subject: ConceptId,
        /// Proposed axiom object.
        object: ConceptId,
    },
}

impl fmt::Display for OntologyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyValue { field } => write!(formatter, "{field} must not be empty"),
            Self::IdentityConflict { kind, id } => {
                write!(
                    formatter,
                    "{kind} identity {id} already has a different definition"
                )
            },
            Self::UnknownConcept(id) => write!(formatter, "unknown ontology concept {id}"),
            Self::UnknownRelationType(id) => {
                write!(formatter, "unknown ontology relation type {id}")
            },
            Self::CycleDetected {
                relation,
                subject,
                object,
            } => write!(
                formatter,
                "ontology axiom {subject} {relation} {object} would create a cycle"
            ),
        }
    }
}

impl std::error::Error for OntologyError {}

fn non_empty(value: impl Into<String>, field: &'static str) -> Result<String, OntologyError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(OntologyError::EmptyValue { field });
    }
    Ok(value)
}

fn deserialize_non_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    non_empty(value, "value").map_err(serde::de::Error::custom)
}

/// Stable identifier for a domain concept such as `framework` or `laravel`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConceptId(String);

impl ConceptId {
    /// Creates a validated concept identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, OntologyError> {
        Ok(Self(non_empty(value, "concept id")?))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ConceptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ConceptId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Stable identifier for a semantic relation type such as `is_a`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RelationTypeId(String);

impl RelationTypeId {
    /// Creates a validated relation-type identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, OntologyError> {
        Ok(Self(non_empty(value, "relation type id")?))
    }

    /// Returns the identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RelationTypeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RelationTypeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// A named concept in the domain ontology.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OntologyConcept {
    id: ConceptId,
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    label: String,
}

impl OntologyConcept {
    /// Creates a concept with a stable ID and human-readable label.
    pub fn new(id: ConceptId, label: impl Into<String>) -> Result<Self, OntologyError> {
        Ok(Self {
            id,
            label: non_empty(label, "concept label")?,
        })
    }

    /// Returns the stable concept identifier.
    pub fn id(&self) -> &ConceptId {
        &self.id
    }

    /// Returns the display label.
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// Formal behavior attached to an ontology relation type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationSemantics {
    /// Whether `a R b` and `b R c` imply `a R c`.
    pub transitive: bool,
    /// Whether `a R b` also implies `b R a`.
    pub symmetric: bool,
    /// Whether every concept relates to itself.
    pub reflexive: bool,
    /// Whether adding a cycle must be rejected.
    pub acyclic: bool,
}

/// Definition of a semantic relationship used by ontology axioms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OntologyRelationType {
    id: RelationTypeId,
    #[serde(deserialize_with = "deserialize_non_empty_string")]
    label: String,
    semantics: RelationSemantics,
    inverse: Option<RelationTypeId>,
}

impl OntologyRelationType {
    /// Creates a directional relation with no inference properties.
    pub fn new(id: RelationTypeId, label: impl Into<String>) -> Result<Self, OntologyError> {
        Ok(Self {
            id,
            label: non_empty(label, "relation type label")?,
            semantics: RelationSemantics::default(),
            inverse: None,
        })
    }

    /// Assigns explicit semantic behavior.
    pub fn with_semantics(mut self, semantics: RelationSemantics) -> Self {
        self.semantics = semantics;
        self
    }

    /// Names the inverse relation type.
    pub fn with_inverse(mut self, inverse: RelationTypeId) -> Self {
        self.inverse = Some(inverse);
        self
    }

    /// Returns the stable relation-type identifier.
    pub fn id(&self) -> &RelationTypeId {
        &self.id
    }

    /// Returns the display label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the formal inference behavior.
    pub fn semantics(&self) -> RelationSemantics {
        self.semantics
    }

    /// Returns the optional inverse relation type.
    pub fn inverse(&self) -> Option<&RelationTypeId> {
        self.inverse.as_ref()
    }
}

/// One semantic statement between two registered concepts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OntologyAxiom {
    subject: ConceptId,
    relation: RelationTypeId,
    object: ConceptId,
}

impl OntologyAxiom {
    /// Creates an axiom. Registration validates referenced concepts and type.
    pub fn new(subject: ConceptId, relation: RelationTypeId, object: ConceptId) -> Self {
        Self {
            subject,
            relation,
            object,
        }
    }

    /// Returns the source concept.
    pub fn subject(&self) -> &ConceptId {
        &self.subject
    }

    /// Returns the semantic relation type.
    pub fn relation(&self) -> &RelationTypeId {
        &self.relation
    }

    /// Returns the destination concept.
    pub fn object(&self) -> &ConceptId {
        &self.object
    }
}

/// Result of an idempotent ontology write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OntologyWrite {
    /// A new definition or axiom was registered.
    Inserted,
    /// The exact definition or axiom already existed.
    Unchanged,
}

/// Ontology record categories used by conflict diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OntologyRecordKind {
    /// Domain concept.
    Concept,
    /// Semantic relation type.
    RelationType,
}

impl fmt::Display for OntologyRecordKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Concept => formatter.write_str("ontology concept"),
            Self::RelationType => formatter.write_str("ontology relation type"),
        }
    }
}

/// Counts of definitions held by an [`Ontology`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OntologyStats {
    /// Number of registered concepts.
    pub concepts: usize,
    /// Number of registered relation types.
    pub relation_types: usize,
    /// Number of semantic axioms.
    pub axioms: usize,
}

/// Validated domain ontology with deterministic semantic traversal.
///
/// The default ontology contains standard relation definitions but no domain
/// concepts or axioms. Callers explicitly register their product vocabulary.
///
/// # Examples
///
/// ```rust
/// use termivar_core::{ConceptId, Ontology, OntologyAxiom, OntologyConcept};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut ontology = Ontology::new();
/// let framework = ConceptId::new("framework")?;
/// let technology = ConceptId::new("technology")?;
/// let laravel = ConceptId::new("laravel")?;
/// ontology.add_concept(OntologyConcept::new(framework.clone(), "Framework")?)?;
/// ontology.add_concept(OntologyConcept::new(technology.clone(), "Technology")?)?;
/// ontology.add_concept(OntologyConcept::new(laravel.clone(), "Laravel")?)?;
/// ontology.add_axiom(OntologyAxiom::new(
///     laravel.clone(),
///     Ontology::relation_id(Ontology::IS_A)?,
///     framework.clone(),
/// ))?;
/// ontology.add_axiom(OntologyAxiom::new(
///     framework,
///     Ontology::relation_id(Ontology::IS_A)?,
///     technology.clone(),
/// ))?;
///
/// assert!(ontology.is_a(&laravel, &technology)?);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Ontology {
    concepts: BTreeMap<ConceptId, OntologyConcept>,
    relation_types: BTreeMap<RelationTypeId, OntologyRelationType>,
    axioms: BTreeSet<OntologyAxiom>,
}

impl Ontology {
    /// Canonical transitive type hierarchy relation.
    pub const IS_A: &'static str = "is_a";
    /// Canonical transitive containment relation.
    pub const PART_OF: &'static str = "part_of";
    /// Inverse of [`Self::PART_OF`].
    pub const HAS_PART: &'static str = "has_part";
    /// Directional dependency relation.
    pub const DEPENDS_ON: &'static str = "depends_on";
    /// Inverse of [`Self::DEPENDS_ON`].
    pub const REQUIRED_BY: &'static str = "required_by";
    /// Logical implication relation.
    pub const IMPLIES: &'static str = "implies";
    /// Symmetric non-hierarchical association.
    pub const ASSOCIATED_WITH: &'static str = "associated_with";
    /// Implementation-language relation.
    pub const IMPLEMENTED_IN: &'static str = "implemented_in";
    /// Capability or category provision relation.
    pub const PROVIDES: &'static str = "provides";

    /// Creates an empty domain vocabulary with standard relation definitions.
    pub fn new() -> Self {
        let mut ontology = Self {
            concepts: BTreeMap::new(),
            relation_types: BTreeMap::new(),
            axioms: BTreeSet::new(),
        };
        for relation in standard_relation_types() {
            ontology
                .relation_types
                .insert(relation.id().clone(), relation);
        }
        ontology
    }

    /// Builds a validated relation-type ID for a canonical or custom name.
    pub fn relation_id(value: impl Into<String>) -> Result<RelationTypeId, OntologyError> {
        RelationTypeId::new(value)
    }

    /// Registers a concept idempotently.
    pub fn add_concept(
        &mut self,
        concept: OntologyConcept,
    ) -> Result<OntologyWrite, OntologyError> {
        if let Some(existing) = self.concepts.get(concept.id()) {
            return if existing == &concept {
                Ok(OntologyWrite::Unchanged)
            } else {
                Err(OntologyError::IdentityConflict {
                    kind: OntologyRecordKind::Concept,
                    id: concept.id().to_string(),
                })
            };
        }
        self.concepts.insert(concept.id().clone(), concept);
        Ok(OntologyWrite::Inserted)
    }

    /// Registers a semantic relation type idempotently.
    pub fn add_relation_type(
        &mut self,
        relation_type: OntologyRelationType,
    ) -> Result<OntologyWrite, OntologyError> {
        if let Some(existing) = self.relation_types.get(relation_type.id()) {
            return if existing == &relation_type {
                Ok(OntologyWrite::Unchanged)
            } else {
                Err(OntologyError::IdentityConflict {
                    kind: OntologyRecordKind::RelationType,
                    id: relation_type.id().to_string(),
                })
            };
        }
        self.relation_types
            .insert(relation_type.id().clone(), relation_type);
        Ok(OntologyWrite::Inserted)
    }

    /// Registers a validated semantic axiom idempotently.
    pub fn add_axiom(&mut self, axiom: OntologyAxiom) -> Result<OntologyWrite, OntologyError> {
        self.ensure_concept(axiom.subject())?;
        self.ensure_concept(axiom.object())?;
        let relation_type = self.ensure_relation_type(axiom.relation())?;

        if relation_type.semantics().acyclic
            && (axiom.subject() == axiom.object()
                || self.is_related(axiom.object(), axiom.relation(), axiom.subject())?)
        {
            return Err(OntologyError::CycleDetected {
                relation: axiom.relation().clone(),
                subject: axiom.subject().clone(),
                object: axiom.object().clone(),
            });
        }

        if self.is_related(axiom.subject(), axiom.relation(), axiom.object())? {
            return Ok(OntologyWrite::Unchanged);
        }

        if self.axioms.insert(axiom) {
            Ok(OntologyWrite::Inserted)
        } else {
            Ok(OntologyWrite::Unchanged)
        }
    }

    /// Returns a concept definition by ID.
    pub fn concept(&self, id: &ConceptId) -> Option<&OntologyConcept> {
        self.concepts.get(id)
    }

    /// Returns a semantic relation definition by ID.
    pub fn relation_type(&self, id: &RelationTypeId) -> Option<&OntologyRelationType> {
        self.relation_types.get(id)
    }

    /// Returns all concepts in stable ID order.
    pub fn concepts(&self) -> Vec<OntologyConcept> {
        self.concepts.values().cloned().collect()
    }

    /// Returns all relation types in stable ID order.
    pub fn relation_types(&self) -> Vec<OntologyRelationType> {
        self.relation_types.values().cloned().collect()
    }

    /// Returns all axioms in stable tuple order.
    pub fn axioms(&self) -> Vec<OntologyAxiom> {
        self.axioms.iter().cloned().collect()
    }

    /// Evaluates a relationship using its declared semantic behavior.
    pub fn is_related(
        &self,
        subject: &ConceptId,
        relation: &RelationTypeId,
        object: &ConceptId,
    ) -> Result<bool, OntologyError> {
        self.ensure_concept(subject)?;
        self.ensure_concept(object)?;
        let relation_type = self.ensure_relation_type(relation)?;
        let semantics = relation_type.semantics();

        if semantics.reflexive && subject == object {
            return Ok(true);
        }

        let direct = self.neighbors(subject, relation_type);
        if direct.contains(object) {
            return Ok(true);
        }
        if !semantics.transitive {
            return Ok(false);
        }

        let mut visited = BTreeSet::from([subject.clone()]);
        let mut queue: VecDeque<_> = direct.into_iter().collect();
        while let Some(current) = queue.pop_front() {
            if &current == object {
                return Ok(true);
            }
            if !visited.insert(current.clone()) {
                continue;
            }
            queue.extend(
                self.neighbors(&current, relation_type)
                    .into_iter()
                    .filter(|neighbor| !visited.contains(neighbor)),
            );
        }
        Ok(false)
    }

    /// Evaluates the canonical transitive `is_a` hierarchy.
    pub fn is_a(&self, child: &ConceptId, ancestor: &ConceptId) -> Result<bool, OntologyError> {
        self.is_related(child, &Self::relation_id(Self::IS_A)?, ancestor)
    }

    /// Returns axioms whose subject matches a concept, in stable order.
    pub fn axioms_from(&self, subject: &ConceptId) -> Result<Vec<OntologyAxiom>, OntologyError> {
        self.ensure_concept(subject)?;
        Ok(self
            .axioms
            .iter()
            .filter(|axiom| axiom.subject() == subject)
            .cloned()
            .collect())
    }

    /// Returns a count snapshot.
    pub fn stats(&self) -> OntologyStats {
        OntologyStats {
            concepts: self.concepts.len(),
            relation_types: self.relation_types.len(),
            axioms: self.axioms.len(),
        }
    }

    fn ensure_concept(&self, id: &ConceptId) -> Result<&OntologyConcept, OntologyError> {
        self.concepts
            .get(id)
            .ok_or_else(|| OntologyError::UnknownConcept(id.clone()))
    }

    fn ensure_relation_type(
        &self,
        id: &RelationTypeId,
    ) -> Result<&OntologyRelationType, OntologyError> {
        self.relation_types
            .get(id)
            .ok_or_else(|| OntologyError::UnknownRelationType(id.clone()))
    }

    fn neighbors(
        &self,
        subject: &ConceptId,
        relation_type: &OntologyRelationType,
    ) -> BTreeSet<ConceptId> {
        self.axioms
            .iter()
            .filter_map(|axiom| {
                if axiom.relation() == relation_type.id() && axiom.subject() == subject {
                    Some(axiom.object().clone())
                } else if axiom.object() == subject
                    && ((axiom.relation() == relation_type.id()
                        && relation_type.semantics().symmetric)
                        || relation_type.inverse() == Some(axiom.relation()))
                {
                    Some(axiom.subject().clone())
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for Ontology {
    fn default() -> Self {
        Self::new()
    }
}

fn standard_relation_types() -> Vec<OntologyRelationType> {
    let relation = |id: &'static str, label: &'static str| {
        OntologyRelationType::new(
            RelationTypeId::new(id).expect("standard relation ID is valid"),
            label,
        )
        .expect("standard relation label is valid")
    };
    let id = |value: &'static str| {
        RelationTypeId::new(value).expect("standard inverse relation ID is valid")
    };

    vec![
        relation(Ontology::IS_A, "is a").with_semantics(RelationSemantics {
            transitive: true,
            reflexive: true,
            acyclic: true,
            ..RelationSemantics::default()
        }),
        relation(Ontology::PART_OF, "part of")
            .with_semantics(RelationSemantics {
                transitive: true,
                acyclic: true,
                ..RelationSemantics::default()
            })
            .with_inverse(id(Ontology::HAS_PART)),
        relation(Ontology::HAS_PART, "has part")
            .with_semantics(RelationSemantics {
                transitive: true,
                acyclic: true,
                ..RelationSemantics::default()
            })
            .with_inverse(id(Ontology::PART_OF)),
        relation(Ontology::DEPENDS_ON, "depends on").with_inverse(id(Ontology::REQUIRED_BY)),
        relation(Ontology::REQUIRED_BY, "required by").with_inverse(id(Ontology::DEPENDS_ON)),
        relation(Ontology::IMPLIES, "implies").with_semantics(RelationSemantics {
            transitive: true,
            reflexive: true,
            ..RelationSemantics::default()
        }),
        relation(Ontology::ASSOCIATED_WITH, "associated with").with_semantics(RelationSemantics {
            symmetric: true,
            ..RelationSemantics::default()
        }),
        relation(Ontology::IMPLEMENTED_IN, "implemented in"),
        relation(Ontology::PROVIDES, "provides"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn concept(id: &str) -> OntologyConcept {
        OntologyConcept::new(ConceptId::new(id).unwrap(), id).unwrap()
    }

    fn concept_id(id: &str) -> ConceptId {
        ConceptId::new(id).unwrap()
    }

    fn axiom(subject: &str, relation: &str, object: &str) -> OntologyAxiom {
        OntologyAxiom::new(
            concept_id(subject),
            Ontology::relation_id(relation).unwrap(),
            concept_id(object),
        )
    }

    #[test]
    fn standard_relations_publish_explicit_semantics() {
        let ontology = Ontology::new();
        let is_a = ontology
            .relation_type(&Ontology::relation_id(Ontology::IS_A).unwrap())
            .unwrap();
        assert!(is_a.semantics().transitive);
        assert!(is_a.semantics().reflexive);
        assert!(is_a.semantics().acyclic);

        let associated = ontology
            .relation_type(&Ontology::relation_id(Ontology::ASSOCIATED_WITH).unwrap())
            .unwrap();
        assert!(associated.semantics().symmetric);
        assert!(!associated.semantics().transitive);
        assert_eq!(ontology.stats().relation_types, 9);
    }

    #[test]
    fn is_a_hierarchy_is_transitive_and_reflexive() {
        let mut ontology = Ontology::new();
        for id in ["laravel", "framework", "technology"] {
            ontology.add_concept(concept(id)).unwrap();
        }
        ontology
            .add_axiom(axiom("laravel", Ontology::IS_A, "framework"))
            .unwrap();
        ontology
            .add_axiom(axiom("framework", Ontology::IS_A, "technology"))
            .unwrap();

        assert!(ontology
            .is_a(&concept_id("laravel"), &concept_id("technology"))
            .unwrap());
        assert!(ontology
            .is_a(&concept_id("laravel"), &concept_id("laravel"))
            .unwrap());
    }

    #[test]
    fn different_relation_meanings_do_not_collapse_into_reachability() {
        let mut ontology = Ontology::new();
        for id in ["laravel", "framework", "php", "language"] {
            ontology.add_concept(concept(id)).unwrap();
        }
        ontology
            .add_axiom(axiom("laravel", Ontology::IS_A, "framework"))
            .unwrap();
        ontology
            .add_axiom(axiom("laravel", Ontology::IMPLEMENTED_IN, "php"))
            .unwrap();
        ontology
            .add_axiom(axiom("php", Ontology::IS_A, "language"))
            .unwrap();

        assert!(ontology
            .is_a(&concept_id("laravel"), &concept_id("framework"))
            .unwrap());
        assert!(!ontology
            .is_a(&concept_id("laravel"), &concept_id("language"))
            .unwrap());
        assert!(ontology
            .is_related(
                &concept_id("laravel"),
                &Ontology::relation_id(Ontology::IMPLEMENTED_IN).unwrap(),
                &concept_id("php"),
            )
            .unwrap());
    }

    #[test]
    fn symmetric_relation_is_queryable_in_both_directions() {
        let mut ontology = Ontology::new();
        ontology.add_concept(concept("laravel")).unwrap();
        ontology.add_concept(concept("livewire")).unwrap();
        ontology
            .add_axiom(axiom("livewire", Ontology::ASSOCIATED_WITH, "laravel"))
            .unwrap();
        let relation = Ontology::relation_id(Ontology::ASSOCIATED_WITH).unwrap();

        assert!(ontology
            .is_related(&concept_id("laravel"), &relation, &concept_id("livewire"))
            .unwrap());
    }

    #[test]
    fn inverse_relation_semantics_are_evaluated_without_duplicate_axioms() {
        let mut ontology = Ontology::new();
        ontology.add_concept(concept("livewire")).unwrap();
        ontology.add_concept(concept("laravel")).unwrap();
        ontology
            .add_axiom(axiom("livewire", Ontology::PART_OF, "laravel"))
            .unwrap();

        assert!(ontology
            .is_related(
                &concept_id("laravel"),
                &Ontology::relation_id(Ontology::HAS_PART).unwrap(),
                &concept_id("livewire"),
            )
            .unwrap());
        assert_eq!(ontology.stats().axioms, 1);
    }

    #[test]
    fn acyclic_hierarchy_rejects_cycles_without_mutation() {
        let mut ontology = Ontology::new();
        ontology.add_concept(concept("framework")).unwrap();
        ontology.add_concept(concept("laravel")).unwrap();
        ontology
            .add_axiom(axiom("laravel", Ontology::IS_A, "framework"))
            .unwrap();

        let result = ontology.add_axiom(axiom("framework", Ontology::IS_A, "laravel"));
        assert!(matches!(result, Err(OntologyError::CycleDetected { .. })));
        assert_eq!(ontology.stats().axioms, 1);
    }

    #[test]
    fn unknown_references_are_rejected() {
        let mut ontology = Ontology::new();
        ontology.add_concept(concept("laravel")).unwrap();
        assert_eq!(
            ontology.add_axiom(axiom("laravel", Ontology::IS_A, "framework")),
            Err(OntologyError::UnknownConcept(concept_id("framework")))
        );
        assert!(matches!(
            ontology.is_related(
                &concept_id("laravel"),
                &RelationTypeId::new("unknown").unwrap(),
                &concept_id("laravel"),
            ),
            Err(OntologyError::UnknownRelationType(_))
        ));
    }

    #[test]
    fn definitions_are_idempotent_but_conflicts_are_rejected() {
        let mut ontology = Ontology::new();
        let framework = concept("framework");
        assert_eq!(
            ontology.add_concept(framework.clone()).unwrap(),
            OntologyWrite::Inserted
        );
        assert_eq!(
            ontology.add_concept(framework).unwrap(),
            OntologyWrite::Unchanged
        );
        let conflicting = OntologyConcept::new(concept_id("framework"), "Different label").unwrap();
        assert!(matches!(
            ontology.add_concept(conflicting),
            Err(OntologyError::IdentityConflict {
                kind: OntologyRecordKind::Concept,
                ..
            })
        ));
    }

    #[test]
    fn wire_format_preserves_identifier_and_label_invariants() {
        assert!(serde_json::from_str::<ConceptId>("\" \"").is_err());
        let invalid = serde_json::json!({ "id": "framework", "label": " " });
        assert!(serde_json::from_value::<OntologyConcept>(invalid).is_err());
    }
}
