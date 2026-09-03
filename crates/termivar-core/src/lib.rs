//! Inward-facing, transport-neutral contracts shared by Termivar crates.
//!
//! The default crate surface contains evidence, reasoning, ontology, outcome,
//! predicate, and run-report records. Execution behavior and transport models
//! belong in higher-level crates. The pre-quarantine configuration, error,
//! event, finding, and raw HTTP/result records remain available only through
//! the non-default `legacy-contracts` compatibility feature.

//!
//! # Example
//!
//! ```rust
//! use termivar_core::ConfidenceScore;
//!
//! let confidence = ConfidenceScore::from_basis_points(8_500)?;
//! assert_eq!(confidence.basis_points(), 8_500);
//! # Ok::<(), termivar_core::ReasoningModelError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "legacy-contracts")]
pub mod config;
#[cfg(feature = "legacy-contracts")]
pub mod error;
#[cfg(feature = "legacy-contracts")]
pub mod events;
#[cfg(feature = "legacy-contracts")]
pub mod models;
pub mod ontology;
pub mod outcome;
pub mod predicates;
pub mod reasoning;
pub mod run_report;

#[cfg(feature = "legacy-contracts")]
pub use config::{Config, ConfigBuilder, ConfigError, ScanIntensity};
#[cfg(feature = "legacy-contracts")]
pub use error::{Error, Result};
#[cfg(feature = "legacy-contracts")]
pub use events::{Event, EventBuilder, EventSeverity, EventType};
#[cfg(feature = "legacy-contracts")]
pub use models::{HttpRequest, HttpResponse, ScanFinding, ScanResult, Vulnerability};
pub use ontology::{
    ConceptId, Ontology, OntologyAxiom, OntologyConcept, OntologyError, OntologyRecordKind,
    OntologyRelationType, OntologyStats, OntologyWrite, RelationSemantics, RelationTypeId,
};
pub use outcome::{Outcome, OutcomeError, OutcomeStatus, VerificationStage};
pub use predicates::{
    ApiEvidencePredicate, ApiKnowledgePredicate, ApiResponseFormat, ApiSurfaceKind,
    ApiVisibilityBoundaryKind, ApiVisibilityComparison, ApiVisibilityDimension,
    ApiVisibilityObservation, ApiVisibilityPairKind, ApiVisibilityResult, ApiVocabularyError,
    ComparisonId, HttpEvidencePredicate, OpaqueContextId, PredicateDescriptor, ResourceScopeId,
    WebKnowledgePredicate,
};
pub use reasoning::{
    BayesianBelief, BayesianEvidence, BayesianUpdate, BeliefWrite, ConfidenceScore,
    ContributionDirection, DerivationAlgorithm, EntityId, EntityKind, Evidence,
    EvidenceContribution, EvidenceDerivation, EvidenceId, EvidenceKind, EvidenceOrigin,
    EvidenceSource, EvidenceValue, Fact, Hypothesis, HypothesisState, HypothesisStrength,
    KnowledgeEntity, KnowledgePredicate, KnowledgeRelation, Probability, ReasoningModelError,
    RelationId, RelationKind, MAX_DERIVATION_ALGORITHM_BYTES, MAX_DERIVATION_PARENTS,
};
pub use run_report::{
    ResourceAccounting, ResourceAccountingMode, RunAccounting, RunOutcomeRecord, RunReport,
    RunReportError, RunReportInput, RunStatus, RunStepReport, RunStepStatus, RunStopCode,
    RunStopReason, SecuritySeverity, MAX_RUN_REPORT_EVIDENCE_IDS, MAX_RUN_REPORT_OUTCOMES,
    MAX_RUN_REPORT_STEPS, MAX_RUN_REPORT_TEXT_BYTES, RUN_REPORT_SCHEMA,
};
