//! Stable inward-facing contracts shared by Venom crates.
//!
//! `venom-core` contains transport-neutral data: configuration, events,
//! findings, errors, and request/response models. Execution behavior belongs
//! in higher-level crates.
//!
//! # Example
//!
//! ```rust
//! use venom_core::{Event, EventType, ScanFinding};
//!
//! let event = Event::builder(EventType::ScanStarted, "authorized scan").build();
//! let finding = ScanFinding {
//!     phase: 1,
//!     module_name: "example".to_string(),
//!     severity: "INFO".to_string(),
//!     description: "Contract example".to_string(),
//!     evidence: "https://example.test".to_string(),
//! };
//!
//! assert_eq!(event.event_type, EventType::ScanStarted);
//! assert_eq!(finding.phase, 1);
//! ```

#![deny(rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod error;
pub mod events;
pub mod models;
pub mod ontology;
pub mod outcome;
pub mod predicates;
pub mod reasoning;
pub mod run_report;

pub use config::{Config, ConfigBuilder, ConfigError, ScanIntensity};
pub use error::{Error, Result};
pub use events::{Event, EventBuilder, EventSeverity, EventType};
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
