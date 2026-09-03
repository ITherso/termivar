//! Semantic Model Builder components: deterministic entity extraction from scanner evidence (Phase 1).
//!
//! ## Runtime scope
//!
//! - **Build:** always/default.
//! - **Execution:** host/library only; consumes `Evidence`. Not wired into the
//!   default `termivar scan` runtime and not automatically composed into
//!   `StandardWebDecisionRuntime`.
//! - **Default `termivar scan`:** no.
//! - **Support:** implemented and tested (Phase 1.5).
//!
//! See `docs/internals/runtime-map.md`.

mod entity;
mod extractor;

pub use entity::{
    AuthArtifactKind, LimitsError, SemanticEntity, SemanticEntityType, SemanticExtractionLimits,
    SemanticExtractionResult,
};
pub use extractor::EntityExtractor;
