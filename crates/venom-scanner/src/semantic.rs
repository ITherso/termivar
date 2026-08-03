//! Semantic Model Builder components: deterministic entity extraction from scanner evidence (Phase 1).

mod entity;
mod extractor;

pub use entity::{
    AuthArtifactKind, LimitsError, SemanticEntity, SemanticEntityType, SemanticExtractionLimits,
    SemanticExtractionResult,
};
pub use extractor::EntityExtractor;
