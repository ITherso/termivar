//! Semantic Model Builder components: entity extraction, relation discovery, and plane classification.

mod entity;
mod extractor;

pub use entity::{AuthArtifactKind, SemanticEntity, SemanticEntityType, SemanticExtractionLimits};
pub use extractor::EntityExtractor;
