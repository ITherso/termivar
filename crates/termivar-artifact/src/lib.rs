//! Preview bounded artifact-signature compilation and scanning.
//!
//! This crate classifies deterministic byte-pattern matches as observations.
//! It owns no path, network, process, browser, or exploit authority and never
//! interprets matched content as a vulnerability or malware verdict.

#![forbid(unsafe_code)]

use thiserror::Error;

mod catalog;
mod pattern;
mod report;
mod scanner;

/// A fail-closed signature model, catalog, scan, or rendering error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ArtifactError {
    /// A bounded input exceeded its compiled ceiling.
    #[error("{field} exceeds the compiled limit of {limit}")]
    LimitExceeded { field: &'static str, limit: usize },
    /// A stable identity was not canonical.
    #[error("{field} is not a canonical artifact identity")]
    InvalidIdentifier { field: &'static str },
    /// A pack or signature revision was zero.
    #[error("{field} must be greater than zero")]
    InvalidRevision { field: &'static str },
    /// Host-supplied manifest bytes were not UTF-8.
    #[error("artifact signature manifest is not valid UTF-8")]
    InvalidUtf8,
    /// TOML did not match the strict schema.
    #[error("artifact signature manifest does not match the strict schema")]
    InvalidManifestSyntax,
    /// The manifest schema is not supported.
    #[error("unsupported artifact signature schema")]
    UnsupportedSchema,
    /// A bounded human-readable metadata field was invalid.
    #[error("{field} is not valid bounded artifact metadata")]
    InvalidText { field: &'static str },
    /// A signature pattern token or shape was invalid.
    #[error("invalid artifact signature pattern")]
    InvalidPattern,
    /// A signature did not contain enough exact literal bytes.
    #[error("artifact signature requires at least two exact literal bytes")]
    InsufficientLiteralBytes,
    /// A pack identity was registered more than once.
    #[error("duplicate artifact signature pack")]
    DuplicatePack,
    /// One pack identity appeared with conflicting revisions.
    #[error("conflicting artifact signature pack revision")]
    ConflictingPackRevision,
    /// A signature identity was registered more than once.
    #[error("duplicate artifact signature identity")]
    DuplicateSignature,
    /// One signature identity appeared with conflicting revisions.
    #[error("conflicting artifact signature revision")]
    ConflictingSignatureRevision,
    /// Two identities declared the same semantic byte pattern.
    #[error("duplicate semantic artifact signature pattern")]
    DuplicateSemanticPattern,
    /// A catalog hard ceiling was exceeded.
    #[error("artifact signature catalog capacity exceeded")]
    CatalogCapacityExceeded,
    /// Scan limits were zero or exceeded a hard ceiling.
    #[error("invalid artifact scan limit: {field}")]
    InvalidScanLimit { field: &'static str },
    /// Absolute input offset arithmetic overflowed.
    #[error("artifact scan offset overflow")]
    OffsetOverflow,
    /// Stable report serialization exceeded its closed contract.
    #[error("artifact scan report serialization failed")]
    ReportSerializationFailed,
    /// Internal scan-report facts contradicted the closed report contract.
    #[error("invalid artifact scan report: {field}")]
    InvalidScanReport { field: &'static str },
}

pub use catalog::{
    ArtifactCatalog, ArtifactCatalogBuilder, ArtifactCatalogDigest, ArtifactCatalogSignature,
    ArtifactObservationClass, ArtifactPackId, ArtifactPackRevision, ArtifactSignatureDefinition,
    ArtifactSignatureId, ArtifactSignaturePack, ArtifactSignatureRef, ArtifactSignatureRevision,
    ARTIFACT_SIGNATURE_SCHEMA, MAX_CATALOG_QUERY_RESULTS, MAX_DESCRIPTION_BYTES, MAX_LABEL_BYTES,
    MAX_PACKS_PER_CATALOG, MAX_PACK_SUMMARY_BYTES, MAX_PACK_TITLE_BYTES, MAX_SIGNATURES_PER_PACK,
    MAX_SIGNATURE_MANIFEST_BYTES, MAX_TAGS_PER_SIGNATURE, MAX_TAG_BYTES,
    MAX_TOTAL_COMPILED_PATTERN_BYTES, MAX_TOTAL_SIGNATURES,
};
pub use pattern::{ArtifactPattern, MAX_PATTERN_BYTES, MIN_LITERAL_BYTES};
pub use report::{
    ArtifactContentIdentity, ArtifactDigest, ArtifactMatchObservation, ArtifactScanCompletion,
    ArtifactScanReport, ConsumedPrefixDigest, ARTIFACT_SCAN_REPORT_SCHEMA, MAX_REPORT_BYTES,
};
pub use scanner::{
    ArtifactScanLimits, ArtifactScanner, ARTIFACT_SCAN_ALGORITHM_VERSION, DEFAULT_INPUT_BYTES,
    DEFAULT_MATCHES_PER_SCAN, DEFAULT_MATCH_WORK_UNITS, DEFAULT_READER_CHUNK_BYTES,
    MAX_INPUT_BYTES, MAX_MATCHES_PER_SCAN, MAX_MATCH_WORK_UNITS, MAX_READER_CHUNK_BYTES,
};

impl ArtifactSignaturePack {
    /// Parses and validates one strict bounded TOML pack supplied by a host.
    ///
    /// The operation performs no filesystem access and compiles every pattern
    /// before returning a checked pack.
    pub fn parse_toml(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() > MAX_SIGNATURE_MANIFEST_BYTES {
            return Err(ArtifactError::LimitExceeded {
                field: "signature manifest bytes",
                limit: MAX_SIGNATURE_MANIFEST_BYTES,
            });
        }
        let source = std::str::from_utf8(bytes).map_err(|_| ArtifactError::InvalidUtf8)?;
        catalog::parse_pack_source(source)
    }
}
