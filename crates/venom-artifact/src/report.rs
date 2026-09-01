//! Stable observation-only artifact scan reports and renderers.

use crate::{ArtifactCatalogDigest, ArtifactError, ArtifactObservationClass, ArtifactSignatureRef};
use serde::Serialize;
use std::fmt;

/// Stable machine-readable report schema.
pub const ARTIFACT_SCAN_REPORT_SCHEMA: &str = "venom.artifact-scan/v1";
/// Maximum bytes emitted by either built-in report renderer.
pub const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const MAX_RENDERED_REPORT_BASE_BYTES: usize = 4 * 1024;
const MAX_RENDERED_OBSERVATION_BYTES: usize = 512;

const _: () = assert!(
    MAX_RENDERED_REPORT_BASE_BYTES + crate::MAX_MATCHES_PER_SCAN * MAX_RENDERED_OBSERVATION_BYTES
        <= MAX_REPORT_BYTES
);

/// SHA-256 identity of a completely consumed artifact.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ArtifactDigest(String);

impl ArtifactDigest {
    pub(crate) fn from_hex(hex_digest: &str) -> Self {
        Self(format!("artifact-sha256:{hex_digest}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// SHA-256 identity of only the bounded bytes consumed by an incomplete scan.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ConsumedPrefixDigest(String);

impl ConsumedPrefixDigest {
    pub(crate) fn from_hex(hex_digest: &str) -> Self {
        Self(format!("consumed-prefix-sha256:{hex_digest}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ConsumedPrefixDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ConsumedPrefixDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ConsumedPrefixDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Typed content identity that never labels an incomplete prefix as a full artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ArtifactContentIdentity {
    Artifact {
        digest: ArtifactDigest,
    },
    ConsumedPrefix {
        digest: ConsumedPrefixDigest,
        bytes_consumed: u64,
    },
}

impl ArtifactContentIdentity {
    pub fn digest(&self) -> &str {
        match self {
            Self::Artifact { digest } => digest.as_str(),
            Self::ConsumedPrefix { digest, .. } => digest.as_str(),
        }
    }

    pub fn is_complete_artifact(&self) -> bool {
        matches!(self, Self::Artifact { .. })
    }
}

/// Typed bounded completion state for one scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactScanCompletion {
    Complete,
    InputLimitReached,
    MatchLimitReached,
    MatchWorkLimitReached,
    ReaderFailed,
}

impl ArtifactScanCompletion {
    pub fn is_complete(self) -> bool {
        self == Self::Complete
    }

    /// Returns the stable V1 wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::InputLimitReached => "input-limit-reached",
            Self::MatchLimitReached => "match-limit-reached",
            Self::MatchWorkLimitReached => "match-work-limit-reached",
            Self::ReaderFailed => "reader-failed",
        }
    }
}

/// One deterministic observation. It contains no matched bytes or verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactMatchObservation {
    signature: ArtifactSignatureRef,
    absolute_offset: u64,
    pattern_length: u16,
    observation_class: ArtifactObservationClass,
    ordinal: u32,
}

impl ArtifactMatchObservation {
    pub(crate) fn new(
        signature: ArtifactSignatureRef,
        absolute_offset: u64,
        pattern_length: usize,
        observation_class: ArtifactObservationClass,
    ) -> Result<Self, ArtifactError> {
        let pattern_length =
            u16::try_from(pattern_length).map_err(|_| ArtifactError::LimitExceeded {
                field: "reported pattern length",
                limit: u16::MAX as usize,
            })?;
        Ok(Self {
            signature,
            absolute_offset,
            pattern_length,
            observation_class,
            ordinal: 0,
        })
    }

    pub fn signature(&self) -> &ArtifactSignatureRef {
        &self.signature
    }

    pub fn absolute_offset(&self) -> u64 {
        self.absolute_offset
    }

    pub fn pattern_length(&self) -> u16 {
        self.pattern_length
    }

    pub fn observation_class(&self) -> ArtifactObservationClass {
        self.observation_class
    }

    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
}

/// Stable bounded artifact scan report. A match is only an observation.
///
/// Serialization is deliberately available only through [`Self::to_json`],
/// which enforces the report byte ceiling.
///
/// ```compile_fail
/// fn bypass_bounded_renderer(report: &venom_artifact::ArtifactScanReport) {
///     let _ = serde_json::to_string(report);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactScanReport {
    schema: &'static str,
    algorithm_version: &'static str,
    catalog_digest: ArtifactCatalogDigest,
    content_identity: ArtifactContentIdentity,
    completion: ArtifactScanCompletion,
    bytes_consumed: u64,
    match_start_positions_checked: u64,
    signatures_considered: usize,
    match_count: usize,
    matches: Vec<ArtifactMatchObservation>,
    match_work_units: usize,
}

pub(crate) struct ArtifactScanReportParts {
    pub algorithm_version: &'static str,
    pub catalog_digest: ArtifactCatalogDigest,
    pub content_identity: ArtifactContentIdentity,
    pub completion: ArtifactScanCompletion,
    pub bytes_consumed: u64,
    pub match_start_positions_checked: u64,
    pub signatures_considered: usize,
    pub matches: Vec<ArtifactMatchObservation>,
    pub match_work_units: usize,
}

impl ArtifactScanReport {
    pub(crate) fn new(parts: ArtifactScanReportParts) -> Result<Self, ArtifactError> {
        let ArtifactScanReportParts {
            algorithm_version,
            catalog_digest,
            content_identity,
            completion,
            bytes_consumed,
            match_start_positions_checked,
            signatures_considered,
            mut matches,
            match_work_units,
        } = parts;
        if matches.len() > crate::MAX_MATCHES_PER_SCAN {
            return Err(ArtifactError::LimitExceeded {
                field: "artifact report matches",
                limit: crate::MAX_MATCHES_PER_SCAN,
            });
        }
        if match_work_units > crate::MAX_MATCH_WORK_UNITS {
            return Err(ArtifactError::LimitExceeded {
                field: "artifact match work units",
                limit: crate::MAX_MATCH_WORK_UNITS,
            });
        }
        match (&content_identity, completion) {
            (ArtifactContentIdentity::Artifact { .. }, ArtifactScanCompletion::Complete) => {
                if match_start_positions_checked != bytes_consumed {
                    return Err(ArtifactError::InvalidScanReport {
                        field: "complete match frontier",
                    });
                }
            },
            (
                ArtifactContentIdentity::ConsumedPrefix {
                    bytes_consumed: identity_bytes,
                    ..
                },
                completion,
            ) if !completion.is_complete() => {
                if *identity_bytes != bytes_consumed {
                    return Err(ArtifactError::InvalidScanReport {
                        field: "consumed prefix bytes",
                    });
                }
            },
            _ => {
                return Err(ArtifactError::InvalidScanReport {
                    field: "content identity completion",
                });
            },
        }
        if match_start_positions_checked > bytes_consumed {
            return Err(ArtifactError::InvalidScanReport {
                field: "match start positions checked",
            });
        }
        let worst_case_rendered_bytes = matches
            .len()
            .checked_mul(MAX_RENDERED_OBSERVATION_BYTES)
            .and_then(|bytes| bytes.checked_add(MAX_RENDERED_REPORT_BASE_BYTES))
            .ok_or(ArtifactError::ReportSerializationFailed)?;
        if worst_case_rendered_bytes > MAX_REPORT_BYTES {
            return Err(ArtifactError::LimitExceeded {
                field: "artifact report shape",
                limit: MAX_REPORT_BYTES,
            });
        }
        matches.sort_by(|left, right| {
            (
                left.absolute_offset,
                &left.signature,
                left.pattern_length,
                left.observation_class,
            )
                .cmp(&(
                    right.absolute_offset,
                    &right.signature,
                    right.pattern_length,
                    right.observation_class,
                ))
        });
        for (index, observation) in matches.iter_mut().enumerate() {
            observation.ordinal =
                u32::try_from(index + 1).map_err(|_| ArtifactError::LimitExceeded {
                    field: "match observation ordinals",
                    limit: u32::MAX as usize,
                })?;
        }
        Ok(Self {
            schema: ARTIFACT_SCAN_REPORT_SCHEMA,
            algorithm_version,
            catalog_digest,
            content_identity,
            completion,
            bytes_consumed,
            match_start_positions_checked,
            signatures_considered,
            match_count: matches.len(),
            matches,
            match_work_units,
        })
    }

    pub fn schema(&self) -> &str {
        self.schema
    }

    pub fn algorithm_version(&self) -> &str {
        self.algorithm_version
    }

    pub fn catalog_digest(&self) -> &ArtifactCatalogDigest {
        &self.catalog_digest
    }

    pub fn content_identity(&self) -> &ArtifactContentIdentity {
        &self.content_identity
    }

    pub fn completion(&self) -> ArtifactScanCompletion {
        self.completion
    }

    pub fn is_complete(&self) -> bool {
        self.completion.is_complete()
    }

    /// Returns source bytes consumed and included in the content digest.
    ///
    /// On an incomplete report this can exceed the fully checked matcher
    /// frontier because a bounded reader may have read ahead by one chunk.
    pub fn bytes_consumed(&self) -> u64 {
        self.bytes_consumed
    }

    /// Returns the exclusive byte-start frontier fully checked by the matcher.
    ///
    /// Every possible match start below this value was checked against every
    /// catalog anchor group. No claim is made about starts at or above it.
    pub fn match_start_positions_checked(&self) -> u64 {
        self.match_start_positions_checked
    }

    pub fn signatures_considered(&self) -> usize {
        self.signatures_considered
    }

    pub fn match_count(&self) -> usize {
        self.match_count
    }

    pub fn matches(&self) -> impl ExactSizeIterator<Item = &ArtifactMatchObservation> {
        self.matches.iter()
    }

    pub fn match_work_units(&self) -> usize {
        self.match_work_units
    }

    /// Serializes stable bounded JSON without paths, matched bytes, or verdicts.
    pub fn to_json(&self) -> Result<String, ArtifactError> {
        let wire = ArtifactScanReportWire {
            schema: self.schema,
            algorithm_version: self.algorithm_version,
            catalog_digest: &self.catalog_digest,
            content_identity: &self.content_identity,
            completion: self.completion,
            bytes_consumed: self.bytes_consumed,
            match_start_positions_checked: self.match_start_positions_checked,
            signatures_considered: self.signatures_considered,
            match_count: self.match_count,
            matches: &self.matches,
            match_work_units: self.match_work_units,
        };
        let json =
            serde_json::to_string(&wire).map_err(|_| ArtifactError::ReportSerializationFailed)?;
        enforce_report_bound(json)
    }

    /// Renders bounded human-readable observation output for opt-in adapters.
    pub fn render_text(&self) -> Result<String, ArtifactError> {
        let mut rendered = format!(
            "schema: {}\nalgorithm: {}\ncompletion: {}\nbytes consumed: {}\nmatch start positions checked: {}\nsignatures considered: {}\nmatches: {}\nmatch work units: {}\n",
            self.schema,
            self.algorithm_version,
            self.completion.as_str(),
            self.bytes_consumed,
            self.match_start_positions_checked,
            self.signatures_considered,
            self.match_count,
            self.match_work_units
        );
        for observation in &self.matches {
            use std::fmt::Write;
            writeln!(
                rendered,
                "{}: {}:{}@{} ({} bytes, {})",
                observation.ordinal,
                observation.signature.pack_id(),
                observation.signature.signature_id(),
                observation.absolute_offset,
                observation.pattern_length,
                observation.observation_class.as_str()
            )
            .map_err(|_| ArtifactError::ReportSerializationFailed)?;
            if rendered.len() > MAX_REPORT_BYTES {
                return Err(ArtifactError::LimitExceeded {
                    field: "artifact report bytes",
                    limit: MAX_REPORT_BYTES,
                });
            }
        }
        enforce_report_bound(rendered)
    }
}

#[derive(Serialize)]
struct ArtifactScanReportWire<'a> {
    schema: &'static str,
    algorithm_version: &'static str,
    catalog_digest: &'a ArtifactCatalogDigest,
    content_identity: &'a ArtifactContentIdentity,
    completion: ArtifactScanCompletion,
    bytes_consumed: u64,
    match_start_positions_checked: u64,
    signatures_considered: usize,
    match_count: usize,
    matches: &'a [ArtifactMatchObservation],
    match_work_units: usize,
}

fn enforce_report_bound(rendered: String) -> Result<String, ArtifactError> {
    if rendered.len() > MAX_REPORT_BYTES {
        return Err(ArtifactError::LimitExceeded {
            field: "artifact report bytes",
            limit: MAX_REPORT_BYTES,
        });
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArtifactCatalog, ArtifactPackId, ArtifactSignatureId, ArtifactSignaturePack,
        ArtifactSignatureRevision,
    };

    fn catalog_digest() -> ArtifactCatalogDigest {
        let source = br#"schema = "venom.artifact-signatures/v1"
pack_id = "lab"
pack_revision = 1
title = "Lab"
summary = "Harmless report fixture"
[[signatures]]
id = "marker"
revision = 1
label = "Marker"
observation_class = "test-canary"
pattern = "41 42"
tags = ["lab"]
"#;
        let pack = ArtifactSignaturePack::parse_toml(source).expect("pack");
        let mut builder = ArtifactCatalog::builder();
        builder.register(pack).expect("register");
        builder.seal().expect("seal").digest().clone()
    }

    fn report() -> ArtifactScanReport {
        let reference = ArtifactSignatureRef::new(
            ArtifactPackId::parse("lab").expect("pack"),
            ArtifactSignatureId::parse("marker").expect("signature"),
            ArtifactSignatureRevision::new(1).expect("revision"),
        );
        ArtifactScanReport::new(ArtifactScanReportParts {
            algorithm_version: "venom.artifact-signature-scan/v1",
            catalog_digest: catalog_digest(),
            content_identity: ArtifactContentIdentity::Artifact {
                digest: ArtifactDigest::from_hex("11"),
            },
            completion: ArtifactScanCompletion::Complete,
            bytes_consumed: 4,
            match_start_positions_checked: 4,
            signatures_considered: 1,
            matches: vec![
                ArtifactMatchObservation::new(
                    reference.clone(),
                    2,
                    2,
                    ArtifactObservationClass::TestCanary,
                )
                .expect("match"),
                ArtifactMatchObservation::new(
                    reference,
                    0,
                    2,
                    ArtifactObservationClass::TestCanary,
                )
                .expect("match"),
            ],
            match_work_units: 2,
        })
        .expect("report")
    }

    fn empty_report_parts(
        content_identity: ArtifactContentIdentity,
        completion: ArtifactScanCompletion,
        bytes_consumed: u64,
        match_start_positions_checked: u64,
    ) -> ArtifactScanReportParts {
        ArtifactScanReportParts {
            algorithm_version: "venom.artifact-signature-scan/v1",
            catalog_digest: catalog_digest(),
            content_identity,
            completion,
            bytes_consumed,
            match_start_positions_checked,
            signatures_considered: 1,
            matches: Vec::new(),
            match_work_units: 1,
        }
    }

    #[test]
    fn report_orders_observations_and_assigns_stable_ordinals() {
        let report = report();
        let matches = report.matches().collect::<Vec<_>>();
        assert_eq!(matches[0].absolute_offset(), 0);
        assert_eq!(matches[0].ordinal(), 1);
        assert_eq!(matches[1].absolute_offset(), 2);
        assert_eq!(matches[1].ordinal(), 2);
        assert!(report.is_complete());
        assert!(report.content_identity().is_complete_artifact());
    }

    #[test]
    fn json_and_text_are_stable_and_observation_only() {
        let report = report();
        let json = report.to_json().expect("json");
        assert!(json.contains("\"schema\":\"venom.artifact-scan/v1\""));
        assert!(json.contains("\"completion\":\"complete\""));
        assert!(json.contains("\"bytes_consumed\":4"));
        assert!(json.contains("\"match_start_positions_checked\":4"));
        assert!(!json.contains("bytes_scanned"));
        assert!(json.contains("\"match_count\":2"));
        for forbidden in ["vulnerability", "severity", "malware", "matched_bytes"] {
            assert!(!json.to_ascii_lowercase().contains(forbidden));
        }
        let text = report.render_text().expect("text");
        assert!(text.contains("matches: 2"));
        assert!(text.contains("lab:marker@0"));
        assert!(text.contains("completion: complete"));
        assert!(text.contains("test-canary"));
        assert!(!text.contains("TestCanary"));
        assert_eq!(report.to_json().expect("repeat"), json);
    }

    #[test]
    fn consumed_prefix_identity_is_explicitly_not_a_full_artifact() {
        let identity = ArtifactContentIdentity::ConsumedPrefix {
            digest: ConsumedPrefixDigest::from_hex("22"),
            bytes_consumed: 3,
        };
        assert!(!identity.is_complete_artifact());
        assert!(identity.digest().starts_with("consumed-prefix-sha256:"));
        assert!(!ArtifactScanCompletion::ReaderFailed.is_complete());
    }

    #[test]
    fn exact_maximum_report_shape_is_always_bounded() {
        let identity = "a".repeat(64);
        let reference = ArtifactSignatureRef::new(
            ArtifactPackId::parse(identity.clone()).expect("pack"),
            ArtifactSignatureId::parse(identity).expect("signature"),
            ArtifactSignatureRevision::new(u32::MAX).expect("revision"),
        );
        let mut matches = Vec::with_capacity(crate::MAX_MATCHES_PER_SCAN);
        for index in 0..crate::MAX_MATCHES_PER_SCAN {
            matches.push(
                ArtifactMatchObservation::new(
                    reference.clone(),
                    index as u64,
                    crate::MAX_PATTERN_BYTES,
                    ArtifactObservationClass::SuspiciousSequence,
                )
                .expect("observation"),
            );
        }
        let report = ArtifactScanReport::new(ArtifactScanReportParts {
            algorithm_version: "venom.artifact-signature-scan/v1",
            catalog_digest: catalog_digest(),
            content_identity: ArtifactContentIdentity::ConsumedPrefix {
                digest: ConsumedPrefixDigest::from_hex(&"f".repeat(64)),
                bytes_consumed: u64::MAX,
            },
            completion: ArtifactScanCompletion::MatchWorkLimitReached,
            bytes_consumed: u64::MAX,
            match_start_positions_checked: u64::MAX,
            signatures_considered: crate::MAX_TOTAL_SIGNATURES,
            matches,
            match_work_units: crate::MAX_MATCH_WORK_UNITS,
        })
        .expect("maximum report");
        let json = report.to_json().expect("bounded JSON");
        let text = report.render_text().expect("bounded text");
        assert!(json.len() <= MAX_REPORT_BYTES);
        assert!(text.len() <= MAX_REPORT_BYTES);
        assert_eq!(report.match_count(), crate::MAX_MATCHES_PER_SCAN);
        assert_eq!(report.match_work_units(), crate::MAX_MATCH_WORK_UNITS);
    }

    #[test]
    fn internal_report_shape_rejects_excess_matches_and_work_units() {
        let reference = ArtifactSignatureRef::new(
            ArtifactPackId::parse("lab").expect("pack"),
            ArtifactSignatureId::parse("marker").expect("signature"),
            ArtifactSignatureRevision::new(1).expect("revision"),
        );
        let observation =
            ArtifactMatchObservation::new(reference, 0, 2, ArtifactObservationClass::TestCanary)
                .expect("observation");
        let excessive_matches = vec![observation; crate::MAX_MATCHES_PER_SCAN + 1];
        assert!(matches!(
            ArtifactScanReport::new(ArtifactScanReportParts {
                algorithm_version: "venom.artifact-signature-scan/v1",
                catalog_digest: catalog_digest(),
                content_identity: ArtifactContentIdentity::Artifact {
                    digest: ArtifactDigest::from_hex("00")
                },
                completion: ArtifactScanCompletion::Complete,
                bytes_consumed: 0,
                match_start_positions_checked: 0,
                signatures_considered: 1,
                matches: excessive_matches,
                match_work_units: 0,
            }),
            Err(ArtifactError::LimitExceeded {
                field: "artifact report matches",
                ..
            })
        ));
        assert!(matches!(
            ArtifactScanReport::new(ArtifactScanReportParts {
                algorithm_version: "venom.artifact-signature-scan/v1",
                catalog_digest: catalog_digest(),
                content_identity: ArtifactContentIdentity::Artifact {
                    digest: ArtifactDigest::from_hex("00")
                },
                completion: ArtifactScanCompletion::Complete,
                bytes_consumed: 0,
                match_start_positions_checked: 0,
                signatures_considered: 1,
                matches: Vec::new(),
                match_work_units: crate::MAX_MATCH_WORK_UNITS + 1,
            }),
            Err(ArtifactError::LimitExceeded {
                field: "artifact match work units",
                ..
            })
        ));

        assert!(matches!(
            ArtifactScanReport::new(ArtifactScanReportParts {
                algorithm_version: "venom.artifact-signature-scan/v1",
                catalog_digest: catalog_digest(),
                content_identity: ArtifactContentIdentity::ConsumedPrefix {
                    digest: ConsumedPrefixDigest::from_hex("00"),
                    bytes_consumed: 1,
                },
                completion: ArtifactScanCompletion::MatchWorkLimitReached,
                bytes_consumed: 1,
                match_start_positions_checked: 2,
                signatures_considered: 1,
                matches: Vec::new(),
                match_work_units: 1,
            }),
            Err(ArtifactError::InvalidScanReport {
                field: "match start positions checked"
            })
        ));
    }

    #[test]
    fn internal_report_rejects_contradictory_identity_completion_and_frontier() {
        assert_eq!(
            ArtifactScanReport::new(empty_report_parts(
                ArtifactContentIdentity::ConsumedPrefix {
                    digest: ConsumedPrefixDigest::from_hex("00"),
                    bytes_consumed: 1,
                },
                ArtifactScanCompletion::Complete,
                1,
                1,
            )),
            Err(ArtifactError::InvalidScanReport {
                field: "content identity completion"
            })
        );
        assert_eq!(
            ArtifactScanReport::new(empty_report_parts(
                ArtifactContentIdentity::Artifact {
                    digest: ArtifactDigest::from_hex("00"),
                },
                ArtifactScanCompletion::MatchWorkLimitReached,
                1,
                0,
            )),
            Err(ArtifactError::InvalidScanReport {
                field: "content identity completion"
            })
        );
        assert_eq!(
            ArtifactScanReport::new(empty_report_parts(
                ArtifactContentIdentity::ConsumedPrefix {
                    digest: ConsumedPrefixDigest::from_hex("00"),
                    bytes_consumed: 2,
                },
                ArtifactScanCompletion::MatchWorkLimitReached,
                1,
                0,
            )),
            Err(ArtifactError::InvalidScanReport {
                field: "consumed prefix bytes"
            })
        );
        assert_eq!(
            ArtifactScanReport::new(empty_report_parts(
                ArtifactContentIdentity::Artifact {
                    digest: ArtifactDigest::from_hex("00"),
                },
                ArtifactScanCompletion::Complete,
                2,
                1,
            )),
            Err(ArtifactError::InvalidScanReport {
                field: "complete match frontier"
            })
        );
    }
}
