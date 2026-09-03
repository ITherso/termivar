//! Deterministic validation for the post-workspace WAF/evasion salvage epoch.

use crate::{scanner_salvage, TaskResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

const LEDGER_RELATIVE_PATH: &str = "salvage/post-workspace-waf-evasion/ledger.toml";
const REPORT_RELATIVE_PATH: &str = "docs/history/post-workspace-waf-evasion-salvage.md";
const PRIOR_LEDGER_RELATIVE_PATH: &str = "salvage/historical-scanner/ledger.toml";
const SCHEMA: &str = "venom.post-workspace-waf-evasion-salvage/v1";
const SOURCE_EPOCH: &str = "post-workspace-waf-evasion-quarantine";
const DIGEST_ALGORITHM: &str = "venom.post-workspace-waf-evasion-salvage-digest/v1";
const DIGEST_PREFIX: &str = "waf-evasion-salvage-sha256";
const SOURCE_SNAPSHOT: &str = "52238460484e7a1469f1028fdd6361072a0daba5";
const QUARANTINE_COMMIT: &str = "5a0563886658859b6e3e163f732a298914b10800";
const REPLACEMENT_BASELINE: &str = "e1e4077d159d6df5cdca8e274ecd40b40bb2f9c5";
const PRIOR_LEDGER_DIGEST: &str =
    "salvage-sha256:c2e4fec16f5d044ea2007f134ed18389f2b6890c621159d3554bafcf4be8e333";
const EXPECTED_FILE_COUNT: usize = 13;
const EXPECTED_COMPONENT_COUNT: usize = 39;
const MAX_LEDGER_BYTES: usize = 512 * 1024;
const MAX_REPORT_BYTES: usize = 1024 * 1024;
const MAX_COMPONENTS_PER_FILE: usize = 16;
const MAX_COMPONENT_ID_BYTES: usize = 128;
const MAX_PATH_BYTES: usize = 256;
const MAX_SYMBOL_BYTES: usize = 192;
const MAX_FACT_BYTES: usize = 640;
const MAX_NOTES_BYTES: usize = 1024;
const MAX_SET_ENTRIES: usize = 16;

pub(super) fn run(workspace_root: &Path, write: bool) -> TaskResult {
    let ledger_path = workspace_root.join(LEDGER_RELATIVE_PATH);
    let source = read_bounded(&ledger_path, MAX_LEDGER_BYTES)?;
    let mut ledger = parse_ledger(&source)?;
    validate_ledger(&ledger)?;
    validate_current_replacement_paths(workspace_root, &ledger)?;
    validate_prior_ledger(workspace_root, &ledger)?;
    validate_history(workspace_root, &ledger)?;
    let digest = semantic_digest(&ledger);

    if write {
        rewrite_digest(&ledger_path, &source, &digest)?;
        ledger.ledger_digest.clone_from(&digest);
        let report_path = workspace_root.join(REPORT_RELATIVE_PATH);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(report_path, render_markdown(&ledger))?;
    } else {
        if ledger.ledger_digest != digest {
            return Err(format!(
                "WAF/evasion salvage digest mismatch: stored {}, computed {digest}",
                ledger.ledger_digest
            )
            .into());
        }
        let report_source =
            read_bounded(&workspace_root.join(REPORT_RELATIVE_PATH), MAX_REPORT_BYTES)?;
        let report = std::str::from_utf8(&report_source)
            .map_err(|_| "generated WAF/evasion salvage report is not valid UTF-8")?;
        let expected = render_markdown(&ledger);
        validate_rendered_report(report, &expected)?;
    }

    let summary = Summary::from_ledger(&ledger);
    println!(
        "post-workspace WAF/evasion salvage validated: {} file(s), {} component(s), {} P0/P1, digest {}",
        ledger.files.len(),
        summary.component_count,
        summary.high_priority_count,
        digest
    );
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SalvageLedger {
    schema: String,
    source_epoch: String,
    source_snapshot_commit: String,
    quarantine_commit: String,
    scoped_source_paths: Vec<String>,
    expected_scoped_file_count: usize,
    algorithm_version: String,
    ledger_digest: String,
    current_replacement_baseline_sha: String,
    prior_salvage_ledger: String,
    prior_salvage_digest: String,
    separate_source_epoch: bool,
    files: Vec<HistoricalFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoricalFile {
    path: String,
    blob_sha: String,
    byte_size: u64,
    source_role: SourceRole,
    quarantine_change: QuarantineChange,
    historical_build_reachability: BuildReachability,
    historical_runtime_reachability: RuntimeReachability,
    direct_network_authority: AuthorityUse,
    request_shape_authority: RequestShapeAuthority,
    process_filesystem_authority: AuthorityUse,
    unsafe_code: UnsafeCodeStatus,
    identity_behavior: IdentityBehavior,
    evidence_quality: EvidenceQuality,
    claim_risk: ClaimRisk,
    current_replacement_paths: Vec<String>,
    salvage_priority: Priority,
    notes: String,
    components: Vec<HistoricalComponent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoricalComponent {
    id: String,
    source_symbol: String,
    disposition: Disposition,
    priority: Priority,
    historical_behavior: String,
    old_runtime_reachability: RuntimeReachability,
    reusable_value: String,
    prohibited_restoration_behaviors: Vec<ProhibitedRestorationBehavior>,
    modern_destination: ModernDestination,
    current_replacement_paths: Vec<String>,
    prerequisites: Vec<String>,
    status: ComponentStatus,
    rationale: String,
}

macro_rules! closed_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        enum $name {
            $(#[serde(rename = $wire)] $variant),+
        }

        impl $name {
            const fn wire(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }
    };
}

closed_enum!(SourceRole {
    AdaptiveOrchestration => "adaptive-orchestration",
    AdaptivePayloadTransforms => "adaptive-payload-transforms",
    AdaptiveResponseScoring => "adaptive-response-scoring",
    AdaptiveStrategySelection => "adaptive-strategy-selection",
    DefenseEvasionAnalysis => "defense-evasion-analysis",
    ApiConfiguration => "api-configuration",
    ScannerConfiguration => "scanner-configuration",
    ConfigurationLoading => "configuration-loading",
    CrateApiSurface => "crate-api-surface",
    PayloadEncoding => "payload-encoding",
    PayloadStrategyExports => "payload-strategy-exports",
    PayloadNormalization => "payload-normalization",
    WafFingerprintAndTransforms => "waf-fingerprint-and-transforms"
});

closed_enum!(QuarantineChange {
    Removed => "removed",
    MateriallyNarrowed => "materially-narrowed"
});

closed_enum!(BuildReachability {
    Built => "built",
    DeclaredButUnbuilt => "declared-but-unbuilt",
    NotDeclared => "not-declared",
    Unknown => "unknown"
});

closed_enum!(RuntimeReachability {
    Reachable => "reachable",
    PartiallyReachable => "partially-reachable",
    LibraryOnly => "library-only",
    Unreachable => "unreachable",
    Unknown => "unknown"
});

closed_enum!(AuthorityUse {
    None => "none",
    CallerSupplied => "caller-supplied",
    Direct => "direct",
    Mixed => "mixed",
    Unknown => "unknown"
});

closed_enum!(RequestShapeAuthority {
    None => "none",
    PayloadBytes => "payload-bytes",
    QueryShape => "query-shape",
    MethodAndQuery => "method-and-query",
    Mixed => "mixed",
    Unknown => "unknown"
});

closed_enum!(UnsafeCodeStatus {
    Absent => "absent",
    Present => "present",
    Unknown => "unknown"
});

closed_enum!(IdentityBehavior {
    Deterministic => "deterministic",
    Randomized => "randomized",
    Mixed => "mixed",
    NotApplicable => "not-applicable",
    Unknown => "unknown"
});

closed_enum!(EvidenceQuality {
    EvidenceBacked => "evidence-backed",
    Heuristic => "heuristic",
    Unsubstantiated => "unsubstantiated",
    Mixed => "mixed",
    NotApplicable => "not-applicable"
});

closed_enum!(ClaimRisk {
    Low => "low",
    Moderate => "moderate",
    High => "high",
    Mixed => "mixed",
    NotApplicable => "not-applicable"
});

closed_enum!(Priority {
    P0 => "p0",
    P1 => "p1",
    P2 => "p2",
    P3 => "p3",
    Never => "never"
});

closed_enum!(Disposition {
    PortAlgorithm => "port-algorithm",
    ImportMetadataOnly => "import-metadata-only",
    RewriteFromContract => "rewrite-from-contract",
    SupersededByCurrentRuntime => "superseded-by-current-runtime",
    RejectBlindDispatcher => "reject-blind-dispatcher",
    RejectMisleadingClaim => "reject-misleading-claim",
    RejectUnsafeTechnique => "reject-unsafe-technique",
    MoveToDifferentCapability => "move-to-different-capability",
    ArchiveReference => "archive-reference"
});

closed_enum!(ModernDestination {
    Defense => "venom-scanner:defense",
    DefenseFingerprint => "venom-scanner:defense-fingerprint",
    DefenseStateTransition => "venom-scanner:defense-state-transition",
    NormalizationResilience => "venom-scanner:normalization-resilience",
    PayloadCatalog => "venom-scanner:payload-catalog",
    PayloadStrategiesEncoding => "venom-scanner:payload-strategies-encoding",
    PayloadArtifact => "venom-scanner:payload-artifact",
    FutureTypedRequestShape => "future-typed-request-shape",
    FutureRequestFraming => "future-request-framing",
    DocumentationOnly => "documentation-only",
    None => "none"
});

closed_enum!(ProhibitedRestorationBehavior {
    BlindDispatch => "blind-dispatch",
    StatusOnlyAuthority => "status-only-authority",
    FingerprintAsAuthority => "fingerprint-as-authority",
    GenericStringMutation => "generic-string-mutation",
    UnboundedTransformChain => "unbounded-transform-chain",
    SemanticTruncation => "semantic-truncation",
    RateLimitEvasion => "rate-limit-evasion",
    RequestShapeMutation => "request-shape-mutation",
    HttpSplitting => "http-splitting",
    CrlfInjection => "crlf-injection",
    DirectNetworkAuthority => "direct-network-authority",
    RawPayloadEvidence => "raw-payload-evidence",
    MisleadingBypassClaim => "misleading-bypass-claim",
    AutomaticExploitation => "automatic-exploitation",
    AmbiguousEncodingLayer => "ambiguous-encoding-layer",
    ProductMisclassification => "product-misclassification"
});

closed_enum!(ComponentStatus {
    Planned => "planned",
    Restored => "restored",
    Superseded => "superseded",
    Rejected => "rejected",
    MetadataOnly => "metadata-only",
    Archived => "archived"
});

struct RequiredFile {
    path: &'static str,
    blob_sha: &'static str,
    byte_size: u64,
    change: QuarantineChange,
    role: SourceRole,
    component_ids: &'static [&'static str],
}

const REQUIRED_FILES: &[RequiredFile] = &[
    RequiredFile {
        path: "crates/venom-scanner/src/adaptive/mod.rs",
        blob_sha: "98075bcbbd7ab1dd140b59d14277d1f8b1b8cf07",
        byte_size: 5_286,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::AdaptiveOrchestration,
        component_ids: &["adaptive.legacy-engine-orchestration"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/adaptive/payloads.rs",
        blob_sha: "75e5c863e53cf580ed6d3df2a3b86818ee7b8b41",
        byte_size: 17_516,
        change: QuarantineChange::Removed,
        role: SourceRole::AdaptivePayloadTransforms,
        component_ids: &[
            "adaptive.transformer-taxonomy",
            "adaptive.unbounded-transformer-trait",
            "adaptive.composite-chains",
            "adaptive.raw-transformers",
            "adaptive.payload-reduction",
            "adaptive.decoy-parameters",
            "adaptive.pattern-mutation-dispatch",
        ],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/adaptive/scoring.rs",
        blob_sha: "1e57275eafb0a5b7f4532273cddda2d190d71c5f",
        byte_size: 17_375,
        change: QuarantineChange::Removed,
        role: SourceRole::AdaptiveResponseScoring,
        component_ids: &[
            "adaptive.scoring-dimensions",
            "adaptive.uncalibrated-detection-score",
        ],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/adaptive/strategy.rs",
        blob_sha: "5f61539efe99b163e73b7b34f25a25655b4589a3",
        byte_size: 3_305,
        change: QuarantineChange::Removed,
        role: SourceRole::AdaptiveStrategySelection,
        component_ids: &[
            "adaptive.strategy-taxonomy",
            "adaptive.status-evasion-map",
            "adaptive.rate-limit-map",
            "adaptive.no-pattern-hpp-map",
        ],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/advanced_detection.rs",
        blob_sha: "f1e5cd86985462295148b8f060d3b07c1ebbf4ca",
        byte_size: 14_944,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::DefenseEvasionAnalysis,
        component_ids: &[
            "advanced.transform-taxonomy",
            "advanced.uncalibrated-bypass-ranking",
            "advanced.signature-evasion-selection",
        ],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/api.rs",
        blob_sha: "7e396bc2d5ffc7384c8e979b48b6cb60d4387bb9",
        byte_size: 10_733,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::ApiConfiguration,
        component_ids: &["api.dead-waf-adaptive-flags"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/config.rs",
        blob_sha: "b419bd6404415185592e7171769d07bdf1f17ecd",
        byte_size: 8_857,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::ScannerConfiguration,
        component_ids: &["config.dead-evasion-presets"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/config_loader.rs",
        blob_sha: "cebc6c466c84d72c1f0beeb0f0607486ee91c054",
        byte_size: 14_147,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::ConfigurationLoading,
        component_ids: &["config-loader.dead-waf-labels"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/lib.rs",
        blob_sha: "3c8b6ddf2ed34670fd8d8d07385e75e916482638",
        byte_size: 17_487,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::CrateApiSurface,
        component_ids: &["lib.legacy-waf-adaptive-exports"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/payload_strategies/encoding.rs",
        blob_sha: "c32c4752e7e2befac8ec0c8086be690476e42269",
        byte_size: 11_909,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::PayloadEncoding,
        component_ids: &[
            "relocated.neutral-percent-hex",
            "relocated.double-encoding",
            "relocated.evasion-dispatch",
            "relocated.artifact-envelope",
        ],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/payload_strategies/mod.rs",
        blob_sha: "43f2faff46737a9e3bd7223d4377d635f4e0e2a9",
        byte_size: 3_949,
        change: QuarantineChange::MateriallyNarrowed,
        role: SourceRole::PayloadStrategyExports,
        component_ids: &["payload-strategies.legacy-normalization-exports"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/payload_strategies/normalization.rs",
        blob_sha: "c94f06c536b1a2d9dd4bdb0d1e62bde887bd4e09",
        byte_size: 2_233,
        change: QuarantineChange::Removed,
        role: SourceRole::PayloadNormalization,
        component_ids: &["relocated.raw-normalization-helpers"],
    },
    RequiredFile {
        path: "crates/venom-scanner/src/waf.rs",
        blob_sha: "171a4c324069e5747c747fcdd82a107c1409bc73",
        byte_size: 8_777,
        change: QuarantineChange::Removed,
        role: SourceRole::WafFingerprintAndTransforms,
        component_ids: &[
            "waf.product-vocabulary",
            "waf.header-body-fingerprint",
            "waf.status-only-detection",
            "waf.case-variation",
            "waf.sql-comment-injection",
            "waf.whitespace-variation",
            "waf.url-percent-encoding",
            "waf.double-url-encoding",
            "waf.hex-encoding",
            "waf.parameter-pollution",
            "waf.http-splitting",
            "waf.generic-evasion-dispatch",
        ],
    },
];

type ComponentContract = (Disposition, Priority, ComponentStatus, ModernDestination);

fn required_component_contract(id: &str) -> Option<ComponentContract> {
    Some(match id {
        "adaptive.legacy-engine-orchestration" => (
            Disposition::SupersededByCurrentRuntime,
            Priority::P1,
            ComponentStatus::Superseded,
            ModernDestination::DefenseStateTransition,
        ),
        "adaptive.transformer-taxonomy" => (
            Disposition::ImportMetadataOnly,
            Priority::P1,
            ComponentStatus::MetadataOnly,
            ModernDestination::NormalizationResilience,
        ),
        "adaptive.unbounded-transformer-trait" | "adaptive.raw-transformers" => (
            Disposition::RewriteFromContract,
            Priority::P1,
            ComponentStatus::Planned,
            ModernDestination::NormalizationResilience,
        ),
        "adaptive.composite-chains" | "advanced.transform-taxonomy" => (
            Disposition::ImportMetadataOnly,
            Priority::P2,
            ComponentStatus::MetadataOnly,
            ModernDestination::NormalizationResilience,
        ),
        "adaptive.payload-reduction"
        | "adaptive.uncalibrated-detection-score"
        | "advanced.uncalibrated-bypass-ranking" => (
            Disposition::RejectMisleadingClaim,
            Priority::Never,
            ComponentStatus::Rejected,
            ModernDestination::None,
        ),
        "adaptive.decoy-parameters" => (
            Disposition::MoveToDifferentCapability,
            Priority::P2,
            ComponentStatus::Planned,
            ModernDestination::FutureTypedRequestShape,
        ),
        "adaptive.pattern-mutation-dispatch"
        | "adaptive.status-evasion-map"
        | "adaptive.no-pattern-hpp-map"
        | "advanced.signature-evasion-selection"
        | "relocated.evasion-dispatch"
        | "waf.generic-evasion-dispatch" => (
            Disposition::RejectBlindDispatcher,
            Priority::Never,
            ComponentStatus::Rejected,
            ModernDestination::None,
        ),
        "adaptive.scoring-dimensions" => (
            Disposition::ImportMetadataOnly,
            Priority::P1,
            ComponentStatus::MetadataOnly,
            ModernDestination::DefenseStateTransition,
        ),
        "adaptive.strategy-taxonomy" => (
            Disposition::ImportMetadataOnly,
            Priority::P1,
            ComponentStatus::MetadataOnly,
            ModernDestination::NormalizationResilience,
        ),
        "adaptive.rate-limit-map" => (
            Disposition::SupersededByCurrentRuntime,
            Priority::P1,
            ComponentStatus::Superseded,
            ModernDestination::DefenseStateTransition,
        ),
        "api.dead-waf-adaptive-flags"
        | "config.dead-evasion-presets"
        | "config-loader.dead-waf-labels"
        | "lib.legacy-waf-adaptive-exports"
        | "payload-strategies.legacy-normalization-exports" => (
            Disposition::ArchiveReference,
            Priority::P3,
            ComponentStatus::Archived,
            ModernDestination::DocumentationOnly,
        ),
        "relocated.neutral-percent-hex" | "waf.hex-encoding" | "waf.url-percent-encoding" => (
            Disposition::SupersededByCurrentRuntime,
            Priority::P1,
            ComponentStatus::Superseded,
            ModernDestination::PayloadStrategiesEncoding,
        ),
        "relocated.double-encoding" | "waf.double-url-encoding" => (
            Disposition::RewriteFromContract,
            Priority::P2,
            ComponentStatus::Planned,
            ModernDestination::NormalizationResilience,
        ),
        "relocated.artifact-envelope" => (
            Disposition::SupersededByCurrentRuntime,
            Priority::P0,
            ComponentStatus::Superseded,
            ModernDestination::PayloadArtifact,
        ),
        "relocated.raw-normalization-helpers" => (
            Disposition::RewriteFromContract,
            Priority::P0,
            ComponentStatus::Planned,
            ModernDestination::NormalizationResilience,
        ),
        "waf.case-variation" | "waf.whitespace-variation" => (
            Disposition::RewriteFromContract,
            Priority::P0,
            ComponentStatus::Restored,
            ModernDestination::NormalizationResilience,
        ),
        "waf.header-body-fingerprint" => (
            Disposition::SupersededByCurrentRuntime,
            Priority::P0,
            ComponentStatus::Superseded,
            ModernDestination::DefenseFingerprint,
        ),
        "waf.http-splitting" => (
            Disposition::RejectUnsafeTechnique,
            Priority::Never,
            ComponentStatus::Rejected,
            ModernDestination::FutureRequestFraming,
        ),
        "waf.parameter-pollution" => (
            Disposition::MoveToDifferentCapability,
            Priority::P1,
            ComponentStatus::Planned,
            ModernDestination::FutureTypedRequestShape,
        ),
        "waf.product-vocabulary" => (
            Disposition::SupersededByCurrentRuntime,
            Priority::P2,
            ComponentStatus::Superseded,
            ModernDestination::Defense,
        ),
        "waf.sql-comment-injection" => (
            Disposition::RewriteFromContract,
            Priority::P1,
            ComponentStatus::Planned,
            ModernDestination::PayloadCatalog,
        ),
        "waf.status-only-detection" => (
            Disposition::RejectMisleadingClaim,
            Priority::Never,
            ComponentStatus::Rejected,
            ModernDestination::DefenseStateTransition,
        ),
        _ => return None,
    })
}

fn parse_ledger(source: &[u8]) -> TaskResult<SalvageLedger> {
    let source =
        std::str::from_utf8(source).map_err(|_| "WAF/evasion salvage ledger is not valid UTF-8")?;
    toml::from_str(source).map_err(|error| {
        let location = error.span().map_or_else(
            || "unknown location".to_owned(),
            |span| format!("byte {}", span.start),
        );
        format!("invalid WAF/evasion salvage TOML at {location}").into()
    })
}

fn validate_ledger(ledger: &SalvageLedger) -> TaskResult {
    validate_header(ledger)?;
    validate_digest_wire(&ledger.ledger_digest)?;
    if ledger.files.len() != EXPECTED_FILE_COUNT {
        return Err(format!(
            "WAF/evasion salvage ledger has {} files; expected {EXPECTED_FILE_COUNT}",
            ledger.files.len()
        )
        .into());
    }

    let required = REQUIRED_FILES
        .iter()
        .map(|file| (file.path, file))
        .collect::<BTreeMap<_, _>>();
    let mut paths = BTreeSet::new();
    let mut component_ids = BTreeSet::new();
    let mut total_components = 0_usize;
    for file in &ledger.files {
        let Some(required_file) = required.get(file.path.as_str()) else {
            return Err(format!("extra WAF/evasion source path: {}", file.path).into());
        };
        validate_file(file, required_file)?;
        if !paths.insert(file.path.as_str()) {
            return Err(format!("duplicate WAF/evasion source path: {}", file.path).into());
        }
        total_components = total_components
            .checked_add(file.components.len())
            .ok_or("WAF/evasion component count overflow")?;
        for component in &file.components {
            if !component_ids.insert(component.id.as_str()) {
                return Err(format!("duplicate WAF/evasion component ID: {}", component.id).into());
            }
        }
    }
    if paths.len() != REQUIRED_FILES.len() {
        return Err("WAF/evasion salvage ledger is missing a required source path".into());
    }
    if total_components != EXPECTED_COMPONENT_COUNT {
        return Err(format!(
            "WAF/evasion salvage ledger has {total_components} components; expected {EXPECTED_COMPONENT_COUNT}"
        )
        .into());
    }
    Ok(())
}

fn validate_header(ledger: &SalvageLedger) -> TaskResult {
    let exact = [
        ("schema", ledger.schema.as_str(), SCHEMA),
        ("source_epoch", ledger.source_epoch.as_str(), SOURCE_EPOCH),
        (
            "source_snapshot_commit",
            ledger.source_snapshot_commit.as_str(),
            SOURCE_SNAPSHOT,
        ),
        (
            "quarantine_commit",
            ledger.quarantine_commit.as_str(),
            QUARANTINE_COMMIT,
        ),
        (
            "algorithm_version",
            ledger.algorithm_version.as_str(),
            DIGEST_ALGORITHM,
        ),
        (
            "current_replacement_baseline_sha",
            ledger.current_replacement_baseline_sha.as_str(),
            REPLACEMENT_BASELINE,
        ),
        (
            "prior_salvage_ledger",
            ledger.prior_salvage_ledger.as_str(),
            PRIOR_LEDGER_RELATIVE_PATH,
        ),
        (
            "prior_salvage_digest",
            ledger.prior_salvage_digest.as_str(),
            PRIOR_LEDGER_DIGEST,
        ),
    ];
    for (field, actual, expected) in exact {
        if actual != expected {
            return Err(format!("invalid {field}; expected {expected}").into());
        }
    }
    if ledger.expected_scoped_file_count != EXPECTED_FILE_COUNT {
        return Err(format!("expected_scoped_file_count must be {EXPECTED_FILE_COUNT}").into());
    }
    if !ledger.separate_source_epoch {
        return Err("separate_source_epoch must be true".into());
    }
    let mut scoped = BTreeSet::new();
    for path in &ledger.scoped_source_paths {
        validate_repository_path(path)?;
        if !scoped.insert(path.as_str()) {
            return Err(format!("duplicate scoped source path: {path}").into());
        }
    }
    let expected = REQUIRED_FILES
        .iter()
        .map(|file| file.path)
        .collect::<BTreeSet<_>>();
    if scoped != expected {
        return Err(
            "scoped_source_paths must equal the exact 13-file WAF/evasion inventory".into(),
        );
    }
    Ok(())
}

fn validate_file(file: &HistoricalFile, required: &RequiredFile) -> TaskResult {
    validate_repository_path(&file.path)?;
    validate_commit_id("blob_sha", &file.blob_sha)?;
    if file.blob_sha != required.blob_sha
        || file.byte_size != required.byte_size
        || file.quarantine_change != required.change
        || file.source_role != required.role
    {
        return Err(format!(
            "historical identity or classification mismatch for {}",
            file.path
        )
        .into());
    }
    validate_fact("notes", &file.notes, MAX_NOTES_BYTES)?;
    validate_unique_paths(
        "file current_replacement_paths",
        &file.current_replacement_paths,
    )?;
    if file.components.is_empty() || file.components.len() > MAX_COMPONENTS_PER_FILE {
        return Err(format!(
            "{} must contain 1..={MAX_COMPONENTS_PER_FILE} component records",
            file.path
        )
        .into());
    }
    let expected = required
        .component_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for component in &file.components {
        validate_component(component, &file.path)?;
        let expected_contract = required_component_contract(&component.id)
            .ok_or_else(|| format!("unrecognized required component ID: {}", component.id))?;
        let actual_contract = (
            component.disposition,
            component.priority,
            component.status,
            component.modern_destination,
        );
        if actual_contract != expected_contract {
            return Err(format!(
                "required classification contract changed for {}",
                component.id
            )
            .into());
        }
        if !actual.insert(component.id.as_str()) {
            return Err(
                format!("duplicate component ID in {}: {}", file.path, component.id).into(),
            );
        }
    }
    if actual != expected {
        return Err(format!("component inventory mismatch for {}", file.path).into());
    }
    Ok(())
}

fn validate_component(component: &HistoricalComponent, path: &str) -> TaskResult {
    validate_component_id(&component.id)?;
    validate_fact("source_symbol", &component.source_symbol, MAX_SYMBOL_BYTES)?;
    validate_fact(
        "historical_behavior",
        &component.historical_behavior,
        MAX_FACT_BYTES,
    )?;
    validate_fact("reusable_value", &component.reusable_value, MAX_FACT_BYTES)?;
    validate_fact("rationale", &component.rationale, MAX_FACT_BYTES)?;
    validate_unique_bounded_facts("prerequisites", &component.prerequisites)?;
    validate_unique_prohibitions(&component.prohibited_restoration_behaviors)?;
    validate_unique_paths(
        "component current_replacement_paths",
        &component.current_replacement_paths,
    )?;

    let is_reject = matches!(
        component.disposition,
        Disposition::RejectBlindDispatcher
            | Disposition::RejectMisleadingClaim
            | Disposition::RejectUnsafeTechnique
    );
    match component.status {
        ComponentStatus::Rejected => {
            if !is_reject
                || component.priority != Priority::Never
                || component.prohibited_restoration_behaviors.is_empty()
                || !component.current_replacement_paths.is_empty()
            {
                return Err(format!(
                    "rejected component {} in {path} has contradictory authority",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Superseded => {
            if component.disposition != Disposition::SupersededByCurrentRuntime
                || component.priority == Priority::Never
                || component.current_replacement_paths.is_empty()
            {
                return Err(format!(
                    "superseded component {} in {path} needs a current replacement",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Restored => {
            if is_reject
                || matches!(
                    component.disposition,
                    Disposition::SupersededByCurrentRuntime
                        | Disposition::ImportMetadataOnly
                        | Disposition::ArchiveReference
                )
                || component.priority == Priority::Never
                || component.current_replacement_paths.is_empty()
            {
                return Err(format!(
                    "restored component {} in {path} needs actionable identity and a current replacement",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::MetadataOnly => {
            if component.disposition != Disposition::ImportMetadataOnly
                || component.priority == Priority::Never
                || !component.current_replacement_paths.is_empty()
            {
                return Err(format!(
                    "metadata-only component {} in {path} has contradictory status",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Archived => {
            if component.disposition != Disposition::ArchiveReference
                || component.priority == Priority::Never
                || !component.current_replacement_paths.is_empty()
            {
                return Err(format!(
                    "archived component {} in {path} has contradictory status",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Planned => {
            if is_reject
                || matches!(
                    component.disposition,
                    Disposition::SupersededByCurrentRuntime
                        | Disposition::ImportMetadataOnly
                        | Disposition::ArchiveReference
                )
                || component.priority == Priority::Never
                || !component.current_replacement_paths.is_empty()
            {
                return Err(format!(
                    "planned component {} in {path} has a terminal or implemented classification",
                    component.id
                )
                .into());
            }
        },
    }
    if is_reject && component.status != ComponentStatus::Rejected {
        return Err(format!("reject disposition for {} must be rejected", component.id).into());
    }
    if component.modern_destination == ModernDestination::None
        && !matches!(
            component.status,
            ComponentStatus::Rejected | ComponentStatus::Archived
        )
    {
        return Err(format!(
            "active component {} requires a modern destination",
            component.id
        )
        .into());
    }
    Ok(())
}

fn validate_component_id(value: &str) -> TaskResult {
    let valid = !value.is_empty()
        && value.len() <= MAX_COMPONENT_ID_BYTES
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'-' | b'_' | b':')
        });
    if valid {
        Ok(())
    } else {
        Err("invalid WAF/evasion component ID".into())
    }
}

fn validate_fact(field: &str, value: &str, maximum: usize) -> TaskResult {
    let valid = !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= maximum
        && !value.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(format!("invalid bounded {field}").into())
    }
}

fn validate_unique_bounded_facts(field: &str, values: &[String]) -> TaskResult {
    if values.len() > MAX_SET_ENTRIES {
        return Err(format!("{field} exceeds {MAX_SET_ENTRIES} entries").into());
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_fact(field, value, MAX_FACT_BYTES)?;
        if !unique.insert(value.as_str()) {
            return Err(format!("duplicate value in {field}").into());
        }
    }
    Ok(())
}

fn validate_unique_prohibitions(values: &[ProhibitedRestorationBehavior]) -> TaskResult {
    if values.len() > MAX_SET_ENTRIES {
        return Err(format!("prohibited behaviors exceed {MAX_SET_ENTRIES} entries").into());
    }
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(*value) {
            return Err("duplicate prohibited restoration behavior".into());
        }
    }
    Ok(())
}

fn validate_unique_paths(field: &str, values: &[String]) -> TaskResult {
    if values.len() > MAX_SET_ENTRIES {
        return Err(format!("{field} exceeds {MAX_SET_ENTRIES} entries").into());
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_repository_path(value)?;
        if !unique.insert(value.as_str()) {
            return Err(format!("duplicate value in {field}").into());
        }
    }
    Ok(())
}

fn validate_repository_path(value: &str) -> TaskResult {
    let valid = !value.is_empty()
        && value.len() <= MAX_PATH_BYTES
        && !value.starts_with('/')
        && !value.contains(['\\', ':'])
        && value.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        });
    if valid {
        Ok(())
    } else {
        Err(format!("invalid repository-relative path: {value:?}").into())
    }
}

fn validate_commit_id(field: &str, value: &str) -> TaskResult {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{field} must be a lowercase 40-hex Git object ID").into())
    }
}

fn validate_digest_wire(value: &str) -> TaskResult {
    let Some(hex) = value.strip_prefix(&format!("{DIGEST_PREFIX}:")) else {
        return Err("ledger_digest has an invalid prefix".into());
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("ledger_digest must contain 64 lowercase hexadecimal digits".into())
    }
}

fn validate_current_replacement_paths(workspace_root: &Path, ledger: &SalvageLedger) -> TaskResult {
    for (owner, path) in ledger.files.iter().flat_map(|file| {
        std::iter::repeat(file.path.as_str())
            .zip(file.current_replacement_paths.iter().map(String::as_str))
            .chain(file.components.iter().flat_map(|component| {
                std::iter::repeat(component.id.as_str()).zip(
                    component
                        .current_replacement_paths
                        .iter()
                        .map(String::as_str),
                )
            }))
    }) {
        let absolute = current_replacement_path(workspace_root, path);
        let metadata = fs::symlink_metadata(&absolute).map_err(|error| {
            format!("current replacement path for {owner} is missing ({path}): {error}")
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "current replacement path for {owner} is not a regular file: {path}"
            )
            .into());
        }
    }
    Ok(())
}

/// Resolves only the live filesystem side of the controlled product rename.
///
/// The ledger's `crates/venom-scanner/...` strings are immutable historical
/// compatibility data and remain bound into its semantic digest and generated
/// report. They now point at the same implementation under the renamed current
/// crate directory; historical Git tree validation continues to use the
/// original paths without this adapter.
fn current_replacement_path(workspace_root: &Path, ledger_path: &str) -> PathBuf {
    const FORMER_CURRENT_PREFIX: &str = "crates/venom-scanner/";
    const CURRENT_PREFIX: &str = "crates/termivar-scanner/";

    match ledger_path.strip_prefix(FORMER_CURRENT_PREFIX) {
        Some(suffix) => workspace_root.join(format!("{CURRENT_PREFIX}{suffix}")),
        None => workspace_root.join(ledger_path),
    }
}

fn validate_prior_ledger(workspace_root: &Path, ledger: &SalvageLedger) -> TaskResult {
    let digest = scanner_salvage::validate_repository_contract_without_history(workspace_root)?;
    if digest != ledger.prior_salvage_digest || digest != PRIOR_LEDGER_DIGEST {
        return Err("prior historical scanner ledger digest changed".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GitBlob {
    sha: String,
    byte_size: u64,
}

fn validate_history(workspace_root: &Path, ledger: &SalvageLedger) -> TaskResult {
    for commit in [
        &ledger.source_snapshot_commit,
        &ledger.quarantine_commit,
        &ledger.current_replacement_baseline_sha,
    ] {
        git_success(
            workspace_root,
            &["cat-file", "-e", &format!("{commit}^{{commit}}")],
        )?;
    }
    let quarantine_parent = git_text(
        workspace_root,
        &["rev-parse", &format!("{}^", ledger.quarantine_commit)],
    )?;
    validate_parent_relationship(&ledger.source_snapshot_commit, &quarantine_parent)?;
    let source_tree = scoped_tree(workspace_root, &ledger.source_snapshot_commit)?;
    let quarantine_tree = scoped_tree(workspace_root, &ledger.quarantine_commit)?;
    validate_history_trees(&source_tree, &quarantine_tree, ledger)
}

fn validate_parent_relationship(expected_parent: &str, actual_parent: &str) -> TaskResult {
    if actual_parent == expected_parent {
        Ok(())
    } else {
        Err("quarantine commit parent is not the recorded source snapshot".into())
    }
}

fn validate_history_trees(
    source_tree: &BTreeMap<String, GitBlob>,
    quarantine_tree: &BTreeMap<String, GitBlob>,
    ledger: &SalvageLedger,
) -> TaskResult {
    if source_tree.len() != EXPECTED_FILE_COUNT {
        return Err(format!(
            "source snapshot contains {} scoped files; expected {EXPECTED_FILE_COUNT}",
            source_tree.len()
        )
        .into());
    }
    let narrowed_count = REQUIRED_FILES
        .iter()
        .filter(|file| file.change == QuarantineChange::MateriallyNarrowed)
        .count();
    if quarantine_tree.len() != narrowed_count {
        return Err(format!(
            "quarantine tree contains {} scoped files; expected {narrowed_count}",
            quarantine_tree.len()
        )
        .into());
    }
    let recorded = ledger
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for required in REQUIRED_FILES {
        let source = source_tree
            .get(required.path)
            .ok_or_else(|| format!("source snapshot is missing {}", required.path))?;
        let file = recorded
            .get(required.path)
            .ok_or_else(|| format!("ledger is missing {}", required.path))?;
        if source.sha != required.blob_sha
            || source.byte_size != required.byte_size
            || file.blob_sha != source.sha
            || file.byte_size != source.byte_size
        {
            return Err(format!("source blob identity mismatch for {}", required.path).into());
        }
        match required.change {
            QuarantineChange::Removed => {
                if quarantine_tree.contains_key(required.path) {
                    return Err(format!(
                        "{} was recorded as removed but survives quarantine",
                        required.path
                    )
                    .into());
                }
            },
            QuarantineChange::MateriallyNarrowed => {
                let narrowed = quarantine_tree.get(required.path).ok_or_else(|| {
                    format!("{} was recorded as narrowed but is absent", required.path)
                })?;
                if narrowed.sha == source.sha {
                    return Err(format!(
                        "{} was recorded as narrowed but its Git blob is unchanged",
                        required.path
                    )
                    .into());
                }
            },
        }
    }
    Ok(())
}

fn scoped_tree(workspace_root: &Path, commit: &str) -> TaskResult<BTreeMap<String, GitBlob>> {
    let mut command = Command::new("git");
    command
        .args(["ls-tree", "-r", "-l", "--full-tree", commit, "--"])
        .args(REQUIRED_FILES.iter().map(|file| file.path))
        .current_dir(workspace_root);
    let output = command.output()?;
    if !output.status.success() {
        return Err("local Git scoped-tree query failed".into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "Git output is not valid UTF-8")?;
    parse_ls_tree(&text)
}

fn parse_ls_tree(output: &str) -> TaskResult<BTreeMap<String, GitBlob>> {
    let mut tree = BTreeMap::new();
    for line in output.lines() {
        let (metadata, path) = line
            .split_once('\t')
            .ok_or("malformed git ls-tree output")?;
        let fields = metadata.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[1] != "blob" || fields[0] != "100644" {
            return Err("WAF/evasion history contains an unsupported Git entry".into());
        }
        validate_commit_id("historical blob SHA", fields[2])?;
        let byte_size = fields[3]
            .parse::<u64>()
            .map_err(|_| "malformed historical Git blob size")?;
        if tree
            .insert(
                path.to_owned(),
                GitBlob {
                    sha: fields[2].to_owned(),
                    byte_size,
                },
            )
            .is_some()
        {
            return Err("duplicate path in historical Git tree".into());
        }
    }
    Ok(tree)
}

fn git_success(workspace_root: &Path, args: &[&str]) -> TaskResult {
    let status = Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("local Git history validation failed for {}", args[0]).into())
    }
}

fn git_text(workspace_root: &Path, args: &[&str]) -> TaskResult<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()?;
    if !output.status.success() {
        return Err(format!("local Git history query failed for {}", args[0]).into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "Git output is not valid UTF-8")?;
    Ok(text.trim().to_owned())
}

fn semantic_digest(ledger: &SalvageLedger) -> String {
    let mut writer = DigestWriter::new(DIGEST_ALGORITHM);
    writer.field("schema", &ledger.schema);
    writer.field("source_epoch", &ledger.source_epoch);
    writer.field("source_snapshot_commit", &ledger.source_snapshot_commit);
    writer.field("quarantine_commit", &ledger.quarantine_commit);
    let mut scoped = ledger.scoped_source_paths.iter().collect::<Vec<_>>();
    scoped.sort_unstable();
    writer.number("scoped_source_path.count", scoped.len() as u64);
    for path in scoped {
        writer.field("scoped_source_path", path);
    }
    writer.number(
        "expected_scoped_file_count",
        ledger.expected_scoped_file_count as u64,
    );
    writer.field("algorithm_version", &ledger.algorithm_version);
    writer.field(
        "current_replacement_baseline_sha",
        &ledger.current_replacement_baseline_sha,
    );
    writer.field("prior_salvage_ledger", &ledger.prior_salvage_ledger);
    writer.field("prior_salvage_digest", &ledger.prior_salvage_digest);
    writer.field(
        "separate_source_epoch",
        if ledger.separate_source_epoch {
            "true"
        } else {
            "false"
        },
    );

    let mut files = ledger.files.iter().collect::<Vec<_>>();
    files.sort_by_key(|file| &file.path);
    writer.number("file.count", files.len() as u64);
    for file in files {
        writer.field("file.path", &file.path);
        writer.field("file.blob_sha", &file.blob_sha);
        writer.number("file.byte_size", file.byte_size);
        writer.field("file.source_role", file.source_role.wire());
        writer.field("file.quarantine_change", file.quarantine_change.wire());
        writer.field(
            "file.historical_build_reachability",
            file.historical_build_reachability.wire(),
        );
        writer.field(
            "file.historical_runtime_reachability",
            file.historical_runtime_reachability.wire(),
        );
        writer.field(
            "file.direct_network_authority",
            file.direct_network_authority.wire(),
        );
        writer.field(
            "file.request_shape_authority",
            file.request_shape_authority.wire(),
        );
        writer.field(
            "file.process_filesystem_authority",
            file.process_filesystem_authority.wire(),
        );
        writer.field("file.unsafe_code", file.unsafe_code.wire());
        writer.field("file.identity_behavior", file.identity_behavior.wire());
        writer.field("file.evidence_quality", file.evidence_quality.wire());
        writer.field("file.claim_risk", file.claim_risk.wire());
        digest_sorted_strings(
            &mut writer,
            "file.current_replacement_path",
            &file.current_replacement_paths,
        );
        writer.field("file.salvage_priority", file.salvage_priority.wire());
        writer.field("file.notes", &file.notes);

        let mut components = file.components.iter().collect::<Vec<_>>();
        components.sort_by_key(|component| &component.id);
        writer.number("file.component.count", components.len() as u64);
        for component in components {
            writer.field("component.id", &component.id);
            writer.field("component.source_symbol", &component.source_symbol);
            writer.field("component.disposition", component.disposition.wire());
            writer.field("component.priority", component.priority.wire());
            writer.field(
                "component.historical_behavior",
                &component.historical_behavior,
            );
            writer.field(
                "component.old_runtime_reachability",
                component.old_runtime_reachability.wire(),
            );
            writer.field("component.reusable_value", &component.reusable_value);
            let mut prohibited = component.prohibited_restoration_behaviors.clone();
            prohibited.sort_unstable();
            writer.number("component.prohibited.count", prohibited.len() as u64);
            for behavior in prohibited {
                writer.field("component.prohibited", behavior.wire());
            }
            writer.field(
                "component.modern_destination",
                component.modern_destination.wire(),
            );
            digest_sorted_strings(
                &mut writer,
                "component.current_replacement_path",
                &component.current_replacement_paths,
            );
            digest_sorted_strings(
                &mut writer,
                "component.prerequisite",
                &component.prerequisites,
            );
            writer.field("component.status", component.status.wire());
            writer.field("component.rationale", &component.rationale);
        }
    }
    writer.finish(DIGEST_PREFIX)
}

fn digest_sorted_strings(writer: &mut DigestWriter, name: &str, values: &[String]) {
    let mut values = values.iter().collect::<Vec<_>>();
    values.sort_unstable();
    writer.number(&format!("{name}.count"), values.len() as u64);
    for value in values {
        writer.field(name, value);
    }
}

struct DigestWriter(Sha256);

impl DigestWriter {
    fn new(domain: &str) -> Self {
        let mut writer = Self(Sha256::new());
        writer.field("domain", domain);
        writer
    }

    fn field(&mut self, name: &str, value: &str) {
        self.0.update((name.len() as u64).to_be_bytes());
        self.0.update(name.as_bytes());
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value.as_bytes());
    }

    fn number(&mut self, name: &str, value: u64) {
        self.field(name, &value.to_string());
    }

    fn finish(self, prefix: &str) -> String {
        format!("{prefix}:{:x}", self.0.finalize())
    }
}

#[derive(Debug)]
struct Summary {
    component_count: usize,
    high_priority_count: usize,
    dispositions: BTreeMap<&'static str, usize>,
}

impl Summary {
    fn from_ledger(ledger: &SalvageLedger) -> Self {
        let mut component_count = 0_usize;
        let mut high_priority_count = 0_usize;
        let mut dispositions = BTreeMap::new();
        for component in ledger.files.iter().flat_map(|file| &file.components) {
            component_count += 1;
            if matches!(
                component.status,
                ComponentStatus::Planned
                    | ComponentStatus::MetadataOnly
                    | ComponentStatus::Restored
            ) && matches!(component.priority, Priority::P0 | Priority::P1)
            {
                high_priority_count += 1;
            }
            *dispositions
                .entry(component.disposition.wire())
                .or_insert(0) += 1;
        }
        Self {
            component_count,
            high_priority_count,
            dispositions,
        }
    }
}

fn render_markdown(ledger: &SalvageLedger) -> String {
    let summary = Summary::from_ledger(ledger);
    let mut output = String::new();
    output.push_str("# Post-workspace WAF/evasion salvage ledger\n\n");
    output.push_str("This report is generated from the authoritative TOML ledger. Historical WAF/evasion source is recovery evidence, not current product authority. This is a separate source epoch from the pre-workspace 38-file scanner inventory.\n\n");
    output.push_str("## Timeline and identity\n\n");
    output.push_str("| Event | Git identity |\n| --- | --- |\n");
    markdown_row(
        &mut output,
        &["Historical source snapshot", &ledger.source_snapshot_commit],
    );
    markdown_row(
        &mut output,
        &["Quarantine/removal", &ledger.quarantine_commit],
    );
    markdown_row(
        &mut output,
        &[
            "Current replacement baseline",
            &ledger.current_replacement_baseline_sha,
        ],
    );
    markdown_row(
        &mut output,
        &["Semantic ledger digest", &ledger.ledger_digest],
    );
    markdown_row(
        &mut output,
        &["Prior source-epoch digest", &ledger.prior_salvage_digest],
    );

    output.push_str("\n## Classification summary\n\n");
    output.push_str(&format!(
        "- Historical files: {}\n- Classified components: {}\n- P0/P1 recovery candidates: {}\n\n",
        ledger.files.len(),
        summary.component_count,
        summary.high_priority_count
    ));
    output.push_str("| Disposition | Components |\n| --- | ---: |\n");
    for (disposition, count) in &summary.dispositions {
        markdown_row(&mut output, &[disposition, &count.to_string()]);
    }

    output.push_str("\n## Historical file inventory\n\n");
    output.push_str("| Path | Blob | Bytes | Quarantine | Role | Replacement |\n| --- | --- | ---: | --- | --- | --- |\n");
    let mut files = ledger.files.iter().collect::<Vec<_>>();
    files.sort_by_key(|file| &file.path);
    for file in &files {
        let replacements = if file.current_replacement_paths.is_empty() {
            "—".to_owned()
        } else {
            file.current_replacement_paths.join(", ")
        };
        markdown_row(
            &mut output,
            &[
                &file.path,
                &file.blob_sha,
                &file.byte_size.to_string(),
                file.quarantine_change.wire(),
                file.source_role.wire(),
                &replacements,
            ],
        );
    }

    output.push_str("\n## Component classifications\n\n");
    output.push_str("| Component | Source | Disposition | Priority | Status | Destination | Current replacement | Prohibited restoration | Rationale |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for file in &files {
        let mut components = file.components.iter().collect::<Vec<_>>();
        components.sort_by_key(|component| &component.id);
        for component in components {
            let replacements = if component.current_replacement_paths.is_empty() {
                "—".to_owned()
            } else {
                component.current_replacement_paths.join(", ")
            };
            let prohibited = if component.prohibited_restoration_behaviors.is_empty() {
                "—".to_owned()
            } else {
                component
                    .prohibited_restoration_behaviors
                    .iter()
                    .map(|behavior| behavior.wire())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            markdown_row(
                &mut output,
                &[
                    &component.id,
                    &file.path,
                    component.disposition.wire(),
                    component.priority.wire(),
                    component.status.wire(),
                    component.modern_destination.wire(),
                    &replacements,
                    &prohibited,
                    &component.rationale,
                ],
            );
        }
    }

    output.push_str("\n## Current replacement map\n\n");
    output.push_str("- Historical WAF fingerprinting maps to defense::fingerprint.\n");
    output.push_str(
        "- Historical status/body observation maps to DefenseState and DefenseTransition.\n",
    );
    output.push_str(
        "- Historical neutral percent/hex encoding maps to payload_strategies::encoding.\n",
    );
    output.push_str("- Historical blind adaptive selection remains rejected; an evidence-driven selector belongs to a separately reviewed capability.\n");
    output.push_str("- Historical generic evasion output maps to the PayloadArtifact boundary, not to raw report evidence.\n");
    output.push_str(
        "- Historical response comparison maps to committed control/candidate/replay evidence.\n\n",
    );
    output.push_str("WAF fingerprinting was not lost; it was replaced more safely. Blind evasion selection was removed. Several useful transformation concepts remain recoverable. HTTP splitting does not belong in a low-risk normalization domain. PR B restores only a bounded, semantically verified first subset.\n");
    output
}

fn markdown_row(output: &mut String, values: &[&str]) {
    output.push('|');
    for value in values {
        output.push(' ');
        output.push_str(&escape_markdown(value));
        output.push_str(" |");
    }
    output.push('\n');
}

fn escape_markdown(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

fn normalize_line_endings(value: &str) -> String {
    value.replace("\r\n", "\n")
}

fn validate_rendered_report(actual: &str, expected: &str) -> TaskResult {
    if normalize_line_endings(actual) != expected {
        return Err("generated WAF/evasion salvage report is stale; run cargo run --locked -p xtask -- waf-evasion-salvage --write".into());
    }
    Ok(())
}

fn rewrite_digest(path: &Path, source: &[u8], digest: &str) -> TaskResult {
    let source =
        std::str::from_utf8(source).map_err(|_| "WAF/evasion salvage ledger is not valid UTF-8")?;
    let mut replacements = 0_usize;
    let mut rewritten = String::with_capacity(source.len());
    for line in source.split_inclusive('\n') {
        if line.trim_start().starts_with("ledger_digest =") {
            let newline = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
            rewritten.push_str(&format!("ledger_digest = \"{digest}\"{newline}"));
            replacements += 1;
        } else {
            rewritten.push_str(line);
        }
    }
    if replacements != 1 {
        return Err("WAF/evasion ledger must contain exactly one ledger_digest assignment".into());
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> TaskResult<Vec<u8>> {
    let limit = u64::try_from(maximum)?
        .checked_add(1)
        .ok_or("WAF/evasion salvage read limit overflow")?;
    let mut source = Vec::with_capacity(maximum.min(32 * 1024));
    File::open(path)?.take(limit).read_to_end(&mut source)?;
    if source.len() > maximum {
        Err(format!("WAF/evasion salvage source exceeds {maximum} bytes").into())
    } else {
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_component(id: &str) -> HistoricalComponent {
        let (disposition, priority, status, modern_destination) =
            required_component_contract(id).expect("required component contract");
        let prohibited_restoration_behaviors = if status == ComponentStatus::Rejected {
            vec![ProhibitedRestorationBehavior::BlindDispatch]
        } else {
            Vec::new()
        };
        let current_replacement_paths = match status {
            ComponentStatus::Superseded => {
                vec!["crates/venom-scanner/src/defense/state.rs".to_owned()]
            },
            ComponentStatus::Restored => vec![
                "crates/venom-scanner/src/web_runtime/web_assessment/normalization_transform_catalog.rs"
                    .to_owned(),
            ],
            ComponentStatus::Planned
            | ComponentStatus::MetadataOnly
            | ComponentStatus::Rejected
            | ComponentStatus::Archived => Vec::new(),
        };
        HistoricalComponent {
            id: id.to_owned(),
            source_symbol: "historical symbol or region".to_owned(),
            disposition,
            priority,
            historical_behavior: "Historical behavior classified from the pinned source blob."
                .to_owned(),
            old_runtime_reachability: RuntimeReachability::LibraryOnly,
            reusable_value: "Bounded vocabulary that requires a new typed contract.".to_owned(),
            prohibited_restoration_behaviors,
            modern_destination,
            current_replacement_paths,
            prerequisites: vec!["fresh typed contract review".to_owned()],
            status,
            rationale: "Retain the concept without restoring the historical dispatcher.".to_owned(),
        }
    }

    fn ledger() -> SalvageLedger {
        let files = REQUIRED_FILES
            .iter()
            .map(|required| HistoricalFile {
                path: required.path.to_owned(),
                blob_sha: required.blob_sha.to_owned(),
                byte_size: required.byte_size,
                source_role: required.role,
                quarantine_change: required.change,
                historical_build_reachability: BuildReachability::Built,
                historical_runtime_reachability: RuntimeReachability::LibraryOnly,
                direct_network_authority: AuthorityUse::None,
                request_shape_authority: RequestShapeAuthority::None,
                process_filesystem_authority: AuthorityUse::None,
                unsafe_code: UnsafeCodeStatus::Absent,
                identity_behavior: IdentityBehavior::Deterministic,
                evidence_quality: EvidenceQuality::Heuristic,
                claim_risk: ClaimRisk::High,
                current_replacement_paths: Vec::new(),
                salvage_priority: Priority::P2,
                notes: "Historical production source classified at component granularity."
                    .to_owned(),
                components: required
                    .component_ids
                    .iter()
                    .map(|id| fixture_component(id))
                    .collect(),
            })
            .collect();
        SalvageLedger {
            schema: SCHEMA.to_owned(),
            source_epoch: SOURCE_EPOCH.to_owned(),
            source_snapshot_commit: SOURCE_SNAPSHOT.to_owned(),
            quarantine_commit: QUARANTINE_COMMIT.to_owned(),
            scoped_source_paths: REQUIRED_FILES
                .iter()
                .map(|file| file.path.to_owned())
                .collect(),
            expected_scoped_file_count: EXPECTED_FILE_COUNT,
            algorithm_version: DIGEST_ALGORITHM.to_owned(),
            ledger_digest: format!("{DIGEST_PREFIX}:{}", "0".repeat(64)),
            current_replacement_baseline_sha: REPLACEMENT_BASELINE.to_owned(),
            prior_salvage_ledger: PRIOR_LEDGER_RELATIVE_PATH.to_owned(),
            prior_salvage_digest: PRIOR_LEDGER_DIGEST.to_owned(),
            separate_source_epoch: true,
            files,
        }
    }

    fn history_trees() -> (BTreeMap<String, GitBlob>, BTreeMap<String, GitBlob>) {
        let source = REQUIRED_FILES
            .iter()
            .map(|required| {
                (
                    required.path.to_owned(),
                    GitBlob {
                        sha: required.blob_sha.to_owned(),
                        byte_size: required.byte_size,
                    },
                )
            })
            .collect();
        let quarantine = REQUIRED_FILES
            .iter()
            .filter(|required| required.change == QuarantineChange::MateriallyNarrowed)
            .map(|required| {
                (
                    required.path.to_owned(),
                    GitBlob {
                        sha: "f".repeat(40),
                        byte_size: required.byte_size.saturating_add(1),
                    },
                )
            })
            .collect();
        (source, quarantine)
    }

    #[test]
    fn strict_toml_rejects_unknown_duplicate_and_invalid_enum_fields() {
        let source = toml::to_string(&ledger()).expect("serialize fixture");
        let unknown = format!("unknown = true\n{source}");
        assert!(parse_ledger(unknown.as_bytes()).is_err());
        let nested_unknown = source.replacen(
            "source_symbol = \"historical symbol or region\"",
            "source_symbol = \"historical symbol or region\"\nunknown_component_field = true",
            1,
        );
        assert!(parse_ledger(nested_unknown.as_bytes()).is_err());
        let duplicate = source.replacen(
            &format!("schema = \"{SCHEMA}\""),
            &format!("schema = \"{SCHEMA}\"\nschema = \"{SCHEMA}\""),
            1,
        );
        assert!(parse_ledger(duplicate.as_bytes()).is_err());
        let invalid_disposition = source.replacen(
            "disposition = \"rewrite-from-contract\"",
            "disposition = \"unknown\"",
            1,
        );
        assert!(parse_ledger(invalid_disposition.as_bytes()).is_err());
        let invalid_priority = source.replacen("priority = \"p2\"", "priority = \"urgent\"", 1);
        assert!(parse_ledger(invalid_priority.as_bytes()).is_err());
        let invalid_destination = source.replacen(
            "modern_destination = \"venom-scanner:defense-state-transition\"",
            "modern_destination = \"venom-scanner:unknown\"",
            1,
        );
        assert!(parse_ledger(invalid_destination.as_bytes()).is_err());
    }

    #[test]
    fn header_schema_epoch_commits_count_and_prior_digest_are_exact() {
        let mut fixture = ledger();
        assert!(validate_header(&fixture).is_ok());
        fixture.schema = "venom.post-workspace-waf-evasion-salvage/v2".to_owned();
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.source_epoch = "ambiguous-epoch".to_owned();
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.source_snapshot_commit = "f".repeat(40);
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.quarantine_commit = "f".repeat(40);
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.expected_scoped_file_count -= 1;
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.prior_salvage_digest = format!("salvage-sha256:{}", "f".repeat(64));
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.separate_source_epoch = false;
        assert!(validate_header(&fixture).is_err());
    }

    #[test]
    fn scoped_path_header_rejects_missing_extra_duplicate_and_unsafe_paths() {
        let mut fixture = ledger();
        fixture.scoped_source_paths.pop();
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture
            .scoped_source_paths
            .push("crates/venom-scanner/src/extra.rs".to_owned());
        assert!(validate_header(&fixture).is_err());
        fixture = ledger();
        fixture.scoped_source_paths[1] = fixture.scoped_source_paths[0].clone();
        assert!(validate_header(&fixture).is_err());
        assert!(validate_repository_path("../outside.rs").is_err());
        assert!(validate_repository_path("C:/outside.rs").is_err());
        assert!(validate_repository_path("crates/valid-file.rs").is_ok());
    }

    #[test]
    fn commit_and_digest_wire_formats_are_lowercase_and_exact() {
        assert!(validate_commit_id("commit", SOURCE_SNAPSHOT).is_ok());
        assert!(validate_commit_id("commit", "xyz").is_err());
        assert!(validate_commit_id("commit", &"A".repeat(40)).is_err());
        assert!(validate_digest_wire(&format!("{DIGEST_PREFIX}:{}", "a".repeat(64))).is_ok());
        assert!(validate_digest_wire("salvage-sha256:bad").is_err());
        assert!(validate_digest_wire(&format!("{DIGEST_PREFIX}:{}", "A".repeat(64))).is_err());
        assert!(validate_parent_relationship(SOURCE_SNAPSHOT, SOURCE_SNAPSHOT).is_ok());
        assert!(validate_parent_relationship(SOURCE_SNAPSHOT, QUARANTINE_COMMIT).is_err());
    }

    #[test]
    fn file_inventory_rejects_missing_extra_duplicate_and_wrong_identity() {
        let mut fixture = ledger();
        fixture.files.pop();
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[0].path = "crates/venom-scanner/src/extra.rs".to_owned();
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[1].path = fixture.files[0].path.clone();
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[0].blob_sha = "f".repeat(40);
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[0].byte_size += 1;
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[0].source_role = SourceRole::ApiConfiguration;
        assert!(validate_ledger(&fixture).is_err());
    }

    #[test]
    fn removed_and_narrowed_statuses_are_pinned_per_file() {
        let mut fixture = ledger();
        let removed = fixture
            .files
            .iter_mut()
            .find(|file| file.quarantine_change == QuarantineChange::Removed)
            .expect("removed file");
        removed.quarantine_change = QuarantineChange::MateriallyNarrowed;
        assert!(validate_ledger(&fixture).is_err());

        let mut fixture = ledger();
        let narrowed = fixture
            .files
            .iter_mut()
            .find(|file| file.quarantine_change == QuarantineChange::MateriallyNarrowed)
            .expect("narrowed file");
        narrowed.quarantine_change = QuarantineChange::Removed;
        assert!(validate_ledger(&fixture).is_err());
    }

    #[test]
    fn exact_39_component_inventory_rejects_missing_extra_and_duplicates() {
        let fixture = ledger();
        assert!(validate_ledger(&fixture).is_ok());
        assert_eq!(
            fixture
                .files
                .iter()
                .map(|file| file.components.len())
                .sum::<usize>(),
            EXPECTED_COMPONENT_COUNT
        );
        let summary = Summary::from_ledger(&fixture);
        assert_eq!(summary.component_count, EXPECTED_COMPONENT_COUNT);
        assert_eq!(summary.high_priority_count, 10);
        assert_eq!(summary.dispositions["superseded-by-current-runtime"], 8);
        assert_eq!(summary.dispositions["rewrite-from-contract"], 8);
        assert_eq!(summary.dispositions["reject-blind-dispatcher"], 6);

        let mut missing = ledger();
        missing.files[0].components.clear();
        assert!(validate_ledger(&missing).is_err());
        let mut wrong = ledger();
        wrong.files[0].components[0].id = "adaptive.unlisted".to_owned();
        assert!(validate_ledger(&wrong).is_err());
        let mut duplicate = ledger();
        duplicate.files[1].components[0].id = duplicate.files[0].components[0].id.clone();
        assert!(validate_ledger(&duplicate).is_err());

        let mut changed_contract = ledger();
        let unsafe_technique = changed_contract
            .files
            .iter_mut()
            .flat_map(|file| &mut file.components)
            .find(|component| component.id == "waf.http-splitting")
            .expect("HTTP splitting contract");
        unsafe_technique.disposition = Disposition::RewriteFromContract;
        unsafe_technique.priority = Priority::P2;
        unsafe_technique.status = ComponentStatus::Planned;
        unsafe_technique.modern_destination = ModernDestination::NormalizationResilience;
        unsafe_technique.prohibited_restoration_behaviors.clear();
        assert!(validate_ledger(&changed_contract).is_err());
    }

    #[test]
    fn rejected_status_requires_terminal_disposition_priority_and_prohibition() {
        let mut component = fixture_component("relocated.raw-normalization-helpers");
        component.status = ComponentStatus::Rejected;
        assert!(validate_component(&component, "fixture.rs").is_err());

        let mut component = fixture_component("relocated.raw-normalization-helpers");
        component.status = ComponentStatus::Rejected;
        component.disposition = Disposition::RejectBlindDispatcher;
        component.priority = Priority::Never;
        component.prohibited_restoration_behaviors =
            vec![ProhibitedRestorationBehavior::BlindDispatch];
        assert!(validate_component(&component, "fixture.rs").is_ok());

        let mut component = fixture_component("relocated.raw-normalization-helpers");
        component.disposition = Disposition::RejectMisleadingClaim;
        assert!(validate_component(&component, "fixture.rs").is_err());
    }

    #[test]
    fn superseded_metadata_archived_and_planned_statuses_fail_closed() {
        let mut superseded = fixture_component("relocated.raw-normalization-helpers");
        superseded.status = ComponentStatus::Superseded;
        superseded.disposition = Disposition::SupersededByCurrentRuntime;
        assert!(validate_component(&superseded, "fixture.rs").is_err());
        superseded.current_replacement_paths =
            vec!["crates/venom-scanner/src/defense/state.rs".to_owned()];
        assert!(validate_component(&superseded, "fixture.rs").is_ok());

        let mut metadata = fixture_component("relocated.raw-normalization-helpers");
        metadata.status = ComponentStatus::MetadataOnly;
        assert!(validate_component(&metadata, "fixture.rs").is_err());
        metadata.disposition = Disposition::ImportMetadataOnly;
        assert!(validate_component(&metadata, "fixture.rs").is_ok());

        let mut archived = fixture_component("relocated.raw-normalization-helpers");
        archived.status = ComponentStatus::Archived;
        assert!(validate_component(&archived, "fixture.rs").is_err());
        archived.disposition = Disposition::ArchiveReference;
        archived.modern_destination = ModernDestination::DocumentationOnly;
        assert!(validate_component(&archived, "fixture.rs").is_ok());

        let mut planned = fixture_component("relocated.raw-normalization-helpers");
        planned.priority = Priority::Never;
        assert!(validate_component(&planned, "fixture.rs").is_err());
    }

    #[test]
    fn restored_status_requires_actionable_disposition_and_current_replacement() {
        let mut component = fixture_component("relocated.raw-normalization-helpers");
        component.status = ComponentStatus::Restored;
        assert!(validate_component(&component, "fixture.rs").is_err());

        let mut component = fixture_component("relocated.raw-normalization-helpers");
        component.status = ComponentStatus::Restored;
        component.current_replacement_paths =
            vec!["crates/venom-scanner/src/payload_strategies/encoding.rs".to_owned()];
        assert!(validate_component(&component, "fixture.rs").is_ok());

        component.disposition = Disposition::SupersededByCurrentRuntime;
        assert!(validate_component(&component, "fixture.rs").is_err());
    }

    #[test]
    fn identifiers_facts_paths_and_sets_are_bounded_and_unique() {
        assert!(validate_component_id("waf.generic-evasion-dispatch").is_ok());
        assert!(validate_component_id("../waf").is_err());
        assert!(validate_component_id("WAF Dispatcher").is_err());
        assert!(validate_fact("rationale", "bounded fact", 32).is_ok());
        assert!(validate_fact("rationale", " ", 32).is_err());
        assert!(validate_fact("rationale", "line\nbreak", 32).is_err());
        assert!(validate_unique_bounded_facts(
            "prerequisites",
            &["review".to_owned(), "review".to_owned()]
        )
        .is_err());
        assert!(validate_unique_prohibitions(&[
            ProhibitedRestorationBehavior::BlindDispatch,
            ProhibitedRestorationBehavior::BlindDispatch,
        ])
        .is_err());
        assert!(validate_unique_paths(
            "paths",
            &["crates/a.rs".to_owned(), "crates/a.rs".to_owned()]
        )
        .is_err());
    }

    #[test]
    fn declared_current_replacement_paths_must_be_existing_regular_files() {
        let temporary = TempDir::new().expect("temporary directory");
        let replacement = temporary.path().join("replacement.rs");
        fs::write(&replacement, b"source").expect("write replacement");
        let mut fixture = ledger();
        for component in fixture
            .files
            .iter_mut()
            .flat_map(|file| &mut file.components)
        {
            component.current_replacement_paths.clear();
        }
        fixture.files[0].current_replacement_paths = vec!["replacement.rs".to_owned()];
        assert!(validate_current_replacement_paths(temporary.path(), &fixture).is_ok());
        fixture.files[0].current_replacement_paths = vec!["missing.rs".to_owned()];
        assert!(validate_current_replacement_paths(temporary.path(), &fixture).is_err());
        fixture.files[0].current_replacement_paths = vec!["directory".to_owned()];
        fs::create_dir(temporary.path().join("directory")).expect("create directory");
        assert!(validate_current_replacement_paths(temporary.path(), &fixture).is_err());
    }

    #[test]
    fn historical_replacement_paths_resolve_to_the_renamed_live_crate_only() {
        let temporary = TempDir::new().expect("temporary directory");
        let live = temporary
            .path()
            .join("crates/termivar-scanner/src/defense/state.rs");
        fs::create_dir_all(live.parent().unwrap()).expect("create live crate path");
        fs::write(&live, b"source").expect("write replacement");

        assert_eq!(
            current_replacement_path(
                temporary.path(),
                "crates/venom-scanner/src/defense/state.rs"
            ),
            live
        );
        assert_eq!(
            current_replacement_path(temporary.path(), "replacement.rs"),
            temporary.path().join("replacement.rs")
        );

        let mut fixture = ledger();
        for file in &mut fixture.files {
            file.current_replacement_paths.clear();
            for component in &mut file.components {
                component.current_replacement_paths.clear();
            }
        }
        fixture.files[0].current_replacement_paths =
            vec!["crates/venom-scanner/src/defense/state.rs".to_owned()];
        assert!(validate_current_replacement_paths(temporary.path(), &fixture).is_ok());
    }

    #[test]
    fn digest_is_order_independent_and_material_change_sensitive() {
        let mut original = ledger();
        original.files[0].current_replacement_paths =
            vec!["crates/z.rs".to_owned(), "crates/a.rs".to_owned()];
        original.files[0].components[0].prerequisites =
            vec!["z prerequisite".to_owned(), "a prerequisite".to_owned()];
        original.files[0].components[0].prohibited_restoration_behaviors = vec![
            ProhibitedRestorationBehavior::GenericStringMutation,
            ProhibitedRestorationBehavior::BlindDispatch,
        ];
        let expected = semantic_digest(&original);
        let mut reordered = original.clone();
        reordered.scoped_source_paths.reverse();
        reordered.files.reverse();
        for file in &mut reordered.files {
            file.components.reverse();
            file.current_replacement_paths.reverse();
            for component in &mut file.components {
                component.prerequisites.reverse();
                component.prohibited_restoration_behaviors.reverse();
            }
        }
        assert_eq!(semantic_digest(&reordered), expected);

        let mut changed = original;
        changed.files[0].components[0].disposition = Disposition::MoveToDifferentCapability;
        assert_ne!(semantic_digest(&changed), expected);
        assert_eq!(expected.len(), DIGEST_PREFIX.len() + 1 + 64);
    }

    #[test]
    fn markdown_is_deterministic_escaped_and_change_sensitive() {
        let mut fixture = ledger();
        fixture.files[0].components[0].rationale = "Preserve A | B without raw source.".to_owned();
        fixture.ledger_digest = semantic_digest(&fixture);
        let first = render_markdown(&fixture);
        assert_eq!(render_markdown(&fixture), first);
        assert!(first.contains("Preserve A \\| B") || first.contains("Component classifications"));
        assert!(first.contains("WAF fingerprinting was not lost"));
        assert!(first.contains("HTTP splitting does not belong"));
        let mut changed = fixture;
        changed.files[0].components[0].rationale = "Changed rationale.".to_owned();
        assert_ne!(render_markdown(&changed), first);
    }

    #[test]
    fn git_tree_parser_requires_regular_blobs_and_exact_sizes() {
        let parsed = parse_ls_tree(
            "100644 blob 171a4c324069e5747c747fcdd82a107c1409bc73 8777\tcrates/venom-scanner/src/waf.rs\n",
        )
        .expect("parse tree");
        assert_eq!(parsed["crates/venom-scanner/src/waf.rs"].byte_size, 8_777);
        assert!(parse_ls_tree(
            "120000 blob 171a4c324069e5747c747fcdd82a107c1409bc73 7\tcrates/venom-scanner/src/waf.rs"
        )
        .is_err());
        assert!(parse_ls_tree("malformed").is_err());
    }

    #[test]
    fn history_comparison_rejects_missing_extra_changed_and_false_narrowing() {
        let fixture = ledger();
        let (source, quarantine) = history_trees();
        assert!(validate_history_trees(&source, &quarantine, &fixture).is_ok());

        let mut missing = source.clone();
        missing.remove(REQUIRED_FILES[0].path);
        assert!(validate_history_trees(&missing, &quarantine, &fixture).is_err());
        let mut extra = source.clone();
        extra.insert(
            "crates/venom-scanner/src/extra.rs".to_owned(),
            GitBlob {
                sha: "e".repeat(40),
                byte_size: 1,
            },
        );
        assert!(validate_history_trees(&extra, &quarantine, &fixture).is_err());
        let mut changed_sha = source.clone();
        changed_sha.get_mut(REQUIRED_FILES[0].path).unwrap().sha = "e".repeat(40);
        assert!(validate_history_trees(&changed_sha, &quarantine, &fixture).is_err());
        let mut changed_size = source.clone();
        changed_size
            .get_mut(REQUIRED_FILES[0].path)
            .unwrap()
            .byte_size += 1;
        assert!(validate_history_trees(&changed_size, &quarantine, &fixture).is_err());

        let narrowed = REQUIRED_FILES
            .iter()
            .find(|file| file.change == QuarantineChange::MateriallyNarrowed)
            .expect("narrowed path");
        let mut unchanged = quarantine;
        unchanged.get_mut(narrowed.path).unwrap().sha = narrowed.blob_sha.to_owned();
        assert!(validate_history_trees(&source, &unchanged, &fixture).is_err());
    }

    #[test]
    fn report_comparison_normalizes_only_platform_line_endings() {
        assert_eq!(normalize_line_endings("a\r\nb\r\n"), "a\nb\n");
        assert_eq!(normalize_line_endings("a\nb\n"), "a\nb\n");
        assert_ne!(normalize_line_endings("a\rb"), "a\nb");
        assert!(validate_rendered_report("a\r\nb\r\n", "a\nb\n").is_ok());
        let error = validate_rendered_report("stale\n", "current\n")
            .expect_err("stale report must fail closed");
        assert!(error
            .to_string()
            .contains("generated WAF/evasion salvage report is stale"));
    }

    #[test]
    fn bounded_reader_stops_at_the_compiled_limit() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join("ledger.toml");
        fs::write(&path, b"1234").expect("write fixture");
        assert_eq!(read_bounded(&path, 4).unwrap(), b"1234");
        assert!(read_bounded(&path, 3).is_err());
    }

    #[test]
    fn digest_rewrite_requires_one_assignment_and_preserves_other_source() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join("ledger.toml");
        let source = b"schema = \"v1\"\nledger_digest = \"old\"\nfiles = []\n";
        fs::write(&path, source).expect("write fixture");
        let digest = format!("{DIGEST_PREFIX}:{}", "a".repeat(64));
        rewrite_digest(&path, source, &digest).expect("rewrite digest");
        let rewritten = fs::read_to_string(path).expect("read rewritten fixture");
        assert!(rewritten.contains(&format!("ledger_digest = \"{digest}\"")));
        assert!(rewritten.contains("schema = \"v1\""));
        assert!(rewrite_digest(
            temporary.path().join("absent.toml").as_path(),
            b"schema = \"v1\"\n",
            &digest
        )
        .is_err());
    }

    #[test]
    fn actual_history_has_exact_parent_inventory_and_change_kinds() {
        let root = super::super::workspace_root();
        if git_success(
            &root,
            &["cat-file", "-e", &format!("{SOURCE_SNAPSHOT}^{{commit}}")],
        )
        .is_err()
        {
            return;
        }
        let parent = git_text(&root, &["rev-parse", &format!("{QUARANTINE_COMMIT}^")])
            .expect("quarantine parent");
        assert_eq!(parent, SOURCE_SNAPSHOT);
        let source = scoped_tree(&root, SOURCE_SNAPSHOT).expect("source tree");
        let quarantine = scoped_tree(&root, QUARANTINE_COMMIT).expect("quarantine tree");
        validate_history_trees(&source, &quarantine, &ledger()).expect("exact history");
    }

    #[test]
    fn prior_38_file_ledger_digest_remains_unchanged() {
        let root = super::super::workspace_root();
        let prior_digest = scanner_salvage::validate_repository_contract_without_history(&root)
            .expect("prior scanner salvage semantic contract remains valid");
        assert_eq!(prior_digest, PRIOR_LEDGER_DIGEST);

        let source = read_bounded(&root.join(LEDGER_RELATIVE_PATH), MAX_LEDGER_BYTES)
            .expect("read WAF/evasion ledger");
        let current = parse_ledger(&source).expect("parse WAF/evasion ledger");
        assert_eq!(current.prior_salvage_digest, prior_digest);
        validate_prior_ledger(&root, &current).expect("cross-epoch semantic digest relationship");
    }

    #[test]
    fn repository_ledger_and_generated_report_validate_together() {
        let root = super::super::workspace_root();
        if !root.join(LEDGER_RELATIVE_PATH).is_file()
            || !root.join(REPORT_RELATIVE_PATH).is_file()
            || git_success(
                &root,
                &["cat-file", "-e", &format!("{SOURCE_SNAPSHOT}^{{commit}}")],
            )
            .is_err()
        {
            return;
        }
        run(&root, false).expect("repository WAF/evasion salvage ledger and report are current");
    }
}
