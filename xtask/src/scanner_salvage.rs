//! Deterministic validation for the deleted scanner tree's salvage ledger.

use crate::TaskResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
};

const LEDGER_RELATIVE_PATH: &str = "salvage/historical-scanner/ledger.toml";
const REPORT_RELATIVE_PATH: &str = "docs/history/historical-scanner-salvage.md";
const SCHEMA: &str = "venom.historical-scanner-salvage/v1";
const DIGEST_ALGORITHM: &str = "venom.historical-scanner-salvage-digest/v1";
const DIGEST_PREFIX: &str = "salvage-sha256";
const SOURCE_SNAPSHOT: &str = "ede3d9e5b1098434a771ae6ca3cb530941e22210";
const WORKSPACE_SPLIT: &str = "3c90364279284bdbb82494b4e03d71b5066657c4";
const DELETION_COMMIT: &str = "28bfb2d8ae3a4f707b7423cac65b6be8e11085b6";
const REPLACEMENT_BASELINE: &str = "cbca14d10db4ee641308f3b3e290bf75d937c8a7";
const HISTORICAL_ROOT: &str = "src/scanner";
const EXPECTED_FILE_COUNT: usize = 38;
const MAX_LEDGER_BYTES: usize = 512 * 1024;
const MAX_REPORT_BYTES: usize = 1024 * 1024;
const MAX_COMPONENTS_PER_FILE: usize = 32;
const MAX_TOTAL_COMPONENTS: usize = 512;
const MAX_COMPONENT_ID_BYTES: usize = 128;
const MAX_SYMBOL_BYTES: usize = 192;
const MAX_FACT_BYTES: usize = 512;
const MAX_NOTES_BYTES: usize = 768;
const MAX_PREREQUISITES: usize = 16;

pub(super) fn run(workspace_root: &Path, write: bool) -> TaskResult {
    let mut local = load_and_validate_local_semantics(workspace_root)?;
    validate_history(workspace_root, &local.ledger)?;

    if write {
        let ledger_path = workspace_root.join(LEDGER_RELATIVE_PATH);
        rewrite_digest(&ledger_path, &local.source, &local.semantic_digest)?;
        local
            .ledger
            .ledger_digest
            .clone_from(&local.semantic_digest);
        let report_path = workspace_root.join(REPORT_RELATIVE_PATH);
        if let Some(parent) = report_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(report_path, render_markdown(&local.ledger))?;
    } else {
        validate_checked_local_outputs(workspace_root, &local.ledger, &local.semantic_digest)?;
    }

    let summary = Summary::from_ledger(&local.ledger);
    println!(
        "historical scanner salvage validated: {} file(s), {} component(s), {} P0/P1, digest {}",
        local.ledger.files.len(),
        summary.component_count,
        summary.high_priority_count,
        local.semantic_digest
    );
    Ok(())
}

struct ValidatedLocalScannerSalvage {
    source: Vec<u8>,
    ledger: SalvageLedger,
    semantic_digest: String,
}

fn load_and_validate_local_semantics(
    workspace_root: &Path,
) -> TaskResult<ValidatedLocalScannerSalvage> {
    let ledger_path = workspace_root.join(LEDGER_RELATIVE_PATH);
    let source = read_bounded(&ledger_path, MAX_LEDGER_BYTES)?;
    let ledger = parse_ledger(&source)?;
    validate_ledger(&ledger)?;
    validate_required_component_contracts(&ledger)?;
    let semantic_digest = semantic_digest(&ledger);
    Ok(ValidatedLocalScannerSalvage {
        source,
        ledger,
        semantic_digest,
    })
}

fn validate_checked_local_outputs(
    workspace_root: &Path,
    ledger: &SalvageLedger,
    semantic_digest: &str,
) -> TaskResult {
    if ledger.ledger_digest != semantic_digest {
        return Err(format!(
            "salvage ledger digest mismatch: stored {}, computed {semantic_digest}",
            ledger.ledger_digest
        )
        .into());
    }
    let report_source = read_bounded(&workspace_root.join(REPORT_RELATIVE_PATH), MAX_REPORT_BYTES)?;
    let report = std::str::from_utf8(&report_source)
        .map_err(|_| "generated salvage report is not valid UTF-8")?;
    let expected = render_markdown(ledger);
    if normalize_line_endings(report) != expected {
        return Err("generated salvage report is stale; run `cargo run -p xtask -- scanner-salvage --write`".into());
    }
    Ok(())
}

pub(super) fn validate_repository_contract_without_history(
    workspace_root: &Path,
) -> TaskResult<String> {
    let local = load_and_validate_local_semantics(workspace_root)?;
    validate_checked_local_outputs(workspace_root, &local.ledger, &local.semantic_digest)?;
    Ok(local.semantic_digest)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SalvageLedger {
    schema: String,
    source_snapshot_commit: String,
    workspace_split_commit: String,
    deletion_commit: String,
    historical_source_root: String,
    expected_file_count: usize,
    algorithm_version: String,
    ledger_digest: String,
    current_replacement_baseline_sha: String,
    files: Vec<HistoricalFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoricalFile {
    path: String,
    blob_sha: String,
    byte_size: u64,
    source_role: SourceRole,
    build_reachability: BuildReachability,
    old_default_runtime_reachability: RuntimeReachability,
    direct_network_io: AuthorityUse,
    direct_filesystem_io: AuthorityUse,
    process_interaction: AuthorityUse,
    unsafe_code: UnsafeCodeStatus,
    identity_behavior: IdentityBehavior,
    evidence_quality: EvidenceQuality,
    claim_risk: ClaimRisk,
    current_replacement: Option<String>,
    salvage_priority: Priority,
    notes: String,
    components: Vec<HistoricalComponent>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoricalComponent {
    id: String,
    symbol: String,
    disposition: Disposition,
    priority: Priority,
    historical_behavior: String,
    old_runtime_reachability: RuntimeReachability,
    reusable_value: String,
    prohibited_behaviors: Vec<ProhibitedBehavior>,
    modern_destination: ModernDestination,
    prerequisites: Vec<String>,
    status: ComponentStatus,
    modern_implementation: Option<String>,
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
    Analysis => "analysis",
    Anomaly => "anomaly",
    ApiAssessment => "api-assessment",
    Baseline => "baseline",
    Behavioral => "behavioral",
    BusinessLogic => "business-logic",
    Deserialization => "deserialization",
    SignatureDetection => "signature-detection",
    EndpointFuzzing => "endpoint-fuzzing",
    ErrorHandling => "error-handling",
    ExploitResearch => "exploit-research",
    GadgetAnalysis => "gadget-analysis",
    Authorization => "authorization",
    Infrastructure => "infrastructure",
    TestFixture => "test-fixture",
    MachineLearning => "machine-learning",
    ModuleRoot => "module-root",
    Mutation => "mutation",
    Authentication => "authentication",
    Reconnaissance => "reconnaissance",
    Concurrency => "concurrency",
    PayloadCatalog => "payload-catalog",
    Benchmark => "benchmark",
    ReleaseConfiguration => "release-configuration",
    Scoring => "scoring",
    SourceAnalysis => "source-analysis",
    SqlInjection => "sql-injection",
    ServerSideRequest => "server-side-request",
    TemplateInjection => "template-injection",
    ThreatIntelligence => "threat-intelligence",
    WebSocket => "websocket",
    CrossSiteScripting => "cross-site-scripting"
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
    Fabricated => "fabricated",
    Mixed => "mixed",
    FixtureOnly => "fixture-only",
    NotApplicable => "not-applicable"
});

closed_enum!(ClaimRisk {
    Low => "low",
    Moderate => "moderate",
    High => "high",
    Fabricated => "fabricated",
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
    ImportFixtureCorpus => "import-fixture-corpus",
    ArchiveReference => "archive-reference",
    SupersededByCurrentRuntime => "superseded-by-current-runtime",
    RejectFabricatedBehavior => "reject-fabricated-behavior",
    RejectUnsafeAdapter => "reject-unsafe-adapter",
    RejectMisleadingClaim => "reject-misleading-claim"
});

closed_enum!(ModernDestination {
    VenomArtifact => "venom-artifact",
    WebAssessment => "venom-scanner:web-assessment",
    ApiAssessment => "venom-scanner:api-assessment",
    Authorization => "venom-scanner:authz",
    Oast => "venom-scanner:oast",
    PayloadCatalog => "venom-scanner:payload-catalog",
    Anomaly => "venom-scanner:anomaly",
    VenomExploit => "venom-exploit",
    FutureVenomMl => "future-venom-ml",
    FutureWebSocketDomain => "future-websocket-domain",
    FixtureCorpus => "fixture-corpus",
    DocumentationOnly => "documentation-only",
    None => "none"
});

closed_enum!(ProhibitedBehavior {
    UnsafeAdapter => "unsafe-adapter",
    UnboundedIo => "unbounded-io",
    DirectNetworkAuthority => "direct-network-authority",
    DirectFilesystemAuthority => "direct-filesystem-authority",
    ProcessAuthority => "process-authority",
    FabricatedFinding => "fabricated-finding",
    MisleadingClaim => "misleading-claim",
    RandomIdentity => "random-identity",
    RawSensitiveEvidence => "raw-sensitive-evidence",
    AutomaticSeverity => "automatic-severity",
    LegacyRuntimeCoupling => "legacy-runtime-coupling",
    UnconditionalSuccess => "unconditional-success"
});

closed_enum!(ComponentStatus {
    Planned => "planned",
    Restored => "restored",
    Superseded => "superseded",
    Rejected => "rejected"
});

fn parse_ledger(source: &[u8]) -> TaskResult<SalvageLedger> {
    let source = std::str::from_utf8(source).map_err(|_| "salvage ledger is not valid UTF-8")?;
    toml::from_str(source).map_err(|error| {
        let location = error.span().map_or_else(
            || "unknown location".to_owned(),
            |span| format!("byte {}", span.start),
        );
        format!("invalid salvage ledger TOML at {location}").into()
    })
}

fn validate_ledger(ledger: &SalvageLedger) -> TaskResult {
    validate_header(ledger)?;
    validate_digest_wire(&ledger.ledger_digest)?;
    if ledger.files.len() != ledger.expected_file_count {
        return Err(format!(
            "salvage ledger has {} files; expected {}",
            ledger.files.len(),
            ledger.expected_file_count
        )
        .into());
    }

    let mut paths = BTreeSet::new();
    let mut component_ids = BTreeSet::new();
    let mut total_components = 0_usize;
    for file in &ledger.files {
        validate_file(file)?;
        if !paths.insert(file.path.as_str()) {
            return Err(format!("duplicate historical file path: {}", file.path).into());
        }
        total_components = total_components
            .checked_add(file.components.len())
            .ok_or("historical component count overflow")?;
        if total_components > MAX_TOTAL_COMPONENTS {
            return Err(format!(
                "salvage ledger exceeds {MAX_TOTAL_COMPONENTS} historical components"
            )
            .into());
        }
        for component in &file.components {
            if !component_ids.insert(component.id.as_str()) {
                return Err(format!("duplicate historical component ID: {}", component.id).into());
            }
        }
    }
    Ok(())
}

fn validate_required_component_contracts(ledger: &SalvageLedger) -> TaskResult {
    let detector = ledger
        .files
        .iter()
        .find(|file| file.path == "src/scanner/detector.rs")
        .ok_or("detector.rs is missing from the salvage ledger")?;
    let actual = detector
        .components
        .iter()
        .map(|component| {
            (
                component.id.as_str(),
                (
                    component.disposition,
                    component.priority,
                    component.status,
                    component.modern_destination,
                    component.modern_implementation.as_deref(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected = BTreeMap::from([
        (
            "detector.byte-pattern",
            (
                Disposition::PortAlgorithm,
                Priority::P0,
                ComponentStatus::Restored,
                ModernDestination::VenomArtifact,
                Some("venom_artifact::ArtifactScanner (venom.artifact-signature-scan/v1)"),
            ),
        ),
        (
            "detector.mmap-file-adapter",
            (
                Disposition::RejectUnsafeAdapter,
                Priority::Never,
                ComponentStatus::Rejected,
                ModernDestination::None,
                None,
            ),
        ),
        (
            "detector.request-vulnerability",
            (
                Disposition::RejectFabricatedBehavior,
                Priority::Never,
                ComponentStatus::Rejected,
                ModernDestination::None,
                None,
            ),
        ),
        (
            "detector.unused-bmh-claim",
            (
                Disposition::RejectMisleadingClaim,
                Priority::Never,
                ComponentStatus::Rejected,
                ModernDestination::None,
                None,
            ),
        ),
    ]);
    if actual != expected {
        return Err("detector.rs must retain its exact four-way salvage split".into());
    }

    let api = ledger
        .files
        .iter()
        .find(|file| file.path == "src/scanner/api_scanner.rs")
        .ok_or("api_scanner.rs is missing from the salvage ledger")?;
    let actual = api
        .components
        .iter()
        .map(|component| {
            (
                component.id.as_str(),
                (
                    component.disposition,
                    component.priority,
                    component.status,
                    component.modern_destination,
                    component.modern_implementation.as_deref(),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected = BTreeMap::from([
        (
            "api.protocol-taxonomy",
            (
                Disposition::RewriteFromContract,
                Priority::P1,
                ComponentStatus::Restored,
                ModernDestination::ApiAssessment,
                Some("venom_scanner::graphql_review (web.review.graphql.introspection-pair@1)"),
            ),
        ),
        (
            "api.protocol-taxonomy.remaining",
            (
                Disposition::RewriteFromContract,
                Priority::P1,
                ComponentStatus::Planned,
                ModernDestination::ApiAssessment,
                None,
            ),
        ),
        (
            "api.unconditional-tests",
            (
                Disposition::RejectFabricatedBehavior,
                Priority::Never,
                ComponentStatus::Rejected,
                ModernDestination::None,
                None,
            ),
        ),
    ]);
    if actual == expected {
        Ok(())
    } else {
        Err("api_scanner.rs must retain its exact GraphQL/rest and rejection split".into())
    }
}

fn validate_header(ledger: &SalvageLedger) -> TaskResult {
    let exact = [
        ("schema", ledger.schema.as_str(), SCHEMA),
        (
            "source_snapshot_commit",
            ledger.source_snapshot_commit.as_str(),
            SOURCE_SNAPSHOT,
        ),
        (
            "workspace_split_commit",
            ledger.workspace_split_commit.as_str(),
            WORKSPACE_SPLIT,
        ),
        (
            "deletion_commit",
            ledger.deletion_commit.as_str(),
            DELETION_COMMIT,
        ),
        (
            "historical_source_root",
            ledger.historical_source_root.as_str(),
            HISTORICAL_ROOT,
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
    ];
    for (field, actual, expected) in exact {
        if actual != expected {
            return Err(format!("invalid {field}; expected {expected}").into());
        }
    }
    if ledger.expected_file_count != EXPECTED_FILE_COUNT {
        return Err(format!("expected_file_count must be {EXPECTED_FILE_COUNT}").into());
    }
    Ok(())
}

fn validate_file(file: &HistoricalFile) -> TaskResult {
    if !valid_historical_path(&file.path) {
        return Err(format!("invalid historical scanner path: {}", file.path).into());
    }
    validate_commit_id("blob_sha", &file.blob_sha)?;
    if file.byte_size == 0 {
        return Err(format!("historical file has zero byte size: {}", file.path).into());
    }
    validate_fact("notes", &file.notes, MAX_NOTES_BYTES)?;
    if let Some(replacement) = &file.current_replacement {
        validate_fact("current_replacement", replacement, MAX_FACT_BYTES)?;
    }
    if file.components.is_empty() || file.components.len() > MAX_COMPONENTS_PER_FILE {
        return Err(format!(
            "{} must contain 1..={MAX_COMPONENTS_PER_FILE} component records",
            file.path
        )
        .into());
    }
    for component in &file.components {
        validate_component(component, &file.path)?;
    }
    Ok(())
}

fn validate_component(component: &HistoricalComponent, path: &str) -> TaskResult {
    validate_component_id(&component.id)?;
    validate_fact("component symbol", &component.symbol, MAX_SYMBOL_BYTES)?;
    validate_fact(
        "historical_behavior",
        &component.historical_behavior,
        MAX_FACT_BYTES,
    )?;
    validate_fact("reusable_value", &component.reusable_value, MAX_FACT_BYTES)?;
    validate_fact("rationale", &component.rationale, MAX_FACT_BYTES)?;
    validate_unique_bounded_facts("prerequisites", &component.prerequisites)?;
    validate_unique_prohibitions(&component.prohibited_behaviors)?;
    if let Some(implementation) = &component.modern_implementation {
        validate_fact("modern_implementation", implementation, MAX_FACT_BYTES)?;
    }

    let is_reject = matches!(
        component.disposition,
        Disposition::RejectFabricatedBehavior
            | Disposition::RejectUnsafeAdapter
            | Disposition::RejectMisleadingClaim
    );
    match component.status {
        ComponentStatus::Rejected => {
            if !is_reject
                || component.priority != Priority::Never
                || component.prohibited_behaviors.is_empty()
            {
                return Err(format!(
                    "rejected component {} in {path} needs never priority, a reject disposition, and prohibited behavior",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Superseded => {
            if component.disposition != Disposition::SupersededByCurrentRuntime {
                return Err(format!(
                    "superseded component {} in {path} needs superseded-by-current-runtime",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Restored => {
            if is_reject
                || component.disposition == Disposition::SupersededByCurrentRuntime
                || component.priority == Priority::Never
                || component.modern_implementation.is_none()
            {
                return Err(format!(
                    "restored component {} in {path} needs actionable priority, a restorable disposition, and modern implementation",
                    component.id
                )
                .into());
            }
        },
        ComponentStatus::Planned => {
            if is_reject
                || component.disposition == Disposition::SupersededByCurrentRuntime
                || component.priority == Priority::Never
            {
                return Err(format!(
                    "planned component {} in {path} has a terminal disposition or never priority",
                    component.id
                )
                .into());
            }
            if component.modern_implementation.is_some() {
                return Err(format!(
                    "planned component {} in {path} cannot claim a modern implementation",
                    component.id
                )
                .into());
            }
        },
    }
    if is_reject && component.status != ComponentStatus::Rejected {
        return Err(format!(
            "reject disposition for {} must have rejected status",
            component.id
        )
        .into());
    }
    if component.modern_destination == ModernDestination::None
        && matches!(
            component.status,
            ComponentStatus::Planned | ComponentStatus::Restored
        )
    {
        return Err(format!(
            "active component {} in {path} requires a modern destination",
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
        Err("invalid historical component ID".into())
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
    if values.len() > MAX_PREREQUISITES {
        return Err(format!("{field} exceeds {MAX_PREREQUISITES} entries").into());
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_fact(field, value, MAX_FACT_BYTES)?;
        if !unique.insert(value) {
            return Err(format!("duplicate value in {field}").into());
        }
    }
    Ok(())
}

fn validate_unique_prohibitions(values: &[ProhibitedBehavior]) -> TaskResult {
    let mut unique = BTreeSet::new();
    for value in values {
        if !unique.insert(*value) {
            return Err("duplicate prohibited behavior".into());
        }
    }
    Ok(())
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

fn valid_historical_path(path: &str) -> bool {
    path.starts_with("src/scanner/")
        && path.ends_with(".rs")
        && !path.contains("..")
        && !path.contains('\\')
        && path.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'_' | b'-' | b'.')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GitBlob {
    sha: String,
    byte_size: u64,
}

fn validate_history(workspace_root: &Path, ledger: &SalvageLedger) -> TaskResult {
    for commit in [
        &ledger.source_snapshot_commit,
        &ledger.workspace_split_commit,
        &ledger.deletion_commit,
        &ledger.current_replacement_baseline_sha,
    ] {
        git_success(
            workspace_root,
            &["cat-file", "-e", &format!("{commit}^{{commit}}")],
        )?;
    }
    let deletion_parent = git_text(
        workspace_root,
        &["rev-parse", &format!("{}^", ledger.deletion_commit)],
    )?;
    if deletion_parent != ledger.source_snapshot_commit {
        return Err("deletion commit parent is not the recorded source snapshot".into());
    }
    git_success(
        workspace_root,
        &[
            "merge-base",
            "--is-ancestor",
            &ledger.workspace_split_commit,
            &ledger.source_snapshot_commit,
        ],
    )?;
    let tree = historical_tree(workspace_root, &ledger.source_snapshot_commit)?;
    validate_tree_against_ledger(&tree, ledger)
}

fn validate_tree_against_ledger(
    tree: &BTreeMap<String, GitBlob>,
    ledger: &SalvageLedger,
) -> TaskResult {
    if tree.len() != EXPECTED_FILE_COUNT {
        return Err(format!(
            "historical Git tree contains {} files; expected {EXPECTED_FILE_COUNT}",
            tree.len()
        )
        .into());
    }
    let recorded = ledger
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for (path, blob) in tree {
        let Some(file) = recorded.get(path.as_str()) else {
            return Err(format!("historical file missing from salvage ledger: {path}").into());
        };
        if file.blob_sha != blob.sha {
            return Err(format!("historical blob SHA mismatch for {path}").into());
        }
        if file.byte_size != blob.byte_size {
            return Err(format!("historical byte-size mismatch for {path}").into());
        }
    }
    for path in recorded.keys() {
        if !tree.contains_key(*path) {
            return Err(format!("ledger path is absent from historical Git tree: {path}").into());
        }
    }
    Ok(())
}

fn historical_tree(workspace_root: &Path, commit: &str) -> TaskResult<BTreeMap<String, GitBlob>> {
    let output = git_text(
        workspace_root,
        &[
            "ls-tree",
            "-r",
            "-l",
            "--full-tree",
            commit,
            "--",
            HISTORICAL_ROOT,
        ],
    )?;
    parse_ls_tree(&output)
}

fn parse_ls_tree(output: &str) -> TaskResult<BTreeMap<String, GitBlob>> {
    let mut tree = BTreeMap::new();
    for line in output.lines() {
        let (metadata, path) = line
            .split_once('\t')
            .ok_or("malformed git ls-tree output")?;
        let fields = metadata.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[1] != "blob" || fields[0] != "100644" {
            return Err("historical scanner tree contains an unsupported Git entry".into());
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
        Err(format!("local Git history validation failed for `{}`", args[0]).into())
    }
}

fn git_text(workspace_root: &Path, args: &[&str]) -> TaskResult<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()?;
    if !output.status.success() {
        return Err(format!("local Git history query failed for `{}`", args[0]).into());
    }
    let text = String::from_utf8(output.stdout).map_err(|_| "Git output is not valid UTF-8")?;
    Ok(text.trim().to_owned())
}

fn semantic_digest(ledger: &SalvageLedger) -> String {
    let mut writer = DigestWriter::new(DIGEST_ALGORITHM);
    writer.field("schema", &ledger.schema);
    writer.field("source_snapshot_commit", &ledger.source_snapshot_commit);
    writer.field("workspace_split_commit", &ledger.workspace_split_commit);
    writer.field("deletion_commit", &ledger.deletion_commit);
    writer.field("historical_source_root", &ledger.historical_source_root);
    writer.number("expected_file_count", ledger.expected_file_count as u64);
    writer.field("algorithm_version", &ledger.algorithm_version);
    writer.field(
        "current_replacement_baseline_sha",
        &ledger.current_replacement_baseline_sha,
    );

    let mut files = ledger.files.iter().collect::<Vec<_>>();
    files.sort_by_key(|file| &file.path);
    for file in files {
        writer.field("file.path", &file.path);
        writer.field("file.blob_sha", &file.blob_sha);
        writer.number("file.byte_size", file.byte_size);
        writer.field("file.source_role", file.source_role.wire());
        writer.field("file.build_reachability", file.build_reachability.wire());
        writer.field(
            "file.old_default_runtime_reachability",
            file.old_default_runtime_reachability.wire(),
        );
        writer.field("file.direct_network_io", file.direct_network_io.wire());
        writer.field(
            "file.direct_filesystem_io",
            file.direct_filesystem_io.wire(),
        );
        writer.field("file.process_interaction", file.process_interaction.wire());
        writer.field("file.unsafe_code", file.unsafe_code.wire());
        writer.field("file.identity_behavior", file.identity_behavior.wire());
        writer.field("file.evidence_quality", file.evidence_quality.wire());
        writer.field("file.claim_risk", file.claim_risk.wire());
        writer.optional(
            "file.current_replacement",
            file.current_replacement.as_deref(),
        );
        writer.field("file.salvage_priority", file.salvage_priority.wire());
        writer.field("file.notes", &file.notes);

        let mut components = file.components.iter().collect::<Vec<_>>();
        components.sort_by_key(|component| &component.id);
        for component in components {
            writer.field("component.id", &component.id);
            writer.field("component.symbol", &component.symbol);
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
            let mut prohibited = component.prohibited_behaviors.clone();
            prohibited.sort_unstable();
            for behavior in prohibited {
                writer.field("component.prohibited_behavior", behavior.wire());
            }
            writer.field(
                "component.modern_destination",
                component.modern_destination.wire(),
            );
            let mut prerequisites = component.prerequisites.iter().collect::<Vec<_>>();
            prerequisites.sort_unstable();
            for prerequisite in prerequisites {
                writer.field("component.prerequisite", prerequisite);
            }
            writer.field("component.status", component.status.wire());
            writer.optional(
                "component.modern_implementation",
                component.modern_implementation.as_deref(),
            );
            writer.field("component.rationale", &component.rationale);
        }
    }
    writer.finish(DIGEST_PREFIX)
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

    fn optional(&mut self, name: &str, value: Option<&str>) {
        self.field(
            &format!("{name}.present"),
            if value.is_some() { "true" } else { "false" },
        );
        if let Some(value) = value {
            self.field(name, value);
        }
    }

    fn finish(self, prefix: &str) -> String {
        format!("{prefix}:{:x}", self.0.finalize())
    }
}

fn render_markdown(ledger: &SalvageLedger) -> String {
    let summary = Summary::from_ledger(ledger);
    let mut output = String::new();
    output.push_str("# Historical scanner salvage ledger\n\n");
    output.push_str(
        "This report is generated from `salvage/historical-scanner/ledger.toml`. Historical source is recovery evidence, not current product authority. No listed historical module participates in the current runtime merely because it appears here.\n\n",
    );
    output.push_str("## Timeline and identity\n\n");
    output.push_str("| Event | Git identity |\n| --- | --- |\n");
    markdown_row(
        &mut output,
        &["Workspace split", &ledger.workspace_split_commit],
    );
    markdown_row(
        &mut output,
        &["Pre-deletion snapshot", &ledger.source_snapshot_commit],
    );
    markdown_row(&mut output, &["Physical deletion", &ledger.deletion_commit]);
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
    output.push_str("| Path | Blob | Bytes | Role | Build | Default runtime | Priority | Replacement |\n| --- | --- | ---: | --- | --- | --- | --- | --- |\n");
    let mut files = ledger.files.iter().collect::<Vec<_>>();
    files.sort_by_key(|file| &file.path);
    for file in &files {
        markdown_row(
            &mut output,
            &[
                &format!("`{}`", file.path),
                &format!("`{}`", file.blob_sha),
                &file.byte_size.to_string(),
                file.source_role.wire(),
                file.build_reachability.wire(),
                file.old_default_runtime_reachability.wire(),
                file.salvage_priority.wire(),
                file.current_replacement.as_deref().unwrap_or("—"),
            ],
        );
    }

    output.push_str("\n## Component classifications\n\n");
    output.push_str("| Component | Source | Disposition | Priority | Status | Destination | Prohibited restoration |\n| --- | --- | --- | --- | --- | --- | --- |\n");
    for file in &files {
        let mut components = file.components.iter().collect::<Vec<_>>();
        components.sort_by_key(|component| &component.id);
        for component in components {
            let prohibited = component
                .prohibited_behaviors
                .iter()
                .map(|behavior| behavior.wire())
                .collect::<Vec<_>>()
                .join(", ");
            markdown_row(
                &mut output,
                &[
                    &format!("`{}`", component.id),
                    &format!("`{}`", file.path),
                    component.disposition.wire(),
                    component.priority.wire(),
                    component.status.wire(),
                    component.modern_destination.wire(),
                    if prohibited.is_empty() {
                        "—"
                    } else {
                        &prohibited
                    },
                ],
            );
        }
    }

    output.push_str("\n## P0/P1 recovery roadmap\n\n");
    for file in &files {
        let mut components = file.components.iter().collect::<Vec<_>>();
        components.sort_by_key(|component| &component.id);
        for component in components.into_iter().filter(|component| {
            matches!(component.priority, Priority::P0 | Priority::P1)
                && matches!(
                    component.status,
                    ComponentStatus::Planned | ComponentStatus::Restored
                )
        }) {
            let implementation = component
                .modern_implementation
                .as_deref()
                .map(|value| format!("; implementation `{}`", escape_markdown(value)))
                .unwrap_or_default();
            output.push_str(&format!(
                "- `{}` → `{}` ({}{}): {}\n",
                escape_markdown(&component.id),
                component.modern_destination.wire(),
                component.status.wire(),
                implementation,
                escape_markdown(&component.rationale)
            ));
        }
    }

    output.push_str("\n## Explicitly rejected historical behavior\n\n");
    for file in &files {
        let mut components = file.components.iter().collect::<Vec<_>>();
        components.sort_by_key(|component| &component.id);
        for component in components
            .into_iter()
            .filter(|component| component.status == ComponentStatus::Rejected)
        {
            output.push_str(&format!(
                "- `{}`: {}\n",
                escape_markdown(&component.id),
                escape_markdown(&component.rationale)
            ));
        }
    }

    output.push_str("\n## Restoration policy\n\n");
    output.push_str("A future restoration must update the relevant component from `planned` to `restored`, name its modern implementation, and pass current architecture, evidence, coverage, and exact-head CI contracts. The old monolith is not restored as a product runtime.\n");
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
                ComponentStatus::Planned | ComponentStatus::Restored
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

fn rewrite_digest(path: &Path, source: &[u8], digest: &str) -> TaskResult {
    let source = std::str::from_utf8(source).map_err(|_| "salvage ledger is not valid UTF-8")?;
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
        return Err("salvage ledger must contain exactly one ledger_digest assignment".into());
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> TaskResult<Vec<u8>> {
    let limit = u64::try_from(maximum)?
        .checked_add(1)
        .ok_or("salvage ledger read limit overflow")?;
    let mut source = Vec::with_capacity(maximum.min(32 * 1024));
    File::open(path)?.take(limit).read_to_end(&mut source)?;
    if source.len() > maximum {
        Err(format!("salvage ledger exceeds {maximum} bytes").into())
    } else {
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn component(id: &str) -> HistoricalComponent {
        HistoricalComponent {
            id: id.to_owned(),
            symbol: "module contents".to_owned(),
            disposition: Disposition::ArchiveReference,
            priority: Priority::P3,
            historical_behavior: "Historical implementation reference.".to_owned(),
            old_runtime_reachability: RuntimeReachability::Unreachable,
            reusable_value: "Documents prior research.".to_owned(),
            prohibited_behaviors: Vec::new(),
            modern_destination: ModernDestination::DocumentationOnly,
            prerequisites: vec!["fresh contract review".to_owned()],
            status: ComponentStatus::Planned,
            modern_implementation: None,
            rationale: "Retain only as bounded historical reference.".to_owned(),
        }
    }

    fn ledger() -> SalvageLedger {
        let files = (0..EXPECTED_FILE_COUNT)
            .map(|index| HistoricalFile {
                path: format!("src/scanner/file_{index:02}.rs"),
                blob_sha: format!("{index:040x}"),
                byte_size: 100 + index as u64,
                source_role: SourceRole::Analysis,
                build_reachability: BuildReachability::DeclaredButUnbuilt,
                old_default_runtime_reachability: RuntimeReachability::Unreachable,
                direct_network_io: AuthorityUse::None,
                direct_filesystem_io: AuthorityUse::None,
                process_interaction: AuthorityUse::None,
                unsafe_code: UnsafeCodeStatus::Absent,
                identity_behavior: IdentityBehavior::Deterministic,
                evidence_quality: EvidenceQuality::NotApplicable,
                claim_risk: ClaimRisk::Low,
                current_replacement: None,
                salvage_priority: Priority::P3,
                notes: "Historical source classified at component level.".to_owned(),
                components: vec![component(&format!("file-{index:02}.reference"))],
            })
            .collect();
        SalvageLedger {
            schema: SCHEMA.to_owned(),
            source_snapshot_commit: SOURCE_SNAPSHOT.to_owned(),
            workspace_split_commit: WORKSPACE_SPLIT.to_owned(),
            deletion_commit: DELETION_COMMIT.to_owned(),
            historical_source_root: HISTORICAL_ROOT.to_owned(),
            expected_file_count: EXPECTED_FILE_COUNT,
            algorithm_version: DIGEST_ALGORITHM.to_owned(),
            ledger_digest: format!("{DIGEST_PREFIX}:{}", "0".repeat(64)),
            current_replacement_baseline_sha: "cbca14d10db4ee641308f3b3e290bf75d937c8a7".to_owned(),
            files,
        }
    }

    #[test]
    fn strict_toml_rejects_unknown_and_duplicate_fields() {
        let source = toml::to_string(&ledger()).expect("serialize fixture");
        let unknown = format!("unknown = true\n{source}");
        assert!(parse_ledger(unknown.as_bytes()).is_err());
        let duplicate = source.replacen(
            &format!("schema = \"{SCHEMA}\""),
            &format!("schema = \"{SCHEMA}\"\nschema = \"{SCHEMA}\""),
            1,
        );
        assert!(parse_ledger(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn header_schema_commits_count_and_digest_are_exact() {
        let mut fixture = ledger();
        assert!(validate_ledger(&fixture).is_ok());
        fixture.schema = "venom.historical-scanner-salvage/v2".to_owned();
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.source_snapshot_commit = "f".repeat(40);
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.expected_file_count = 37;
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.current_replacement_baseline_sha = "f".repeat(40);
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.ledger_digest = "salvage-sha256:ABC".to_owned();
        assert!(validate_ledger(&fixture).is_err());
    }

    #[test]
    fn file_inventory_rejects_missing_duplicate_and_unclassified_files() {
        let mut fixture = ledger();
        fixture.files.pop();
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        let duplicate_path = fixture.files[0].path.clone();
        fixture.files[1].path = duplicate_path;
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[0].components.clear();
        assert!(validate_ledger(&fixture).is_err());
        fixture = ledger();
        fixture.files[1].components[0].id = fixture.files[0].components[0].id.clone();
        assert!(validate_ledger(&fixture).is_err());
    }

    #[test]
    fn component_status_contracts_fail_closed() {
        let mut fixture = ledger();
        let component = &mut fixture.files[0].components[0];
        component.status = ComponentStatus::Restored;
        assert!(validate_ledger(&fixture).is_err());

        let mut fixture = ledger();
        let component = &mut fixture.files[0].components[0];
        component.status = ComponentStatus::Rejected;
        assert!(validate_ledger(&fixture).is_err());

        let mut fixture = ledger();
        let component = &mut fixture.files[0].components[0];
        component.disposition = Disposition::RejectFabricatedBehavior;
        assert!(validate_ledger(&fixture).is_err());

        let mut fixture = ledger();
        let component = &mut fixture.files[0].components[0];
        component.status = ComponentStatus::Superseded;
        assert!(validate_ledger(&fixture).is_err());

        let mut fixture = ledger();
        fixture.files[0].components[0].priority = Priority::Never;
        assert!(validate_ledger(&fixture).is_err());

        let mut fixture = ledger();
        let component = &mut fixture.files[0].components[0];
        component.status = ComponentStatus::Rejected;
        component.disposition = Disposition::RejectFabricatedBehavior;
        component.modern_destination = ModernDestination::None;
        component.prohibited_behaviors = vec![ProhibitedBehavior::FabricatedFinding];
        component.priority = Priority::P3;
        assert!(validate_ledger(&fixture).is_err());
    }

    #[test]
    fn required_detector_split_is_exact_and_fail_closed() {
        let root = super::super::workspace_root();
        let source = fs::read(root.join(LEDGER_RELATIVE_PATH)).expect("read repository ledger");
        let mut fixture = parse_ledger(&source).expect("parse repository ledger");
        validate_required_component_contracts(&fixture).expect("required detector split");

        let detector = fixture
            .files
            .iter_mut()
            .find(|file| file.path == "src/scanner/detector.rs")
            .expect("detector record");
        detector
            .components
            .iter_mut()
            .find(|component| component.id == "detector.byte-pattern")
            .expect("byte-pattern component")
            .disposition = Disposition::ArchiveReference;
        assert!(validate_required_component_contracts(&fixture).is_err());

        let source = fs::read(root.join(LEDGER_RELATIVE_PATH)).expect("read repository ledger");
        let mut fixture = parse_ledger(&source).expect("parse repository ledger");
        fixture
            .files
            .iter_mut()
            .find(|file| file.path == "src/scanner/detector.rs")
            .expect("detector record")
            .components
            .iter_mut()
            .find(|component| component.id == "detector.byte-pattern")
            .expect("byte-pattern component")
            .modern_implementation = Some("venom_artifact::OtherScanner".to_owned());
        assert!(validate_required_component_contracts(&fixture).is_err());
    }

    #[test]
    fn required_api_protocol_split_is_exact_and_fail_closed() {
        let root = super::super::workspace_root();
        let source = fs::read(root.join(LEDGER_RELATIVE_PATH)).expect("read repository ledger");
        let mut fixture = parse_ledger(&source).expect("parse repository ledger");
        validate_required_component_contracts(&fixture).expect("required API protocol split");

        let api = fixture
            .files
            .iter_mut()
            .find(|file| file.path == "src/scanner/api_scanner.rs")
            .expect("API scanner record");
        api.components
            .iter_mut()
            .find(|component| component.id == "api.protocol-taxonomy")
            .expect("GraphQL protocol component")
            .modern_implementation = Some("venom_scanner::legacy_api_scanner".to_owned());
        assert!(validate_required_component_contracts(&fixture).is_err());

        let source = fs::read(root.join(LEDGER_RELATIVE_PATH)).expect("read repository ledger");
        let mut fixture = parse_ledger(&source).expect("parse repository ledger");
        fixture
            .files
            .iter_mut()
            .find(|file| file.path == "src/scanner/api_scanner.rs")
            .expect("API scanner record")
            .components
            .iter_mut()
            .find(|component| component.id == "api.unconditional-tests")
            .expect("fabricated API test component")
            .status = ComponentStatus::Planned;
        assert!(validate_required_component_contracts(&fixture).is_err());
    }

    #[test]
    fn high_priority_summary_counts_only_actionable_components() {
        let mut fixture = ledger();
        fixture.files[0].components[0].priority = Priority::P0;
        let superseded = &mut fixture.files[1].components[0];
        superseded.priority = Priority::P1;
        superseded.status = ComponentStatus::Superseded;
        superseded.disposition = Disposition::SupersededByCurrentRuntime;

        let summary = Summary::from_ledger(&fixture);
        assert_eq!(summary.high_priority_count, 1);
    }

    #[test]
    fn restored_rejected_and_superseded_contracts_accept_complete_records() {
        let mut fixture = ledger();
        let restored = &mut fixture.files[0].components[0];
        restored.status = ComponentStatus::Restored;
        restored.disposition = Disposition::PortAlgorithm;
        restored.modern_destination = ModernDestination::VenomArtifact;
        restored.modern_implementation = Some("venom_artifact::ArtifactScanner".to_owned());

        let rejected = &mut fixture.files[1].components[0];
        rejected.status = ComponentStatus::Rejected;
        rejected.disposition = Disposition::RejectUnsafeAdapter;
        rejected.priority = Priority::Never;
        rejected.modern_destination = ModernDestination::None;
        rejected.prohibited_behaviors = vec![ProhibitedBehavior::UnsafeAdapter];

        let superseded = &mut fixture.files[2].components[0];
        superseded.status = ComponentStatus::Superseded;
        superseded.disposition = Disposition::SupersededByCurrentRuntime;
        assert!(validate_ledger(&fixture).is_ok());
    }

    #[test]
    fn identifiers_facts_and_sets_are_bounded() {
        assert!(validate_component_id("detector.byte-pattern").is_ok());
        assert!(validate_component_id("../detector").is_err());
        assert!(validate_component_id("Detector Path").is_err());
        assert!(validate_fact("rationale", "bounded fact", 32).is_ok());
        assert!(validate_fact("rationale", " ", 32).is_err());
        assert!(validate_fact("rationale", "secret\nsource", 32).is_err());
        assert!(validate_unique_bounded_facts(
            "prerequisites",
            &["review".to_owned(), "review".to_owned()]
        )
        .is_err());
        assert!(validate_unique_prohibitions(&[
            ProhibitedBehavior::UnsafeAdapter,
            ProhibitedBehavior::UnsafeAdapter,
        ])
        .is_err());
    }

    #[test]
    fn digest_is_semantic_order_independent_and_change_sensitive() {
        let original = ledger();
        let expected = semantic_digest(&original);
        let mut reordered = original.clone();
        reordered.files.reverse();
        for file in &mut reordered.files {
            file.components.reverse();
            file.components[0].prerequisites.reverse();
            file.components[0].prohibited_behaviors.reverse();
        }
        assert_eq!(semantic_digest(&reordered), expected);

        let mut changed = original;
        changed.files[0].components[0].disposition = Disposition::RewriteFromContract;
        assert_ne!(semantic_digest(&changed), expected);
        assert_eq!(expected.len(), "salvage-sha256:".len() + 64);
    }

    #[test]
    fn markdown_is_deterministic_escaped_and_change_sensitive() {
        let mut fixture = ledger();
        fixture.files[0].components[0].rationale = "Preserve A | B, not raw source.".to_owned();
        fixture.files[0].components[0].priority = Priority::P0;
        fixture.ledger_digest = semantic_digest(&fixture);
        let first = render_markdown(&fixture);
        let second = render_markdown(&fixture);
        assert_eq!(first, second);
        assert!(first.contains("Preserve A \\| B"));
        assert!(first.contains("Historical file inventory"));
        let mut changed = fixture;
        changed.files[0].components[0].rationale = "Changed rationale.".to_owned();
        assert_ne!(render_markdown(&changed), first);
    }

    #[test]
    fn git_tree_parser_requires_regular_blobs_and_exact_sizes() {
        let parsed = parse_ls_tree(
            "100644 blob ce5ddb0590e12dead0a57553d4391ffc36e20e67   10718\tsrc/scanner/analyzer.rs\n",
        )
        .expect("parse tree");
        assert_eq!(parsed["src/scanner/analyzer.rs"].byte_size, 10_718);
        assert!(parse_ls_tree(
            "120000 blob ce5ddb0590e12dead0a57553d4391ffc36e20e67 7\tsrc/scanner/link.rs"
        )
        .is_err());
        assert!(parse_ls_tree("malformed").is_err());
    }

    #[test]
    fn historical_tree_comparison_rejects_missing_extra_and_changed_blobs() {
        let fixture = ledger();
        let expected_tree = fixture
            .files
            .iter()
            .map(|file| {
                (
                    file.path.clone(),
                    GitBlob {
                        sha: file.blob_sha.clone(),
                        byte_size: file.byte_size,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert!(validate_tree_against_ledger(&expected_tree, &fixture).is_ok());

        let mut missing = expected_tree.clone();
        missing.remove(&fixture.files[0].path);
        assert!(validate_tree_against_ledger(&missing, &fixture).is_err());

        let mut changed_sha = expected_tree.clone();
        changed_sha.get_mut(&fixture.files[0].path).unwrap().sha = "f".repeat(40);
        assert!(validate_tree_against_ledger(&changed_sha, &fixture).is_err());

        let mut changed_size = expected_tree;
        changed_size
            .get_mut(&fixture.files[0].path)
            .unwrap()
            .byte_size += 1;
        assert!(validate_tree_against_ledger(&changed_size, &fixture).is_err());
    }

    #[test]
    fn report_comparison_normalizes_only_platform_line_endings() {
        assert_eq!(normalize_line_endings("a\r\nb\r\n"), "a\nb\n");
        assert_eq!(normalize_line_endings("a\nb\n"), "a\nb\n");
        assert_ne!(normalize_line_endings("a\rb"), "a\nb");
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
    fn local_repository_contract_requires_no_git_history() {
        const EXPECTED_DIGEST: &str =
            "salvage-sha256:c2e4fec16f5d044ea2007f134ed18389f2b6890c621159d3554bafcf4be8e333";

        let repository = super::super::workspace_root();
        let temporary = TempDir::new().expect("temporary directory");
        for relative in [LEDGER_RELATIVE_PATH, REPORT_RELATIVE_PATH] {
            let destination = temporary.path().join(relative);
            fs::create_dir_all(destination.parent().expect("fixture parent"))
                .expect("create fixture parent");
            fs::copy(repository.join(relative), destination).expect("copy repository fixture");
        }
        assert!(!temporary.path().join(".git").exists());

        let digest = validate_repository_contract_without_history(temporary.path())
            .expect("local semantic contract without Git history");
        assert_eq!(digest, EXPECTED_DIGEST);

        let ledger_path = temporary.path().join(LEDGER_RELATIVE_PATH);
        let original_ledger = fs::read_to_string(&ledger_path).expect("read copied ledger");
        let stale_ledger = original_ledger.replace(
            EXPECTED_DIGEST,
            &format!("{DIGEST_PREFIX}:{}", "0".repeat(64)),
        );
        fs::write(&ledger_path, stale_ledger).expect("write stale digest fixture");
        assert!(validate_repository_contract_without_history(temporary.path()).is_err());

        fs::write(&ledger_path, original_ledger).expect("restore ledger fixture");
        let report_path = temporary.path().join(REPORT_RELATIVE_PATH);
        let mut stale_report = fs::read_to_string(&report_path).expect("read copied report");
        stale_report.push_str("\nstale\n");
        fs::write(report_path, stale_report).expect("write stale report fixture");
        assert!(validate_repository_contract_without_history(temporary.path()).is_err());
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
    fn actual_historical_tree_has_the_expected_closed_inventory() {
        let root = super::super::workspace_root();
        if git_success(
            &root,
            &["cat-file", "-e", &format!("{SOURCE_SNAPSHOT}^{{commit}}")],
        )
        .is_err()
        {
            // Shallow compatibility checkouts exercise the pure validator tests;
            // the dedicated scanner-salvage command requires full local history.
            return;
        }
        let tree = historical_tree(&root, SOURCE_SNAPSHOT).expect("historical objects available");
        assert_eq!(tree.len(), EXPECTED_FILE_COUNT);
        assert!(tree.contains_key("src/scanner/detector.rs"));
        assert!(tree.contains_key("src/scanner/ml_detection.rs"));
        assert!(tree.contains_key("src/scanner/xss_payloads.rs"));
    }

    #[test]
    fn repository_ledger_and_generated_report_validate_together() {
        let root = super::super::workspace_root();
        if !root.join(LEDGER_RELATIVE_PATH).is_file()
            || git_success(
                &root,
                &["cat-file", "-e", &format!("{SOURCE_SNAPSHOT}^{{commit}}")],
            )
            .is_err()
        {
            return;
        }
        run(&root, false).expect("repository salvage ledger and report are current");
    }
}
