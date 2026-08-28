//! Transport-capability ownership policy for scanner runtimes.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use proc_macro2::{TokenStream, TokenTree};
use syn::{
    visit::{self, Visit},
    Item, ItemExternCrate, ItemMod, ItemUse, Macro, Path as SynPath,
};

use super::{
    collect_use_paths, display_path, has_cfg_test, ident_name, is_colon, is_punctuation,
    item_attributes, normalize_identifier,
};

/// Production modules that consume the bounded standard decision runtime.
const BOUNDED_RUNTIME_SOURCES: &[&str] = &[
    "crates/venom-cli/src/assessment_scan.rs",
    "crates/venom-scanner/src/decision_loop.rs",
    "crates/venom-scanner/src/decision_runner.rs",
    ASSESSMENT_ITEM_SOURCE,
    "crates/venom-scanner/src/web_runtime/assessment_passive.rs",
    "crates/venom-scanner/src/web_runtime/assessment_report.rs",
    "crates/venom-scanner/src/web_runtime/assessment_defense.rs",
    "crates/venom-scanner/src/http_evidence.rs",
    "crates/venom-scanner/src/http_evidence/form_controls.rs",
    "crates/venom-scanner/src/payload_strategy.rs",
    "crates/venom-scanner/src/planner.rs",
    "crates/venom-scanner/src/runtime_budget.rs",
    "crates/venom-scanner/src/web_runtime/scan_profile.rs",
    "crates/venom-scanner/src/verification.rs",
    "crates/venom-scanner/src/web_actions.rs",
    "crates/venom-scanner/src/web_runtime/web_assessment.rs",
    "crates/venom-scanner/src/web_runtime/web_assessment/discovery.rs",
    "crates/venom-scanner/src/web_runtime/web_assessment/semantic.rs",
    "crates/venom-scanner/src/web_decision.rs",
    "crates/venom-scanner/src/web_execution.rs",
    "crates/venom-scanner/src/web_planning.rs",
    "crates/venom-scanner/src/web_reasoning.rs",
    "crates/venom-scanner/src/web_runtime.rs",
    "crates/venom-scanner/src/web_runtime/authority.rs",
    "crates/venom-scanner/src/web_runtime/api_visibility.rs",
    "crates/venom-scanner/src/web_runtime/api_visibility/differential.rs",
    "crates/venom-scanner/src/web_runtime/api_visibility/differential/execution.rs",
    "crates/venom-scanner/src/web_verification.rs",
];

/// The sole raw HTTP-client owner in the bounded runtime.
const TRANSPORT_OWNER_SOURCE: &str = "crates/venom-scanner/src/http_evidence/request_broker.rs";
const SHARED_RUNTIME_AUTHORITY_SOURCE: &str = "crates/venom-scanner/src/web_runtime/authority.rs";
const LEGACY_DISCOVERY_AUTHORITY_SOURCE: &str = "crates/venom-scanner/src/legacy_discovery.rs";
const ASSESSMENT_ITEM_SOURCE: &str = "crates/venom-scanner/src/web_runtime/assessment_item.rs";
const ASSESSMENT_REPORT_SOURCE: &str = "crates/venom-scanner/src/web_runtime/assessment_report.rs";
const KNOWLEDGE_SOURCE: &str = "crates/venom-scanner/src/knowledge.rs";

const ASSESSMENT_EXTERNAL_TRAIT_PROTECTED_TYPES: &[&str] = &[
    "AssessmentBasis",
    "AssessmentDifferentialBasis",
    "AssessmentItem",
    "AssessmentItemSet",
    "AssessmentObservationBasis",
    "AssessmentProjectionContext",
    "AssessmentVerifierBasis",
];

const ASSESSMENT_FORBIDDEN_EXTERNAL_TRAITS: &[&str] =
    &["Clone", "Copy", "Deserialize", "Serialize"];

const ASSESSMENT_ITEM_PUBLIC_EXPORTS: &[&str] = &[
    "ASSESSMENT_ITEM_SCHEMA",
    "MAX_ASSESSMENT_CAPABILITY_ID_BYTES",
    "MAX_ASSESSMENT_DISPLAY_BYTES",
    "MAX_ASSESSMENT_ITEM_EVIDENCE_REFERENCES",
    "MAX_ASSESSMENT_ITEM_SET_ITEMS",
    "AssessmentBasis",
    "AssessmentCaseReference",
    "AssessmentConfirmationDenial",
    "AssessmentDifferentialBasis",
    "AssessmentDisposition",
    "AssessmentEvidenceReference",
    "AssessmentItem",
    "AssessmentItemProjectionError",
    "AssessmentObservationBasis",
    "AssessmentOutcomeReference",
    "AssessmentRemediation",
    "AssessmentSubjectReference",
    "AssessmentVerifierBasis",
];

const ASSESSMENT_PROJECTION_CONTEXT_LIMITS: &[(&str, usize)] = &[
    ("MAX_PROJECTION_SUBJECTS", 1_024),
    ("MAX_PROJECTION_QUERY_NAMES_PER_SUBJECT", 256),
    ("MAX_PROJECTION_CASES", 10_000),
    ("MAX_PROJECTION_OUTCOMES", 10_000),
    ("MAX_PROJECTION_EVIDENCE", 262_144),
    ("MAX_PROJECTION_SUBJECT_ID_BYTES", 16_384),
    ("MAX_PROJECTION_RUNTIME_ID_BYTES", 1_024),
];

const WEB_ASSESSMENT_PUBLIC_EXPORTS: &[&str] = &[
    "DEFAULT_WEB_ASSESSMENT_MAX_ACTIVE_VERIFICATIONS",
    "DEFAULT_WEB_ASSESSMENT_MAX_CANONICAL_URL_BYTES",
    "DEFAULT_WEB_ASSESSMENT_MAX_CONTROLS_PER_FORM",
    "DEFAULT_WEB_ASSESSMENT_MAX_DEPTH",
    "DEFAULT_WEB_ASSESSMENT_MAX_FORMS",
    "DEFAULT_WEB_ASSESSMENT_MAX_QUERY_NAMES",
    "DEFAULT_WEB_ASSESSMENT_MAX_REFERENCES_PER_DOCUMENT",
    "DEFAULT_WEB_ASSESSMENT_MAX_RESPONSE_BODY_BYTES",
    "DEFAULT_WEB_ASSESSMENT_MAX_RETAINED_URL_BYTES",
    "DEFAULT_WEB_ASSESSMENT_MAX_SUBJECTS",
    "DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_REQUESTS",
    "DEFAULT_WEB_ASSESSMENT_MAX_TOTAL_RESPONSE_BYTES",
    "DEFAULT_WEB_ASSESSMENT_MAX_WALL_TIME",
    "HARD_MAX_WEB_ASSESSMENT_ACTIVE_VERIFICATIONS",
    "HARD_MAX_WEB_ASSESSMENT_CANONICAL_URL_BYTES",
    "HARD_MAX_WEB_ASSESSMENT_CONTROLS_PER_FORM",
    "HARD_MAX_WEB_ASSESSMENT_DEPTH",
    "HARD_MAX_WEB_ASSESSMENT_FORMS",
    "HARD_MAX_WEB_ASSESSMENT_QUERY_NAMES",
    "HARD_MAX_WEB_ASSESSMENT_REFERENCES_PER_DOCUMENT",
    "HARD_MAX_WEB_ASSESSMENT_RESPONSE_BODY_BYTES",
    "HARD_MAX_WEB_ASSESSMENT_RETAINED_URL_BYTES",
    "HARD_MAX_WEB_ASSESSMENT_SUBJECTS",
    "HARD_MAX_WEB_ASSESSMENT_TOTAL_REQUESTS",
    "HARD_MAX_WEB_ASSESSMENT_TOTAL_RESPONSE_BYTES",
    "HARD_MAX_WEB_ASSESSMENT_WALL_TIME",
    "WEB_ASSESSMENT_CONCURRENCY",
    "WebAssessmentCompletion",
    "WebAssessmentDefenseAudit",
    "WebAssessmentDefenseBodyCoverage",
    "WebAssessmentDefenseMode",
    "WebAssessmentDefenseObservation",
    "WebAssessmentDefenseShadowPlan",
    "WebAssessmentDefenseTransition",
    "WebAssessmentFailureReceipt",
    "WebAssessmentForm",
    "WebAssessmentFormMethod",
    "WebAssessmentIncompleteReason",
    "WebAssessmentLimits",
    "WebAssessmentLimitsError",
    "WebAssessmentMethod",
    "WebAssessmentRunReport",
    "WebAssessmentRuntime",
    "WebAssessmentRuntimeBuilder",
    "WebAssessmentRuntimeError",
    "WebAssessmentSubject",
    "WebAssessmentSubjectOrigin",
    "WebAssessmentSubjectReport",
    "WebAssessmentUsage",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BrokerConstructorKind {
    RequestAccounting,
    MeteredHttp,
}

impl BrokerConstructorKind {
    const fn label(self) -> &'static str {
        match self {
            Self::RequestAccounting => "RequestAccountingBroker::new",
            Self::MeteredHttp => "HttpRequestBroker::new_metered",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ExpectedBrokerConstructor {
    source: &'static str,
    kind: BrokerConstructorKind,
    impl_target: &'static str,
    function: &'static str,
}

const EXPECTED_BROKER_CONSTRUCTORS: &[ExpectedBrokerConstructor] = &[
    ExpectedBrokerConstructor {
        source: SHARED_RUNTIME_AUTHORITY_SOURCE,
        kind: BrokerConstructorKind::RequestAccounting,
        impl_target: "SharedWebRuntimeAuthority",
        function: "new_exact_origin",
    },
    ExpectedBrokerConstructor {
        source: SHARED_RUNTIME_AUTHORITY_SOURCE,
        kind: BrokerConstructorKind::MeteredHttp,
        impl_target: "SharedWebRuntimeAuthority",
        function: "new_exact_origin",
    },
    ExpectedBrokerConstructor {
        source: LEGACY_DISCOVERY_AUTHORITY_SOURCE,
        kind: BrokerConstructorKind::RequestAccounting,
        impl_target: "LegacyDiscoveryAuthority",
        function: "new",
    },
    ExpectedBrokerConstructor {
        source: LEGACY_DISCOVERY_AUTHORITY_SOURCE,
        kind: BrokerConstructorKind::MeteredHttp,
        impl_target: "LegacyDiscoveryAuthority",
        function: "new",
    },
    ExpectedBrokerConstructor {
        source: LEGACY_DISCOVERY_AUTHORITY_SOURCE,
        kind: BrokerConstructorKind::RequestAccounting,
        impl_target: "LegacyVerificationAuthority",
        function: "new",
    },
    ExpectedBrokerConstructor {
        source: LEGACY_DISCOVERY_AUTHORITY_SOURCE,
        kind: BrokerConstructorKind::MeteredHttp,
        impl_target: "LegacyVerificationAuthority",
        function: "new",
    },
];

/// Legacy sources migrated behind context-owned exact-origin, metered
/// authorities. Discovery and verification have distinct finite envelopes;
/// phase consumers must never regain the public raw client or construct a
/// second transport capability.
const MIGRATED_LEGACY_DISCOVERY_SOURCES: &[&str] = &[
    LEGACY_DISCOVERY_AUTHORITY_SOURCE,
    "crates/venom-scanner/src/phases/phase2_crawl.rs",
    "crates/venom-scanner/src/phases/phase3_fuzzer.rs",
    "crates/venom-scanner/src/phases/phase4_param.rs",
    "crates/venom-scanner/src/phases/phase5_sqli.rs",
    "crates/venom-scanner/src/phases/phase6_xss.rs",
    "crates/venom-scanner/src/phases/phase7_ssti.rs",
    "crates/venom-scanner/src/phases/phase8_lfi_xxe.rs",
    "crates/venom-scanner/src/phases/phase9_ssrf.rs",
];

const LEGACY_VERIFICATION_PHASE_SOURCES: &[&str] = &[
    "crates/venom-scanner/src/phases/phase5_sqli.rs",
    "crates/venom-scanner/src/phases/phase6_xss.rs",
    "crates/venom-scanner/src/phases/phase7_ssti.rs",
    "crates/venom-scanner/src/phases/phase8_lfi_xxe.rs",
    "crates/venom-scanner/src/phases/phase9_ssrf.rs",
];

const LEGACY_CLAIM_BRIDGE_PHASE_SOURCES: &[&str] = &[
    "crates/venom-scanner/src/phases/phase5_sqli.rs",
    "crates/venom-scanner/src/phases/phase7_ssti.rs",
    "crates/venom-scanner/src/phases/phase8_lfi_xxe.rs",
];

/// Existing standalone facades that intentionally construct an unmetered
/// broker because they execute outside `StandardWebDecisionRuntime`.
///
/// Keep this inventory exact: bounded runtime modules, including paired API
/// visibility collection, must never be added here.
const UNMETERED_STANDALONE_FACADE_SOURCES: &[&str] = &[
    "crates/venom-scanner/src/http_evidence.rs",
    "crates/venom-scanner/src/web_execution.rs",
];

/// Exact raw-client source inventory. Entries other than the broker owner are
/// legacy and are not covered by `RuntimeBudget`.
const DIRECT_CLIENT_SOURCE_ALLOWLIST: &[&str] = &[
    "crates/venom-cli/src/main.rs",
    "crates/venom-scanner/src/context.rs",
    TRANSPORT_OWNER_SOURCE,
    "crates/venom-scanner/src/sdk.rs",
];

/// Exact production `.send()` inventory for the legacy phase pipeline.
const LEGACY_PHASE_SEND_ALLOWLIST: &[(&str, usize)] =
    &[("crates/venom-scanner/src/phases/phase1_recon.rs", 1)];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut violations = validate_policy_inventory();
    let legacy_authority_aliases = collect_full_tree_legacy_authority_aliases(workspace_root)?;

    for source_name in BOUNDED_RUNTIME_SOURCES {
        let source = fs::read_to_string(workspace_root.join(source_name))?;
        violations.extend(inspect_bounded_source_with_legacy_aliases(
            source_name,
            &source,
            &legacy_authority_aliases,
        )?);
    }
    for source_name in MIGRATED_LEGACY_DISCOVERY_SOURCES {
        let source = fs::read_to_string(workspace_root.join(source_name))?;
        violations.extend(inspect_migrated_discovery_source(source_name, &source)?);
        if LEGACY_VERIFICATION_PHASE_SOURCES.contains(source_name) {
            violations.extend(inspect_legacy_verification_claim_language(
                source_name,
                &source,
            ));
        }
    }

    violations.extend(broker_constructor_inventory_violations(workspace_root)?);
    violations.extend(web_assessment_contract_violations(workspace_root)?);

    let expected_clients: BTreeSet<_> = DIRECT_CLIENT_SOURCE_ALLOWLIST
        .iter()
        .map(|source| (*source).to_owned())
        .collect();
    let actual_clients = direct_client_sources(workspace_root)?;
    for source in actual_clients.difference(&expected_clients) {
        violations.push(format!(
            "{source} acquires a direct network client outside the exact transport-owner/legacy allowlist"
        ));
    }
    for source in expected_clients.difference(&actual_clients) {
        violations.push(format!(
            "direct-client source allowlist contains stale entry {source}; update the inventory deliberately"
        ));
    }

    let expected_sends: BTreeMap<_, _> = LEGACY_PHASE_SEND_ALLOWLIST
        .iter()
        .map(|(source, count)| ((*source).to_owned(), *count))
        .collect();
    let actual_sends = legacy_send_inventory(workspace_root)?;
    let send_sources: BTreeSet<_> = expected_sends
        .keys()
        .chain(actual_sends.keys())
        .cloned()
        .collect();
    for source in send_sources {
        let expected = expected_sends.get(&source).copied().unwrap_or(0);
        let actual = actual_sends.get(&source).copied().unwrap_or(0);
        if actual != expected {
            violations.push(format!(
                "legacy direct-I/O source {source} contains {actual} production .send() calls; exact allowlist requires {expected}"
            ));
        }
    }

    Ok(violations)
}

fn web_assessment_contract_violations(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let assessment = fs::read_to_string(
        workspace_root.join("crates/venom-scanner/src/web_runtime/web_assessment.rs"),
    )?;
    let discovery = fs::read_to_string(
        workspace_root.join("crates/venom-scanner/src/web_runtime/web_assessment/discovery.rs"),
    )?;
    let semantic = fs::read_to_string(
        workspace_root.join("crates/venom-scanner/src/web_runtime/web_assessment/semantic.rs"),
    )?;
    let passive = fs::read_to_string(
        workspace_root.join("crates/venom-scanner/src/web_runtime/assessment_passive.rs"),
    )?;
    let passive_headers = fs::read_to_string(
        workspace_root.join("crates/venom-scanner/src/http_evidence/passive_review.rs"),
    )?;
    let assessment_item = fs::read_to_string(workspace_root.join(ASSESSMENT_ITEM_SOURCE))?;
    let assessment_report = fs::read_to_string(workspace_root.join(ASSESSMENT_REPORT_SOURCE))?;
    let knowledge = fs::read_to_string(workspace_root.join(KNOWLEDGE_SOURCE))?;
    let http_evidence =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/http_evidence.rs"))?;
    let broker = fs::read_to_string(workspace_root.join(TRANSPORT_OWNER_SOURCE))?;
    let facade =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/web_runtime.rs"))?;
    let mut violations = Vec::new();

    for (source_name, source) in [
        (
            "crates/venom-scanner/src/web_runtime/web_assessment.rs",
            assessment.as_str(),
        ),
        (
            "crates/venom-scanner/src/web_runtime/web_assessment/discovery.rs",
            discovery.as_str(),
        ),
        (
            "crates/venom-scanner/src/web_runtime/web_assessment/semantic.rs",
            semantic.as_str(),
        ),
        (
            "crates/venom-scanner/src/web_runtime/assessment_passive.rs",
            passive.as_str(),
        ),
        (ASSESSMENT_ITEM_SOURCE, assessment_item.as_str()),
    ] {
        for forbidden in [
            "HttpRequestBroker",
            "RequestAccountingBroker",
            "reqwest",
            "legacy_discovery",
            "ScanPhase",
            "RESPONSE_BODY_SAMPLE",
            "TextSample",
        ] {
            if source.contains(forbidden) {
                violations.push(format!(
                    "{source_name} references forbidden assessment capability `{forbidden}`; reuse only the shared standard runtime authority"
                ));
            }
        }
    }
    for (required, label) in [
        (
            "WEB_ASSESSMENT_CONCURRENCY: usize = 1",
            "fixed sequential execution",
        ),
        (
            "projection_from_committed_bootstrap",
            "post-commit evidence replay",
        ),
    ] {
        if !assessment.contains(required) {
            violations.push(format!(
                "origin assessment lost required {label} marker `{required}`"
            ));
        }
    }
    violations.extend(inspect_web_assessment_composition(&assessment)?);
    violations.extend(inspect_web_assessment_models(&assessment)?);
    violations.extend(inspect_web_assessment_facade(&facade)?);
    violations.extend(inspect_assessment_item_facade(&facade)?);
    violations.extend(inspect_assessment_item_projection(&assessment_item)?);
    violations.extend(inspect_assessment_report_boundary(&assessment_report)?);
    violations.extend(inspect_knowledge_authority_accessor(&knowledge)?);
    violations.extend(inspect_cross_source_assessment_bypasses(workspace_root)?);
    violations.extend(inspect_assessment_semantic_markers(&semantic));
    violations.extend(inspect_assessment_passive_markers(
        &passive_headers,
        &passive,
        &http_evidence,
    ));
    violations.extend(inspect_complete_observer_seam(&http_evidence)?);
    violations.extend(inspect_assessment_transport_markers(
        &http_evidence,
        &broker,
    ));
    Ok(violations)
}

fn inspect_assessment_semantic_markers(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (required, boundary) in [
        ("commit_bootstrap", "committed-receipt input boundary"),
        (
            "knowledge.evidence(evidence.id()).as_ref() != Some(evidence)",
            "exact live knowledge cross-check",
        ),
        (
            "extract_from_web_assessment_evidence",
            "strict assessment semantic projector",
        ),
        (
            "SemanticExtractionLimits::new",
            "checked semantic limit construction",
        ),
    ] {
        if !source.contains(required) {
            violations.push(format!(
                "assessment semantic composition lost {boundary} marker `{required}`"
            ));
        }
    }
    for forbidden in [
        "extract_from_snapshot",
        "evidence_for_subject",
        "evidence_for_predicate",
        "snapshot_for_subject",
    ] {
        if source.contains(forbidden) {
            violations.push(format!(
                "assessment semantic composition references `{forbidden}`; consume only exact evidence ids from committed receipts"
            ));
        }
    }
    violations
}

fn inspect_assessment_passive_markers(
    header_projection: &str,
    committed_projection: &str,
    http_evidence: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (marker, boundary) in [
        (
            "MAX_PASSIVE_HEADER_OCCURRENCES: usize = 8",
            "header occurrence ceiling",
        ),
        (
            "MAX_PASSIVE_HEADER_VALUE_BYTES: usize = 8 * 1024",
            "header value ceiling",
        ),
        (
            "MAX_PASSIVE_SET_COOKIE_OCCURRENCES: usize = 16",
            "Set-Cookie occurrence ceiling",
        ),
        (
            "MAX_PASSIVE_DERIVED_OBSERVATIONS: usize = 160",
            "derived observation ceiling",
        ),
        (
            "PassiveProjectionState::ProjectionIncomplete",
            "explicit incomplete state",
        ),
    ] {
        if !header_projection.contains(marker) {
            violations.push(format!(
                "passive header projection lost {boundary} marker `{marker}`"
            ));
        }
    }
    for forbidden in [
        "reqwest::Client",
        "RequestBuilder",
        "HttpRequestBroker",
        "RequestAccountingBroker",
        "RuntimeBudget",
        ".send(",
    ] {
        if header_projection.contains(forbidden) {
            violations.push(format!(
                "passive header projection contains forbidden transport authority `{forbidden}`"
            ));
        }
    }
    let committed_syntax = syn::parse_file(committed_projection);
    for forbidden in [
        "HeaderMap",
        "HeaderValue",
        "reqwest",
        "HttpRequestBroker",
        "RequestAccountingBroker",
    ] {
        if committed_syntax
            .as_ref()
            .is_ok_and(|syntax| syntax_references_exact_ident(syntax, forbidden))
        {
            violations.push(format!(
                "committed passive projection crosses the value-free boundary with `{forbidden}`"
            ));
        }
    }
    if committed_projection.contains("response.headers") {
        violations.push(
            "committed passive projection crosses the value-free boundary with `response.headers`"
                .to_owned(),
        );
    }
    if let Err(error) = &committed_syntax {
        violations.push(format!(
            "committed passive projection could not be parsed for value-free boundary checks: {error}"
        ));
    }
    for (marker, boundary) in [
        (
            "receipt.case().action_id() != BOOTSTRAP_ACTION_ID",
            "bootstrap action correlation",
        ),
        (
            "receipt.case().hypothesis_id() != BOOTSTRAP_HYPOTHESIS_ID",
            "bootstrap hypothesis correlation",
        ),
        (
            "receipt.case().payload_strategy().is_some()",
            "payload-free bootstrap boundary",
        ),
        (
            "!receipt.case().applies_hypothesis_transition()",
            "bootstrap transition policy",
        ),
        (
            "knowledge.evidence(evidence.id()).as_ref() != Some(evidence)",
            "exact committed knowledge replay",
        ),
        (
            "self.observations.len() >= HARD_MAX_WEB_ASSESSMENT_SUBJECTS",
            "passive ledger observation ceiling",
        ),
        (
            "if let Some(existing) = self.receipt_evidence.get(&key)",
            "same-key replay comparison",
        ),
    ] {
        if !committed_projection.contains(marker) {
            violations.push(format!(
                "committed passive projection lost {boundary} marker `{marker}`"
            ));
        }
    }
    if committed_projection.contains("let mut prospective = self.clone()") {
        violations.push(
            "committed passive ledger must validate before mutation without cloning the full ledger"
                .to_owned(),
        );
    }
    for (marker, boundary) in [
        (
            "let passive_response_projection = project_passive_response(&response.headers);",
            "raw-header-local projection",
        ),
        (
            "passive_response_projection: &passive_response_projection",
            "borrowed value-free observer handoff",
        ),
        (
            "if self.complete_response_observer.is_none()",
            "legacy cookie extraction quarantine",
        ),
    ] {
        if !http_evidence.contains(marker) {
            violations.push(format!(
                "HTTP evidence seam lost {boundary} marker `{marker}`"
            ));
        }
    }

    match syn::parse_file(header_projection) {
        Ok(syntax) => {
            let cookie = syntax.items.iter().find_map(|item| match item {
                Item::Struct(item) if item.ident == "PassiveCookieMetadata" => Some(item),
                _ => None,
            });
            let expected = [
                "domain_attribute_present",
                "http_only",
                "name",
                "path_attribute_present",
                "same_site",
                "secure",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
            let observed = cookie
                .into_iter()
                .flat_map(|item| item.fields.iter())
                .filter_map(|field| field.ident.as_ref().map(ident_name))
                .collect::<BTreeSet<_>>();
            if observed != expected {
                violations.push(
                    "PassiveCookieMetadata must retain only a bounded name and value-free attribute metadata"
                        .to_owned(),
                );
            }
            let custom_redacted_debug = syntax.items.iter().any(|item| {
                matches!(item, Item::Impl(item_impl)
                    if item_impl.trait_.as_ref().is_some_and(|(_, path, _)|
                        path.segments.last().is_some_and(|segment| segment.ident == "Debug"))
                        && matches!(item_impl.self_ty.as_ref(), syn::Type::Path(path)
                            if path.path.segments.last().is_some_and(|segment|
                                segment.ident == "PassiveCookieMetadata")))
            });
            if !custom_redacted_debug {
                violations.push(
                    "PassiveCookieMetadata must use a custom redacted Debug implementation"
                        .to_owned(),
                );
            }
        },
        Err(error) => violations.push(format!(
            "passive header projection could not be parsed for architecture checks: {error}"
        )),
    }
    violations
}

fn inspect_assessment_transport_markers(http_evidence: &str, broker: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !http_evidence.contains("complete_response_observer_seal::Sealed")
        || !http_evidence
            .contains("impl Sealed for crate::web_runtime::AssessmentDiscoveryObserver {}")
    {
        violations.push(
            "complete-body response observer must remain sealed to the exact assessment implementation"
                .to_owned(),
        );
    }
    if !http_evidence.contains("restricted.captured_headers.clear();") {
        violations.push(
            "assessment HTTP policy must clear every raw captured response header".to_owned(),
        );
    }
    if broker.matches(".redirect(RedirectPolicy::none())").count() != 1 {
        violations.push(
            "the sole production request broker must configure exactly one redirect-disabled client"
                .to_owned(),
        );
    }
    if broker.matches("body_complete = true;").count() != 1
        || !broker.contains("let Some(chunk) = response.chunk().await")
    {
        violations.push(
            "complete-body authority must be granted exactly once at observed response-stream EOF"
                .to_owned(),
        );
    }
    violations
}

fn inspect_web_assessment_composition(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = AssessmentCompositionVisitor::default();
    visitor.visit_file(&syntax);
    let mut violations = visitor.violations.into_iter().collect::<Vec<_>>();
    if visitor.authority_calls != 1 {
        violations.push(format!(
            "origin assessment must construct SharedWebRuntimeAuthority exactly once in WebAssessmentRuntimeBuilder::build; observed {} direct calls",
            visitor.authority_calls
        ));
    }
    if visitor.shared_child_builds != 1 {
        violations.push(format!(
            "origin assessment must contain exactly one standard child build_with_shared_authority composition point; observed {}",
            visitor.shared_child_builds
        ));
    }
    if visitor.standalone_build_calls != 0 {
        violations.push(format!(
            "origin assessment contains {} standalone .build() calls; every standard child must use build_with_shared_authority",
            visitor.standalone_build_calls
        ));
    }
    if visitor.runtime_start_calls != 1 {
        violations.push(format!(
            "origin assessment reporting must capture SystemTime::now exactly once at the unconditional WebAssessmentRuntime::analyze start; observed {} calls",
            visitor.runtime_start_calls
        ));
    }
    if visitor.runtime_start_bindings != 1 {
        violations.push(format!(
            "origin assessment reporting must bind its runtime start behind exactly one cfg(reporting) local; observed {} bindings",
            visitor.runtime_start_bindings
        ));
    }
    if visitor.report_start_assignments != 1 {
        violations.push(format!(
            "WebAssessmentRunReport must receive exactly one cfg(reporting) run_started_at assignment from the runtime-owned local; observed {} assignments",
            visitor.report_start_assignments
        ));
    }
    Ok(violations)
}

#[derive(Default)]
struct AssessmentCompositionVisitor {
    current_impl: Option<String>,
    current_function: Option<String>,
    control_depth: usize,
    closure_depth: usize,
    authority_calls: usize,
    shared_child_builds: usize,
    standalone_build_calls: usize,
    runtime_start_calls: usize,
    runtime_start_bindings: usize,
    report_start_assignments: usize,
    violations: BTreeSet<String>,
}

impl AssessmentCompositionVisitor {
    fn in_control_flow(&mut self, visit: impl FnOnce(&mut Self)) {
        self.control_depth = self.control_depth.saturating_add(1);
        visit(self);
        self.control_depth = self.control_depth.saturating_sub(1);
    }

    fn current_boundary(&self) -> (&str, &str) {
        (
            self.current_impl.as_deref().unwrap_or("<free>"),
            self.current_function.as_deref().unwrap_or("<none>"),
        )
    }
}

impl<'ast> Visit<'ast> for AssessmentCompositionVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let prior = self.current_impl.take();
        self.current_impl = match item.self_ty.as_ref() {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| ident_name(&segment.ident)),
            _ => None,
        };
        visit::visit_item_impl(self, item);
        self.current_impl = prior;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let prior = self.current_function.replace(ident_name(&item.sig.ident));
        visit::visit_impl_item_fn(self, item);
        self.current_function = prior;
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let prior_impl = self.current_impl.take();
        let prior_function = self.current_function.replace(ident_name(&item.sig.ident));
        visit::visit_item_fn(self, item);
        self.current_impl = prior_impl;
        self.current_function = prior_function;
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = expression.func.as_ref() {
            let segments = path_segments(&path.path);
            if segments.len() == 2
                && normalize_identifier(&segments[0]) == "SystemTime"
                && normalize_identifier(&segments[1]) == "now"
            {
                self.runtime_start_calls = self.runtime_start_calls.saturating_add(1);
                let (impl_name, function_name) = self.current_boundary();
                if impl_name != "WebAssessmentRuntime"
                    || function_name != "analyze"
                    || self.control_depth != 0
                    || self.closure_depth != 0
                {
                    self.violations.insert(format!(
                        "SystemTime::now must remain one unconditional runtime-owned capture in WebAssessmentRuntime::analyze, not {impl_name}::{function_name}"
                    ));
                }
            }
            if segments.len() >= 2
                && segments
                    .last()
                    .is_some_and(|value| normalize_identifier(value) == "new_exact_origin")
                && segments
                    .get(segments.len() - 2)
                    .is_some_and(|value| normalize_identifier(value) == "SharedWebRuntimeAuthority")
            {
                self.authority_calls = self.authority_calls.saturating_add(1);
                let (impl_name, function_name) = self.current_boundary();
                if impl_name != "WebAssessmentRuntimeBuilder"
                    || function_name != "build"
                    || self.control_depth != 0
                    || self.closure_depth != 0
                {
                    self.violations.insert(format!(
                        "SharedWebRuntimeAuthority::new_exact_origin must be one unconditional direct call in WebAssessmentRuntimeBuilder::build, not {impl_name}::{function_name}"
                    ));
                }
            }
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if matches!(&local.pat, syn::Pat::Ident(pattern)
            if pattern.ident == "run_started_at"
                && pattern.by_ref.is_none()
                && pattern.mutability.is_none()
                && pattern.subpat.is_none())
        {
            self.runtime_start_bindings = self.runtime_start_bindings.saturating_add(1);
            let (impl_name, function_name) = self.current_boundary();
            let exact_initializer = local.init.as_ref().is_some_and(|init| {
                init.diverge.is_none()
                    && matches!(init.expr.as_ref(), syn::Expr::Call(call)
                        if expression_path_ends_with(call.func.as_ref(), &["SystemTime", "now"])
                            && call.args.is_empty())
            });
            if impl_name != "WebAssessmentRuntime"
                || function_name != "analyze"
                || !attributes_are_exact_cfg_feature(&local.attrs, "reporting")
                || !exact_initializer
            {
                self.violations.insert(
                    "run_started_at must remain one exact cfg(reporting) SystemTime::now local in WebAssessmentRuntime::analyze"
                        .to_owned(),
                );
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if matches!(&field.member, syn::Member::Named(member)
            if ident_name(member) == "run_started_at")
        {
            self.report_start_assignments = self.report_start_assignments.saturating_add(1);
            let (impl_name, function_name) = self.current_boundary();
            if impl_name != "WebAssessmentRuntime"
                || function_name != "analyze"
                || !attributes_are_exact_cfg_feature(&field.attrs, "reporting")
                || !expression_is_path_ident(&field.expr, "run_started_at")
            {
                self.violations.insert(
                    "run_started_at report construction must remain the exact cfg(reporting) runtime-owned local assignment"
                        .to_owned(),
                );
            }
        }
        visit::visit_field_value(self, field);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        match normalize_identifier(&ident_name(&expression.method)) {
            "build_with_shared_authority" => {
                self.shared_child_builds = self.shared_child_builds.saturating_add(1);
                let (impl_name, function_name) = self.current_boundary();
                if impl_name != "WebAssessmentRuntime" || function_name != "analyze" {
                    self.violations.insert(format!(
                        "build_with_shared_authority must remain inside WebAssessmentRuntime::analyze, not {impl_name}::{function_name}"
                    ));
                }
            },
            "build" => {
                self.standalone_build_calls = self.standalone_build_calls.saturating_add(1);
            },
            _ => {},
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.in_control_flow(|visitor| visit::visit_expr_if(visitor, expression));
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.in_control_flow(|visitor| visit::visit_expr_for_loop(visitor, expression));
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.in_control_flow(|visitor| visit::visit_expr_loop(visitor, expression));
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.in_control_flow(|visitor| visit::visit_expr_match(visitor, expression));
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.in_control_flow(|visitor| visit::visit_expr_while(visitor, expression));
    }

    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        self.closure_depth = self.closure_depth.saturating_add(1);
        visit::visit_expr_closure(self, expression);
        self.closure_depth = self.closure_depth.saturating_sub(1);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        if token_stream_contains_identifier(item.tokens.clone(), "new_exact_origin")
            || token_stream_contains_identifier(item.tokens.clone(), "build_with_shared_authority")
        {
            self.violations.insert(
                "origin assessment hides authority construction or child composition inside a macro"
                    .to_owned(),
            );
        }
        visit::visit_macro(self, item);
    }
}

fn inspect_web_assessment_models(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let mut public_types = BTreeSet::new();
    let mut audit_owners = BTreeMap::<String, usize>::new();
    let mut defense_audit_owners = BTreeMap::<String, usize>::new();

    for item in &syntax.items {
        match item {
            Item::Struct(item) if !has_cfg_test(&item.attrs) => {
                let name = ident_name(&item.ident);
                if matches!(item.vis, syn::Visibility::Public(_)) {
                    public_types.insert(name.clone());
                    if item
                        .fields
                        .iter()
                        .any(|field| !matches!(field.vis, syn::Visibility::Inherited))
                    {
                        violations.push(format!(
                            "public assessment model {name} exposes fields; keep checked state private behind accessors"
                        ));
                    }
                    if attrs_reference_serde(&item.attrs) {
                        violations.push(format!(
                            "public assessment model {name} must not acquire a serde wire contract in this commit"
                        ));
                    }
                }
                let audit_count = item
                    .fields
                    .iter()
                    .filter(|field| type_references_ident(&field.ty, "TransportDispatchAudit"))
                    .count();
                if audit_count > 0 {
                    audit_owners.insert(name.clone(), audit_count);
                }
                let defense_audit_count = item
                    .fields
                    .iter()
                    .filter(|field| type_references_ident(&field.ty, "WebAssessmentDefenseAudit"))
                    .count();
                if defense_audit_count > 0 {
                    defense_audit_owners.insert(name.clone(), defense_audit_count);
                }
                if name == "WebAssessmentSubjectReport"
                    && item.fields.iter().any(|field| {
                        type_references_ident(&field.ty, "RuntimeUsage")
                            || type_references_ident(&field.ty, "TransportDispatchAudit")
                    })
                {
                    violations.push(
                        "WebAssessmentSubjectReport must remain subject-local and cannot own cumulative usage or transport audit snapshots"
                            .to_owned(),
                    );
                }
                if name == "WebAssessmentRunReport" {
                    let run_started_at = item.fields.iter().find(|field| {
                        field
                            .ident
                            .as_ref()
                            .is_some_and(|ident| ident_name(ident) == "run_started_at")
                    });
                    if run_started_at.is_none_or(|field| {
                        !is_plain_ident(&field.ty, "SystemTime")
                            || !attributes_are_exact_cfg_feature(&field.attrs, "reporting")
                    }) || item.fields.iter().any(|field| {
                        field
                            .ident
                            .as_ref()
                            .is_none_or(|ident| ident_name(ident) != "run_started_at")
                            && !field.attrs.is_empty()
                    }) {
                        violations.push(
                            "WebAssessmentRunReport must retain exactly one private cfg(reporting) SystemTime run_started_at field and no other conditional fields"
                                .to_owned(),
                        );
                    }
                }
            },
            Item::Enum(item)
                if !has_cfg_test(&item.attrs) && matches!(item.vis, syn::Visibility::Public(_)) =>
            {
                let name = ident_name(&item.ident);
                public_types.insert(name.clone());
                if attrs_reference_serde(&item.attrs) {
                    violations.push(format!(
                        "public assessment model {name} must not acquire a serde wire contract in this commit"
                    ));
                }
            },
            _ => {},
        }
    }

    let expected_audit_owners = BTreeMap::from([
        ("WebAssessmentFailureReceipt".to_owned(), 1usize),
        ("WebAssessmentRunReport".to_owned(), 1usize),
    ]);
    if audit_owners != expected_audit_owners {
        violations.push(format!(
            "assessment cumulative transport audit ownership drifted: expected {expected_audit_owners:?}, observed {audit_owners:?}"
        ));
    }
    let expected_defense_audit_owners = BTreeMap::from([
        ("WebAssessmentFailureReceipt".to_owned(), 1usize),
        ("WebAssessmentRunReport".to_owned(), 1usize),
        ("WebAssessmentRuntime".to_owned(), 1usize),
    ]);
    if defense_audit_owners != expected_defense_audit_owners {
        violations.push(format!(
            "assessment defense audit ownership drifted: expected {expected_defense_audit_owners:?}, observed {defense_audit_owners:?}"
        ));
    }
    for item in &syntax.items {
        let Item::Impl(item_impl) = item else {
            continue;
        };
        let Some((_, trait_path, _)) = &item_impl.trait_ else {
            continue;
        };
        let Some(trait_name) = trait_path
            .segments
            .last()
            .map(|segment| ident_name(&segment.ident))
        else {
            continue;
        };
        if !matches!(trait_name.as_str(), "Serialize" | "Deserialize") {
            continue;
        }
        let syn::Type::Path(self_type) = item_impl.self_ty.as_ref() else {
            continue;
        };
        if let Some(type_name) = self_type
            .path
            .segments
            .last()
            .map(|segment| ident_name(&segment.ident))
            .filter(|name| public_types.contains(name))
        {
            violations.push(format!(
                "public assessment model {type_name} implements {trait_name}; no assessment wire contract is authorized in this commit"
            ));
        }
    }
    Ok(violations)
}

fn attrs_reference_serde(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("serde")
            || (attribute.path().is_ident("derive")
                && (token_stream_contains_identifier(
                    attribute
                        .meta
                        .require_list()
                        .map_or_else(|_| TokenStream::new(), |list| list.tokens.clone()),
                    "Serialize",
                ) || token_stream_contains_identifier(
                    attribute
                        .meta
                        .require_list()
                        .map_or_else(|_| TokenStream::new(), |list| list.tokens.clone()),
                    "Deserialize",
                )))
    })
}

fn type_references_ident(item_type: &syn::Type, needle: &str) -> bool {
    struct IdentVisitor<'needle> {
        needle: &'needle str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for IdentVisitor<'_> {
        fn visit_path(&mut self, path: &'ast SynPath) {
            self.found |= path
                .segments
                .iter()
                .any(|segment| normalize_identifier(&ident_name(&segment.ident)) == self.needle);
            if !self.found {
                visit::visit_path(self, path);
            }
        }
    }
    let mut visitor = IdentVisitor {
        needle,
        found: false,
    };
    visitor.visit_type(item_type);
    visitor.found
}

fn inspect_web_assessment_facade(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(item) if item.ident == "web_assessment" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() != 1
        || !matches!(modules[0].vis, syn::Visibility::Inherited)
        || modules[0].content.is_some()
        || !modules[0].attrs.is_empty()
    {
        violations.push(
            "web assessment module must be one private canonical external child with no path redirection"
                .to_owned(),
        );
    }

    let mut exports = BTreeSet::new();
    for item in &syntax.items {
        let Item::Use(item_use) = item else {
            continue;
        };
        if !matches!(item_use.vis, syn::Visibility::Public(_)) {
            continue;
        }
        let mut paths = Vec::new();
        collect_use_paths(&item_use.tree, Vec::new(), &mut paths);
        for (segments, binding, _) in paths {
            if segments
                .first()
                .is_some_and(|segment| normalize_identifier(segment) == "web_assessment")
            {
                let export = binding
                    .or_else(|| segments.last().cloned())
                    .ok_or_else(|| {
                        syn::Error::new_spanned(&item_use.tree, "missing assessment export binding")
                    })?;
                exports.insert(normalize_identifier(&export).to_owned());
            }
        }
    }
    let expected = WEB_ASSESSMENT_PUBLIC_EXPORTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    if exports != expected {
        violations.push(format!(
            "web assessment web-runtime export allowlist drifted; missing={:?}, unexpected={:?}",
            expected.difference(&exports).collect::<Vec<_>>(),
            exports.difference(&expected).collect::<Vec<_>>()
        ));
    }
    Ok(violations)
}

fn inspect_assessment_item_facade(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(item) if item.ident == "assessment_item" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() != 1
        || !matches!(modules[0].vis, syn::Visibility::Inherited)
        || modules[0].content.is_some()
        || !modules[0].attrs.is_empty()
    {
        violations.push(
            "assessment item module must be one private canonical external child with no path redirection"
                .to_owned(),
        );
    }

    let mut exports = BTreeSet::new();
    let mut export_items = 0usize;
    for item in &syntax.items {
        let Item::Use(item_use) = item else {
            continue;
        };
        if !matches!(item_use.vis, syn::Visibility::Public(_)) {
            continue;
        }
        let mut paths = Vec::new();
        collect_use_paths(&item_use.tree, Vec::new(), &mut paths);
        let mut matched_item = false;
        for (segments, binding, is_glob) in paths {
            if segments
                .first()
                .is_some_and(|segment| normalize_identifier(segment) == "assessment_item")
            {
                matched_item = true;
                if !item_use.attrs.is_empty() {
                    violations.push(
                        "assessment item facade export must be unconditional and unannotated"
                            .to_owned(),
                    );
                }
                let is_alias = binding.as_ref().is_some_and(|binding| {
                    segments.last().is_none_or(|source| {
                        normalize_identifier(source) != normalize_identifier(binding)
                    })
                });
                if is_glob || is_alias {
                    violations.push(
                        "assessment item facade must use exact direct exports without aliases or globs"
                            .to_owned(),
                    );
                }
                let export = binding
                    .as_ref()
                    .or_else(|| segments.last())
                    .ok_or_else(|| {
                        syn::Error::new_spanned(&item_use.tree, "missing assessment item export")
                    })?;
                exports.insert(normalize_identifier(export).to_owned());
            }
        }
        if matched_item {
            export_items = export_items.saturating_add(1);
        }
    }
    if export_items != 1 {
        violations.push(format!(
            "assessment item facade must contain exactly one direct public export item; observed {export_items}"
        ));
    }
    let expected = ASSESSMENT_ITEM_PUBLIC_EXPORTS
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    if exports != expected {
        violations.push(format!(
            "assessment item web-runtime export allowlist drifted; missing={:?}, unexpected={:?}",
            expected.difference(&exports).collect::<Vec<_>>(),
            exports.difference(&expected).collect::<Vec<_>>()
        ));
    }
    Ok(violations)
}

fn inspect_assessment_item_projection(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    for forbidden in [
        "HttpRequestBroker",
        "RequestAccountingBroker",
        "SharedWebRuntimeAuthority",
        "RuntimeBudget",
        "HttpEvidenceExecutor",
        "DecisionExecutorRegistry",
        "StandardWebDecisionRuntime",
        "WebAssessmentRuntime",
        "RuntimeApiVisibility",
        "ScanContext",
        "ScanPhase",
        "legacy_discovery",
        "std::net",
        "tokio::net",
        "crate::runner",
        "crate::sdk",
        "reqwest",
        "hyper",
    ] {
        if source.contains(forbidden) {
            violations.push(format!(
                "{ASSESSMENT_ITEM_SOURCE} references forbidden execution authority `{forbidden}`; assessment items may project only committed runtime truth"
            ));
        }
    }
    for forbidden in ["async fn", ".execute(", ".analyze("] {
        if source.contains(forbidden) {
            violations.push(format!(
                "{ASSESSMENT_ITEM_SOURCE} contains forbidden execution marker `{forbidden}`; assessment projection must remain synchronous and read-only"
            ));
        }
    }
    if source.contains("maximum_disposition: AssessmentDisposition") {
        violations.push(
            "assessment capability descriptors must derive their maximum disposition from typed claim policy"
                .to_owned(),
        );
    }

    let expected_public = ASSESSMENT_ITEM_PUBLIC_EXPORTS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let mut observed_public = BTreeSet::new();
    let mut public_types = BTreeSet::new();
    for item in &syntax.items {
        let (visibility, fields, attributes, name) = match item {
            Item::Const(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Struct(item) => (
                &item.vis,
                Some(&item.fields),
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Enum(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Fn(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.sig.ident),
            ),
            Item::Mod(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Static(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Trait(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Type(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::TraitAlias(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            Item::Union(item) => (
                &item.vis,
                None,
                item.attrs.as_slice(),
                ident_name(&item.ident),
            ),
            _ => continue,
        };
        if !matches!(visibility, syn::Visibility::Public(_)) {
            continue;
        }
        observed_public.insert(name.clone());
        if matches!(item, Item::Struct(_) | Item::Enum(_)) {
            public_types.insert(name.clone());
        }
        if attrs_reference_serde(attributes) {
            violations.push(format!(
                "public assessment item model {name} must not derive serialization; reporting owns an explicit redacted projection"
            ));
        }
        if let Some(fields) = fields {
            for field in fields {
                if !matches!(field.vis, syn::Visibility::Inherited) {
                    violations.push(format!(
                        "public assessment item model {name} exposes a mutable construction field"
                    ));
                }
            }
        }
    }
    if observed_public != expected_public {
        violations.push(format!(
            "assessment item public inventory drifted; missing={:?}, unexpected={:?}",
            expected_public
                .difference(&observed_public)
                .collect::<Vec<_>>(),
            observed_public
                .difference(&expected_public)
                .collect::<Vec<_>>()
        ));
    }
    violations.extend(inspect_assessment_item_public_storage(&syntax));
    violations.extend(inspect_assessment_projection_context(&syntax, source));
    violations.extend(inspect_assessment_item_set(&syntax));
    violations.extend(inspect_assessment_scope_binding(&syntax));
    violations.extend(inspect_assessment_item_factory_signatures(&syntax));
    violations.extend(inspect_assessment_projection_ordering(&syntax));
    violations.extend(inspect_production_verifier_descriptors(
        ASSESSMENT_ITEM_SOURCE,
        &syntax,
        false,
    ));

    if syntax_invokes_method(&syntax, "snapshot_for_subject") {
        violations.push(
            "assessment item projection must not clone broad subject snapshots; use exact committed evidence and opaque knowledge authority"
                .to_owned(),
        );
    }

    let expected_methods = BTreeMap::from([
        ("AssessmentDisposition", BTreeSet::from(["as_str"])),
        ("AssessmentSubjectReference", BTreeSet::from(["ordinal"])),
        ("AssessmentEvidenceReference", BTreeSet::from(["ordinal"])),
        ("AssessmentCaseReference", BTreeSet::from(["ordinal"])),
        ("AssessmentOutcomeReference", BTreeSet::from(["ordinal"])),
        ("AssessmentRemediation", BTreeSet::from(["id", "summary"])),
        ("AssessmentObservationBasis", BTreeSet::from(["evidence"])),
        (
            "AssessmentDifferentialBasis",
            BTreeSet::from(["candidate", "control"]),
        ),
        (
            "AssessmentVerifierBasis",
            BTreeSet::from([
                "case_reference",
                "evidence",
                "outcome_reference",
                "stage",
                "verifier_rule_id",
            ]),
        ),
        (
            "AssessmentBasis",
            BTreeSet::from(["case_reference", "evidence_count"]),
        ),
        (
            "AssessmentItem",
            BTreeSet::from([
                "basis",
                "capability_id",
                "category",
                "confidence",
                "cwe",
                "disposition",
                "evidence_count",
                "fingerprint",
                "redacted_summary",
                "remediation",
                "schema",
                "severity",
                "subject_reference",
                "title",
            ]),
        ),
    ]);
    let mut observed_methods = BTreeMap::<String, BTreeSet<String>>::new();
    for item in &syntax.items {
        let Item::Impl(item_impl) = item else {
            continue;
        };
        let syn::Type::Path(self_type) = item_impl.self_ty.as_ref() else {
            continue;
        };
        let Some(type_name) = self_type
            .path
            .segments
            .last()
            .map(|segment| ident_name(&segment.ident))
        else {
            continue;
        };
        if let Some((_, trait_path, _)) = &item_impl.trait_ {
            let trait_name = trait_path
                .segments
                .last()
                .map(|segment| ident_name(&segment.ident))
                .unwrap_or_default();
            if public_types.contains(&type_name)
                && matches!(
                    trait_name.as_str(),
                    "Serialize"
                        | "Deserialize"
                        | "Default"
                        | "From"
                        | "TryFrom"
                        | "DerefMut"
                        | "AsMut"
                        | "BorrowMut"
                )
            {
                violations.push(format!(
                    "public assessment item model {type_name} implements forbidden construction or mutation trait {trait_name}"
                ));
            }
            continue;
        }
        for member in &item_impl.items {
            let syn::ImplItem::Fn(method) = member else {
                continue;
            };
            if method.sig.asyncness.is_some() {
                violations.push(format!(
                    "assessment item projection method {type_name}::{} must remain synchronous",
                    method.sig.ident
                ));
            }
            for argument in &method.sig.inputs {
                if let syn::FnArg::Typed(argument) = argument {
                    if type_references_ident(&argument.ty, "AssessmentDisposition") {
                        violations.push(format!(
                            "assessment item factory {type_name}::{} accepts a raw AssessmentDisposition",
                            method.sig.ident
                        ));
                    }
                }
            }
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }
            let method_name = ident_name(&method.sig.ident);
            observed_methods
                .entry(type_name.clone())
                .or_default()
                .insert(method_name.clone());
            let receiver = method.sig.receiver();
            if receiver.is_none()
                || receiver.is_some_and(|receiver| receiver.mutability.is_some())
                || method.sig.inputs.len() != 1
            {
                violations.push(format!(
                    "public assessment item method {type_name}::{method_name} must be a read-only accessor with no caller-controlled arguments"
                ));
            }
        }
    }
    let expected_methods = expected_methods
        .into_iter()
        .map(|(owner, methods)| {
            (
                owner.to_owned(),
                methods.into_iter().map(str::to_owned).collect(),
            )
        })
        .collect::<BTreeMap<String, BTreeSet<String>>>();
    if observed_methods != expected_methods {
        violations.push(format!(
            "assessment item read-only accessor inventory drifted: expected {expected_methods:?}, observed {observed_methods:?}"
        ));
    }

    let disposition = syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == "AssessmentDisposition" => Some(item),
        _ => None,
    });
    let disposition_variants = disposition
        .map(|item| {
            item.variants
                .iter()
                .map(|variant| ident_name(&variant.ident))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if disposition_variants != ["Informational", "NeedsReview", "Confirmed"]
        || disposition.is_none_or(|item| {
            !item
                .attrs
                .iter()
                .any(|attribute| attribute.path().is_ident("non_exhaustive"))
                || item.variants.iter().any(|variant| {
                    !matches!(variant.fields, syn::Fields::Unit) || variant.discriminant.is_some()
                })
        })
    {
        violations.push(
            "AssessmentDisposition must remain the exact non-exhaustive unit set Informational, NeedsReview, Confirmed"
                .to_owned(),
        );
    }
    let basis = syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == "AssessmentBasis" => Some(item),
        _ => None,
    });
    let expected_basis = [
        ("Observation", "AssessmentObservationBasis"),
        ("Differential", "AssessmentDifferentialBasis"),
        ("Verifier", "AssessmentVerifierBasis"),
    ];
    let basis_matches = basis.is_some_and(|item| {
        item.variants.len() == expected_basis.len()
            && item
                .variants
                .iter()
                .zip(expected_basis)
                .all(|(variant, (name, field_type))| {
                    ident_name(&variant.ident) == name
                        && variant.discriminant.is_none()
                        && match &variant.fields {
                            syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                                is_plain_ident(&fields.unnamed[0].ty, field_type)
                            },
                            _ => false,
                        }
                })
    });
    if !basis_matches {
        violations.push(
            "AssessmentBasis must remain the exact typed Observation, Differential, Verifier authority set"
                .to_owned(),
        );
    }
    for required in [
        "Self::Observation(_) => AssessmentDisposition::Informational",
        "Self::Differential(_) => AssessmentDisposition::NeedsReview",
        "Self::Verifier(_) => AssessmentDisposition::Confirmed",
        "Self::ObservationOnly => AssessmentDisposition::Informational",
        "Self::DifferentialReview => AssessmentDisposition::NeedsReview",
        "Self::VerifierTransition(_) => AssessmentDisposition::Confirmed",
        "extraction.proof.authorize()?;",
    ] {
        if source.matches(required).count() != 1 {
            violations.push(format!(
                "assessment item claim mapping lost exact authority marker `{required}`"
            ));
        }
    }
    if source
        .find("extraction.proof.authorize()?;")
        .zip(source.find("AssessmentBasis::Verifier(AssessmentVerifierBasis {"))
        .is_none_or(|(authorization, construction)| authorization >= construction)
        || source
            .matches("AssessmentBasis::Verifier(AssessmentVerifierBasis {")
            .count()
            != 1
    {
        violations.push(
            "confirmed assessment basis must have one construction site after verifier proof authorization"
                .to_owned(),
        );
    }
    for (marker, expected, boundary) in [
        (
            "preflight_evidence_ids(evidence_ids)?;",
            2,
            "observation and context evidence preflight",
        ),
        (
            "preflight_evidence_ids(control_ids)?;",
            1,
            "differential control evidence preflight",
        ),
        (
            "preflight_evidence_ids(candidate_ids)?;",
            1,
            "differential candidate evidence preflight",
        ),
        (
            "digest_field(&mut digest, stable_scope_id.as_str());",
            2,
            "assessment scope fingerprint framing",
        ),
        (
            "confidence = confidence.min(evidence_confidence);",
            1,
            "committed evidence reliability confidence ceiling",
        ),
    ] {
        if source.matches(marker).count() != expected {
            violations.push(format!(
                "assessment item {boundary} must retain exact marker `{marker}`"
            ));
        }
    }
    Ok(violations)
}

fn inspect_assessment_item_public_storage(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    for item in &syntax.items {
        let Item::Struct(item) = item else {
            continue;
        };
        if !matches!(item.vis, syn::Visibility::Public(_)) {
            continue;
        }
        let name = ident_name(&item.ident);
        let safe = match name.as_str() {
            "AssessmentSubjectReference"
            | "AssessmentEvidenceReference"
            | "AssessmentCaseReference"
            | "AssessmentOutcomeReference" => {
                private_single_tuple_field_is(item, |field| is_plain_ident(field, "u32"))
            },
            "AssessmentRemediation" => private_named_fields(item).is_some_and(|fields| {
                fields.len() == 2
                    && fields
                        .get("id")
                        .is_some_and(|field| is_static_str_reference(field))
                    && fields
                        .get("summary")
                        .is_some_and(|field| is_static_str_reference(field))
            }),
            "AssessmentObservationBasis" => private_named_fields(item).is_some_and(|fields| {
                fields.len() == 1
                    && fields.get("evidence").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentEvidenceReference"])
                    })
            }),
            "AssessmentDifferentialBasis" => private_named_fields(item).is_some_and(|fields| {
                fields.len() == 2
                    && ["control", "candidate"].iter().all(|field_name| {
                        fields.get(*field_name).is_some_and(|field| {
                            is_generic_of_idents(field, "Vec", &["AssessmentEvidenceReference"])
                        })
                    })
            }),
            "AssessmentVerifierBasis" => private_named_fields(item).is_some_and(|fields| {
                fields.len() == 5
                    && fields
                        .get("case_reference")
                        .is_some_and(|field| is_plain_ident(field, "AssessmentCaseReference"))
                    && fields
                        .get("outcome_reference")
                        .is_some_and(|field| is_plain_ident(field, "AssessmentOutcomeReference"))
                    && fields
                        .get("verifier_rule_id")
                        .is_some_and(|field| is_static_str_reference(field))
                    && fields
                        .get("stage")
                        .is_some_and(|field| is_plain_ident(field, "VerificationStage"))
                    && fields.get("evidence").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentEvidenceReference"])
                    })
            }),
            "AssessmentItem" => private_named_fields(item).is_some_and(|fields| {
                fields.len() == 5
                    && fields.get("capability").is_some_and(|field| {
                        is_static_borrowed_ident(field, "AssessmentCapabilityDescriptor")
                    })
                    && fields
                        .get("subject_reference")
                        .is_some_and(|field| is_plain_ident(field, "AssessmentSubjectReference"))
                    && fields
                        .get("confidence")
                        .is_some_and(|field| is_plain_ident(field, "Probability"))
                    && fields
                        .get("fingerprint")
                        .is_some_and(|field| is_plain_ident(field, "String"))
                    && fields
                        .get("basis")
                        .is_some_and(|field| is_plain_ident(field, "AssessmentBasis"))
            }),
            _ => true,
        };
        if !safe {
            violations.push(format!(
                "public assessment item model {name} stores a secret-bearing, dynamic, or non-canonical field shape"
            ));
        }
    }

    let denial = syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == "AssessmentConfirmationDenial" => Some(item),
        _ => None,
    });
    if denial.is_none_or(|item| {
        item.variants
            .iter()
            .any(|variant| !matches!(variant.fields, syn::Fields::Unit))
    }) {
        violations.push(
            "AssessmentConfirmationDenial must remain a value-free reason vocabulary".to_owned(),
        );
    }

    let projection_error = syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == "AssessmentItemProjectionError" => Some(item),
        _ => None,
    });
    if projection_error.is_none_or(|item| {
        item.variants
            .iter()
            .flat_map(|variant| variant.fields.iter())
            .any(|field| !assessment_projection_error_field_is_safe(&field.ty))
    }) {
        violations.push(
            "AssessmentItemProjectionError must not retain secret-bearing or caller-controlled dynamic values"
                .to_owned(),
        );
    }
    violations
}

fn inspect_assessment_item_factory_signatures(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(item_impl) = inherent_impl(syntax, "AssessmentItem") else {
        violations.push("AssessmentItem must have one inherent implementation".to_owned());
        return violations;
    };
    let verifier_factories = item_impl
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "from_verifier_projection" => {
                Some(method)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    if verifier_factories.len() != 1
        || !verifier_factories
            .first()
            .is_some_and(|method| exact_verifier_projection_factory(method))
    {
        violations.push(
            "AssessmentItem::from_verifier_projection must remain the exact private committed-receipt/outcome/knowledge factory"
                .to_owned(),
        );
    }

    let forbidden_factory_inputs = [
        "AssessmentDisposition",
        "AssessmentSubjectReference",
        "AssessmentEvidenceReference",
        "AssessmentCaseReference",
        "AssessmentOutcomeReference",
        "BTreeMap",
        "HashMap",
        "DecisionExecutionFailureReceipt",
        "StandardWebDecisionFailureReceipt",
        "DecisionRunnerTurn",
    ];
    for item in &item_impl.items {
        let syn::ImplItem::Fn(method) = item else {
            continue;
        };
        let method_name = ident_name(&method.sig.ident);
        if !method_name.starts_with("from_") {
            continue;
        }
        for argument in &method.sig.inputs {
            let syn::FnArg::Typed(argument) = argument else {
                continue;
            };
            if let Some(forbidden) = forbidden_factory_inputs
                .iter()
                .find(|forbidden| type_references_ident(&argument.ty, forbidden))
            {
                violations.push(format!(
                    "assessment item factory AssessmentItem::{method_name} accepts forbidden raw caller authority {forbidden}"
                ));
            }
        }
    }
    violations
}

fn inspect_assessment_projection_context(syntax: &syn::File, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let context = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "AssessmentProjectionContext" => Some(item),
        _ => None,
    });
    let context_shape_is_exact = context.is_some_and(|item| {
        matches!(item.vis, syn::Visibility::Restricted(_))
            && private_named_fields(item).is_some_and(|fields| {
                fields.len() == 8
                    && fields
                        .get("knowledge_authority")
                        .is_some_and(|field| is_plain_ident(field, "KnowledgeAuthority"))
                    && fields
                        .get("stable_scope_id")
                        .is_some_and(|field| is_plain_ident(field, "StableAssessmentScopeId"))
                    && fields.get("subjects").is_some_and(|field| {
                        is_generic_of_idents(field, "BTreeMap", &["EntityId", "SubjectProjection"])
                    })
                    && fields.get("stable_subject_ids").is_some_and(|field| {
                        is_generic_of_idents(field, "BTreeSet", &["StableAssessmentSubjectId"])
                    })
                    && fields.get("cases").is_some_and(|field| {
                        generic_type_arguments(field, "BTreeMap").is_some_and(|arguments| {
                            arguments.len() == 2
                                && is_entity_string_tuple(arguments[0])
                                && is_plain_ident(arguments[1], "AssessmentCaseReference")
                        })
                    })
                    && fields.get("outcomes").is_some_and(|field| {
                        is_generic_of_idents(
                            field,
                            "BTreeMap",
                            &["RuntimeOutcomeIdentity", "AssessmentOutcomeReference"],
                        )
                    })
                    && fields.get("evidence").is_some_and(|field| {
                        is_generic_of_idents(
                            field,
                            "BTreeMap",
                            &["EvidenceId", "EvidenceProjection"],
                        )
                    })
                    && fields.get("items").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentItem"])
                    })
            })
    });
    if !context_shape_is_exact {
        violations.push(
            "AssessmentProjectionContext must retain only opaque authority and exact bounded identity maps"
                .to_owned(),
        );
    }
    if context.is_some_and(|item| attrs_reference_any_ident(&item.attrs, &["Clone", "Copy"]))
        || syntax.items.iter().any(|item| {
            let Item::Impl(item) = item else {
                return false;
            };
            let self_is_context = matches!(item.self_ty.as_ref(), syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|segment|
                    segment.ident == "AssessmentProjectionContext"));
            let trait_is_cloneable = item.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Clone" || segment.ident == "Copy")
            });
            self_is_context && trait_is_cloneable
        })
    {
        violations.push(
            "AssessmentProjectionContext must not be Clone or Copy; document-local ordinal authority cannot fork"
                .to_owned(),
        );
    }

    for (name, expected_fields) in [
        (
            "EvidenceProjection",
            &[
                ("reference", "AssessmentEvidenceReference"),
                ("subject", "EntityId"),
            ][..],
        ),
        (
            "SubjectProjection",
            &[
                ("reference", "AssessmentSubjectReference"),
                ("stable_id", "StableAssessmentSubjectId"),
            ][..],
        ),
    ] {
        let projection = syntax.items.iter().find_map(|item| match item {
            Item::Struct(item) if item.ident == name => Some(item),
            _ => None,
        });
        let exact = projection.is_some_and(|item| {
            private_named_fields(item).is_some_and(|fields| {
                let extra = usize::from(name == "SubjectProjection");
                fields.len() == expected_fields.len() + extra
                    && expected_fields.iter().all(|(field_name, field_type)| {
                        fields
                            .get(*field_name)
                            .is_some_and(|field| is_plain_ident(field, field_type))
                    })
                    && (name != "SubjectProjection"
                        || fields.get("query_parameter_names").is_some_and(|field| {
                            is_generic_of_idents(field, "BTreeSet", &["String"])
                        }))
            })
        });
        if !exact {
            violations.push(format!(
                "{name} must not retain raw evidence values, response bodies, credentials, or unbounded dynamic fields"
            ));
        }
    }

    let outcome_identity_is_subject_bound = syntax.items.iter().any(|item| {
        let Item::Struct(item) = item else {
            return false;
        };
        item.ident == "RuntimeOutcomeIdentity"
            && private_named_fields(item).is_some_and(|fields| {
                fields.len() == 9
                    && fields
                        .get("subject")
                        .is_some_and(|field| is_plain_ident(field, "EntityId"))
                    && ["case_id", "action_id", "hypothesis_id"]
                        .iter()
                        .all(|name| {
                            fields
                                .get(*name)
                                .is_some_and(|field| is_plain_ident(field, "String"))
                        })
                    && fields
                        .get("verifier_rule_id")
                        .is_some_and(|field| is_generic_of_idents(field, "Option", &["String"]))
                    && fields
                        .get("stage")
                        .is_some_and(|field| is_static_str_reference(field))
                    && fields
                        .get("status")
                        .is_some_and(|field| is_plain_ident(field, "OutcomeStatus"))
                    && fields
                        .get("confidence")
                        .is_some_and(|field| is_plain_ident(field, "Probability"))
                    && fields.get("evidence_ids").is_some_and(|field| {
                        is_generic_of_idents(field, "BTreeSet", &["EvidenceId"])
                    })
            })
    });
    if !outcome_identity_is_subject_bound {
        violations.push(
            "RuntimeOutcomeIdentity must retain its exact subject-bound runtime identity"
                .to_owned(),
        );
    }

    for (name, expected) in ASSESSMENT_PROJECTION_CONTEXT_LIMITS {
        let item = syntax.items.iter().find_map(|item| match item {
            Item::Const(item) if item.ident == *name => Some(item),
            _ => None,
        });
        let exact = item.is_some_and(|item| {
            matches!(item.vis, syn::Visibility::Inherited)
                && is_plain_ident(&item.ty, "usize")
                && matches!(item.expr.as_ref(), syn::Expr::Lit(expression)
                    if matches!(&expression.lit, syn::Lit::Int(value)
                        if value.base10_parse::<usize>().ok() == Some(*expected)))
        });
        if !exact {
            violations.push(format!(
                "assessment projection compiled ceiling {name} must remain exactly {expected}"
            ));
        }
    }

    let Some(item_impl) = inherent_impl(syntax, "AssessmentProjectionContext") else {
        violations.push(
            "AssessmentProjectionContext must have one crate-owned inherent implementation"
                .to_owned(),
        );
        return violations;
    };
    let methods = item_impl
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some((ident_name(&method.sig.ident), method)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();

    let constructor_is_exact = methods.get("new").is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && method.sig.receiver().is_none()
            && typed_input_types(method) == ["KnowledgeBase", "StableAssessmentScopeId"]
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_plain_ident(output, "Self"))
            && block_references_all(&method.block, &["authority", "stable_scope_id"])
    });
    if !constructor_is_exact {
        violations.push(
            "AssessmentProjectionContext::new must bind one KnowledgeBase authority and stable non-secret exact-origin scope identity"
                .to_owned(),
        );
    }

    let validator_is_exact = methods
        .get("validate_knowledge_authority")
        .is_some_and(|method| {
            method.sig.receiver().is_some_and(|receiver| {
                receiver.reference.is_some() && receiver.mutability.is_none()
            }) && typed_input_types(method) == ["KnowledgeBase"]
                && block_references_all(
                    &method.block,
                    &[
                        "is_same_as",
                        "knowledge_authority",
                        "KnowledgeAuthorityMismatch",
                    ],
                )
        });
    if !validator_is_exact {
        violations.push(
            "AssessmentProjectionContext must fail closed when knowledge authority identity differs"
                .to_owned(),
        );
    }
    if methods
        .get("validate_knowledge_authority")
        .is_none_or(|method| !block_has_exact_knowledge_authority_comparison(&method.block))
    {
        violations.push(
            "AssessmentProjectionContext knowledge validation must compare knowledge.authority().is_same_as(&self.knowledge_authority)"
                .to_owned(),
        );
    }

    let finish_is_exact = methods.get("finish").is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && method.sig.receiver().is_some_and(|receiver| {
                receiver.reference.is_none() && receiver.mutability.is_none()
            })
            && typed_input_types(method).is_empty()
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_plain_ident(output, "AssessmentItemSet"))
            && block_references_all(
                &method.block,
                &[
                    "AssessmentSubjectInventoryEntry",
                    "assessment_subject_fingerprint",
                    "sort_unstable_by_key",
                    "stable_scope_id",
                    "subjects",
                    "items",
                ],
            )
            && block_has_exact_report_only_field_value(&method.block, "stable_scope_id")
    });
    if !finish_is_exact {
        violations.push(
            "AssessmentProjectionContext::finish must consume its sole authority into one sorted AssessmentItemSet inventory"
                .to_owned(),
        );
    }

    for (method_name, required) in [
        (
            "register_subject",
            &[
                "check_projection_limit",
                "MAX_PROJECTION_SUBJECTS",
                "MAX_PROJECTION_QUERY_NAMES_PER_SUBJECT",
            ][..],
        ),
        (
            "register_case",
            &["check_projection_limit", "MAX_PROJECTION_CASES"][..],
        ),
        (
            "register_outcome",
            &["check_projection_limit", "MAX_PROJECTION_OUTCOMES"][..],
        ),
        (
            "register_evidence",
            &[
                "check_projection_limit",
                "MAX_PROJECTION_EVIDENCE",
                "validate_knowledge_authority",
            ][..],
        ),
        ("evidence_references", &["validate_knowledge_authority"][..]),
    ] {
        if methods
            .get(method_name)
            .is_none_or(|method| !block_references_all(&method.block, required))
        {
            violations.push(format!(
                "AssessmentProjectionContext::{method_name} lost its compiled cap or knowledge-authority check"
            ));
        }
    }
    for required in [
        "if current_len >= maximum",
        "AssessmentItemProjectionError::ProjectionContextLimit",
    ] {
        if !source.contains(required) {
            violations.push(format!(
                "assessment projection limit helper lost fail-closed marker `{required}`"
            ));
        }
    }
    violations
}

fn block_has_exact_report_only_field_value(block: &syn::Block, expected: &str) -> bool {
    struct ReportFieldVisitor<'a> {
        expected: &'a str,
        total: usize,
        exact: usize,
    }
    impl<'ast> Visit<'ast> for ReportFieldVisitor<'_> {
        fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
            if matches!(&field.member, syn::Member::Named(member)
                if ident_name(member) == self.expected)
            {
                self.total = self.total.saturating_add(1);
                if attributes_are_exact_cfg_feature(&field.attrs, "reporting")
                    && matches!(&field.expr, syn::Expr::Field(expression)
                        if expression_is_path_ident(expression.base.as_ref(), "self")
                            && matches!(&expression.member, syn::Member::Named(member)
                                if ident_name(member) == self.expected))
                {
                    self.exact = self.exact.saturating_add(1);
                }
            }
            visit::visit_field_value(self, field);
        }
    }
    let mut visitor = ReportFieldVisitor {
        expected,
        total: 0,
        exact: 0,
    };
    visitor.visit_block(block);
    visitor.total == 1 && visitor.exact == 1
}

fn inspect_assessment_item_set(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let item_set = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "AssessmentItemSet" => Some(item),
        _ => None,
    });
    let exact_set = item_set.is_some_and(|item| {
        is_pub_crate_visibility(&item.vis)
            && private_named_field(item, "stable_scope_id")
                .is_some_and(|field| attributes_are_exact_cfg_feature(&field.attrs, "reporting"))
            && private_named_field(item, "subjects").is_some_and(|field| field.attrs.is_empty())
            && private_named_field(item, "items").is_some_and(|field| field.attrs.is_empty())
            && private_named_fields(item).is_some_and(|fields| {
                fields.len() == 3
                    && fields
                        .get("stable_scope_id")
                        .is_some_and(|field| is_plain_ident(field, "StableAssessmentScopeId"))
                    && fields.get("subjects").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentSubjectInventoryEntry"])
                    })
                    && fields.get("items").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentItem"])
                    })
            })
    });
    if !exact_set {
        violations.push(
            "AssessmentItemSet must privately own exactly its stable scope, subject inventory, and projected items"
                .to_owned(),
        );
    }
    if item_set.is_some_and(|item| attrs_reference_any_ident(&item.attrs, &["Clone", "Copy"]))
        || type_has_explicit_trait_impl(syntax, "AssessmentItemSet", &["Clone", "Copy"])
    {
        violations.push(
            "AssessmentItemSet must not be Clone or Copy; its context-owned reference authority cannot fork"
                .to_owned(),
        );
    }

    let inventory = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "AssessmentSubjectInventoryEntry" => Some(item),
        _ => None,
    });
    let exact_inventory = inventory.is_some_and(|item| {
        is_pub_crate_visibility(&item.vis)
            && private_named_field(item, "reference").is_some_and(|field| field.attrs.is_empty())
            && private_named_field(item, "fingerprint").is_some_and(|field| field.attrs.is_empty())
            && private_named_fields(item).is_some_and(|fields| {
                fields.len() == 2
                    && fields
                        .get("reference")
                        .is_some_and(|field| is_plain_ident(field, "AssessmentSubjectReference"))
                    && fields
                        .get("fingerprint")
                        .is_some_and(|field| is_plain_ident(field, "String"))
            })
    });
    if !exact_inventory {
        violations.push(
            "AssessmentSubjectInventoryEntry must remain a private opaque reference plus stable digest"
                .to_owned(),
        );
    }

    let inventory_fingerprint = inherent_impl(syntax, "AssessmentSubjectInventoryEntry")
        .and_then(|item| {
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "fingerprint" => Some(method),
                _ => None,
            })
        })
        .is_some_and(|method| {
            is_pub_crate_visibility(&method.vis)
                && attributes_are_exact_cfg_feature_or_test(&method.attrs, "reporting")
                && method.sig.receiver().is_some_and(|receiver| {
                    receiver.reference.is_some() && receiver.mutability.is_none()
                })
                && typed_input_types(method).is_empty()
                && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                    if is_borrowed_ident(output, "str"))
                && block_references_all(&method.block, &["fingerprint"])
        });
    if !inventory_fingerprint {
        violations.push(
            "AssessmentSubjectInventoryEntry::fingerprint must remain a report/test-only borrowed opaque digest accessor"
                .to_owned(),
        );
    }

    let Some(item_impl) = inherent_impl(syntax, "AssessmentItemSet") else {
        violations
            .push("AssessmentItemSet must have one closed inherent implementation".to_owned());
        return violations;
    };
    let methods = item_impl
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some((ident_name(&method.sig.ident), method)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let expected = BTreeSet::from([
        "contains_only_stable_subject".to_owned(),
        "into_parts".to_owned(),
        "items".to_owned(),
        "matches_exact_origin".to_owned(),
    ]);
    if methods.keys().cloned().collect::<BTreeSet<_>>() != expected {
        violations.push(
            "AssessmentItemSet must expose only exact-origin validation, one exact stable-subject check, and consuming report decomposition; no raw constructor, append, or merge surface is allowed"
                .to_owned(),
        );
    }
    let matches_origin = methods.get("matches_exact_origin").is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && attributes_are_exact_cfg_feature(&method.attrs, "reporting")
            && method.sig.receiver().is_some_and(|receiver| {
                receiver.reference.is_some() && receiver.mutability.is_none()
            })
            && typed_input_types(method) == ["str"]
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_plain_ident(output, "bool"))
            && block_references_all(&method.block, &["stable_scope_id", "matches_exact_origin"])
    });
    if !matches_origin {
        violations.push(
            "AssessmentItemSet::matches_exact_origin must delegate to its private stable scope identity"
                .to_owned(),
        );
    }
    let items = methods.get("items").is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && method.attrs.is_empty()
            && method.sig.receiver().is_some_and(|receiver| {
                receiver.reference.is_some() && receiver.mutability.is_none()
            })
            && typed_input_types(method).is_empty()
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_borrowed_slice_of(output, "AssessmentItem"))
    });
    if !items {
        violations.push(
            "AssessmentItemSet::items must remain a read-only borrowed typed-item view".to_owned(),
        );
    }
    let contains_only_stable_subject =
        methods
            .get("contains_only_stable_subject")
            .is_some_and(|method| {
                is_pub_crate_visibility(&method.vis)
                    && attributes_are_exact_cfg_feature_allowing_docs(&method.attrs, "reporting")
                    && method.sig.receiver().is_some_and(|receiver| {
                        receiver.reference.is_some() && receiver.mutability.is_none()
                    })
                    && typed_input_types(method) == ["str"]
                    && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                    if is_plain_ident(output, "bool"))
                    && stable_subject_inventory_check_is_exact(&method.block)
            });
    if !contains_only_stable_subject {
        violations.push(
            "AssessmentItemSet::contains_only_stable_subject must validate one checked stable identity, bind its digest to the existing scope, and require exactly subject reference zero"
                .to_owned(),
        );
    }
    let into_parts = methods.get("into_parts").is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && attributes_are_exact_cfg_feature_or_test(&method.attrs, "reporting")
            && method.sig.receiver().is_some_and(|receiver| {
                receiver.reference.is_none() && receiver.mutability.is_none()
            })
            && typed_input_types(method).is_empty()
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_assessment_item_set_parts(output))
            && block_references_all(&method.block, &["subjects", "items"])
    });
    if !into_parts {
        violations.push(
            "AssessmentItemSet::into_parts must consume the set into its exact subject inventory and item vector"
                .to_owned(),
        );
    }
    violations
}

fn stable_subject_inventory_check_is_exact(block: &syn::Block) -> bool {
    if block.stmts.len() != 3 {
        return false;
    }
    let checked_identity = matches!(&block.stmts[0], syn::Stmt::Local(local)
        if matches!(&local.pat, syn::Pat::TupleStruct(pattern)
            if pattern.path.is_ident("Ok")
                && pattern.elems.len() == 1
                && matches!(&pattern.elems[0], syn::Pat::Ident(identity)
                    if identity.ident == "stable_identity"))
            && local.init.as_ref().is_some_and(|init|
                matches!(init.expr.as_ref(), syn::Expr::Call(call)
                    if expression_path_ends_with(call.func.as_ref(), &["StableAssessmentSubjectId", "new"])
                        && call.args.len() == 1
                        && call.args.first().is_some_and(|argument|
                            expression_is_path_ident(argument, "stable_identity")))
                && init.diverge.as_ref().is_some_and(|(_, diverge)|
                    matches!(diverge.as_ref(), syn::Expr::Block(block)
                        if block.block.stmts.len() == 1
                            && matches!(&block.block.stmts[0], syn::Stmt::Expr(syn::Expr::Return(returned), Some(_))
                                if returned.expr.as_ref().is_some_and(|expression|
                                    matches!(expression.as_ref(), syn::Expr::Lit(literal)
                                        if matches!(&literal.lit, syn::Lit::Bool(value) if !value.value))))))));
    let scoped_fingerprint = matches!(&block.stmts[1], syn::Stmt::Local(local)
        if matches!(&local.pat, syn::Pat::Ident(expected) if expected.ident == "expected")
            && local.init.as_ref().is_some_and(|init|
                matches!(init.expr.as_ref(), syn::Expr::Call(call)
                    if expression_path_ends_with(call.func.as_ref(), &["assessment_subject_fingerprint"])
                        && call.args.len() == 2
                        && call.args.first().is_some_and(|argument|
                            expression_is_borrowed_self_field(argument, "stable_scope_id"))
                        && call.args.iter().nth(1).is_some_and(|argument|
                            matches!(argument, syn::Expr::Reference(reference)
                                if reference.mutability.is_none()
                                    && expression_is_path_ident(reference.expr.as_ref(), "stable_identity"))))));
    let exact_inventory_match = matches!(&block.stmts[2], syn::Stmt::Expr(syn::Expr::Macro(item), None)
        if item.mac.path.is_ident("matches")
            && normalized_token_text(&item.mac.tokens)
                == "self.subjects.as_slice(),[subject]ifsubject.reference()==AssessmentSubjectReference::new(0)&&subject.fingerprint()==expected");
    checked_identity && scoped_fingerprint && exact_inventory_match
}

fn expression_path_ends_with(expression: &syn::Expr, expected: &[&str]) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    if path.qself.is_some() || path.path.segments.len() != expected.len() {
        return false;
    }
    path.path
        .segments
        .iter()
        .zip(expected)
        .all(|(actual, expected)| {
            normalize_identifier(&ident_name(&actual.ident)) == *expected
                && matches!(actual.arguments, syn::PathArguments::None)
        })
}

fn normalized_token_text(tokens: &TokenStream) -> String {
    tokens
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn inspect_assessment_scope_binding(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let scope = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "StableAssessmentScopeId" => Some(item),
        _ => None,
    });
    if scope.is_none_or(|item| {
        !is_pub_crate_visibility(&item.vis)
            || !private_single_tuple_field_is(item, |field| is_plain_ident(field, "String"))
    }) {
        violations.push(
            "StableAssessmentScopeId must remain a crate-private checked exact-origin digest"
                .to_owned(),
        );
    }
    let Some(scope_impl) = inherent_impl(syntax, "StableAssessmentScopeId") else {
        violations.push("StableAssessmentScopeId must have one checked implementation".to_owned());
        return violations;
    };
    let methods = scope_impl
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some((ident_name(&method.sig.ident), method)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let constructor = methods.get("from_exact_origin").is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && method.sig.receiver().is_none()
            && typed_input_types(method) == ["str"]
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_result_of(output, "Self", "AssessmentItemProjectionError"))
            && block_references_all(
                &method.block,
                &[
                    "Url",
                    "parse",
                    "scheme",
                    "username",
                    "password",
                    "host",
                    "path",
                    "query",
                    "fragment",
                    "origin",
                    "ascii_serialization",
                    "SCOPE_IDENTITY_DOMAIN",
                    "digest_field",
                ],
            )
    });
    if !constructor {
        violations.push(
            "StableAssessmentScopeId::from_exact_origin must validate one canonical credential-free HTTP(S) origin before digesting it"
                .to_owned(),
        );
    }
    let matcher = methods.get("matches_exact_origin").is_some_and(|method| {
        matches!(method.vis, syn::Visibility::Inherited)
            && attributes_are_exact_cfg_feature(&method.attrs, "reporting")
            && method.sig.receiver().is_some_and(|receiver| {
                receiver.reference.is_some() && receiver.mutability.is_none()
            })
            && typed_input_types(method) == ["str"]
            && block_references_all(&method.block, &["from_exact_origin", "is_ok_and"])
    });
    if !matcher {
        violations.push(
            "StableAssessmentScopeId::matches_exact_origin must revalidate and compare the checked origin digest"
                .to_owned(),
        );
    }
    violations
}

fn inspect_assessment_projection_ordering(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let Some(context_impl) = inherent_impl(syntax, "AssessmentProjectionContext") else {
        return violations;
    };
    let context_methods = context_impl
        .items
        .iter()
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some((ident_name(&method.sig.ident), method)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();

    if context_methods
        .get("register_outcome")
        .is_none_or(|method| {
            !(statement_reference_precedes(
                &method.block,
                "preflight_ordered_evidence_ids",
                "RuntimeOutcomeIdentity",
            ) && statement_reference_precedes(
                &method.block,
                "preflight_ordered_evidence_ids",
                "next_ordinal",
            ) && statement_reference_precedes(
                &method.block,
                "preflight_ordered_evidence_ids",
                "insert",
            ))
        })
    {
        violations.push(
            "AssessmentProjectionContext::register_outcome must preflight ordered evidence before identity construction or registration"
                .to_owned(),
        );
    }

    for (method_name, constructor) in [
        ("project_observation", "from_observation"),
        ("project_differential", "from_differential"),
        ("project_verifier", "from_verifier_projection"),
    ] {
        if context_methods.get(method_name).is_none_or(|method| {
            !(statement_reference_precedes(&method.block, "check_projection_limit", constructor)
                && block_references_all(&method.block, &["MAX_ASSESSMENT_ITEM_SET_ITEMS", "items"]))
        }) {
            violations.push(format!(
                "AssessmentProjectionContext::{method_name} must enforce the item ceiling before item construction"
            ));
        }
    }

    let Some(item_impl) = inherent_impl(syntax, "AssessmentItem") else {
        return violations;
    };
    let verifier = item_impl.items.iter().find_map(|item| match item {
        syn::ImplItem::Fn(method) if method.sig.ident == "from_verifier_projection" => Some(method),
        _ => None,
    });
    if verifier.is_none_or(|method| {
        !(statement_reference_precedes(
            &method.block,
            "preflight_ordered_evidence_ids",
            "extract_confirmation_proof",
        ) && statement_reference_precedes(&method.block, "authorize", "evidence_references")
            && statement_reference_precedes(&method.block, "authorize", "build"))
    }) {
        violations.push(
            "verifier projection must preflight ordered evidence, authorize its proof, and only then allocate references or construct Confirmed"
                .to_owned(),
        );
    }
    if verifier.is_none_or(|method| !verifier_confidence_is_exact(method)) {
        violations.push(
            "Confirmed confidence must be the minimum of capability policy, committed evidence reliability, and verifier outcome confidence"
                .to_owned(),
        );
    }
    violations
}

fn inspect_assessment_report_boundary(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let truth = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "CompletedWebAssessmentTruth" => Some(item),
        _ => None,
    });
    let truth_shape_is_exact = truth.is_some_and(|item| {
        is_pub_crate_visibility(&item.vis)
            && private_named_fields(item).is_some_and(|fields| {
                fields.len() == 7
                    && fields
                        .get("run_started_at")
                        .is_some_and(|field| is_plain_ident(field, "SystemTime"))
                    && fields
                        .get("target")
                        .is_some_and(|field| is_plain_ident(field, "String"))
                    && fields
                        .get("authorized_origin")
                        .is_some_and(|field| is_plain_ident(field, "String"))
                    && fields
                        .get("target_identity")
                        .is_some_and(|field| is_fixed_u8_array(field, 32))
                    && fields
                        .get("expected_accounting")
                        .is_some_and(|field| is_plain_ident(field, "RunAccounting"))
                    && fields
                        .get("expected_elapsed_ms")
                        .is_some_and(|field| is_plain_ident(field, "u64"))
                    && fields
                        .get("profile")
                        .is_some_and(|field| is_plain_ident(field, "ScanProfileV1"))
            })
    });
    if !truth_shape_is_exact {
        violations.push(
            "CompletedWebAssessmentTruth must privately retain exactly the runtime start, canonical target/origin, target digest, expected accounting/duration, and governing profile"
                .to_owned(),
        );
    }
    let truth_constructor =
        inherent_impl(&syntax, "CompletedWebAssessmentTruth").and_then(|item| {
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "new" => Some(method),
                _ => None,
            })
        });
    let truth_constructor_is_exact = truth_constructor.is_some_and(|method| {
        is_pub_crate_visibility(&method.vis)
            && method.sig.receiver().is_none()
            && completed_truth_constructor_inputs_are_exact(method)
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                if is_result_of(output, "Self", "AssessmentRunReportError"))
            && block_references_all(
                &method.block,
                &[
                    "validate_completed_assessment_truth",
                    "AssessmentUsageTruth",
                    "run_started_at",
                    "target",
                    "authorized_origin",
                    "origin",
                    "ascii_serialization",
                    "assessment_target_identity",
                    "expected_run_accounting",
                    "elapsed_ms",
                    "profile",
                ],
            )
            && statement_reference_precedes(
                &method.block,
                "validate_completed_assessment_truth",
                "assessment_target_identity",
            )
            && statement_reference_precedes(
                &method.block,
                "validate_completed_assessment_truth",
                "expected_run_accounting",
            )
            && !block_invokes_exact_function(&method.block, &["SystemTime", "now"])
    });
    if !truth_constructor_is_exact {
        violations.push(
            "CompletedWebAssessmentTruth::new must accept the runtime-owned start and validate the exact root/profile/completion/usage authority before minting canonical report truth"
                .to_owned(),
        );
    }

    let report = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "AssessmentRunReport" => Some(item),
        _ => None,
    });
    let report_shape_is_exact = report.is_some_and(|item| {
        matches!(item.vis, syn::Visibility::Public(_))
            && private_named_fields(item).is_some_and(|fields| {
                fields.len() == 4
                    && fields
                        .get("run_report")
                        .is_some_and(|field| is_plain_ident(field, "RunReport"))
                    && fields
                        .get("profile")
                        .is_some_and(|field| is_plain_ident(field, "ScanProfileV1"))
                    && fields.get("subjects").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentSubjectInventoryEntry"])
                    })
                    && fields.get("items").is_some_and(|field| {
                        is_generic_of_idents(field, "Vec", &["AssessmentItem"])
                    })
            })
    });
    if !report_shape_is_exact {
        violations.push(
            "AssessmentRunReport must privately retain the validated run/profile, consumed subject inventory, and typed items"
                .to_owned(),
        );
    }

    let report_impls = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if item.trait_.is_none()
                    && type_last_identifier(item.self_ty.as_ref()).as_deref()
                        == Some("AssessmentRunReport") =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let report_methods = report_impls
        .iter()
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some((ident_name(&method.sig.ident), method)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let completed_constructor = report_methods
        .get("from_completed_truth")
        .is_some_and(|method| {
            is_pub_crate_visibility(&method.vis)
                && method
                    .attrs
                    .iter()
                    .all(|attribute| attribute.path().is_ident("doc"))
                && method.sig.receiver().is_none()
                && typed_input_types(method) == ["AssessmentItemSet", "CompletedWebAssessmentTruth"]
                && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                    if is_result_of(output, "Self", "AssessmentRunReportError"))
                && block_references_all(&method.block, &["build_run_report", "new_validated"])
                && statement_reference_precedes(&method.block, "build_run_report", "new_validated")
        });
    if !completed_constructor {
        violations.push(
            "AssessmentRunReport::from_completed_truth must consume only AssessmentItemSet plus runtime-owned completion truth, build the generic envelope internally, and then validate it"
                .to_owned(),
        );
    }

    let test_constructor = report_methods.get("new").is_some_and(|method| {
        matches!(method.vis, syn::Visibility::Inherited)
            && has_cfg_test(&method.attrs)
            && method.sig.receiver().is_none()
            && typed_input_types(method)
                == [
                    "RunReport",
                    "AssessmentItemSet",
                    "CompletedWebAssessmentTruth",
                ]
            && block_references_all(&method.block, &["new_validated"])
    });
    if !test_constructor {
        violations.push(
            "AssessmentRunReport::new may accept a caller-supplied RunReport only as the exact private cfg(test) negative-test seam"
                .to_owned(),
        );
    }

    let validator = report_methods.get("new_validated").is_some_and(|method| {
        matches!(method.vis, syn::Visibility::Inherited)
            && method.attrs.is_empty()
            && method.sig.receiver().is_none()
            && typed_input_types(method)
                == [
                    "RunReport",
                    "AssessmentItemSet",
                    "CompletedWebAssessmentTruth",
                ]
            && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
                    if is_result_of(output, "Self", "AssessmentRunReportError"))
            && block_references_all(
                &method.block,
                &[
                    "validate_run_identity",
                    "validate_run_completion",
                    "validate_run_accounting",
                    "matches_exact_origin",
                    "authorized_origin",
                    "ScopeAuthorityMismatch",
                    "contains_only_stable_subject",
                    "SubjectReferenceMismatch",
                    "into_parts",
                    "validate_subject_inventory",
                    "validate_and_canonicalize_items",
                    "profile",
                ],
            )
            && block_has_exact_stable_subject_call(&method.block)
            && statement_reference_precedes(
                &method.block,
                "validate_run_identity",
                "validate_run_completion",
            )
            && statement_reference_precedes(
                &method.block,
                "validate_run_completion",
                "validate_run_accounting",
            )
            && statement_reference_precedes(
                &method.block,
                "validate_run_accounting",
                "matches_exact_origin",
            )
            && statement_reference_precedes(&method.block, "matches_exact_origin", "into_parts")
            && statement_reference_precedes(
                &method.block,
                "contains_only_stable_subject",
                "into_parts",
            )
            && statement_reference_precedes(&method.block, "validate_subject_inventory", "Self")
            && statement_reference_precedes(
                &method.block,
                "validate_and_canonicalize_items",
                "Self",
            )
    });
    if !validator {
        violations.push(
            "AssessmentRunReport::new_validated must remain private and validate run identity/completion/accounting, the exact root subject, inventory, and items before construction"
                .to_owned(),
        );
    }

    if report_methods.values().any(|method| {
        !has_cfg_test(&method.attrs)
            && !matches!(method.vis, syn::Visibility::Inherited)
            && typed_input_types(method)
                .iter()
                .any(|input| input == "RunReport")
    }) {
        violations.push(
            "AssessmentRunReport must not expose any production public or crate-private caller-supplied RunReport input"
                .to_owned(),
        );
    }

    violations.extend(inspect_runtime_owned_assessment_run_builder(&syntax));

    violations.extend(inspect_assessment_report_truth_validators(&syntax));

    let canonicalizer = syntax.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == "validate_and_canonicalize_items" => Some(item),
        _ => None,
    });
    if canonicalizer.is_none_or(|function| {
        !statement_reference_precedes(&function.block, "validate_item_count", "canonicalize_items")
            || !statement_reference_precedes(
                &function.block,
                "validate_profile_item_count",
                "canonicalize_items",
            )
    }) {
        violations.push(
            "assessment report item/profile ceilings must be validated before canonical item ordering"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn completed_truth_constructor_inputs_are_exact(method: &syn::ImplItemFn) -> bool {
    let inputs = method
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            syn::FnArg::Typed(argument) => Some(argument.ty.as_ref()),
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    inputs.len() == 7
        && is_plain_ident(inputs[0], "SystemTime")
        && is_borrowed_ident(inputs[1], "WebAssessmentSubject")
        && is_plain_ident(inputs[2], "WebAssessmentLimits")
        && is_plain_ident(inputs[3], "WebAssessmentUsage")
        && is_borrowed_ident(inputs[4], "WebAssessmentCompletion")
        && is_plain_ident(inputs[5], "WebAssessmentDefenseMode")
        && is_plain_ident(inputs[6], "ScanProfileV1")
}

fn inspect_runtime_owned_assessment_run_builder(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let builder = syntax.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "build_run_report" => Some(function),
        _ => None,
    });
    let exact = builder.is_some_and(|function| {
        matches!(function.vis, syn::Visibility::Inherited)
            && function.attrs.is_empty()
            && function.sig.inputs.len() == 1
            && function.sig.inputs.first().is_some_and(|argument| {
                matches!(argument, syn::FnArg::Typed(argument)
                    if is_borrowed_ident(argument.ty.as_ref(), "CompletedWebAssessmentTruth"))
            })
            && matches!(&function.sig.output, syn::ReturnType::Type(_, output)
                if is_result_of(output, "RunReport", "AssessmentRunReportError"))
            && block_references_all(
                &function.block,
                &[
                    "run_started_at",
                    "checked_add",
                    "Duration",
                    "from_millis",
                    "expected_elapsed_ms",
                    "RunEnvelopeInvalid",
                    "RunStopReason",
                    "RunStopCode",
                    "Completed",
                    "WEB_ASSESSMENT_STOP_DETAIL",
                    "RunStepReport",
                    "WEB_ASSESSMENT_RUN_STEP_ID",
                    "RunStepStatus",
                    "Succeeded",
                    "RunReportInput",
                    "RunStatus",
                    "Complete",
                    "target",
                    "authorized_origin",
                    "with_accounting",
                    "expected_accounting",
                    "with_steps",
                    "with_outcomes",
                    "Vec",
                    "RunReport",
                ],
            )
            && !block_invokes_exact_function(&function.block, &["SystemTime", "now"])
            && statement_reference_precedes(&function.block, "checked_add", "RunStopReason")
            && statement_reference_precedes(&function.block, "RunStopReason", "RunStepReport")
            && statement_reference_precedes(&function.block, "RunStepReport", "RunReportInput")
            && statement_reference_precedes(&function.block, "RunReportInput", "RunReport")
    });
    if !exact {
        violations.push(
            "build_run_report must privately mint the sole complete generic envelope from runtime-owned start, exact elapsed usage/accounting, one canonical succeeded step, and no outcomes"
                .to_owned(),
        );
    }
    violations
}

fn block_invokes_exact_function(block: &syn::Block, expected: &[&str]) -> bool {
    struct ExactCallVisitor<'a> {
        expected: &'a [&'a str],
        found: bool,
    }
    impl<'ast> Visit<'ast> for ExactCallVisitor<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.found |= expression_path_ends_with(call.func.as_ref(), self.expected);
            if !self.found {
                visit::visit_expr_call(self, call);
            }
        }
    }
    let mut visitor = ExactCallVisitor {
        expected,
        found: false,
    };
    visitor.visit_block(block);
    visitor.found
}

fn inspect_assessment_report_truth_validators(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let validators = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) => Some((ident_name(&function.sig.ident), function)),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();

    let identity = validators
        .get("validate_run_identity")
        .is_some_and(|function| {
            matches!(function.vis, syn::Visibility::Inherited)
                && block_references_all(
                    &function.block,
                    &[
                        "authorized_origin",
                        "target",
                        "Url",
                        "parse",
                        "is_canonical_http_origin",
                        "scheme",
                        "username",
                        "password",
                        "host",
                        "query",
                        "fragment",
                        "origin",
                        "ascii_serialization",
                        "assessment_target_identity",
                        "expected_target_identity",
                        "RunIdentityNotExactOrigin",
                    ],
                )
        });
    if !identity {
        violations.push(
            "assessment report run identity validator must bind one canonical credential-free HTTP(S) target to the authorized origin and completed target digest"
                .to_owned(),
        );
    }

    let completion = validators
        .get("validate_run_completion")
        .is_some_and(|function| {
            matches!(function.vis, syn::Visibility::Inherited)
                && block_references_all(
                    &function.block,
                    &[
                        "status",
                        "RunStatus",
                        "Complete",
                        "stop_reason",
                        "RunStopCode",
                        "Completed",
                        "RunNotComplete",
                        "outcomes",
                        "is_empty",
                        "RunOutcomesForbidden",
                    ],
                )
        });
    if !completion {
        violations.push(
            "assessment report completion validator must require completed status/stop truth and reject every generic run outcome"
                .to_owned(),
        );
    }

    let accounting = validators
        .get("validate_run_accounting")
        .is_some_and(|function| {
            matches!(function.vis, syn::Visibility::Inherited)
                && block_references_all(
                    &function.block,
                    &[
                        "accounting",
                        "expected",
                        "RunAccountingMismatch",
                        "completed_at",
                        "started_at",
                        "num_milliseconds",
                        "expected_elapsed_ms",
                        "subsec_nanos",
                        "rem_euclid",
                        "RunDurationMismatch",
                        "steps",
                        "ordinal",
                        "action_id",
                        "WEB_ASSESSMENT_RUN_STEP_ID",
                        "status",
                        "RunStepStatus",
                        "Succeeded",
                        "duration_ms",
                        "detail",
                        "is_some",
                        "RunStepMismatch",
                    ],
                )
                && statement_reference_precedes(
                    &function.block,
                    "RunAccountingMismatch",
                    "RunDurationMismatch",
                )
                && statement_reference_precedes(
                    &function.block,
                    "RunDurationMismatch",
                    "RunStepMismatch",
                )
        });
    if !accounting {
        violations.push(
            "assessment report accounting validator must require exact metering, millisecond duration, and the sole canonical succeeded assessment step"
                .to_owned(),
        );
    }

    let assessment_truth = validators
        .get("validate_completed_assessment_truth")
        .is_some_and(|function| {
            matches!(function.vis, syn::Visibility::Inherited)
                && block_references_all(
                    &function.block,
                    &[
                        "BuiltInScanProfile",
                        "WebReview",
                        "BaselineItemsForbidden",
                        "web_assessment_limits",
                        "ProfileAuthorityMismatch",
                        "defense_enforcement_enabled",
                        "WebAssessmentDefenseMode",
                        "Enforced",
                        "ObservationOnly",
                        "ProfileDefenseMismatch",
                        "WebAssessmentCompletion",
                        "Complete",
                        "AssessmentIncomplete",
                        "WebAssessmentSubjectOrigin",
                        "AuthorizedRoot",
                        "depth",
                        "WebAssessmentMethod",
                        "Get",
                        "scheme",
                        "host",
                        "username",
                        "password",
                        "query",
                        "fragment",
                        "path",
                        "max_canonical_url_bytes",
                        "retained_subjects",
                        "executed_subjects",
                        "max_subjects",
                        "retained_forms",
                        "max_forms",
                        "retained_unique_url_bytes",
                        "max_retained_url_bytes",
                        "total_requests",
                        "max_total_requests",
                        "active_verifications",
                        "max_active_verifications",
                        "request_body_bytes",
                        "max_request_body_bytes",
                        "response_bytes",
                        "max_total_response_bytes",
                        "elapsed_ms",
                        "max_wall_time",
                        "AssessmentUsageMismatch",
                    ],
                )
        });
    if !assessment_truth {
        violations.push(
            "completed assessment truth validator must bind the web-review profile, defense mode, complete root execution, and every bounded usage ceiling"
                .to_owned(),
        );
    }

    let inventory = validators
        .get("validate_subject_inventory")
        .is_some_and(|function| {
            matches!(function.vis, syn::Visibility::Inherited)
                && block_references_all(
                    &function.block,
                    &[
                        "subjects",
                        "is_empty",
                        "BTreeSet",
                        "enumerate",
                        "reference",
                        "ordinal",
                        "try_from",
                        "fingerprint",
                        "insert",
                        "items",
                        "subject_reference",
                        "len",
                        "SubjectReferenceMismatch",
                    ],
                )
        });
    if !inventory {
        violations.push(
            "assessment report inventory validator must require a nonempty consecutive unique subject inventory and reject out-of-range item references"
                .to_owned(),
        );
    }
    violations
}

fn block_has_exact_stable_subject_call(block: &syn::Block) -> bool {
    struct StableSubjectCallVisitor {
        exact_calls: usize,
        total_calls: usize,
    }
    impl<'ast> Visit<'ast> for StableSubjectCallVisitor {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "contains_only_stable_subject" {
                self.total_calls = self.total_calls.saturating_add(1);
                let exact = expression_is_path_ident(call.receiver.as_ref(), "items")
                    && call.args.len() == 1
                    && call.args.first().is_some_and(|argument| {
                        matches!(argument, syn::Expr::Lit(literal)
                            if matches!(&literal.lit, syn::Lit::Str(value)
                                if value.value() == "authorized-root@1"))
                    });
                if exact {
                    self.exact_calls = self.exact_calls.saturating_add(1);
                }
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = StableSubjectCallVisitor {
        exact_calls: 0,
        total_calls: 0,
    };
    visitor.visit_block(block);
    visitor.total_calls == 1 && visitor.exact_calls == 1
}

fn is_fixed_u8_array(item_type: &syn::Type, expected_length: usize) -> bool {
    matches!(item_type, syn::Type::Array(array)
        if is_plain_ident(array.elem.as_ref(), "u8")
            && matches!(&array.len, syn::Expr::Lit(literal)
                if matches!(&literal.lit, syn::Lit::Int(length)
                    if length.base10_parse::<usize>().ok() == Some(expected_length))))
}

fn inspect_knowledge_authority_accessor(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let knowledge_impls = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if item.trait_.is_none()
                    && type_last_identifier(item.self_ty.as_ref()).as_deref()
                        == Some("KnowledgeBase") =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let accessors = knowledge_impls
        .iter()
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "authority" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let exact = accessors.len() == 1
        && accessors[0]
            .sig
            .receiver()
            .is_some_and(|receiver| receiver.reference.is_some() && receiver.mutability.is_none())
        && is_pub_crate_visibility(&accessors[0].vis)
        && typed_input_types(accessors[0]).is_empty()
        && matches!(&accessors[0].sig.output, syn::ReturnType::Type(_, output)
            if is_borrowed_ident(output, "KnowledgeAuthority"))
        && block_is_borrowed_self_field(&accessors[0].block, "authority");
    if !exact {
        violations.push(
            "KnowledgeBase::authority must remain the exact pub(crate) read-only &KnowledgeAuthority accessor"
                .to_owned(),
        );
    }

    let authority_impls = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if item.trait_.is_none()
                    && type_last_identifier(item.self_ty.as_ref()).as_deref()
                        == Some("KnowledgeAuthority") =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let comparators = authority_impls
        .iter()
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "is_same_as" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    if comparators.len() != 1
        || !is_pub_crate_visibility(&comparators[0].vis)
        || comparators[0]
            .sig
            .receiver()
            .is_none_or(|receiver| receiver.reference.is_none() || receiver.mutability.is_some())
        || typed_input_types(comparators[0]) != ["Self"]
        || !matches!(&comparators[0].sig.output, syn::ReturnType::Type(_, output)
            if is_plain_ident(output, "bool"))
        || !block_references_all(&comparators[0].block, &["Arc", "ptr_eq"])
    {
        violations.push(
            "KnowledgeAuthority::is_same_as must remain a crate-private Arc identity comparison"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn inspect_cross_source_assessment_bypasses(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let runtime_root = workspace_root.join("crates/venom-scanner/src/web_runtime");
    let mut paths = Vec::new();
    collect_rust_sources(&runtime_root, &mut paths)?;
    paths.sort();
    let mut violations = Vec::new();
    for path in paths {
        let source_name = relative_source_name(workspace_root, &path)?;
        let source = fs::read_to_string(&path)?;
        let syntax = syn::parse_file(&source)?;
        let file_is_test = source_path_is_test_only(&path);
        if source_name != ASSESSMENT_ITEM_SOURCE {
            violations.extend(inspect_external_assessment_impls(&source_name, &syntax));
        }
        violations.extend(inspect_production_verifier_descriptors(
            &source_name,
            &syntax,
            file_is_test,
        ));
    }
    Ok(violations)
}

fn inspect_external_assessment_impls(source_name: &str, syntax: &syn::File) -> Vec<String> {
    let (protected_type_aliases, forbidden_trait_aliases) = collect_assessment_impl_aliases(syntax);
    let mut violations = Vec::new();
    struct ImplVisitor<'a> {
        source_name: &'a str,
        protected_type_aliases: &'a BTreeSet<String>,
        forbidden_trait_aliases: &'a BTreeSet<String>,
        violations: &'a mut Vec<String>,
    }
    impl<'ast> Visit<'ast> for ImplVisitor<'_> {
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let Some(self_name) = type_last_identifier(item.self_ty.as_ref()) else {
                visit::visit_item_impl(self, item);
                return;
            };
            if !self.protected_type_aliases.contains(&self_name) {
                visit::visit_item_impl(self, item);
                return;
            }
            match item.trait_.as_ref() {
                None => {
                    self.violations.push(format!(
                        "{} defines an external inherent impl for {}; construction authority must remain in {}",
                        self.source_name, self_name, ASSESSMENT_ITEM_SOURCE
                    ));
                },
                Some((_, trait_path, _)) => {
                    let trait_name = trait_path
                        .segments
                        .last()
                        .map(|segment| ident_name(&segment.ident))
                        .unwrap_or_default();
                    if self.forbidden_trait_aliases.contains(&trait_name) {
                        self.violations.push(format!(
                            "{} externally implements forbidden trait {} for protected assessment model {}",
                            self.source_name, trait_name, self_name
                        ));
                    }
                },
            }
            visit::visit_item_impl(self, item);
        }

        fn visit_macro(&mut self, item: &'ast Macro) {
            let mentions_protected = self
                .protected_type_aliases
                .iter()
                .any(|name| token_stream_contains_identifier(item.tokens.clone(), name));
            if mentions_protected && token_stream_contains_identifier(item.tokens.clone(), "impl") {
                self.violations.push(format!(
                    "{} may not hide an assessment-model impl inside a macro outside {}",
                    self.source_name, ASSESSMENT_ITEM_SOURCE
                ));
            }
            visit::visit_macro(self, item);
        }
    }
    let mut visitor = ImplVisitor {
        source_name,
        protected_type_aliases: &protected_type_aliases,
        forbidden_trait_aliases: &forbidden_trait_aliases,
        violations: &mut violations,
    };
    visitor.visit_file(syntax);
    violations
}

fn collect_assessment_impl_aliases(syntax: &syn::File) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut protected = ASSESSMENT_EXTERNAL_TRAIT_PROTECTED_TYPES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let mut forbidden_traits = ASSESSMENT_FORBIDDEN_EXTERNAL_TRAITS
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    for item in &syntax.items {
        let Item::Use(item_use) = item else {
            continue;
        };
        let mut uses = Vec::new();
        collect_use_paths(&item_use.tree, Vec::new(), &mut uses);
        for (segments, binding, is_glob) in uses {
            if is_glob {
                continue;
            }
            let Some(source) = segments.last().map(|segment| normalize_identifier(segment)) else {
                continue;
            };
            let target = binding
                .as_deref()
                .map(normalize_identifier)
                .unwrap_or(source)
                .to_owned();
            if ASSESSMENT_EXTERNAL_TRAIT_PROTECTED_TYPES.contains(&source) {
                protected.insert(target.clone());
            }
            if ASSESSMENT_FORBIDDEN_EXTERNAL_TRAITS.contains(&source) {
                forbidden_traits.insert(target);
            }
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for item in &syntax.items {
            let Item::Type(alias) = item else {
                continue;
            };
            if protected
                .iter()
                .any(|protected| type_references_ident(&alias.ty, protected))
            {
                changed |= protected.insert(ident_name(&alias.ident));
            }
        }
    }
    (protected, forbidden_traits)
}

fn inspect_production_verifier_descriptors(
    source_name: &str,
    syntax: &syn::File,
    file_is_test: bool,
) -> Vec<String> {
    if file_is_test {
        return Vec::new();
    }
    #[derive(Default)]
    struct DescriptorVisitor {
        descriptor_initializers: usize,
        noninformational_initializers: usize,
        verifier_transitions: usize,
    }
    impl<'ast> Visit<'ast> for DescriptorVisitor {
        fn visit_item(&mut self, item: &'ast Item) {
            if !has_cfg_test(item_attributes(item)) {
                visit::visit_item(self, item);
            }
        }

        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            if type_references_ident(&item.ty, "AssessmentCapabilityDescriptor") {
                self.descriptor_initializers = self.descriptor_initializers.saturating_add(1);
                if !expression_invokes_named_function(&item.expr, "informational") {
                    self.noninformational_initializers =
                        self.noninformational_initializers.saturating_add(1);
                }
                if expression_references_ident(&item.expr, "VerifierTransition") {
                    self.verifier_transitions = self.verifier_transitions.saturating_add(1);
                }
            }
            visit::visit_item_const(self, item);
        }

        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            if type_references_ident(&item.ty, "AssessmentCapabilityDescriptor") {
                self.descriptor_initializers = self.descriptor_initializers.saturating_add(1);
                if !expression_invokes_named_function(&item.expr, "informational") {
                    self.noninformational_initializers =
                        self.noninformational_initializers.saturating_add(1);
                }
                if expression_references_ident(&item.expr, "VerifierTransition") {
                    self.verifier_transitions = self.verifier_transitions.saturating_add(1);
                }
            }
            visit::visit_item_static(self, item);
        }
    }
    let mut visitor = DescriptorVisitor::default();
    visitor.visit_file(syntax);
    let mut violations = Vec::new();
    if visitor.verifier_transitions != 0 || visitor.noninformational_initializers != 0 {
        violations.push(format!(
            "{source_name} defines a production AssessmentCapabilityDescriptor outside the observation-only informational constructor; VerifierTransition descriptors remain test-only"
        ));
    }
    violations
}

fn source_path_is_test_only(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|value| value == "tests")
    }) || path
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.ends_with("_tests") || value == "tests")
}

fn type_has_explicit_trait_impl(
    syntax: &syn::File,
    expected_type: &str,
    forbidden_traits: &[&str],
) -> bool {
    syntax.items.iter().any(|item| {
        let Item::Impl(item) = item else {
            return false;
        };
        type_last_identifier(item.self_ty.as_ref()).as_deref() == Some(expected_type)
            && item.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments.last().is_some_and(|segment| {
                    forbidden_traits.contains(&normalize_identifier(&ident_name(&segment.ident)))
                })
            })
    })
}

fn is_assessment_item_set_parts(item_type: &syn::Type) -> bool {
    matches!(item_type, syn::Type::Tuple(tuple)
        if tuple.elems.len() == 2
            && is_generic_of_idents(
                &tuple.elems[0],
                "Vec",
                &["AssessmentSubjectInventoryEntry"],
            )
            && is_generic_of_idents(&tuple.elems[1], "Vec", &["AssessmentItem"]))
}

fn is_borrowed_slice_of(item_type: &syn::Type, expected: &str) -> bool {
    matches!(item_type, syn::Type::Reference(reference)
        if reference.mutability.is_none()
            && matches!(reference.elem.as_ref(), syn::Type::Slice(slice)
                if is_plain_ident(slice.elem.as_ref(), expected)))
}

fn statement_reference_precedes(block: &syn::Block, first: &str, second: &str) -> bool {
    let first = block
        .stmts
        .iter()
        .position(|statement| statement_references_ident(statement, first));
    let second = block
        .stmts
        .iter()
        .position(|statement| statement_references_ident(statement, second));
    first
        .zip(second)
        .is_some_and(|(first, second)| first < second)
}

fn statement_references_ident(statement: &syn::Stmt, needle: &str) -> bool {
    struct IdentifierVisitor<'a> {
        needle: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for IdentifierVisitor<'_> {
        fn visit_path(&mut self, path: &'ast SynPath) {
            self.found |= path
                .segments
                .iter()
                .any(|segment| normalize_identifier(&ident_name(&segment.ident)) == self.needle);
            if !self.found {
                visit::visit_path(self, path);
            }
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.found |= normalize_identifier(&ident_name(&call.method)) == self.needle;
            if !self.found {
                visit::visit_expr_method_call(self, call);
            }
        }

        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.found |= matches!(&field.member, syn::Member::Named(member)
                if normalize_identifier(&ident_name(member)) == self.needle);
            if !self.found {
                visit::visit_expr_field(self, field);
            }
        }
    }
    let mut visitor = IdentifierVisitor {
        needle: normalize_identifier(needle),
        found: false,
    };
    visitor.visit_stmt(statement);
    visitor.found
}

fn expression_references_ident(expression: &syn::Expr, needle: &str) -> bool {
    let statement = syn::Stmt::Expr(expression.clone(), None);
    statement_references_ident(&statement, needle)
}

fn expression_invokes_named_function(expression: &syn::Expr, needle: &str) -> bool {
    struct CallVisitor<'a> {
        needle: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for CallVisitor<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.found |= matches!(call.func.as_ref(), syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|segment|
                    normalize_identifier(&ident_name(&segment.ident)) == self.needle));
            if !self.found {
                visit::visit_expr_call(self, call);
            }
        }
    }
    let mut visitor = CallVisitor {
        needle: normalize_identifier(needle),
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}

fn syntax_invokes_method(syntax: &syn::File, needle: &str) -> bool {
    struct MethodVisitor<'a> {
        needle: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for MethodVisitor<'_> {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.found |= normalize_identifier(&ident_name(&call.method)) == self.needle;
            if !self.found {
                visit::visit_expr_method_call(self, call);
            }
        }
    }
    let mut visitor = MethodVisitor {
        needle: normalize_identifier(needle),
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

fn syntax_references_exact_ident(syntax: &syn::File, needle: &str) -> bool {
    struct ExactIdentifierVisitor<'a> {
        needle: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for ExactIdentifierVisitor<'_> {
        fn visit_path(&mut self, path: &'ast SynPath) {
            self.found |= path
                .segments
                .iter()
                .any(|segment| normalize_identifier(&ident_name(&segment.ident)) == self.needle);
            if !self.found {
                visit::visit_path(self, path);
            }
        }

        fn visit_item_use(&mut self, item: &'ast ItemUse) {
            let mut paths = Vec::new();
            collect_use_paths(&item.tree, Vec::new(), &mut paths);
            self.found |= paths.iter().any(|(segments, _, _)| {
                segments
                    .iter()
                    .any(|segment| normalize_identifier(segment) == self.needle)
            });
            if !self.found {
                visit::visit_item_use(self, item);
            }
        }

        fn visit_macro(&mut self, item: &'ast Macro) {
            self.found |= token_stream_contains_identifier(item.tokens.clone(), self.needle);
            if !self.found {
                visit::visit_macro(self, item);
            }
        }
    }
    let mut visitor = ExactIdentifierVisitor {
        needle: normalize_identifier(needle),
        found: false,
    };
    visitor.visit_file(syntax);
    visitor.found
}

fn block_has_exact_knowledge_authority_comparison(block: &syn::Block) -> bool {
    struct ComparisonVisitor {
        exact_calls: usize,
        total_calls: usize,
    }
    impl<'ast> Visit<'ast> for ComparisonVisitor {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "is_same_as" {
                self.total_calls = self.total_calls.saturating_add(1);
                let receiver_is_authority = matches!(call.receiver.as_ref(), syn::Expr::MethodCall(authority)
                    if authority.method == "authority"
                        && authority.args.is_empty()
                        && expression_is_path_ident(authority.receiver.as_ref(), "knowledge"));
                let argument_is_context_authority = call.args.len() == 1
                    && call.args.first().is_some_and(|argument| {
                        expression_is_borrowed_self_field(argument, "knowledge_authority")
                    });
                if receiver_is_authority && argument_is_context_authority {
                    self.exact_calls = self.exact_calls.saturating_add(1);
                }
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = ComparisonVisitor {
        exact_calls: 0,
        total_calls: 0,
    };
    visitor.visit_block(block);
    visitor.total_calls == 1 && visitor.exact_calls == 1
}

fn block_is_borrowed_self_field(block: &syn::Block, expected: &str) -> bool {
    block.stmts.len() == 1
        && matches!(&block.stmts[0], syn::Stmt::Expr(expression, None)
            if expression_is_borrowed_self_field(expression, expected))
}

fn expression_is_borrowed_self_field(expression: &syn::Expr, expected: &str) -> bool {
    let syn::Expr::Reference(reference) = expression else {
        return false;
    };
    reference.mutability.is_none()
        && matches!(reference.expr.as_ref(), syn::Expr::Field(field)
            if expression_is_path_ident(field.base.as_ref(), "self")
                && matches!(&field.member, syn::Member::Named(member)
                    if normalize_identifier(&ident_name(member)) == expected))
}

fn expression_is_path_ident(expression: &syn::Expr, expected: &str) -> bool {
    matches!(expression, syn::Expr::Path(path)
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path.path.segments.last().is_some_and(|segment|
                normalize_identifier(&ident_name(&segment.ident)) == expected))
}

fn verifier_confidence_is_exact(method: &syn::ImplItemFn) -> bool {
    struct ConfidenceVisitor {
        exact_min_calls: usize,
    }
    impl<'ast> Visit<'ast> for ConfidenceVisitor {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "min"
                && call.args.len() == 1
                && expression_references_ident(
                    call.receiver.as_ref(),
                    "bounded_observation_confidence",
                )
                && call.args.first().is_some_and(|argument| {
                    expression_references_ident(argument, "outcome")
                        && expression_references_ident(argument, "confidence")
                })
            {
                self.exact_min_calls = self.exact_min_calls.saturating_add(1);
            }
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut visitor = ConfidenceVisitor { exact_min_calls: 0 };
    visitor.visit_block(&method.block);
    let evidence_helper_precedes_build =
        statement_reference_precedes(&method.block, "bounded_observation_confidence", "build");
    visitor.exact_min_calls == 1 && evidence_helper_precedes_build
}

fn exact_verifier_projection_factory(method: &syn::ImplItemFn) -> bool {
    if !matches!(method.vis, syn::Visibility::Inherited)
        || method.sig.receiver().is_some()
        || method.sig.asyncness.is_some()
        || method.sig.constness.is_some()
        || method.sig.unsafety.is_some()
        || method.sig.abi.is_some()
        || method.sig.variadic.is_some()
        || !method.sig.generics.params.is_empty()
        || method.sig.generics.where_clause.is_some()
    {
        return false;
    }
    let arguments = method
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            syn::FnArg::Typed(argument) => Some(argument.ty.as_ref()),
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    arguments.len() == 6
        && is_static_borrowed_ident(arguments[0], "AssessmentCapabilityDescriptor")
        && is_borrowed_ident(arguments[1], "AssessmentProjectionContext")
        && is_borrowed_ident(arguments[2], "AssessmentItemTarget")
        && is_borrowed_ident(arguments[3], "DecisionEvidenceReceipt")
        && is_borrowed_ident(arguments[4], "DecisionOutcomeReport")
        && is_borrowed_ident(arguments[5], "KnowledgeBase")
        && matches!(&method.sig.output, syn::ReturnType::Type(_, output)
            if is_result_of(output, "Self", "AssessmentItemProjectionError"))
}

fn inherent_impl<'a>(syntax: &'a syn::File, expected: &str) -> Option<&'a syn::ItemImpl> {
    let mut implementations = syntax.items.iter().filter_map(|item| match item {
        Item::Impl(item) if item.trait_.is_none() => {
            let syn::Type::Path(item_type) = item.self_ty.as_ref() else {
                return None;
            };
            item_type
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == expected)
                .then_some(item)
        },
        _ => None,
    });
    let first = implementations.next()?;
    implementations.next().is_none().then_some(first)
}

fn private_named_fields(item: &syn::ItemStruct) -> Option<BTreeMap<String, &syn::Type>> {
    let syn::Fields::Named(fields) = &item.fields else {
        return None;
    };
    fields
        .named
        .iter()
        .map(|field| {
            if !matches!(field.vis, syn::Visibility::Inherited) {
                return None;
            }
            Some((ident_name(field.ident.as_ref()?), &field.ty))
        })
        .collect()
}

fn private_named_field<'a>(item: &'a syn::ItemStruct, expected: &str) -> Option<&'a syn::Field> {
    let syn::Fields::Named(fields) = &item.fields else {
        return None;
    };
    fields.named.iter().find(|field| {
        matches!(field.vis, syn::Visibility::Inherited)
            && field
                .ident
                .as_ref()
                .is_some_and(|ident| ident_name(ident) == expected)
    })
}

fn private_single_tuple_field_is(
    item: &syn::ItemStruct,
    predicate: impl FnOnce(&syn::Type) -> bool,
) -> bool {
    let syn::Fields::Unnamed(fields) = &item.fields else {
        return false;
    };
    fields.unnamed.len() == 1
        && matches!(fields.unnamed[0].vis, syn::Visibility::Inherited)
        && predicate(&fields.unnamed[0].ty)
}

fn generic_type_arguments<'a>(item_type: &'a syn::Type, outer: &str) -> Option<Vec<&'a syn::Type>> {
    let syn::Type::Path(path) = item_type else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let segment = path.path.segments.last()?;
    if normalize_identifier(&ident_name(&segment.ident)) != outer {
        return None;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    arguments
        .args
        .iter()
        .map(|argument| match argument {
            syn::GenericArgument::Type(item_type) => Some(item_type),
            _ => None,
        })
        .collect()
}

fn is_generic_of_idents(item_type: &syn::Type, outer: &str, arguments: &[&str]) -> bool {
    generic_type_arguments(item_type, outer).is_some_and(|actual| {
        actual.len() == arguments.len()
            && actual
                .iter()
                .zip(arguments)
                .all(|(item_type, expected)| is_plain_ident(item_type, expected))
    })
}

fn is_entity_string_tuple(item_type: &syn::Type) -> bool {
    matches!(item_type, syn::Type::Tuple(tuple)
        if tuple.elems.len() == 2
            && is_plain_ident(&tuple.elems[0], "EntityId")
            && is_plain_ident(&tuple.elems[1], "String"))
}

fn is_static_str_reference(item_type: &syn::Type) -> bool {
    matches!(item_type, syn::Type::Reference(reference)
        if reference.mutability.is_none()
            && reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "static")
            && is_plain_ident(reference.elem.as_ref(), "str"))
}

fn is_static_borrowed_ident(item_type: &syn::Type, expected: &str) -> bool {
    matches!(item_type, syn::Type::Reference(reference)
        if reference.mutability.is_none()
            && reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "static")
            && is_plain_ident(reference.elem.as_ref(), expected))
}

fn assessment_projection_error_field_is_safe(item_type: &syn::Type) -> bool {
    is_plain_ident(item_type, "AssessmentDisposition")
        || is_plain_ident(item_type, "AssessmentConfirmationDenial")
        || is_plain_ident(item_type, "usize")
        || is_static_str_reference(item_type)
}

fn is_pub_crate_visibility(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Restricted(restricted)
        if restricted.in_token.is_none() && restricted.path.is_ident("crate"))
}

fn typed_input_types(method: &syn::ImplItemFn) -> Vec<String> {
    method
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            syn::FnArg::Typed(argument) => type_last_identifier(&argument.ty),
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn type_last_identifier(item_type: &syn::Type) -> Option<String> {
    match item_type {
        syn::Type::Reference(reference) => type_last_identifier(reference.elem.as_ref()),
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| ident_name(&segment.ident)),
        _ => None,
    }
}

fn is_result_of(item_type: &syn::Type, success: &str, error: &str) -> bool {
    generic_type_arguments(item_type, "Result").is_some_and(|arguments| {
        arguments.len() == 2
            && is_plain_ident(arguments[0], success)
            && is_plain_ident(arguments[1], error)
    })
}

fn block_references_all(block: &syn::Block, required: &[&str]) -> bool {
    struct IdentifierVisitor {
        identifiers: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for IdentifierVisitor {
        fn visit_path(&mut self, path: &'ast SynPath) {
            self.identifiers.extend(
                path.segments
                    .iter()
                    .map(|segment| normalize_identifier(&ident_name(&segment.ident)).to_owned()),
            );
            visit::visit_path(self, path);
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.identifiers
                .insert(normalize_identifier(&ident_name(&call.method)).to_owned());
            visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if let syn::Member::Named(member) = &field.member {
                self.identifiers
                    .insert(normalize_identifier(&ident_name(member)).to_owned());
            }
            visit::visit_expr_field(self, field);
        }

        fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
            if let syn::Member::Named(member) = &field.member {
                self.identifiers
                    .insert(normalize_identifier(&ident_name(member)).to_owned());
            }
            visit::visit_field_value(self, field);
        }

        fn visit_macro(&mut self, item: &'ast Macro) {
            collect_token_identifiers(item.tokens.clone(), &mut self.identifiers);
            visit::visit_macro(self, item);
        }
    }
    let mut visitor = IdentifierVisitor {
        identifiers: BTreeSet::new(),
    };
    visitor.visit_block(block);
    required
        .iter()
        .all(|required| visitor.identifiers.contains(normalize_identifier(required)))
}

fn inspect_complete_observer_seam(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let observer_trait = syntax.items.iter().find_map(|item| match item {
        Item::Trait(item) if item.ident == "CompleteHttpResponseObserver" => Some(item),
        _ => None,
    });
    if observer_trait.is_none_or(|item| {
        !matches!(item.vis, syn::Visibility::Restricted(_))
            || !item.supertraits.iter().any(|bound| match bound {
                syn::TypeParamBound::Trait(bound) => path_segments(&bound.path)
                    .iter()
                    .any(|segment| normalize_identifier(segment) == "Sealed"),
                _ => false,
            })
    }) {
        violations.push(
            "complete response observer must remain crate-private and inherit the private Sealed allowlist"
                .to_owned(),
        );
    }
    if let Some(item) = observer_trait {
        let methods = item
            .items
            .iter()
            .filter_map(|trait_item| match trait_item {
                syn::TraitItem::Fn(method) => Some(method),
                _ => None,
            })
            .collect::<Vec<_>>();
        let observe_is_exact = methods.len() == 1
            && methods[0].sig.ident == "observe"
            && methods[0].sig.inputs.len() == 2
            && methods[0]
                .sig
                .inputs
                .iter()
                .skip(1)
                .all(|input| match input {
                    syn::FnArg::Typed(argument) => {
                        type_references_ident(&argument.ty, "CompleteHttpResponseObservation")
                            && !type_references_any_ident(
                                &argument.ty,
                                &["HeaderMap", "HeaderValue", "String", "Bytes"],
                            )
                    },
                    syn::FnArg::Receiver(_) => false,
                })
            && match &methods[0].sig.output {
                syn::ReturnType::Type(_, output) => {
                    type_references_ident(output, "Evidence")
                        && type_references_ident(output, "HttpEvidenceError")
                },
                syn::ReturnType::Default => false,
            };
        if !observe_is_exact {
            violations.push(
                "complete response observer must expose only the exact borrowed observation-to-evidence method"
                    .to_owned(),
            );
        }
    }
    let observation = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "CompleteHttpResponseObservation" => Some(item),
        _ => None,
    });
    if observation.is_none_or(|item| {
        !matches!(item.vis, syn::Visibility::Restricted(_))
            || item
                .fields
                .iter()
                .any(|field| !matches!(field.vis, syn::Visibility::Inherited))
    }) {
        violations.push(
            "complete response observation must remain crate-private with private fields"
                .to_owned(),
        );
    }
    if let Some(item) = observation {
        let actual_fields = item
            .fields
            .iter()
            .filter_map(|field| field.ident.as_ref().map(ident_name))
            .collect::<BTreeSet<_>>();
        let expected_fields = [
            "action_id",
            "applies_hypothesis_transition",
            "case_id",
            "complete_body",
            "has_payload_strategy",
            "hypothesis_id",
            "media_type",
            "method",
            "reliability",
            "request_method_evidence_id",
            "request_url_evidence_id",
            "requested_url",
            "response_body_digest_evidence_id",
            "response_body_truncated_evidence_id",
            "response_final_url_evidence_id",
            "response_media_type_evidence_id",
            "response_status_evidence_id",
            "passive_response_projection",
            "stage",
            "status",
            "subject",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        let complete_body_is_borrowed_slice = item.fields.iter().any(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "complete_body")
                && is_optional_borrowed_u8_slice(&field.ty)
        });
        let every_field_type_is_exact = item.fields.iter().all(|field| {
            field.ident.as_ref().is_some_and(|ident| {
                assessment_observation_type_matches(&ident_name(ident), &field.ty)
            })
        });
        let forbidden_owned_field = item.fields.iter().any(|field| {
            type_references_any_ident(
                &field.ty,
                &["HeaderMap", "HeaderValue", "Vec", "String", "Bytes"],
            )
        });
        if actual_fields != expected_fields
            || !complete_body_is_borrowed_slice
            || !every_field_type_is_exact
            || forbidden_owned_field
            || attrs_reference_any_ident(
                &item.attrs,
                &["Clone", "Debug", "Serialize", "Deserialize", "serde"],
            )
        {
            violations.push(
                "complete response observation must remain the exact non-cloneable borrowed scalar/ID/body/value-free-passive view with no owned strings, headers, or bytes"
                    .to_owned(),
            );
        }
        let allowed_accessors = expected_fields;
        let accessor_methods = syntax
            .items
            .iter()
            .filter_map(|syntax_item| match syntax_item {
                Item::Impl(item_impl)
                    if matches!(item_impl.self_ty.as_ref(), syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|segment|
                            segment.ident == "CompleteHttpResponseObservation")) =>
                {
                    Some(item_impl)
                },
                _ => None,
            })
            .flat_map(|item_impl| item_impl.items.iter())
            .filter_map(|impl_item| match impl_item {
                syn::ImplItem::Fn(method) => Some(method),
                _ => None,
            })
            .collect::<Vec<_>>();
        let actual_accessors = accessor_methods
            .iter()
            .map(|method| ident_name(&method.sig.ident))
            .collect::<BTreeSet<_>>();
        let accessor_signatures_are_exact = accessor_methods.iter().all(|method| {
            let name = ident_name(&method.sig.ident);
            matches!(method.vis, syn::Visibility::Restricted(_))
                && method.sig.inputs.len() == 1
                && matches!(method.sig.inputs.first(), Some(syn::FnArg::Receiver(_)))
                && match &method.sig.output {
                    syn::ReturnType::Type(_, output) => {
                        assessment_observation_type_matches(&name, output)
                    },
                    syn::ReturnType::Default => false,
                }
        });
        if actual_accessors != allowed_accessors || !accessor_signatures_are_exact {
            violations.push(format!(
                "complete response observation accessor allowlist drifted; expected {allowed_accessors:?}, observed {actual_accessors:?}"
            ));
        }
        if syntax.items.iter().any(|syntax_item| {
            matches!(syntax_item, Item::Impl(item_impl)
                if item_impl.trait_.is_some()
                    && matches!(item_impl.self_ty.as_ref(), syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|segment|
                            segment.ident == "CompleteHttpResponseObservation")))
        }) {
            violations.push(
                "complete response observation must not implement cloning, serialization, ownership, or formatting traits"
                    .to_owned(),
            );
        }
    }
    let seal_module = syntax.items.iter().find_map(|item| match item {
        Item::Mod(item) if item.ident == "complete_response_observer_seal" => Some(item),
        _ => None,
    });
    let exact_seal = seal_module.is_some_and(|module| {
        matches!(module.vis, syn::Visibility::Inherited)
            && module.content.as_ref().is_some_and(|(_, items)| {
                let sealed_traits = items
                    .iter()
                    .filter(|item| matches!(item, Item::Trait(item) if item.ident == "Sealed"))
                    .count();
                let production_impls = items
                    .iter()
                    .filter_map(|item| match item {
                        Item::Impl(item) if !has_cfg_test(&item.attrs) => Some(item),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                sealed_traits == 1
                    && production_impls.len() == 1
                    && production_impls[0]
                        .trait_
                        .as_ref()
                        .is_some_and(|(_, path, _)| {
                            path.segments
                                .last()
                                .is_some_and(|segment| segment.ident == "Sealed")
                        })
                    && matches!(production_impls[0].self_ty.as_ref(), syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|segment|
                            segment.ident == "AssessmentDiscoveryObserver"))
                    && items.iter().all(|item| match item {
                        Item::Impl(item) => {
                            !has_cfg_test(&item.attrs)
                                || item.trait_.as_ref().is_some_and(|(_, path, _)| {
                                    path.segments
                                        .last()
                                        .is_some_and(|segment| segment.ident == "Sealed")
                                })
                        },
                        _ => true,
                    })
            })
    });
    if !exact_seal {
        violations.push(
            "complete response observer seal must allowlist exactly AssessmentDiscoveryObserver"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn attrs_reference_any_ident(attributes: &[syn::Attribute], needles: &[&str]) -> bool {
    attributes.iter().any(|attribute| {
        let path_matches = attribute.path().segments.iter().any(|segment| {
            needles
                .iter()
                .any(|needle| normalize_identifier(&ident_name(&segment.ident)) == *needle)
        });
        path_matches
            || match &attribute.meta {
                syn::Meta::List(list) => needles
                    .iter()
                    .any(|needle| token_stream_contains_identifier(list.tokens.clone(), needle)),
                syn::Meta::Path(_) | syn::Meta::NameValue(_) => false,
            }
    })
}

fn attributes_are_exact_cfg_feature(attributes: &[syn::Attribute], expected: &str) -> bool {
    attributes.len() == 1 && attribute_is_exact_cfg_feature(&attributes[0], expected)
}

fn attributes_are_exact_cfg_feature_allowing_docs(
    attributes: &[syn::Attribute],
    expected: &str,
) -> bool {
    let mut non_docs = attributes
        .iter()
        .filter(|attribute| !attribute.path().is_ident("doc"));
    let Some(attribute) = non_docs.next() else {
        return false;
    };
    non_docs.next().is_none() && attribute_is_exact_cfg_feature(attribute, expected)
}

fn attribute_is_exact_cfg_feature(attribute: &syn::Attribute, expected: &str) -> bool {
    if !attribute.path().is_ident("cfg") {
        return false;
    }
    let Ok(list) = attribute.meta.require_list() else {
        return false;
    };
    matches!(syn::parse2::<syn::Meta>(list.tokens.clone()),
        Ok(syn::Meta::NameValue(value))
            if value.path.is_ident("feature")
                && matches!(&value.value, syn::Expr::Lit(expression)
                    if matches!(&expression.lit, syn::Lit::Str(value)
                        if value.value() == expected)))
}

fn attributes_are_exact_cfg_feature_or_test(attributes: &[syn::Attribute], expected: &str) -> bool {
    if attributes.len() != 1 || !attributes[0].path().is_ident("cfg") {
        return false;
    }
    let Ok(list) = attributes[0].meta.require_list() else {
        return false;
    };
    normalized_token_text(&list.tokens) == format!("any(feature=\"{expected}\",test)")
}

fn type_references_any_ident(item_type: &syn::Type, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| type_references_ident(item_type, needle))
}

fn is_optional_borrowed_u8_slice(item_type: &syn::Type) -> bool {
    let syn::Type::Path(option) = item_type else {
        return false;
    };
    let Some(segment) = option.path.segments.last() else {
        return false;
    };
    if segment.ident != "Option" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(syn::Type::Reference(reference))) = arguments.args.first()
    else {
        return false;
    };
    if reference.mutability.is_some() {
        return false;
    }
    let syn::Type::Slice(slice) = reference.elem.as_ref() else {
        return false;
    };
    matches!(slice.elem.as_ref(), syn::Type::Path(path)
        if path.path.is_ident("u8"))
}

fn assessment_observation_type_matches(name: &str, item_type: &syn::Type) -> bool {
    match name {
        "case_id" | "action_id" | "hypothesis_id" => is_borrowed_ident(item_type, "str"),
        "has_payload_strategy" | "applies_hypothesis_transition" => {
            is_plain_ident(item_type, "bool")
        },
        "stage" => is_plain_ident(item_type, "DecisionExecutionStage"),
        "subject" => is_borrowed_ident(item_type, "EntityId"),
        "method" => is_plain_ident(item_type, "HttpProbeMethod"),
        "requested_url" => is_borrowed_ident(item_type, "Url"),
        "status" => is_plain_ident(item_type, "u16"),
        "media_type" => is_optional_borrowed_ident(item_type, "str"),
        "reliability" => is_plain_ident(item_type, "ConfidenceScore"),
        "complete_body" => is_optional_borrowed_u8_slice(item_type),
        "request_method_evidence_id"
        | "request_url_evidence_id"
        | "response_status_evidence_id"
        | "response_final_url_evidence_id"
        | "response_media_type_evidence_id"
        | "response_body_truncated_evidence_id"
        | "response_body_digest_evidence_id" => is_optional_borrowed_ident(item_type, "EvidenceId"),
        "passive_response_projection" => is_borrowed_ident(item_type, "PassiveResponseProjection"),
        _ => false,
    }
}

fn is_plain_ident(item_type: &syn::Type, expected: &str) -> bool {
    matches!(item_type, syn::Type::Path(path)
        if path.qself.is_none()
            && path.path.segments.last().is_some_and(|segment|
                normalize_identifier(&ident_name(&segment.ident)) == expected
                    && matches!(segment.arguments, syn::PathArguments::None)))
}

fn is_borrowed_ident(item_type: &syn::Type, expected: &str) -> bool {
    matches!(item_type, syn::Type::Reference(reference)
        if reference.mutability.is_none() && is_plain_ident(reference.elem.as_ref(), expected))
}

fn is_optional_borrowed_ident(item_type: &syn::Type, expected: &str) -> bool {
    let syn::Type::Path(option) = item_type else {
        return false;
    };
    let Some(segment) = option.path.segments.last() else {
        return false;
    };
    if segment.ident != "Option" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    matches!(arguments.args.first(), Some(syn::GenericArgument::Type(item_type))
        if is_borrowed_ident(item_type, expected))
        && arguments.args.len() == 1
}

fn inspect_legacy_verification_claim_language(source_name: &str, source: &str) -> Vec<String> {
    let production = source.split("#[cfg(test)]").next().unwrap_or(source);
    let normalized = production.to_ascii_lowercase();
    let mut violations = [
        ("confirmed", "verifier-owned confirmation language"),
        ("vulnerability", "vulnerability language"),
        ("severity: \"high\"", "HIGH raw severity"),
        ("severity: \"critical\"", "CRITICAL raw severity"),
        (" expert", "expert product identity"),
        ("escaper", "exploit-escaper identity"),
    ]
    .into_iter()
    .filter(|(needle, _)| normalized.contains(needle))
    .map(|(_, label)| {
            format!(
                "{source_name} contains {label} in a legacy verification phase; emit INFO observations and defer claim transitions to a verifier"
            )
    })
    .collect::<Vec<_>>();
    for (needle, label) in [
        ("Outcome::new", "direct Outcome construction"),
        ("RunOutcomeRecord::", "direct run-outcome construction"),
        ("RunOutcomeRecordInput", "direct run-outcome input"),
    ] {
        if production.contains(needle) {
            violations.push(format!(
                "{source_name} contains {label}; legacy verification phases must use VerificationReport through the context bridge"
            ));
        }
    }
    violations
}

fn validate_policy_inventory() -> Vec<String> {
    let mut violations = Vec::new();
    let bounded: BTreeSet<_> = BOUNDED_RUNTIME_SOURCES.iter().copied().collect();
    if bounded.len() != BOUNDED_RUNTIME_SOURCES.len() {
        violations.push("bounded runtime transport policy contains duplicate sources".to_owned());
    }
    if bounded.contains(TRANSPORT_OWNER_SOURCE) {
        violations.push(format!(
            "transport owner {TRANSPORT_OWNER_SOURCE} must remain separate from bounded consumers"
        ));
    }
    let migrated: BTreeSet<_> = MIGRATED_LEGACY_DISCOVERY_SOURCES.iter().copied().collect();
    if migrated.len() != MIGRATED_LEGACY_DISCOVERY_SOURCES.len() {
        violations.push("migrated legacy discovery policy contains duplicate sources".to_owned());
    }
    if migrated.iter().any(|source| bounded.contains(source)) {
        violations.push(
            "migrated legacy discovery sources must remain separate from the standard bounded runtime inventory"
                .to_owned(),
        );
    }
    if DIRECT_CLIENT_SOURCE_ALLOWLIST
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != DIRECT_CLIENT_SOURCE_ALLOWLIST.len()
    {
        violations.push("direct-client source allowlist contains duplicates".to_owned());
    }
    if UNMETERED_STANDALONE_FACADE_SOURCES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .len()
        != UNMETERED_STANDALONE_FACADE_SOURCES.len()
    {
        violations.push("unmetered standalone facade allowlist contains duplicates".to_owned());
    }
    for source in UNMETERED_STANDALONE_FACADE_SOURCES {
        if !bounded.contains(source) {
            violations.push(format!(
                "unmetered standalone facade {source} must remain in the bounded-source inventory"
            ));
        }
    }
    if LEGACY_PHASE_SEND_ALLOWLIST
        .iter()
        .map(|(source, _)| *source)
        .collect::<BTreeSet<_>>()
        .len()
        != LEGACY_PHASE_SEND_ALLOWLIST.len()
    {
        violations.push("legacy phase send allowlist contains duplicate sources".to_owned());
    }
    violations
}

#[cfg(test)]
fn inspect_bounded_source(source_name: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    inspect_bounded_source_with_legacy_aliases(
        source_name,
        source,
        &canonical_legacy_authority_aliases(),
    )
}

fn inspect_bounded_source_with_legacy_aliases(
    source_name: &str,
    source: &str,
    legacy_authority_aliases: &BTreeSet<String>,
) -> Result<Vec<String>, syn::Error> {
    inspect_owned_transport_source(source_name, source, false, false, legacy_authority_aliases)
}

fn inspect_migrated_discovery_source(
    source_name: &str,
    source: &str,
) -> Result<Vec<String>, syn::Error> {
    let mut violations = inspect_owned_transport_source(
        source_name,
        source,
        true,
        true,
        &canonical_legacy_authority_aliases(),
    )?;
    if source_name != LEGACY_DISCOVERY_AUTHORITY_SOURCE {
        let syntax = syn::parse_file(source)?;
        let mut visitor = DiscoveryConsumerVisitor {
            source: source_name,
            context_aliases: collect_context_aliases(&syntax),
            forbidden_claim_aliases: if LEGACY_VERIFICATION_PHASE_SOURCES.contains(&source_name) {
                collect_forbidden_claim_aliases(&syntax)
            } else {
                BTreeSet::new()
            },
            violations: BTreeSet::new(),
        };
        visitor.visit_file(&syntax);
        violations.extend(visitor.violations);
    }
    Ok(violations)
}

fn inspect_owned_transport_source(
    source_name: &str,
    source: &str,
    allow_legacy_context_type: bool,
    forbid_execute: bool,
    legacy_authority_aliases: &BTreeSet<String>,
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = OwnershipVisitor {
        source: source_name,
        inline_module_depth: 0,
        allow_legacy_context_type,
        forbid_execute,
        legacy_authority_aliases: legacy_authority_aliases.clone(),
        violations: BTreeSet::new(),
    };
    visitor.visit_file(&syntax);
    Ok(visitor.violations.into_iter().collect())
}

fn canonical_legacy_authority_aliases() -> BTreeSet<String> {
    BTreeSet::from([
        "LegacyDiscoveryAuthority".to_owned(),
        "LegacyVerificationAuthority".to_owned(),
    ])
}

fn collect_full_tree_legacy_authority_aliases(
    workspace_root: &Path,
) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let scanner_root = workspace_root.join("crates/venom-scanner/src");
    let mut paths = Vec::new();
    collect_rust_sources(&scanner_root, &mut paths)?;
    paths.sort();
    let production_paths = production_scanner_sources(&scanner_root, &paths)?;
    let sources = production_paths
        .into_iter()
        .map(fs::read_to_string)
        .collect::<Result<Vec<_>, _>>()?;
    collect_legacy_authority_aliases_from_sources(sources.iter().map(String::as_str))
        .map_err(Into::into)
}

fn collect_legacy_authority_aliases_from_sources<'source>(
    sources: impl IntoIterator<Item = &'source str>,
) -> Result<BTreeSet<String>, syn::Error> {
    let mut edges = Vec::<(String, String)>::new();
    for source in sources {
        let syntax = syn::parse_file(source)?;
        let mut collector = LegacyAuthorityAliasCollector { edges: Vec::new() };
        collector.visit_file(&syntax);
        edges.extend(collector.edges);
    }

    let mut aliases = canonical_legacy_authority_aliases();
    loop {
        let mut changed = false;
        for (alias, target) in &edges {
            if aliases.contains(target) {
                changed |= aliases.insert(alias.clone());
            }
        }
        if !changed {
            break;
        }
    }
    Ok(aliases)
}

struct LegacyAuthorityAliasCollector {
    edges: Vec<(String, String)>,
}

impl LegacyAuthorityAliasCollector {
    fn record_type_alias(&mut self, alias: &syn::Ident, dependencies: TypeDependencies) {
        let alias = normalize_identifier(&ident_name(alias)).to_owned();
        self.edges.extend(
            dependencies
                .names
                .into_iter()
                .map(|dependency| (alias.clone(), dependency)),
        );
    }
}

impl<'ast> Visit<'ast> for LegacyAuthorityAliasCollector {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, binding, glob) in paths {
            if glob {
                continue;
            }
            let Some(target) = segments
                .last()
                .map(|value| normalize_identifier(value).to_owned())
            else {
                continue;
            };
            let alias = binding
                .as_deref()
                .map(normalize_identifier)
                .unwrap_or(&target)
                .to_owned();
            self.edges.push((alias, target));
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.record_type_alias(
            &item.ident,
            type_dependencies_with_generics(Some(item.ty.as_ref()), &item.generics),
        );
        visit::visit_item_type(self, item);
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.record_type_alias(
            &item.ident,
            type_dependencies_with_generics(
                item.default.as_ref().map(|(_, ty)| ty),
                &item.generics,
            ),
        );
        visit::visit_trait_item_type(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.record_type_alias(
            &item.ident,
            type_dependencies_with_generics(Some(&item.ty), &item.generics),
        );
        visit::visit_impl_item_type(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_impl_item_fn(self, item);
        }
    }
}

#[derive(Clone)]
struct BrokerConstructorAliases {
    request_accounting: BTreeSet<String>,
    http_request: BTreeSet<String>,
    opaque_constructor_receivers: BTreeSet<String>,
    include_macros: BTreeSet<String>,
}

impl BrokerConstructorAliases {
    fn kind_for_name(&self, name: &str) -> Option<BrokerConstructorKind> {
        let name = normalize_identifier(name);
        if self.request_accounting.contains(name) {
            Some(BrokerConstructorKind::RequestAccounting)
        } else if self.http_request.contains(name) {
            Some(BrokerConstructorKind::MeteredHttp)
        } else {
            None
        }
    }

    fn name_has_kind(&self, name: &str, kind: BrokerConstructorKind) -> bool {
        let name = normalize_identifier(name);
        match kind {
            BrokerConstructorKind::RequestAccounting => self.request_accounting.contains(name),
            BrokerConstructorKind::MeteredHttp => self.http_request.contains(name),
        }
    }

    fn is_opaque_constructor_receiver(&self, name: &str) -> bool {
        self.opaque_constructor_receivers
            .contains(normalize_identifier(name))
    }

    fn is_include_macro(&self, name: &str) -> bool {
        self.include_macros.contains(normalize_identifier(name))
    }
}

#[cfg(test)]
fn collect_broker_constructor_aliases(syntax: &syn::File) -> BrokerConstructorAliases {
    let mut collector = broker_constructor_alias_collector();
    collector.visit_file(syntax);
    resolve_broker_constructor_aliases(collector)
}

fn broker_constructor_alias_collector() -> BrokerConstructorAliasCollector {
    BrokerConstructorAliasCollector {
        request_accounting: BTreeSet::from(["RequestAccountingBroker".to_owned()]),
        http_request: BTreeSet::from(["HttpRequestBroker".to_owned()]),
        opaque_constructor_receivers: BTreeSet::new(),
        include_macros: BTreeSet::from(["include".to_owned()]),
        alias_edges: Vec::new(),
    }
}

fn resolve_broker_constructor_aliases(
    mut collector: BrokerConstructorAliasCollector,
) -> BrokerConstructorAliases {
    // Resolve use aliases and type aliases together to a fixed point. This is
    // intentionally scope-conservative: no renamed or raw binding may erase
    // constructor or source-inclusion provenance inside a production source.
    loop {
        let mut changed = false;
        for (alias, target) in &collector.alias_edges {
            if collector.request_accounting.contains(target) {
                changed |= collector.request_accounting.insert(alias.clone());
            }
            if collector.http_request.contains(target) {
                changed |= collector.http_request.insert(alias.clone());
            }
            if collector.opaque_constructor_receivers.contains(target) {
                changed |= collector.opaque_constructor_receivers.insert(alias.clone());
            }
            if collector.include_macros.contains(target) {
                changed |= collector.include_macros.insert(alias.clone());
            }
        }
        if !changed {
            break;
        }
    }

    BrokerConstructorAliases {
        request_accounting: collector.request_accounting,
        http_request: collector.http_request,
        opaque_constructor_receivers: collector.opaque_constructor_receivers,
        include_macros: collector.include_macros,
    }
}

struct BrokerConstructorAliasCollector {
    request_accounting: BTreeSet<String>,
    http_request: BTreeSet<String>,
    opaque_constructor_receivers: BTreeSet<String>,
    include_macros: BTreeSet<String>,
    alias_edges: Vec<(String, String)>,
}

impl BrokerConstructorAliasCollector {
    fn record_type_alias(&mut self, alias: &syn::Ident, dependencies: TypeDependencies) {
        let alias = normalize_identifier(&ident_name(alias)).to_owned();
        let has_associated_projection = dependencies.has_associated_projection;
        self.alias_edges.extend(
            dependencies
                .names
                .into_iter()
                .map(|dependency| (alias.clone(), dependency)),
        );
        if has_associated_projection {
            self.opaque_constructor_receivers.insert(alias);
        }
    }
}

impl<'ast> Visit<'ast> for BrokerConstructorAliasCollector {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, binding, glob) in paths {
            if glob {
                continue;
            }
            let Some(imported) = segments.last().map(String::as_str) else {
                continue;
            };
            let local = normalize_identifier(binding.as_deref().unwrap_or(imported)).to_owned();
            self.alias_edges
                .push((local, normalize_identifier(imported).to_owned()));
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.record_type_alias(
            &item.ident,
            type_dependencies_with_generics(Some(item.ty.as_ref()), &item.generics),
        );
        visit::visit_item_type(self, item);
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.record_type_alias(
            &item.ident,
            type_dependencies_with_generics(
                item.default.as_ref().map(|(_, ty)| ty),
                &item.generics,
            ),
        );
        visit::visit_trait_item_type(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.record_type_alias(
            &item.ident,
            type_dependencies_with_generics(Some(&item.ty), &item.generics),
        );
        visit::visit_impl_item_type(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_impl_item_fn(self, item);
        }
    }
}

fn type_path(ty: &syn::Type) -> Option<&syn::TypePath> {
    match ty {
        syn::Type::Group(group) => type_path(&group.elem),
        syn::Type::Paren(parenthesized) => type_path(&parenthesized.elem),
        syn::Type::Path(path) => Some(path),
        _ => None,
    }
}

#[derive(Default)]
struct TypeDependencies {
    names: BTreeSet<String>,
    has_associated_projection: bool,
}

fn type_dependencies_with_generics(
    ty: Option<&syn::Type>,
    generics: &syn::Generics,
) -> TypeDependencies {
    let mut dependencies = TypeDependencies::default();
    if let Some(ty) = ty {
        dependencies.visit_type(ty);
    }
    for parameter in &generics.params {
        if let syn::GenericParam::Type(parameter) = parameter {
            if let Some(default) = &parameter.default {
                dependencies.visit_type(default);
            }
        }
    }
    dependencies
}

impl<'ast> Visit<'ast> for TypeDependencies {
    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        self.has_associated_projection |= path.qself.is_some();
        self.names.extend(
            path.path
                .segments
                .iter()
                .map(|segment| normalize_identifier(&ident_name(&segment.ident)).to_owned()),
        );
        visit::visit_type_path(self, path);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        collect_token_identifiers(item.tokens.clone(), &mut self.names);
        visit::visit_macro(self, item);
    }
}

fn collect_token_identifiers(stream: TokenStream, output: &mut BTreeSet<String>) {
    for token in stream {
        match token {
            TokenTree::Ident(identifier) => {
                output.insert(normalize_identifier(&ident_name(&identifier)).to_owned());
            },
            TokenTree::Group(group) => collect_token_identifiers(group.stream(), output),
            _ => {},
        }
    }
}

fn broker_constructor_inventory_violations(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let scanner_root = workspace_root.join("crates/venom-scanner/src");
    let mut paths = Vec::new();
    collect_rust_sources(&scanner_root, &mut paths)?;
    paths.sort();
    let production_paths = production_scanner_sources(&scanner_root, &paths)?;

    let sources = production_paths
        .into_iter()
        .map(|path| Ok((path.clone(), fs::read_to_string(path)?)))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let mut alias_collector = broker_constructor_alias_collector();
    for (_, source) in &sources {
        alias_collector.visit_file(&syn::parse_file(source)?)
    }
    let aliases = resolve_broker_constructor_aliases(alias_collector);

    let mut actual = BTreeMap::<BrokerConstructorOwnerKey, usize>::new();
    let mut violations = Vec::new();
    for (path, source) in sources {
        let source_name = relative_source_name(workspace_root, &path)?;
        let inventory = inspect_broker_constructor_source_with_aliases(&source, aliases.clone())?;
        violations.extend(inventory.violations(&source_name));
        for call in &inventory.direct_call_sites {
            let key = BrokerConstructorOwnerKey::from_call(&source_name, call);
            let count = actual.entry(key).or_default();
            *count = count.saturating_add(1);
        }
    }

    violations.extend(validate_broker_constructor_inventory(&actual));
    Ok(violations)
}

#[derive(Debug)]
struct ScannerModuleEdge {
    target: PathBuf,
    test_only: bool,
}

/// Returns every source that can participate in a production scanner build.
///
/// A filename is never treated as evidence that a source is test-only. A file
/// is omitted only when it is reachable from an exact `#[cfg(test)]` module
/// declaration and is not reachable from a production root. Unlisted files
/// remain production inventory roots so adding an un-wired source cannot hide
/// a transport constructor from this gate.
fn production_scanner_sources(
    scanner_root: &Path,
    paths: &[PathBuf],
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let known = paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut edges = BTreeMap::<PathBuf, Vec<ScannerModuleEdge>>::new();
    let mut inbound = BTreeSet::new();

    for path in paths {
        let syntax = syn::parse_file(&fs::read_to_string(path)?)?;
        let mut source_edges = Vec::new();
        collect_scanner_module_edges(path, &syntax.items, false, &mut source_edges);
        source_edges.retain(|edge| known.contains(&edge.target));
        inbound.extend(source_edges.iter().map(|edge| edge.target.clone()));
        edges.insert(path.clone(), source_edges);
    }

    let library = scanner_root.join("lib.rs");
    let binary = scanner_root.join("main.rs");
    let roots = paths
        .iter()
        .filter(|path| **path == library || **path == binary || !inbound.contains(*path))
        .cloned()
        .collect::<Vec<_>>();
    let production_reachable = scanner_source_reachability(&roots, &edges, false);

    let test_roots = edges
        .values()
        .flatten()
        .filter(|edge| edge.test_only)
        .map(|edge| edge.target.clone())
        .collect::<Vec<_>>();
    let test_reachable = scanner_source_reachability(&test_roots, &edges, true);

    Ok(paths
        .iter()
        .filter(|path| production_reachable.contains(*path) || !test_reachable.contains(*path))
        .cloned()
        .collect())
}

fn scanner_source_reachability(
    roots: &[PathBuf],
    edges: &BTreeMap<PathBuf, Vec<ScannerModuleEdge>>,
    traverse_test_edges: bool,
) -> BTreeSet<PathBuf> {
    let mut reachable = BTreeSet::new();
    let mut pending = roots.iter().cloned().collect::<VecDeque<_>>();
    while let Some(source) = pending.pop_front() {
        if !reachable.insert(source.clone()) {
            continue;
        }
        for edge in edges.get(&source).into_iter().flatten() {
            if traverse_test_edges || !edge.test_only {
                pending.push_back(edge.target.clone());
            }
        }
    }
    reachable
}

fn collect_scanner_module_edges(
    source_path: &Path,
    items: &[Item],
    inherited_test_only: bool,
    output: &mut Vec<ScannerModuleEdge>,
) {
    let module_dir = default_child_module_dir(source_path);
    collect_scanner_module_edges_in_dir(
        source_path,
        &module_dir,
        items,
        inherited_test_only,
        output,
    );
}

fn collect_scanner_module_edges_in_dir(
    source_path: &Path,
    module_dir: &Path,
    items: &[Item],
    inherited_test_only: bool,
    output: &mut Vec<ScannerModuleEdge>,
) {
    for item in items {
        let Item::Mod(module) = item else {
            continue;
        };
        let test_only = inherited_test_only || has_cfg_test(&module.attrs);
        let module_name = normalize_identifier(&ident_name(&module.ident)).to_owned();
        if let Some((_, nested)) = &module.content {
            collect_scanner_module_edges_in_dir(
                source_path,
                &module_dir.join(&module_name),
                nested,
                test_only,
                output,
            );
            continue;
        }

        let target = module_path_attribute(module)
            .map(|relative| {
                source_path
                    .parent()
                    .unwrap_or_else(|| Path::new(""))
                    .join(relative)
            })
            .or_else(|| {
                let flat = module_dir.join(format!("{module_name}.rs"));
                flat.is_file().then_some(flat)
            })
            .or_else(|| {
                let nested = module_dir.join(&module_name).join("mod.rs");
                nested.is_file().then_some(nested)
            });
        if let Some(target) = target {
            output.push(ScannerModuleEdge { target, test_only });
        }
    }
}

fn default_child_module_dir(source_path: &Path) -> PathBuf {
    let parent = source_path.parent().unwrap_or_else(|| Path::new(""));
    match source_path.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") | None => parent.to_owned(),
        Some(stem) => parent.join(stem),
    }
}

fn module_path_attribute(module: &ItemMod) -> Option<PathBuf> {
    module.attrs.iter().find_map(|attribute| {
        if !attribute.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(name_value) = &attribute.meta else {
            return None;
        };
        let syn::Expr::Lit(literal) = &name_value.value else {
            return None;
        };
        let syn::Lit::Str(path) = &literal.lit else {
            return None;
        };
        Some(PathBuf::from(path.value()))
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BrokerConstructorOwnerKey {
    source: String,
    kind: BrokerConstructorKind,
    impl_target: String,
    function: String,
    trait_impl: bool,
}

impl BrokerConstructorOwnerKey {
    fn from_call(source: &str, call: &BrokerConstructorDirectCall) -> Self {
        Self {
            source: source.to_owned(),
            kind: call.kind,
            impl_target: call
                .impl_target
                .clone()
                .unwrap_or_else(|| "<free>".to_owned()),
            function: call.function.clone().unwrap_or_else(|| "<none>".to_owned()),
            trait_impl: call.trait_impl,
        }
    }
}

fn validate_broker_constructor_inventory(
    actual: &BTreeMap<BrokerConstructorOwnerKey, usize>,
) -> Vec<String> {
    let expected = EXPECTED_BROKER_CONSTRUCTORS
        .iter()
        .map(|owner| {
            (
                BrokerConstructorOwnerKey {
                    source: owner.source.to_owned(),
                    kind: owner.kind,
                    impl_target: owner.impl_target.to_owned(),
                    function: owner.function.to_owned(),
                    trait_impl: false,
                },
                1,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let keys = actual
        .keys()
        .chain(expected.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    keys.into_iter()
        .filter_map(|owner| {
            let actual_count = actual.get(&owner).copied().unwrap_or(0);
            let expected_count = expected.get(&owner).copied().unwrap_or(0);
            (actual_count != expected_count).then(|| {
                let impl_kind = if owner.trait_impl { "trait impl" } else { "impl" };
                format!(
                    "{} {impl_kind} {}::{} contains {actual_count} production {} calls; exact authority owner inventory requires {expected_count}",
                    owner.source,
                    owner.impl_target,
                    owner.function,
                    owner.kind.label()
                )
            })
        })
        .collect()
}

#[cfg(test)]
fn inspect_broker_constructor_source(
    source: &str,
) -> Result<BrokerConstructorSourceInventory, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let aliases = collect_broker_constructor_aliases(&syntax);
    inspect_broker_constructor_syntax_with_aliases(&syntax, aliases)
}

fn inspect_broker_constructor_source_with_aliases(
    source: &str,
    aliases: BrokerConstructorAliases,
) -> Result<BrokerConstructorSourceInventory, syn::Error> {
    let syntax = syn::parse_file(source)?;
    inspect_broker_constructor_syntax_with_aliases(&syntax, aliases)
}

fn inspect_broker_constructor_syntax_with_aliases(
    syntax: &syn::File,
    aliases: BrokerConstructorAliases,
) -> Result<BrokerConstructorSourceInventory, syn::Error> {
    let mut visitor = BrokerConstructorInventoryVisitor {
        aliases,
        impl_targets: Vec::new(),
        functions: Vec::new(),
        control_flow_depth: 0,
        closure_depth: 0,
        single_shot_closure_depth: 0,
        inventory: BrokerConstructorSourceInventory::default(),
    };
    visitor.visit_file(syntax);
    Ok(visitor.inventory)
}

#[derive(Debug, Default)]
struct BrokerConstructorSourceInventory {
    direct_calls: BTreeMap<BrokerConstructorKind, usize>,
    direct_call_sites: Vec<BrokerConstructorDirectCall>,
    non_call_references: BTreeMap<BrokerConstructorKind, usize>,
    opaque_alias_references: BTreeMap<BrokerConstructorKind, usize>,
    opaque_macro_references: usize,
    macro_references: BTreeMap<BrokerConstructorKind, usize>,
    source_indirections: BTreeSet<&'static str>,
}

#[derive(Debug)]
struct BrokerConstructorDirectCall {
    kind: BrokerConstructorKind,
    impl_target: Option<String>,
    function: Option<String>,
    trait_impl: bool,
    control_flow_depth: usize,
    closure_depth: usize,
    single_shot_closure_depth: usize,
}

#[derive(Debug, Clone)]
struct BrokerImplContext {
    broker_kind: Option<BrokerConstructorKind>,
    target_name: Option<String>,
    trait_impl: bool,
}

impl BrokerConstructorSourceInventory {
    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.direct_calls.is_empty()
            && self.direct_call_sites.is_empty()
            && self.non_call_references.is_empty()
            && self.opaque_alias_references.is_empty()
            && self.opaque_macro_references == 0
            && self.macro_references.is_empty()
            && self.source_indirections.is_empty()
    }

    fn violations(&self, source_name: &str) -> Vec<String> {
        let mut violations = self
            .non_call_references
            .iter()
            .filter(|(_, count)| **count > 0)
            .map(|(kind, count)| {
                format!(
                    "{source_name} contains {count} non-call {} references; broker constructors must remain exact direct AST calls",
                    kind.label()
                )
            })
            .collect::<Vec<_>>();
        violations.extend(
            self.opaque_alias_references
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(kind, count)| {
                    format!(
                        "{source_name} contains {count} ambiguous associated-type alias references to {}; associated projections cannot own broker constructors",
                        kind.label()
                    )
                }),
        );
        if self.opaque_macro_references > 0 {
            violations.push(format!(
                "{source_name} contains {} macro references to opaque associated-type aliases; associated projections cannot hide broker constructors",
                self.opaque_macro_references
            ));
        }
        violations.extend(
            self.macro_references
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(kind, count)| {
                    format!(
                        "{source_name} contains {count} macro references to {}; broker constructors must not be defined, substituted, or invoked through macros",
                        kind.label()
                    )
                }),
        );
        violations.extend(self.source_indirections.iter().map(|kind| {
            format!(
                "{source_name} uses production {kind} source indirection; broker-constructor inventory requires directly parsed scanner modules"
            )
        }));
        violations.extend(
            self.direct_call_sites
                .iter()
                .filter(|call| call.control_flow_depth > 0)
                .map(|call| {
                    format!(
                        "{source_name} places {} inside loop/conditional control flow; authority constructors must mint each broker exactly once on their direct constructor path",
                        call.kind.label()
                    )
                }),
        );
        violations.extend(self.direct_call_sites.iter().filter_map(|call| {
            if call.closure_depth == 0 {
                return None;
            }
            let allowed_legacy_single_shot = call.kind == BrokerConstructorKind::MeteredHttp
                && call.closure_depth == 1
                && call.single_shot_closure_depth == 1
                && call.function.as_deref() == Some("new")
                && call.impl_target.as_deref().is_some_and(|target| {
                    matches!(
                        target,
                        "LegacyDiscoveryAuthority" | "LegacyVerificationAuthority"
                    )
                });
            (!allowed_legacy_single_shot).then(|| {
                format!(
                    "{source_name} places {} inside a helper/repeating closure; authority constructors must mint brokers on their direct constructor path",
                    call.kind.label()
                )
            })
        }));
        violations
    }
}

struct BrokerConstructorInventoryVisitor {
    aliases: BrokerConstructorAliases,
    impl_targets: Vec<BrokerImplContext>,
    functions: Vec<String>,
    control_flow_depth: usize,
    closure_depth: usize,
    single_shot_closure_depth: usize,
    inventory: BrokerConstructorSourceInventory,
}

impl BrokerConstructorInventoryVisitor {
    fn current_impl_target(&self) -> Option<BrokerConstructorKind> {
        self.impl_targets
            .last()
            .and_then(|context| context.broker_kind)
    }

    fn current_impl_context(&self) -> Option<&BrokerImplContext> {
        self.impl_targets.last()
    }

    fn current_function(&self) -> Option<String> {
        self.functions.last().cloned()
    }

    fn constructor_member_kind(member: &str) -> Option<BrokerConstructorKind> {
        match normalize_identifier(member) {
            "new" => Some(BrokerConstructorKind::RequestAccounting),
            "new_metered" => Some(BrokerConstructorKind::MeteredHttp),
            _ => None,
        }
    }

    fn constructor_kind(
        &self,
        path: &SynPath,
        qself: Option<&syn::QSelf>,
    ) -> Option<BrokerConstructorKind> {
        let member = path
            .segments
            .last()
            .map(|segment| ident_name(&segment.ident))?;
        let kind = Self::constructor_member_kind(&member)?;
        let qself_matches = qself.is_some_and(|qself| self.type_has_kind(&qself.ty, kind));
        let receiver_matches = path.segments.iter().rev().nth(1).is_some_and(|receiver| {
            let receiver = ident_name(&receiver.ident);
            if receiver == "Self" {
                self.current_impl_target() == Some(kind)
            } else {
                self.aliases.name_has_kind(&receiver, kind)
            }
        });
        (qself_matches || receiver_matches).then_some(kind)
    }

    fn constructor_kind_for_segments(&self, segments: &[String]) -> Option<BrokerConstructorKind> {
        let member = segments
            .last()
            .map(|segment| normalize_identifier(segment))?;
        let receiver = segments
            .iter()
            .rev()
            .nth(1)
            .map(|segment| normalize_identifier(segment))?;
        let kind = Self::constructor_member_kind(member)?;
        let receiver_matches = if receiver == "Self" {
            self.current_impl_target() == Some(kind)
        } else {
            self.aliases.name_has_kind(receiver, kind)
        };
        receiver_matches.then_some(kind)
    }

    fn opaque_constructor_kind(
        &self,
        path: &SynPath,
        qself: Option<&syn::QSelf>,
    ) -> Option<BrokerConstructorKind> {
        let member = path
            .segments
            .last()
            .map(|segment| ident_name(&segment.ident))?;
        let kind = Self::constructor_member_kind(&member)?;
        let opaque_qself = qself.is_some_and(|qself| !self.type_has_kind(&qself.ty, kind));
        let opaque_receiver = path.segments.iter().rev().nth(1).is_some_and(|receiver| {
            self.aliases
                .is_opaque_constructor_receiver(&ident_name(&receiver.ident))
        });
        (opaque_qself || opaque_receiver).then_some(kind)
    }

    fn opaque_constructor_kind_for_segments(
        &self,
        segments: &[String],
    ) -> Option<BrokerConstructorKind> {
        let member = segments.last()?;
        let kind = Self::constructor_member_kind(member)?;
        let opaque_receiver = segments
            .iter()
            .rev()
            .nth(1)
            .is_some_and(|receiver| self.aliases.is_opaque_constructor_receiver(receiver));
        opaque_receiver.then_some(kind)
    }

    fn kind_for_type(&self, ty: &syn::Type) -> Option<BrokerConstructorKind> {
        match ty {
            syn::Type::Group(group) => self.kind_for_type(&group.elem),
            syn::Type::Paren(parenthesized) => self.kind_for_type(&parenthesized.elem),
            syn::Type::Path(path) => path.path.segments.last().and_then(|segment| {
                let name = ident_name(&segment.ident);
                if name == "Self" {
                    self.current_impl_target()
                } else {
                    self.aliases.kind_for_name(&name)
                }
            }),
            syn::Type::Reference(reference) => self.kind_for_type(&reference.elem),
            _ => None,
        }
    }

    fn type_has_kind(&self, ty: &syn::Type, kind: BrokerConstructorKind) -> bool {
        match ty {
            syn::Type::Group(group) => self.type_has_kind(&group.elem, kind),
            syn::Type::Paren(parenthesized) => self.type_has_kind(&parenthesized.elem, kind),
            syn::Type::Path(path) => path.path.segments.last().is_some_and(|segment| {
                let name = ident_name(&segment.ident);
                if name == "Self" {
                    self.current_impl_target() == Some(kind)
                } else {
                    self.aliases.name_has_kind(&name, kind)
                }
            }),
            syn::Type::Reference(reference) => self.type_has_kind(&reference.elem, kind),
            _ => false,
        }
    }

    fn inspect_macro(&mut self, stream: TokenStream) {
        let tokens = stream.into_iter().collect::<Vec<_>>();
        for token in &tokens {
            if let TokenTree::Group(group) = token {
                self.inspect_macro(group.stream());
            }
        }
        // Mentioning a broker type in a macro is forbidden even if the
        // constructor member is supplied by a metavariable in the definition
        // or substituted by the invocation. This deliberately rejects a
        // broader class than direct path recognition so macros cannot hide a
        // constructor from the exact AST-call inventory.
        for token in &tokens {
            let TokenTree::Ident(identifier) = token else {
                continue;
            };
            for kind in [
                BrokerConstructorKind::RequestAccounting,
                BrokerConstructorKind::MeteredHttp,
            ] {
                if self.aliases.name_has_kind(&ident_name(identifier), kind) {
                    let count = self.inventory.macro_references.entry(kind).or_default();
                    *count = count.saturating_add(1);
                }
            }
            if self
                .aliases
                .is_opaque_constructor_receiver(&ident_name(identifier))
            {
                self.inventory.opaque_macro_references =
                    self.inventory.opaque_macro_references.saturating_add(1);
            }
            if self.aliases.is_include_macro(&ident_name(identifier)) {
                self.record_source_indirection("include! inside a macro");
            }
        }
        for start in 0..tokens.len() {
            let TokenTree::Ident(root) = &tokens[start] else {
                continue;
            };
            let mut segments = vec![ident_name(root)];
            let mut cursor = start + 1;
            while cursor + 2 < tokens.len()
                && is_colon(&tokens[cursor])
                && is_colon(&tokens[cursor + 1])
            {
                let TokenTree::Ident(segment) = &tokens[cursor + 2] else {
                    break;
                };
                segments.push(ident_name(segment));
                cursor += 3;
            }
            if segments.len() < 2 {
                continue;
            }
            let receiver = segments[segments.len() - 2].as_str();
            let member = segments[segments.len() - 1].as_str();
            let Some(kind) = Self::constructor_member_kind(member) else {
                continue;
            };
            let receiver_matches = if receiver == "Self" {
                self.current_impl_target() == Some(kind)
            } else {
                self.aliases.name_has_kind(receiver, kind)
            };
            if !receiver_matches {
                continue;
            }
            let count = self.inventory.macro_references.entry(kind).or_default();
            *count = count.saturating_add(1);
        }
    }

    fn record_source_indirection(&mut self, kind: &'static str) {
        self.inventory.source_indirections.insert(kind);
    }

    fn record_direct_call(&mut self, kind: BrokerConstructorKind) {
        let count = self.inventory.direct_calls.entry(kind).or_default();
        *count = count.saturating_add(1);
        let context = self.current_impl_context();
        self.inventory
            .direct_call_sites
            .push(BrokerConstructorDirectCall {
                kind,
                impl_target: context.and_then(|context| context.target_name.clone()),
                function: self.current_function(),
                trait_impl: context.is_some_and(|context| context.trait_impl),
                control_flow_depth: self.control_flow_depth,
                closure_depth: self.closure_depth,
                single_shot_closure_depth: self.single_shot_closure_depth,
            });
    }

    fn enter_control_flow(&mut self, visit: impl FnOnce(&mut Self)) {
        self.control_flow_depth = self.control_flow_depth.saturating_add(1);
        visit(self);
        self.control_flow_depth = self.control_flow_depth.saturating_sub(1);
    }
}

impl<'ast> Visit<'ast> for BrokerConstructorInventoryVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        let target_name = type_path(&item.self_ty).and_then(|path| {
            path.path
                .segments
                .last()
                .map(|segment| normalize_identifier(&ident_name(&segment.ident)).to_owned())
        });
        self.impl_targets.push(BrokerImplContext {
            broker_kind: self.kind_for_type(&item.self_ty),
            target_name,
            trait_impl: item.trait_.is_some(),
        });
        visit::visit_item_impl(self, item);
        self.impl_targets.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !has_cfg_test(&item.attrs) {
            self.functions
                .push(normalize_identifier(&ident_name(&item.sig.ident)).to_owned());
            visit::visit_impl_item_fn(self, item);
            self.functions.pop();
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !has_cfg_test(&item.attrs) {
            self.functions
                .push(normalize_identifier(&ident_name(&item.sig.ident)).to_owned());
            visit::visit_item_fn(self, item);
            self.functions.pop();
        }
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if !has_cfg_test(&item.attrs) {
            self.functions
                .push(normalize_identifier(&ident_name(&item.sig.ident)).to_owned());
            visit::visit_trait_item_fn(self, item);
            self.functions.pop();
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, _, _) in paths {
            if let Some(kind) = self.constructor_kind_for_segments(&segments) {
                let count = self.inventory.non_call_references.entry(kind).or_default();
                *count = count.saturating_add(1);
            } else if let Some(kind) = self.opaque_constructor_kind_for_segments(&segments) {
                let count = self
                    .inventory
                    .opaque_alias_references
                    .entry(kind)
                    .or_default();
                *count = count.saturating_add(1);
            }
            if segments
                .last()
                .is_some_and(|segment| self.aliases.is_include_macro(segment))
            {
                self.record_source_indirection("imported include! macro alias");
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = expression.func.as_ref() {
            if let Some(kind) = self.constructor_kind(&path.path, path.qself.as_ref()) {
                self.record_direct_call(kind);
                // Do not visit the callee path again: every constructor-shaped
                // path outside this exact direct-call position is forbidden.
                for argument in &expression.args {
                    self.visit_expr(argument);
                }
                return;
            }
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        if let Some(kind) = self.constructor_kind(&expression.path, expression.qself.as_ref()) {
            let count = self.inventory.non_call_references.entry(kind).or_default();
            *count = count.saturating_add(1);
        } else if let Some(kind) =
            self.opaque_constructor_kind(&expression.path, expression.qself.as_ref())
        {
            let count = self
                .inventory
                .opaque_alias_references
                .entry(kind)
                .or_default();
            *count = count.saturating_add(1);
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if item.attrs.iter().any(attribute_can_redirect_module_path) {
            self.record_source_indirection("#[path]/#[cfg_attr(..., path = ...)]");
        }
        visit::visit_item_mod(self, item);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        if item
            .path
            .segments
            .last()
            .is_some_and(|segment| self.aliases.is_include_macro(&ident_name(&segment.ident)))
        {
            self.record_source_indirection("include!");
        }
        self.inspect_macro(item.tokens.clone());
        visit::visit_macro(self, item);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.enter_control_flow(|visitor| visit::visit_expr_for_loop(visitor, expression));
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.enter_control_flow(|visitor| visit::visit_expr_loop(visitor, expression));
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.enter_control_flow(|visitor| visit::visit_expr_while(visitor, expression));
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.enter_control_flow(|visitor| visit::visit_expr_if(visitor, expression));
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.enter_control_flow(|visitor| visit::visit_expr_match(visitor, expression));
    }

    fn visit_expr_closure(&mut self, expression: &'ast syn::ExprClosure) {
        self.closure_depth = self.closure_depth.saturating_add(1);
        visit::visit_expr_closure(self, expression);
        self.closure_depth = self.closure_depth.saturating_sub(1);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if normalize_identifier(&ident_name(&expression.method)) != "and_then" {
            visit::visit_expr_method_call(self, expression);
            return;
        }

        self.visit_expr(&expression.receiver);
        for argument in &expression.args {
            if let syn::Expr::Closure(closure) = argument {
                self.closure_depth = self.closure_depth.saturating_add(1);
                self.single_shot_closure_depth = self.single_shot_closure_depth.saturating_add(1);
                visit::visit_expr_closure(self, closure);
                self.single_shot_closure_depth = self.single_shot_closure_depth.saturating_sub(1);
                self.closure_depth = self.closure_depth.saturating_sub(1);
            } else {
                self.visit_expr(argument);
            }
        }
    }

    fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
        self.enter_control_flow(|visitor| visit::visit_expr_async(visitor, expression));
    }
}

fn attribute_can_redirect_module_path(attribute: &syn::Attribute) -> bool {
    if attribute.path().is_ident("path") {
        return true;
    }
    attribute.path().is_ident("cfg_attr")
        && match &attribute.meta {
            syn::Meta::List(list) => token_stream_contains_identifier(list.tokens.clone(), "path"),
            _ => false,
        }
}

fn token_stream_contains_identifier(stream: TokenStream, needle: &str) -> bool {
    stream.into_iter().any(|token| match token {
        TokenTree::Ident(identifier) => normalize_identifier(&ident_name(&identifier)) == needle,
        TokenTree::Group(group) => token_stream_contains_identifier(group.stream(), needle),
        _ => false,
    })
}

struct OwnershipVisitor<'source> {
    source: &'source str,
    inline_module_depth: usize,
    allow_legacy_context_type: bool,
    forbid_execute: bool,
    legacy_authority_aliases: BTreeSet<String>,
    violations: BTreeSet<String>,
}

impl OwnershipVisitor<'_> {
    fn inspect_segments(&mut self, segments: &[String]) {
        if segments.is_empty()
            || (self.source == "crates/venom-scanner/src/http_evidence.rs"
                && allowed_http_facade_path(segments))
        {
            return;
        }
        if BOUNDED_RUNTIME_SOURCES.contains(&self.source)
            && segments.iter().any(|segment| {
                let segment = normalize_identifier(segment);
                segment == "legacy_discovery" || self.legacy_authority_aliases.contains(segment)
            })
        {
            self.violations.insert(format!(
                "{} references legacy discovery/verification authority {}; bounded Surface-B code must use SharedWebRuntimeAuthority",
                self.source,
                display_path(segments)
            ));
        }
        if self.source == ASSESSMENT_ITEM_SOURCE
            || matches!(
                self.source,
                "crates/venom-scanner/src/web_runtime/web_assessment.rs"
                    | "crates/venom-scanner/src/web_runtime/web_assessment/discovery.rs"
                    | "crates/venom-scanner/src/web_runtime/web_assessment/semantic.rs"
            )
        {
            if segments
                .iter()
                .any(|segment| normalize_identifier(segment) == "phases")
            {
                self.violations.insert(format!(
                    "{} references quarantined legacy phase path {}; the origin assessment must use only Surface-B evidence producers",
                    self.source,
                    display_path(segments)
                ));
            }
            if segments
                .iter()
                .any(|segment| normalize_identifier(segment) == "ScanPhase")
            {
                self.violations.insert(format!(
                    "{} references legacy discovery/verification authority {}; the origin assessment cannot invoke ScanPhase",
                    self.source,
                    display_path(segments)
                ));
            }
            if segments.iter().any(|segment| {
                matches!(
                    normalize_identifier(segment),
                    "HttpRequestBroker" | "RequestAccountingBroker"
                )
            }) {
                self.violations.insert(format!(
                    "{} references forbidden direct transport authority {}; origin assessment transport must come only from SharedWebRuntimeAuthority",
                    self.source,
                    display_path(segments)
                ));
            }
        }
        if self.source == "crates/venom-scanner/src/payload_strategy.rs"
            && is_nondeterministic_strategy_path(segments)
        {
            self.violations.insert(format!(
                "{} imports nondeterministic or stateful path {}; payload strategies must remain pure contracts",
                self.source,
                display_path(segments)
            ));
        }
        if !UNMETERED_STANDALONE_FACADE_SOURCES.contains(&self.source)
            && segments
                .last()
                .is_some_and(|item| normalize_identifier(item) == "new_unmetered")
        {
            self.violations.insert(format!(
                "{} constructs an unmetered request broker outside the legacy standalone HTTP facade",
                self.source
            ));
        }
        let reqwest = segments
            .first()
            .is_some_and(|root| normalize_identifier(root) == "reqwest");
        let legacy_client_path = is_legacy_client_path(segments)
            && !(self.allow_legacy_context_type && is_context_type_path(segments));
        if reqwest || is_direct_transport_path(segments) || legacy_client_path {
            self.violations.insert(format!(
                "{} acquires forbidden direct transport path {}; use crate::http_evidence::HttpRequestBroker",
                self.source,
                display_path(segments)
            ));
        }
    }

    fn inspect_use(&mut self, item: &ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, _, _) in paths {
            let broad_root = segments
                .first()
                .map(String::as_str)
                .map(normalize_identifier);
            let imports_root = segments.len() == 1
                || (segments.len() == 2
                    && segments
                        .get(1)
                        .is_some_and(|segment| normalize_identifier(segment) == "self"));
            if imports_root
                && matches!(
                    broad_root,
                    Some("crate" | "self" | "super" | "std" | "tokio")
                )
            {
                self.violations.insert(format!(
                    "{} aliases broad runtime root {}; import an explicit non-network module",
                    self.source,
                    display_path(&segments)
                ));
            } else {
                self.inspect_segments(&segments);
            }
        }
    }

    fn inspect_macro(&mut self, stream: TokenStream) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for token in &tokens {
            if let TokenTree::Group(group) = token {
                self.inspect_macro(group.stream());
            }
            if let TokenTree::Ident(identifier) = token {
                let identifier = normalize_identifier(&ident_name(identifier)).to_owned();
                if BOUNDED_RUNTIME_SOURCES.contains(&self.source)
                    && self.legacy_authority_aliases.contains(&identifier)
                {
                    self.violations.insert(format!(
                        "{} references legacy discovery/verification authority alias {identifier} inside a macro; bounded Surface-B code must use SharedWebRuntimeAuthority",
                        self.source
                    ));
                }
            }
        }
        for start in 0..tokens.len() {
            let TokenTree::Ident(root) = &tokens[start] else {
                continue;
            };
            let mut segments = vec![root.to_string()];
            let mut cursor = start + 1;
            while cursor + 2 < tokens.len()
                && is_colon(&tokens[cursor])
                && is_colon(&tokens[cursor + 1])
            {
                let TokenTree::Ident(segment) = &tokens[cursor + 2] else {
                    break;
                };
                segments.push(segment.to_string());
                cursor += 3;
            }
            if segments.len() > 1 {
                self.inspect_segments(&segments);
            }
        }
        for window in tokens.windows(2) {
            let [dot, TokenTree::Ident(member)] = window else {
                continue;
            };
            let member = ident_name(member);
            if is_punctuation(dot, '.')
                && (matches!(member.as_str(), "client" | "send")
                    || (self.forbid_execute && member == "execute"))
            {
                self.violations.insert(format!(
                    "{} hides forbidden direct transport member .{member} inside a macro",
                    self.source
                ));
            }
        }
    }
}

impl<'ast> Visit<'ast> for OwnershipVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.inspect_use(item);
        visit::visit_item_use(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if item.content.is_some() {
            self.inline_module_depth = self.inline_module_depth.saturating_add(1);
            visit::visit_item_mod(self, item);
            self.inline_module_depth = self.inline_module_depth.saturating_sub(1);
            return;
        }

        let module = ident_name(&item.ident);
        let registered = matches!(
            (self.source, module.as_str()),
            (
                "crates/venom-scanner/src/http_evidence.rs",
                "request_broker"
            ) | ("crates/venom-scanner/src/http_evidence.rs", "form_controls")
                | (
                    "crates/venom-scanner/src/http_evidence.rs",
                    "passive_review"
                )
                | ("crates/venom-scanner/src/web_runtime.rs", "authority")
                | ("crates/venom-scanner/src/web_runtime.rs", "api_visibility")
                | ("crates/venom-scanner/src/web_runtime.rs", "assessment_item")
                | (
                    "crates/venom-scanner/src/web_runtime.rs",
                    "assessment_passive"
                )
                | (
                    "crates/venom-scanner/src/web_runtime.rs",
                    "assessment_report"
                )
                | (
                    "crates/venom-scanner/src/web_runtime/api_visibility.rs",
                    "differential"
                )
                | (
                    "crates/venom-scanner/src/web_runtime/api_visibility/differential.rs",
                    "execution"
                )
                | (
                    "crates/venom-scanner/src/web_runtime.rs",
                    "assessment_defense"
                )
                | ("crates/venom-scanner/src/web_runtime.rs", "scan_profile")
                | ("crates/venom-scanner/src/web_runtime.rs", "web_assessment")
                | (
                    "crates/venom-scanner/src/web_runtime/web_assessment.rs",
                    "discovery"
                )
                | (
                    "crates/venom-scanner/src/web_runtime/web_assessment.rs",
                    "semantic"
                )
        );
        let attributes_are_exact = if self.source == "crates/venom-scanner/src/web_runtime.rs"
            && module == "assessment_report"
        {
            attributes_are_exact_cfg_feature(&item.attrs, "reporting")
        } else {
            item.attrs.is_empty()
        };
        let visibility_is_exact = if self.source == "crates/venom-scanner/src/http_evidence.rs"
            && module == "passive_review"
        {
            is_pub_crate_visibility(&item.vis)
        } else {
            matches!(item.vis, syn::Visibility::Inherited)
        };
        let canonical = self.inline_module_depth == 0
            && attributes_are_exact
            && visibility_is_exact
            && registered;
        if !canonical {
            self.violations.insert(format!(
                "{} declares unregistered external submodule {module}; add its source to the bounded transport policy before wiring it",
                self.source
            ));
        }
        visit::visit_item_mod(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        let root = ident_name(&item.ident);
        if is_network_crate_root(&root)
            || matches!(root.as_str(), "reqwest" | "self" | "std" | "tokio")
        {
            self.violations.insert(format!(
                "{} aliases forbidden transport-capable crate {root}",
                self.source
            ));
        }
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        self.inspect_segments(&path_segments(path));
        visit::visit_path(self, path);
    }

    fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
        if matches!(
            &expression.member,
            syn::Member::Named(member) if ident_name(member) == "client"
        ) {
            self.violations.insert(format!(
                "{} accesses a raw .client field outside the transport owner",
                self.source
            ));
        }
        visit::visit_expr_field(self, expression);
    }

    fn visit_pat_struct(&mut self, pattern: &'ast syn::PatStruct) {
        for field in &pattern.fields {
            if matches!(
                &field.member,
                syn::Member::Named(member) if ident_name(member) == "client"
            ) {
                self.violations.insert(format!(
                    "{} destructures a raw client field outside the transport owner",
                    self.source
                ));
            }
        }
        visit::visit_pat_struct(self, pattern);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        let method = ident_name(&expression.method);
        if method == "send" {
            self.violations.insert(format!(
                "{} calls .send() outside the transport owner",
                self.source
            ));
        }
        if self.forbid_execute && method == "execute" {
            self.violations.insert(format!(
                "{} calls .execute() outside the bounded discovery broker",
                self.source
            ));
        }
        if method == "new_unmetered" && !UNMETERED_STANDALONE_FACADE_SOURCES.contains(&self.source)
        {
            self.violations.insert(format!(
                "{} constructs an unmetered request broker outside the legacy standalone HTTP facade",
                self.source
            ));
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        self.inspect_macro(item.tokens.clone());
        visit::visit_macro(self, item);
    }
}

struct DiscoveryConsumerVisitor<'source> {
    source: &'source str,
    context_aliases: BTreeSet<String>,
    forbidden_claim_aliases: BTreeSet<String>,
    violations: BTreeSet<String>,
}

const FORBIDDEN_LEGACY_CLAIM_TYPES: &[&str] =
    &["Outcome", "RunOutcomeRecord", "RunOutcomeRecordInput"];

fn collect_forbidden_claim_aliases(syntax: &syn::File) -> BTreeSet<String> {
    let mut aliases = FORBIDDEN_LEGACY_CLAIM_TYPES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<BTreeSet<_>>();
    for item in &syntax.items {
        match item {
            Item::Use(item_use) if !has_cfg_test(&item_use.attrs) => {
                let mut paths = Vec::new();
                collect_use_paths(&item_use.tree, Vec::new(), &mut paths);
                for (segments, binding, _) in paths {
                    if segments.last().is_some_and(|segment| {
                        FORBIDDEN_LEGACY_CLAIM_TYPES.contains(&normalize_identifier(segment))
                    }) {
                        if let Some(alias) = binding.or_else(|| segments.last().cloned()) {
                            aliases.insert(normalize_identifier(&alias).to_owned());
                        }
                    }
                }
            },
            Item::Type(item_type) if !has_cfg_test(&item_type.attrs) => {
                if let syn::Type::Path(path) = item_type.ty.as_ref() {
                    if path.path.segments.last().is_some_and(|segment| {
                        FORBIDDEN_LEGACY_CLAIM_TYPES
                            .contains(&normalize_identifier(&segment.ident.to_string()))
                    }) {
                        aliases
                            .insert(normalize_identifier(&item_type.ident.to_string()).to_owned());
                    }
                }
            },
            _ => {},
        }
    }
    aliases
}

fn collect_context_aliases(syntax: &syn::File) -> BTreeSet<String> {
    let mut collector = ContextAliasCollector::default();
    collector.visit_file(syntax);

    let mut aliases = BTreeSet::from(["ScanContext".to_owned()]);
    aliases.extend(collector.direct_aliases);
    loop {
        let mut changed = false;
        for (alias, source) in &collector.alias_edges {
            if source
                .iter()
                .any(|segment| aliases.contains(normalize_identifier(segment)))
            {
                changed |= aliases.insert(alias.clone());
            }
        }
        if !changed {
            break;
        }
    }
    aliases
}

#[derive(Default)]
struct ContextAliasCollector {
    direct_aliases: BTreeSet<String>,
    alias_edges: Vec<(String, Vec<String>)>,
}

impl<'ast> Visit<'ast> for ContextAliasCollector {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, binding, _) in paths {
            let Some(alias) = binding
                .or_else(|| segments.last().cloned())
                .map(|value| normalize_identifier(&value).to_owned())
            else {
                continue;
            };
            if is_context_type_path(&segments) {
                self.direct_aliases.insert(alias);
            } else {
                self.alias_edges.push((alias, segments));
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let syn::Type::Path(path) = item.ty.as_ref() {
            self.alias_edges.push((
                normalize_identifier(&item.ident.to_string()).to_owned(),
                path_segments(&path.path),
            ));
        }
        visit::visit_item_type(self, item);
    }
}

fn is_internal_discovery_path(segments: &[String]) -> bool {
    segments
        .first()
        .is_some_and(|root| matches!(normalize_identifier(root), "crate" | "super"))
}

fn is_allowed_discovery_consumer_path(source: &str, segments: &[String]) -> bool {
    if segments.len() == 1
        && segments
            .first()
            .is_some_and(|root| matches!(normalize_identifier(root), "crate" | "super"))
    {
        // Restricted visibilities such as `pub(super)` are not dependency
        // paths. Broad root imports are rejected separately by OwnershipVisitor.
        return true;
    }
    let segment = |index: usize| {
        segments
            .get(index)
            .map(String::as_str)
            .map(normalize_identifier)
    };
    let claim_bridge = LEGACY_CLAIM_BRIDGE_PHASE_SOURCES.contains(&source);
    match segment(0) {
        Some("crate") => match (segment(1), segment(2)) {
            (
                Some(
                    "ActiveVerifier" | "Expression" | "KnowledgeLayer" | "VerificationCase"
                    | "VerificationReport" | "VerificationRule",
                ),
                None,
            ) if claim_bridge => true,
            (Some("knowledge"), Some("KnowledgeWrite")) if claim_bridge => true,
            (Some("rules"), Some("Expression" | "KnowledgeLayer")) if claim_bridge => true,
            (
                Some("verification"),
                Some(
                    "ActiveVerifier" | "VerificationCase" | "VerificationReport"
                    | "VerificationRule",
                ),
            ) if claim_bridge => true,
            (Some("context"), Some("ScanContext")) => segments.len() == 3,
            (Some("contracts"), Some("ScanFinding" | "ScanPhase")) => true,
            (Some("error"), Some("ScannerError")) => true,
            (Some("http_evidence"), Some("HttpProbeMethod")) => true,
            (
                Some("legacy_discovery"),
                Some(
                    "BoundedHttpResponse"
                    | "DiscoveryDelta"
                    | "DiscoveryForm"
                    | "DiscoveryFormMethod",
                ),
            ) => true,
            _ => false,
        },
        Some("super") => {
            source == "crates/venom-scanner/src/phases/phase4_param.rs"
                && segment(1) == Some("phase3_fuzzer")
                && segment(2) == Some("ResponseSignature")
        },
        _ => false,
    }
}

impl DiscoveryConsumerVisitor<'_> {
    fn inspect_segments(&mut self, segments: &[String]) {
        if LEGACY_VERIFICATION_PHASE_SOURCES.contains(&self.source)
            && segments.iter().any(|segment| {
                self.forbidden_claim_aliases
                    .contains(normalize_identifier(segment))
            })
        {
            self.violations.insert(format!(
                "{} imports or constructs a direct outcome type {}; use VerificationReport through the context bridge",
                self.source,
                display_path(segments)
            ));
        }
        let forbidden = segments.iter().any(|segment| {
            matches!(
                normalize_identifier(segment),
                "HttpEvidenceExecutor"
                    | "HttpEvidencePolicy"
                    | "HttpRequestBroker"
                    | "RequestAccountingBroker"
                    | "RuntimeBudget"
                    | "ScannerSdk"
                    | "StandardWebDiscoveryExecutorProfile"
                    | "LegacyDiscoveryAuthority"
                    | "LegacyVerificationAuthority"
                    | "VerificationLimits"
            )
        });
        if forbidden {
            self.violations.insert(format!(
                "{} imports or constructs discovery authority internals {}; phase consumers must use ScanContext request/state seams",
                self.source,
                display_path(segments)
            ));
        }
        let context_qualifier = segments.iter().enumerate().any(|(index, segment)| {
            let segment = normalize_identifier(segment);
            self.context_aliases.contains(segment) && index + 1 < segments.len()
        });
        if context_qualifier {
            self.violations.insert(format!(
                "{} uses a ScanContext associated path inside a migrated phase; accept the host-owned shared context and use its instance seams",
                self.source
            ));
        }
        if is_internal_discovery_path(segments)
            && !is_allowed_discovery_consumer_path(self.source, segments)
        {
            self.violations.insert(format!(
                "{} reaches internal path {} outside the strict migrated-discovery API allowlist",
                self.source,
                display_path(segments)
            ));
        }
    }

    fn inspect_macro(&mut self, stream: TokenStream) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for token in &tokens {
            if let TokenTree::Group(group) = token {
                self.inspect_macro(group.stream());
            }
            if let TokenTree::Ident(identifier) = token {
                self.inspect_segments(&[identifier.to_string()]);
            }
        }
        for start in 0..tokens.len() {
            let TokenTree::Ident(root) = &tokens[start] else {
                continue;
            };
            let mut segments = vec![root.to_string()];
            let mut cursor = start + 1;
            while cursor + 2 < tokens.len()
                && is_colon(&tokens[cursor])
                && is_colon(&tokens[cursor + 1])
            {
                let TokenTree::Ident(segment) = &tokens[cursor + 2] else {
                    break;
                };
                segments.push(segment.to_string());
                cursor += 3;
            }
            if segments.len() > 1 {
                self.inspect_segments(&segments);
            }
        }
        for window in tokens.windows(2) {
            let [dot, TokenTree::Ident(member)] = window else {
                continue;
            };
            if is_punctuation(dot, '.')
                && matches!(
                    ident_name(member).as_str(),
                    "add_endpoint"
                        | "mark_visited"
                        | "with_pre_execution_discovery_limits"
                        | "with_pre_execution_verification_limits"
                        | "new_with_discovery_limits"
                        | "new_with_verification_limits"
                        | "discovered_endpoints"
                        | "visited_urls"
                )
            {
                self.violations.insert(format!(
                    "{} hides a typed-discovery authority bypass inside a macro",
                    self.source
                ));
            }
        }
    }
}

impl<'ast> Visit<'ast> for DiscoveryConsumerVisitor<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, binding, _) in paths {
            if is_context_type_path(&segments) {
                let alias = binding
                    .or_else(|| segments.last().cloned())
                    .map(|value| normalize_identifier(&value).to_owned());
                if let Some(alias) = alias {
                    self.context_aliases.insert(alias);
                }
            }
            self.inspect_segments(&segments);
        }
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        self.inspect_segments(&path_segments(path));
        visit::visit_path(self, path);
    }

    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        if expression
            .qself
            .as_ref()
            .is_some_and(|qself| type_contains_alias(qself.ty.as_ref(), &self.context_aliases))
        {
            self.violations.insert(format!(
                "{} uses a qualified ScanContext associated path inside a migrated phase; use the host-owned shared context",
                self.source
            ));
        }
        visit::visit_expr_path(self, expression);
    }

    fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
        if matches!(
            &expression.member,
            syn::Member::Named(member)
                if matches!(ident_name(member).as_str(), "discovered_endpoints" | "visited_urls")
        ) {
            self.violations.insert(format!(
                "{} accesses legacy discovery compatibility state directly; use typed snapshots and atomic deltas",
                self.source
            ));
        }
        visit::visit_expr_field(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        let method = ident_name(&expression.method);
        if matches!(
            method.as_str(),
            "add_endpoint"
                | "mark_visited"
                | "with_pre_execution_discovery_limits"
                | "with_pre_execution_verification_limits"
                | "new_with_discovery_limits"
                | "new_with_verification_limits"
        ) {
            self.violations.insert(format!(
                "{} bypasses or replaces the shared typed discovery authority",
                self.source
            ));
        }
        if LEGACY_VERIFICATION_PHASE_SOURCES.contains(&self.source) && method == "request" {
            self.violations.insert(format!(
                "{} consumes the passive discovery request seam from a verification phase; use verification_request",
                self.source
            ));
        }
        if !LEGACY_VERIFICATION_PHASE_SOURCES.contains(&self.source)
            && self.source != LEGACY_DISCOVERY_AUTHORITY_SOURCE
            && method == "verification_request"
        {
            self.violations.insert(format!(
                "{} consumes the active verification request seam from a discovery phase",
                self.source
            ));
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        let segments = path_segments(&expression.path);
        if segments
            .last()
            .is_some_and(|item| self.context_aliases.contains(normalize_identifier(item)))
        {
            self.violations.insert(format!(
                "{} constructs a fresh ScanContext struct inside a migrated phase; use the host-owned shared context",
                self.source
            ));
        }
        visit::visit_expr_struct(self, expression);
    }

    fn visit_pat_struct(&mut self, pattern: &'ast syn::PatStruct) {
        for field in &pattern.fields {
            if matches!(
                &field.member,
                syn::Member::Named(member)
                    if matches!(ident_name(member).as_str(), "discovered_endpoints" | "visited_urls")
            ) {
                self.violations.insert(format!(
                    "{} destructures legacy compatibility state instead of using typed discovery state",
                    self.source
                ));
            }
        }
        visit::visit_pat_struct(self, pattern);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        self.inspect_macro(item.tokens.clone());
        visit::visit_macro(self, item);
    }
}

fn type_contains_alias(ty: &syn::Type, aliases: &BTreeSet<String>) -> bool {
    match ty {
        syn::Type::Group(group) => type_contains_alias(&group.elem, aliases),
        syn::Type::Paren(parenthesized) => type_contains_alias(&parenthesized.elem, aliases),
        syn::Type::Path(path) => path
            .path
            .segments
            .iter()
            .any(|segment| aliases.contains(normalize_identifier(&segment.ident.to_string()))),
        syn::Type::Reference(reference) => type_contains_alias(&reference.elem, aliases),
        _ => false,
    }
}

fn allowed_http_facade_path(segments: &[String]) -> bool {
    segments
        .first()
        .is_some_and(|root| normalize_identifier(root) == "reqwest")
        && segments.get(1).is_some_and(|item| {
            matches!(
                normalize_identifier(item),
                "header" | "Error" | "Method" | "StatusCode" | "Url"
            )
        })
}

fn is_legacy_client_path(segments: &[String]) -> bool {
    segments
        .first()
        .is_some_and(|root| normalize_identifier(root) == "crate")
        && segments
            .get(1)
            .is_some_and(|module| matches!(normalize_identifier(module), "context" | "sdk"))
}

fn is_context_type_path(segments: &[String]) -> bool {
    segments
        .first()
        .is_some_and(|root| normalize_identifier(root) == "crate")
        && segments
            .get(1)
            .is_some_and(|module| normalize_identifier(module) == "context")
        && segments
            .get(2)
            .is_some_and(|item| normalize_identifier(item) == "ScanContext")
}

fn is_direct_transport_path(segments: &[String]) -> bool {
    let Some(root) = segments
        .first()
        .map(String::as_str)
        .map(normalize_identifier)
    else {
        return false;
    };
    match root {
        "std" | "tokio" => {
            let is_net = segments
                .get(1)
                .is_some_and(|module| normalize_identifier(module) == "net");
            if !is_net {
                false
            } else if root == "std" {
                let is_allowed_value = segments.get(2).is_some_and(|item| {
                    matches!(
                        normalize_identifier(item),
                        "IpAddr" | "Ipv4Addr" | "Ipv6Addr" | "AddrParseError"
                    )
                });
                !is_allowed_value
            } else {
                true
            }
        },
        "reqwest" => {
            segments.len() == 1
                || segments.get(1).is_some_and(|item| {
                    matches!(
                        normalize_identifier(item),
                        "blocking" | "get" | "Client" | "ClientBuilder"
                    )
                })
        },
        other => is_network_crate_root(other),
    }
}

fn is_nondeterministic_strategy_path(segments: &[String]) -> bool {
    let Some(root) = segments
        .first()
        .map(String::as_str)
        .map(normalize_identifier)
    else {
        return false;
    };
    match root {
        "std" => !allowed_payload_strategy_std_path(segments),
        "alloc" | "core" | "tokio" => true,
        "crate" => segments.get(1).is_some_and(|module| {
            matches!(
                normalize_identifier(module),
                "context"
                    | "decision_runner"
                    | "http_evidence"
                    | "knowledge"
                    | "runtime_budget"
                    | "sdk"
            )
        }),
        "chrono" | "dashmap" | "env" | "fastrand" | "getrandom" | "include" | "include_bytes"
        | "include_str" | "once_cell" | "option_env" | "parking_lot" | "rand" | "time" | "uuid" => {
            true
        },
        _ => false,
    }
}

fn allowed_payload_strategy_std_path(segments: &[String]) -> bool {
    match segments
        .get(1)
        .map(String::as_str)
        .map(normalize_identifier)
    {
        Some("collections") => segments
            .get(2)
            .is_some_and(|item| normalize_identifier(item) == "BTreeMap"),
        Some("fmt") => true,
        Some("sync") => segments
            .get(2)
            .is_some_and(|item| normalize_identifier(item) == "Arc"),
        _ => false,
    }
}

fn is_network_crate_root(root: &str) -> bool {
    matches!(
        normalize_identifier(root),
        "hyper" | "hyper_util" | "isahc" | "mio" | "socket2" | "surf" | "ureq"
    )
}

fn path_segments(path: &SynPath) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn direct_client_sources(workspace_root: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut sources = Vec::new();
    for root in ["crates/venom-scanner/src", "crates/venom-cli/src"] {
        let source_root = workspace_root.join(root);
        let mut crate_sources = Vec::new();
        collect_rust_sources(&source_root, &mut crate_sources)?;
        crate_sources.sort();
        sources.extend(production_scanner_sources(&source_root, &crate_sources)?);
    }
    let mut direct = BTreeSet::new();
    for path in sources {
        let syntax = syn::parse_file(&fs::read_to_string(&path)?)?;
        let mut visitor = DirectCapabilityVisitor::default();
        visitor.visit_file(&syntax);
        if visitor.found {
            direct.insert(relative_source_name(workspace_root, &path)?);
        }
    }
    Ok(direct)
}

#[derive(Default)]
struct DirectCapabilityVisitor {
    found: bool,
}

impl DirectCapabilityVisitor {
    fn inspect_segments(&mut self, segments: &[String]) {
        self.found |= is_direct_transport_path(segments);
    }

    fn inspect_macro(&mut self, stream: TokenStream) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for token in &tokens {
            if let TokenTree::Group(group) = token {
                self.inspect_macro(group.stream());
            }
        }
        for start in 0..tokens.len() {
            let TokenTree::Ident(root) = &tokens[start] else {
                continue;
            };
            let mut segments = vec![root.to_string()];
            let mut cursor = start + 1;
            while cursor + 2 < tokens.len()
                && is_colon(&tokens[cursor])
                && is_colon(&tokens[cursor + 1])
            {
                let TokenTree::Ident(segment) = &tokens[cursor + 2] else {
                    break;
                };
                segments.push(segment.to_string());
                cursor += 3;
            }
            if segments.len() > 1 {
                self.inspect_segments(&segments);
            }
        }
    }
}

impl<'ast> Visit<'ast> for DirectCapabilityVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, _, _) in paths {
            self.inspect_segments(&segments);
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        self.inspect_segments(&[item.ident.to_string()]);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        self.inspect_segments(&path_segments(path));
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        self.inspect_macro(item.tokens.clone());
        visit::visit_macro(self, item);
    }
}

fn legacy_send_inventory(workspace_root: &Path) -> Result<BTreeMap<String, usize>, Box<dyn Error>> {
    let mut sources = Vec::new();
    collect_rust_sources(
        &workspace_root.join("crates/venom-scanner/src/phases"),
        &mut sources,
    )?;
    let mut inventory = BTreeMap::new();
    for path in sources {
        let count = count_production_method_calls(&fs::read_to_string(&path)?, "send")?;
        if count > 0 {
            inventory.insert(relative_source_name(workspace_root, &path)?, count);
        }
    }
    Ok(inventory)
}

fn count_production_method_calls(source: &str, method: &str) -> Result<usize, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = MethodCallCounter { method, count: 0 };
    visitor.visit_file(&syntax);
    Ok(visitor.count)
}

struct MethodCallCounter<'method> {
    method: &'method str,
    count: usize,
}

impl<'ast> Visit<'ast> for MethodCallCounter<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if ident_name(&expression.method) == self.method {
            self.count = self.count.saturating_add(1);
        }
        visit::visit_expr_method_call(self, expression);
    }
}

fn collect_rust_sources(root: &Path, output: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rust_sources(&path, output)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            output.push(path);
        }
    }
    Ok(())
}

fn relative_source_name(workspace_root: &Path, path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(path
        .strip_prefix(workspace_root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_SHARED_AUTHORITY: &str = r#"
        use crate::http_evidence::HttpRequestBroker;
        use crate::runtime_budget::RequestAccountingBroker;
        struct SharedWebRuntimeAuthority;
        impl SharedWebRuntimeAuthority {
            fn new_exact_origin() {
                let accounting = RequestAccountingBroker::new(budget());
                let _ = HttpRequestBroker::new_metered(policy(), accounting);
            }
        }
    "#;

    const VALID_LEGACY_AUTHORITY: &str = r#"
        use crate::http_evidence::HttpRequestBroker;
        use crate::runtime_budget::RequestAccountingBroker;
        struct LegacyDiscoveryAuthority;
        impl LegacyDiscoveryAuthority {
            fn new() {
                let accounting = RequestAccountingBroker::new(budget());
                let _ = HttpRequestBroker::new_metered(policy(), accounting);
            }
        }
        struct LegacyVerificationAuthority;
        impl LegacyVerificationAuthority {
            fn new() {
                let accounting = RequestAccountingBroker::new(budget());
                let _ = HttpRequestBroker::new_metered(policy(), accounting);
            }
        }
    "#;

    fn constructor_inventory(
        sources: &[(&str, &str)],
    ) -> BTreeMap<BrokerConstructorOwnerKey, usize> {
        let mut inventory = BTreeMap::<BrokerConstructorOwnerKey, usize>::new();
        for (source_name, source) in sources {
            for call in inspect_broker_constructor_source(source)
                .unwrap()
                .direct_call_sites
            {
                let key = BrokerConstructorOwnerKey::from_call(source_name, &call);
                let count = inventory.entry(key).or_default();
                *count = count.saturating_add(1);
            }
        }
        inventory
    }

    fn constructor_source_violations(sources: &[(&str, &str)]) -> Vec<String> {
        let mut violations = Vec::new();
        let mut direct = BTreeMap::<BrokerConstructorOwnerKey, usize>::new();
        for (source_name, source) in sources {
            let inventory = inspect_broker_constructor_source(source).unwrap();
            violations.extend(inventory.violations(source_name));
            for call in inventory.direct_call_sites {
                let key = BrokerConstructorOwnerKey::from_call(source_name, &call);
                let count = direct.entry(key).or_default();
                *count = count.saturating_add(1);
            }
        }
        violations.extend(validate_broker_constructor_inventory(&direct));
        violations
    }

    fn valid_constructor_sources<'a>(
        shared: &'a str,
        extras: &'a [(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut sources = vec![
            (SHARED_RUNTIME_AUTHORITY_SOURCE, shared),
            (LEGACY_DISCOVERY_AUTHORITY_SOURCE, VALID_LEGACY_AUTHORITY),
        ];
        sources.extend_from_slice(extras);
        sources
    }

    #[test]
    fn bounded_sources_reject_direct_clients_sockets_fields_and_sends() {
        let source = r#"
            use reqwest::Client as HiddenClient;
            use std::net::TcpStream;
            use tokio::{net::UdpSocket, time::sleep};

            fn leak(context: &Context) {
                let _ = context.client.get("https://example.test").send();
                let _ = vec![reqwest::Client::new()];
                policy!(context.client.send());
            }

            #[cfg(test)]
            mod tests {
                use tokio::net::TcpListener;
                fn allowed_in_tests(context: &Context) { let _ = context.client.send(); }
            }
        "#;
        let violations = inspect_bounded_source("crates/venom-scanner/src/web_runtime.rs", source)
            .unwrap()
            .join("\n");

        for expected in [
            "reqwest::Client",
            "std::net::TcpStream",
            "tokio::net::UdpSocket",
            "raw .client field",
            "calls .send()",
            "inside a macro",
        ] {
            assert!(
                violations.contains(expected),
                "missing {expected}: {violations}"
            );
        }
        assert!(!violations.contains("TcpListener"));
    }

    #[test]
    fn facade_allows_metadata_types_but_not_a_client() {
        let metadata = r#"
            use reqwest::{header::HeaderMap, Error, Method, StatusCode, Url};
            struct Observation(Method, StatusCode, Url, HeaderMap, Option<Error>);
        "#;
        assert!(
            inspect_bounded_source("crates/venom-scanner/src/http_evidence.rs", metadata)
                .unwrap()
                .is_empty()
        );

        let client = "use reqwest::Client; fn leak() { let _ = Client::new(); }";
        let violations =
            inspect_bounded_source("crates/venom-scanner/src/http_evidence.rs", client)
                .unwrap()
                .join("\n");
        assert!(violations.contains("reqwest::Client"));
    }

    #[test]
    fn payload_strategy_contract_rejects_clock_rng_state_and_transport_imports() {
        for source in [
            "use std::time::SystemTime;",
            "use std::collections::HashMap;",
            "use std::hash::RandomState;",
            "use std::io::stdin;",
            "use std::sync::Mutex;",
            "use core::cell::Cell;",
            "use core::sync::atomic::AtomicU64;",
            "use tokio::sync::RwLock;",
            "use rand::Rng;",
            "use uuid::Uuid;",
            "const SEED: &[u8] = include_bytes!(\"seed.bin\");",
            "const BUILD: Option<&str> = option_env!(\"BUILD_ID\");",
            "use crate::knowledge::KnowledgeBase;",
            "use crate::http_evidence::HttpProbe;",
        ] {
            let violations =
                inspect_bounded_source("crates/venom-scanner/src/payload_strategy.rs", source)
                    .unwrap()
                    .join("\n");
            assert!(
                violations.contains("pure contracts"),
                "stateful strategy dependency unexpectedly passed: {source}"
            );
        }

        let pure = r#"
            use std::{collections::BTreeMap, fmt, sync::Arc};
            use sha2::{Digest, Sha256};
        "#;
        assert!(
            inspect_bounded_source("crates/venom-scanner/src/payload_strategy.rs", pure)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn constructor_inventory_accepts_only_the_exact_production_owners_and_counts() {
        let sources = valid_constructor_sources(VALID_SHARED_AUTHORITY, &[]);
        let inventory = constructor_inventory(&sources);
        assert!(validate_broker_constructor_inventory(&inventory).is_empty());

        let duplicated = format!(
            "{VALID_SHARED_AUTHORITY}\nuse crate::runtime_budget::RequestAccountingBroker as Extra;\nfn extra() {{ let _ = Extra::new(budget()); }}"
        );
        let sources = valid_constructor_sources(&duplicated, &[]);
        let violations =
            validate_broker_constructor_inventory(&constructor_inventory(&sources)).join("\n");
        assert!(violations
            .contains("<free>::extra contains 1 production RequestAccountingBroker::new calls"));
        assert!(violations.contains("requires 0"));
    }

    #[test]
    fn bounded_runtime_inventory_includes_profiled_cli_adapter_only_as_a_consumer() {
        let bounded = BOUNDED_RUNTIME_SOURCES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(bounded.len(), BOUNDED_RUNTIME_SOURCES.len());
        assert!(bounded.contains("crates/venom-cli/src/assessment_scan.rs"));
        assert!(
            !DIRECT_CLIENT_SOURCE_ALLOWLIST.contains(&"crates/venom-cli/src/assessment_scan.rs")
        );
        assert!(!UNMETERED_STANDALONE_FACADE_SOURCES
            .contains(&"crates/venom-cli/src/assessment_scan.rs"));
    }

    #[test]
    fn constructor_inventory_resolves_self_and_raw_aliases_in_every_source() {
        let self_indirection = r#"
            use crate::runtime_budget::RequestAccountingBroker as Accounting;
            trait Escape { fn mint(); }
            impl Escape for Accounting {
                fn mint() { let _ = Self::new(budget()); }
            }
        "#;
        let raw_alias = r#"
            use crate::runtime_budget::RequestAccountingBroker as r#Accounting;
            fn mint() { let _ = r#Accounting::new(budget()); }
        "#;
        let extras = [
            ("crates/venom-scanner/src/lib.rs", self_indirection),
            ("crates/venom-scanner/src/unlisted.rs", raw_alias),
        ];
        let sources = valid_constructor_sources(VALID_SHARED_AUTHORITY, &extras);
        let violations =
            validate_broker_constructor_inventory(&constructor_inventory(&sources)).join("\n");
        assert!(violations.contains("crates/venom-scanner/src/lib.rs trait impl Accounting::mint contains 1 production RequestAccountingBroker::new calls"));
        assert!(violations.contains("crates/venom-scanner/src/unlisted.rs impl <free>::mint contains 1 production RequestAccountingBroker::new calls"));
    }

    #[test]
    fn constructor_inventory_resolves_chained_use_aliases_and_raw_bindings() {
        let chained = r#"
            use crate::http_evidence::HttpRequestBroker as TransportFirst;
            use self::TransportFirst as r#TransportSecond;
            use crate::runtime_budget::RequestAccountingBroker as AccountingFirst;
            use self::AccountingFirst as r#AccountingSecond;
            struct SharedWebRuntimeAuthority;
            impl SharedWebRuntimeAuthority {
                fn new_exact_origin() {
                    let accounting = r#AccountingSecond::new(budget());
                    let _ = r#TransportSecond::new_metered(policy(), accounting);
                }
            }
        "#;
        let sources = valid_constructor_sources(chained, &[]);
        assert!(validate_broker_constructor_inventory(&constructor_inventory(&sources)).is_empty());

        let reexport = r#"
            pub(crate) use crate::runtime_budget::RequestAccountingBroker as First;
            pub(crate) use std::include as load_first;
        "#;
        let bridge = r#"
            pub(crate) use crate::First as r#Second;
            pub(crate) use crate::load_first as r#load_second;
        "#;
        let consumer = r#"
            fn escape() {
                let _ = crate::r#Second::new(budget());
                crate::r#load_second!("hidden.rs");
            }
        "#;
        let mut collector = broker_constructor_alias_collector();
        for source in [reexport, bridge, consumer] {
            collector.visit_file(&syn::parse_file(source).unwrap());
        }
        let aliases = resolve_broker_constructor_aliases(collector);
        let inventory = inspect_broker_constructor_source_with_aliases(consumer, aliases).unwrap();
        assert_eq!(
            inventory
                .direct_calls
                .get(&BrokerConstructorKind::RequestAccounting),
            Some(&1)
        );
        assert!(inventory
            .violations("crates/venom-scanner/src/consumer.rs")
            .join("\n")
            .contains("include! source indirection"));
    }

    #[test]
    fn associated_type_projection_aliases_cannot_hide_constructors() {
        let source = r#"
            use crate::runtime_budget::RequestAccountingBroker;
            trait Reveal { type Output; }
            struct Marker;
            impl Reveal for Marker { type Output = RequestAccountingBroker; }
            type First = <Marker as Reveal>::Output;
            type Second = First;
            use self::Second as r#Third;
            fn mint() { let _ = r#Third::new(budget()); }
        "#;
        let inventory = inspect_broker_constructor_source(source).unwrap();
        assert_eq!(
            inventory
                .direct_calls
                .get(&BrokerConstructorKind::RequestAccounting),
            Some(&1)
        );
        let calls = inventory
            .direct_call_sites
            .iter()
            .map(|call| {
                BrokerConstructorOwnerKey::from_call(
                    "crates/venom-scanner/src/projection_escape.rs",
                    call,
                )
            })
            .map(|key| (key, 1))
            .collect::<BTreeMap<_, _>>();
        let violations = validate_broker_constructor_inventory(&calls).join("\n");
        assert!(violations.contains("projection_escape.rs impl <free>::mint"));
        assert!(violations.contains("RequestAccountingBroker::new"));
    }

    #[test]
    fn generic_type_alias_rhs_recursively_preserves_broker_provenance() {
        let source = r#"
            use crate::runtime_budget::RequestAccountingBroker;
            type Id<T> = T;
            type Accounting = Id<RequestAccountingBroker>;
            fn mint() { let _ = Accounting::new(budget()); }
        "#;
        let inventory = inspect_broker_constructor_source(source).unwrap();
        assert_eq!(
            inventory
                .direct_calls
                .get(&BrokerConstructorKind::RequestAccounting),
            Some(&1)
        );
        let calls = inventory
            .direct_call_sites
            .iter()
            .map(|call| {
                BrokerConstructorOwnerKey::from_call(
                    "crates/venom-scanner/src/generic_alias.rs",
                    call,
                )
            })
            .map(|key| (key, 1))
            .collect::<BTreeMap<_, _>>();
        let violations = validate_broker_constructor_inventory(&calls).join("\n");
        assert!(violations.contains("generic_alias.rs impl <free>::mint"));
        assert!(violations.contains("RequestAccountingBroker::new"));
    }

    #[test]
    fn generic_type_defaults_preserve_broker_provenance() {
        let source = r#"
            use crate::runtime_budget::RequestAccountingBroker;
            type Accounting<T = RequestAccountingBroker> = T;
            trait Defaults { type Associated<T = RequestAccountingBroker>; }
            fn mint() {
                let _ = Accounting::new(budget());
                let _ = Associated::new(budget());
            }
        "#;
        let inventory = inspect_broker_constructor_source(source).unwrap();
        assert_eq!(
            inventory
                .direct_calls
                .get(&BrokerConstructorKind::RequestAccounting),
            Some(&2)
        );
    }

    #[test]
    fn constructor_inventory_rejects_function_pointers_and_parenthesized_calls() {
        for source in [
            r#"
                use crate::runtime_budget::RequestAccountingBroker as Accounting;
                fn mint() { let constructor = Accounting::new; let _ = constructor(budget()); }
            "#,
            r#"
                use crate::runtime_budget::RequestAccountingBroker;
                fn mint() { let _ = (RequestAccountingBroker::new)(budget()); }
            "#,
            r#"
                use crate::runtime_budget::RequestAccountingBroker::new as constructor;
                fn mint() { let _ = constructor(budget()); }
            "#,
        ] {
            let inventory = inspect_broker_constructor_source(source).unwrap();
            assert!(inventory.direct_calls.is_empty());
            let violations = inventory
                .violations("crates/venom-scanner/src/escape.rs")
                .join("\n");
            assert!(violations.contains("non-call RequestAccountingBroker::new references"));
        }
    }

    #[test]
    fn constructor_inventory_rejects_macro_definitions_invocations_and_substitution() {
        let shared = r#"
            use crate::http_evidence::HttpRequestBroker;
            use crate::runtime_budget::RequestAccountingBroker;
            macro_rules! mint {
                ($constructor:path) => { $constructor(budget()) };
            }
            fn compose() {
                let accounting = mint!(RequestAccountingBroker::new);
                repeat_twice!(HttpRequestBroker::new_metered(policy(), accounting.clone()));
            }
        "#;
        let sources = valid_constructor_sources(shared, &[]);
        let violations = constructor_source_violations(&sources).join("\n");
        assert!(violations.contains("macro references to RequestAccountingBroker::new"));
        assert!(violations.contains("macro references to HttpRequestBroker::new_metered"));
        assert!(violations.contains("contains 0 production RequestAccountingBroker::new calls"));
        assert!(violations.contains("contains 0 production HttpRequestBroker::new_metered calls"));
    }

    #[test]
    fn constructor_inventory_requires_exact_inherent_owner_functions_and_direct_paths() {
        let helper = r#"
            use crate::http_evidence::HttpRequestBroker;
            use crate::runtime_budget::RequestAccountingBroker;
            struct SharedWebRuntimeAuthority;
            impl SharedWebRuntimeAuthority {
                fn new_exact_origin() {
                    let accounting = helper();
                    let _ = HttpRequestBroker::new_metered(policy(), accounting);
                }
            }
            fn helper() { let _ = RequestAccountingBroker::new(budget()); }
        "#;
        let helper_sources = valid_constructor_sources(helper, &[]);
        let helper_violations = constructor_source_violations(&helper_sources).join("\n");
        assert!(helper_violations
            .contains("<free>::helper contains 1 production RequestAccountingBroker::new calls"));
        assert!(helper_violations.contains("SharedWebRuntimeAuthority::new_exact_origin contains 0 production RequestAccountingBroker::new calls"));

        let trait_impl = r#"
            use crate::http_evidence::HttpRequestBroker;
            use crate::runtime_budget::RequestAccountingBroker;
            struct SharedWebRuntimeAuthority;
            trait Build { fn new_exact_origin(); }
            impl Build for SharedWebRuntimeAuthority {
                fn new_exact_origin() {
                    let accounting = RequestAccountingBroker::new(budget());
                    let _ = HttpRequestBroker::new_metered(policy(), accounting);
                }
            }
        "#;
        let trait_sources = valid_constructor_sources(trait_impl, &[]);
        let trait_violations = constructor_source_violations(&trait_sources).join("\n");
        assert!(trait_violations.contains("trait impl SharedWebRuntimeAuthority::new_exact_origin"));
        assert!(trait_violations.contains("exact authority owner inventory requires 0"));

        let looped = r#"
            use crate::http_evidence::HttpRequestBroker;
            use crate::runtime_budget::RequestAccountingBroker;
            struct SharedWebRuntimeAuthority;
            impl SharedWebRuntimeAuthority {
                fn new_exact_origin() {
                    for _ in 0..1 {
                        let _ = RequestAccountingBroker::new(budget());
                    }
                    let _ = HttpRequestBroker::new_metered(policy(), accounting());
                }
            }
        "#;
        let loop_sources = valid_constructor_sources(looped, &[]);
        let loop_violations = constructor_source_violations(&loop_sources).join("\n");
        assert!(loop_violations.contains("inside loop/conditional control flow"));

        let closure = r#"
            use crate::http_evidence::HttpRequestBroker;
            use crate::runtime_budget::RequestAccountingBroker;
            struct SharedWebRuntimeAuthority;
            impl SharedWebRuntimeAuthority {
                fn new_exact_origin() {
                    (0..1).for_each(|_| { let _ = RequestAccountingBroker::new(budget()); });
                    let _ = HttpRequestBroker::new_metered(policy(), accounting());
                }
            }
        "#;
        let closure_sources = valid_constructor_sources(closure, &[]);
        let closure_violations = constructor_source_violations(&closure_sources).join("\n");
        assert!(closure_violations.contains("inside a helper/repeating closure"));
    }

    #[test]
    fn constructor_inventory_rejects_source_indirection_but_allows_cfg_test_paths() {
        let include = inspect_broker_constructor_source("include!(\"hidden.rs\");")
            .unwrap()
            .violations("crates/venom-scanner/src/lib.rs")
            .join("\n");
        assert!(include.contains("production include! source indirection"));

        let macro_include = inspect_broker_constructor_source(
            "macro_rules! hidden { () => { include!(\"hidden.rs\") } }",
        )
        .unwrap()
        .violations("crates/venom-scanner/src/lib.rs")
        .join("\n");
        assert!(macro_include.contains("include! inside a macro"));

        let imported_include = inspect_broker_constructor_source(
            r#"
                use std::include as load_first;
                use self::load_first as r#load_second;
                r#load_second!("hidden.rs");
            "#,
        )
        .unwrap()
        .violations("crates/venom-scanner/src/lib.rs")
        .join("\n");
        assert!(imported_include.contains("imported include! macro alias"));
        assert!(imported_include.contains("include! source indirection"));

        let path = inspect_broker_constructor_source("#[path = \"hidden.rs\"] mod hidden;")
            .unwrap()
            .violations("crates/venom-scanner/src/lib.rs")
            .join("\n");
        assert!(path.contains("production #[path]"));

        let test_path =
            inspect_broker_constructor_source("#[cfg(test)] #[path = \"tests.rs\"] mod tests;")
                .unwrap();
        assert!(test_path.is_empty());
    }

    #[test]
    fn production_source_inventory_uses_module_reachability_not_test_filenames() {
        let directory = tempfile::tempdir().unwrap();
        let scanner_root = directory.path();
        fs::write(
            scanner_root.join("lib.rs"),
            "mod bridge_tests; #[cfg(test)] mod only_tests;",
        )
        .unwrap();
        fs::write(scanner_root.join("bridge_tests.rs"), "fn production() {}").unwrap();
        fs::write(scanner_root.join("only_tests.rs"), "fn test_only() {}").unwrap();
        fs::write(scanner_root.join("unlisted_tests.rs"), "fn unlisted() {}").unwrap();

        let mut paths = Vec::new();
        collect_rust_sources(scanner_root, &mut paths).unwrap();
        paths.sort();
        let production = production_scanner_sources(scanner_root, &paths)
            .unwrap()
            .into_iter()
            .filter_map(|path| {
                path.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect::<BTreeSet<_>>();

        assert!(production.contains("lib.rs"));
        assert!(production.contains("bridge_tests.rs"));
        assert!(production.contains("unlisted_tests.rs"));
        assert!(!production.contains("only_tests.rs"));
    }

    #[test]
    fn constructor_inventory_ignores_comments_and_test_only_items() {
        let comments = r#"
            // RequestAccountingBroker::new(budget());
            /* HttpRequestBroker::new_metered(policy(), accounting()); */
            const TEXT: &str = "RequestAccountingBroker::new(budget())";
            #[cfg(test)]
            fn test_only() {
                RequestAccountingBroker::new(budget());
                HttpRequestBroker::new_metered(policy(), accounting());
            }
        "#;
        assert!(inspect_broker_constructor_source(comments)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn bounded_surface_b_cannot_reference_legacy_authorities() {
        for source in [
            "use crate::legacy_discovery::LegacyDiscoveryAuthority as Escape;",
            "use crate::legacy_discovery as legacy; fn escape() { legacy::LegacyVerificationAuthority::new(); }",
            "fn escape() { hidden!(crate::legacy_discovery::LegacyDiscoveryAuthority::new()); }",
        ] {
            let violations =
                inspect_bounded_source("crates/venom-scanner/src/web_runtime.rs", source)
                    .unwrap()
                    .join("\n");
            assert!(
                violations.contains("bounded Surface-B code must use SharedWebRuntimeAuthority"),
                "bounded legacy-authority escape unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn bounded_surface_b_rejects_full_tree_legacy_authority_reexport_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let scanner_root = directory.path().join("crates/venom-scanner/src");
        fs::create_dir_all(&scanner_root).unwrap();
        fs::write(
            scanner_root.join("lib.rs"),
            r#"
                mod legacy_discovery;
                mod bridge;
                mod web_runtime;
                pub(crate) use legacy_discovery::LegacyDiscoveryAuthority as Fresh;
                type Id<T> = T;
                pub(crate) type GenericFresh = Id<LegacyDiscoveryAuthority>;
            "#,
        )
        .unwrap();
        fs::write(
            scanner_root.join("legacy_discovery.rs"),
            "pub(crate) struct LegacyDiscoveryAuthority;",
        )
        .unwrap();
        fs::write(
            scanner_root.join("bridge.rs"),
            "pub(crate) use crate::Fresh as r#FreshAgain;",
        )
        .unwrap();
        let bounded = r#"
            use crate::bridge::r#FreshAgain as Local;
            use crate::GenericFresh as GenericLocal;
            fn consume(_: Local, _: GenericLocal) {}
        "#;
        fs::write(scanner_root.join("web_runtime.rs"), bounded).unwrap();

        let aliases = collect_full_tree_legacy_authority_aliases(directory.path()).unwrap();
        for alias in [
            "Fresh",
            "FreshAgain",
            "Local",
            "GenericFresh",
            "GenericLocal",
        ] {
            assert!(aliases.contains(alias), "missing tainted alias {alias}");
        }
        let violations = inspect_bounded_source_with_legacy_aliases(
            "crates/venom-scanner/src/web_runtime.rs",
            bounded,
            &aliases,
        )
        .unwrap()
        .join("\n");
        assert!(violations.contains("bounded Surface-B code must use SharedWebRuntimeAuthority"));
        assert!(violations.contains("FreshAgain"));
    }

    #[test]
    fn generic_type_defaults_preserve_legacy_authority_provenance() {
        let definitions = r#"
            type DefaultFresh<T = LegacyDiscoveryAuthority> = T;
            trait Defaults {
                type AssociatedFresh<T = LegacyVerificationAuthority>;
            }
        "#;
        let bounded = r#"
            use crate::{AssociatedFresh, DefaultFresh};
            fn consume(_: DefaultFresh, _: AssociatedFresh) {}
        "#;
        let aliases =
            collect_legacy_authority_aliases_from_sources([definitions, bounded]).unwrap();
        for alias in ["DefaultFresh", "AssociatedFresh"] {
            assert!(aliases.contains(alias), "missing tainted alias {alias}");
        }
        let violations = inspect_bounded_source_with_legacy_aliases(
            "crates/venom-scanner/src/web_runtime.rs",
            bounded,
            &aliases,
        )
        .unwrap()
        .join("\n");
        assert!(violations.contains("DefaultFresh"));
        assert!(violations.contains("AssociatedFresh"));
    }

    #[test]
    fn migrated_discovery_can_use_context_type_but_not_raw_transport() {
        let safe = r#"
            use crate::context::ScanContext;
            async fn discover(context: &ScanContext) { context.request(); }
        "#;
        assert!(inspect_migrated_discovery_source(
            "crates/venom-scanner/src/phases/phase2_crawl.rs",
            safe,
        )
        .unwrap()
        .is_empty());

        for source in [
            "use crate::context::ScanContext; fn leak(context: &ScanContext) { let _ = &context.client; }",
            "use reqwest::Client; fn leak() { let _ = Client::new(); }",
            "fn leak(client: Client, request: Request) { client.execute(request); }",
            "fn leak(client: Client) { client.get(\"https://example.test\").send(); }",
            "fn leak(policy: Policy) { HttpRequestBroker::new_unmetered(policy); }",
            "fn leak(context: ScanContext) { let ScanContext { client: raw, .. } = context; raw.dispatch(); }",
        ] {
            assert!(
                !inspect_migrated_discovery_source(
                    "crates/venom-scanner/src/phases/phase2_crawl.rs",
                    source,
                )
                .unwrap()
                .is_empty(),
                "migrated discovery transport escape unexpectedly passed: {source}"
            );
        }

        for source in [
            "use venom_core::Outcome as Claim; fn forge() { Claim::new(input()); }",
            "type Claim = venom_core::RunOutcomeRecord; fn forge() { Claim::unresolved(a(), b(), c(), d()); }",
            "fn forge() { audit!(venom_core::RunOutcomeRecord::from_outcome(a(), b())); }",
        ] {
            let violations = inspect_migrated_discovery_source(
                "crates/venom-scanner/src/phases/phase9_ssrf.rs",
                source,
            )
            .unwrap();
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains("direct outcome type")),
                "direct claim alias unexpectedly passed: {source}; {violations:?}"
            );
        }
    }

    #[test]
    fn migrated_phase_consumers_cannot_multiply_or_bypass_discovery_authority() {
        for source in [
            "use crate::http_evidence::HttpRequestBroker; fn escape() { HttpRequestBroker::new_metered(); }",
            "use crate::runtime_budget::RequestAccountingBroker;",
            "use crate::RuntimeBudget;",
            "use crate::legacy_discovery::LegacyDiscoveryAuthority;",
            "use crate::legacy_discovery::LegacyVerificationAuthority;",
            "use crate::VerificationLimits;",
            "fn escape(context: &ScanContext) { context.add_endpoint(); }",
            "fn escape(context: &ScanContext) { context.mark_visited(); }",
            "fn escape(context: &ScanContext) { let _ = &context.discovered_endpoints; }",
            "fn escape(context: &ScanContext) { let _ = &context.visited_urls; }",
            "fn escape(context: ScanContext) { context.with_pre_execution_discovery_limits(); }",
            "fn escape(context: ScanContext) { context.with_pre_execution_verification_limits(); }",
            "fn escape() { crate::context::ScanContext::new(target(), Default::default(), telemetry()); }",
            "use crate::context::ScanContext as Fresh; fn escape() { Fresh::with_timeout(target(), Default::default(), telemetry(), 30); }",
            "fn escape(context: ScanContext) { let ScanContext { discovered_endpoints, .. } = context; mutate(discovered_endpoints); }",
            "fn escape() { policy!(LegacyDiscoveryAuthority::new()); }",
            "fn escape(context: &ScanContext) { policy!(context.add_endpoint()); }",
        ] {
            assert!(
                !inspect_migrated_discovery_source(
                    "crates/venom-scanner/src/phases/phase2_crawl.rs",
                    source,
                )
                .unwrap()
                .is_empty(),
                "discovery authority escape unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn migrated_phases_cannot_cross_passive_and_active_request_seams() {
        let passive = "use crate::context::ScanContext; async fn run(context: &ScanContext) { context.request(); }";
        assert!(inspect_migrated_discovery_source(
            "crates/venom-scanner/src/phases/phase2_crawl.rs",
            passive,
        )
        .unwrap()
        .is_empty());
        assert!(!inspect_migrated_discovery_source(
            "crates/venom-scanner/src/phases/phase5_sqli.rs",
            passive,
        )
        .unwrap()
        .is_empty());

        let active = "use crate::context::ScanContext; async fn run(context: &ScanContext) { context.verification_request(); }";
        assert!(inspect_migrated_discovery_source(
            "crates/venom-scanner/src/phases/phase5_sqli.rs",
            active,
        )
        .unwrap()
        .is_empty());
        assert!(!inspect_migrated_discovery_source(
            "crates/venom-scanner/src/phases/phase2_crawl.rs",
            active,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn legacy_verification_claim_language_is_fail_closed() {
        let safe = r#"
            fn observation() -> ScanFinding {
                ScanFinding { severity: "INFO", description: "manual review", evidence: "bounded" }
            }
            #[cfg(test)]
            mod tests { const NEGATIVE_ASSERTION: &str = "not confirmed"; }
        "#;
        assert!(inspect_legacy_verification_claim_language("phase.rs", safe).is_empty());

        for source in [
            "fn result() { let _ = \"confirmed SQL injection\"; }",
            "fn result() { let _ = \"vulnerability\"; }",
            "fn result() { ScanFinding { severity: \"HIGH\" }; }",
            "fn result() { ScanFinding { severity: \"CRITICAL\" }; }",
            "fn name() -> &'static str { \"SQL Expert\" }",
            "fn name() -> &'static str { \"Sandbox Escaper\" }",
            "fn forge() { Outcome::new(input()); }",
            "fn forge() { RunOutcomeRecord::unresolved(a(), b(), c(), d()); }",
            "fn forge(_: RunOutcomeRecordInput) {}",
        ] {
            assert!(
                !inspect_legacy_verification_claim_language("phase.rs", source).is_empty(),
                "legacy claim language unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn migrated_phase_consumers_reject_every_alternate_runtime_constructor() {
        for source in [
            r#"
                use crate::http_evidence::{HttpEvidenceExecutor, HttpEvidencePolicy};
                fn escape(policy: HttpEvidencePolicy, probes: Probes) {
                    let executor = HttpEvidenceExecutor::new(policy, probes);
                    DecisionActionExecutor::execute(&executor, action(), context());
                }
            "#,
            r#"
                use crate::web_execution::StandardWebDiscoveryExecutorProfile;
                fn escape(policy: Policy) {
                    StandardWebDiscoveryExecutorProfile::new(policy);
                }
            "#,
            r#"
                use crate::context::ScanContext;
                fn escape() {
                    ScanContext::new(target(), Default::default(), telemetry());
                }
            "#,
            r#"
                use crate::context::ScanContext as Fresh;
                fn escape() {
                    Fresh::new(target(), Default::default(), telemetry());
                }
            "#,
            r#"
                use crate::context::ScanContext;
                type Fresh = ScanContext;
                fn escape() {
                    Fresh::with_event_bus(target(), Default::default(), telemetry(), events());
                }
            "#,
            r#"
                use crate::context::ScanContext;
                fn escape() {
                    <ScanContext>::new(target(), Default::default(), telemetry());
                }
            "#,
            r#"
                use crate::context::ScanContext as Fresh;
                fn escape() {
                    <Fresh>::with_event_bus(
                        target(), Default::default(), telemetry(), events(),
                    );
                }
            "#,
            r#"
                use crate::sdk::ScannerSdk;
                fn escape() { ScannerSdk::builder(); }
            "#,
        ] {
            assert!(
                !inspect_migrated_discovery_source(
                    "crates/venom-scanner/src/phases/phase2_crawl.rs",
                    source,
                )
                .unwrap()
                .is_empty(),
                "alternate migrated-discovery runtime unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn migrated_phase_internal_api_allowlist_is_exact() {
        let allowed = r#"
            use crate::{
                context::ScanContext,
                contracts::{ScanFinding, ScanPhase},
                error::ScannerError,
                http_evidence::HttpProbeMethod,
                legacy_discovery::{
                    BoundedHttpResponse, DiscoveryDelta, DiscoveryForm, DiscoveryFormMethod,
                },
            };
            use super::phase3_fuzzer::ResponseSignature;

            fn consume(
                context: &ScanContext,
                response: &BoundedHttpResponse,
            ) -> Result<(HttpProbeMethod, DiscoveryDelta), ScannerError> {
                let _ = (context, response);
                Ok((HttpProbeMethod::Get, DiscoveryDelta::new()))
            }
        "#;
        assert!(inspect_migrated_discovery_source(
            "crates/venom-scanner/src/phases/phase4_param.rs",
            allowed,
        )
        .unwrap()
        .is_empty());

        for source in [
            "use crate::sdk::ScannerBuilder;",
            "use crate::web_runtime::StandardWebDecisionRuntime;",
            "use crate::context::DiscoveryAuthority;",
            "use super::phase2_crawl::CrawlPhase;",
        ] {
            assert!(
                !inspect_migrated_discovery_source(
                    "crates/venom-scanner/src/phases/phase4_param.rs",
                    source,
                )
                .unwrap()
                .is_empty(),
                "non-allowlisted internal path unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn paired_visibility_source_cannot_construct_an_unmetered_broker() {
        for source in [
            "fn escape(policy: Policy) { HttpRequestBroker :: new_unmetered (policy); }",
            "use crate::http_evidence::HttpRequestBroker as Broker; fn escape(policy: Policy) { Broker::new_unmetered(policy); }",
            "fn escape(broker: Broker, policy: Policy) { broker.new_unmetered(policy); }",
            "fn escape(policy: Policy) { policy!(Broker::new_unmetered(policy)); }",
        ] {
            let violations = inspect_bounded_source(
                "crates/venom-scanner/src/web_runtime/api_visibility/differential/execution.rs",
                source,
            )
            .unwrap()
            .join("\n");

            assert!(
                violations.contains("constructs an unmetered request broker"),
                "unmetered alias unexpectedly passed: {source}: {violations}"
            );
        }
    }

    #[test]
    fn aliases_and_macro_paths_cannot_hide_transport() {
        for source in [
            "use reqwest as transport;",
            "extern crate reqwest as transport;",
            "extern crate self as application;",
            "fn leak() { policy!(tokio::net::TcpStream::connect()); }",
            "fn leak() { policy!(context.client.send()); }",
        ] {
            assert!(
                !inspect_bounded_source("crates/venom-scanner/src/web_execution.rs", source)
                    .unwrap()
                    .is_empty(),
                "transport escape unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn broad_root_aliases_cannot_hide_transport_paths() {
        for source in [
            "use crate as app;",
            "use crate::{self as app};",
            "use self as local;",
            "use super as parent;",
            "use std as runtime;",
            "use tokio::{self as runtime};",
        ] {
            let violations =
                inspect_bounded_source("crates/venom-scanner/src/web_execution.rs", source)
                    .unwrap()
                    .join("\n");
            assert!(
                violations.contains("aliases broad runtime root"),
                "broad root alias unexpectedly passed: {source}: {violations}"
            );
        }

        assert!(inspect_bounded_source(
            "crates/venom-scanner/src/web_execution.rs",
            "use super::DecisionLoop;",
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn external_submodules_require_explicit_transport_policy_registration() {
        for (source_name, source) in [
            ("crates/venom-scanner/src/web_runtime.rs", "mod escape;"),
            (
                "crates/venom-scanner/src/web_runtime.rs",
                "#[path = \"escape.rs\"] mod api_visibility;",
            ),
            (
                "crates/venom-scanner/src/web_runtime.rs",
                "pub mod api_visibility;",
            ),
            (
                "crates/venom-scanner/src/web_runtime.rs",
                "mod nested { mod api_visibility; }",
            ),
        ] {
            let violations = inspect_bounded_source(source_name, source)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("unregistered external submodule"),
                "external module unexpectedly passed: {source}: {violations}"
            );
        }

        for (source_name, source) in [
            (
                "crates/venom-scanner/src/http_evidence.rs",
                "mod request_broker;",
            ),
            (
                "crates/venom-scanner/src/http_evidence.rs",
                "mod form_controls;",
            ),
            (
                "crates/venom-scanner/src/web_runtime.rs",
                "mod api_visibility;",
            ),
        ] {
            assert!(
                inspect_bounded_source(source_name, source)
                    .unwrap()
                    .is_empty(),
                "canonical bounded submodule was rejected: {source}"
            );
        }

        let inline = "mod helper { use crate::context::ScanContext; }";
        let violations =
            inspect_bounded_source("crates/venom-scanner/src/web_execution.rs", inline)
                .unwrap()
                .join("\n");
        assert!(violations.contains("crate::context::ScanContext"));
        assert!(!violations.contains("unregistered external submodule"));
    }

    #[test]
    fn production_send_inventory_ignores_exact_test_modules() {
        let source = r#"
            fn production(sender: Sender) { sender.send(); }
            #[cfg(test)]
            mod tests {
                fn helper(sender: Sender) { sender.send(); }
            }
        "#;
        assert_eq!(count_production_method_calls(source, "send").unwrap(), 1);
    }

    #[test]
    fn direct_capability_detection_distinguishes_metadata() {
        let metadata = syn::parse_file("use reqwest::StatusCode;").unwrap();
        let mut metadata_visitor = DirectCapabilityVisitor::default();
        metadata_visitor.visit_file(&metadata);
        assert!(!metadata_visitor.found);

        for source in [
            "use reqwest::Client;",
            "use tokio::net::TcpStream;",
            "fn leak() { let _ = reqwest::get(\"https://example.test\"); }",
        ] {
            let syntax = syn::parse_file(source).unwrap();
            let mut visitor = DirectCapabilityVisitor::default();
            visitor.visit_file(&syntax);
            assert!(visitor.found, "direct capability not detected: {source}");
        }
    }

    #[test]
    fn direct_client_inventory_uses_reachability_not_test_filenames_in_every_crate() {
        let directory = tempfile::tempdir().unwrap();
        for (crate_name, root_file) in [("venom-scanner", "lib.rs"), ("venom-cli", "main.rs")] {
            let source_root = directory.path().join(format!("crates/{crate_name}/src"));
            fs::create_dir_all(&source_root).unwrap();
            fs::write(
                source_root.join(root_file),
                "mod escape_tests; #[cfg(test)] mod only_tests;",
            )
            .unwrap();
            fs::write(
                source_root.join("escape_tests.rs"),
                "fn escape() { let _ = reqwest::Client::new(); }",
            )
            .unwrap();
            fs::write(
                source_root.join("only_tests.rs"),
                "fn fixture() { let _ = reqwest::Client::new(); }",
            )
            .unwrap();
        }
        let scanner_root = directory.path().join("crates/venom-scanner/src");
        fs::write(
            scanner_root.join("lib.rs"),
            r#"
                mod escape_tests;
                #[cfg(test)]
                #[path = "main.rs"]
                mod test_binary;
                #[cfg(test)]
                mod only_tests;
            "#,
        )
        .unwrap();
        fs::write(
            scanner_root.join("main.rs"),
            "mod binary_escape_tests; fn main() {}",
        )
        .unwrap();
        fs::write(
            scanner_root.join("binary_escape_tests.rs"),
            "fn escape() { let _ = reqwest::Client::new(); }",
        )
        .unwrap();

        let direct = direct_client_sources(directory.path()).unwrap();
        for crate_name in ["venom-scanner", "venom-cli"] {
            assert!(direct.contains(&format!("crates/{crate_name}/src/escape_tests.rs")));
            assert!(!direct.contains(&format!("crates/{crate_name}/src/only_tests.rs")));
        }
        assert!(direct.contains("crates/venom-scanner/src/binary_escape_tests.rs"));
    }

    fn valid_assessment_composition() -> &'static str {
        r#"
            struct SharedWebRuntimeAuthority;
            impl SharedWebRuntimeAuthority { fn new_exact_origin() -> Self { Self } }
            struct ChildBuilder;
            impl ChildBuilder { fn build_with_shared_authority(&self, _: SharedWebRuntimeAuthority) {} }
            struct WebAssessmentRuntimeBuilder;
            impl WebAssessmentRuntimeBuilder {
                fn build(&self) {
                    let _authority = SharedWebRuntimeAuthority::new_exact_origin();
                }
            }
            struct WebAssessmentRuntime;
            impl WebAssessmentRuntime {
                async fn analyze(&self, builder: ChildBuilder, authority: SharedWebRuntimeAuthority) {
                    #[cfg(feature = "reporting")]
                    let run_started_at = SystemTime::now();
                    builder.build_with_shared_authority(authority);
                    let _report = WebAssessmentRunReport {
                        #[cfg(feature = "reporting")]
                        run_started_at,
                    };
                }
            }
        "#
    }

    #[test]
    fn assessment_composition_gate_requires_one_direct_global_authority_and_shared_children() {
        assert!(
            inspect_web_assessment_composition(valid_assessment_composition())
                .unwrap()
                .is_empty()
        );

        for (mutation, needle) in [
            (
                valid_assessment_composition().replace(
                    "let _authority = SharedWebRuntimeAuthority::new_exact_origin();",
                    "if enabled() { let _authority = SharedWebRuntimeAuthority::new_exact_origin(); }",
                ),
                "unconditional direct call",
            ),
            (
                valid_assessment_composition().replace(
                    "builder.build_with_shared_authority(authority);",
                    "builder.build();",
                ),
                "standalone .build()",
            ),
            (
                valid_assessment_composition().replace(
                    "let _authority = SharedWebRuntimeAuthority::new_exact_origin();",
                    "",
                ),
                "exactly once",
            ),
        ] {
            let violations = inspect_web_assessment_composition(&mutation)
                .unwrap()
                .join("\n");
            assert!(violations.contains(needle), "{violations}");
        }
    }

    #[test]
    fn assessment_transport_gate_rejects_legacy_phases_and_direct_io() {
        for (source, needle) in [
            (
                "use crate::phases::phase1::Runner;",
                "quarantined legacy phase path",
            ),
            (
                "use crate::contracts::ScanPhase;",
                "legacy discovery/verification authority",
            ),
            (
                "use crate::legacy_discovery::Crawler;",
                "legacy discovery/verification authority",
            ),
            (
                "fn f() { let _ = reqwest::Client::new(); }",
                "forbidden direct transport",
            ),
            (
                "fn f() { let _ = HttpRequestBroker::new_metered(); }",
                "forbidden direct transport",
            ),
            (
                "fn f() { let _ = RequestAccountingBroker::new(); }",
                "forbidden direct transport",
            ),
        ] {
            let violations = inspect_bounded_source(
                "crates/venom-scanner/src/web_runtime/web_assessment.rs",
                source,
            )
            .unwrap()
            .join("\n");
            assert!(violations.contains(needle), "{source}: {violations}");
        }
    }

    #[test]
    fn assessment_facade_export_allowlist_is_exact() {
        let exports = WEB_ASSESSMENT_PUBLIC_EXPORTS.join(", ");
        let valid = format!(
            "mod web_assessment;\n\
             pub use web_assessment::{{{exports}}};"
        );
        assert!(inspect_web_assessment_facade(&valid).unwrap().is_empty());
        let unexpected = valid.replace("};", ", AccidentalExport};");
        let violations = inspect_web_assessment_facade(&unexpected)
            .unwrap()
            .join("\n");
        assert!(violations.contains("unexpected"), "{violations}");
        let public_module = valid.replace("mod web_assessment;", "pub mod web_assessment;");
        let violations = inspect_web_assessment_facade(&public_module)
            .unwrap()
            .join("\n");
        assert!(violations.contains("private canonical external child"));

        let redirected = valid.replace(
            "mod web_assessment;",
            "#[path = \"alternate.rs\"] mod web_assessment;",
        );
        let violations = inspect_web_assessment_facade(&redirected)
            .unwrap()
            .join("\n");
        assert!(violations.contains("no path redirection"));
    }

    #[test]
    fn assessment_item_source_is_a_bounded_projection_consumer() {
        assert!(BOUNDED_RUNTIME_SOURCES.contains(&ASSESSMENT_ITEM_SOURCE));
        assert!(!DIRECT_CLIENT_SOURCE_ALLOWLIST.contains(&ASSESSMENT_ITEM_SOURCE));
        assert!(!UNMETERED_STANDALONE_FACADE_SOURCES.contains(&ASSESSMENT_ITEM_SOURCE));
    }

    #[test]
    fn assessment_item_transport_gate_rejects_network_and_legacy_authority() {
        let source = "use crate::{contracts::ScanPhase, http_evidence::HttpRequestBroker};\n\
                      fn escape(broker: HttpRequestBroker) { broker.send(); }";
        let violations = inspect_owned_transport_source(
            ASSESSMENT_ITEM_SOURCE,
            source,
            false,
            false,
            &BTreeSet::new(),
        )
        .unwrap()
        .join("\n");
        assert!(violations.contains("ScanPhase"), "{violations}");
        assert!(violations.contains("HttpRequestBroker"), "{violations}");
        assert!(violations.contains(".send()"), "{violations}");
    }

    #[test]
    fn assessment_item_facade_is_private_direct_unconditional_and_exact() {
        let source = include_str!("../../../crates/venom-scanner/src/web_runtime.rs");
        assert!(inspect_assessment_item_facade(source).unwrap().is_empty());

        let public_module = source.replacen("mod assessment_item;", "pub mod assessment_item;", 1);
        let violations = inspect_assessment_item_facade(&public_module)
            .unwrap()
            .join("\n");
        assert!(violations.contains("private canonical"), "{violations}");

        let conditional = source.replacen(
            "pub use assessment_item::{",
            "#[cfg(test)]\npub use assessment_item::{",
            1,
        );
        let violations = inspect_assessment_item_facade(&conditional)
            .unwrap()
            .join("\n");
        assert!(violations.contains("unconditional"), "{violations}");

        let extra = source.replacen(
            "pub use assessment_item::{",
            "pub use assessment_item::{AssessmentCapabilityDescriptor,",
            1,
        );
        let violations = inspect_assessment_item_facade(&extra).unwrap().join("\n");
        assert!(violations.contains("unexpected"), "{violations}");
    }

    #[test]
    fn assessment_item_contract_is_read_only_nonserializable_and_claim_derived() {
        let source =
            include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_item.rs");
        assert!(
            inspect_assessment_item_projection(source)
                .unwrap()
                .is_empty(),
            "{}",
            inspect_assessment_item_projection(source)
                .unwrap()
                .join("\n")
        );

        let public_field = source.replacen(
            "pub struct AssessmentSubjectReference(u32);",
            "pub struct AssessmentSubjectReference(pub u32);",
            1,
        );
        let violations = inspect_assessment_item_projection(&public_field)
            .unwrap()
            .join("\n");
        assert!(violations.contains("construction field"), "{violations}");

        let serializable = source.replacen(
            "pub struct AssessmentSubjectReference(u32);",
            "#[derive(Serialize)]\npub struct AssessmentSubjectReference(u32);",
            1,
        );
        let violations = inspect_assessment_item_projection(&serializable)
            .unwrap()
            .join("\n");
        assert!(violations.contains("serialization"), "{violations}");

        let upgraded = source.replacen(
            "Self::Observation(_) => AssessmentDisposition::Informational",
            "Self::Observation(_) => AssessmentDisposition::Confirmed",
            1,
        );
        let violations = inspect_assessment_item_projection(&upgraded)
            .unwrap()
            .join("\n");
        assert!(violations.contains("authority marker"), "{violations}");

        let network = format!("{source}\nuse crate::RuntimeBudget;");
        let violations = inspect_assessment_item_projection(&network)
            .unwrap()
            .join("\n");
        assert!(violations.contains("RuntimeBudget"), "{violations}");
    }

    #[test]
    fn assessment_item_projection_context_and_factory_authority_are_pinned() {
        let source =
            include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_item.rs");

        for forbidden_input in [
            "DecisionExecutionFailureReceipt",
            "StandardWebDecisionFailureReceipt",
            "DecisionRunnerTurn",
            "AssessmentSubjectReference",
            "AssessmentDisposition",
            "BTreeMap<String, String>",
        ] {
            let mutated = source.replacen(
                "    fn from_verifier_projection(\n        capability: &'static AssessmentCapabilityDescriptor,\n        context: &AssessmentProjectionContext,\n        target: &AssessmentItemTarget,\n        receipt: &DecisionEvidenceReceipt,",
                &format!(
                    "    fn from_verifier_projection(\n        capability: &'static AssessmentCapabilityDescriptor,\n        context: &AssessmentProjectionContext,\n        forbidden: {forbidden_input},\n        receipt: &DecisionEvidenceReceipt,"
                ),
                1,
            );
            let violations = inspect_assessment_item_projection(&mutated)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("raw caller authority"),
                "missing input rejection for {forbidden_input}: {violations}"
            );
            assert!(
                violations.contains("exact private"),
                "missing exact factory rejection for {forbidden_input}: {violations}"
            );
        }

        let wrong_authority = source.replacen(
            "knowledge_authority: KnowledgeAuthority,",
            "knowledge_authority: String,",
            1,
        );
        let violations = inspect_assessment_item_projection(&wrong_authority)
            .unwrap()
            .join("\n");
        assert!(violations.contains("opaque authority"), "{violations}");

        let cloneable_context = source.replacen(
            "pub(crate) struct AssessmentProjectionContext {",
            "#[derive(Clone)]\npub(crate) struct AssessmentProjectionContext {",
            1,
        );
        let violations = inspect_assessment_item_projection(&cloneable_context)
            .unwrap()
            .join("\n");
        assert!(violations.contains("must not be Clone"), "{violations}");

        let raw_scope = source.replacen(
            "pub(crate) struct AssessmentProjectionContext {\n    knowledge_authority: KnowledgeAuthority,\n    stable_scope_id: StableAssessmentScopeId,",
            "pub(crate) struct AssessmentProjectionContext {\n    knowledge_authority: KnowledgeAuthority,\n    stable_scope_id: String,",
            1,
        );
        let violations = inspect_assessment_item_projection(&raw_scope)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("exact bounded identity maps"),
            "{violations}"
        );

        let unscoped_fingerprint = source.replacen(
            "digest_field(&mut digest, stable_scope_id.as_str());",
            "let _ = stable_scope_id;",
            1,
        );
        let violations = inspect_assessment_item_projection(&unscoped_fingerprint)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("scope fingerprint framing"),
            "{violations}"
        );

        let unbounded_observation = source.replacen(
            "preflight_evidence_ids(evidence_ids)?;",
            "let _ = evidence_ids;",
            1,
        );
        let violations = inspect_assessment_item_projection(&unbounded_observation)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("observation and context evidence preflight"),
            "{violations}"
        );

        let missing_authority_check = source.replacen(
            "self.validate_knowledge_authority(knowledge)?;",
            "let _ = knowledge;",
            1,
        );
        let violations = inspect_assessment_item_projection(&missing_authority_check)
            .unwrap()
            .join("\n");
        assert!(violations.contains("register_evidence"), "{violations}");

        let raised_cap = source.replacen(
            "const MAX_PROJECTION_CASES: usize = 10_000;",
            "const MAX_PROJECTION_CASES: usize = 10_001;",
            1,
        );
        let violations = inspect_assessment_item_projection(&raised_cap)
            .unwrap()
            .join("\n");
        assert!(violations.contains("MAX_PROJECTION_CASES"), "{violations}");

        let raw_context_evidence = source.replacen(
            "struct EvidenceProjection {\n    reference: AssessmentEvidenceReference,\n    subject: EntityId,\n}",
            "struct EvidenceProjection {\n    reference: AssessmentEvidenceReference,\n    subject: EntityId,\n    raw: Evidence,\n}",
            1,
        );
        let violations = inspect_assessment_item_projection(&raw_context_evidence)
            .unwrap()
            .join("\n");
        assert!(violations.contains("EvidenceProjection"), "{violations}");

        let unbound_outcome = source.replacen(
            "struct RuntimeOutcomeIdentity {\n    subject: EntityId,",
            "struct RuntimeOutcomeIdentity {\n    subject: String,",
            1,
        );
        let violations = inspect_assessment_item_projection(&unbound_outcome)
            .unwrap()
            .join("\n");
        assert!(violations.contains("subject-bound"), "{violations}");

        let raw_public_body = source.replacen(
            "    basis: AssessmentBasis,\n}",
            "    basis: AssessmentBasis,\n    raw_body: Vec<u8>,\n}",
            1,
        );
        let violations = inspect_assessment_item_projection(&raw_public_body)
            .unwrap()
            .join("\n");
        assert!(violations.contains("secret-bearing"), "{violations}");

        let dynamic_error = source.replacen(
            "pub enum AssessmentItemProjectionError {",
            "pub enum AssessmentItemProjectionError {\n    LeakedCredential(String),",
            1,
        );
        let violations = inspect_assessment_item_projection(&dynamic_error)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("caller-controlled dynamic"),
            "{violations}"
        );
    }

    #[test]
    fn assessment_projection_knowledge_authority_and_exact_outcome_identity_are_pinned() {
        let item_source =
            include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_item.rs");
        let knowledge_source = include_str!("../../../crates/venom-scanner/src/knowledge.rs");

        let extra_constructor_input = item_source.replacen(
            "pub(crate) fn new(knowledge: &KnowledgeBase, stable_scope_id: StableAssessmentScopeId)",
            "pub(crate) fn new(knowledge: &KnowledgeBase, subject: &EntityId, stable_scope_id: StableAssessmentScopeId)",
            1,
        );
        assert_ne!(extra_constructor_input, item_source);
        let violations = inspect_assessment_item_projection(&extra_constructor_input)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("AssessmentProjectionContext::new"),
            "{violations}"
        );

        let fake_authority = item_source.replacen(
            "knowledge.authority().is_same_as(&self.knowledge_authority)",
            "true",
            1,
        );
        assert_ne!(fake_authority, item_source);
        let violations = inspect_assessment_item_projection(&fake_authority)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("knowledge.authority().is_same_as"),
            "{violations}"
        );

        let snapshot_escape = format!(
            "{item_source}\nfn snapshot_escape(knowledge: &KnowledgeBase, subject: &EntityId) {{ let _ = knowledge.snapshot_for_subject(subject); }}"
        );
        let violations = inspect_assessment_item_projection(&snapshot_escape)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("broad subject snapshots"),
            "{violations}"
        );

        for (field, replacement) in [
            ("status: OutcomeStatus,", "status: String,"),
            ("confidence: Probability,", "confidence: String,"),
            (
                "evidence_ids: BTreeSet<EvidenceId>,",
                "evidence_ids: Vec<EvidenceId>,",
            ),
        ] {
            let mutated = item_source.replacen(field, replacement, 1);
            assert_ne!(mutated, item_source, "stale identity mutation for {field}");
            let violations = inspect_assessment_item_projection(&mutated)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("subject-bound runtime identity"),
                "{violations}"
            );
        }

        let public_accessor = knowledge_source.replace(
            "pub(crate) fn authority(&self) -> &KnowledgeAuthority",
            "pub fn authority(&self) -> &KnowledgeAuthority",
        );
        assert_ne!(public_accessor, knowledge_source);
        let violations = inspect_knowledge_authority_accessor(&public_accessor)
            .unwrap()
            .join("\n");
        assert!(violations.contains("exact pub(crate)"), "{violations}");

        let cloned_accessor =
            knowledge_source.replace("&self.authority\n    }", "&self.authority.clone()\n    }");
        assert_ne!(cloned_accessor, knowledge_source);
        let violations = inspect_knowledge_authority_accessor(&cloned_accessor)
            .unwrap()
            .join("\n");
        assert!(violations.contains("exact pub(crate)"), "{violations}");

        let value_comparison =
            knowledge_source.replacen("Arc::ptr_eq(&self.0, &other.0)", "self.0 == other.0", 1);
        assert_ne!(value_comparison, knowledge_source);
        let violations = inspect_knowledge_authority_accessor(&value_comparison)
            .unwrap()
            .join("\n");
        assert!(violations.contains("Arc identity"), "{violations}");
    }

    #[test]
    fn assessment_item_set_and_report_consumption_are_closed() {
        let item_source =
            include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_item.rs");
        let report_source =
            include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_report.rs");

        let live_violations = inspect_assessment_report_boundary(report_source)
            .unwrap()
            .join("\n");
        assert!(live_violations.is_empty(), "{live_violations}");

        let cloneable_set = item_source.replacen(
            "pub(crate) struct AssessmentItemSet {",
            "#[derive(Clone)]\npub(crate) struct AssessmentItemSet {",
            1,
        );
        assert_ne!(cloneable_set, item_source);
        let violations = inspect_assessment_item_projection(&cloneable_set)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("AssessmentItemSet must not be Clone"),
            "{violations}"
        );

        let raw_append = item_source.replacen(
            "impl AssessmentItemSet {",
            "impl AssessmentItemSet {\n    pub(crate) fn append(&mut self, mut items: Vec<AssessmentItem>) { self.items.append(&mut items); }",
            1,
        );
        assert_ne!(raw_append, item_source);
        let violations = inspect_assessment_item_projection(&raw_append)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("no raw constructor, append, or merge"),
            "{violations}"
        );

        let borrowed_finish = item_source.replacen(
            "pub(crate) fn finish(self) -> AssessmentItemSet",
            "pub(crate) fn finish(&self) -> AssessmentItemSet",
            1,
        );
        assert_ne!(borrowed_finish, item_source);
        let violations = inspect_assessment_item_projection(&borrowed_finish)
            .unwrap()
            .join("\n");
        assert!(violations.contains("finish must consume"), "{violations}");

        for weakened in [
            item_source.replacen(
                "StableAssessmentSubjectId::new(stable_identity)",
                "Ok(StableAssessmentSubjectId(stable_identity.to_owned()))",
                1,
            ),
            item_source.replacen(
                "subject.reference() == AssessmentSubjectReference::new(0)",
                "true",
                1,
            ),
            item_source.replacen("subject.fingerprint() == expected", "true", 1),
        ] {
            assert_ne!(weakened, item_source);
            let violations = inspect_assessment_item_projection(&weakened)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("contains_only_stable_subject"),
                "{violations}"
            );
        }

        let raw_report_items = report_source.replacen(
            "items: AssessmentItemSet,",
            "items: Vec<AssessmentItem>,",
            1,
        );
        assert_ne!(raw_report_items, report_source);
        let violations = inspect_assessment_report_boundary(&raw_report_items)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("from_completed_truth must consume only AssessmentItemSet"),
            "{violations}"
        );

        let caller_supplied_run = report_source.replacen(
            "pub(crate) fn from_completed_truth(\n        items: AssessmentItemSet,",
            "pub(crate) fn from_completed_truth(\n        run_report: RunReport,\n        items: AssessmentItemSet,",
            1,
        );
        assert_ne!(caller_supplied_run, report_source);
        let violations = inspect_assessment_report_boundary(&caller_supplied_run)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("caller-supplied RunReport input"),
            "{violations}"
        );

        for widened in [
            report_source.replacen("#[cfg(test)]\n    fn new(", "pub(crate) fn new(", 1),
            report_source.replacen(
                "    fn new_validated(\n",
                "    pub(crate) fn new_validated(\n",
                1,
            ),
        ] {
            assert_ne!(widened, report_source);
            let violations = inspect_assessment_report_boundary(&widened)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("caller-supplied RunReport input"),
                "{violations}"
            );
        }

        let ambient_truth_clock = report_source.replacen(
            "            run_started_at,",
            "            run_started_at: SystemTime::now(),",
            1,
        );
        assert_ne!(ambient_truth_clock, report_source);
        let violations = inspect_assessment_report_boundary(&ambient_truth_clock)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("accept the runtime-owned start"),
            "{violations}"
        );

        for (original, replacement) in [
            (
                "        let run_report = build_run_report(&truth)?;",
                "        let run_report = forged_run_report();",
            ),
            (
                "truth.expected_accounting.clone()",
                "RunAccounting::default()",
            ),
            (
                ".with_outcomes(Vec::new())",
                ".with_outcomes(vec![forged_outcome()])",
            ),
            (
                "    let completed_at = truth\n        .run_started_at",
                "    let completed_at = SystemTime::now()",
            ),
        ] {
            let weakened = report_source.replacen(original, replacement, 1);
            assert_ne!(
                weakened, report_source,
                "stale runtime-owned mutation: {original}"
            );
            let violations = inspect_assessment_report_boundary(&weakened)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("runtime-owned") || violations.contains("build_run_report"),
                "{violations}"
            );
        }

        let unbound_scope = report_source.replacen(
            "if !items.matches_exact_origin(run_report.authorized_origin()) {",
            "if false {",
            1,
        );
        assert_ne!(unbound_scope, report_source);
        let violations = inspect_assessment_report_boundary(&unbound_scope)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("validate run identity/completion/accounting"),
            "{violations}"
        );

        for (original, replacement) in [
            (
                "validate_run_completion(&run_report)?;",
                "let _ = &run_report;",
            ),
            (
                "validate_run_accounting(\n            &run_report,\n            &truth.expected_accounting,\n            truth.expected_elapsed_ms,\n        )?;",
                "let _ = (&truth.expected_accounting, truth.expected_elapsed_ms);",
            ),
            (
                "contains_only_stable_subject(\"authorized-root@1\")",
                "contains_only_stable_subject(\"caller-selected-root\")",
            ),
        ] {
            let weakened = report_source.replacen(original, replacement, 1);
            assert_ne!(weakened, report_source, "stale report mutation: {original}");
            let violations = inspect_assessment_report_boundary(&weakened)
                .unwrap()
                .join("\n");
            assert!(
                violations.contains("validate run identity/completion/accounting"),
                "{violations}"
            );
        }

        for (original, replacement, expected) in [
            (
                "run_report.outcomes().is_empty()",
                "true",
                "completion validator",
            ),
            (
                "elapsed.subsec_nanos().rem_euclid(1_000_000) != 0",
                "false",
                "accounting validator",
            ),
            ("step.detail().is_some()", "false", "accounting validator"),
            (
                "profile.web_assessment_limits() != limits",
                "false",
                "completed assessment truth validator",
            ),
            (
                "authorized_root.origin() != WebAssessmentSubjectOrigin::AuthorizedRoot",
                "false",
                "completed assessment truth validator",
            ),
            (
                "usage.executed_subjects != usage.retained_subjects",
                "false",
                "completed assessment truth validator",
            ),
            (
                "subject.reference().ordinal() != u32::try_from(ordinal).unwrap_or(u32::MAX)",
                "false",
                "inventory validator",
            ),
        ] {
            let weakened = report_source.replacen(original, replacement, 1);
            assert_ne!(
                weakened, report_source,
                "stale validator mutation: {original}"
            );
            let violations = inspect_assessment_report_boundary(&weakened)
                .unwrap()
                .join("\n");
            assert!(violations.contains(expected), "{violations}");
        }

        let postconstruction_count = report_source.replacen(
            "validate_item_count(items.len())?;\n    validate_profile_item_count(profile, items.len())?;\n    canonicalize_items(items)",
            "let result = canonicalize_items(items);\n    validate_item_count(items.len())?;\n    validate_profile_item_count(profile, items.len())?;\n    result",
            1,
        );
        assert_ne!(postconstruction_count, report_source);
        let violations = inspect_assessment_report_boundary(&postconstruction_count)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("ceilings must be validated before"),
            "{violations}"
        );
    }

    #[test]
    fn assessment_projection_preflight_and_confirmed_confidence_order_are_pinned() {
        let item_source =
            include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_item.rs");

        let late_outcome_preflight = item_source
            .replacen(
                "        preflight_ordered_evidence_ids(outcome.evidence_ids())?;\n        validate_outcome_identity(outcome)?;",
                "        validate_outcome_identity(outcome)?;",
                1,
            )
            .replacen(
                "        let identity = RuntimeOutcomeIdentity::from_outcome(outcome);",
                "        let identity = RuntimeOutcomeIdentity::from_outcome(outcome);\n        preflight_ordered_evidence_ids(outcome.evidence_ids())?;",
                1,
            );
        assert_ne!(late_outcome_preflight, item_source);
        let violations = inspect_assessment_item_projection(&late_outcome_preflight)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("register_outcome must preflight"),
            "{violations}"
        );

        let late_verifier_preflight = item_source.replacen(
            "        preflight_ordered_evidence_ids(outcome.evidence_ids())?;\n        let extraction = extract_confirmation_proof(capability, receipt, decision, knowledge);",
            "        let extraction = extract_confirmation_proof(capability, receipt, decision, knowledge);\n        preflight_ordered_evidence_ids(outcome.evidence_ids())?;",
            1,
        );
        assert_ne!(late_verifier_preflight, item_source);
        let violations = inspect_assessment_item_projection(&late_verifier_preflight)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("verifier projection must preflight"),
            "{violations}"
        );

        let late_item_ceiling = item_source.replacen(
            "        check_projection_limit(\"items\", self.items.len(), MAX_ASSESSMENT_ITEM_SET_ITEMS)?;\n        let item = AssessmentItem::from_observation(",
            "        let item = AssessmentItem::from_observation(",
            1,
        ).replacen(
            "        self.push_item(item);",
            "        check_projection_limit(\"items\", self.items.len(), MAX_ASSESSMENT_ITEM_SET_ITEMS)?;\n        self.push_item(item);",
            1,
        );
        assert_ne!(late_item_ceiling, item_source);
        let violations = inspect_assessment_item_projection(&late_item_ceiling)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("project_observation must enforce"),
            "{violations}"
        );

        let inflated_confidence = item_source.replacen(
            ".min(outcome.confidence());",
            ".max(outcome.confidence());",
            1,
        );
        assert_ne!(inflated_confidence, item_source);
        let violations = inspect_assessment_item_projection(&inflated_confidence)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("Confirmed confidence must be the minimum"),
            "{violations}"
        );

        let credential_tolerant_scope = item_source.replacen(
            "            || url.password().is_some()",
            "            || false",
            1,
        );
        assert_ne!(credential_tolerant_scope, item_source);
        let violations = inspect_assessment_item_projection(&credential_tolerant_scope)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("canonical credential-free"),
            "{violations}"
        );
    }

    #[test]
    fn assessment_cross_source_impl_and_production_descriptor_bypasses_are_rejected() {
        for (name, source, expected) in [
            (
                "clone",
                "impl Clone for AssessmentItem { fn clone(&self) -> Self { todo!() } }",
                "forbidden trait Clone",
            ),
            (
                "serde",
                "impl Serialize for AssessmentObservationBasis {}",
                "forbidden trait Serialize",
            ),
            (
                "inherent",
                "impl AssessmentProjectionContext { fn merge(&mut self) {} }",
                "external inherent impl",
            ),
            (
                "aliased",
                "use crate::AssessmentItem as ProductItem; use serde::Serialize as Wire; impl Wire for ProductItem {}",
                "forbidden trait Wire",
            ),
            (
                "macro",
                "macro_rules! escape { () => { impl Clone for AssessmentItem {} } }",
                "inside a macro",
            ),
        ] {
            let syntax = syn::parse_file(source).unwrap();
            let violations = inspect_external_assessment_impls("external.rs", &syntax).join("\n");
            assert!(
                violations.contains(expected),
                "missing {name} bypass rejection: {violations}"
            );
        }

        let informational = syn::parse_file(
            "const SAFE: AssessmentCapabilityDescriptor = AssessmentCapabilityDescriptor::informational();",
        )
        .unwrap();
        assert!(
            inspect_production_verifier_descriptors("safe.rs", &informational, false).is_empty()
        );

        let verifier = syn::parse_file(
            "const BAD: AssessmentCapabilityDescriptor = build(AssessmentClaimPolicy::VerifierTransition(policy));",
        )
        .unwrap();
        let violations =
            inspect_production_verifier_descriptors("bad.rs", &verifier, false).join("\n");
        assert!(
            violations.contains("VerifierTransition descriptors remain test-only"),
            "{violations}"
        );

        let test_only = syn::parse_file(
            "#[cfg(test)] const OK_IN_TEST: AssessmentCapabilityDescriptor = build(AssessmentClaimPolicy::VerifierTransition(policy));",
        )
        .unwrap();
        assert!(inspect_production_verifier_descriptors("test.rs", &test_only, false).is_empty());
        assert!(inspect_production_verifier_descriptors("any.rs", &verifier, true).is_empty());
    }

    #[test]
    fn assessment_models_keep_fields_private_without_serde_or_nested_audits() {
        let valid = r#"
            pub struct WebAssessmentSubjectReport { subject: String }
            pub struct WebAssessmentDefenseAudit { mode: String }
            pub struct WebAssessmentRunReport {
                #[cfg(feature = "reporting")]
                run_started_at: SystemTime,
                transport: TransportDispatchAudit,
                defense: WebAssessmentDefenseAudit,
            }
            pub struct WebAssessmentFailureReceipt { transport: TransportDispatchAudit, defense: WebAssessmentDefenseAudit }
            struct WebAssessmentRuntime { defense_audit: WebAssessmentDefenseAudit }
        "#;
        assert!(inspect_web_assessment_models(valid).unwrap().is_empty());

        let public_field = valid.replace("subject: String", "pub subject: String");
        let violations = inspect_web_assessment_models(&public_field)
            .unwrap()
            .join("\n");
        assert!(violations.contains("exposes fields"), "{violations}");

        let serde = valid.replace(
            "pub struct WebAssessmentSubjectReport",
            "#[derive(Serialize)] pub struct WebAssessmentSubjectReport",
        );
        let violations = inspect_web_assessment_models(&serde).unwrap().join("\n");
        assert!(violations.contains("serde wire contract"), "{violations}");

        let nested_audit = valid.replace(
            "subject: String",
            "subject: String, transport: TransportDispatchAudit",
        );
        let violations = inspect_web_assessment_models(&nested_audit)
            .unwrap()
            .join("\n");
        assert!(violations.contains("subject-local"), "{violations}");
        assert!(violations.contains("ownership drifted"), "{violations}");

        let nested_defense = valid.replace(
            "subject: String",
            "subject: String, defense: WebAssessmentDefenseAudit",
        );
        let violations = inspect_web_assessment_models(&nested_defense)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("defense audit ownership drifted"),
            "{violations}"
        );
    }

    #[test]
    fn sealed_observer_and_eof_header_redirect_markers_are_mutation_locked() {
        let seam = include_str!("../../../crates/venom-scanner/src/http_evidence.rs");
        assert!(inspect_complete_observer_seam(seam).unwrap().is_empty());
        let broadened = seam.replace(
            "impl Sealed for crate::web_runtime::AssessmentDiscoveryObserver {}",
            "impl Sealed for crate::web_runtime::AssessmentDiscoveryObserver {} impl Sealed for Other {}",
        );
        assert!(inspect_complete_observer_seam(&broadened)
            .unwrap()
            .join("\n")
            .contains("exactly AssessmentDiscoveryObserver"));

        let owned_body = seam.replace("complete_body: Option<&'a [u8]>", "complete_body: Vec<u8>");
        let violations = inspect_complete_observer_seam(&owned_body)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("non-cloneable borrowed"),
            "{violations}"
        );
        let clonable = seam.replace(
            "pub(crate) struct CompleteHttpResponseObservation<'a>",
            "#[derive(Clone, Debug)] pub(crate) struct CompleteHttpResponseObservation<'a>",
        );
        let violations = inspect_complete_observer_seam(&clonable)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("non-cloneable borrowed"),
            "{violations}"
        );
        let raw_header = seam.replace(
            "complete_body: Option<&'a [u8]>",
            "complete_body: Option<&'a [u8]>, raw_headers: HeaderMap",
        );
        let violations = inspect_complete_observer_seam(&raw_header)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("non-cloneable borrowed"),
            "{violations}"
        );
        let mutable_body = seam.replace(
            "complete_body: Option<&'a [u8]>",
            "complete_body: Option<&'a mut [u8]>",
        );
        let violations = inspect_complete_observer_seam(&mutable_body)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("non-cloneable borrowed"),
            "{violations}"
        );
        let borrowed_raw_media = seam.replace(
            "media_type: Option<&'a str>",
            "media_type: Option<&'a [u8]>",
        );
        let violations = inspect_complete_observer_seam(&borrowed_raw_media)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("non-cloneable borrowed"),
            "{violations}"
        );
        let public_accessor = seam.replace(
            "impl CompleteHttpResponseObservation<'_> {",
            "impl CompleteHttpResponseObservation<'_> { pub fn raw_body(&self) -> &[u8] { &[] }",
        );
        let violations = inspect_complete_observer_seam(&public_accessor)
            .unwrap()
            .join("\n");
        assert!(violations.contains("accessor allowlist"), "{violations}");
        let manual_clone = format!(
            "{seam}\nimpl<'a> Clone for CompleteHttpResponseObservation<'a> {{ fn clone(&self) -> Self {{ unreachable!() }} }}"
        );
        let violations = inspect_complete_observer_seam(&manual_clone)
            .unwrap()
            .join("\n");
        assert!(violations.contains("must not implement"), "{violations}");

        let http = seam.to_owned();
        let broker =
            include_str!("../../../crates/venom-scanner/src/http_evidence/request_broker.rs");
        assert!(inspect_assessment_transport_markers(&http, broker).is_empty());
        for (mutated_http, mutated_broker, needle) in [
            (
                http.replace("restricted.captured_headers.clear();", ""),
                broker.to_owned(),
                "clear every raw captured",
            ),
            (
                http.clone(),
                broker.replace("body_complete = true;", ""),
                "observed response-stream EOF",
            ),
            (
                http,
                broker.replace(".redirect(RedirectPolicy::none())", ""),
                "redirect-disabled",
            ),
        ] {
            let violations =
                inspect_assessment_transport_markers(&mutated_http, &mutated_broker).join("\n");
            assert!(violations.contains(needle), "{violations}");
        }
    }
}
