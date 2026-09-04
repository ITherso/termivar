//! Exact architecture contract for the bounded SSRF OAST query review.
//!
//! The review is one non-default child of `WebAssessmentRuntime`: target
//! traffic stays on the parent broker, provider traffic stays behind the
//! single narrowing native-provider mint, and only the full repeated-callback
//! relation may project one knowledge-only review item.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use syn::{Fields, Item, Visibility};

const SCANNER_MANIFEST: &str = "crates/termivar-scanner/Cargo.toml";
const CLI_MANIFEST: &str = "crates/termivar-cli/Cargo.toml";
const CLI_MAIN: &str = "crates/termivar-cli/src/main.rs";
const CLI_AUTH_INPUT: &str = "crates/termivar-cli/src/auth_input.rs";
const CLI_ASSESSMENT_SCAN: &str = "crates/termivar-cli/src/assessment_scan.rs";
const SCANNER_LIBRARY: &str = "crates/termivar-scanner/src/lib.rs";
const SCANNER_SOURCE_ROOT: &str = "crates/termivar-scanner/src";
const DOMAIN_SOURCE: &str = "crates/termivar-scanner/src/ssrf_oast_review.rs";
const RUNTIME_ROOT_SOURCE: &str = "crates/termivar-scanner/src/web_runtime.rs";
const RUNTIME_SOURCE: &str = "crates/termivar-scanner/src/web_runtime/ssrf_oast_runtime.rs";
const AUTHORITY_SOURCE: &str = "crates/termivar-scanner/src/web_runtime/authority.rs";
const ACTION_SOURCE: &str = "crates/termivar-scanner/src/web_actions/native_review.rs";
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const TESTS_WORKFLOW: &str = ".github/workflows/tests.yml";
const COVERAGE_BASELINE_POINTER: &str = "docs/reports/coverage/accepted-baseline.txt";

const SCANNER_FEATURE: &str = "ssrf-oast-review";
const EXACT_SCANNER_FEATURE_MEMBERS: &[&str] = &[
    "dep:getrandom",
    "oast-correlation",
    "oast-native-provider",
    "scanning",
];
const EXACT_CLI_FEATURE_MEMBERS: &[&str] = &["termivar-scanner/ssrf-oast-review"];
const AGGREGATE_FEATURES: &[&str] = &["default", "enterprise", "full", "minimal", "research"];

const EXPECTED_AUDIT_FIELDS: &[&str] = &[
    "active_verification_count",
    "candidate_callback_observed",
    "candidate_source",
    "cleanup_verified",
    "item_projected",
    "outcome",
    "policy_id",
    "preflight_clean",
    "provider_request_count",
    "replay_callback_observed",
    "target_request_count",
];

const PUBLIC_PROVIDER_LITERALS: &[&str] = &[
    "burpcollaborator",
    "canarytokens",
    "dnslog.cn",
    "interact.sh",
    "interactsh",
    "oastify",
    "requestbin",
    "webhook.site",
];

const INTERNAL_DESTINATION_LITERALS: &[&str] = &[
    "127.0.0.1",
    "169.254.169.254",
    "::1",
    "localhost",
    "metadata.google.internal",
];

const GATES: &[(u8, &str)] = &[
    (1, "feature non-default"),
    (2, "absent from release-bundle"),
    (3, "explicit web-review"),
    (4, "explicit policy"),
    (5, "exact target-origin match"),
    (6, "exact provider HTTPS origin"),
    (7, "provider differs from target origin"),
    (8, "no public provider default"),
    (9, "one WebAssessmentRuntime"),
    (10, "one target broker"),
    (11, "one parent budget"),
    (12, "one narrowing provider authority"),
    (13, "maximum one resource"),
    (14, "maximum one query parameter"),
    (15, "exactly three target requests"),
    (16, "maximum twelve provider requests"),
    (17, "one active verification"),
    (18, "GET only"),
    (19, "no target auth, cookie, or body"),
    (20, "no path, header, body, or cookie mutation"),
    (21, "no internal or cloud payload"),
    (22, "no alternate scheme"),
    (23, "no redirects or retries"),
    (24, "no background task"),
    (25, ".invalid control"),
    (26, "distinct Candidate and Replay identities"),
    (27, "both callbacks required"),
    (28, "one-sided callback cannot create item"),
    (29, "maximum NeedsReview"),
    (30, "maximum KnowledgeOnly"),
    (31, "never Confirmed"),
    (32, "no severity"),
    (33, "one final report"),
    (34, "no legacy phase import"),
    (35, "no auto-chaining"),
    (36, "no raw callback, provider, or secret output"),
    (37, "no release or tag change"),
    (38, "every production Rust source in Cobertura"),
];

#[derive(Clone)]
struct ContractSources {
    scanner_manifest: String,
    cli_manifest: String,
    cli_main: String,
    cli_auth_input: String,
    cli_assessment_scan: String,
    scanner_library: String,
    domain: String,
    runtime_root: String,
    runtime: String,
    authority: String,
    action: String,
    release_workflow: String,
    tests_workflow: String,
    coverage_baseline: String,
    scanner_sources: Vec<(String, String)>,
}

impl ContractSources {
    fn load(workspace_root: &Path) -> Result<Self, Box<dyn Error>> {
        let scanner_sources = rust_sources_below(&workspace_root.join(SCANNER_SOURCE_ROOT))?
            .into_iter()
            .map(|path| {
                let relative =
                    normalized_relative(&workspace_root.join(SCANNER_SOURCE_ROOT), &path)?;
                let source = fs::read_to_string(path)?;
                Ok((relative, production_prefix(&source).to_owned()))
            })
            .collect::<Result<Vec<_>, io::Error>>()?;
        let baseline_pointer = fs::read_to_string(workspace_root.join(COVERAGE_BASELINE_POINTER))?;
        let baseline_path = checked_repository_path(workspace_root, baseline_pointer.trim())?;

        Ok(Self {
            scanner_manifest: read(workspace_root, SCANNER_MANIFEST)?,
            cli_manifest: read(workspace_root, CLI_MANIFEST)?,
            cli_main: read(workspace_root, CLI_MAIN)?,
            cli_auth_input: read(workspace_root, CLI_AUTH_INPUT)?,
            cli_assessment_scan: read(workspace_root, CLI_ASSESSMENT_SCAN)?,
            scanner_library: read(workspace_root, SCANNER_LIBRARY)?,
            domain: read(workspace_root, DOMAIN_SOURCE)?,
            runtime_root: read(workspace_root, RUNTIME_ROOT_SOURCE)?,
            runtime: read(workspace_root, RUNTIME_SOURCE)?,
            authority: read(workspace_root, AUTHORITY_SOURCE)?,
            action: read(workspace_root, ACTION_SOURCE)?,
            release_workflow: read(workspace_root, RELEASE_WORKFLOW)?,
            tests_workflow: read(workspace_root, TESTS_WORKFLOW)?,
            coverage_baseline: fs::read_to_string(baseline_path)?,
            scanner_sources,
        })
    }
}

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let sources = ContractSources::load(workspace_root)?;
    contract_violations(&sources)
}

fn contract_violations(sources: &ContractSources) -> Result<Vec<String>, Box<dyn Error>> {
    let scanner_features = manifest_features(&sources.scanner_manifest)?;
    let cli_features = manifest_features(&sources.cli_manifest)?;
    let domain = compact_whitespace(production_prefix(&sources.domain));
    let runtime = compact_whitespace(production_prefix(&sources.runtime));
    let runtime_root = compact_whitespace(production_prefix(&sources.runtime_root));
    let authority = compact_whitespace(production_prefix(&sources.authority));
    let action = compact_whitespace(production_prefix(&sources.action));
    let cli_main = compact_whitespace(production_prefix(&sources.cli_main));
    let cli_auth = compact_whitespace(production_prefix(&sources.cli_auth_input));
    let cli_scan = compact_whitespace(production_prefix(&sources.cli_assessment_scan));
    let combined_contract = format!("{domain}{runtime}{runtime_root}{action}");
    let mut result = Evaluation::default();

    let expected_scanner = string_set(EXACT_SCANNER_FEATURE_MEMBERS);
    let expected_cli = string_set(EXACT_CLI_FEATURE_MEMBERS);
    let feature_non_default = scanner_features.get(SCANNER_FEATURE) == Some(&expected_scanner)
        && cli_features.get(SCANNER_FEATURE) == Some(&expected_cli)
        && AGGREGATE_FEATURES.iter().all(|aggregate| {
            !feature_reaches(&scanner_features, aggregate, SCANNER_FEATURE)
                && !feature_reaches(&cli_features, aggregate, SCANNER_FEATURE)
        });
    result.require(
        1,
        feature_non_default,
        "scanner/CLI feature closure widened or became default",
    );

    let release_members = cli_features
        .get("release-bundle")
        .cloned()
        .unwrap_or_default();
    result.require(
        2,
        !feature_reaches(&cli_features, "release-bundle", SCANNER_FEATURE)
            && !release_members.contains(SCANNER_FEATURE)
            && !sources.release_workflow.contains(SCANNER_FEATURE),
        "SSRF OAST review entered the release bundle or release workflow",
    );

    result.require(
        3,
        cli_main.contains("fnscan_ssrf_oast_review_flags_conflict(")
            && cli_main
                .contains("ssrf_oast_review_enabled&&profile!=Some(CliScanProfile::WebReview)")
            && cli_main.contains("SSRFOASTqueryreviewrequires`--profileweb-review`"),
        "CLI preflight no longer requires an explicit web-review profile",
    );

    result.require(
        4,
        cli_main.contains("ssrf_oast_review:bool")
            && cli_main.contains("ssrf_oast_policy:Option<PathBuf>")
            && cli_main.contains("requires_all=[\"profile\",\"ssrf_oast_policy\"]")
            && cli_main.contains("requires_all=[\"profile\",\"ssrf_oast_review\"]")
            && cli_main.contains("requires=\"ssrf_oast_policy\"")
            && cli_auth.contains(
                "letpolicy_file=policy_file.ok_or(SsrfOastReviewInputError::MissingPolicy)?",
            )
            && cli_auth.contains("MissingAdministratorSource")
            && !cli_main.contains("oast_admin_token:Option"),
        "policy or exactly-one administrator-token source is no longer explicit",
    );

    result.require(
        5,
        domain.contains("letassessment_origin=canonical_target_origin(assessment_target)")
            && domain.contains("if!same_origin(&assessment_origin,&target_origin)")
            && domain.contains("TargetOriginMismatch"),
        "policy parsing no longer binds the declaration to the assessment exact origin",
    );

    result.require(
        6,
        domain.contains("letprovider_origin=PublicOrigin::from_str(&wire.provider_origin)")
            && domain.contains(
                "parsed.scheme()==\"https\"||(allow_test_loopback&&is_http_loopback_origin(&parsed))",
            )
            && domain.contains("!same_origin(&parsed,&provider)")
            && domain.matches("provider_origin,false,").count() == 1
            && domain.matches("provider_origin,true,").count() == 1
            && domain.contains("#[cfg(test)]pub(crate)fnnew_for_loopback(")
            && domain.contains("if!is_http_loopback_origin(&provider)"),
        "provider or callback authority is no longer one exact HTTPS origin",
    );

    result.require(
        7,
        domain.contains("ifsame_origin(&target_origin,&provider_url)")
            && domain.contains("ProviderOriginMatchesTarget"),
        "provider and target origins may coincide",
    );

    let provider_defaults_absent = PUBLIC_PROVIDER_LITERALS.iter().all(|literal| {
        !production_prefix(&sources.domain)
            .to_ascii_lowercase()
            .contains(literal)
            && !production_prefix(&sources.runtime)
                .to_ascii_lowercase()
                .contains(literal)
    });
    result.require(
        8,
        provider_defaults_absent,
        "a public OAST provider literal became a default",
    );

    let runtime_declarations = sources
        .scanner_sources
        .iter()
        .map(|(_, source)| {
            compact_whitespace(source)
                .matches("pubstructWebAssessmentRuntime{")
                .count()
        })
        .sum::<usize>();
    result.require(
        9,
        runtime_declarations == 1
            && runtime_root.contains("modssrf_oast_runtime;")
            && !combined_contract.contains("structSsrfOastRuntime{"),
        "the review no longer composes through the sole WebAssessmentRuntime",
    );

    result.require(
        10,
        runtime
            .matches("authority.requests().collect_for_runtime(")
            .count()
            == 1
            && runtime.contains("SSRF_OAST_REVIEW_ACTION_ID")
            && !runtime.contains("HttpRequestBroker::new(")
            && !runtime.contains("reqwest::"),
        "target traffic is not confined to the one parent request broker",
    );

    result.require(
        11,
        runtime.contains("SharedWebRuntimeAuthority")
            && runtime.contains("self.authority.cancellation()")
            && !runtime.contains("RuntimeBudget::")
            && !runtime.contains("RequestAccounting::new("),
        "the review owns budget, accounting, or cancellation state outside the parent",
    );

    let mint_callers = sources
        .scanner_sources
        .iter()
        .filter_map(|(path, source)| {
            source
                .contains(".mint_native_oast_provider(")
                .then_some(path.as_str())
        })
        .collect::<Vec<_>>();
    result.require(
        12,
        mint_callers == ["web_runtime/ssrf_oast_runtime.rs"]
            && runtime.matches(".mint_native_oast_provider(").count() == 1
            && authority.contains("NativeOastProviderAdapter::mint("),
        "native-provider authority is not minted exactly once by the SSRF child through shared authority",
    );

    result.require(
        13,
        domain.contains("MAX_SSRF_OAST_REVIEW_RESOURCES:usize=1;")
            && runtime.contains("MAX_SSRF_OAST_REVIEW_RESOURCES:usize=1;"),
        "resource ceiling is not exactly one",
    );

    result.require(
        14,
        domain.contains("MAX_SSRF_OAST_REVIEW_PARAMETERS:usize=1;")
            && runtime.contains("MAX_SSRF_OAST_REVIEW_PARAMETERS:usize=1;")
            && action.contains(
                "Self::SsrfOastQueryReview=>NativeWebReviewDifferentialInput::SingleQueryParameter",
            ),
        "query-parameter ceiling or differential surface widened",
    );

    result.require(
        15,
        domain.contains("SSRF_OAST_TARGET_REQUESTS:usize=3;")
            && runtime.contains("MAX_SSRF_OAST_REVIEW_REQUESTS:usize=SSRF_OAST_TARGET_REQUESTS;")
            && runtime.matches("collect_target(&self.authority,").count() == 3
            && runtime.contains("receipts.len()<=SSRF_OAST_TARGET_REQUESTS"),
        "target plan is not exactly Control, Candidate, Replay through three requests",
    );

    result.require(
        16,
        domain.contains("MAX_SSRF_OAST_PROVIDER_REQUESTS:usize=12;")
            && runtime.contains(
                "MAX_SSRF_OAST_REVIEW_PROVIDER_REQUESTS:usize=MAX_SSRF_OAST_PROVIDER_REQUESTS;",
            )
            && runtime.contains("constMAX_POST_DISPATCH_POLLS:u16=7;")
            && runtime.contains(
                "NativeOastProviderLimits::new(1,2,u16::try_from(MAX_SSRF_OAST_PROVIDER_REQUESTS)",
            ),
        "provider schedule exceeds or no longer pins the twelve-request ceiling",
    );

    result.require(
        17,
        domain.contains("SSRF_OAST_ACTIVE_VERIFICATIONS:usize=1;")
            && runtime.contains(
                "MAX_SSRF_OAST_REVIEW_ACTIVE_VERIFICATIONS:usize=SSRF_OAST_ACTIVE_VERIFICATIONS;",
            )
            && runtime.contains("SSRF_OAST_REVIEW_ACTION_CYCLE_ALLOWANCE:u32=1;"),
        "logical active-verification ceiling is not one",
    );

    result.require(
        18,
        runtime.matches("HttpProbeMethod::Get").count() == 1
            && !runtime.contains("HttpProbeMethod::Post")
            && !runtime.contains("HttpProbeMethod::Put")
            && !runtime.contains("HttpProbeMethod::Patch")
            && !runtime.contains("HttpProbeMethod::Delete"),
        "target request method is not fixed to GET",
    );

    result.require(
        19,
        runtime.contains("letprobe=HttpProbe::new(url.clone(),HttpProbeMethod::Get)")
            && !runtime.contains(".with_header(")
            && !runtime.contains(".with_body(")
            && !runtime.contains("Authorization")
            && !runtime.contains("Cookie"),
        "target probe acquired authentication, cookie, header, or body authority",
    );

    result.require(
        20,
        domain.contains("target.set_query(Some(&query));")
            && domain.contains("selected.execution_resource.path()!=control.path()")
            && domain.contains("selected.execution_resource.path()!=candidate.path()")
            && domain.contains("selected.execution_resource.path()!=replay.path()")
            && !runtime.contains("set_path(")
            && !runtime.contains("set_fragment(")
            && !runtime.contains("with_header(")
            && !runtime.contains("with_body("),
        "mutation is no longer confined to one query occurrence",
    );

    let internal_payload_absent = INTERNAL_DESTINATION_LITERALS.iter().all(|literal| {
        !production_prefix(&sources.domain).contains(literal)
            && !production_prefix(&sources.runtime).contains(literal)
    });
    result.require(
        21,
        internal_payload_absent,
        "an internal/cloud destination literal entered production review code",
    );

    result.require(
        22,
        domain.contains(
            "parsed.scheme()==\"https\"||(allow_test_loopback&&is_http_loopback_origin(&parsed))",
        )
            && domain.contains(
                "Self::from_callback_strings_inner(selected,control_seed,candidate_target,replay_target,provider_origin,false,)",
            )
            && domain.matches("provider_origin,true,").count() == 1
            && domain.contains("Url::parse(&format!(\"https://c-{label}.invalid/\"))")
            && !runtime.contains("HttpProbeMethod::Connect"),
        "control/callback construction permits an alternate scheme",
    );

    result.require(
        23,
        runtime.contains("(300..400).contains(&response.status())")
            && !runtime.contains("redirect::")
            && !runtime.contains("retry")
            && !runtime.contains("backoff"),
        "redirect or retry behavior entered the SSRF child",
    );

    result.require(
        24,
        !combined_contract.contains("tokio::spawn")
            && !combined_contract.contains("spawn_blocking")
            && !combined_contract.contains("std::thread::spawn")
            && !combined_contract.contains("thread::spawn"),
        "background work entered the bounded review",
    );

    result.require(
        25,
        domain.contains("Url::parse(&format!(\"https://c-{label}.invalid/\"))")
            && domain.contains("CONTROL_LABEL_DOMAIN")
            && domain.contains("letcontrol=selected.control_execution_url(control_seed)?;"),
        "control no longer uses one case-derived .invalid URL",
    );

    result.require(
        26,
        domain.contains("ifcandidate_target==replay_target")
            && domain.contains("entropy.candidate==entropy.replay")
            && domain.contains("ifcandidate_bytes==replay_bytes")
            && runtime.contains("callback_case(request,\"candidate\")")
            && runtime.contains("callback_case(request,\"replay\")"),
        "Candidate and Replay callback/correlation identities may coincide",
    );

    result.require(
        27,
        domain.contains("match(candidate_exact,replay_exact)")
            && domain.contains("(true,true)=>{}")
            && domain
                .matches(domain_suffix_for_repeated_callbacks())
                .count()
                == 1,
        "positive classification no longer requires both exact callbacks",
    );

    result.require(
        28,
        domain.contains("(true,false)=>returnOk(SsrfOastReviewOutcome::CandidateOnly)")
            && domain.contains("(false,true)=>returnOk(SsrfOastReviewOutcome::ReplayOnly)")
            && domain.contains("matches!(self,Self::RepeatedCallbacksObserved)"),
        "a one-sided callback may project the item",
    );

    result.require(
        29,
        runtime.contains("AssessmentCapabilityDescriptor::differential_review(")
            && runtime.contains("SSRF_OAST_REVIEW_CAPABILITY_ID")
            && runtime.contains("Repeatedout-of-bandinteractionobserved"),
        "item authority is no longer capped by the differential-review constructor",
    );

    result.require(
        30,
        action.contains("Self::SsrfOastQueryReview=>\"web.review.ssrf.oast-query@1\"")
            && action.contains("pubconstfnverification_target(self)->VerificationTarget")
            && action.contains("VerificationTarget::KnowledgeOnly"),
        "action verification authority is no longer KnowledgeOnly",
    );

    result.require(
        31,
        runtime.contains("request.case().applies_hypothesis_transition()")
            && runtime.contains("AssessmentCapabilityDescriptor::differential_review(")
            && !runtime.contains("AssessmentCapabilityDescriptor::verifier(")
            && !runtime.contains("AssessmentDisposition::Confirmed"),
        "the review can enter a Confirmed transition",
    );

    result.require(
        32,
        runtime.contains("Some(\"CWE-918\"),")
            && runtime.contains("\"Twoindependentlyallocatedcallbacktargets")
            && runtime.contains(",None,1_000_000,Some(\"CWE-918\")"),
        "the SSRF review item acquired severity",
    );

    result.require(
        33,
        runtime.contains("pubstructWebAssessmentSsrfOastAudit{")
            && !runtime.contains("structSsrfOastReport")
            && !runtime.contains("finish_report(")
            && !runtime.contains("finalize_report(")
            && runtime_root.matches("ssrf_oast_review:").count() >= 2,
        "the child owns a detached report or is not consumed by the composed runtime",
    );

    result.require(
        34,
        !combined_contract.contains("legacy_scanner")
            && !combined_contract.contains("crate::phases")
            && !combined_contract.contains("post_exploitation"),
        "legacy or post-exploitation code entered the modern review",
    );

    result.require(
        35,
        !runtime.contains("SqlStructural")
            && !runtime.contains("SstiStructural")
            && !runtime.contains("XssStructural")
            && !runtime.contains("ResourceAuthorizationDifferential")
            && !runtime.contains("RestReadOnlyReplay")
            && runtime.contains("request.case().payload_strategy().is_some()")
            && runtime.contains("request.case().applies_hypothesis_transition()"),
        "the SSRF child chains into another vulnerability family or payload strategy",
    );

    let audit_fields = exact_private_struct_fields(&sources.runtime, "WebAssessmentSsrfOastAudit")?;
    let expected_audit_fields = string_set(EXPECTED_AUDIT_FIELDS);
    result.require(
        36,
        audit_fields.as_ref() == Some(&expected_audit_fields)
            && !expected_audit_fields.iter().any(|field| {
                matches!(
                    field.as_str(),
                    "target_url"
                        | "query_value"
                        | "provider_origin"
                        | "callback_url"
                        | "callback_id"
                        | "event_id"
                        | "admin_token"
                        | "body"
                        | "headers"
                        | "timestamp"
                )
            })
            && runtime.contains("SsrfOastReviewConfig(<redacted>)")
            && domain.contains("SsrfOastAdminToken(<redacted>)")
            && domain.contains("SsrfOastCorrelationMaterial(<redacted>)"),
        "audit or debug surface exposes raw target/provider/callback/secret data",
    );

    result.require(
        37,
        !sources.release_workflow.contains(SCANNER_FEATURE)
            && !sources.release_workflow.contains("termivar-oast-provider")
            && !sources
                .cli_manifest
                .contains("[[bin]]\nname = \"termivar-oast-provider\"")
            && cli_scan.contains("builder=builder.with_ssrf_oast_review(policy,administrator);")
            && !cli_scan.contains("release"),
        "review wiring altered release/tag publication or introduced a provider release binary",
    );

    result.require(
        38,
        sources
            .tests_workflow
            .contains("cargo +1.88.0 tarpaulin --locked --workspace --all-features --ignore-tests")
            && sources
                .scanner_library
                .contains("#[cfg(feature = \"ssrf-oast-review\")]\npub mod ssrf_oast_review;")
            && sources
                .runtime_root
                .contains("#[cfg(feature = \"ssrf-oast-review\")]\nmod ssrf_oast_runtime;")
            && !sources.domain.contains("coverage(off)")
            && !sources.runtime.contains("coverage(off)")
            && !sources.coverage_baseline.contains(DOMAIN_SOURCE)
            && !sources.coverage_baseline.contains(RUNTIME_SOURCE),
        "new production sources are hidden, omitted, or absent from all-feature Cobertura input",
    );

    Ok(result.finish())
}

fn domain_suffix_for_repeated_callbacks() -> &'static str {
    "Ok(SsrfOastReviewOutcome::RepeatedCallbacksObserved)}"
}

#[derive(Default)]
struct Evaluation {
    evaluated: BTreeSet<u8>,
    violations: Vec<String>,
}

impl Evaluation {
    fn require(&mut self, number: u8, condition: bool, detail: &str) {
        if !self.evaluated.insert(number) {
            self.violations.push(format!(
                "[ssrf-oast gate {number}] gate was evaluated more than once"
            ));
        }
        if !condition {
            let name = GATES
                .iter()
                .find_map(|(candidate, name)| (*candidate == number).then_some(*name))
                .unwrap_or("unregistered gate");
            self.violations
                .push(format!("[ssrf-oast gate {number}: {name}] {detail}"));
        }
    }

    fn finish(mut self) -> Vec<String> {
        let expected = GATES
            .iter()
            .map(|(number, _)| *number)
            .collect::<BTreeSet<_>>();
        if self.evaluated != expected {
            self.violations.push(format!(
                "[ssrf-oast gates] exact gate inventory mismatch: expected {expected:?}, evaluated {:?}",
                self.evaluated
            ));
        }
        self.violations
    }
}

fn manifest_features(source: &str) -> Result<BTreeMap<String, BTreeSet<String>>, toml::de::Error> {
    let value = source.parse::<toml::Value>()?;
    Ok(value
        .get("features")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .map(|(name, value)| {
            let members = value
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .collect();
            (name.clone(), members)
        })
        .collect())
}

fn feature_reaches(
    features: &BTreeMap<String, BTreeSet<String>>,
    root: &str,
    sought: &str,
) -> bool {
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !visited.insert(feature.to_owned()) {
            continue;
        }
        let Some(members) = features.get(feature) else {
            continue;
        };
        for member in members {
            if member == sought {
                return true;
            }
            if features.contains_key(member) {
                pending.push(member);
            }
        }
    }
    false
}

fn exact_private_struct_fields(
    source: &str,
    name: &str,
) -> Result<Option<BTreeSet<String>>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let declarations = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(record) if record.ident == name => Some(record),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [record] = declarations.as_slice() else {
        return Ok(None);
    };
    if !matches!(record.fields, Fields::Named(_))
        || record
            .fields
            .iter()
            .any(|field| !matches!(field.vis, Visibility::Inherited))
    {
        return Ok(None);
    }
    Ok(Some(
        record
            .fields
            .iter()
            .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
            .collect(),
    ))
}

fn compact_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn production_prefix(source: &str) -> &str {
    source
        .rsplit_once("#[cfg(test)]")
        .map_or(source, |(production, _)| production)
}

fn string_set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn read(workspace_root: &Path, relative: &str) -> Result<String, io::Error> {
    fs::read_to_string(workspace_root.join(relative))
}

fn checked_repository_path(workspace_root: &Path, relative: &str) -> Result<PathBuf, io::Error> {
    let relative = Path::new(relative);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "coverage baseline pointer escapes the repository",
        ));
    }
    Ok(workspace_root.join(relative))
}

fn rust_sources_below(root: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut files = Vec::new();
    collect_rust_sources(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rust_sources(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), io::Error> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_rust_sources(&path, files)?;
        } else if metadata.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn normalized_relative(root: &Path, path: &Path) -> Result<String, io::Error> {
    path.strip_prefix(root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the workspace root")
            .to_path_buf()
    }

    fn current_sources() -> ContractSources {
        ContractSources::load(&workspace_root()).expect("load SSRF OAST architecture sources")
    }

    fn assert_gate_fails(sources: &ContractSources, number: u8) {
        let violations = contract_violations(sources).expect("evaluate SSRF OAST architecture");
        assert!(
            violations
                .iter()
                .any(|violation| violation.starts_with(&format!("[ssrf-oast gate {number}:"))),
            "gate {number} did not reject mutation: {violations:#?}"
        );
    }

    fn append_production(source: &str, addition: &str) -> String {
        source.rsplit_once("#[cfg(test)]").map_or_else(
            || format!("{source}\n{addition}\n"),
            |(production, tests)| format!("{production}\n{addition}\n#[cfg(test)]{tests}"),
        )
    }

    #[test]
    fn exact_gate_inventory_pins_all_thirty_eight_mission_boundaries() {
        assert_eq!(GATES.len(), 38);
        assert_eq!(
            GATES.iter().map(|(number, _)| *number).collect::<Vec<_>>(),
            (1_u8..=38).collect::<Vec<_>>()
        );
        assert_eq!(
            GATES
                .iter()
                .map(|(_, name)| *name)
                .collect::<BTreeSet<_>>()
                .len(),
            38
        );
    }

    #[test]
    fn current_workspace_satisfies_exact_ssrf_oast_contract() {
        let violations = contract_violations(&current_sources()).unwrap();
        assert!(
            violations.is_empty(),
            "SSRF OAST architecture violations: {violations:#?}"
        );
    }

    #[test]
    fn helper_contracts_fail_closed_for_ambiguous_shapes_and_paths() {
        let mut evaluation = Evaluation::default();
        evaluation.require(1, true, "first evaluation");
        evaluation.require(1, true, "duplicate evaluation");
        let violations = evaluation.finish();
        assert!(violations
            .iter()
            .any(|value| value.contains("evaluated more than once")));
        assert!(violations
            .iter()
            .any(|value| value.contains("exact gate inventory mismatch")));

        assert_eq!(
            exact_private_struct_fields("struct Audit { value: bool }", "Audit").unwrap(),
            Some(string_set(&["value"]))
        );
        assert_eq!(
            exact_private_struct_fields(
                "struct Audit { value: bool } struct Audit { other: bool }",
                "Audit"
            )
            .unwrap(),
            None
        );
        assert_eq!(
            exact_private_struct_fields("struct Audit { pub value: bool }", "Audit").unwrap(),
            None
        );

        let root = Path::new("workspace");
        let error = checked_repository_path(root, "../outside.json").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn feature_profile_policy_and_release_mutations_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.scanner_manifest = mutation.scanner_manifest.replace(
            "default = [\"core\", \"scanning\"]",
            "default = [\"core\", \"scanning\", \"ssrf-oast-review\"]",
        );
        assert_gate_fails(&mutation, 1);

        let mut mutation = sources.clone();
        mutation.cli_manifest = mutation.cli_manifest.replace(
            "release-bundle = [",
            "release-bundle = [\n    \"ssrf-oast-review\",",
        );
        assert_gate_fails(&mutation, 2);

        let mut mutation = sources.clone();
        mutation.cli_main = mutation.cli_main.replace(
            "profile != Some(CliScanProfile::WebReview)",
            "profile == Some(CliScanProfile::WebReview)",
        );
        assert_gate_fails(&mutation, 3);

        let mut mutation = sources;
        mutation.cli_auth_input = mutation.cli_auth_input.replace(
            ".ok_or(SsrfOastReviewInputError::MissingPolicy)?",
            ".expect(\"implicit policy\")",
        );
        assert_gate_fails(&mutation, 4);
    }

    #[test]
    fn origin_and_provider_authority_mutations_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.domain = mutation.domain.replace(
            "if !same_origin(&assessment_origin, &target_origin)",
            "if false",
        );
        assert_gate_fails(&mutation, 5);

        let mut mutation = sources.clone();
        mutation.domain = mutation.domain.replacen(
            "parsed.scheme() == \"https\"",
            "parsed.scheme() == \"ftp\"",
            1,
        );
        assert_ne!(mutation.domain, sources.domain);
        assert_gate_fails(&mutation, 6);

        let mut mutation = sources.clone();
        mutation.domain = mutation
            .domain
            .replace("if same_origin(&target_origin, &provider_url)", "if false");
        assert_gate_fails(&mutation, 7);

        let mut mutation = sources;
        mutation.runtime = append_production(
            &mutation.runtime,
            "const DEFAULT_PROVIDER: &str = \"https://interact.sh\";",
        );
        assert_gate_fails(&mutation, 8);
    }

    #[test]
    fn composition_authority_and_budget_mutations_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.runtime = append_production(&mutation.runtime, "struct SsrfOastRuntime {}");
        assert_gate_fails(&mutation, 9);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(
            &mutation.runtime,
            "fn escape() { let _ = HttpRequestBroker::new(); }",
        );
        assert_gate_fails(&mutation, 10);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(
            &mutation.runtime,
            "fn own_budget() { let _ = RuntimeBudget::default(); }",
        );
        assert_gate_fails(&mutation, 11);

        let mut mutation = sources;
        mutation.scanner_sources.push((
            "plugin.rs".to_owned(),
            "fn escape(authority: Authority, config: Config) { let _ = authority.mint_native_oast_provider(config); }".to_owned(),
        ));
        assert_gate_fails(&mutation, 12);
    }

    #[test]
    fn resource_request_and_method_ceiling_mutations_fail_closed() {
        let sources = current_sources();
        for (number, from, to) in [
            (
                13,
                "MAX_SSRF_OAST_REVIEW_RESOURCES: usize = 1",
                "MAX_SSRF_OAST_REVIEW_RESOURCES: usize = 2",
            ),
            (
                14,
                "MAX_SSRF_OAST_REVIEW_PARAMETERS: usize = 1",
                "MAX_SSRF_OAST_REVIEW_PARAMETERS: usize = 2",
            ),
            (
                15,
                "SSRF_OAST_TARGET_REQUESTS: usize = 3",
                "SSRF_OAST_TARGET_REQUESTS: usize = 4",
            ),
            (
                16,
                "MAX_SSRF_OAST_PROVIDER_REQUESTS: usize = 12",
                "MAX_SSRF_OAST_PROVIDER_REQUESTS: usize = 13",
            ),
            (
                17,
                "SSRF_OAST_ACTIVE_VERIFICATIONS: usize = 1",
                "SSRF_OAST_ACTIVE_VERIFICATIONS: usize = 2",
            ),
        ] {
            let mut mutation = sources.clone();
            mutation.domain = mutation.domain.replacen(from, to, 1);
            assert_gate_fails(&mutation, number);
        }

        let mut mutation = sources;
        mutation.runtime = mutation
            .runtime
            .replace("HttpProbeMethod::Get", "HttpProbeMethod::Post");
        assert_gate_fails(&mutation, 18);
    }

    #[test]
    fn target_mutation_and_scheduling_escapes_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.runtime = append_production(
            &mutation.runtime,
            "fn add_auth(probe: HttpProbe) { let _ = probe.with_header(\"authorization\", \"secret\"); }",
        );
        assert_gate_fails(&mutation, 19);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(
            &mutation.runtime,
            "fn mutate(mut url: Url) { url.set_path(\"/admin\"); }",
        );
        assert_gate_fails(&mutation, 20);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(
            &mutation.runtime,
            "const METADATA: &str = \"169.254.169.254\";",
        );
        assert_gate_fails(&mutation, 21);

        let mut mutation = sources.clone();
        mutation.domain = mutation
            .domain
            .replace("https://c-{label}.invalid/", "gopher://c-{label}.invalid/");
        assert_gate_fails(&mutation, 22);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(&mutation.runtime, "fn retry_target() {}");
        assert_gate_fails(&mutation, 23);

        let mut mutation = sources;
        mutation.runtime = append_production(
            &mutation.runtime,
            "fn background() { tokio::spawn(async {}); }",
        );
        assert_gate_fails(&mutation, 24);
    }

    #[test]
    fn correlation_and_positive_relation_mutations_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.domain = mutation
            .domain
            .replace("https://c-{label}.invalid/", "https://c-{label}.example/");
        assert_gate_fails(&mutation, 25);

        let mut mutation = sources.clone();
        mutation.domain = mutation
            .domain
            .replace("if candidate_target == replay_target", "if false");
        assert_gate_fails(&mutation, 26);

        let mut mutation = sources.clone();
        mutation.domain = mutation.domain.replace(
            "(true, true) => {},",
            "(true, true) => return Ok(SsrfOastReviewOutcome::NoCallback),",
        );
        assert_gate_fails(&mutation, 27);

        let mut mutation = sources;
        mutation.domain = mutation.domain.replace(
            "matches!(self, Self::RepeatedCallbacksObserved)",
            "matches!(self, Self::RepeatedCallbacksObserved | Self::CandidateOnly)",
        );
        assert_gate_fails(&mutation, 28);
    }

    #[test]
    fn claim_report_and_isolation_mutations_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.runtime = mutation.runtime.replace(
            "AssessmentCapabilityDescriptor::differential_review(",
            "AssessmentCapabilityDescriptor::verifier(",
        );
        assert_gate_fails(&mutation, 29);
        assert_gate_fails(&mutation, 31);

        let mut mutation = sources.clone();
        mutation.action = mutation.action.replace(
            "VerificationTarget::KnowledgeOnly",
            "VerificationTarget::MotivationHypothesis",
        );
        assert_gate_fails(&mutation, 30);

        let mut mutation = sources.clone();
        mutation.runtime = mutation.runtime.replace(
            "        None,\n        1_000_000,",
            "        Some(SecuritySeverity::High),\n        1_000_000,",
        );
        assert_gate_fails(&mutation, 32);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(
            &mutation.runtime,
            "struct SsrfOastReport; fn finalize_report() {}",
        );
        assert_gate_fails(&mutation, 33);

        let mut mutation = sources.clone();
        mutation.runtime = append_production(&mutation.runtime, "use crate::phases::phase9_ssrf;");
        assert_gate_fails(&mutation, 34);

        let mut mutation = sources;
        mutation.runtime =
            append_production(&mutation.runtime, "fn chain(_: SqlStructuralQueryPair) {}");
        assert_gate_fails(&mutation, 35);
    }

    #[test]
    fn redaction_release_and_coverage_mutations_fail_closed() {
        let sources = current_sources();

        let mut mutation = sources.clone();
        mutation.runtime = mutation.runtime.replace(
            "    item_projected: bool,",
            "    item_projected: bool,\n    callback_url: String,",
        );
        assert_gate_fails(&mutation, 36);

        let mut mutation = sources.clone();
        mutation
            .release_workflow
            .push_str("\n- run: cargo build -p termivar-cli --features ssrf-oast-review\n");
        assert_gate_fails(&mutation, 37);

        let mut mutation = sources;
        mutation.domain = append_production(&mutation.domain, "#[coverage(off)] fn hidden() {}");
        assert_gate_fails(&mutation, 38);
    }
}
