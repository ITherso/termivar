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
    "crates/venom-scanner/src/decision_loop.rs",
    "crates/venom-scanner/src/decision_runner.rs",
    "crates/venom-scanner/src/http_evidence.rs",
    "crates/venom-scanner/src/http_evidence/form_controls.rs",
    "crates/venom-scanner/src/payload_strategy.rs",
    "crates/venom-scanner/src/planner.rs",
    "crates/venom-scanner/src/runtime_budget.rs",
    "crates/venom-scanner/src/verification.rs",
    "crates/venom-scanner/src/web_actions.rs",
    "crates/venom-scanner/src/web_assessment.rs",
    "crates/venom-scanner/src/web_assessment/discovery.rs",
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
    let assessment =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/web_assessment.rs"))?;
    let discovery = fs::read_to_string(
        workspace_root.join("crates/venom-scanner/src/web_assessment/discovery.rs"),
    )?;
    let http_evidence =
        fs::read_to_string(workspace_root.join("crates/venom-scanner/src/http_evidence.rs"))?;
    let broker = fs::read_to_string(workspace_root.join(TRANSPORT_OWNER_SOURCE))?;
    let facade = fs::read_to_string(workspace_root.join("crates/venom-scanner/src/lib.rs"))?;
    let mut violations = Vec::new();

    for (source_name, source) in [
        (
            "crates/venom-scanner/src/web_assessment.rs",
            assessment.as_str(),
        ),
        (
            "crates/venom-scanner/src/web_assessment/discovery.rs",
            discovery.as_str(),
        ),
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
    violations.extend(inspect_complete_observer_seam(&http_evidence)?);
    violations.extend(inspect_assessment_transport_markers(
        &http_evidence,
        &broker,
    ));
    Ok(violations)
}

fn inspect_assessment_transport_markers(http_evidence: &str, broker: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !http_evidence.contains("complete_response_observer_seal::Sealed")
        || !http_evidence
            .contains("impl Sealed for crate::web_assessment::AssessmentDiscoveryObserver {}")
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
        || modules[0]
            .attrs
            .iter()
            .any(attribute_can_redirect_module_path)
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
            "web assessment crate-root export allowlist drifted; missing={:?}, unexpected={:?}",
            expected.difference(&exports).collect::<Vec<_>>(),
            exports.difference(&expected).collect::<Vec<_>>()
        ));
    }
    Ok(violations)
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
            "response_media_type_evidence_id",
            "response_status_evidence_id",
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
                "complete response observation must remain the exact non-cloneable borrowed scalar/ID/body view with no owned strings, headers, or bytes"
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
                let impl_targets = items
                    .iter()
                    .filter_map(|item| match item {
                        Item::Impl(item) => Some(item),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                sealed_traits == 1
                    && impl_targets.len() == 1
                    && impl_targets[0].trait_.as_ref().is_some_and(|(_, path, _)| {
                        path.segments
                            .last()
                            .is_some_and(|segment| segment.ident == "Sealed")
                    })
                    && matches!(impl_targets[0].self_ty.as_ref(), syn::Type::Path(path)
                        if path.path.segments.last().is_some_and(|segment|
                            segment.ident == "AssessmentDiscoveryObserver"))
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
        | "response_media_type_evidence_id"
        | "response_body_truncated_evidence_id"
        | "response_body_digest_evidence_id" => is_optional_borrowed_ident(item_type, "EvidenceId"),
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
        if matches!(
            self.source,
            "crates/venom-scanner/src/web_assessment.rs"
                | "crates/venom-scanner/src/web_assessment/discovery.rs"
        ) {
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
        let canonical = self.inline_module_depth == 0
            && item.attrs.is_empty()
            && matches!(item.vis, syn::Visibility::Inherited)
            && matches!(
                (self.source, module.as_str()),
                (
                    "crates/venom-scanner/src/http_evidence.rs",
                    "request_broker"
                ) | ("crates/venom-scanner/src/http_evidence.rs", "form_controls")
                    | ("crates/venom-scanner/src/web_runtime.rs", "authority")
                    | ("crates/venom-scanner/src/web_runtime.rs", "api_visibility")
                    | (
                        "crates/venom-scanner/src/web_runtime/api_visibility.rs",
                        "differential"
                    )
                    | (
                        "crates/venom-scanner/src/web_runtime/api_visibility/differential.rs",
                        "execution"
                    )
                    | ("crates/venom-scanner/src/web_assessment.rs", "discovery")
            );
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
                    builder.build_with_shared_authority(authority);
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
            let violations =
                inspect_bounded_source("crates/venom-scanner/src/web_assessment.rs", source)
                    .unwrap()
                    .join("\n");
            assert!(violations.contains(needle), "{source}: {violations}");
        }
    }

    #[test]
    fn assessment_facade_export_allowlist_is_exact() {
        let exports = WEB_ASSESSMENT_PUBLIC_EXPORTS.join(", ");
        let valid = format!(
            "#[cfg(feature = \"scanning\")] mod web_assessment;\n\
             #[cfg(feature = \"scanning\")] pub use web_assessment::{{{exports}}};"
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
    }

    #[test]
    fn assessment_models_keep_fields_private_without_serde_or_nested_audits() {
        let valid = r#"
            pub struct WebAssessmentSubjectReport { subject: String }
            pub struct WebAssessmentRunReport { transport: TransportDispatchAudit }
            pub struct WebAssessmentFailureReceipt { transport: TransportDispatchAudit }
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
    }

    #[test]
    fn sealed_observer_and_eof_header_redirect_markers_are_mutation_locked() {
        let seam = include_str!("../../../crates/venom-scanner/src/http_evidence.rs");
        assert!(inspect_complete_observer_seam(seam).unwrap().is_empty());
        let broadened = seam.replace(
            "impl Sealed for crate::web_assessment::AssessmentDiscoveryObserver {}",
            "impl Sealed for crate::web_assessment::AssessmentDiscoveryObserver {} impl Sealed for Other {}",
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
