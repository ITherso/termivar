//! Transport-capability ownership policy for scanner runtimes.

use std::{
    collections::{BTreeMap, BTreeSet},
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
    "crates/venom-scanner/src/payload_strategy.rs",
    "crates/venom-scanner/src/planner.rs",
    "crates/venom-scanner/src/runtime_budget.rs",
    "crates/venom-scanner/src/verification.rs",
    "crates/venom-scanner/src/web_actions.rs",
    "crates/venom-scanner/src/web_decision.rs",
    "crates/venom-scanner/src/web_execution.rs",
    "crates/venom-scanner/src/web_planning.rs",
    "crates/venom-scanner/src/web_reasoning.rs",
    "crates/venom-scanner/src/web_runtime.rs",
    "crates/venom-scanner/src/web_runtime/api_visibility.rs",
    "crates/venom-scanner/src/web_runtime/api_visibility/differential.rs",
    "crates/venom-scanner/src/web_runtime/api_visibility/differential/execution.rs",
    "crates/venom-scanner/src/web_verification.rs",
];

/// The sole raw HTTP-client owner in the bounded runtime.
const TRANSPORT_OWNER_SOURCE: &str = "crates/venom-scanner/src/http_evidence/request_broker.rs";
const STANDARD_RUNTIME_COMPOSITION_SOURCE: &str = "crates/venom-scanner/src/web_runtime.rs";

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
const LEGACY_PHASE_SEND_ALLOWLIST: &[(&str, usize)] = &[
    ("crates/venom-scanner/src/phases/phase1_recon.rs", 1),
    ("crates/venom-scanner/src/phases/phase2_crawl.rs", 1),
    ("crates/venom-scanner/src/phases/phase3_fuzzer.rs", 1),
    ("crates/venom-scanner/src/phases/phase4_param.rs", 1),
    ("crates/venom-scanner/src/phases/phase5_sqli.rs", 3),
    ("crates/venom-scanner/src/phases/phase6_xss.rs", 2),
    ("crates/venom-scanner/src/phases/phase7_ssti.rs", 1),
    ("crates/venom-scanner/src/phases/phase8_lfi_xxe.rs", 4),
    ("crates/venom-scanner/src/phases/phase9_ssrf.rs", 2),
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut violations = validate_policy_inventory();

    for source_name in BOUNDED_RUNTIME_SOURCES {
        let source = fs::read_to_string(workspace_root.join(source_name))?;
        violations.extend(inspect_bounded_source(source_name, &source)?);
    }

    let standard_runtime =
        fs::read_to_string(workspace_root.join(STANDARD_RUNTIME_COMPOSITION_SOURCE))?;
    violations.extend(inspect_standard_runtime_accounting(&standard_runtime));

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

fn inspect_standard_runtime_accounting(source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if !source.contains("HttpRequestBroker::new_metered(") {
        violations.push(format!(
            "{STANDARD_RUNTIME_COMPOSITION_SOURCE} must construct its broker with HttpRequestBroker::new_metered"
        ));
    }
    if source.contains("HttpRequestBroker::new_unmetered(") {
        violations.push(format!(
            "{STANDARD_RUNTIME_COMPOSITION_SOURCE} must not construct an unmetered request broker"
        ));
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

fn inspect_bounded_source(source_name: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = OwnershipVisitor {
        source: source_name,
        inline_module_depth: 0,
        violations: BTreeSet::new(),
    };
    visitor.visit_file(&syntax);
    Ok(visitor.violations.into_iter().collect())
}

struct OwnershipVisitor<'source> {
    source: &'source str,
    inline_module_depth: usize,
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
        if reqwest || is_direct_transport_path(segments) || is_legacy_client_path(segments) {
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
            if is_punctuation(dot, '.') && matches!(member.as_str(), "client" | "send") {
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
                ) | ("crates/venom-scanner/src/web_runtime.rs", "api_visibility")
                    | (
                        "crates/venom-scanner/src/web_runtime/api_visibility.rs",
                        "differential"
                    )
                    | (
                        "crates/venom-scanner/src/web_runtime/api_visibility/differential.rs",
                        "execution"
                    )
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

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        let method = ident_name(&expression.method);
        if method == "send" {
            self.violations.insert(format!(
                "{} calls .send() outside the transport owner",
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

fn is_direct_transport_path(segments: &[String]) -> bool {
    let Some(root) = segments
        .first()
        .map(String::as_str)
        .map(normalize_identifier)
    else {
        return false;
    };
    match root {
        "std" | "tokio" => segments
            .get(1)
            .is_some_and(|module| normalize_identifier(module) == "net"),
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
        collect_rust_sources(&workspace_root.join(root), &mut sources)?;
    }
    let mut direct = BTreeSet::new();
    for path in sources {
        if path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| stem == "tests" || stem.ends_with("_tests"))
        {
            continue;
        }
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
    fn standard_runtime_must_select_the_metered_broker_constructor() {
        assert!(inspect_standard_runtime_accounting(
            "let broker = HttpRequestBroker::new_metered(policy, accounting)?;"
        )
        .is_empty());

        let violations = inspect_standard_runtime_accounting(
            "let broker = HttpRequestBroker::new_unmetered(policy)?;",
        )
        .join("\n");
        assert!(violations.contains("must construct its broker"));
        assert!(violations.contains("must not construct an unmetered"));
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
}
