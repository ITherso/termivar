//! Exact isolation and release-boundary checks for the self-hosted native OAST
//! provider. The provider is an auxiliary raw-free callback mailbox, never a
//! scanner or a release-bundle component.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(test)]
use std::collections::VecDeque;

use cargo_metadata::{DependencyKind, MetadataCommand, Package};
use syn::{
    visit::{self, Visit},
    Fields, FnArg, GenericArgument, ImplItem, Item, PathArguments, ReturnType, Type, UseTree,
    Visibility,
};

const PACKAGE: &str = "termivar-oast";
const MANIFEST: &str = "crates/termivar-oast/Cargo.toml";
const SOURCE_ROOT: &str = "crates/termivar-oast/src";
const SCANNER_MANIFEST: &str = "crates/termivar-scanner/Cargo.toml";
const SCANNER_SOURCE_ROOT: &str = "crates/termivar-scanner/src";
const SCANNER_ADAPTER: &str = "native_oast_provider.rs";
const SHARED_AUTHORITY_SOURCE: &str = "crates/termivar-scanner/src/web_runtime/authority.rs";
const CLI_MANIFEST: &str = "crates/termivar-cli/Cargo.toml";
const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";
const DENY_CONFIG: &str = "deny.toml";
const AUDIT_SCRIPT: &str = "scripts/ci/run-cargo-audit.sh";
const EXACT_RELEASE_BUILD: &str = "cargo build --locked --release --target ${{ matrix.target }} -p termivar-cli --features release-bundle";

const EXPECTED_RUNTIME_DEPENDENCIES: &[&str] = &[
    "axum",
    "base64",
    "clap",
    "futures",
    "getrandom",
    "hyper",
    "hyper-util",
    "reqwest",
    "serde",
    "serde_json",
    "sha2",
    "subtle",
    "tokio",
    "tokio-util",
    "tower",
    "url",
    "zeroize",
];

const EXPECTED_SOURCE_FILES: &[&str] = &[
    "bin/termivar-oast-provider.rs",
    "client.rs",
    "config.rs",
    "lib.rs",
    "protocol.rs",
    "secret.rs",
    "server.rs",
    "state.rs",
];

const FORBIDDEN_CRYPTO_PACKAGES: &[&str] = &[
    "rsa", "ring", "openssl", "aws-lc", "aes", "chacha", "x25519", "ed25519",
];

const REQUIRED_REVIEWED_TLS_PACKAGES: &[&str] = &["reqwest", "ring", "rustls", "rustls-webpki"];

const REQUIRED_PROTOCOL_LITERALS: &[&str] = &[
    "security.termivar-oast.session/v1",
    "security.termivar-oast.callback/v1",
    "security.termivar-oast.poll/v1",
    "security.termivar-oast.cleanup/v1",
    "/v1/sessions",
    "/c/",
];

const FORBIDDEN_PRODUCT_REFERENCES: &[&str] = &[
    "WebAssessmentRuntime",
    "AssessmentItem",
    "RunReport",
    "ScanFinding",
    "termivar_scanner",
    "legacy_scanner",
    "phase9_ssrf",
    "post_exploitation",
];

const FORBIDDEN_BACKGROUND_FRAGMENTS: &[&str] = &[
    "tokio::spawn",
    "spawn_blocking",
    "std::thread::spawn",
    "thread::spawn",
];

const FORBIDDEN_PROVIDER_LITERALS: &[&str] = &[
    "interact.sh",
    "interactsh",
    "burpcollaborator",
    "oastify",
    "canarytokens",
    "dnslog.cn",
    "requestbin",
    "webhook.site",
];

const FORBIDDEN_STATE_FIELDS: &[&str] = &[
    "ip",
    "port",
    "url",
    "path",
    "query",
    "header",
    "headers",
    "cookie",
    "cookies",
    "body",
    "timestamp",
    "user_agent",
    "source_address",
    "remote_address",
    "forwarded_for",
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let packages = metadata.workspace_packages();
    let Some(provider) = packages
        .iter()
        .copied()
        .find(|package| package.name == PACKAGE)
    else {
        return Ok(vec![format!(
            "workspace package `{PACKAGE}` is missing from `{MANIFEST}`"
        )]);
    };

    let mut violations = package_contract_violations(workspace_root, provider);
    violations.extend(dependency_edge_violations(&packages));

    violations.extend(feature_crypto_dependency_violations(
        workspace_root,
        "server",
        false,
        &[],
    )?);
    violations.extend(feature_crypto_dependency_violations(
        workspace_root,
        "client",
        true,
        REQUIRED_REVIEWED_TLS_PACKAGES,
    )?);
    violations.extend(source_contract_violations(workspace_root)?);
    violations.extend(scanner_adapter_contract_violations(workspace_root)?);
    violations.extend(release_isolation_violations(workspace_root)?);
    violations.extend(advisory_policy_violations(workspace_root)?);
    Ok(violations)
}

fn package_contract_violations(workspace_root: &Path, provider: &Package) -> Vec<String> {
    let mut violations = Vec::new();
    let expected_manifest = workspace_root.join(MANIFEST);
    if provider.manifest_path.as_std_path() != expected_manifest {
        violations.push(format!(
            "{PACKAGE} must remain the auxiliary package at {}, found {}",
            expected_manifest.display(),
            provider.manifest_path
        ));
    }
    if provider
        .publish
        .as_ref()
        .is_none_or(|registries| !registries.is_empty())
    {
        violations.push(format!("{PACKAGE} must remain `publish = false`"));
    }

    let target_kinds: BTreeSet<_> = provider
        .targets
        .iter()
        .map(|target| {
            (
                target.name.as_str(),
                target.kind.iter().map(String::as_str).collect::<Vec<_>>(),
                target
                    .required_features
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect();
    let expected_targets = BTreeSet::from([
        ("termivar_oast", vec!["lib"], BTreeSet::new()),
        (
            "termivar-oast-provider",
            vec!["bin"],
            BTreeSet::from(["server"]),
        ),
    ]);
    if target_kinds != expected_targets {
        violations.push(format!(
            "{PACKAGE} must expose exactly its library and server-gated provider binary targets"
        ));
    }

    violations.extend(feature_contract_violations(&provider.features));

    let runtime = dependency_names(provider, DependencyKind::Normal);
    let expected: BTreeSet<_> = EXPECTED_RUNTIME_DEPENDENCIES.iter().copied().collect();
    if runtime != expected {
        violations.push(format!(
            "{PACKAGE} runtime dependencies must remain exactly {expected:?}, found {runtime:?}"
        ));
    }
    for kind in [DependencyKind::Build, DependencyKind::Unknown] {
        let names = dependency_names(provider, kind);
        if !names.is_empty() {
            violations.push(format!(
                "{PACKAGE} has forbidden {kind:?} dependencies {names:?}"
            ));
        }
    }
    if provider.dependencies.iter().any(|dependency| {
        dependency.rename.is_some() || dependency.target.is_some() || dependency.path.is_some()
    }) {
        violations.push(format!(
            "{PACKAGE} dependencies must not be renamed, target-conditional, or local workspace edges"
        ));
    }
    violations
}

fn feature_contract_violations(features: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    let expected = BTreeMap::from([
        (
            "client".to_owned(),
            BTreeSet::from([
                "dep:reqwest",
                "dep:serde_json",
                "dep:tokio",
                "dep:tokio-util",
            ]),
        ),
        ("default".to_owned(), BTreeSet::new()),
        (
            "server".to_owned(),
            BTreeSet::from([
                "dep:axum",
                "dep:clap",
                "dep:futures",
                "dep:hyper",
                "dep:hyper-util",
                "dep:serde_json",
                "dep:tokio",
                "dep:tower",
            ]),
        ),
        ("test-support".to_owned(), BTreeSet::from(["server"])),
    ]);
    let actual: BTreeMap<_, BTreeSet<_>> = features
        .iter()
        .map(|(name, members)| {
            (
                name.to_owned(),
                members.iter().map(String::as_str).collect::<BTreeSet<_>>(),
            )
        })
        .collect();
    if actual == expected {
        Vec::new()
    } else {
        vec![format!(
            "{PACKAGE} features must remain the exact non-default provider-server boundary"
        )]
    }
}

fn dependency_names(package: &Package, kind: DependencyKind) -> BTreeSet<&str> {
    package
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind == kind)
        .map(|dependency| dependency.name.as_str())
        .collect()
}

fn dependency_edge_violations(packages: &[&Package]) -> Vec<String> {
    let consumers = packages
        .iter()
        .copied()
        .filter(|package| package.name != PACKAGE)
        .filter(|package| {
            package
                .dependencies
                .iter()
                .any(|dependency| dependency.name == PACKAGE)
        })
        .collect::<Vec<_>>();
    let mut violations = Vec::new();
    if consumers
        .iter()
        .map(|package| package.name.as_str())
        .collect::<Vec<_>>()
        != ["termivar-scanner"]
    {
        violations.push(format!(
            "{PACKAGE} must have exactly one workspace consumer, termivar-scanner; found {:?}",
            consumers
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>()
        ));
    }
    if let Some(scanner) = consumers
        .iter()
        .copied()
        .find(|package| package.name == "termivar-scanner")
    {
        let normal_edges = scanner
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.name == PACKAGE && dependency.kind == DependencyKind::Normal
            })
            .collect::<Vec<_>>();
        let normal_is_exact = matches!(normal_edges.as_slice(), [dependency]
            if dependency.optional
                && !dependency.uses_default_features
                && dependency.features.iter().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["client"]));
        if !normal_is_exact {
            violations.push(format!(
                "termivar-scanner must consume {PACKAGE} exactly once as an optional, default-disabled client-only dependency"
            ));
        }
        let development_edges = scanner
            .dependencies
            .iter()
            .filter(|dependency| {
                dependency.name == PACKAGE && dependency.kind == DependencyKind::Development
            })
            .collect::<Vec<_>>();
        let development_is_exact = matches!(development_edges.as_slice(), [dependency]
            if !dependency.optional
                && !dependency.uses_default_features
                && dependency.features.iter().map(String::as_str).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["client", "test-support"]));
        if !development_is_exact {
            violations.push(
                "termivar-scanner must isolate native OAST loopback fixtures to one default-disabled client+test-support dev-dependency"
                    .to_owned(),
            );
        }
        if scanner.dependencies.iter().any(|dependency| {
            dependency.name == PACKAGE
                && !matches!(
                    dependency.kind,
                    DependencyKind::Normal | DependencyKind::Development
                )
        }) {
            violations.push(format!(
                "termivar-scanner must not add a build or unknown dependency edge to {PACKAGE}"
            ));
        }
    }
    violations
}

fn feature_crypto_dependency_violations(
    workspace_root: &Path,
    feature: &str,
    reviewed_tls_ring: bool,
    required: &[&str],
) -> Result<Vec<String>, io::Error> {
    // `cargo metadata` unifies features across workspace members, which would
    // pull the scanner's client+test-support dev edge into a server-only
    // inspection. `cargo tree -p` preserves the exact requested feature graph.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(workspace_root)
        .args([
            "tree",
            "--locked",
            "--manifest-path",
            MANIFEST,
            "-p",
            PACKAGE,
            "--no-default-features",
            "--features",
            feature,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .output()?;
    if !output.status.success() {
        return Ok(vec![format!(
            "{PACKAGE}/{feature} production dependency closure could not be resolved with locked Cargo"
        )]);
    }
    let packages = String::from_utf8(output.stdout)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    for package in &packages {
        if let Some(family) = forbidden_crypto_family(package) {
            if !(reviewed_tls_ring && family == "ring") {
                violations.push(format!(
                    "{PACKAGE}/{feature} production closure contains forbidden {family} package `{package}`"
                ));
            }
        }
    }
    for required in required {
        if !packages.contains(*required) {
            violations.push(format!(
                "{PACKAGE}/{feature} TLS closure must retain reviewed package `{required}`"
            ));
        }
    }
    Ok(violations)
}

#[cfg(test)]
fn dependency_closure_crypto_violations(
    root: &str,
    package_names: &BTreeMap<String, String>,
    dependency_edges: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    dependency_closure_crypto_violations_with_policy(root, package_names, dependency_edges, false)
}

#[cfg(test)]
fn dependency_closure_crypto_violations_with_reviewed_ring(
    root: &str,
    package_names: &BTreeMap<String, String>,
    dependency_edges: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    dependency_closure_crypto_violations_with_policy(root, package_names, dependency_edges, true)
}

#[cfg(test)]
fn dependency_closure_crypto_violations_with_policy(
    root: &str,
    package_names: &BTreeMap<String, String>,
    dependency_edges: &BTreeMap<String, BTreeSet<String>>,
    reviewed_tls_ring: bool,
) -> Vec<String> {
    if !package_names.contains_key(root) || !dependency_edges.contains_key(root) {
        return vec![format!(
            "{PACKAGE} is absent from the all-features dependency closure"
        )];
    }

    let mut pending = VecDeque::from([root.to_owned()]);
    let mut visited = BTreeSet::new();
    let mut forbidden = BTreeSet::new();
    while let Some(package_id) = pending.pop_front() {
        if !visited.insert(package_id.clone()) {
            continue;
        }
        if let Some(name) = package_names.get(&package_id) {
            if let Some(family) = forbidden_crypto_family(name) {
                if !(reviewed_tls_ring && family == "ring") {
                    forbidden.insert((family, name.clone()));
                }
            }
        }
        if let Some(dependencies) = dependency_edges.get(&package_id) {
            pending.extend(dependencies.iter().cloned());
        }
    }

    forbidden
        .into_iter()
        .map(|(family, name)| {
            format!(
                "{PACKAGE} all-features dependency closure contains forbidden {family} package `{name}`"
            )
        })
        .collect()
}

fn forbidden_crypto_family(package_name: &str) -> Option<&'static str> {
    let normalized = package_name.to_ascii_lowercase();
    FORBIDDEN_CRYPTO_PACKAGES.iter().copied().find(|family| {
        normalized == *family
            || (matches!(
                *family,
                "rsa" | "openssl" | "aws-lc" | "aes" | "x25519" | "ed25519"
            ) && normalized.starts_with(&format!("{family}-")))
            || (*family == "chacha" && normalized.starts_with("chacha"))
    })
}

fn source_contract_violations(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let source_root = workspace_root.join(SOURCE_ROOT);
    let mut paths = rust_sources_below(&source_root)?;
    paths.sort();
    let actual: BTreeSet<_> = paths
        .iter()
        .map(|path| normalized_relative(&source_root, path))
        .collect::<Result<_, _>>()?;
    let expected: BTreeSet<_> = EXPECTED_SOURCE_FILES
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut violations = Vec::new();
    if actual != expected {
        violations.push(format!(
            "{PACKAGE} production source inventory must remain exactly {expected:?}, found {actual:?}"
        ));
    }

    let mut combined = String::new();
    for path in &paths {
        let source = fs::read_to_string(path)?;
        let relative = normalized_relative(workspace_root, path)?;
        for forbidden in FORBIDDEN_PRODUCT_REFERENCES {
            if source.contains(forbidden) {
                violations.push(format!(
                    "{relative} imports or names forbidden scanner/report surface `{forbidden}`"
                ));
            }
        }
        let production = production_prefix(&source);
        for forbidden in FORBIDDEN_BACKGROUND_FRAGMENTS {
            if production.contains(forbidden) {
                violations.push(format!(
                    "{relative} starts forbidden background work through `{forbidden}`"
                ));
            }
        }
        for forbidden in FORBIDDEN_PROVIDER_LITERALS {
            if source.to_ascii_lowercase().contains(forbidden) {
                violations.push(format!(
                    "{relative} embeds forbidden public/compatibility provider literal `{forbidden}`"
                ));
            }
        }
        combined.push_str(&source);
        combined.push('\n');
    }

    for required in REQUIRED_PROTOCOL_LITERALS {
        if !combined.contains(required) {
            violations.push(format!(
                "{PACKAGE} must pin protocol/route literal `{required}`"
            ));
        }
    }
    if !combined.contains("is_loopback") {
        violations.push(format!(
            "{PACKAGE} production configuration must explicitly validate loopback bind authority"
        ));
    }
    if !combined.contains("https") {
        violations.push(format!(
            "{PACKAGE} production configuration must explicitly validate its HTTPS public origin"
        ));
    }

    let state_source = fs::read_to_string(source_root.join("state.rs"))?;
    violations.extend(state_shape_violations(&state_source)?);

    let secret_source = fs::read_to_string(source_root.join("secret.rs"))?;
    violations.extend(secret_surface_violations(
        &secret_source,
        &[("AdminToken", "AdminToken(<redacted>)")],
    )?);

    let protocol_source = fs::read_to_string(source_root.join("protocol.rs"))?;
    violations.extend(secret_surface_violations(
        &protocol_source,
        &[
            ("SessionToken", "SessionToken(<redacted>)"),
            ("ManagementBearer", "ManagementBearer(<redacted>)"),
            ("CallbackTarget", "CallbackTarget(<redacted>)"),
        ],
    )?);

    let library_source = fs::read_to_string(source_root.join("lib.rs"))?;
    let client_source = fs::read_to_string(source_root.join("client.rs"))?;
    violations.extend(client_transport_contract_violations(production_prefix(
        &client_source,
    ))?);
    let server_source = fs::read_to_string(source_root.join("server.rs"))?;
    violations.extend(server_surface_violations(
        production_prefix(&server_source),
        production_prefix(&library_source),
    )?);
    violations.extend(server_transport_contract_violations(production_prefix(
        &server_source,
    )));

    let library = syn::parse_file(&library_source)?;
    let forbids_unsafe = library.attrs.iter().any(|attribute| {
        attribute.path().is_ident("forbid")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "unsafe_code")
    });
    if !forbids_unsafe {
        violations.push(format!("{PACKAGE} must retain `#![forbid(unsafe_code)]`"));
    }
    Ok(violations)
}

fn client_transport_contract_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let compact = compact_whitespace(source);
    let mut violations = Vec::new();
    for required in [
        "Client::builder()",
        ".redirect(RedirectPolicy::none())",
        ".retry(reqwest::retry::never())",
        ".no_proxy()",
        ".referer(false)",
        ".http1_only()",
        "constREGISTER_PATH:&str=\"/v1/sessions\";",
        "format!(\"/v1/sessions/{}/callbacks\",session_id.as_str())",
        "format!(\"/v1/sessions/{}/events\",session_id.as_str())",
        "format!(\"/v1/sessions/{}\",session_id.as_str())",
    ] {
        if compact.matches(required).count() != 1 {
            violations.push(format!(
                "{PACKAGE} fixed HTTPS client must contain exactly one `{required}` contract"
            ));
        }
    }
    for forbidden in [
        "danger_accept_invalid_certs",
        "danger_accept_invalid_hostnames",
        ".proxy(",
        "Proxy::",
        ".cookie_store(",
        ".cookie_provider(",
        "Client::new()",
        "tokio::spawn",
        "spawn_blocking",
    ] {
        if compact.contains(forbidden) {
            violations.push(format!(
                "{PACKAGE} fixed HTTPS client must not use `{forbidden}`"
            ));
        }
    }

    let mut public_signatures = Vec::new();
    for item in &syntax.items {
        match item {
            Item::Fn(function) if matches!(function.vis, Visibility::Public(_)) => {
                public_signatures.push(&function.sig)
            },
            Item::Impl(implementation) => {
                public_signatures.extend(implementation.items.iter().filter_map(|item| {
                    let syn::ImplItem::Fn(method) = item else {
                        return None;
                    };
                    matches!(method.vis, Visibility::Public(_)).then_some(&method.sig)
                }));
            },
            _ => {},
        }
    }
    if public_signatures
        .iter()
        .any(|signature| signature_accepts_arbitrary_authority(signature))
    {
        violations.push(format!(
            "{PACKAGE} client module must expose no public function accepting arbitrary URL or string authority"
        ));
    }

    for implementation in syntax.items.iter().filter_map(|item| match item {
        Item::Impl(implementation) => Some(implementation),
        _ => None,
    }) {
        let self_type = type_path_tail(&implementation.self_ty);
        let trait_name = implementation
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .map(|segment| segment.ident.to_string());
        if self_type.as_deref() == Some("NativeOastClient") && trait_name.as_deref() == Some("Drop")
        {
            violations.push(format!(
                "{PACKAGE} client must not perform implicit cleanup or network work in Drop"
            ));
        }
    }
    Ok(violations)
}

fn signature_accepts_arbitrary_authority(signature: &syn::Signature) -> bool {
    signature.inputs.iter().any(|input| {
        let syn::FnArg::Typed(argument) = input else {
            return false;
        };
        let mut visitor = ArbitraryAuthorityTypeVisitor::default();
        visitor.visit_type(&argument.ty);
        visitor.found
    })
}

#[derive(Default)]
struct ArbitraryAuthorityTypeVisitor {
    found: bool,
}

impl<'ast> syn::visit::Visit<'ast> for ArbitraryAuthorityTypeVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if path.segments.last().is_some_and(|segment| {
            matches!(segment.ident.to_string().as_str(), "Url" | "String" | "str")
        }) {
            self.found = true;
        }
        syn::visit::visit_path(self, path);
    }
}

fn scanner_adapter_contract_violations(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let scanner_manifest = fs::read_to_string(workspace_root.join(SCANNER_MANIFEST))?;
    let scanner_value = toml::from_str::<toml::Value>(&scanner_manifest)?;
    let mut violations = Vec::new();
    let features = scanner_value
        .get("features")
        .and_then(toml::Value::as_table);
    let native_members = features
        .and_then(|table| table.get("oast-native-provider"))
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<BTreeSet<_>>()
        });
    if native_members
        != Some(BTreeSet::from([
            "dep:termivar-oast",
            "oast-correlation",
            "scanning",
        ]))
    {
        violations.push(
            "termivar-scanner/oast-native-provider must contain exactly oast-correlation, scanning, and dep:termivar-oast"
                .to_owned(),
        );
    }
    if let Some(features) = features {
        for aggregate in ["default", "full", "enterprise", "minimal", "research"] {
            if feature_reaches(features, aggregate, "oast-native-provider") {
                violations.push(format!(
                    "termivar-scanner feature `{aggregate}` must not enable oast-native-provider"
                ));
            }
        }
    }

    let source_root = workspace_root.join(SCANNER_SOURCE_ROOT);
    let adapter_path = source_root.join(SCANNER_ADAPTER);
    if !adapter_path.is_file() {
        violations.push(format!(
            "the sealed native OAST adapter must live only at {SCANNER_SOURCE_ROOT}/{SCANNER_ADAPTER}"
        ));
        return Ok(violations);
    }

    let adapter = fs::read_to_string(&adapter_path)?;
    let production = source_without_exact_oast_test_modules(&adapter)?;
    for required in [
        "NativeOastProviderOperation",
        "NativeOastProviderLimits",
        "NativeOastProviderPermit",
        "NativeOastProviderLifecycle",
        "NativeOastProviderReceipt",
        "NativeOastProviderAdapter",
        "Register",
        "AllocateCallback",
        "Poll",
        "Cleanup",
    ] {
        if !production.contains(required) {
            violations.push(format!(
                "the native OAST adapter must retain exact contract `{required}`"
            ));
        }
    }
    violations.extend(adapter_forbidden_authority_violations(&production));
    violations.extend(adapter_private_authority_shape_violations(&production)?);

    let mut scanner_sources = rust_sources_below(&source_root)?;
    scanner_sources.sort();
    let mut provider_consumers = Vec::new();
    let mut scanner_production_sources = Vec::new();
    for path in scanner_sources {
        let source = fs::read_to_string(&path)?;
        let relative = normalized_relative(&source_root, &path)?;
        let production = source_without_exact_oast_test_modules(production_prefix(&source))?;
        let consumes_provider = production.contains("termivar_oast");
        if consumes_provider {
            provider_consumers.push(relative.clone());
        }
        scanner_production_sources.push((relative, production));
    }
    if provider_consumers != [SCANNER_ADAPTER.to_owned()] {
        violations.push(format!(
            "termivar-scanner must have exactly one production termivar_oast consumer at {SCANNER_ADAPTER}; found {provider_consumers:?}"
        ));
    }
    violations.extend(sealed_mint_consumer_violations(
        &scanner_production_sources,
    )?);

    let library = fs::read_to_string(source_root.join("lib.rs"))?;
    let compact_library = compact_whitespace(production_prefix(&library));
    let exact_module = "#[cfg(feature=\"oast-native-provider\")]pub(crate)modnative_oast_provider;";
    if compact_library.matches(exact_module).count() != 1 {
        violations.push(
            "termivar-scanner must declare exactly one crate-private native_oast_provider module behind only oast-native-provider"
                .to_owned(),
        );
    }

    let cli_manifest = fs::read_to_string(workspace_root.join(CLI_MANIFEST))?;
    let cli_source = fs::read_to_string(workspace_root.join("crates/termivar-cli/src/main.rs"))?;
    for forbidden in ["oast-native-provider", "termivar-oast", "oast-provider"] {
        if cli_manifest.contains(forbidden) || production_prefix(&cli_source).contains(forbidden) {
            violations.push(format!(
                "the native OAST provider adapter must expose no CLI dependency, feature, or flag containing `{forbidden}`"
            ));
        }
    }

    let authority = fs::read_to_string(workspace_root.join(SHARED_AUTHORITY_SOURCE))?;
    violations.extend(shared_provider_mint_contract_violations(&authority)?);

    Ok(violations)
}

fn adapter_forbidden_authority_violations(production: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for forbidden in [
        "reqwest::",
        "TcpStream",
        "UdpSocket",
        "AssessmentItem",
        "ScanFinding",
        "RunReport",
        "reporting::",
        "legacy_scanner",
        "crate::phases",
        "crate::plugin",
        "crate::lua",
        "crate::graphql_review",
        "crate::openapi_review",
        "crate::rest_review",
        "crate::authorization_review",
        "post_exploitation",
    ] {
        if production.contains(forbidden) {
            violations.push(format!(
                "the native OAST adapter must not consume forbidden authority surface `{forbidden}`"
            ));
        }
    }
    for forbidden in FORBIDDEN_BACKGROUND_FRAGMENTS {
        if production.contains(forbidden) {
            violations.push(format!(
                "the native OAST adapter must not start background work through `{forbidden}`"
            ));
        }
    }
    violations
}

fn adapter_private_authority_shape_violations(production: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(production)?;
    let mut violations = Vec::new();
    let compact = compact_whitespace(production);
    if compact.contains("allow(dead_code") {
        violations.push(
            "the sealed native OAST adapter must not suppress dead-code policy with `allow`"
                .to_owned(),
        );
    }
    for (marker, expected) in [
        ("NativeOastClient::new(", 1),
        ("NativeOastProviderPermit::mint(", 1),
        ("implNativeOastClientBoundaryforNativeOastProviderPermit", 1),
    ] {
        if compact.matches(marker).count() != expected {
            violations.push(format!(
                "the sealed native OAST adapter must contain exactly {expected} `{marker}` authority edge"
            ));
        }
    }

    for type_name in [
        "NativeOastProviderConfiguration",
        "NativeOastProviderPermit",
        "NativeOastProviderAdapter",
    ] {
        let declarations = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(record) if record.ident == type_name => Some(record),
                _ => None,
            })
            .collect::<Vec<_>>();
        let [declaration] = declarations.as_slice() else {
            violations.push(format!(
                "the sealed native OAST adapter must declare exactly one `{type_name}`"
            ));
            continue;
        };
        if !matches!(declaration.vis, Visibility::Restricted(_))
            || declaration
                .fields
                .iter()
                .any(|field| !matches!(field.vis, Visibility::Inherited))
        {
            violations.push(format!(
                "the sealed native OAST `{type_name}` and all of its fields must remain crate-private"
            ));
        }
        if derives_any(
            &declaration.attrs,
            &["Clone", "Copy", "Serialize", "Deserialize"],
        ) {
            violations.push(format!(
                "the sealed native OAST `{type_name}` must remain move-only and non-serializable"
            ));
        }
    }

    for implementation in syntax.items.iter().filter_map(|item| match item {
        Item::Impl(implementation) => Some(implementation),
        _ => None,
    }) {
        let Some(type_name) = type_path_tail(&implementation.self_ty) else {
            continue;
        };
        if !matches!(
            type_name.as_str(),
            "NativeOastProviderConfiguration"
                | "NativeOastProviderPermit"
                | "NativeOastProviderAdapter"
        ) {
            continue;
        }
        let trait_name = implementation
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .map(|segment| segment.ident.to_string());
        if trait_name.as_deref().is_some_and(|name| {
            matches!(
                name,
                "Clone" | "Copy" | "Serialize" | "Deserialize" | "Drop"
            )
        }) {
            violations.push(format!(
                "the sealed native OAST `{type_name}` must not implement `{}`",
                trait_name.unwrap_or_default()
            ));
        }
    }

    let inherent_mint_methods = |type_name: &str| {
        syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Impl(implementation)
                    if implementation.trait_.is_none()
                        && type_path_tail(&implementation.self_ty).as_deref()
                            == Some(type_name) =>
                {
                    Some(implementation)
                },
                _ => None,
            })
            .flat_map(|implementation| &implementation.items)
            .filter_map(|item| match item {
                ImplItem::Fn(method) if method.sig.ident == "mint" => Some(method),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let permit_mints = inherent_mint_methods("NativeOastProviderPermit");
    if !matches!(permit_mints.as_slice(), [method]
        if matches!(method.vis, Visibility::Inherited))
    {
        violations.push(
            "NativeOastProviderPermit::mint must remain exactly one private constructor in the sealed adapter module"
                .to_owned(),
        );
    }
    let adapter_mints = inherent_mint_methods("NativeOastProviderAdapter");
    let consumes_token_by_value = matches!(adapter_mints.as_slice(), [method]
        if matches!(method.vis, Visibility::Restricted(_))
            && matches!(method.sig.inputs.first(), Some(FnArg::Typed(argument))
                if type_path_tail(&argument.ty).as_deref()
                    == Some("NativeOastProviderMintToken")));
    if !consumes_token_by_value {
        violations.push(
            "NativeOastProviderAdapter::mint must remain one crate-private constructor consuming the move-only authority token by value"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn sealed_mint_consumer_violations(
    sources: &[(String, String)],
) -> Result<Vec<String>, syn::Error> {
    let mut adapter_mint_consumers = Vec::new();
    let mut permit_mint_consumers = Vec::new();
    let mut token_constructors = Vec::new();
    let mut renamed_authority_symbols = Vec::new();

    for (path, source) in sources {
        let syntax = syn::parse_file(source)?;
        let mut visitor = SealedMintConsumerVisitor::default();
        visitor.visit_file(&syntax);
        adapter_mint_consumers.extend(std::iter::repeat_n(path.clone(), visitor.adapter_mints));
        permit_mint_consumers.extend(std::iter::repeat_n(path.clone(), visitor.permit_mints));
        token_constructors.extend(std::iter::repeat_n(
            path.clone(),
            visitor.token_constructors,
        ));
        renamed_authority_symbols.extend(
            visitor
                .renamed_authority_symbols
                .into_iter()
                .map(|symbol| format!("{path}: {symbol}")),
        );
    }

    let mut violations = Vec::new();
    let authority_path = "web_runtime/authority.rs".to_owned();
    if adapter_mint_consumers != [authority_path.clone()] {
        violations.push(format!(
            "NativeOastProviderAdapter::mint must have exactly one production caller in web_runtime/authority.rs; found {adapter_mint_consumers:?}"
        ));
    }
    if permit_mint_consumers != [SCANNER_ADAPTER.to_owned()] {
        violations.push(format!(
            "NativeOastProviderPermit::mint must have exactly one production caller inside {SCANNER_ADAPTER}; found {permit_mint_consumers:?}"
        ));
    }
    if token_constructors != [authority_path] {
        violations.push(format!(
            "NativeOastProviderMintToken must have exactly one production construction site in web_runtime/authority.rs; found {token_constructors:?}"
        ));
    }
    if !renamed_authority_symbols.is_empty() {
        violations.push(format!(
            "native OAST mint authority symbols must not be renamed or aliased: {renamed_authority_symbols:?}"
        ));
    }
    Ok(violations)
}

#[derive(Default)]
struct SealedMintConsumerVisitor {
    adapter_mints: usize,
    permit_mints: usize,
    token_constructors: usize,
    renamed_authority_symbols: Vec<String>,
}

impl<'ast> Visit<'ast> for SealedMintConsumerVisitor {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        let called = expression_call_path(expression);
        if called
            .as_deref()
            .is_some_and(|path| path.ends_with("NativeOastProviderAdapter::mint"))
        {
            self.adapter_mints = self.adapter_mints.saturating_add(1);
        } else if called
            .as_deref()
            .is_some_and(|path| path.ends_with("NativeOastProviderPermit::mint"))
        {
            self.permit_mints = self.permit_mints.saturating_add(1);
        } else if called
            .as_deref()
            .is_some_and(|path| path.ends_with("NativeOastProviderMintToken"))
        {
            self.token_constructors = self.token_constructors.saturating_add(1);
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        flatten_use_tree(&item.tree, &mut Vec::new(), &mut paths);
        self.renamed_authority_symbols
            .extend(paths.into_iter().filter(|path| {
                path.contains(" as ")
                    && [
                        "NativeOastProviderAdapter",
                        "NativeOastProviderPermit",
                        "NativeOastProviderMintToken",
                        "NativeOastProviderMintSeal",
                    ]
                    .iter()
                    .any(|symbol| path.contains(symbol))
            }));
        visit::visit_item_use(self, item);
    }
}

fn shared_provider_mint_contract_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    violations.extend(mint_token_shape_violations(&syntax));
    let authorities = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(record) if record.ident == "SharedWebRuntimeAuthority" => Some(record),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [authority] = authorities.as_slice() else {
        return Ok(vec![
            "the shared web runtime must declare exactly one SharedWebRuntimeAuthority".to_owned(),
        ]);
    };
    let minted_fields = authority
        .fields
        .iter()
        .filter(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|name| name == "native_oast_provider_minted")
        })
        .collect::<Vec<_>>();
    if minted_fields.len() != 1
        || !exact_nested_type(&minted_fields[0].ty, &["Arc", "Mutex", "bool"])
        || !has_exact_feature_cfg(&minted_fields[0].attrs, "oast-native-provider")
    {
        violations.push(
            "SharedWebRuntimeAuthority must retain one feature-gated Arc<Mutex<bool>> native OAST mint-once state shared across clones"
                .to_owned(),
        );
    }
    if !derives_any(&authority.attrs, &["Clone"]) {
        violations.push(
            "SharedWebRuntimeAuthority must clone the shared native OAST mint-once state rather than reset it per clone"
                .to_owned(),
        );
    }

    let mint_methods = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if implementation.trait_.is_none()
                    && type_path_tail(&implementation.self_ty).as_deref()
                        == Some("SharedWebRuntimeAuthority") =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .flat_map(|implementation| &implementation.items)
        .filter_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "mint_native_oast_provider" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = mint_methods.as_slice() else {
        violations.push(
            "SharedWebRuntimeAuthority must expose exactly one crate-private native OAST mint method"
                .to_owned(),
        );
        return Ok(violations);
    };
    let receiver_is_shared = matches!(
        method.sig.inputs.first(),
        Some(FnArg::Receiver(receiver)) if receiver.reference.is_some() && receiver.mutability.is_none()
    );
    let configuration_inputs = method
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            FnArg::Typed(argument) => Some(argument),
            FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    if !matches!(method.vis, Visibility::Restricted(_))
        || !receiver_is_shared
        || configuration_inputs.len() != 1
        || type_path_tail(&configuration_inputs[0].ty).as_deref()
            != Some("NativeOastProviderConfiguration")
        || !has_exact_feature_cfg(&method.attrs, "oast-native-provider")
    {
        violations.push(
            "the native OAST mint seam must remain one feature-gated crate-private &self method accepting only NativeOastProviderConfiguration"
                .to_owned(),
        );
    }

    let mut visitor = SharedProviderMintVisitor::default();
    visitor.visit_block(&method.block);
    for (binding, actual) in [
        ("shared mint-state lock", visitor.mint_state_locks),
        ("shared mint-state check", visitor.mint_state_checks),
        ("already-minted rejection", visitor.already_minted_errors),
        (
            "parent request-accounting clone",
            visitor.request_accounting_clones,
        ),
        ("parent budget", visitor.budget_reads),
        ("parent cancellation clone", visitor.cancellation_clones),
        ("parent deadline", visitor.deadline_reads),
        ("fixed adapter mint", visitor.adapter_mints),
        ("mint-state commit", visitor.mint_state_commits),
    ] {
        if actual != 1 {
            violations.push(format!(
                "the shared native OAST mint seam must contain exactly one {binding}; found {actual}"
            ));
        }
    }
    if visitor.adapter_mint_position.is_none()
        || visitor.mint_commit_position.is_none()
        || visitor.adapter_mint_position >= visitor.mint_commit_position
    {
        violations.push(
            "the shared native OAST authority must mark the mint complete only after adapter construction succeeds"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn mint_token_shape_violations(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();
    let seals = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(record) if record.ident == "NativeOastProviderMintSeal" => Some(record),
            _ => None,
        })
        .collect::<Vec<_>>();
    let seal_is_exact = matches!(seals.as_slice(), [seal]
        if matches!(seal.vis, Visibility::Inherited)
            && matches!(seal.fields, Fields::Unit)
            && has_exact_feature_cfg(&seal.attrs, "oast-native-provider")
            && !derives_any(&seal.attrs, &["Clone", "Copy", "Default", "Serialize", "Deserialize"]));
    if !seal_is_exact {
        violations.push(
            "the native OAST mint seal must remain one private, feature-gated, unconstructible unit type"
                .to_owned(),
        );
    }

    let tokens = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(record) if record.ident == "NativeOastProviderMintToken" => Some(record),
            _ => None,
        })
        .collect::<Vec<_>>();
    let token_is_exact = matches!(tokens.as_slice(), [token]
        if matches!(token.vis, Visibility::Restricted(_))
            && matches!(&token.fields, Fields::Unnamed(fields)
                if fields.unnamed.len() == 1
                    && fields.unnamed.first().is_some_and(|field|
                        matches!(field.vis, Visibility::Inherited)
                            && type_path_tail(&field.ty).as_deref()
                                == Some("NativeOastProviderMintSeal")))
            && has_exact_feature_cfg(&token.attrs, "oast-native-provider")
            && !derives_any(&token.attrs, &["Clone", "Copy", "Default", "Serialize", "Deserialize"]));
    if !token_is_exact {
        violations.push(
            "the native OAST mint token must remain one crate-private, feature-gated, move-only wrapper over the private seal"
                .to_owned(),
        );
    }

    for implementation in syntax.items.iter().filter_map(|item| match item {
        Item::Impl(implementation) => Some(implementation),
        _ => None,
    }) {
        if type_path_tail(&implementation.self_ty)
            .as_deref()
            .is_some_and(|name| {
                matches!(
                    name,
                    "NativeOastProviderMintSeal" | "NativeOastProviderMintToken"
                )
            })
        {
            violations.push(
                "the native OAST mint seal and token must expose no constructors or trait implementations"
                    .to_owned(),
            );
        }
    }
    violations
}

#[derive(Default)]
struct SharedProviderMintVisitor {
    position: usize,
    mint_state_locks: usize,
    mint_state_checks: usize,
    already_minted_errors: usize,
    request_accounting_clones: usize,
    budget_reads: usize,
    cancellation_clones: usize,
    deadline_reads: usize,
    adapter_mints: usize,
    mint_state_commits: usize,
    adapter_mint_position: Option<usize>,
    mint_commit_position: Option<usize>,
}

impl<'ast> Visit<'ast> for SharedProviderMintVisitor {
    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.position = self.position.saturating_add(1);
        let method = expression.method.to_string();
        let receiver_field = self_field_name(&expression.receiver);
        match (receiver_field.as_deref(), method.as_str()) {
            (Some("native_oast_provider_minted"), "lock") => {
                self.mint_state_locks = self.mint_state_locks.saturating_add(1)
            },
            (Some("request_accounting"), "clone") => {
                self.request_accounting_clones = self.request_accounting_clones.saturating_add(1)
            },
            (Some("cancellation"), "clone") => {
                self.cancellation_clones = self.cancellation_clones.saturating_add(1)
            },
            _ => {},
        }
        if path_expression_name(&expression.receiver).as_deref() == Some("timing")
            && method == "deadline"
        {
            self.deadline_reads = self.deadline_reads.saturating_add(1);
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
        if self_field_name_from_field(expression).as_deref() == Some("budget") {
            self.budget_reads = self.budget_reads.saturating_add(1);
        }
        visit::visit_expr_field(self, expression);
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        self.position = self.position.saturating_add(1);
        let called = expression_call_path(expression);
        if called.as_deref() == Some("NativeOastProviderAdapter::mint") {
            self.adapter_mints = self.adapter_mints.saturating_add(1);
            self.adapter_mint_position = Some(self.position);
        } else if called.as_deref() == Some("NativeOastProviderError::authority_already_minted") {
            self.already_minted_errors = self.already_minted_errors.saturating_add(1);
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        if is_dereferenced_binding(&expression.cond, "minted") {
            self.mint_state_checks = self.mint_state_checks.saturating_add(1);
        }
        visit::visit_expr_if(self, expression);
    }

    fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
        self.position = self.position.saturating_add(1);
        if is_dereferenced_binding(&expression.left, "minted")
            && matches!(
                expression.right.as_ref(),
                syn::Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Bool(value) if value.value)
            )
        {
            self.mint_state_commits = self.mint_state_commits.saturating_add(1);
            self.mint_commit_position = Some(self.position);
        }
        visit::visit_expr_assign(self, expression);
    }
}

fn self_field_name(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Field(field) = expression else {
        return None;
    };
    self_field_name_from_field(field)
}

fn self_field_name_from_field(expression: &syn::ExprField) -> Option<String> {
    let syn::Expr::Path(base) = expression.base.as_ref() else {
        return None;
    };
    if base.path.segments.len() != 1 || base.path.segments[0].ident != "self" {
        return None;
    }
    match &expression.member {
        syn::Member::Named(identifier) => Some(identifier.to_string()),
        syn::Member::Unnamed(_) => None,
    }
}

fn path_expression_name(expression: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expression else {
        return None;
    };
    (path.path.segments.len() == 1).then(|| path.path.segments[0].ident.to_string())
}

fn expression_call_path(expression: &syn::ExprCall) -> Option<String> {
    let syn::Expr::Path(path) = expression.func.as_ref() else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
    )
}

fn is_dereferenced_binding(expression: &syn::Expr, binding: &str) -> bool {
    let syn::Expr::Unary(unary) = expression else {
        return false;
    };
    if !matches!(unary.op, syn::UnOp::Deref(_)) {
        return false;
    }
    path_expression_name(&unary.expr).as_deref() == Some(binding)
}

fn exact_nested_type(ty: &Type, names: &[&str]) -> bool {
    let Some((expected, remaining)) = names.split_first() else {
        return false;
    };
    let Type::Path(path) = ty else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    if segment.ident != *expected {
        return false;
    }
    if remaining.is_empty() {
        return matches!(segment.arguments, PathArguments::None);
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let mut types = arguments.args.iter().filter_map(|argument| match argument {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    });
    let Some(inner) = types.next() else {
        return false;
    };
    types.next().is_none() && arguments.args.len() == 1 && exact_nested_type(inner, remaining)
}

fn derives_any(attributes: &[syn::Attribute], names: &[&str]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("derive")
            && attribute.meta.require_list().is_ok_and(|list| {
                list.tokens
                    .to_string()
                    .split(|character: char| !character.is_alphanumeric())
                    .any(|derived| names.contains(&derived))
            })
    })
}

fn has_exact_feature_cfg(attributes: &[syn::Attribute], feature: &str) -> bool {
    let expected = format!("feature=\"{feature}\"");
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute.meta.require_list().is_ok_and(|list| {
                list.tokens
                    .to_string()
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect::<String>()
                    == expected
            })
    })
}

fn feature_reaches(
    features: &toml::map::Map<String, toml::Value>,
    start: &str,
    target: &str,
) -> bool {
    let mut pending = vec![start];
    let mut visited = BTreeSet::new();
    while let Some(feature) = pending.pop() {
        if !visited.insert(feature) {
            continue;
        }
        if feature == target {
            return true;
        }
        if let Some(members) = features.get(feature).and_then(toml::Value::as_array) {
            pending.extend(
                members
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .filter(|member| {
                        !member.starts_with("dep:")
                            && !member.contains('/')
                            && features.contains_key(*member)
                    }),
            );
        }
    }
    false
}

fn server_surface_violations(
    server_source: &str,
    library_source: &str,
) -> Result<Vec<String>, syn::Error> {
    let server = syn::parse_file(server_source)?;
    let library = syn::parse_file(library_source)?;
    let mut violations = Vec::new();

    let provider_routers = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "provider_router" => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    if provider_routers.len() != 1
        || !matches!(provider_routers[0].vis, Visibility::Inherited)
        || !return_type_ends_with(&provider_routers[0].sig.output, "Router")
    {
        violations.push(format!(
            "{PACKAGE} must retain exactly one private provider_router returning Router"
        ));
    }

    for (name, expected_public) in [("serve_provider", true), ("serve_listener", false)] {
        let functions = server
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        let visibility_matches = functions.first().is_some_and(|function| {
            if expected_public {
                matches!(function.vis, Visibility::Public(_))
            } else {
                matches!(function.vis, Visibility::Inherited)
            }
        });
        if functions.len() != 1 || !visibility_matches {
            violations.push(format!(
                "{PACKAGE} server `{name}` visibility must remain exactly {}",
                if expected_public { "public" } else { "private" }
            ));
        }
    }
    let fixture_listeners = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "serve_provider_on_listener" => {
                Some(function)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    if fixture_listeners.len() != 1
        || !matches!(fixture_listeners[0].vis, Visibility::Public(_))
        || cfg_feature_names(&fixture_listeners[0].attrs)
            != BTreeSet::from(["test-support".to_owned()])
        || !has_doc_hidden(&fixture_listeners[0].attrs)
    {
        violations.push(format!(
            "{PACKAGE} fixture listener must be exactly public, doc-hidden, and gated only by `test-support`"
        ));
    }
    for function in server.items.iter().filter_map(|item| match item {
        Item::Fn(function) => Some(function),
        _ => None,
    }) {
        if matches!(function.vis, Visibility::Public(_))
            && !matches!(
                function.sig.ident.to_string().as_str(),
                "serve_provider" | "serve_provider_on_listener"
            )
        {
            violations.push(format!(
                "{PACKAGE} server must not export helper function `{}`",
                function.sig.ident
            ));
        }
    }

    let server_modules = library
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == "server" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    if server_modules.len() != 1
        || !matches!(server_modules[0].vis, Visibility::Inherited)
        || server_modules[0].content.is_some()
        || cfg_feature_names(&server_modules[0].attrs) != BTreeSet::from(["server".to_owned()])
    {
        violations.push(format!(
            "{PACKAGE} server module must remain private, external, and gated only by `server`"
        ));
    }

    let mut server_exports = BTreeSet::new();
    for item in &library.items {
        let Item::Use(import) = item else {
            continue;
        };
        if !matches!(import.vis, Visibility::Public(_)) {
            continue;
        }
        let mut paths = Vec::new();
        flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
        server_exports.extend(paths.into_iter().filter_map(|path| {
            let path = path.strip_prefix("crate::").unwrap_or(&path);
            path.starts_with("server::").then(|| {
                (
                    path.to_owned(),
                    cfg_feature_names(&import.attrs),
                    has_doc_hidden(&import.attrs),
                )
            })
        }));
    }
    if server_exports
        != BTreeSet::from([
            (
                "server::ProviderServerError".to_owned(),
                BTreeSet::from(["server".to_owned()]),
                false,
            ),
            (
                "server::serve_provider".to_owned(),
                BTreeSet::from(["server".to_owned()]),
                false,
            ),
            (
                "server::serve_provider_on_listener".to_owned(),
                BTreeSet::from(["test-support".to_owned()]),
                true,
            ),
        ])
    {
        violations.push(format!(
            "{PACKAGE} library must export only its server API plus the exact doc-hidden test-support listener fixture"
        ));
    }

    Ok(violations)
}

fn return_type_ends_with(output: &ReturnType, expected: &str) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == expected)
}

fn cfg_feature_names(attributes: &[syn::Attribute]) -> BTreeSet<String> {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .filter_map(|attribute| attribute.meta.require_list().ok())
        .filter_map(|list| {
            let compact = list
                .tokens
                .to_string()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>();
            compact
                .strip_prefix("feature=\"")
                .and_then(|value| value.strip_suffix('"'))
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn has_doc_hidden(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("doc")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "hidden")
    })
}

fn flatten_use_tree(tree: &UseTree, prefix: &mut Vec<String>, output: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(&path.tree, prefix, output);
            prefix.pop();
        },
        UseTree::Name(name) => {
            let mut path = prefix.clone();
            path.push(name.ident.to_string());
            output.push(path.join("::"));
        },
        UseTree::Rename(rename) => {
            let mut path = prefix.clone();
            path.push(format!("{} as {}", rename.ident, rename.rename));
            output.push(path.join("::"));
        },
        UseTree::Glob(_) => {
            let mut path = prefix.clone();
            path.push("*".to_owned());
            output.push(path.join("::"));
        },
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix, output);
            }
        },
    }
}

fn server_transport_contract_violations(source: &str) -> Vec<String> {
    let compact = compact_whitespace(source);
    let required_once = [
        "letpermits=usize::from(provider.max_concurrent_requests());",
        "Semaphore::new(permits)",
        "Arc::clone(&self.requests).acquire_owned().await",
        "letconnection_limit=usize::from(provider.max_concurrent_requests());",
        "letmutconnections=FuturesUnordered::new();",
        "ifconnections.len()>=connection_limit{let_=connections.next().await;continue;}",
        "ifconnections.is_empty(){",
        "tokio::select!{",
        "_=connections.next()=>{}",
        "http1::Builder::new().serve_connection(TokioIo::new(stream),service).await",
    ];
    let mut violations = Vec::new();
    for required in required_once {
        if compact.matches(required).count() != 1 {
            violations.push(format!(
                "{PACKAGE} bounded server transport must contain exactly one `{required}` contract"
            ));
        }
    }
    for (required, count) in [
        ("listener.accept()", 2),
        (
            "connections.push(serve_connection(router.clone(),stream));",
            2,
        ),
    ] {
        if compact.matches(required).count() != count {
            violations.push(format!(
                "{PACKAGE} bounded server transport must contain exactly {count} `{required}` sites"
            ));
        }
    }
    for forbidden in [
        "try_acquire",
        "axum::serve",
        "hyper::Server",
        "tokio::spawn",
    ] {
        if compact.contains(forbidden) {
            violations.push(format!(
                "{PACKAGE} bounded server transport must not use `{forbidden}`"
            ));
        }
    }
    violations
}

fn compact_whitespace(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn production_prefix(source: &str) -> &str {
    let normalized_marker = "#[cfg(test)]\nmod tests";
    let windows_marker = "#[cfg(test)]\r\nmod tests";
    source
        .rfind(normalized_marker)
        .or_else(|| source.rfind(windows_marker))
        .map_or(source, |boundary| &source[..boundary])
}

/// Removes only the exact scanner OAST test modules from a source file.
///
/// Unlike `production_prefix`, this preserves production items that follow a
/// focused test module. Each removed slice must independently parse as one
/// Rust module, so a malformed or broadened cfg guard fails closed.
fn source_without_exact_oast_test_modules(source: &str) -> Result<String, syn::Error> {
    const TEST_GUARDS: [&str; 2] = [
        "#[cfg(all(test, feature = \"oast-correlation\"))]",
        "#[cfg(all(test, feature = \"oast-native-provider\"))]",
    ];

    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    loop {
        let next = TEST_GUARDS
            .iter()
            .filter_map(|guard| source[cursor..].find(guard).map(|offset| (offset, *guard)))
            .min_by_key(|(offset, _)| *offset);
        let Some((offset, guard)) = next else {
            output.push_str(&source[cursor..]);
            return Ok(output);
        };
        let start = cursor + offset;
        output.push_str(&source[cursor..start]);

        let after_guard = start + guard.len();
        let module_start = source[after_guard..]
            .find(|character: char| !character.is_whitespace())
            .map(|offset| after_guard + offset);
        let Some(module_start) = module_start else {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "OAST test cfg guard has no following module",
            ));
        };
        if !source[module_start..].starts_with("mod ") {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "OAST test cfg guard must apply directly to a module",
            ));
        }

        let mut end = None;
        for (relative, character) in source[module_start..].char_indices() {
            if character != '}' {
                continue;
            }
            let candidate_end = module_start + relative + character.len_utf8();
            let candidate = &source[start..candidate_end];
            if syn::parse_str::<syn::ItemMod>(candidate).is_ok() {
                end = Some(candidate_end);
                break;
            }
        }
        let Some(candidate_end) = end else {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "OAST test cfg guard did not contain one complete module",
            ));
        };
        cursor = candidate_end;
    }
}

fn state_shape_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    for item in syntax.items {
        let Item::Struct(record) = item else {
            continue;
        };
        let Fields::Named(fields) = record.fields else {
            continue;
        };
        for field in fields.named {
            let Some(identifier) = field.ident else {
                continue;
            };
            let normalized = identifier.to_string().to_ascii_lowercase();
            if FORBIDDEN_STATE_FIELDS.contains(&normalized.as_str()) {
                violations.push(format!(
                    "{PACKAGE} state must not retain raw callback field `{identifier}`"
                ));
            }
        }
    }
    Ok(violations)
}

fn secret_surface_violations(
    source: &str,
    expected: &[(&str, &str)],
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();

    for (name, redacted_marker) in expected {
        let records = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(record) if record.ident == *name => Some(record),
                _ => None,
            })
            .collect::<Vec<_>>();
        if records.len() != 1 {
            violations.push(format!(
                "{PACKAGE} secret surface must declare exactly one `{name}`"
            ));
            continue;
        }
        let record = records[0];
        if record
            .fields
            .iter()
            .any(|field| !matches!(field.vis, Visibility::Inherited))
        {
            violations.push(format!(
                "{PACKAGE} secret surface `{name}` fields must remain private"
            ));
        }
        for attribute in &record.attrs {
            if !attribute.path().is_ident("derive") {
                continue;
            }
            let derives = attribute
                .meta
                .require_list()
                .map(|list| list.tokens.to_string())
                .unwrap_or_default();
            if ["Clone", "Copy", "Serialize", "Deserialize"]
                .iter()
                .any(|forbidden| {
                    derives
                        .split(|character: char| !character.is_alphanumeric())
                        .any(|derived| derived == *forbidden)
                })
            {
                violations.push(format!(
                    "{PACKAGE} secret surface `{name}` must remain move-only and non-serializable"
                ));
            }
        }

        let mut debug_implementations = 0_usize;
        for implementation in syntax.items.iter().filter_map(|item| match item {
            Item::Impl(implementation) => Some(implementation),
            _ => None,
        }) {
            if type_path_tail(&implementation.self_ty).as_deref() != Some(*name) {
                continue;
            }
            let Some((_, trait_path, _)) = &implementation.trait_ else {
                continue;
            };
            let trait_name = trait_path
                .segments
                .last()
                .map(|segment| segment.ident.to_string());
            match trait_name.as_deref() {
                Some("Debug") => debug_implementations += 1,
                Some("Clone" | "Copy" | "Serialize" | "Deserialize") => violations.push(format!(
                    "{PACKAGE} secret surface `{name}` must not implement `{}`",
                    trait_name.as_deref().unwrap_or_default()
                )),
                _ => {},
            }
        }
        if debug_implementations != 1 || !source.contains(redacted_marker) {
            violations.push(format!(
                "{PACKAGE} secret surface `{name}` must have exactly one redacted Debug implementation"
            ));
        }
    }

    Ok(violations)
}

fn type_path_tail(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn release_isolation_violations(workspace_root: &Path) -> io::Result<Vec<String>> {
    let cli_manifest = fs::read_to_string(workspace_root.join(CLI_MANIFEST))?;
    let release_workflow = fs::read_to_string(workspace_root.join(RELEASE_WORKFLOW))?;
    Ok(release_isolation_source_violations(
        &cli_manifest,
        &release_workflow,
    ))
}

fn release_isolation_source_violations(cli_manifest: &str, release_workflow: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if cli_manifest.contains(PACKAGE) || cli_manifest.contains("termivar-oast-provider") {
        violations.push(format!(
            "termivar-cli and release-bundle must not depend on or expose {PACKAGE}"
        ));
    }
    if release_workflow.contains(PACKAGE) || release_workflow.contains("termivar-oast-provider") {
        violations.push(
            "release workflow must not build, package, attest, or publish the native OAST provider"
                .to_owned(),
        );
    }
    if !release_workflow.contains(EXACT_RELEASE_BUILD)
        || release_workflow.contains("cargo build --workspace")
        || release_workflow.contains("cargo build --all")
    {
        violations.push(
            "release workflow must remain scoped to the exact termivar-cli release-bundle build"
                .to_owned(),
        );
    }
    violations
}

fn advisory_policy_violations(workspace_root: &Path) -> io::Result<Vec<String>> {
    let deny_config = fs::read_to_string(workspace_root.join(DENY_CONFIG))?;
    let audit_script = fs::read_to_string(workspace_root.join(AUDIT_SCRIPT))?;
    Ok(advisory_policy_source_violations(
        &deny_config,
        &audit_script,
    ))
}

fn advisory_policy_source_violations(deny_config: &str, audit_script: &str) -> Vec<String> {
    let mut violations = Vec::new();
    let deny_value = toml::from_str::<toml::Value>(deny_config);
    let empty_deny_ignore = deny_value.as_ref().ok().is_some_and(|config| {
        config
            .get("advisories")
            .and_then(|advisories| advisories.get("ignore"))
            .and_then(toml::Value::as_array)
            .is_some_and(Vec::is_empty)
    });
    if !empty_deny_ignore {
        violations.push(
            "native OAST dependency policy requires an explicit empty advisory ignore list"
                .to_owned(),
        );
    }

    if audit_script
        .split_whitespace()
        .any(|token| token == "--ignore" || token.starts_with("--ignore="))
    {
        violations.push(
            "native OAST dependency policy forbids cargo-audit ignore or stale-database flags"
                .to_owned(),
        );
    }
    violations
}

fn rust_sources_below(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.retain(|path| path.extension().is_some_and(|extension| extension == "rs"));
    Ok(files)
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_files(&entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn normalized_relative(root: &Path, path: &Path) -> io::Result<String> {
    path.strip_prefix(root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_workspace_native_oast_contract_is_green() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below the workspace root");
        let violations = check(workspace_root).expect("native OAST architecture check");
        assert!(
            violations.is_empty(),
            "native OAST architecture violations: {violations:#?}"
        );
    }

    #[test]
    fn provider_feature_contract_is_exact_and_non_default() {
        let valid = BTreeMap::from([
            (
                "client".to_owned(),
                vec![
                    "dep:reqwest".to_owned(),
                    "dep:serde_json".to_owned(),
                    "dep:tokio".to_owned(),
                    "dep:tokio-util".to_owned(),
                ],
            ),
            ("default".to_owned(), Vec::new()),
            (
                "server".to_owned(),
                vec![
                    "dep:axum".to_owned(),
                    "dep:clap".to_owned(),
                    "dep:futures".to_owned(),
                    "dep:hyper".to_owned(),
                    "dep:hyper-util".to_owned(),
                    "dep:serde_json".to_owned(),
                    "dep:tokio".to_owned(),
                    "dep:tower".to_owned(),
                ],
            ),
            ("test-support".to_owned(), vec!["server".to_owned()]),
        ]);
        assert!(feature_contract_violations(&valid).is_empty());

        let mut default_on = valid.clone();
        default_on
            .get_mut("default")
            .unwrap()
            .push("server".to_owned());
        assert!(!feature_contract_violations(&default_on).is_empty());

        let mut widened = valid;
        widened
            .get_mut("server")
            .unwrap()
            .push("dep:termivar-scanner".to_owned());
        assert!(!feature_contract_violations(&widened).is_empty());
    }

    fn dependency_graph(
        entries: &[(&str, &str, &[&str])],
    ) -> (BTreeMap<String, String>, BTreeMap<String, BTreeSet<String>>) {
        let names = entries
            .iter()
            .map(|(id, name, _)| ((*id).to_owned(), (*name).to_owned()))
            .collect();
        let edges = entries
            .iter()
            .map(|(id, _, dependencies)| {
                (
                    (*id).to_owned(),
                    dependencies
                        .iter()
                        .map(|dependency| (*dependency).to_owned())
                        .collect(),
                )
            })
            .collect();
        (names, edges)
    }

    #[test]
    fn provider_server_crypto_gate_remains_strict_and_closure_scoped() {
        let allowed = [
            ("provider", PACKAGE, &["sha", "subtle", "random"][..]),
            ("sha", "sha2", &[][..]),
            ("subtle", "subtle", &[][..]),
            ("random", "getrandom", &[][..]),
            ("unrelated-ring", "ring", &[][..]),
        ];
        let (names, edges) = dependency_graph(&allowed);
        assert!(dependency_closure_crypto_violations("provider", &names, &edges).is_empty());

        for forbidden in [
            "rsa",
            "ring",
            "openssl-sys",
            "aws-lc-rs",
            "aes-gcm",
            "chacha20poly1305",
            "x25519-dalek",
            "ed25519-dalek",
        ] {
            let graph = [
                ("provider", PACKAGE, &["wrapper"][..]),
                ("wrapper", "transport-wrapper", &["renamed-edge"][..]),
                ("renamed-edge", forbidden, &[][..]),
            ];
            let (names, edges) = dependency_graph(&graph);
            let violations = dependency_closure_crypto_violations("provider", &names, &edges);
            assert_eq!(violations.len(), 1, "{forbidden}: {violations:?}");
            assert!(violations[0].contains(forbidden));
        }
    }

    #[test]
    fn reviewed_client_crypto_gate_allows_only_tls_ring_not_application_crypto() {
        let allowed = [
            ("provider", PACKAGE, &["reqwest"] as &[&str]),
            ("reqwest", "reqwest", &["rustls"]),
            ("rustls", "rustls", &["webpki", "ring"]),
            ("webpki", "rustls-webpki", &["ring"]),
            ("ring", "ring", &[]),
            ("unrelated-rsa", "rsa", &[]),
        ];
        let (names, edges) = dependency_graph(&allowed);
        assert!(dependency_closure_crypto_violations_with_reviewed_ring(
            "provider", &names, &edges
        )
        .is_empty());

        for forbidden in [
            "rsa",
            "openssl-sys",
            "aws-lc-rs",
            "aes-gcm",
            "chacha20poly1305",
            "x25519-dalek",
            "ed25519-dalek",
        ] {
            let graph = [
                ("provider", PACKAGE, &["reqwest"] as &[&str]),
                ("reqwest", "reqwest", &["rustls", "bad"]),
                ("rustls", "rustls", &["webpki", "ring"]),
                ("webpki", "rustls-webpki", &["ring"]),
                ("ring", "ring", &[]),
                ("bad", forbidden, &[]),
            ];
            let (names, edges) = dependency_graph(&graph);
            let violations =
                dependency_closure_crypto_violations_with_reviewed_ring("provider", &names, &edges);
            assert_eq!(violations.len(), 1, "{forbidden}: {violations:?}");
            assert!(violations[0].contains(forbidden));
        }
    }

    #[test]
    fn scanner_feature_reachability_keeps_native_adapter_out_of_aggregates() {
        let manifest = toml::from_str::<toml::Value>(
            r#"
                [features]
                default = ["scanning"]
                scanning = []
                oast-correlation = []
                oast-native-provider = ["scanning", "oast-correlation", "dep:termivar-oast"]
                full = ["scanning", "oast-correlation"]
                enterprise = ["full"]
                research = ["full"]
            "#,
        )
        .unwrap();
        let features = manifest["features"].as_table().unwrap();
        for aggregate in ["default", "full", "enterprise", "research"] {
            assert!(!feature_reaches(
                features,
                aggregate,
                "oast-native-provider"
            ));
        }
        assert!(feature_reaches(
            features,
            "oast-native-provider",
            "oast-native-provider"
        ));

        let widened = toml::from_str::<toml::Value>(
            r#"
                [features]
                default = ["scanning"]
                scanning = []
                oast-native-provider = ["scanning"]
                full = ["oast-native-provider"]
            "#,
        )
        .unwrap();
        assert!(feature_reaches(
            widened["features"].as_table().unwrap(),
            "full",
            "oast-native-provider"
        ));
    }

    #[test]
    fn provider_crypto_gate_fails_closed_when_resolve_root_is_missing() {
        let (names, edges) = dependency_graph(&[("other", "ring", &[])]);
        let violations = dependency_closure_crypto_violations("provider", &names, &edges);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("absent"));
    }

    fn valid_server_source() -> &'static str {
        r#"
            fn provider_router(provider: ProviderState) -> Router { todo!() }
            pub async fn serve_provider(provider: ProviderState) -> Result<(), Error> { todo!() }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub async fn serve_provider_on_listener(listener: TcpListener, provider: ProviderState) -> Result<(), Error> {
                serve_listener(listener, provider).await
            }
            async fn serve_listener(listener: TcpListener, provider: ProviderState) -> Result<(), Error> {
                let connection_limit = usize::from(provider.max_concurrent_requests());
                let router = provider_router(provider);
                let mut connections = FuturesUnordered::new();
                loop {
                    if connections.len() >= connection_limit {
                        let _ = connections.next().await;
                        continue;
                    }
                    if connections.is_empty() {
                        let (stream, _) = listener.accept().await.map_err(|_| Error)?;
                        connections.push(serve_connection(router.clone(), stream));
                        continue;
                    }
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (stream, _) = accepted.map_err(|_| Error)?;
                            connections.push(serve_connection(router.clone(), stream));
                        }
                        _ = connections.next() => {}
                    }
                }
            }
            async fn serve_connection(router: Router, stream: TcpStream) -> Result<(), Error> {
                let service = service_fn();
                http1::Builder::new().serve_connection(TokioIo::new(stream), service).await
            }
            struct AppState { requests: Semaphore }
            impl AppState {
                fn new(provider: ProviderState) -> Self {
                    let permits = usize::from(provider.max_concurrent_requests());
                    Self { requests: Semaphore::new(permits) }
                }
                async fn admit(&self) {
                    Arc::clone(&self.requests).acquire_owned().await;
                }
            }
        "#
    }

    fn valid_library_source() -> &'static str {
        r#"
            #[cfg(feature = "server")]
            mod server;
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub use server::serve_provider_on_listener;
            #[cfg(feature = "server")]
            pub use server::{serve_provider, ProviderServerError};
        "#
    }

    #[test]
    fn provider_router_and_server_exports_are_exactly_private() {
        assert!(
            server_surface_violations(valid_server_source(), valid_library_source())
                .unwrap()
                .is_empty()
        );

        for (server, library) in [
            (
                valid_server_source().replacen("fn provider_router", "pub fn provider_router", 1),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "async fn serve_listener",
                    "pub async fn serve_listener",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().to_owned(),
                valid_library_source().replacen("mod server", "pub mod server", 1),
            ),
            (
                valid_server_source().to_owned(),
                valid_library_source().replace(
                    "serve_provider, ProviderServerError",
                    "serve_provider, ProviderServerError, provider_router",
                ),
            ),
        ] {
            assert!(!server_surface_violations(&server, &library)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn native_client_keeps_fixed_routes_hardened_transport_and_no_drop_network() {
        let source = include_str!("../../../crates/termivar-oast/src/client.rs");
        let production = production_prefix(source);
        assert!(
            client_transport_contract_violations(production)
                .unwrap()
                .is_empty(),
            "repository native OAST client drifted from its fixed transport contract"
        );

        for mutation in [
            production.replacen("RedirectPolicy::none()", "RedirectPolicy::limited(1)", 1),
            production.replacen(".no_proxy()", ".proxy(proxy)", 1),
            production.replacen("/v1/sessions/{}/events", "/arbitrary/{}/events", 1),
            format!("{production}\npub fn arbitrary(url: Url) {{ let _ = url; }}"),
            format!("{production}\nimpl Drop for NativeOastClient {{ fn drop(&mut self) {{}} }}"),
        ] {
            assert!(
                !client_transport_contract_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "native client transport mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn connection_accept_loop_is_bounded_and_mutations_fail_closed() {
        assert!(server_transport_contract_violations(valid_server_source()).is_empty());

        for mutation in [
            valid_server_source().replace(
                "usize::from(provider.max_concurrent_requests())",
                "usize::from(provider.max_concurrent_requests()) + 1",
            ),
            valid_server_source().replace(
                "if connections.len() >= connection_limit",
                "if false && connections.len() >= connection_limit",
            ),
            valid_server_source().replace("FuturesUnordered::new()", "Vec::new()"),
            format!(
                "{}\nasync fn escape(listener: TcpListener) {{ let _ = listener.accept().await; }}",
                valid_server_source()
            ),
            format!(
                "{}\nasync fn escape() {{ tokio::spawn(async {{}}); }}",
                valid_server_source()
            ),
            valid_server_source().replace(
                "http1::Builder::new().serve_connection(TokioIo::new(stream), service).await",
                "axum::serve(listener, router).await",
            ),
        ] {
            assert!(!server_transport_contract_violations(&mutation).is_empty());
        }
    }

    #[test]
    fn native_oast_dependency_policy_cannot_add_advisory_ignores() {
        let deny = "[advisories]\nignore = []\n";
        let audit = "cargo-audit audit --file Cargo.lock";
        assert!(advisory_policy_source_violations(deny, audit).is_empty());

        assert!(!advisory_policy_source_violations(
            "[advisories]\nignore = [\"RUSTSEC-2023-0071\"]\n",
            audit,
        )
        .is_empty());
        assert!(!advisory_policy_source_violations(
            deny,
            "cargo-audit audit --ignore RUSTSEC-2023-0071 --file Cargo.lock",
        )
        .is_empty());
    }

    #[test]
    fn raw_callback_fields_are_rejected_from_provider_state() {
        assert!(state_shape_violations(
            "struct Event { event_id: String, callback_id: String, duplicate_count: u16 }"
        )
        .unwrap()
        .is_empty());
        for field in FORBIDDEN_STATE_FIELDS {
            let source = format!("struct Event {{ {field}: String }}");
            let violations = state_shape_violations(&source).unwrap();
            assert_eq!(violations.len(), 1, "{field}");
        }
    }

    #[test]
    fn provider_secret_surfaces_remain_move_only_private_and_redacted() {
        let valid = r#"
            struct AdminToken { bytes: Vec<u8> }
            impl fmt::Debug for AdminToken {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("AdminToken(<redacted>)")
                }
            }
        "#;
        let expected = [("AdminToken", "AdminToken(<redacted>)")];
        assert!(secret_surface_violations(valid, &expected)
            .unwrap()
            .is_empty());

        for mutation in [
            valid.replacen("struct AdminToken", "#[derive(Clone)] struct AdminToken", 1),
            valid.replacen("bytes: Vec<u8>", "pub bytes: Vec<u8>", 1),
            format!("{valid}\nimpl Serialize for AdminToken {{}}"),
            valid.replace("AdminToken(<redacted>)", "AdminToken(secret)"),
            valid.replacen(
                "impl fmt::Debug for AdminToken",
                "impl Clone for AdminToken",
                1,
            ),
        ] {
            assert!(!secret_surface_violations(&mutation, &expected)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn provider_cannot_enter_release_bundle_or_release_workflow() {
        let cli = "[features]\ndefault=[]\nrelease-bundle=[\"rest-review\"]\n";
        let workflow = EXACT_RELEASE_BUILD;
        assert!(release_isolation_source_violations(cli, workflow).is_empty());

        let widened_cli = format!("{cli}\n{PACKAGE} = {{ path = \"../termivar-oast\" }}");
        assert!(!release_isolation_source_violations(&widened_cli, workflow).is_empty());
        let widened_workflow =
            format!("{workflow}\ncargo build -p termivar-oast --bin termivar-oast-provider");
        assert!(!release_isolation_source_violations(cli, &widened_workflow).is_empty());
    }

    #[test]
    fn background_work_is_checked_only_in_production_source() {
        let production = "fn serve() { tokio::spawn(async {}); }";
        assert!(production_prefix(production).contains("tokio::spawn"));

        let test_only =
            "fn serve() {}\n#[cfg(test)]\nmod tests { fn fixture() { tokio::spawn(async {}); } }";
        assert!(!production_prefix(test_only).contains("tokio::spawn"));
    }

    #[test]
    fn exact_oast_feature_test_modules_are_removed_without_hiding_later_production() {
        let source = r#"
            fn before() {}
            #[cfg(all(test, feature = "oast-native-provider"))]
            mod permit_tests {
                fn fixture() { reqwest::Client::new(); }
            }
            fn between() { NativeOastClient::new(); }
            #[cfg(all(test, feature = "oast-correlation"))]
            mod tests {
                fn fixture() { tokio::spawn(async {}); }
            }
            fn after() {}
        "#;
        let production = source_without_exact_oast_test_modules(source).unwrap();
        assert!(production.contains("fn before()"));
        assert!(production.contains("fn between() { NativeOastClient::new(); }"));
        assert!(production.contains("fn after()"));
        assert!(!production.contains("reqwest::Client"));
        assert!(!production.contains("tokio::spawn"));

        let broadened = source.replace(
            "all(test, feature = \"oast-native-provider\")",
            "any(test, feature = \"oast-native-provider\")",
        );
        let broadened_production = source_without_exact_oast_test_modules(&broadened).unwrap();
        assert!(broadened_production.contains("reqwest::Client"));
    }

    #[test]
    fn native_adapter_and_permit_mint_consumers_are_exact_and_fail_closed() {
        let authority = (
            "web_runtime/authority.rs".to_owned(),
            r#"
                fn mint() {
                    NativeOastProviderAdapter::mint(
                        NativeOastProviderMintToken(NativeOastProviderMintSeal),
                    );
                }
            "#
            .to_owned(),
        );
        let adapter = (
            SCANNER_ADAPTER.to_owned(),
            "fn mint_permit() { NativeOastProviderPermit::mint(); }".to_owned(),
        );
        let valid = vec![authority.clone(), adapter.clone()];
        assert!(sealed_mint_consumer_violations(&valid).unwrap().is_empty());

        for escape in [
            "plugin.rs",
            "lua.rs",
            "exploit.rs",
            "legacy_scanner.rs",
            "other_scanner_module.rs",
        ] {
            let mut widened = valid.clone();
            widened.push((
                escape.to_owned(),
                "fn escape() { NativeOastProviderAdapter::mint(); }".to_owned(),
            ));
            assert!(
                !sealed_mint_consumer_violations(&widened)
                    .unwrap()
                    .is_empty(),
                "forbidden adapter mint consumer {escape} unexpectedly passed"
            );
        }

        for widened in [
            vec![
                authority.clone(),
                adapter.clone(),
                (
                    "other.rs".to_owned(),
                    "fn escape() { NativeOastProviderPermit::mint(); }".to_owned(),
                ),
            ],
            vec![
                authority.clone(),
                adapter.clone(),
                (
                    "other.rs".to_owned(),
                    "fn escape() { NativeOastProviderMintToken(NativeOastProviderMintSeal); }"
                        .to_owned(),
                ),
            ],
            vec![
                authority,
                adapter,
                (
                    "other.rs".to_owned(),
                    "use crate::native_oast_provider::NativeOastProviderAdapter as Escape;"
                        .to_owned(),
                ),
            ],
        ] {
            assert!(!sealed_mint_consumer_violations(&widened)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn native_adapter_mint_token_remains_private_move_only_and_unconstructible() {
        let valid = syn::parse_file(
            r#"
                #[cfg(feature = "oast-native-provider")]
                struct NativeOastProviderMintSeal;
                #[cfg(feature = "oast-native-provider")]
                pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);
            "#,
        )
        .unwrap();
        assert!(mint_token_shape_violations(&valid).is_empty());

        for mutation in [
            r#"
                #[cfg(feature = "oast-native-provider")]
                pub(crate) struct NativeOastProviderMintSeal;
                #[cfg(feature = "oast-native-provider")]
                pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);
            "#,
            r#"
                #[cfg(feature = "oast-native-provider")]
                struct NativeOastProviderMintSeal;
                #[cfg(feature = "oast-native-provider")]
                #[derive(Clone)]
                pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);
            "#,
            r#"
                #[cfg(feature = "oast-native-provider")]
                struct NativeOastProviderMintSeal;
                #[cfg(feature = "oast-native-provider")]
                pub(crate) struct NativeOastProviderMintToken(pub(crate) NativeOastProviderMintSeal);
            "#,
            r#"
                #[cfg(feature = "oast-native-provider")]
                struct NativeOastProviderMintSeal;
                #[cfg(feature = "oast-native-provider")]
                pub(crate) struct NativeOastProviderMintToken(NativeOastProviderMintSeal);
                impl NativeOastProviderMintToken { fn forge() -> Self { todo!() } }
            "#,
        ] {
            let syntax = syn::parse_file(mutation).unwrap();
            assert!(!mint_token_shape_violations(&syntax).is_empty());
        }
    }
}
