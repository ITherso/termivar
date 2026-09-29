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
use sha2::{Digest, Sha256};
use syn::{
    parse::Parser,
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
const SCANNER_HTTP_EVIDENCE: &str = "http_evidence.rs";
const SCANNER_REQUEST_BROKER: &str = "http_evidence/request_broker.rs";
const SSRF_OAST_REVIEW_CONTRACT: &str = "ssrf_oast_review.rs";
const SSRF_OAST_REVIEW_RUNTIME: &str = "web_runtime/ssrf_oast_runtime.rs";
const XML_EXTERNAL_ENTITY_REVIEW_CONTRACT: &str = "xml_external_entity_review.rs";
const XML_EXTERNAL_ENTITY_REVIEW_RUNTIME: &str = "web_runtime/xml_external_entity_runtime.rs";
const SSRF_OAST_REVIEW_TESTS: &str = "web_runtime/assessment_review_tests.rs";
const WEB_RUNTIME_TESTS: &str = "web_runtime_tests.rs";
const ASSESSMENT_REVIEW_SOURCE: &str = "web_runtime/assessment_review.rs";
const WEB_RUNTIME_SOURCE: &str = "web_runtime.rs";
const EXACT_SCANNER_PROVIDER_CONSUMERS: &[&str] = &[
    SCANNER_ADAPTER,
    SSRF_OAST_REVIEW_CONTRACT,
    SSRF_OAST_REVIEW_RUNTIME,
    XML_EXTERNAL_ENTITY_REVIEW_RUNTIME,
    XML_EXTERNAL_ENTITY_REVIEW_CONTRACT,
];
const EXACT_TEST_ONLY_PROVIDER_CONSUMERS: &[&str] = &[SSRF_OAST_REVIEW_TESTS, WEB_RUNTIME_TESTS];
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
    "libc",
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
    violations.extend(feature_crypto_dependency_violations(
        workspace_root,
        "owned-https-test-profile",
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
        dependency.rename.is_some()
            || dependency.path.is_some()
            || !dependency_platform_is_allowed(
                &dependency.name,
                dependency
                    .target
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                dependency.optional,
            )
    }) {
        violations.push(format!(
            "{PACKAGE} dependencies must not be renamed or local; only optional server libc may target cfg(unix)"
        ));
    }
    violations
}

fn dependency_platform_is_allowed(name: &str, target: Option<&str>, optional: bool) -> bool {
    if name == "libc" {
        optional && target == Some("cfg(unix)")
    } else {
        target.is_none()
    }
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
            "owned-https-test-profile".to_owned(),
            BTreeSet::from(["client"]),
        ),
        (
            "server".to_owned(),
            BTreeSet::from([
                "dep:axum",
                "dep:clap",
                "dep:futures",
                "dep:hyper",
                "dep:hyper-util",
                "dep:libc",
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
            "{PACKAGE} features must remain the exact non-default client/server/test-support/owned-HTTPS boundary"
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
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["termivar-cli", "termivar-scanner"])
    {
        violations.push(format!(
            "{PACKAGE} must have exactly the scanner runtime consumer and CLI test-only consumer; found {:?}",
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
    if let Some(cli) = consumers
        .iter()
        .copied()
        .find(|package| package.name == "termivar-cli")
    {
        let development_edges = cli
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
                    == BTreeSet::from(["client", "owned-https-test-profile", "test-support"]));
        if !development_is_exact {
            violations.push(
                "termivar-cli must isolate the owned HTTPS actual-CLI fixture to one default-disabled client+test-support+owned-https-test-profile dev-dependency"
                    .to_owned(),
            );
        }
        if cli.dependencies.iter().any(|dependency| {
            dependency.name == PACKAGE && dependency.kind != DependencyKind::Development
        }) {
            violations.push(format!(
                "termivar-cli must not add a production, build, or unknown dependency edge to {PACKAGE}"
            ));
        }
    }
    if let Some(cli) = packages
        .iter()
        .copied()
        .find(|package| package.name == "termivar-cli")
    {
        violations.extend(cli_owned_https_tls_dependency_violations(&cli.dependencies));
    }
    violations
}

fn cli_owned_https_tls_dependency_violations(
    dependencies: &[cargo_metadata::Dependency],
) -> Vec<String> {
    let edges = dependencies
        .iter()
        .filter(|dependency| dependency.name == "tokio-rustls")
        .collect::<Vec<_>>();
    let exact = matches!(edges.as_slice(), [dependency]
        if dependency.kind == DependencyKind::Development
            && !dependency.optional
            && !dependency.uses_default_features
            && dependency.rename.is_none()
            && dependency.path.is_none()
            && dependency.target.is_none()
            && dependency.features.iter().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["ring", "tls12"]));
    if exact {
        Vec::new()
    } else {
        vec![
            "termivar-cli owned HTTPS fixture must use exactly one unrenamed, unconditional, non-optional, default-disabled tokio-rustls development edge with only ring and tls12"
                .to_owned(),
        ]
    }
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
    violations.extend(owned_https_profile_port_surface_violations(
        production_prefix(&client_source),
    )?);
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
        ".tls_built_in_root_certs(false)",
        ".add_root_certificate(root_certificate)",
        ".resolve(OWNED_HTTPS_TEST_PROVIDER_HOST,profile_port.resolved_address(),)",
        "constOWNED_HTTPS_TEST_PROVIDER_HOST:&str=\"oast-provider.termivar.test\";",
        "constOWNED_HTTPS_TEST_PROVIDER_ORIGIN:&str=\"https://oast-provider.termivar.test/\";",
        "constOWNED_HTTPS_TEST_PROVIDER_IPV6:Ipv6Addr=Ipv6Addr::LOCALHOST;",
        "public_origin.as_str()!=OWNED_HTTPS_TEST_PROVIDER_ORIGIN",
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
    if !owned_https_client_constructor_is_exact(&syntax) {
        violations.push(format!(
            "{PACKAGE} owned HTTPS client constructor must retain its exact origin guard, parsed origin, reviewed root, fixed resolver, and final client fields"
        ));
    }
    if !owned_https_client_identity_constants_are_exact(&syntax) {
        violations.push(format!(
            "{PACKAGE} owned HTTPS client must retain exactly one feature-gated reviewed host, origin, IPv6 loopback, and root-byte identity"
        ));
    }
    if !owned_https_client_base64_import_is_exact(&syntax) {
        violations.push(format!(
            "{PACKAGE} owned HTTPS client must retain the exact feature-gated base64 STANDARD and Engine-as-underscore import"
        ));
    }
    if !fixed_client_builder_is_exact(&syntax) {
        violations.push(format!(
            "{PACKAGE} fixed client builder must retain its exact private signature and hardened transport chain"
        ));
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

fn owned_https_client_identity_constants_are_exact(syntax: &syn::File) -> bool {
    const FEATURE: &str = "owned-https-test-profile";
    let constants = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(constant)
                if matches!(
                    constant.ident.to_string().as_str(),
                    "OWNED_HTTPS_TEST_PROVIDER_HOST"
                        | "OWNED_HTTPS_TEST_PROVIDER_ORIGIN"
                        | "OWNED_HTTPS_TEST_PROVIDER_IPV6"
                        | "OWNED_HTTPS_TEST_ROOT_CERTIFICATE_DER_BASE64"
                ) =>
            {
                Some((constant.ident.to_string(), constant))
            },
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let exact_shape = |constant: &syn::ItemConst| {
        matches!(constant.vis, Visibility::Inherited)
            && constant.attrs.len() == 1
            && has_only_exact_feature_cfg(&constant.attrs, FEATURE)
    };
    let string_literal = |name: &str, expected: &str| {
        constants.get(name).is_some_and(|constant| {
            exact_shape(constant)
                && matches!(constant.ty.as_ref(), Type::Reference(reference)
                    if reference.lifetime.is_none()
                        && reference.mutability.is_none()
                        && exact_type_path(&reference.elem, &["str"]))
                && matches!(constant.expr.as_ref(), syn::Expr::Lit(value)
                    if value.attrs.is_empty()
                        && matches!(&value.lit, syn::Lit::Str(value)
                            if value.value() == expected))
        })
    };
    let address_is_exact =
        constants
            .get("OWNED_HTTPS_TEST_PROVIDER_IPV6")
            .is_some_and(|constant| {
                exact_shape(constant)
                    && exact_type_path(&constant.ty, &["Ipv6Addr"])
                    && matches!(constant.expr.as_ref(), syn::Expr::Path(address)
                    if address.qself.is_none()
                        && exact_syn_path(&address.path, &["Ipv6Addr", "LOCALHOST"]))
            });
    let root_is_exact = constants
        .get("OWNED_HTTPS_TEST_ROOT_CERTIFICATE_DER_BASE64")
        .is_some_and(|constant| {
            exact_shape(constant)
                && matches!(constant.ty.as_ref(), Type::Reference(reference)
                    if reference.lifetime.is_none()
                        && reference.mutability.is_none()
                        && exact_type_path(&reference.elem, &["str"]))
                && concat_literal_sha256_is_exact(
                    &constant.expr,
                    "e90f75c7eabb03020ee377f4b3e0ab19432ccf6ced79d7d006b34d91be5c3f53",
                )
        });
    constants.len() == 4
        && string_literal(
            "OWNED_HTTPS_TEST_PROVIDER_HOST",
            "oast-provider.termivar.test",
        )
        && string_literal(
            "OWNED_HTTPS_TEST_PROVIDER_ORIGIN",
            "https://oast-provider.termivar.test/",
        )
        && address_is_exact
        && root_is_exact
}

fn owned_https_client_base64_import_is_exact(syntax: &syn::File) -> bool {
    const FEATURE: &str = "owned-https-test-profile";
    const EXPECTED_STANDARD: &str = "base64::engine::general_purpose::STANDARD";
    const EXPECTED_ENGINE: &str = "base64::Engine as _";

    let mut candidates = Vec::new();
    for item in &syntax.items {
        if matches!(item, Item::Macro(_)) {
            return false;
        }
        let shadows_base64 = match item {
            Item::Mod(item) => normalize_identifier(&item.ident.to_string()) == "base64",
            Item::Type(item) => normalize_identifier(&item.ident.to_string()) == "base64",
            Item::Struct(item) => normalize_identifier(&item.ident.to_string()) == "base64",
            Item::Enum(item) => normalize_identifier(&item.ident.to_string()) == "base64",
            Item::Union(item) => normalize_identifier(&item.ident.to_string()) == "base64",
            Item::Trait(item) => normalize_identifier(&item.ident.to_string()) == "base64",
            _ => false,
        };
        if shadows_base64 {
            return false;
        }
        if matches!(item, Item::ExternCrate(external)
            if normalize_identifier(&external.ident.to_string()) == "base64"
                || external.rename.as_ref().is_some_and(|(_, binding)|
                    normalize_identifier(&binding.to_string()) == "base64"))
        {
            return false;
        }
        let Item::Use(import) = item else {
            continue;
        };
        let mut paths = Vec::new();
        flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
        let relevant = paths.iter().any(|path| {
            let normalized = path.replace("r#", "");
            let (target, binding) = normalized
                .split_once(" as ")
                .map_or((normalized.as_str(), None), |(target, binding)| {
                    (target, Some(binding))
                });
            let terminal = target.rsplit("::").next();
            target == "base64"
                || target.starts_with("base64::")
                || terminal == Some("STANDARD")
                || terminal == Some("Engine")
                || binding == Some("STANDARD")
                || binding == Some("Engine")
                || binding == Some("base64")
                || target.ends_with("::*")
        });
        if relevant {
            candidates.push((import, paths));
        }
    }

    matches!(candidates.as_slice(), [(import, paths)]
        if matches!(import.vis, Visibility::Inherited)
            && import.leading_colon.is_none()
            && import.attrs.len() == 1
            && has_only_exact_feature_cfg(&import.attrs, FEATURE)
            && paths.len() == 2
            && paths.iter().any(|path| path.replace("r#", "") == EXPECTED_STANDARD)
            && paths.iter().any(|path| path.replace("r#", "") == EXPECTED_ENGINE))
}

fn fixed_client_builder_is_exact(syntax: &syn::File) -> bool {
    if !fixed_client_builder_imports_are_exact(syntax) {
        return false;
    }
    let functions = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "fixed_client_builder" => Some(function),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [function] = functions.as_slice() else {
        return false;
    };
    if !matches!(function.vis, Visibility::Inherited)
        || !function.attrs.is_empty()
        || function.sig.constness.is_some()
        || function.sig.asyncness.is_some()
        || function.sig.unsafety.is_some()
        || function.sig.abi.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
        || function.sig.variadic.is_some()
        || function.sig.inputs.len() != 1
        || !exact_unattributed_shared_reference_argument(
            function.sig.inputs.first(),
            "origin",
            &["Url"],
        )
        || !return_type_is_path(&function.sig.output, &["reqwest", "ClientBuilder"])
    {
        return false;
    }

    let [syn::Stmt::Expr(expression, None)] = function.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::MethodCall(http1_only) = expression else {
        return false;
    };
    let syn::Expr::MethodCall(referer) = http1_only.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(https_only) = referer.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(no_proxy) = https_only.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(retry) = no_proxy.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(redirect) = retry.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::Call(builder) = redirect.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::Path(builder_function) = builder.func.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Call(no_retry)) = retry.args.first() else {
        return false;
    };
    let syn::Expr::Path(no_retry_function) = no_retry.func.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Call(no_redirect)) = redirect.args.first() else {
        return false;
    };
    let syn::Expr::Path(no_redirect_function) = no_redirect.func.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Binary(https_condition)) = https_only.args.first() else {
        return false;
    };

    http1_only.attrs.is_empty()
        && http1_only.method == "http1_only"
        && http1_only.turbofish.is_none()
        && http1_only.args.is_empty()
        && referer.attrs.is_empty()
        && referer.method == "referer"
        && referer.turbofish.is_none()
        && matches!(referer.args.first(), Some(syn::Expr::Lit(literal))
            if referer.args.len() == 1
                && literal.attrs.is_empty()
                && matches!(&literal.lit, syn::Lit::Bool(value) if !value.value))
        && https_only.attrs.is_empty()
        && https_only.method == "https_only"
        && https_only.turbofish.is_none()
        && https_only.args.len() == 1
        && https_condition.attrs.is_empty()
        && matches!(https_condition.op, syn::BinOp::Eq(_))
        && exact_receiver_method_call(&https_condition.left, "origin", "scheme")
        && matches!(https_condition.right.as_ref(), syn::Expr::Lit(literal)
            if literal.attrs.is_empty()
                && matches!(&literal.lit, syn::Lit::Str(value) if value.value() == "https"))
        && no_proxy.attrs.is_empty()
        && no_proxy.method == "no_proxy"
        && no_proxy.turbofish.is_none()
        && no_proxy.args.is_empty()
        && retry.attrs.is_empty()
        && retry.method == "retry"
        && retry.turbofish.is_none()
        && retry.args.len() == 1
        && no_retry.attrs.is_empty()
        && no_retry.args.is_empty()
        && no_retry_function.attrs.is_empty()
        && no_retry_function.qself.is_none()
        && exact_syn_path(&no_retry_function.path, &["reqwest", "retry", "never"])
        && redirect.attrs.is_empty()
        && redirect.method == "redirect"
        && redirect.turbofish.is_none()
        && redirect.args.len() == 1
        && no_redirect.attrs.is_empty()
        && no_redirect.args.is_empty()
        && no_redirect_function.attrs.is_empty()
        && no_redirect_function.qself.is_none()
        && exact_syn_path(&no_redirect_function.path, &["RedirectPolicy", "none"])
        && builder.attrs.is_empty()
        && builder.args.is_empty()
        && builder_function.attrs.is_empty()
        && builder_function.qself.is_none()
        && exact_syn_path(&builder_function.path, &["Client", "builder"])
}

fn fixed_client_builder_imports_are_exact(syntax: &syn::File) -> bool {
    const EXPECTED: [&str; 3] = [
        "reqwest::redirect::Policy as RedirectPolicy",
        "reqwest::Client",
        "url::Url",
    ];
    let mut bindings = Vec::new();
    for item in &syntax.items {
        let shadows_crate_name = match item {
            Item::Mod(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "reqwest" | "url"
            ),
            Item::Type(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "reqwest" | "url"
            ),
            Item::Struct(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "reqwest" | "url"
            ),
            Item::Enum(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "reqwest" | "url"
            ),
            Item::Union(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "reqwest" | "url"
            ),
            Item::Trait(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "reqwest" | "url"
            ),
            _ => false,
        };
        if shadows_crate_name
            || matches!(item, Item::ExternCrate(external)
                if matches!(normalize_identifier(&external.ident.to_string()), "reqwest" | "url")
                    || external.rename.as_ref().is_some_and(|(_, binding)|
                        matches!(normalize_identifier(&binding.to_string()), "reqwest" | "url")))
        {
            return false;
        }
        let Item::Use(import) = item else {
            continue;
        };
        let mut paths = Vec::new();
        flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
        for path in paths {
            let normalized = path.replace("r#", "");
            let (target, alias) = normalized
                .split_once(" as ")
                .map_or((normalized.as_str(), None), |(target, alias)| {
                    (target, Some(alias))
                });
            let binding = alias.or_else(|| target.rsplit("::").next());
            if target.ends_with("::*")
                || matches!(alias, Some("reqwest" | "url"))
                || matches!(binding, Some("Client" | "RedirectPolicy" | "Url"))
            {
                bindings.push((import, normalized));
            }
        }
    }
    bindings.len() == EXPECTED.len()
        && EXPECTED.iter().all(|expected| {
            bindings.iter().any(|(import, path)| {
                path.as_str() == *expected
                    && matches!(import.vis, Visibility::Inherited)
                    && import.attrs.is_empty()
                    && import.leading_colon.is_none()
            })
        })
}

fn concat_literal_sha256_is_exact(expression: &syn::Expr, expected: &str) -> bool {
    let syn::Expr::Macro(concatenation) = expression else {
        return false;
    };
    if !concatenation.attrs.is_empty() || !exact_syn_path(&concatenation.mac.path, &["concat"]) {
        return false;
    }
    let parser = syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated;
    let Ok(parts) = parser.parse2(concatenation.mac.tokens.clone()) else {
        return false;
    };
    let joined = parts.iter().map(syn::LitStr::value).collect::<String>();
    format!("{:x}", Sha256::digest(joined.as_bytes())) == expected
}

fn owned_https_client_constructor_is_exact(syntax: &syn::File) -> bool {
    let methods = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if implementation.trait_.is_none()
                    && exact_type_path(&implementation.self_ty, &["NativeOastClient"]) =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .flat_map(|implementation| implementation.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "new_owned_https_test_profile" => {
                Some(method)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        return false;
    };
    if !matches!(method.vis, Visibility::Public(_))
        || method.attrs.len() != 2
        || !method.attrs[0].path().is_ident("cfg")
        || !method.attrs[0].meta.require_list().is_ok_and(|list| {
            compact_whitespace(&list.tokens.to_string()) == "feature=\"owned-https-test-profile\""
        })
        || !method.attrs[1].path().is_ident("doc")
        || !method.attrs[1]
            .meta
            .require_list()
            .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "hidden")
        || !plain_method_signature_shape(method, false)
        || method.sig.inputs.len() != 2
        || !exact_typed_argument(
            method.sig.inputs.first(),
            "public_origin",
            &["PublicOrigin"],
        )
        || !exact_typed_argument(
            method.sig.inputs.iter().nth(1),
            "profile_port",
            &["OwnedHttpsTestProfilePort"],
        )
        || !return_type_is_result(&method.sig.output, &["Self"], &["NativeOastClientError"])
    {
        return false;
    }

    let [guard, origin, root_der, root_certificate, client, tail] = method.block.stmts.as_slice()
    else {
        return false;
    };
    owned_https_origin_guard_is_exact(guard)
        && owned_https_origin_local_is_exact(origin)
        && owned_https_root_der_local_is_exact(root_der)
        && owned_https_root_certificate_local_is_exact(root_certificate)
        && owned_https_client_local_is_exact(client)
        && owned_https_client_tail_is_exact(tail)
}

fn return_type_is_result(output: &ReturnType, ok: &[&str], error: &[&str]) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return false;
    }
    let Some(segment) = path.path.segments.first() else {
        return false;
    };
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    segment.ident == "Result"
        && arguments.args.len() == 2
        && matches!(arguments.args.first(), Some(GenericArgument::Type(ty))
            if exact_type_path(ty, ok))
        && matches!(arguments.args.iter().nth(1), Some(GenericArgument::Type(ty))
            if exact_type_path(ty, error))
}

fn owned_https_origin_guard_is_exact(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::If(guard), None) = statement else {
        return false;
    };
    let syn::Expr::Binary(condition) = guard.cond.as_ref() else {
        return false;
    };
    let [syn::Stmt::Expr(syn::Expr::Return(returned), Some(_))] =
        guard.then_branch.stmts.as_slice()
    else {
        return false;
    };
    guard.attrs.is_empty()
        && guard.else_branch.is_none()
        && condition.attrs.is_empty()
        && matches!(condition.op, syn::BinOp::Ne(_))
        && exact_receiver_method_call(&condition.left, "public_origin", "as_str")
        && path_expression_name(&condition.right).as_deref()
            == Some("OWNED_HTTPS_TEST_PROVIDER_ORIGIN")
        && returned.attrs.is_empty()
        && returned
            .expr
            .as_ref()
            .is_some_and(|expression| exact_error_call(expression, "Err"))
}

fn exact_error_call(expression: &syn::Expr, wrapper: &str) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    call.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &[wrapper])
        && matches!(call.args.first(), Some(syn::Expr::Call(error))
            if call.args.len() == 1
                && error.attrs.is_empty()
                && error.args.is_empty()
                && matches!(error.func.as_ref(), syn::Expr::Path(function)
                    if function.qself.is_none()
                        && exact_syn_path(&function.path, &["client_initialization_error"])))
}

fn exact_named_local_expression<'ast>(
    statement: &'ast syn::Stmt,
    name: &str,
) -> Option<&'ast syn::Expr> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Ident(binding) = &local.pat else {
        return None;
    };
    if !local.attrs.is_empty()
        || binding.attrs.len() != 0
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.ident != name
        || binding.subpat.is_some()
    {
        return None;
    }
    local
        .init
        .as_ref()
        .filter(|initializer| initializer.diverge.is_none())
        .map(|initializer| initializer.expr.as_ref())
}

fn exact_mapped_try_receiver(expression: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::Try(attempt) = expression else {
        return None;
    };
    let syn::Expr::MethodCall(map_err) = attempt.expr.as_ref() else {
        return None;
    };
    let Some(syn::Expr::Closure(mapper)) = map_err.args.first() else {
        return None;
    };
    let mapper_is_exact = mapper.attrs.is_empty()
        && mapper.inputs.len() == 1
        && matches!(mapper.inputs.first(), Some(syn::Pat::Wild(wildcard))
            if wildcard.attrs.is_empty())
        && matches!(mapper.body.as_ref(), syn::Expr::Call(error)
            if error.attrs.is_empty()
                && error.args.is_empty()
                && matches!(error.func.as_ref(), syn::Expr::Path(function)
                    if function.qself.is_none()
                        && exact_syn_path(&function.path, &["client_initialization_error"])));
    (attempt.attrs.is_empty()
        && map_err.attrs.is_empty()
        && map_err.method == "map_err"
        && map_err.turbofish.is_none()
        && map_err.args.len() == 1
        && mapper_is_exact)
        .then_some(map_err.receiver.as_ref())
}

fn owned_https_origin_local_is_exact(statement: &syn::Stmt) -> bool {
    let Some(expression) = exact_named_local_expression(statement, "origin") else {
        return false;
    };
    let Some(syn::Expr::Call(parse)) = exact_mapped_try_receiver(expression) else {
        return false;
    };
    let syn::Expr::Path(function) = parse.func.as_ref() else {
        return false;
    };
    parse.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["Url", "parse"])
        && matches!(parse.args.first(), Some(argument)
            if parse.args.len() == 1
                && exact_receiver_method_call(argument, "public_origin", "as_str"))
}

fn owned_https_root_der_local_is_exact(statement: &syn::Stmt) -> bool {
    let Some(expression) = exact_named_local_expression(statement, "root_der") else {
        return false;
    };
    let Some(syn::Expr::MethodCall(decode)) = exact_mapped_try_receiver(expression) else {
        return false;
    };
    decode.attrs.is_empty()
        && decode.method == "decode"
        && decode.turbofish.is_none()
        && path_expression_name(&decode.receiver).as_deref() == Some("STANDARD")
        && matches!(decode.args.first(), Some(argument)
            if decode.args.len() == 1
                && path_expression_name(argument).as_deref()
                    == Some("OWNED_HTTPS_TEST_ROOT_CERTIFICATE_DER_BASE64"))
}

fn owned_https_root_certificate_local_is_exact(statement: &syn::Stmt) -> bool {
    let Some(expression) = exact_named_local_expression(statement, "root_certificate") else {
        return false;
    };
    let Some(syn::Expr::Call(from_der)) = exact_mapped_try_receiver(expression) else {
        return false;
    };
    let syn::Expr::Path(function) = from_der.func.as_ref() else {
        return false;
    };
    from_der.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["reqwest", "Certificate", "from_der"])
        && matches!(from_der.args.first(), Some(syn::Expr::Reference(root))
            if from_der.args.len() == 1
                && root.attrs.is_empty()
                && root.mutability.is_none()
                && path_expression_name(&root.expr).as_deref() == Some("root_der"))
}

fn owned_https_client_local_is_exact(statement: &syn::Stmt) -> bool {
    let Some(expression) = exact_named_local_expression(statement, "client") else {
        return false;
    };
    let Some(syn::Expr::MethodCall(build)) = exact_mapped_try_receiver(expression) else {
        return false;
    };
    let syn::Expr::MethodCall(resolve) = build.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(add_root) = resolve.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(disable_roots) = add_root.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::Call(builder) = disable_roots.receiver.as_ref() else {
        return false;
    };
    let syn::Expr::Path(builder_function) = builder.func.as_ref() else {
        return false;
    };
    build.attrs.is_empty()
        && build.method == "build"
        && build.turbofish.is_none()
        && build.args.is_empty()
        && resolve.attrs.is_empty()
        && resolve.method == "resolve"
        && resolve.turbofish.is_none()
        && resolve.args.len() == 2
        && path_expression_name(&resolve.args[0]).as_deref()
            == Some("OWNED_HTTPS_TEST_PROVIDER_HOST")
        && exact_receiver_method_call(&resolve.args[1], "profile_port", "resolved_address")
        && add_root.attrs.is_empty()
        && add_root.method == "add_root_certificate"
        && add_root.turbofish.is_none()
        && matches!(add_root.args.first(), Some(argument)
            if add_root.args.len() == 1
                && path_expression_name(argument).as_deref() == Some("root_certificate"))
        && disable_roots.attrs.is_empty()
        && disable_roots.method == "tls_built_in_root_certs"
        && disable_roots.turbofish.is_none()
        && matches!(disable_roots.args.first(), Some(syn::Expr::Lit(literal))
            if disable_roots.args.len() == 1
                && literal.attrs.is_empty()
                && matches!(&literal.lit, syn::Lit::Bool(value) if !value.value))
        && builder.attrs.is_empty()
        && builder_function.qself.is_none()
        && exact_syn_path(&builder_function.path, &["fixed_client_builder"])
        && matches!(builder.args.first(), Some(syn::Expr::Reference(origin))
            if builder.args.len() == 1
                && origin.attrs.is_empty()
                && origin.mutability.is_none()
                && path_expression_name(&origin.expr).as_deref() == Some("origin"))
}

fn owned_https_client_tail_is_exact(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::Call(ok), None) = statement else {
        return false;
    };
    let syn::Expr::Path(function) = ok.func.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Struct(client)) = ok.args.first() else {
        return false;
    };
    ok.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["Ok"])
        && ok.args.len() == 1
        && client.attrs.is_empty()
        && client.qself.is_none()
        && exact_syn_path(&client.path, &["Self"])
        && client.rest.is_none()
        && client.fields.len() == 3
        && client
            .fields
            .iter()
            .zip(["public_origin", "origin", "client"])
            .all(|(field, expected)| {
                field.attrs.is_empty()
                    && field.colon_token.is_none()
                    && matches!(&field.member, syn::Member::Named(member) if member == expected)
                    && path_expression_name(&field.expr).as_deref() == Some(expected)
            })
}

fn owned_https_profile_port_surface_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    const FEATURE: &str = "owned-https-test-profile";
    const TYPE_NAME: &str = "OwnedHttpsTestProfilePort";

    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let profiles = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(profile) if profile.ident == TYPE_NAME => Some(profile),
            _ => None,
        })
        .collect::<Vec<_>>();
    let profile_shape_is_exact = profiles.first().is_some_and(|profile| {
        matches!(profile.vis, Visibility::Public(_))
            && profile.attrs.len() == 3
            && profile.attrs[0].path().is_ident("cfg")
            && profile.attrs[0].meta.require_list().is_ok_and(|list| {
                compact_whitespace(&list.tokens.to_string()) == format!("feature=\"{FEATURE}\"")
            })
            && profile.attrs[1].path().is_ident("doc")
            && profile.attrs[1]
                .meta
                .require_list()
                .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "hidden")
            && profile.attrs[2].path().is_ident("derive")
            && profile.attrs[2].meta.require_list().is_ok_and(|list| {
                compact_whitespace(&list.tokens.to_string()) == "Clone,Copy,PartialEq,Eq"
            })
            && matches!(&profile.fields, Fields::Unnamed(fields)
            if fields.unnamed.len() == 1
                && fields.unnamed.first().is_some_and(|field| {
                    matches!(field.vis, Visibility::Inherited)
                        && has_no_conditional_cfg(&field.attrs)
                        && exact_type_path(&field.ty, &["NonZeroU16"])
                }))
    });
    if profiles.len() != 1 || !profile_shape_is_exact {
        violations.push(format!(
            "{PACKAGE} owned HTTPS profile port must remain one public doc-hidden, feature-gated tuple around exactly one private NonZeroU16"
        ));
    }

    let implementations = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if exact_type_path(&implementation.self_ty, &[TYPE_NAME]) =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let inherent = implementations
        .iter()
        .copied()
        .filter(|implementation| implementation.trait_.is_none())
        .collect::<Vec<_>>();
    let methods_are_exact = inherent.first().is_some_and(|implementation| {
        if !has_only_exact_feature_cfg(&implementation.attrs, FEATURE)
            || !plain_impl_shape(implementation)
            || implementation.items.len() != 2
        {
            return false;
        }
        let methods = implementation
            .items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        methods.len() == 2
            && methods.get("new").is_some_and(|method| {
                matches!(method.vis, Visibility::Public(_))
                    && plain_method_shape(method, true)
                    && method.sig.inputs.len() == 1
                    && exact_typed_argument(method.sig.inputs.first(), "port", &["NonZeroU16"])
                    && return_type_is_path(&method.sig.output, &["Self"])
                    && owned_https_profile_port_new_body_is_exact(method)
            })
            && methods.get("resolved_address").is_some_and(|method| {
                matches!(method.vis, Visibility::Inherited)
                    && plain_method_shape(method, false)
                    && method.sig.inputs.len() == 1
                    && owned_receiver(method.sig.inputs.first())
                    && return_type_is_path(&method.sig.output, &["SocketAddr"])
                    && owned_https_profile_resolved_address_body_is_exact(method)
            })
    });
    if inherent.len() != 1 || !methods_are_exact {
        violations.push(format!(
            "{PACKAGE} owned HTTPS profile port must retain only exact `new(NonZeroU16) -> Self` and private `resolved_address(self) -> SocketAddr` methods"
        ));
    }

    let debug_impls = implementations
        .iter()
        .copied()
        .filter(|implementation| {
            implementation
                .trait_
                .as_ref()
                .is_some_and(|(_, path, _)| exact_syn_path(path, &["fmt", "Debug"]))
        })
        .collect::<Vec<_>>();
    if implementations.len() != 2
        || debug_impls.len() != 1
        || !has_only_exact_feature_cfg(&debug_impls[0].attrs, FEATURE)
        || !plain_impl_shape(debug_impls[0])
    {
        violations.push(format!(
            "{PACKAGE} owned HTTPS profile port must retain only its exact feature-gated inherent and redacted Debug implementations"
        ));
    }

    Ok(violations)
}

fn owned_https_profile_port_new_body_is_exact(method: &syn::ImplItemFn) -> bool {
    let [syn::Stmt::Expr(syn::Expr::Call(call), None)] = method.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    call.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["Self"])
        && matches!(call.args.first(), Some(argument)
            if call.args.len() == 1
                && path_expression_name(argument).as_deref() == Some("port"))
}

fn owned_https_profile_resolved_address_body_is_exact(method: &syn::ImplItemFn) -> bool {
    let [syn::Stmt::Expr(syn::Expr::Call(call), None)] = method.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Tuple(tuple)) = call.args.first() else {
        return false;
    };
    let (Some(address), Some(syn::Expr::MethodCall(get))) =
        (tuple.elems.first(), tuple.elems.iter().nth(1))
    else {
        return false;
    };
    call.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["SocketAddr", "from"])
        && call.args.len() == 1
        && tuple.attrs.is_empty()
        && tuple.elems.len() == 2
        && path_expression_name(address).as_deref() == Some("OWNED_HTTPS_TEST_PROVIDER_IPV6")
        && get.attrs.is_empty()
        && get.method == "get"
        && get.turbofish.is_none()
        && get.args.is_empty()
        && matches!(get.receiver.as_ref(), syn::Expr::Field(field)
            if field.attrs.is_empty()
                && path_expression_name(&field.base).as_deref() == Some("self")
                && matches!(&field.member, syn::Member::Unnamed(index) if index.index == 0))
}

fn owned_xml_https_profile_surface_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    const FEATURE: &str = "xml-external-entity-owned-https-test-profile";
    const TYPE_NAME: &str = "OwnedXmlHttpsTestTransportProfile";

    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    if !owned_xml_https_identity_constants_are_exact(&syntax) {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must retain its exact target host, provider origin, and reviewed root bytes"
                .to_owned(),
        );
    }
    let profiles = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(profile) if profile.ident == TYPE_NAME => Some(profile),
            _ => None,
        })
        .collect::<Vec<_>>();
    let profile_shape_is_exact = profiles.first().is_some_and(|profile| {
        is_crate_visibility(&profile.vis)
            && profile.attrs.len() == 2
            && profile.attrs[0].path().is_ident("cfg")
            && profile.attrs[0].meta.require_list().is_ok_and(|list| {
                compact_whitespace(&list.tokens.to_string()) == format!("feature=\"{FEATURE}\"")
            })
            && profile.attrs[1].path().is_ident("derive")
            && profile.attrs[1].meta.require_list().is_ok_and(|list| {
                compact_whitespace(&list.tokens.to_string()) == "Debug,Clone,Copy,PartialEq,Eq"
            })
            && matches!(&profile.fields, Fields::Named(fields)
            if fields.named.len() == 1
                && fields.named.first().is_some_and(|field| {
                    field.ident.as_ref().is_some_and(|identifier| identifier == "port")
                        && matches!(field.vis, Visibility::Inherited)
                        && has_no_conditional_cfg(&field.attrs)
                        && exact_type_path(&field.ty, &["NonZeroU16"])
                }))
    });
    if profiles.len() != 1 || !profile_shape_is_exact {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must remain one crate-private, feature-gated record containing exactly one private NonZeroU16 port"
                .to_owned(),
        );
    }

    let implementations = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if exact_type_path(&implementation.self_ty, &[TYPE_NAME]) =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let methods_are_exact = implementations.first().is_some_and(|implementation| {
        if implementation.trait_.is_some()
            || !has_only_exact_feature_cfg(&implementation.attrs, FEATURE)
            || !plain_impl_shape(implementation)
            || implementation.items.len() != 3
        {
            return false;
        }
        let methods = implementation
            .items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        methods.len() == 3
            && methods
                .get("for_application_and_policy")
                .is_some_and(|method| {
                    is_crate_visibility(&method.vis)
                        && plain_method_shape(method, false)
                        && method.sig.inputs.len() == 2
                        && exact_shared_reference_argument(
                            method.sig.inputs.first(),
                            "application",
                            &["url", "Url"],
                        )
                        && exact_shared_reference_argument(
                            method.sig.inputs.iter().nth(1),
                            "policy",
                            &["XmlExternalEntityReviewPolicy"],
                        )
                        && return_type_is_single_wrapper(&method.sig.output, &["Option"], &["Self"])
                })
            && methods.get("port").is_some_and(|method| {
                is_crate_visibility(&method.vis)
                    && plain_method_shape(method, true)
                    && method.sig.inputs.len() == 1
                    && owned_receiver(method.sig.inputs.first())
                    && return_type_is_path(&method.sig.output, &["NonZeroU16"])
            })
            && methods.get("target_address").is_some_and(|method| {
                matches!(method.vis, Visibility::Inherited)
                    && plain_method_shape(method, false)
                    && method.sig.inputs.len() == 1
                    && owned_receiver(method.sig.inputs.first())
                    && return_type_is_path(&method.sig.output, &["SocketAddr"])
            })
    });
    if implementations.len() != 1 || !methods_are_exact {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must retain only its exact selection, sealed-port, and fixed-target-address method signatures"
                .to_owned(),
        );
    }
    let method_bodies_are_exact = implementations.first().is_some_and(|implementation| {
        let methods = implementation
            .items
            .iter()
            .filter_map(|item| match item {
                ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>();
        methods
            .get("for_application_and_policy")
            .is_some_and(|method| owned_profile_selection_body_is_exact(method))
            && methods
                .get("port")
                .is_some_and(|method| owned_profile_port_body_is_exact(method))
            && methods
                .get("target_address")
                .is_some_and(|method| owned_profile_target_body_is_exact(method))
            && owned_profile_construction_count(&syntax) == 1
    });
    if !method_bodies_are_exact {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must retain its exact selection, port, fixed-loopback body, and sole construction site"
                .to_owned(),
        );
    }
    if !owned_profile_reference_surface_is_exact(&syntax) {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must retain its exact production reference inventory without unsafe construction paths"
                .to_owned(),
        );
    }
    if !owned_profile_consumer_is_sealed(&syntax) {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must remain immutable through the exact broker resolver and retained-profile consumer"
                .to_owned(),
        );
    }
    if !owned_profile_whole_file_access_is_exact(&syntax) {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile must retain its exact immutable whole-file broker access inventory"
                .to_owned(),
        );
    }

    struct AliasSurfaceVisitor {
        aliases: usize,
    }
    impl<'ast> Visit<'ast> for AliasSurfaceVisitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let exact_test_module = item.attrs.len() == 1
                && item.attrs[0].path().is_ident("cfg")
                && item.attrs[0]
                    .meta
                    .require_list()
                    .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "test");
            if !exact_test_module {
                visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            let mut paths = Vec::new();
            flatten_use_tree(&item.tree, &mut Vec::new(), &mut paths);
            if paths.iter().any(|path| {
                let normalized = path.replace("r#", "");
                let target = normalized
                    .split_once(" as ")
                    .map_or(normalized.as_str(), |(target, _)| target);
                target.ends_with("::OwnedXmlHttpsTestTransportProfile")
                    || target == "OwnedXmlHttpsTestTransportProfile"
                    || target.ends_with("::*")
            }) {
                self.aliases = self.aliases.saturating_add(1);
            }
            visit::visit_item_use(self, item);
        }

        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            if type_mentions_owned_xml_profile(&item.ty) {
                self.aliases = self.aliases.saturating_add(1);
            }
            visit::visit_item_type(self, item);
        }

        fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
            if type_mentions_owned_xml_profile(&item.ty) {
                self.aliases = self.aliases.saturating_add(1);
            }
            visit::visit_impl_item_type(self, item);
        }

        fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
            if item
                .default
                .as_ref()
                .is_some_and(|(_, ty)| type_mentions_owned_xml_profile(ty))
            {
                self.aliases = self.aliases.saturating_add(1);
            }
            visit::visit_trait_item_type(self, item);
        }

        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            self.aliases = self.aliases.saturating_add(1);
            visit::visit_item_macro(self, item);
        }
    }
    let mut alias_surface = AliasSurfaceVisitor { aliases: 0 };
    alias_surface.visit_file(&syntax);
    if alias_surface.aliases != 0 {
        violations.push(
            "termivar-scanner owned XML HTTPS transport profile definition must expose no alias, glob, or item-macro bridge"
                .to_owned(),
        );
    }

    Ok(violations)
}

fn owned_xml_https_identity_constants_are_exact(syntax: &syn::File) -> bool {
    let constants = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(constant)
                if matches!(
                    constant.ident.to_string().as_str(),
                    "OWNED_XML_HTTPS_TARGET_HOST"
                        | "OWNED_XML_HTTPS_PROVIDER_ORIGIN"
                        | "OWNED_XML_HTTPS_ROOT_DER_BASE64"
                ) =>
            {
                Some((constant.ident.to_string(), constant))
            },
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    let exact_shape = |constant: &syn::ItemConst| {
        matches!(constant.vis, Visibility::Inherited)
            && constant.attrs.len() == 1
            && has_only_exact_feature_cfg(
                &constant.attrs,
                "xml-external-entity-owned-https-test-profile",
            )
            && matches!(constant.ty.as_ref(), Type::Reference(reference)
                if reference.lifetime.is_none()
                    && reference.mutability.is_none()
                    && exact_type_path(&reference.elem, &["str"]))
    };
    let literal = |name: &str, expected: &str| {
        constants.get(name).is_some_and(|constant| {
            exact_shape(constant)
                && matches!(constant.expr.as_ref(), syn::Expr::Lit(value)
                    if value.attrs.is_empty()
                        && matches!(&value.lit, syn::Lit::Str(value)
                            if value.value() == expected))
        })
    };
    let root_is_exact = constants
        .get("OWNED_XML_HTTPS_ROOT_DER_BASE64")
        .is_some_and(|constant| {
            let syn::Expr::Macro(concatenation) = constant.expr.as_ref() else {
                return false;
            };
            if !exact_shape(constant)
                || !concatenation.attrs.is_empty()
                || !exact_syn_path(&concatenation.mac.path, &["concat"])
            {
                return false;
            }
            let parser =
                syn::punctuated::Punctuated::<syn::LitStr, syn::Token![,]>::parse_terminated;
            let Ok(parts) = parser.parse2(concatenation.mac.tokens.clone()) else {
                return false;
            };
            let joined = parts.iter().map(syn::LitStr::value).collect::<String>();
            format!("{:x}", Sha256::digest(joined.as_bytes()))
                == "e90f75c7eabb03020ee377f4b3e0ab19432ccf6ced79d7d006b34d91be5c3f53"
        });
    constants.len() == 3
        && literal("OWNED_XML_HTTPS_TARGET_HOST", "xml-target.termivar.test")
        && literal(
            "OWNED_XML_HTTPS_PROVIDER_ORIGIN",
            "https://oast-provider.termivar.test/",
        )
        && root_is_exact
}

fn owned_profile_selection_body_is_exact(method: &syn::ImplItemFn) -> bool {
    let [syn::Stmt::Local(port), syn::Stmt::Expr(tail, None)] = method.block.stmts.as_slice()
    else {
        return false;
    };
    let port_binding_is_exact = port.attrs.is_empty()
        && matches!(&port.pat, syn::Pat::Ident(binding)
            if binding.attrs.is_empty()
                && binding.by_ref.is_none()
                && binding.mutability.is_none()
                && binding.ident == "port"
                && binding.subpat.is_none())
        && port.init.as_ref().is_some_and(|initializer| {
            if initializer.diverge.is_some() {
                return false;
            }
            let syn::Expr::Try(outer) = initializer.expr.as_ref() else {
                return false;
            };
            let syn::Expr::Call(call) = outer.expr.as_ref() else {
                return false;
            };
            let syn::Expr::Path(function) = call.func.as_ref() else {
                return false;
            };
            call.attrs.is_empty()
                && function.qself.is_none()
                && exact_syn_path(&function.path, &["NonZeroU16", "new"])
                && matches!(call.args.first(), Some(syn::Expr::Try(inner))
                    if call.args.len() == 1
                        && inner.attrs.is_empty()
                        && exact_receiver_method_call(&inner.expr, "application", "port"))
        });
    let tail = transparent_expression(tail);
    let syn::Expr::MethodCall(then_some) = tail else {
        return false;
    };
    let Some(candidate) = then_some.args.first() else {
        return false;
    };
    let syn::Expr::Struct(candidate) = transparent_expression(candidate) else {
        return false;
    };
    let candidate_is_exact = candidate.attrs.is_empty()
        && candidate.qself.is_none()
        && exact_syn_path(&candidate.path, &["Self"])
        && candidate.rest.is_none()
        && matches!(candidate.fields.first(), Some(field)
            if candidate.fields.len() == 1
                && field.attrs.is_empty()
                && field.colon_token.is_none()
                && matches!(&field.member, syn::Member::Named(member) if member == "port")
                && path_expression_name(&field.expr).as_deref() == Some("port"));
    let mut conditions = Vec::new();
    flatten_boolean_and(transparent_expression(&then_some.receiver), &mut conditions);
    port_binding_is_exact
        && then_some.attrs.is_empty()
        && then_some.method == "then_some"
        && then_some.turbofish.is_none()
        && then_some.args.len() == 1
        && candidate_is_exact
        && matches!(conditions.as_slice(), [scheme, host, application, provider]
            if exact_method_string_equality(scheme, "application", "scheme", "https")
                && exact_method_some_path_equality(
                    host,
                    "application",
                    "host_str",
                    "OWNED_XML_HTTPS_TARGET_HOST",
                )
                && exact_method_path_equality(
                    application,
                    "policy",
                    "application",
                    "application",
                )
                && exact_provider_origin_equality(provider))
}

fn transparent_expression(mut expression: &syn::Expr) -> &syn::Expr {
    loop {
        expression = match expression {
            syn::Expr::Paren(parenthesized) => &parenthesized.expr,
            syn::Expr::Group(group) => &group.expr,
            _ => return expression,
        };
    }
}

fn flatten_boolean_and<'ast>(expression: &'ast syn::Expr, output: &mut Vec<&'ast syn::Expr>) {
    let expression = transparent_expression(expression);
    if let syn::Expr::Binary(binary) = expression {
        if matches!(binary.op, syn::BinOp::And(_)) {
            flatten_boolean_and(&binary.left, output);
            flatten_boolean_and(&binary.right, output);
            return;
        }
    }
    output.push(expression);
}

fn exact_method_string_equality(
    expression: &syn::Expr,
    receiver: &str,
    method: &str,
    expected: &str,
) -> bool {
    matches!(transparent_expression(expression), syn::Expr::Binary(binary)
        if matches!(binary.op, syn::BinOp::Eq(_))
            && exact_receiver_method_call(&binary.left, receiver, method)
            && matches!(transparent_expression(&binary.right), syn::Expr::Lit(literal)
                if literal.attrs.is_empty()
                    && matches!(&literal.lit, syn::Lit::Str(value) if value.value() == expected)))
}

fn exact_method_some_path_equality(
    expression: &syn::Expr,
    receiver: &str,
    method: &str,
    expected: &str,
) -> bool {
    let syn::Expr::Binary(binary) = transparent_expression(expression) else {
        return false;
    };
    let syn::Expr::Call(some) = transparent_expression(&binary.right) else {
        return false;
    };
    let syn::Expr::Path(function) = some.func.as_ref() else {
        return false;
    };
    matches!(binary.op, syn::BinOp::Eq(_))
        && exact_receiver_method_call(&binary.left, receiver, method)
        && some.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["Some"])
        && matches!(some.args.first(), Some(argument)
            if some.args.len() == 1
                && path_expression_name(transparent_expression(argument)).as_deref()
                    == Some(expected))
}

fn exact_method_path_equality(
    expression: &syn::Expr,
    receiver: &str,
    method: &str,
    expected: &str,
) -> bool {
    matches!(transparent_expression(expression), syn::Expr::Binary(binary)
        if matches!(binary.op, syn::BinOp::Eq(_))
            && exact_receiver_method_call(&binary.left, receiver, method)
            && path_expression_name(transparent_expression(&binary.right)).as_deref()
                == Some(expected))
}

fn exact_provider_origin_equality(expression: &syn::Expr) -> bool {
    let syn::Expr::Binary(binary) = transparent_expression(expression) else {
        return false;
    };
    let syn::Expr::MethodCall(as_str) = transparent_expression(&binary.left) else {
        return false;
    };
    matches!(binary.op, syn::BinOp::Eq(_))
        && as_str.attrs.is_empty()
        && as_str.method == "as_str"
        && as_str.turbofish.is_none()
        && as_str.args.is_empty()
        && exact_receiver_method_call(&as_str.receiver, "policy", "provider_origin")
        && path_expression_name(transparent_expression(&binary.right)).as_deref()
            == Some("OWNED_XML_HTTPS_PROVIDER_ORIGIN")
}

fn owned_profile_port_body_is_exact(method: &syn::ImplItemFn) -> bool {
    matches!(method.block.stmts.as_slice(), [syn::Stmt::Expr(syn::Expr::Field(field), None)]
        if field.attrs.is_empty() && self_field_name_from_field(field).as_deref() == Some("port"))
}

fn owned_profile_target_body_is_exact(method: &syn::ImplItemFn) -> bool {
    let [syn::Stmt::Expr(syn::Expr::Call(call), None)] = method.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let Some(syn::Expr::Tuple(tuple)) = call.args.first() else {
        return false;
    };
    let (Some(syn::Expr::Array(address)), Some(syn::Expr::MethodCall(port))) =
        (tuple.elems.first(), tuple.elems.iter().nth(1))
    else {
        return false;
    };
    call.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["SocketAddr", "from"])
        && call.args.len() == 1
        && tuple.attrs.is_empty()
        && tuple.elems.len() == 2
        && address.attrs.is_empty()
        && address.elems.len() == 4
        && address
            .elems
            .iter()
            .zip([127, 0, 0, 1])
            .all(|(element, expected)| exact_integer_literal(element, expected))
        && port.attrs.is_empty()
        && port.method == "get"
        && port.turbofish.is_none()
        && port.args.is_empty()
        && self_field_name(&port.receiver).as_deref() == Some("port")
}

fn owned_profile_construction_count(syntax: &syn::File) -> usize {
    struct ConstructionVisitor {
        profile_impl_depth: usize,
        constructions: usize,
    }
    impl<'ast> Visit<'ast> for ConstructionVisitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let exact_test_module = item.attrs.len() == 1
                && item.attrs[0].path().is_ident("cfg")
                && item.attrs[0]
                    .meta
                    .require_list()
                    .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "test");
            if !exact_test_module {
                visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let profile = exact_type_path(
                item.self_ty.as_ref(),
                &["OwnedXmlHttpsTestTransportProfile"],
            );
            if profile {
                self.profile_impl_depth = self.profile_impl_depth.saturating_add(1);
            }
            visit::visit_item_impl(self, item);
            if profile {
                self.profile_impl_depth = self.profile_impl_depth.saturating_sub(1);
            }
        }

        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            if (self.profile_impl_depth != 0 && exact_syn_path(&expression.path, &["Self"]))
                || exact_syn_path(&expression.path, &["OwnedXmlHttpsTestTransportProfile"])
            {
                self.constructions = self.constructions.saturating_add(1);
            }
            visit::visit_expr_struct(self, expression);
        }
    }

    let mut visitor = ConstructionVisitor {
        profile_impl_depth: 0,
        constructions: 0,
    };
    visitor.visit_file(syntax);
    visitor.constructions
}

fn owned_profile_reference_surface_is_exact(syntax: &syn::File) -> bool {
    struct ReferenceVisitor {
        profile_references: usize,
        unsafe_surfaces: usize,
    }

    impl<'ast> Visit<'ast> for ReferenceVisitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let exact_test_module = item.attrs.len() == 1
                && item.attrs[0].path().is_ident("cfg")
                && item.attrs[0]
                    .meta
                    .require_list()
                    .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "test");
            if !exact_test_module {
                visit::visit_item_mod(self, item);
            }
        }

        fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
            if ty.qself.is_none()
                && ty.path.segments.iter().any(|segment| {
                    normalize_identifier(&segment.ident.to_string())
                        == "OwnedXmlHttpsTestTransportProfile"
                })
            {
                self.profile_references = self.profile_references.saturating_add(1);
            }
            visit::visit_type_path(self, ty);
        }

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none()
                && expression.path.segments.iter().any(|segment| {
                    normalize_identifier(&segment.ident.to_string())
                        == "OwnedXmlHttpsTestTransportProfile"
                })
            {
                self.profile_references = self.profile_references.saturating_add(1);
            }
            visit::visit_expr_path(self, expression);
        }

        fn visit_signature(&mut self, signature: &'ast syn::Signature) {
            if signature.unsafety.is_some() {
                self.unsafe_surfaces = self.unsafe_surfaces.saturating_add(1);
            }
            visit::visit_signature(self, signature);
        }

        fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
            self.unsafe_surfaces = self.unsafe_surfaces.saturating_add(1);
            visit::visit_expr_unsafe(self, expression);
        }
    }

    let mut visitor = ReferenceVisitor {
        profile_references: 0,
        unsafe_surfaces: 0,
    };
    visitor.visit_file(syntax);
    visitor.profile_references == 5 && visitor.unsafe_surfaces == 0
}

fn owned_profile_consumer_is_sealed(syntax: &syn::File) -> bool {
    let methods = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if implementation.trait_.is_none()
                    && exact_type_path(&implementation.self_ty, &["HttpRequestBroker"]) =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .flat_map(|implementation| implementation.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method)
                if method.sig.ident == "configure_owned_xml_https_test_profile" =>
            {
                Some(method)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let [method] = methods.as_slice() else {
        return false;
    };
    if !matches!(method.vis, Visibility::Inherited)
        || !has_only_exact_feature_cfg(
            &method.attrs,
            "xml-external-entity-owned-https-test-profile",
        )
        || !plain_method_signature_shape(method, false)
        || method.sig.inputs.len() != 2
        || !matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
            if receiver.attrs.is_empty()
                && receiver.reference.is_some()
                && receiver.mutability.is_some()
                && receiver.colon_token.is_none())
        || !exact_typed_argument(
            method.sig.inputs.iter().nth(1),
            "profile",
            &["OwnedXmlHttpsTestTransportProfile"],
        )
        || !return_type_is_result_unit_error(&method.sig.output, &["HttpEvidenceError"])
    {
        return false;
    }

    struct ConsumerVisitor {
        profile_paths: usize,
        target_address_calls: usize,
        retained_profile_calls: usize,
        mutable_profile_references: usize,
        profile_assignments: usize,
        protected_field_assignments: usize,
        exact_protected_field_assignments: usize,
        profile_local_bindings: usize,
        macros: usize,
    }
    impl<'ast> Visit<'ast> for ConsumerVisitor {
        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none() && expression.path.is_ident("profile") {
                self.profile_paths = self.profile_paths.saturating_add(1);
            }
            visit::visit_expr_path(self, expression);
        }

        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.attrs.is_empty()
                && expression.method == "target_address"
                && expression.turbofish.is_none()
                && expression.args.is_empty()
                && path_expression_name(&expression.receiver).as_deref() == Some("profile")
            {
                self.target_address_calls = self.target_address_calls.saturating_add(1);
            }
            visit::visit_expr_method_call(self, expression);
        }

        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if expression.attrs.is_empty()
                && matches!(expression.func.as_ref(), syn::Expr::Path(function)
                    if function.qself.is_none() && exact_syn_path(&function.path, &["Some"]))
                && matches!(expression.args.first(), Some(argument)
                    if expression.args.len() == 1
                        && path_expression_name(argument).as_deref() == Some("profile"))
            {
                self.retained_profile_calls = self.retained_profile_calls.saturating_add(1);
            }
            visit::visit_expr_call(self, expression);
        }

        fn visit_expr_reference(&mut self, expression: &'ast syn::ExprReference) {
            if expression.mutability.is_some()
                && expression_mentions_binding(&expression.expr, "profile")
            {
                self.mutable_profile_references = self.mutable_profile_references.saturating_add(1);
            }
            visit::visit_expr_reference(self, expression);
        }

        fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
            if expression_mentions_binding(&expression.left, "profile") {
                self.profile_assignments = self.profile_assignments.saturating_add(1);
            }
            if expression_is_owned_profile_field(&expression.left) {
                self.protected_field_assignments =
                    self.protected_field_assignments.saturating_add(1);
                if owned_profile_retention_assignment_is_exact(expression) {
                    self.exact_protected_field_assignments =
                        self.exact_protected_field_assignments.saturating_add(1);
                }
            }
            visit::visit_expr_assign(self, expression);
        }

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if pattern_mentions_binding(&local.pat, "profile") {
                self.profile_local_bindings = self.profile_local_bindings.saturating_add(1);
            }
            visit::visit_local(self, local);
        }

        fn visit_macro(&mut self, expression: &'ast syn::Macro) {
            self.macros = self.macros.saturating_add(1);
            visit::visit_macro(self, expression);
        }
    }

    let mut visitor = ConsumerVisitor {
        profile_paths: 0,
        target_address_calls: 0,
        retained_profile_calls: 0,
        mutable_profile_references: 0,
        profile_assignments: 0,
        protected_field_assignments: 0,
        exact_protected_field_assignments: 0,
        profile_local_bindings: 0,
        macros: 0,
    };
    visitor.visit_block(&method.block);
    visitor.profile_paths == 2
        && visitor.target_address_calls == 1
        && visitor.retained_profile_calls == 1
        && visitor.mutable_profile_references == 0
        && visitor.profile_assignments == 0
        && visitor.protected_field_assignments == 1
        && visitor.exact_protected_field_assignments == 1
        && visitor.profile_local_bindings == 0
        && visitor.macros == 0
}

fn expression_is_owned_profile_field(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::Field(field)
        if field.attrs.is_empty()
            && matches!(&field.member, syn::Member::Named(member)
                if normalize_identifier(&member.to_string())
                    == "owned_xml_https_test_profile"))
}

fn owned_profile_retention_assignment_is_exact(expression: &syn::ExprAssign) -> bool {
    let syn::Expr::Field(field) = expression.left.as_ref() else {
        return false;
    };
    let syn::Expr::Call(some) = expression.right.as_ref() else {
        return false;
    };
    let syn::Expr::Path(function) = some.func.as_ref() else {
        return false;
    };
    expression.attrs.is_empty()
        && field.attrs.is_empty()
        && path_expression_name(&field.base).as_deref() == Some("self")
        && matches!(&field.member, syn::Member::Named(member)
            if normalize_identifier(&member.to_string())
                == "owned_xml_https_test_profile")
        && some.attrs.is_empty()
        && function.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["Some"])
        && matches!(some.args.first(), Some(argument)
            if some.args.len() == 1
                && path_expression_name(argument).as_deref() == Some("profile"))
}

fn owned_profile_whole_file_access_is_exact(syntax: &syn::File) -> bool {
    struct SurfaceVisitor {
        field_accesses: usize,
        field_initializers: usize,
        exact_field_initializers: usize,
        field_patterns: usize,
        field_assignments: usize,
        exact_retention_assignments: usize,
        profile_paths: usize,
        profile_bindings: usize,
        typed_profile_arguments: usize,
        exact_typed_profile_arguments: usize,
        configure_calls: usize,
        target_address_calls: usize,
        retained_profile_calls: usize,
        self_profile_reads: usize,
        broker_profile_reads: usize,
        mutable_surface_references: usize,
        surface_assignments: usize,
        macro_surface_mentions: usize,
    }

    impl<'ast> Visit<'ast> for SurfaceVisitor {
        fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
            if matches!(&expression.member, syn::Member::Named(member)
                if normalize_identifier(&member.to_string())
                    == "owned_xml_https_test_profile")
            {
                self.field_accesses = self.field_accesses.saturating_add(1);
            }
            visit::visit_expr_field(self, expression);
        }

        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            for field in &expression.fields {
                if matches!(&field.member, syn::Member::Named(member)
                    if normalize_identifier(&member.to_string())
                        == "owned_xml_https_test_profile")
                {
                    self.field_initializers = self.field_initializers.saturating_add(1);
                    if expression.attrs.is_empty()
                        && expression.qself.is_none()
                        && exact_syn_path(&expression.path, &["Self"])
                        && expression.rest.is_none()
                        && field.attrs.len() == 1
                        && has_only_exact_feature_cfg(
                            &field.attrs,
                            "xml-external-entity-owned-https-test-profile",
                        )
                        && field.colon_token.is_some()
                        && path_expression_name(&field.expr).as_deref() == Some("None")
                    {
                        self.exact_field_initializers =
                            self.exact_field_initializers.saturating_add(1);
                    }
                }
            }
            visit::visit_expr_struct(self, expression);
        }

        fn visit_pat_struct(&mut self, pattern: &'ast syn::PatStruct) {
            self.field_patterns = self.field_patterns.saturating_add(
                pattern
                    .fields
                    .iter()
                    .filter(|field| {
                        matches!(&field.member, syn::Member::Named(member)
                            if normalize_identifier(&member.to_string())
                                == "owned_xml_https_test_profile")
                    })
                    .count(),
            );
            visit::visit_pat_struct(self, pattern);
        }

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none()
                && expression.path.leading_colon.is_none()
                && expression.path.is_ident("profile")
            {
                self.profile_paths = self.profile_paths.saturating_add(1);
            }
            visit::visit_expr_path(self, expression);
        }

        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            if normalize_identifier(&pattern.ident.to_string()) == "profile" {
                self.profile_bindings = self.profile_bindings.saturating_add(1);
            }
            visit::visit_pat_ident(self, pattern);
        }

        fn visit_fn_arg(&mut self, argument: &'ast syn::FnArg) {
            if let syn::FnArg::Typed(argument) = argument {
                if exact_type_path(&argument.ty, &["OwnedXmlHttpsTestTransportProfile"]) {
                    self.typed_profile_arguments = self.typed_profile_arguments.saturating_add(1);
                    if argument.attrs.is_empty()
                        && exact_immutable_identifier_pattern(&argument.pat, "profile")
                    {
                        self.exact_typed_profile_arguments =
                            self.exact_typed_profile_arguments.saturating_add(1);
                    }
                }
            }
            visit::visit_fn_arg(self, argument);
        }

        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.attrs.is_empty()
                && expression.method == "configure_owned_xml_https_test_profile"
                && expression.turbofish.is_none()
                && path_expression_name(&expression.receiver).as_deref() == Some("broker")
                && matches!(expression.args.first(), Some(argument)
                    if expression.args.len() == 1
                        && path_expression_name(argument).as_deref() == Some("profile"))
            {
                self.configure_calls = self.configure_calls.saturating_add(1);
            }
            if expression.attrs.is_empty()
                && expression.method == "target_address"
                && expression.turbofish.is_none()
                && expression.args.is_empty()
                && path_expression_name(&expression.receiver).as_deref() == Some("profile")
            {
                self.target_address_calls = self.target_address_calls.saturating_add(1);
            }
            visit::visit_expr_method_call(self, expression);
        }

        fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
            if expression.attrs.is_empty()
                && matches!(expression.func.as_ref(), syn::Expr::Path(function)
                    if function.attrs.is_empty()
                        && function.qself.is_none()
                        && exact_syn_path(&function.path, &["Some"]))
                && matches!(expression.args.first(), Some(argument)
                    if expression.args.len() == 1
                        && path_expression_name(argument).as_deref() == Some("profile"))
            {
                self.retained_profile_calls = self.retained_profile_calls.saturating_add(1);
            }
            visit::visit_expr_call(self, expression);
        }

        fn visit_expr_let(&mut self, expression: &'ast syn::ExprLet) {
            if expression.attrs.is_empty()
                && exact_some_profile_pattern(&expression.pat)
                && matches!(expression.expr.as_ref(), syn::Expr::Field(field)
                    if field.attrs.is_empty()
                        && matches!(&field.member, syn::Member::Named(member)
                            if normalize_identifier(&member.to_string())
                                == "owned_xml_https_test_profile"))
            {
                let syn::Expr::Field(field) = expression.expr.as_ref() else {
                    unreachable!();
                };
                match path_expression_name(&field.base).as_deref() {
                    Some("self") => {
                        self.self_profile_reads = self.self_profile_reads.saturating_add(1);
                    },
                    Some("broker") => {
                        self.broker_profile_reads = self.broker_profile_reads.saturating_add(1);
                    },
                    _ => {},
                }
            }
            visit::visit_expr_let(self, expression);
        }

        fn visit_expr_reference(&mut self, expression: &'ast syn::ExprReference) {
            if expression.mutability.is_some()
                && expression_mentions_owned_profile_surface(&expression.expr)
            {
                self.mutable_surface_references = self.mutable_surface_references.saturating_add(1);
            }
            visit::visit_expr_reference(self, expression);
        }

        fn visit_expr_assign(&mut self, expression: &'ast syn::ExprAssign) {
            if expression_is_owned_profile_field(&expression.left) {
                self.field_assignments = self.field_assignments.saturating_add(1);
                if owned_profile_retention_assignment_is_exact(expression) {
                    self.exact_retention_assignments =
                        self.exact_retention_assignments.saturating_add(1);
                }
            }
            if expression_mentions_binding(&expression.left, "profile") {
                self.surface_assignments = self.surface_assignments.saturating_add(1);
            }
            visit::visit_expr_assign(self, expression);
        }

        fn visit_macro(&mut self, expression: &'ast syn::Macro) {
            let tokens = expression.tokens.to_string().replace("r#", "");
            if tokens.contains("owned_xml_https_test_profile")
                || tokens
                    .split(|character: char| !character.is_alphanumeric() && character != '_')
                    .any(|token| token == "profile")
            {
                self.macro_surface_mentions = self.macro_surface_mentions.saturating_add(1);
            }
            visit::visit_macro(self, expression);
        }
    }

    let mut visitor = SurfaceVisitor {
        field_accesses: 0,
        field_initializers: 0,
        exact_field_initializers: 0,
        field_patterns: 0,
        field_assignments: 0,
        exact_retention_assignments: 0,
        profile_paths: 0,
        profile_bindings: 0,
        typed_profile_arguments: 0,
        exact_typed_profile_arguments: 0,
        configure_calls: 0,
        target_address_calls: 0,
        retained_profile_calls: 0,
        self_profile_reads: 0,
        broker_profile_reads: 0,
        mutable_surface_references: 0,
        surface_assignments: 0,
        macro_surface_mentions: 0,
    };
    visitor.visit_file(syntax);
    visitor.field_accesses == 3
        && visitor.field_initializers == 1
        && visitor.exact_field_initializers == 1
        && visitor.field_patterns == 0
        && visitor.field_assignments == 1
        && visitor.exact_retention_assignments == 1
        && visitor.profile_paths == 6
        && visitor.profile_bindings == 5
        && visitor.typed_profile_arguments == 3
        && visitor.exact_typed_profile_arguments == 3
        && visitor.configure_calls == 3
        && visitor.target_address_calls == 2
        && visitor.retained_profile_calls == 1
        && visitor.self_profile_reads == 1
        && visitor.broker_profile_reads == 1
        && visitor.mutable_surface_references == 0
        && visitor.surface_assignments == 0
        && visitor.macro_surface_mentions == 0
}

fn exact_immutable_identifier_pattern(pattern: &syn::Pat, expected: &str) -> bool {
    matches!(pattern, syn::Pat::Ident(binding)
        if binding.attrs.is_empty()
            && binding.by_ref.is_none()
            && binding.mutability.is_none()
            && normalize_identifier(&binding.ident.to_string()) == expected
            && binding.subpat.is_none())
}

fn exact_some_profile_pattern(pattern: &syn::Pat) -> bool {
    matches!(pattern, syn::Pat::TupleStruct(tuple)
        if tuple.attrs.is_empty()
            && tuple.qself.is_none()
            && exact_syn_path(&tuple.path, &["Some"])
            && matches!(tuple.elems.first(), Some(pattern)
                if tuple.elems.len() == 1
                    && exact_immutable_identifier_pattern(pattern, "profile")))
}

fn expression_mentions_owned_profile_surface(expression: &syn::Expr) -> bool {
    struct SurfaceVisitor {
        found: bool,
    }
    impl<'ast> Visit<'ast> for SurfaceVisitor {
        fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
            if matches!(&expression.member, syn::Member::Named(member)
                if normalize_identifier(&member.to_string())
                    == "owned_xml_https_test_profile")
            {
                self.found = true;
            }
            visit::visit_expr_field(self, expression);
        }

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none() && expression.path.is_ident("profile") {
                self.found = true;
            }
            visit::visit_expr_path(self, expression);
        }
    }
    let mut visitor = SurfaceVisitor { found: false };
    visitor.visit_expr(expression);
    visitor.found
}

fn expression_mentions_binding(expression: &syn::Expr, expected: &str) -> bool {
    struct BindingVisitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for BindingVisitor<'_> {
        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.qself.is_none() && expression.path.is_ident(self.expected) {
                self.found = true;
            }
            visit::visit_expr_path(self, expression);
        }
    }
    let mut visitor = BindingVisitor {
        expected,
        found: false,
    };
    visitor.visit_expr(expression);
    visitor.found
}

fn pattern_mentions_binding(pattern: &syn::Pat, expected: &str) -> bool {
    struct BindingVisitor<'a> {
        expected: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for BindingVisitor<'_> {
        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            if normalize_identifier(&pattern.ident.to_string()) == self.expected {
                self.found = true;
            }
            visit::visit_pat_ident(self, pattern);
        }
    }
    let mut visitor = BindingVisitor {
        expected,
        found: false,
    };
    visitor.visit_pat(pattern);
    visitor.found
}

fn owned_xml_https_profile_reexport_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    const FEATURE: &str = "xml-external-entity-owned-https-test-profile";
    const EXPECTED_PATH: &str = "request_broker::OwnedXmlHttpsTestTransportProfile";

    let syntax = syn::parse_file(source)?;
    let broker_modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.ident == "request_broker" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let broker_module_is_exact = matches!(broker_modules.as_slice(), [module]
        if module.attrs.is_empty()
            && matches!(module.vis, syn::Visibility::Inherited)
            && module.content.is_none()
            && module.semi.is_some());
    struct UseCollector<'ast> {
        imports: Vec<&'ast syn::ItemUse>,
        item_macros: usize,
        profile_type_aliases: usize,
    }
    impl<'ast> Visit<'ast> for UseCollector<'ast> {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let exact_test_module = item.attrs.len() == 1
                && item.attrs[0].path().is_ident("cfg")
                && item.attrs[0]
                    .meta
                    .require_list()
                    .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "test");
            if !exact_test_module {
                visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            self.imports.push(item);
            visit::visit_item_use(self, item);
        }

        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            self.item_macros = self.item_macros.saturating_add(1);
            visit::visit_item_macro(self, item);
        }

        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            if type_mentions_owned_xml_profile(&item.ty) {
                self.profile_type_aliases = self.profile_type_aliases.saturating_add(1);
            }
            visit::visit_item_type(self, item);
        }

        fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
            if type_mentions_owned_xml_profile(&item.ty) {
                self.profile_type_aliases = self.profile_type_aliases.saturating_add(1);
            }
            visit::visit_impl_item_type(self, item);
        }

        fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
            if item
                .default
                .as_ref()
                .is_some_and(|(_, ty)| type_mentions_owned_xml_profile(ty))
            {
                self.profile_type_aliases = self.profile_type_aliases.saturating_add(1);
            }
            visit::visit_trait_item_type(self, item);
        }
    }
    let mut collector = UseCollector {
        imports: Vec::new(),
        item_macros: 0,
        profile_type_aliases: 0,
    };
    collector.visit_file(&syntax);
    let hidden_export_surface = !broker_module_is_exact
        || collector.item_macros != 0
        || collector.profile_type_aliases != 0;
    let exports = collector
        .imports
        .into_iter()
        .filter_map(|import| {
            let mut paths = Vec::new();
            flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
            paths
                .iter()
                .any(|path| owned_profile_use_path_targets_export(path, EXPECTED_PATH))
                .then_some((import, paths))
        })
        .collect::<Vec<_>>();
    let exact = exports.first().is_some_and(|(import, paths)| {
        is_crate_visibility(&import.vis)
            && has_only_exact_feature_cfg(&import.attrs, FEATURE)
            && paths.len() == 1
            && paths.first().is_some_and(|path| path == EXPECTED_PATH)
    });
    Ok(if exports.len() == 1 && exact && !hidden_export_surface {
        Vec::new()
    } else {
        vec![
            "termivar-scanner must re-export the owned XML HTTPS transport profile exactly crate-private and behind only its test-profile feature"
                .to_owned(),
        ]
    })
}

fn type_mentions_owned_xml_profile(ty: &syn::Type) -> bool {
    struct ProfileTypeVisitor {
        found: bool,
    }
    impl<'ast> Visit<'ast> for ProfileTypeVisitor {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if path.segments.last().is_some_and(|segment| {
                normalize_identifier(&segment.ident.to_string())
                    == "OwnedXmlHttpsTestTransportProfile"
            }) {
                self.found = true;
            }
            visit::visit_path(self, path);
        }
    }

    let mut visitor = ProfileTypeVisitor { found: false };
    visitor.visit_type(ty);
    visitor.found
}

fn owned_profile_use_path_targets_export(path: &str, expected_path: &str) -> bool {
    let normalized = path.replace("r#", "");
    let (target, alias) = normalized
        .split_once(" as ")
        .map_or((normalized.as_str(), None), |(target, binding)| {
            (target, Some(binding))
        });
    target == expected_path
        || target.ends_with(&format!("::{expected_path}"))
        || target
            .rsplit("::")
            .next()
            .is_some_and(|segment| segment == "OwnedXmlHttpsTestTransportProfile")
        || target.ends_with("::*")
        || target == "request_broker::*"
        || target.ends_with("::request_broker::*")
        || (alias.is_some()
            && (target == "request_broker"
                || target.ends_with("::request_broker")
                || target == "request_broker::self"
                || target.ends_with("::request_broker::self")))
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
    let owned_https_profile_members = features
        .and_then(|table| table.get("xml-external-entity-owned-https-test-profile"))
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<BTreeSet<_>>()
        });
    if owned_https_profile_members
        != Some(BTreeSet::from([
            "termivar-oast/owned-https-test-profile",
            "xml-external-entity-review",
        ]))
    {
        violations.push(
            "termivar-scanner owned HTTPS profile must contain exactly XML review and the sealed provider test profile"
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
            if feature_reaches(
                features,
                aggregate,
                "xml-external-entity-owned-https-test-profile",
            ) {
                violations.push(format!(
                    "termivar-scanner feature `{aggregate}` must not enable the owned HTTPS test profile"
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
    let request_broker = fs::read_to_string(source_root.join(SCANNER_REQUEST_BROKER))?;
    violations.extend(owned_xml_https_profile_surface_violations(
        production_prefix(&request_broker),
    )?);
    let http_evidence = fs::read_to_string(source_root.join(SCANNER_HTTP_EVIDENCE))?;
    violations.extend(owned_xml_https_profile_reexport_violations(
        production_prefix(&http_evidence),
    )?);

    let mut scanner_sources = rust_sources_below(&source_root)?;
    scanner_sources.sort();
    let mut scanner_production_sources = Vec::new();
    for path in scanner_sources {
        let source = fs::read_to_string(&path)?;
        let relative = normalized_relative(&source_root, &path)?;
        let production = source_without_exact_oast_test_modules(production_prefix(&source))?;
        scanner_production_sources.push((relative, production));
    }
    violations.extend(scanner_provider_consumer_violations(
        &scanner_production_sources,
    ));
    violations.extend(owned_xml_profile_global_reference_violations(
        &scanner_production_sources,
    ));
    let assessment_review = fs::read_to_string(source_root.join(ASSESSMENT_REVIEW_SOURCE))?;
    violations.extend(assessment_review_test_module_violations(&assessment_review));
    let web_runtime = fs::read_to_string(source_root.join(WEB_RUNTIME_SOURCE))?;
    violations.extend(web_runtime_test_module_violations(&web_runtime));
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
    for forbidden in ["oast-native-provider", "oast-provider"] {
        if cli_manifest.contains(forbidden) || production_prefix(&cli_source).contains(forbidden) {
            violations.push(format!(
                "the native OAST provider adapter must expose no CLI dependency, feature, or flag containing `{forbidden}`"
            ));
        }
    }
    if production_prefix(&cli_source).contains("termivar-oast") {
        violations.push(
            "the native OAST provider adapter must expose no production CLI source reference to termivar-oast"
                .to_owned(),
        );
    }

    let authority = fs::read_to_string(workspace_root.join(SHARED_AUTHORITY_SOURCE))?;
    violations.extend(shared_provider_mint_contract_violations(&authority)?);

    Ok(violations)
}

fn owned_xml_profile_global_reference_violations(sources: &[(String, String)]) -> Vec<String> {
    const TYPE_NAME: &str = "OwnedXmlHttpsTestTransportProfile";
    const EXPECTED: &[(&str, usize)] = &[
        (SCANNER_HTTP_EVIDENCE, 1),
        (SCANNER_REQUEST_BROKER, 6),
        ("web_runtime/authority.rs", 4),
        ("web_runtime/xml_external_entity_runtime.rs", 3),
        ("web_runtime/web_assessment.rs", 2),
    ];

    let parsed = sources
        .iter()
        .map(|(path, source)| (path.as_str(), syn::parse_file(source)))
        .collect::<Vec<_>>();
    let actual = parsed
        .iter()
        .filter_map(|(path, syntax)| {
            let count = syntax
                .as_ref()
                .ok()
                .map_or(0, owned_profile_semantic_reference_count);
            (count != 0).then_some((*path, count))
        })
        .collect::<BTreeMap<_, _>>();
    let expected = EXPECTED.iter().copied().collect::<BTreeMap<_, _>>();
    let alias_surface_is_closed = parsed.iter().all(|(_, syntax)| {
        syntax
            .as_ref()
            .is_ok_and(scanner_profile_alias_surface_is_closed)
    });
    if actual == expected && alias_surface_is_closed {
        Vec::new()
    } else {
        vec![format!(
            "termivar-scanner owned XML HTTPS transport profile must retain only its reviewed definition, canonical re-export, and three exact consumers; expected {expected:?}, observed {actual:?}"
        )]
    }
}

fn owned_profile_semantic_reference_count(syntax: &syn::File) -> usize {
    const TYPE_NAME: &str = "OwnedXmlHttpsTestTransportProfile";
    struct ReferenceVisitor {
        count: usize,
    }
    impl ReferenceVisitor {
        fn count_path(&mut self, path: &syn::Path) {
            self.count = self.count.saturating_add(
                path.segments
                    .iter()
                    .filter(|segment| normalize_identifier(&segment.ident.to_string()) == TYPE_NAME)
                    .count(),
            );
        }
    }
    impl<'ast> Visit<'ast> for ReferenceVisitor {
        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if normalize_identifier(&item.ident.to_string()) == TYPE_NAME {
                self.count = self.count.saturating_add(1);
            }
            visit::visit_item_struct(self, item);
        }

        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            let mut paths = Vec::new();
            flatten_use_tree(&item.tree, &mut Vec::new(), &mut paths);
            self.count = self.count.saturating_add(
                paths
                    .iter()
                    .map(|path| path.replace("r#", ""))
                    .filter(|path| {
                        path.split(|character: char| character == ':' || character.is_whitespace())
                            .any(|segment| segment == TYPE_NAME)
                    })
                    .count(),
            );
        }

        fn visit_type_path(&mut self, ty: &'ast syn::TypePath) {
            self.count_path(&ty.path);
            visit::visit_type_path(self, ty);
        }

        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            self.count_path(&expression.path);
            visit::visit_expr_path(self, expression);
        }
    }

    let mut visitor = ReferenceVisitor { count: 0 };
    visitor.visit_file(syntax);
    visitor.count
}

fn scanner_profile_alias_surface_is_closed(syntax: &syn::File) -> bool {
    struct AliasVisitor {
        closed: bool,
    }

    impl<'ast> Visit<'ast> for AliasVisitor {
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            let mut paths = Vec::new();
            flatten_use_tree(&item.tree, &mut Vec::new(), &mut paths);
            for path in paths {
                let normalized = path.replace("r#", "");
                let (target, alias) = normalized
                    .split_once(" as ")
                    .map_or((normalized.as_str(), None), |(target, alias)| {
                        (target, Some(alias))
                    });
                let module_alias = alias.is_some()
                    && target.rsplit("::").next().is_some_and(|segment| {
                        matches!(segment, "http_evidence" | "request_broker" | "self")
                            && (target.contains("http_evidence")
                                || target.contains("request_broker"))
                    });
                let protected_alias_binding = alias
                    .is_some_and(|binding| matches!(binding, "http_evidence" | "request_broker"));
                let protected_module_reexport = !matches!(item.vis, Visibility::Inherited)
                    && target.rsplit("::").next().is_some_and(|segment| {
                        matches!(segment, "http_evidence" | "request_broker" | "self")
                            && (target.contains("http_evidence")
                                || target.contains("request_broker"))
                    });
                let profile_alias = alias.is_some()
                    && target
                        .rsplit("::")
                        .next()
                        .is_some_and(|segment| segment == "OwnedXmlHttpsTestTransportProfile");
                let glob = target == "*" || target.ends_with("::*");
                let dangerous_glob = glob
                    && (!matches!(item.vis, Visibility::Inherited)
                        || target.contains("http_evidence")
                        || target.contains("request_broker"));
                if module_alias
                    || protected_alias_binding
                    || protected_module_reexport
                    || profile_alias
                    || dangerous_glob
                {
                    self.closed = false;
                }
            }
            visit::visit_item_use(self, item);
        }

        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            if type_mentions_owned_xml_profile(&item.ty) {
                self.closed = false;
            }
            visit::visit_item_type(self, item);
        }

        fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
            if type_mentions_owned_xml_profile(&item.ty) {
                self.closed = false;
            }
            visit::visit_impl_item_type(self, item);
        }

        fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
            if item
                .default
                .as_ref()
                .is_some_and(|(_, ty)| type_mentions_owned_xml_profile(ty))
            {
                self.closed = false;
            }
            visit::visit_trait_item_type(self, item);
        }

        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            let tokens = compact_whitespace(&item.mac.tokens.to_string()).replace("r#", "");
            if tokens.contains("http_evidence")
                || tokens.contains("request_broker")
                || tokens.contains("OwnedXmlHttpsTestTransportProfile")
            {
                self.closed = false;
            }
            visit::visit_item_macro(self, item);
        }

        fn visit_macro(&mut self, expression: &'ast syn::Macro) {
            let tokens = compact_whitespace(&expression.tokens.to_string()).replace("r#", "");
            if tokens.contains("http_evidence")
                || tokens.contains("request_broker")
                || tokens.contains("OwnedXmlHttpsTestTransportProfile")
            {
                self.closed = false;
            }
            visit::visit_macro(self, expression);
        }
    }

    let mut visitor = AliasVisitor { closed: true };
    visitor.visit_file(syntax);
    visitor.closed
}

fn scanner_provider_consumer_violations(sources: &[(String, String)]) -> Vec<String> {
    let provider_consumers = sources
        .iter()
        .filter(|(path, source)| {
            !EXACT_TEST_ONLY_PROVIDER_CONSUMERS.contains(&path.as_str())
                && source.contains("termivar_oast")
        })
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    let expected = EXACT_SCANNER_PROVIDER_CONSUMERS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<Vec<_>>();
    (provider_consumers != expected)
        .then(|| {
            format!(
                "termivar-scanner must confine production termivar_oast use to the sealed adapter and exact bounded SSRF/XML domain and runtime consumers; expected {expected:?}, found {provider_consumers:?}"
            )
        })
        .into_iter()
        .collect()
}

fn assessment_review_test_module_violations(source: &str) -> Vec<String> {
    let exact_test_module = "#[cfg(test)]#[path=\"assessment_review_tests.rs\"]modtests;";
    (compact_whitespace(source)
        .matches(exact_test_module)
        .count()
        != 1)
        .then(|| {
            format!(
                "the test-only termivar_oast consumer must remain behind the exact cfg(test) module declaration in {ASSESSMENT_REVIEW_SOURCE}"
            )
        })
        .into_iter()
        .collect()
}

fn web_runtime_test_module_violations(source: &str) -> Vec<String> {
    let exact_test_module = "#[cfg(test)]#[path=\"web_runtime_tests.rs\"]modtests;";
    (compact_whitespace(source)
        .matches(exact_test_module)
        .count()
        != 1)
        .then(|| {
            format!(
                "the test-only termivar_oast consumer must remain behind the exact cfg(test) module declaration in {WEB_RUNTIME_SOURCE}"
            )
        })
        .into_iter()
        .collect()
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
    if !canonical_native_oast_client_import_is_exact(&syntax) {
        violations.push(
            "the sealed native OAST adapter must import NativeOastClient exactly and unaliased from termivar_oast"
                .to_owned(),
        );
    }
    let compact = compact_whitespace(production);
    if compact.contains("allow(dead_code") {
        violations.push(
            "the sealed native OAST adapter must not suppress dead-code policy with `allow`"
                .to_owned(),
        );
    }
    for (marker, expected) in [
        // The two normal constructors are mutually exclusive cfg alternatives:
        // one arm when the owned profile is compiled and one fallback when it
        // is absent. The owned constructor is a third, separately sealed edge.
        ("NativeOastClient::new(", 2),
        ("NativeOastClient::new_owned_https_test_profile(", 1),
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
        if type_name == "NativeOastProviderAdapter"
            && implementation
                .items
                .iter()
                .any(|item| matches!(item, ImplItem::Macro(_)))
        {
            violations.push(
                "NativeOastProviderAdapter must expose no macro-generated constructor surface"
                    .to_owned(),
            );
        }
    }

    let trait_mint_methods = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation) if implementation.trait_.is_some() => Some(implementation),
            _ => None,
        })
        .filter(|implementation| {
            matches!(
                type_path_tail(&implementation.self_ty).as_deref(),
                Some("NativeOastProviderPermit" | "NativeOastProviderAdapter")
            )
        })
        .flat_map(|implementation| implementation.items.iter())
        .filter(|item| matches!(item, ImplItem::Fn(method) if method.sig.ident == "mint"))
        .count();
    if trait_mint_methods != 0 {
        violations.push(
            "native OAST permit and adapter mint authority must have no trait-provided alternate constructor"
                .to_owned(),
        );
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
    if !matches!(adapter_mints.as_slice(), [method]
        if adapter_client_constructor_partition_is_exact(method))
    {
        violations.push(
            "NativeOastProviderAdapter::mint must retain the exact mutually exclusive production and owned-HTTPS client constructor partition"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn canonical_native_oast_client_import_is_exact(syntax: &syn::File) -> bool {
    const TYPE_NAME: &str = "NativeOastClient";
    const EXPECTED: &str = "termivar_oast::NativeOastClient";

    let mut candidates = Vec::new();
    for item in &syntax.items {
        let syn::Item::Use(import) = item else {
            continue;
        };
        let mut paths = Vec::new();
        flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
        for path in paths {
            let normalized = path.replace("r#", "");
            let (target, binding) = normalized
                .split_once(" as ")
                .map_or((normalized.as_str(), None), |(target, binding)| {
                    (target, Some(binding))
                });
            let terminal = target.rsplit("::").next();
            if terminal == Some(TYPE_NAME) || binding == Some(TYPE_NAME) || target.ends_with("::*")
            {
                candidates.push((import, normalized));
            }
        }
    }
    matches!(candidates.as_slice(), [(import, path)]
        if matches!(import.vis, syn::Visibility::Inherited)
            && import.attrs.is_empty()
            && import.leading_colon.is_some()
            && path == EXPECTED)
}

fn adapter_client_constructor_partition_is_exact(method: &syn::ImplItemFn) -> bool {
    const FEATURE: &str = "xml-external-entity-owned-https-test-profile";
    const PERMIT_ARGUMENTS: [&str; 7] = [
        "origin",
        "target_origin",
        "limits",
        "accounting",
        "parent_budget",
        "cancellation",
        "parent_deadline",
    ];

    struct LocalVisitor<'ast> {
        client_locals: Vec<&'ast syn::Local>,
        permit_locals: Vec<&'ast syn::Local>,
        client_bindings: usize,
        permit_bindings: usize,
        permit_argument_bindings: BTreeMap<String, usize>,
        origin_bindings: usize,
        transport_bindings: usize,
        configuration_destructures: usize,
        macro_invocations: usize,
        block_items: usize,
        returns: usize,
    }

    impl<'ast> Visit<'ast> for LocalVisitor<'ast> {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if pattern_binds_identifier(&local.pat, "client") {
                self.client_locals.push(local);
            }
            if pattern_binds_identifier(&local.pat, "permit") {
                self.permit_locals.push(local);
            }
            if native_oast_configuration_destructure_is_exact(local) {
                self.configuration_destructures = self.configuration_destructures.saturating_add(1);
            }
            visit::visit_local(self, local);
        }

        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            let rendered = pattern.ident.to_string();
            let identifier = normalize_identifier(&rendered);
            if PERMIT_ARGUMENTS.contains(&identifier) {
                *self
                    .permit_argument_bindings
                    .entry(identifier.to_owned())
                    .or_default() += 1;
            }
            match identifier {
                "client" => self.client_bindings = self.client_bindings.saturating_add(1),
                "permit" => self.permit_bindings = self.permit_bindings.saturating_add(1),
                "origin" => self.origin_bindings = self.origin_bindings.saturating_add(1),
                "transport" => self.transport_bindings = self.transport_bindings.saturating_add(1),
                _ => {},
            }
            visit::visit_pat_ident(self, pattern);
        }

        fn visit_macro(&mut self, expression: &'ast syn::Macro) {
            self.macro_invocations = self.macro_invocations.saturating_add(1);
            visit::visit_macro(self, expression);
        }

        fn visit_item(&mut self, item: &'ast syn::Item) {
            self.block_items = self.block_items.saturating_add(1);
            visit::visit_item(self, item);
        }

        fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
            self.returns = self.returns.saturating_add(1);
            visit::visit_expr_return(self, expression);
        }
    }

    let mut visitor = LocalVisitor {
        client_locals: Vec::new(),
        permit_locals: Vec::new(),
        client_bindings: 0,
        permit_bindings: 0,
        permit_argument_bindings: BTreeMap::new(),
        origin_bindings: 0,
        transport_bindings: 0,
        configuration_destructures: 0,
        macro_invocations: 0,
        block_items: 0,
        returns: 0,
    };
    visitor.visit_signature(&method.sig);
    visitor.visit_block(&method.block);
    method.attrs.is_empty()
        && adapter_configuration_parameter_is_exact(method)
        && matches!(method.block.stmts.first(), Some(syn::Stmt::Local(local))
            if native_oast_configuration_destructure_is_exact(local))
        && visitor.client_bindings == 3
        && visitor.permit_bindings == 1
        && PERMIT_ARGUMENTS
            .iter()
            .all(|argument| visitor.permit_argument_bindings.get(*argument) == Some(&1))
        && visitor.origin_bindings == 1
        && visitor.transport_bindings == 1
        && visitor.configuration_destructures == 1
        && visitor.macro_invocations == 0
        && visitor.block_items == 0
        && visitor.returns == 0
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && method.sig.constness.is_none()
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.variadic.is_none()
        && matches!(visitor.permit_locals.as_slice(), [permit]
        if permit_binding_is_exact(permit)
            && block_consumes_binding_as_exact_shorthand_field(
                &method.block,
                "Self",
                "permit",
            ))
        && matches!(visitor.client_locals.as_slice(), [enabled, disabled, checked]
        if client_binding_is_exact(enabled)
            && has_only_exact_feature_cfg(&enabled.attrs, FEATURE)
            && enabled.init.as_ref().is_some_and(|initializer|
                initializer.diverge.is_none()
                    && owned_profile_client_match_is_exact(&initializer.expr))
            && client_binding_is_exact(disabled)
            && has_only_exact_not_feature_cfg(&disabled.attrs, FEATURE)
            && disabled.init.as_ref().is_some_and(|initializer|
                initializer.diverge.is_none()
                    && native_oast_client_call_is_exact(&initializer.expr, "new", false))
            && checked_client_binding_is_exact(checked)
            && block_consumes_binding_as_exact_shorthand_field(
                &method.block,
                "Self",
                "client",
            ))
}

fn permit_binding_is_exact(local: &syn::Local) -> bool {
    const ARGUMENTS: [&str; 7] = [
        "origin",
        "target_origin",
        "limits",
        "accounting",
        "parent_budget",
        "cancellation",
        "parent_deadline",
    ];

    let syn::Pat::Ident(binding) = &local.pat else {
        return false;
    };
    let Some(initializer) = &local.init else {
        return false;
    };
    let syn::Expr::Try(attempt) = initializer.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Call(mint) = attempt.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Path(function) = mint.func.as_ref() else {
        return false;
    };

    local.attrs.is_empty()
        && binding.attrs.is_empty()
        && binding.by_ref.is_none()
        && binding.mutability.is_none()
        && normalize_identifier(&binding.ident.to_string()) == "permit"
        && binding.subpat.is_none()
        && initializer.diverge.is_none()
        && attempt.attrs.is_empty()
        && mint.attrs.is_empty()
        && function.attrs.is_empty()
        && function.qself.is_none()
        && exact_syn_path(&function.path, &["NativeOastProviderPermit", "mint"])
        && mint.args.len() == ARGUMENTS.len()
        && mint
            .args
            .iter()
            .zip(ARGUMENTS)
            .all(|(argument, expected)| path_expression_name(argument).as_deref() == Some(expected))
}

fn adapter_configuration_parameter_is_exact(method: &syn::ImplItemFn) -> bool {
    let parameters = method
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(argument)
                if matches!(argument.pat.as_ref(), syn::Pat::Ident(binding)
                    if binding.attrs.is_empty()
                        && binding.by_ref.is_none()
                        && binding.mutability.is_none()
                        && normalize_identifier(&binding.ident.to_string()) == "configuration"
                        && binding.subpat.is_none()) =>
            {
                Some(argument)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    matches!(parameters.as_slice(), [parameter]
        if parameter.attrs.is_empty()
            && type_path_tail(&parameter.ty).as_deref()
                == Some("NativeOastProviderConfiguration"))
}

fn native_oast_configuration_destructure_is_exact(local: &syn::Local) -> bool {
    const FEATURE: &str = "xml-external-entity-owned-https-test-profile";
    const FIELDS: [&str; 6] = [
        "origin",
        "assessment_id",
        "epoch",
        "administrator",
        "limits",
        "transport",
    ];

    if !local.attrs.is_empty() {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    if initializer.diverge.is_some()
        || path_expression_name(&initializer.expr).as_deref() != Some("configuration")
    {
        return false;
    }
    let syn::Pat::Struct(pattern) = &local.pat else {
        return false;
    };
    if !pattern.attrs.is_empty()
        || pattern.qself.is_some()
        || !exact_syn_path(&pattern.path, &["NativeOastProviderConfiguration"])
        || pattern.rest.is_some()
        || pattern.fields.len() != FIELDS.len()
    {
        return false;
    }

    pattern.fields.iter().zip(FIELDS).all(|(field, expected)| {
        let member_is_exact = matches!(&field.member, syn::Member::Named(member)
                if normalize_identifier(&member.to_string()) == expected);
        let binding_is_exact = matches!(field.pat.as_ref(), syn::Pat::Ident(binding)
                if binding.attrs.is_empty()
                    && binding.by_ref.is_none()
                    && binding.mutability.is_none()
                    && normalize_identifier(&binding.ident.to_string()) == expected
                    && binding.subpat.is_none());
        let attributes_are_exact = if expected == "transport" {
            has_only_exact_feature_cfg(&field.attrs, FEATURE)
        } else {
            field.attrs.is_empty()
        };
        member_is_exact && field.colon_token.is_none() && binding_is_exact && attributes_are_exact
    })
}

fn block_consumes_binding_as_exact_shorthand_field(
    block: &syn::Block,
    structure: &str,
    binding: &str,
) -> bool {
    struct FieldVisitor<'a> {
        structure: &'a str,
        binding: &'a str,
        structures: usize,
        fields: usize,
        exact: usize,
    }

    impl<'ast> Visit<'ast> for FieldVisitor<'_> {
        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            if expression.qself.is_none() && exact_syn_path(&expression.path, &[self.structure]) {
                self.structures = self.structures.saturating_add(1);
                for field in &expression.fields {
                    if matches!(&field.member, syn::Member::Named(member)
                        if member == self.binding)
                    {
                        self.fields = self.fields.saturating_add(1);
                        if field.attrs.is_empty()
                            && field.colon_token.is_none()
                            && path_expression_name(&field.expr).as_deref() == Some(self.binding)
                        {
                            self.exact = self.exact.saturating_add(1);
                        }
                    }
                }
            }
            visit::visit_expr_struct(self, expression);
        }
    }

    let mut visitor = FieldVisitor {
        structure,
        binding,
        structures: 0,
        fields: 0,
        exact: 0,
    };
    visitor.visit_block(block);
    visitor.structures == 1 && visitor.fields == 1 && visitor.exact == 1
}

fn pattern_binds_identifier(pattern: &syn::Pat, expected: &str) -> bool {
    struct BindingVisitor<'a> {
        expected: &'a str,
        found: bool,
    }

    impl<'ast> Visit<'ast> for BindingVisitor<'_> {
        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            if pattern.ident.to_string().trim_start_matches("r#") == self.expected {
                self.found = true;
            }
            visit::visit_pat_ident(self, pattern);
        }
    }

    let mut visitor = BindingVisitor {
        expected,
        found: false,
    };
    visitor.visit_pat(pattern);
    visitor.found
}

fn client_binding_is_exact(local: &syn::Local) -> bool {
    matches!(&local.pat, syn::Pat::Ident(pattern)
        if pattern.attrs.is_empty()
            && pattern.ident == "client"
            && pattern.by_ref.is_none()
            && pattern.mutability.is_none()
            && pattern.subpat.is_none())
}

fn checked_client_binding_is_exact(local: &syn::Local) -> bool {
    if !client_binding_is_exact(local) || !local.attrs.is_empty() {
        return false;
    }
    let Some(initializer) = &local.init else {
        return false;
    };
    let syn::Expr::Try(attempt) = initializer.expr.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(map) = attempt.expr.as_ref() else {
        return false;
    };
    initializer.diverge.is_none()
        && map.attrs.is_empty()
        && map.method == "map_err"
        && map.turbofish.is_none()
        && path_expression_name(&map.receiver).as_deref() == Some("client")
        && matches!(map.args.first(), Some(syn::Expr::Closure(_)) if map.args.len() == 1)
}

fn owned_profile_client_match_is_exact(expression: &syn::Expr) -> bool {
    let syn::Expr::Match(selection) = expression else {
        return false;
    };
    if !selection.attrs.is_empty()
        || path_expression_name(&selection.expr).as_deref() != Some("transport")
        || selection.arms.len() != 2
    {
        return false;
    }
    let [production, owned] = selection.arms.as_slice() else {
        return false;
    };
    let production_pattern_is_exact = matches!(&production.pat, syn::Pat::Path(path)
    if path.qself.is_none()
        && exact_syn_path(
            &path.path,
            &["NativeOastProviderTransport", "Production"],
        ));
    let owned_pattern_is_exact = matches!(&owned.pat, syn::Pat::TupleStruct(pattern)
        if pattern.qself.is_none()
            && exact_syn_path(
                &pattern.path,
                &["NativeOastProviderTransport", "OwnedHttpsTestProfile"],
            )
            && matches!(pattern.elems.first(), Some(syn::Pat::Ident(binding))
                if pattern.elems.len() == 1
                    && binding.attrs.is_empty()
                    && binding.by_ref.is_none()
                    && binding.mutability.is_none()
                    && binding.ident == "profile_port"
                    && binding.subpat.is_none()));
    production.attrs.is_empty()
        && production.guard.is_none()
        && production_pattern_is_exact
        && native_oast_client_call_is_exact(&production.body, "new", false)
        && owned.attrs.is_empty()
        && owned.guard.is_none()
        && owned_pattern_is_exact
        && sole_block_expression(&owned.body).is_some_and(|expression| {
            native_oast_client_call_is_exact(expression, "new_owned_https_test_profile", true)
        })
}

fn sole_block_expression(expression: &syn::Expr) -> Option<&syn::Expr> {
    let syn::Expr::Block(block) = expression else {
        return None;
    };
    if !block.attrs.is_empty() || block.label.is_some() {
        return None;
    }
    let [syn::Stmt::Expr(expression, None)] = block.block.stmts.as_slice() else {
        return None;
    };
    Some(expression)
}

fn native_oast_client_call_is_exact(
    expression: &syn::Expr,
    method: &str,
    includes_profile_port: bool,
) -> bool {
    let syn::Expr::Call(call) = expression else {
        return false;
    };
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    let expected = ["NativeOastClient", method];
    if !call.attrs.is_empty()
        || function.qself.is_some()
        || !exact_syn_path(&function.path, &expected)
        || call.args.len() != if includes_profile_port { 2 } else { 1 }
        || !origin_clone_is_exact(&call.args[0])
    {
        return false;
    }
    !includes_profile_port
        || call.args.get(1).is_some_and(|argument| {
            path_expression_name(argument).as_deref() == Some("profile_port")
        })
}

fn origin_clone_is_exact(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::MethodCall(call)
        if call.attrs.is_empty()
            && call.method == "clone"
            && call.turbofish.is_none()
            && call.args.is_empty()
            && path_expression_name(&call.receiver).as_deref() == Some("origin"))
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
    (path.attrs.is_empty()
        && path.qself.is_none()
        && path.path.leading_colon.is_none()
        && path.path.segments.len() == 1
        && matches!(path.path.segments[0].arguments, PathArguments::None))
    .then(|| path.path.segments[0].ident.to_string())
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

fn exact_syn_path(path: &syn::Path, names: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == names.len()
        && path.segments.iter().zip(names).all(|(segment, expected)| {
            segment.ident == *expected && matches!(segment.arguments, PathArguments::None)
        })
}

fn exact_type_path(ty: &Type, names: &[&str]) -> bool {
    matches!(ty, Type::Path(path) if path.qself.is_none() && exact_syn_path(&path.path, names))
}

fn exact_single_wrapper_type(ty: &Type, wrapper: &[&str], inner: &[&str]) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    if path.qself.is_some()
        || path.path.leading_colon.is_some()
        || path.path.segments.len() != wrapper.len()
    {
        return false;
    }
    for (index, (segment, expected)) in path.path.segments.iter().zip(wrapper).enumerate() {
        if segment.ident != *expected {
            return false;
        }
        if index + 1 != wrapper.len() && !matches!(segment.arguments, PathArguments::None) {
            return false;
        }
    }
    let Some(last) = path.path.segments.last() else {
        return false;
    };
    let PathArguments::AngleBracketed(arguments) = &last.arguments else {
        return false;
    };
    matches!(arguments.args.first(), Some(GenericArgument::Type(ty)) if exact_type_path(ty, inner))
        && arguments.args.len() == 1
}

fn exact_single_type_argument<'a>(ty: &'a Type, wrapper: &str) -> Option<&'a Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() || path.path.leading_colon.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let segment = path.path.segments.first()?;
    if segment.ident != wrapper {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    if arguments.args.len() != 1 {
        return None;
    }
    match arguments.args.first()? {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}

fn exact_vec_vec_u8(ty: &Type) -> bool {
    exact_single_type_argument(ty, "Vec")
        .and_then(|inner| exact_single_type_argument(inner, "Vec"))
        .is_some_and(|inner| exact_type_path(inner, &["u8"]))
}

fn exact_private_identity_oracle_storage(ty: &Type) -> bool {
    exact_single_type_argument(ty, "StdMutex").is_some_and(exact_vec_vec_u8)
}

fn exact_receiver_method_call(expression: &syn::Expr, receiver: &str, method: &str) -> bool {
    let syn::Expr::MethodCall(call) = expression else {
        return false;
    };
    call.attrs.is_empty()
        && matches!(call.receiver.as_ref(), syn::Expr::Path(path)
        if path.attrs.is_empty()
            && path.qself.is_none()
            && path.path.leading_colon.is_none()
            && path.path.is_ident(receiver))
        && call.method == method
        && call.turbofish.is_none()
        && call.args.is_empty()
}

fn exact_integer_literal(expression: &syn::Expr, expected: usize) -> bool {
    matches!(expression, syn::Expr::Lit(literal)
        if literal.attrs.is_empty()
            && matches!(&literal.lit, syn::Lit::Int(value)
                if value.base10_parse::<usize>().is_ok_and(|actual| actual == expected)))
}

#[derive(Default)]
struct PrivateIdentityOracleBoundVisitor {
    count_bounds: usize,
    byte_bounds: usize,
}

impl<'ast> Visit<'ast> for PrivateIdentityOracleBoundVisitor {
    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        if matches!(&expression.op, syn::BinOp::Lt(_))
            && exact_receiver_method_call(&expression.left, "identities", "len")
            && exact_integer_literal(&expression.right, 4)
        {
            self.count_bounds += 1;
        }
        if matches!(&expression.op, syn::BinOp::Le(_))
            && exact_receiver_method_call(&expression.left, "value", "len")
            && exact_integer_literal(&expression.right, 64)
        {
            self.byte_bounds += 1;
        }
        visit::visit_expr_binary(self, expression);
    }
}

fn private_identity_oracle_method_is_exact(method: &syn::ImplItemFn) -> bool {
    if !matches!(method.vis, Visibility::Inherited)
        || !plain_method_shape(method, false)
        || method.sig.inputs.len() != 2
        || !matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
            if receiver.reference.is_some()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none())
        || !exact_shared_reference_argument(method.sig.inputs.iter().nth(1), "value", &["str"])
        || !matches!(&method.sig.output, ReturnType::Default)
    {
        return false;
    }
    let mut visitor = PrivateIdentityOracleBoundVisitor::default();
    visitor.visit_block(&method.block);
    visitor.count_bounds == 1 && visitor.byte_bounds == 1
}

fn exact_argument_type<'a>(input: Option<&'a FnArg>, name: &str) -> Option<&'a Type> {
    let FnArg::Typed(argument) = input? else {
        return None;
    };
    let syn::Pat::Ident(pattern) = argument.pat.as_ref() else {
        return None;
    };
    (pattern.ident == name
        && pattern.by_ref.is_none()
        && pattern.mutability.is_none()
        && pattern.subpat.is_none())
    .then_some(argument.ty.as_ref())
}

fn exact_typed_argument(input: Option<&FnArg>, name: &str, ty: &[&str]) -> bool {
    exact_argument_type(input, name).is_some_and(|actual| exact_type_path(actual, ty))
}

fn exact_shared_reference_argument(input: Option<&FnArg>, name: &str, ty: &[&str]) -> bool {
    exact_argument_type(input, name).is_some_and(|actual| {
        matches!(actual, Type::Reference(reference)
            if reference.lifetime.is_none()
                && reference.mutability.is_none()
                && exact_type_path(&reference.elem, ty))
    })
}

fn exact_unattributed_shared_reference_argument(
    input: Option<&FnArg>,
    name: &str,
    ty: &[&str],
) -> bool {
    matches!(input, Some(FnArg::Typed(argument))
        if argument.attrs.is_empty()
            && matches!(argument.pat.as_ref(), syn::Pat::Ident(pattern)
                if pattern.attrs.is_empty()
                    && pattern.ident == name
                    && pattern.by_ref.is_none()
                    && pattern.mutability.is_none()
                    && pattern.subpat.is_none())
            && matches!(argument.ty.as_ref(), Type::Reference(reference)
                if reference.lifetime.is_none()
                    && reference.mutability.is_none()
                    && exact_type_path(&reference.elem, ty)))
}

fn owned_receiver(input: Option<&FnArg>) -> bool {
    matches!(input, Some(FnArg::Receiver(receiver))
        if receiver.reference.is_none()
            && receiver.mutability.is_none()
            && receiver.colon_token.is_none())
}

fn plain_impl_shape(implementation: &syn::ItemImpl) -> bool {
    implementation.defaultness.is_none()
        && implementation.unsafety.is_none()
        && implementation.generics.params.is_empty()
        && implementation.generics.where_clause.is_none()
}

fn plain_method_shape(method: &syn::ImplItemFn, is_const: bool) -> bool {
    plain_method_signature_shape(method, is_const) && has_no_conditional_cfg(&method.attrs)
}

fn plain_method_signature_shape(method: &syn::ImplItemFn, is_const: bool) -> bool {
    method.defaultness.is_none()
        && method.sig.constness.is_some() == is_const
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && method.sig.variadic.is_none()
}

fn is_crate_visibility(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Restricted(restricted)
        if restricted.in_token.is_none() && restricted.path.is_ident("crate"))
}

fn return_type_is_path(output: &ReturnType, expected: &[&str]) -> bool {
    matches!(output, ReturnType::Type(_, ty) if exact_type_path(ty, expected))
}

fn return_type_is_single_wrapper(output: &ReturnType, wrapper: &[&str], inner: &[&str]) -> bool {
    matches!(output, ReturnType::Type(_, ty) if exact_single_wrapper_type(ty, wrapper, inner))
}

fn return_type_is_result_unit_error(output: &ReturnType, error: &[&str]) -> bool {
    let ReturnType::Type(_, ty) = output else {
        return false;
    };
    let Type::Path(path) = ty.as_ref() else {
        return false;
    };
    let Some(result) = path.path.segments.first() else {
        return false;
    };
    if path.qself.is_some()
        || path.path.leading_colon.is_some()
        || path.path.segments.len() != 1
        || result.ident != "Result"
    {
        return false;
    }
    let PathArguments::AngleBracketed(arguments) = &result.arguments else {
        return false;
    };
    let mut arguments = arguments.args.iter();
    matches!(arguments.next(), Some(GenericArgument::Type(Type::Tuple(tuple))) if tuple.elems.is_empty())
        && matches!(arguments.next(), Some(GenericArgument::Type(ty)) if exact_type_path(ty, error))
        && arguments.next().is_none()
}

fn request_ledger_fixture_signature_is_exact(signature: &syn::Signature) -> bool {
    signature.constness.is_none()
        && signature.asyncness.is_some()
        && signature.unsafety.is_none()
        && signature.abi.is_none()
        && signature.generics.params.is_empty()
        && signature.generics.where_clause.is_none()
        && signature.variadic.is_none()
        && signature.inputs.len() == 3
        && exact_typed_argument(signature.inputs.first(), "listener", &["TcpListener"])
        && exact_typed_argument(
            signature.inputs.iter().nth(1),
            "provider",
            &["ProviderState"],
        )
        && exact_typed_argument(
            signature.inputs.iter().nth(2),
            "ledger",
            &["ProviderTestRequestLedger"],
        )
        && return_type_is_result_unit_error(&signature.output, &["ProviderServerError"])
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

fn has_only_exact_feature_cfg(attributes: &[syn::Attribute], feature: &str) -> bool {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("cfg"))
        .count()
        == 1
        && !attributes
            .iter()
            .any(|attribute| attribute.path().is_ident("cfg_attr"))
        && has_exact_feature_cfg(attributes, feature)
}

fn has_only_exact_not_feature_cfg(attributes: &[syn::Attribute], feature: &str) -> bool {
    attributes.len() == 1
        && attributes[0].path().is_ident("cfg")
        && attributes[0].meta.require_list().is_ok_and(|list| {
            list.tokens
                .to_string()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                == format!("not(feature=\"{feature}\")")
        })
}

fn has_no_conditional_cfg(attributes: &[syn::Attribute]) -> bool {
    !attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
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
    for fixture_name in [
        "serve_provider_on_listener",
        "serve_provider_on_listener_with_poll_barrier",
        "serve_provider_on_listener_with_request_ledger",
    ] {
        let fixtures = server
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Fn(function) if function.sig.ident == fixture_name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        if fixtures.len() != 1
            || !matches!(fixtures[0].vis, Visibility::Public(_))
            || cfg_feature_names(&fixtures[0].attrs) != BTreeSet::from(["test-support".to_owned()])
            || !has_doc_hidden(&fixtures[0].attrs)
        {
            violations.push(format!(
                "{PACKAGE} fixture `{fixture_name}` must be exactly public, doc-hidden, and gated only by `test-support`"
            ));
        }
    }
    let request_ledger_fixtures = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function)
                if function.sig.ident == "serve_provider_on_listener_with_request_ledger" =>
            {
                Some(function)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    if request_ledger_fixtures.len() != 1
        || !request_ledger_fixtures.first().is_some_and(|function| {
            matches!(function.vis, Visibility::Public(_))
                && has_only_exact_feature_cfg(&function.attrs, "test-support")
                && has_doc_hidden(&function.attrs)
                && request_ledger_fixture_signature_is_exact(&function.sig)
        })
    {
        violations.push(format!(
            "{PACKAGE} request-ledger fixture must retain its exact async listener, provider, ledger, and ProviderServerError signature"
        ));
    }
    let fixture_barriers = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) if item.ident == "ProviderTestPollBarrier" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if fixture_barriers.len() != 1
        || !matches!(fixture_barriers[0].vis, Visibility::Public(_))
        || cfg_feature_names(&fixture_barriers[0].attrs)
            != BTreeSet::from(["test-support".to_owned()])
        || !has_doc_hidden(&fixture_barriers[0].attrs)
    {
        violations.push(format!(
            "{PACKAGE} fixture poll barrier must be exactly public, doc-hidden, and gated only by `test-support`"
        ));
    }
    for fixture_type in ["ProviderTestRequestLedger", "ProviderTestRequestSnapshot"] {
        let types = server
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(item) if item.ident == fixture_type => Some(item),
                _ => None,
            })
            .collect::<Vec<_>>();
        if types.len() != 1
            || !matches!(types[0].vis, Visibility::Public(_))
            || cfg_feature_names(&types[0].attrs) != BTreeSet::from(["test-support".to_owned()])
            || !has_doc_hidden(&types[0].attrs)
        {
            violations.push(format!(
                "{PACKAGE} fixture type `{fixture_type}` must be exactly public, doc-hidden, and gated only by `test-support`"
            ));
        }
    }
    let request_ledgers = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) if item.ident == "ProviderTestRequestLedger" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let ledger_state_fields = request_ledgers
        .first()
        .map(|record| record.fields.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    if ledger_state_fields.len() != 1
        || ledger_state_fields[0]
            .ident
            .as_ref()
            .is_none_or(|name| name != "state")
        || !matches!(ledger_state_fields[0].vis, Visibility::Inherited)
        || !exact_nested_type(
            &ledger_state_fields[0].ty,
            &["Arc", "ProviderTestRequestLedgerState"],
        )
    {
        violations.push(format!(
            "{PACKAGE} fixture request ledger must retain exactly one private typed state handle"
        ));
    }
    let request_ledger_states = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) if item.ident == "ProviderTestRequestLedgerState" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let request_ledger_state_fields = request_ledger_states
        .first()
        .map(|record| {
            record
                .fields
                .iter()
                .filter_map(|field| {
                    field.ident.as_ref().map(|identifier| {
                        (
                            identifier.to_string(),
                            matches!(field.vis, Visibility::Inherited),
                            type_path_tail(&field.ty),
                        )
                    })
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let mut expected_request_ledger_state_fields = [
        "allocate", "callback", "cleanup", "other", "poll", "register",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), true, Some("AtomicUsize".to_owned())))
    .collect::<BTreeSet<_>>();
    expected_request_ledger_state_fields.insert((
        "private_identity_sentinels".to_owned(),
        true,
        Some("StdMutex".to_owned()),
    ));
    let private_identity_storage_is_exact = request_ledger_states
        .first()
        .and_then(|record| {
            record.fields.iter().find(|field| {
                field
                    .ident
                    .as_ref()
                    .is_some_and(|name| name == "private_identity_sentinels")
            })
        })
        .is_some_and(|field| exact_private_identity_oracle_storage(&field.ty));
    if request_ledger_states.len() != 1
        || !matches!(request_ledger_states[0].vis, Visibility::Inherited)
        || cfg_feature_names(&request_ledger_states[0].attrs)
            != BTreeSet::from(["test-support".to_owned()])
        || request_ledger_state_fields != expected_request_ledger_state_fields
        || !private_identity_storage_is_exact
    {
        violations.push(format!(
            "{PACKAGE} fixture request-ledger state must retain exactly six private raw-free atomic counters plus one bounded private identity oracle"
        ));
    }
    let request_snapshots = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item) if item.ident == "ProviderTestRequestSnapshot" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let snapshot_fields = request_snapshots
        .first()
        .map(|record| {
            record
                .fields
                .iter()
                .filter_map(|field| {
                    field.ident.as_ref().map(|identifier| {
                        (
                            identifier.to_string(),
                            matches!(field.vis, Visibility::Public(_)),
                            type_path_tail(&field.ty),
                        )
                    })
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let expected_snapshot_fields = [
        "allocate", "callback", "cleanup", "other", "poll", "register",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), true, Some("usize".to_owned())))
    .collect::<BTreeSet<_>>();
    if snapshot_fields != expected_snapshot_fields {
        violations.push(format!(
            "{PACKAGE} fixture request snapshot must expose exactly six public raw-free usize counters"
        ));
    }
    let fixture_ledger_impls = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if implementation.trait_.is_none()
                    && type_path_tail(&implementation.self_ty).as_deref()
                        == Some("ProviderTestRequestLedger") =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let public_ledger_methods = fixture_ledger_impls
        .first()
        .map(|implementation| {
            implementation
                .items
                .iter()
                .filter_map(|item| match item {
                    ImplItem::Fn(method) if matches!(method.vis, Visibility::Public(_)) => {
                        Some(method.sig.ident.to_string())
                    },
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let ledger_method_signatures_are_exact =
        fixture_ledger_impls.first().is_some_and(|implementation| {
            let methods = implementation
                .items
                .iter()
                .filter_map(|item| match item {
                    ImplItem::Fn(method) if matches!(method.vis, Visibility::Public(_)) => {
                        Some((method.sig.ident.to_string(), method))
                    },
                    _ => None,
                })
                .collect::<BTreeMap<_, _>>();
            let is_plain = |method: &syn::ImplItemFn| {
                method.sig.constness.is_none()
                    && method.sig.asyncness.is_none()
                    && method.sig.unsafety.is_none()
                    && method.sig.abi.is_none()
                    && method.sig.generics.params.is_empty()
                    && method.sig.generics.where_clause.is_none()
                    && method.sig.variadic.is_none()
            };
            let private_identity_recorders = implementation
                .items
                .iter()
                .filter_map(|item| match item {
                    ImplItem::Fn(method) if method.sig.ident == "record_private_identity" => {
                        Some(method)
                    },
                    _ => None,
                })
                .collect::<Vec<_>>();
            methods.get("new").is_some_and(|method| {
                is_plain(method)
                    && method.sig.inputs.is_empty()
                    && return_type_ends_with(&method.sig.output, "Self")
            }) && methods.get("snapshot").is_some_and(|method| {
                is_plain(method)
                    && method.sig.inputs.len() == 1
                    && matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
                    if receiver.reference.is_some()
                        && receiver.mutability.is_none()
                        && receiver.colon_token.is_none())
                    && return_type_ends_with(&method.sig.output, "ProviderTestRequestSnapshot")
            }) && methods
                .get("private_identity_sentinels")
                .is_some_and(|method| {
                    is_plain(method)
                        && method.sig.inputs.len() == 1
                        && matches!(method.sig.inputs.first(), Some(FnArg::Receiver(receiver))
                    if receiver.reference.is_some()
                        && receiver.mutability.is_none()
                        && receiver.colon_token.is_none())
                        && matches!(&method.sig.output, ReturnType::Type(_, output)
                        if exact_vec_vec_u8(output))
                })
                && matches!(private_identity_recorders.as_slice(), [method]
                if private_identity_oracle_method_is_exact(method))
        });
    if fixture_ledger_impls.len() != 1
        || cfg_feature_names(&fixture_ledger_impls[0].attrs)
            != BTreeSet::from(["test-support".to_owned()])
        || public_ledger_methods
            != BTreeSet::from([
                "new".to_owned(),
                "private_identity_sentinels".to_owned(),
                "snapshot".to_owned(),
            ])
        || !ledger_method_signatures_are_exact
    {
        violations.push(format!(
            "{PACKAGE} fixture request ledger must expose only the exact test-support construction, raw-free snapshot, and bounded private-identity oracle methods"
        ));
    }
    let fixture_barrier_impls = server
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation)
                if implementation.trait_.is_none()
                    && matches!(implementation.self_ty.as_ref(), Type::Path(path)
                        if path.qself.is_none()
                            && path.path.is_ident("ProviderTestPollBarrier")) =>
            {
                Some(implementation)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let public_barrier_methods = fixture_barrier_impls
        .first()
        .map(|implementation| {
            implementation
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::ImplItem::Fn(method) if matches!(method.vis, Visibility::Public(_)) => {
                        Some(method.sig.ident.to_string())
                    },
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if fixture_barrier_impls.len() != 1
        || cfg_feature_names(&fixture_barrier_impls[0].attrs)
            != BTreeSet::from(["test-support".to_owned()])
        || public_barrier_methods
            != BTreeSet::from([
                "arm".to_owned(),
                "new".to_owned(),
                "wait_for_poll_snapshot".to_owned(),
            ])
    {
        violations.push(format!(
            "{PACKAGE} fixture poll barrier must expose only the exact test-support coordination methods"
        ));
    }
    for function in server.items.iter().filter_map(|item| match item {
        Item::Fn(function) => Some(function),
        _ => None,
    }) {
        if matches!(function.vis, Visibility::Public(_))
            && !matches!(
                function.sig.ident.to_string().as_str(),
                "serve_provider"
                    | "serve_provider_on_listener"
                    | "serve_provider_on_listener_with_poll_barrier"
                    | "serve_provider_on_listener_with_request_ledger"
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
            (
                "server::serve_provider_on_listener_with_poll_barrier".to_owned(),
                BTreeSet::from(["test-support".to_owned()]),
                true,
            ),
            (
                "server::serve_provider_on_listener_with_request_ledger".to_owned(),
                BTreeSet::from(["test-support".to_owned()]),
                true,
            ),
            (
                "server::ProviderTestPollBarrier".to_owned(),
                BTreeSet::from(["test-support".to_owned()]),
                true,
            ),
            (
                "server::ProviderTestRequestLedger".to_owned(),
                BTreeSet::from(["test-support".to_owned()]),
                true,
            ),
            (
                "server::ProviderTestRequestSnapshot".to_owned(),
                BTreeSet::from(["test-support".to_owned()]),
                true,
            ),
        ])
    {
        violations.push(format!(
            "{PACKAGE} library must export only its server API plus the exact doc-hidden test-support fixture surface"
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
        "Arc::clone(&self.requests).try_acquire_owned()",
        "constHEADER_READ_TIMEOUT:Duration=Duration::from_secs(10);",
        "constREQUEST_TIMEOUT:Duration=Duration::from_secs(15);",
        "constCONNECTION_IDLE_TIMEOUT:Duration=Duration::from_secs(30);",
        "constCONNECTION_LIFETIME:Duration=Duration::from_secs(120);",
        ".layer(DefaultBodyLimit::max(MAX_MANAGEMENT_BODY_BYTES)).layer(from_fn_with_state(state.clone(),bound_request)).with_state(state)",
        "asyncfnbound_request(State(state):State<AppState>,request:Request<Body>,next:Next,)->Response{",
        "letOk(_permit)=state.admit()else{",
        "next.run(request).await",
        "timeout(REQUEST_TIMEOUT,operation).await.unwrap_or_else(|_|closing_error(StatusCode::REQUEST_TIMEOUT))",
        ".insert(CONNECTION,HeaderValue::from_static(\"close\"));",
        "letconnection_limit=usize::from(provider.max_concurrent_requests());",
        "letmutconnections=FuturesUnordered::new();",
        "ifconnections.len()>=connection_limit{let_=connections.next().await;continue;}",
        "ifconnections.is_empty(){",
        "tokio::select!{",
        "_=connections.next()=>{}",
        "letmutbuilder=http1::Builder::new();",
        "builder.timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT).keep_alive(true);",
        "timeout(CONNECTION_LIFETIME,builder.serve_connection(TokioIo::new(IdleIo::new(stream)),service),).await",
        "deadline:Box::pin(sleep(CONNECTION_IDLE_TIMEOUT))",
        "ifself.deadline.as_mut().poll(cx).is_ready(){",
        ".reset(Instant::now()+CONNECTION_IDLE_TIMEOUT);",
        "ifmatches!(result,Poll::Ready(Ok(())))&&buffer.filled().len()>before{this.made_progress();}",
        "ifmatches!(result,Poll::Ready(Ok(count))ifcount>0){this.made_progress();}",
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
        (".try_acquire_owned()", 1),
        ("state.admit()", 1),
        (".header_read_timeout(", 1),
        (".timer(", 1),
        (".keep_alive(", 1),
        ("this.check_deadline(cx)?;", 4),
        ("this.made_progress();", 2),
    ] {
        if compact.matches(required).count() != count {
            violations.push(format!(
                "{PACKAGE} bounded server transport must contain exactly {count} `{required}` sites"
            ));
        }
    }
    for forbidden in [
        ".acquire_owned(",
        ".acquire(",
        ".try_acquire(",
        ".header_read_timeout(None)",
        ".keep_alive(false)",
        "axum::serve",
        "hyper::Server",
        "tokio::spawn",
        "spawn_blocking",
        "thread::spawn",
    ] {
        if compact.contains(forbidden) {
            violations.push(format!(
                "{PACKAGE} bounded server transport must not use `{forbidden}`"
            ));
        }
    }
    if !admission_precedes_body_dispatch(source) {
        violations.push(format!(
            "{PACKAGE} request middleware must acquire and retain its permit before dispatching the unconsumed body"
        ));
    }
    violations
}

fn admission_precedes_body_dispatch(source: &str) -> bool {
    let Ok(syntax) = syn::parse_file(source) else {
        return false;
    };
    let Some(function) = exact_bound_request_function(&syntax) else {
        return false;
    };
    // Permit only the exact test-support request-ledger observation before the
    // operation future. It records method/route/header classifications without
    // touching the body. The future itself must still acquire its owned permit
    // first and retain it through the awaited handler dispatch.
    let [ledger, syn::Stmt::Local(operation), syn::Stmt::Expr(_, None)] =
        function.block.stmts.as_slice()
    else {
        return false;
    };
    if !is_exact_test_request_ledger_prelude(ledger) {
        return false;
    }
    let syn::Pat::Ident(binding) = &operation.pat else {
        return false;
    };
    if !operation.attrs.is_empty()
        || !binding.attrs.is_empty()
        || binding.by_ref.is_some()
        || binding.mutability.is_some()
        || binding.ident != "operation"
        || binding.subpat.is_some()
    {
        return false;
    }
    let Some(initializer) = &operation.init else {
        return false;
    };
    let syn::Expr::Async(operation) = initializer.expr.as_ref() else {
        return false;
    };
    let [syn::Stmt::Local(admission), syn::Stmt::Expr(syn::Expr::Await(dispatch), None)] =
        operation.block.stmts.as_slice()
    else {
        return false;
    };
    let syn::Pat::TupleStruct(pattern) = &admission.pat else {
        return false;
    };
    if !admission.attrs.is_empty()
        || !pattern.attrs.is_empty()
        || !pattern.path.is_ident("Ok")
        || !matches!(pattern.elems.first(), Some(syn::Pat::Ident(permit))
            if permit.attrs.is_empty()
                && permit.by_ref.is_none()
                && permit.mutability.is_none()
                && permit.ident == "_permit"
                && permit.subpat.is_none())
        || pattern.elems.len() != 1
    {
        return false;
    }
    let Some(initializer) = &admission.init else {
        return false;
    };
    let syn::Expr::MethodCall(admit) = initializer.expr.as_ref() else {
        return false;
    };
    let syn::Expr::MethodCall(run) = dispatch.base.as_ref() else {
        return false;
    };
    initializer.diverge.is_some()
        && operation.attrs.is_empty()
        && admit.attrs.is_empty()
        && admit.method == "admit"
        && admit.turbofish.is_none()
        && path_expression_name(&admit.receiver).as_deref() == Some("state")
        && admit.args.is_empty()
        && dispatch.attrs.is_empty()
        && run.attrs.is_empty()
        && run.method == "run"
        && run.turbofish.is_none()
        && path_expression_name(&run.receiver).as_deref() == Some("next")
        && run.args.len() == 1
        && run.args.first().and_then(path_expression_name).as_deref() == Some("request")
}

fn exact_bound_request_function(syntax: &syn::File) -> Option<&syn::ItemFn> {
    if !bound_request_imports_are_exact(syntax) {
        return None;
    }
    struct AlternateBindingVisitor {
        functions: usize,
        patterns: usize,
        imports: usize,
        item_macros: usize,
        value_items: usize,
    }
    impl<'ast> Visit<'ast> for AlternateBindingVisitor {
        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            if normalize_identifier(&function.sig.ident.to_string()) == "bound_request" {
                self.functions = self.functions.saturating_add(1);
            }
            visit::visit_item_fn(self, function);
        }

        fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
            if normalize_identifier(&pattern.ident.to_string()) == "bound_request" {
                self.patterns = self.patterns.saturating_add(1);
            }
            visit::visit_pat_ident(self, pattern);
        }

        fn visit_item_use(&mut self, import: &'ast syn::ItemUse) {
            let mut paths = Vec::new();
            flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
            if paths.iter().any(|path| {
                let normalized = path.replace("r#", "");
                let (target, binding) = normalized
                    .split_once(" as ")
                    .map_or((normalized.as_str(), None), |(target, binding)| {
                        (target, Some(binding))
                    });
                target.ends_with("::*")
                    || target.rsplit("::").next() == Some("bound_request")
                    || binding == Some("bound_request")
            }) {
                self.imports = self.imports.saturating_add(1);
            }
            visit::visit_item_use(self, import);
        }

        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            self.item_macros = self.item_macros.saturating_add(1);
            visit::visit_item_macro(self, item);
        }

        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            if normalize_identifier(&item.ident.to_string()) == "bound_request" {
                self.value_items = self.value_items.saturating_add(1);
            }
            visit::visit_item_const(self, item);
        }

        fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
            if normalize_identifier(&item.ident.to_string()) == "bound_request" {
                self.value_items = self.value_items.saturating_add(1);
            }
            visit::visit_item_static(self, item);
        }

        fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
            if normalize_identifier(&item.ident.to_string()) == "bound_request" {
                self.value_items = self.value_items.saturating_add(1);
            }
            visit::visit_item_struct(self, item);
        }

        fn visit_item_extern_crate(&mut self, item: &'ast syn::ItemExternCrate) {
            if normalize_identifier(&item.ident.to_string()) == "bound_request"
                || item.rename.as_ref().is_some_and(|(_, binding)| {
                    normalize_identifier(&binding.to_string()) == "bound_request"
                })
            {
                self.imports = self.imports.saturating_add(1);
            }
            visit::visit_item_extern_crate(self, item);
        }
    }

    let mut visitor = AlternateBindingVisitor {
        functions: 0,
        patterns: 0,
        imports: 0,
        item_macros: 0,
        value_items: 0,
    };
    visitor.visit_file(syntax);
    if visitor.functions != 1
        || visitor.patterns != 0
        || visitor.imports != 0
        || visitor.item_macros != 0
        || visitor.value_items != 0
    {
        return None;
    }

    let function = syntax.items.iter().find_map(|item| match item {
        Item::Fn(function)
            if normalize_identifier(&function.sig.ident.to_string()) == "bound_request" =>
        {
            Some(function)
        },
        _ => None,
    })?;
    let mut inputs = function.sig.inputs.iter();
    let state = inputs.next()?;
    let request = inputs.next()?;
    let next = inputs.next()?;
    if !matches!(function.vis, Visibility::Inherited)
        || !function.attrs.is_empty()
        || function.sig.constness.is_some()
        || function.sig.asyncness.is_none()
        || function.sig.unsafety.is_some()
        || function.sig.abi.is_some()
        || !function.sig.generics.params.is_empty()
        || function.sig.generics.where_clause.is_some()
        || function.sig.variadic.is_some()
        || inputs.next().is_some()
        || !exact_bound_request_state_argument(state)
        || !exact_unattributed_typed_argument(request, "request", &["Request"], &["Body"])
        || !exact_unattributed_path_argument(next, "next", &["Next"])
        || !return_type_is_path(&function.sig.output, &["Response"])
    {
        return None;
    }
    Some(function)
}

fn bound_request_imports_are_exact(syntax: &syn::File) -> bool {
    const EXPECTED: [&str; 5] = [
        "axum::body::Body",
        "axum::extract::State",
        "axum::middleware::Next",
        "axum::response::Response",
        "hyper::Request",
    ];
    let mut bindings = Vec::new();
    for item in &syntax.items {
        let shadows_crate_name = match item {
            Item::Mod(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "axum" | "hyper"
            ),
            Item::Type(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "axum" | "hyper"
            ),
            Item::Struct(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "axum" | "hyper"
            ),
            Item::Enum(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "axum" | "hyper"
            ),
            Item::Union(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "axum" | "hyper"
            ),
            Item::Trait(item) => matches!(
                normalize_identifier(&item.ident.to_string()),
                "axum" | "hyper"
            ),
            _ => false,
        };
        if shadows_crate_name
            || matches!(item, Item::ExternCrate(external)
                if matches!(normalize_identifier(&external.ident.to_string()), "axum" | "hyper")
                    || external.rename.as_ref().is_some_and(|(_, binding)|
                        matches!(normalize_identifier(&binding.to_string()), "axum" | "hyper")))
        {
            return false;
        }
        let Item::Use(import) = item else {
            continue;
        };
        let mut paths = Vec::new();
        flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
        for path in paths {
            let normalized = path.replace("r#", "");
            let (target, alias) = normalized
                .split_once(" as ")
                .map_or((normalized.as_str(), None), |(target, alias)| {
                    (target, Some(alias))
                });
            let binding = alias.or_else(|| target.rsplit("::").next());
            if target.ends_with("::*")
                || matches!(alias, Some("axum" | "hyper"))
                || matches!(
                    binding,
                    Some("Body" | "State" | "Next" | "Response" | "Request")
                )
            {
                bindings.push((import, normalized));
            }
        }
    }
    bindings.len() == EXPECTED.len()
        && EXPECTED.iter().all(|expected| {
            bindings.iter().any(|(import, path)| {
                path.as_str() == *expected
                    && matches!(import.vis, Visibility::Inherited)
                    && import.attrs.is_empty()
                    && import.leading_colon.is_none()
            })
        })
}

fn exact_bound_request_state_argument(argument: &FnArg) -> bool {
    let FnArg::Typed(argument) = argument else {
        return false;
    };
    let syn::Pat::TupleStruct(pattern) = argument.pat.as_ref() else {
        return false;
    };
    argument.attrs.is_empty()
        && pattern.attrs.is_empty()
        && pattern.qself.is_none()
        && exact_syn_path(&pattern.path, &["State"])
        && matches!(pattern.elems.first(), Some(binding)
            if pattern.elems.len() == 1
                && exact_immutable_identifier_pattern(binding, "state"))
        && exact_single_wrapper_type(&argument.ty, &["State"], &["AppState"])
}

fn exact_unattributed_typed_argument(
    argument: &FnArg,
    name: &str,
    wrapper: &[&str],
    inner: &[&str],
) -> bool {
    matches!(argument, FnArg::Typed(argument)
        if argument.attrs.is_empty()
            && exact_immutable_identifier_pattern(&argument.pat, name)
            && exact_single_wrapper_type(&argument.ty, wrapper, inner))
}

fn exact_unattributed_path_argument(argument: &FnArg, name: &str, ty: &[&str]) -> bool {
    matches!(argument, FnArg::Typed(argument)
        if argument.attrs.is_empty()
            && exact_immutable_identifier_pattern(&argument.pat, name)
            && exact_type_path(&argument.ty, ty))
}

fn is_exact_test_request_ledger_prelude(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::If(observation), None) = statement else {
        return false;
    };
    if observation.attrs.len() != 1
        || !has_only_exact_feature_cfg(&observation.attrs, "test-support")
        || observation.else_branch.is_some()
    {
        return false;
    }

    let syn::Expr::Let(binding) = observation.cond.as_ref() else {
        return false;
    };
    if !binding.attrs.is_empty() {
        return false;
    }
    let syn::Pat::TupleStruct(pattern) = binding.pat.as_ref() else {
        return false;
    };
    let Some(syn::Pat::Ident(ledger)) = pattern.elems.first() else {
        return false;
    };
    if !pattern.path.is_ident("Some")
        || pattern.elems.len() != 1
        || !ledger.attrs.is_empty()
        || ledger.by_ref.is_some()
        || ledger.mutability.is_some()
        || ledger.ident != "ledger"
        || ledger.subpat.is_some()
    {
        return false;
    }

    let syn::Expr::Reference(state_reference) = binding.expr.as_ref() else {
        return false;
    };
    let syn::Expr::Field(state_ledger) = state_reference.expr.as_ref() else {
        return false;
    };
    if !state_reference.attrs.is_empty()
        || state_reference.mutability.is_some()
        || !state_ledger.attrs.is_empty()
        || path_expression_name(&state_ledger.base).as_deref() != Some("state")
        || !matches!(&state_ledger.member, syn::Member::Named(member) if member == "test_request_ledger")
    {
        return false;
    }

    let [syn::Stmt::Expr(syn::Expr::MethodCall(record), Some(_))] =
        observation.then_branch.stmts.as_slice()
    else {
        return false;
    };
    let Some(syn::Expr::Reference(request_reference)) = record.args.first() else {
        return false;
    };
    record.attrs.is_empty()
        && record.method == "record"
        && record.turbofish.is_none()
        && path_expression_name(&record.receiver).as_deref() == Some("ledger")
        && record.args.len() == 1
        && request_reference.attrs.is_empty()
        && request_reference.mutability.is_none()
        && path_expression_name(&request_reference.expr).as_deref() == Some("request")
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
    let Ok(syntax) = syn::parse_file(source) else {
        return source;
    };
    let exact_modules = syntax
        .items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| match item {
            Item::Mod(module) if exact_terminal_test_module(module) => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !matches!(exact_modules.as_slice(), [index] if *index + 1 == syntax.items.len()) {
        return source;
    }
    let boundaries = source
        .match_indices(normalized_marker)
        .map(|(index, _)| index)
        .chain(source.match_indices(windows_marker).map(|(index, _)| index))
        .collect::<Vec<_>>();
    let [boundary] = boundaries.as_slice() else {
        return source;
    };
    let Ok(suffix) = syn::parse_file(&source[*boundary..]) else {
        return source;
    };
    if matches!(suffix.items.as_slice(), [Item::Mod(module)]
        if exact_terminal_test_module(module))
    {
        &source[..*boundary]
    } else {
        source
    }
}

fn exact_terminal_test_module(module: &syn::ItemMod) -> bool {
    module.ident == "tests"
        && matches!(module.vis, Visibility::Inherited)
        && module.content.is_some()
        && module.semi.is_none()
        && module.attrs.len() == 1
        && module.attrs[0].path().is_ident("cfg")
        && module.attrs[0]
            .meta
            .require_list()
            .is_ok_and(|list| compact_whitespace(&list.tokens.to_string()) == "test")
}

/// Removes only the exact scanner OAST test modules from a source file.
///
/// Unlike `production_prefix`, this preserves production items that follow a
/// focused test module. Each removed slice must independently parse as one
/// Rust module, so a malformed or broadened cfg guard fails closed.
fn source_without_exact_oast_test_modules(source: &str) -> Result<String, syn::Error> {
    const TEST_GUARDS: [(&str, &str); 2] = [
        (
            "#[cfg(all(test, feature = \"oast-correlation\"))]",
            "all(test,feature=\"oast-correlation\")",
        ),
        (
            "#[cfg(all(test, feature = \"oast-native-provider\"))]",
            "all(test,feature=\"oast-native-provider\")",
        ),
    ];

    let mut output = String::with_capacity(source.len());
    let mut cursor = 0;
    let mut removed = [0_usize; TEST_GUARDS.len()];
    loop {
        let next = TEST_GUARDS
            .iter()
            .enumerate()
            .filter_map(|(index, (guard, _))| {
                source[cursor..].find(guard).map(|offset| (offset, index))
            })
            .min_by_key(|(offset, _)| *offset);
        let Some((offset, guard_index)) = next else {
            output.push_str(&source[cursor..]);
            break;
        };
        let (guard, expected_cfg) = TEST_GUARDS[guard_index];
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
            if let Ok(module) = syn::parse_str::<syn::ItemMod>(candidate) {
                let exact_guarded_module = matches!(module.vis, Visibility::Inherited)
                    && module.content.is_some()
                    && module.semi.is_none()
                    && module.attrs.len() == 1
                    && module.attrs[0].path().is_ident("cfg")
                    && module.attrs[0].meta.require_list().is_ok_and(|list| {
                        compact_whitespace(&list.tokens.to_string()) == expected_cfg
                    });
                if exact_guarded_module {
                    end = Some(candidate_end);
                    break;
                }
            }
        }
        let Some(candidate_end) = end else {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "OAST test cfg guard did not contain one complete module",
            ));
        };
        removed[guard_index] = removed[guard_index].saturating_add(1);
        cursor = candidate_end;
    }

    let syntax = syn::parse_file(source)?;
    let mut parsed = [0_usize; TEST_GUARDS.len()];
    for item in &syntax.items {
        let Item::Mod(module) = item else {
            continue;
        };
        if !matches!(module.vis, Visibility::Inherited)
            || module.content.is_none()
            || module.semi.is_some()
            || module.attrs.len() != 1
            || !module.attrs[0].path().is_ident("cfg")
        {
            continue;
        }
        let Ok(list) = module.attrs[0].meta.require_list() else {
            continue;
        };
        let cfg = compact_whitespace(&list.tokens.to_string());
        for (index, (_, expected_cfg)) in TEST_GUARDS.iter().enumerate() {
            if cfg == *expected_cfg {
                parsed[index] = parsed[index].saturating_add(1);
            }
        }
    }
    if removed != parsed {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "raw OAST test cfg guard removals must match exact parsed top-level guarded modules",
        ));
    }
    Ok(output)
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
    match toml::from_str::<toml::Value>(cli_manifest) {
        Ok(manifest) => {
            let has_runtime_dependency = manifest
                .get("dependencies")
                .and_then(toml::Value::as_table)
                .is_some_and(|dependencies| dependencies.contains_key(PACKAGE));
            let release_members = manifest
                .get("features")
                .and_then(|features| features.get("release-bundle"))
                .and_then(toml::Value::as_array);
            let release_exposes_profile = release_members.is_some_and(|members| {
                members
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .any(|member| {
                        matches!(
                            member,
                            "xml-external-entity-owned-https-test-profile" | "termivar-oast"
                        )
                    })
            });
            if has_runtime_dependency
                || release_exposes_profile
                || cli_manifest.contains("termivar-oast-provider")
            {
                violations.push(format!(
                    "termivar-cli production dependencies and release-bundle must not depend on or expose {PACKAGE} or its owned HTTPS test profile"
                ));
            }
        },
        Err(_) => violations.push(
            "termivar-cli manifest must remain valid TOML for release-isolation inspection"
                .to_owned(),
        ),
    }
    if release_workflow.contains(PACKAGE)
        || release_workflow.contains("termivar-oast-provider")
        || release_workflow.contains("xml-external-entity-owned-https-test-profile")
    {
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
    fn scanner_provider_consumers_are_exact_and_test_only_use_is_not_production() {
        let valid = vec![
            (
                SCANNER_ADAPTER.to_owned(),
                "use termivar_oast::NativeOastProviderClient;".to_owned(),
            ),
            (
                SSRF_OAST_REVIEW_CONTRACT.to_owned(),
                "use termivar_oast::CallbackTarget;".to_owned(),
            ),
            (
                SSRF_OAST_REVIEW_RUNTIME.to_owned(),
                "use termivar_oast::CallbackId;".to_owned(),
            ),
            (
                XML_EXTERNAL_ENTITY_REVIEW_RUNTIME.to_owned(),
                "use termivar_oast::PublicOrigin;".to_owned(),
            ),
            (
                XML_EXTERNAL_ENTITY_REVIEW_CONTRACT.to_owned(),
                "use termivar_oast::CallbackTarget;".to_owned(),
            ),
            (
                SSRF_OAST_REVIEW_TESTS.to_owned(),
                "use termivar_oast::{CallbackId, EventId};".to_owned(),
            ),
            (
                WEB_RUNTIME_TESTS.to_owned(),
                "use termivar_oast::{CallbackId, EventId};".to_owned(),
            ),
        ];
        assert!(scanner_provider_consumer_violations(&valid).is_empty());

        for missing in EXACT_SCANNER_PROVIDER_CONSUMERS {
            let mutation = valid
                .iter()
                .filter(|(path, _)| path != missing)
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                !scanner_provider_consumer_violations(&mutation).is_empty(),
                "missing exact consumer `{missing}` unexpectedly passed"
            );
        }

        let mut widened = valid;
        widened.push((
            "web_runtime.rs".to_owned(),
            "use termivar_oast::CallbackId;".to_owned(),
        ));
        assert!(!scanner_provider_consumer_violations(&widened).is_empty());

        let exact_test_module =
            "#[cfg(test)]\n#[path = \"assessment_review_tests.rs\"]\nmod tests;";
        assert!(assessment_review_test_module_violations(exact_test_module).is_empty());
        assert!(!assessment_review_test_module_violations(
            "#[path = \"assessment_review_tests.rs\"]\nmod tests;"
        )
        .is_empty());

        let exact_runtime_test_module =
            "#[cfg(test)]\n#[path = \"web_runtime_tests.rs\"]\nmod tests;";
        assert!(web_runtime_test_module_violations(exact_runtime_test_module).is_empty());
        assert!(!web_runtime_test_module_violations(
            "#[path = \"web_runtime_tests.rs\"]\nmod tests;"
        )
        .is_empty());
    }

    #[test]
    fn owned_xml_profile_reference_inventory_rejects_sibling_aliases() {
        let marker = "OwnedXmlHttpsTestTransportProfile";
        let occurrences = |count| {
            (0..count)
                .map(|index| format!("fn use_profile_{index}(_: {marker}) {{}}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let mut valid = vec![
            (SCANNER_HTTP_EVIDENCE.to_owned(), occurrences(1)),
            (SCANNER_REQUEST_BROKER.to_owned(), occurrences(6)),
            ("web_runtime/authority.rs".to_owned(), occurrences(4)),
            (
                "web_runtime/xml_external_entity_runtime.rs".to_owned(),
                occurrences(3),
            ),
            ("web_runtime/web_assessment.rs".to_owned(), occurrences(2)),
        ];
        assert!(owned_xml_profile_global_reference_violations(&valid).is_empty());

        valid.push((
            "http_evidence/passive_review.rs".to_owned(),
            "pub(crate) type AlternateOwnedProfile = super::OwnedXmlHttpsTestTransportProfile;"
                .to_owned(),
        ));
        assert!(!owned_xml_profile_global_reference_violations(&valid).is_empty());
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
                "owned-https-test-profile".to_owned(),
                vec!["client".to_owned()],
            ),
            (
                "server".to_owned(),
                vec![
                    "dep:axum".to_owned(),
                    "dep:clap".to_owned(),
                    "dep:futures".to_owned(),
                    "dep:hyper".to_owned(),
                    "dep:hyper-util".to_owned(),
                    "dep:libc".to_owned(),
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

        let mut widened = BTreeMap::from([
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
                "owned-https-test-profile".to_owned(),
                vec!["client".to_owned(), "server".to_owned()],
            ),
            (
                "server".to_owned(),
                vec![
                    "dep:axum".to_owned(),
                    "dep:clap".to_owned(),
                    "dep:futures".to_owned(),
                    "dep:hyper".to_owned(),
                    "dep:hyper-util".to_owned(),
                    "dep:libc".to_owned(),
                    "dep:serde_json".to_owned(),
                    "dep:tokio".to_owned(),
                    "dep:tower".to_owned(),
                ],
            ),
            ("test-support".to_owned(), vec!["server".to_owned()]),
        ]);
        assert!(!feature_contract_violations(&widened).is_empty());
        widened
            .get_mut("owned-https-test-profile")
            .unwrap()
            .retain(|member| member != "server");
        assert!(feature_contract_violations(&widened).is_empty());
    }

    #[test]
    fn file_open_dependency_is_exactly_unix_and_server_only() {
        assert!(dependency_platform_is_allowed(
            "libc",
            Some("cfg(unix)"),
            true
        ));
        for (name, target, optional) in [
            ("libc", None, true),
            ("libc", Some("cfg(windows)"), true),
            ("libc", Some("cfg(unix)"), false),
            ("libc", Some("cfg(any(unix, windows))"), true),
            ("reqwest", Some("cfg(unix)"), true),
        ] {
            assert!(!dependency_platform_is_allowed(name, target, optional));
        }
        assert!(dependency_platform_is_allowed("reqwest", None, true));
        assert!(dependency_platform_is_allowed("zeroize", None, false));
    }

    fn valid_cli_owned_https_tls_dependency() -> cargo_metadata::Dependency {
        let mut dependency: cargo_metadata::Dependency = toml::from_str(
            r#"
                name = "tokio-rustls"
                req = "^0.26.4"
                kind = "normal"
                optional = false
                uses_default_features = false
                features = ["ring", "tls12"]
            "#,
        )
        .unwrap();
        dependency.kind = DependencyKind::Development;
        dependency
    }

    #[test]
    fn cli_owned_https_tls_development_edge_is_exact() {
        let exact = valid_cli_owned_https_tls_dependency();
        assert!(cli_owned_https_tls_dependency_violations(&[exact.clone()]).is_empty());

        for mutation in [
            "kind",
            "optional",
            "defaults",
            "feature-added",
            "feature-removed",
            "rename",
            "target",
            "duplicate",
            "missing",
        ] {
            let mut dependencies = vec![exact.clone()];
            match mutation {
                "kind" => dependencies[0].kind = DependencyKind::Normal,
                "optional" => dependencies[0].optional = true,
                "defaults" => dependencies[0].uses_default_features = true,
                "feature-added" => dependencies[0].features.push("logging".to_owned()),
                "feature-removed" => dependencies[0]
                    .features
                    .retain(|feature| feature != "tls12"),
                "rename" => dependencies[0].rename = Some("fixture_tls".to_owned()),
                "target" => dependencies[0].target = Some("cfg(unix)".parse().unwrap()),
                "duplicate" => dependencies.push(exact.clone()),
                "missing" => dependencies.clear(),
                _ => unreachable!(),
            }
            assert!(
                !cli_owned_https_tls_dependency_violations(&dependencies).is_empty(),
                "tokio-rustls `{mutation}` mutation unexpectedly passed"
            );
        }
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
            use axum::{body::Body, extract::State, middleware::Next, response::Response};
            use hyper::Request;
            const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
            const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
            const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
            const CONNECTION_LIFETIME: Duration = Duration::from_secs(120);
            fn provider_router(provider: ProviderState) -> Router {
                let state = AppState::new(provider);
                Router::new()
                    .layer(DefaultBodyLimit::max(MAX_MANAGEMENT_BODY_BYTES))
                    .layer(from_fn_with_state(state.clone(), bound_request))
                    .with_state(state)
            }
            async fn bound_request(
                State(state): State<AppState>,
                request: Request<Body>,
                next: Next,
            ) -> Response {
                #[cfg(feature = "test-support")]
                if let Some(ledger) = &state.test_request_ledger {
                    ledger.record(&request);
                }
                let operation = async {
                    let Ok(_permit) = state.admit() else {
                        return closing_error(StatusCode::SERVICE_UNAVAILABLE);
                    };
                    next.run(request).await
                };
                timeout(REQUEST_TIMEOUT, operation)
                    .await
                    .unwrap_or_else(|_| closing_error(StatusCode::REQUEST_TIMEOUT))
            }
            fn closing_error(status: StatusCode) -> Response {
                let mut response = generic_error(status);
                response.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
                response
            }
            pub async fn serve_provider(provider: ProviderState) -> Result<(), Error> { todo!() }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub async fn serve_provider_on_listener(listener: TcpListener, provider: ProviderState) -> Result<(), Error> {
                serve_listener(listener, provider).await
            }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub struct ProviderTestPollBarrier;
            #[cfg(feature = "test-support")]
            impl ProviderTestPollBarrier {
                pub fn new() -> Self { Self }
                pub fn arm(&self) {}
                pub async fn wait_for_poll_snapshot(&self) -> bool { true }
                fn record_callback(&self) {}
            }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub async fn serve_provider_on_listener_with_poll_barrier(
                listener: TcpListener,
                provider: ProviderState,
                barrier: ProviderTestPollBarrier,
            ) -> Result<(), Error> {
                let _ = barrier;
                serve_listener(listener, provider).await
            }
            #[cfg(feature = "test-support")]
            struct ProviderTestRequestLedgerState {
                register: AtomicUsize,
                allocate: AtomicUsize,
                poll: AtomicUsize,
                cleanup: AtomicUsize,
                callback: AtomicUsize,
                other: AtomicUsize,
                private_identity_sentinels: StdMutex<Vec<Vec<u8>>>,
            }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub struct ProviderTestRequestLedger {
                state: Arc<ProviderTestRequestLedgerState>,
            }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub struct ProviderTestRequestSnapshot {
                pub register: usize,
                pub allocate: usize,
                pub poll: usize,
                pub cleanup: usize,
                pub callback: usize,
                pub other: usize,
            }
            #[cfg(feature = "test-support")]
            impl ProviderTestRequestLedger {
                pub fn new() -> Self { todo!() }
                pub fn snapshot(&self) -> ProviderTestRequestSnapshot { todo!() }
                pub fn private_identity_sentinels(&self) -> Vec<Vec<u8>> { todo!() }
                fn record_private_identity(&self, value: &str) {
                    let mut identities = self.state.private_identity_sentinels.lock().unwrap();
                    if identities.len() < 4 && value.len() <= 64 {
                        identities.push(value.as_bytes().to_vec());
                    }
                }
                fn record(&self, request: &Request<Body>) {
                    let _ = request;
                }
            }
            #[cfg(feature = "test-support")]
            #[doc(hidden)]
            pub async fn serve_provider_on_listener_with_request_ledger(
                listener: TcpListener,
                provider: ProviderState,
                ledger: ProviderTestRequestLedger,
            ) -> Result<(), ProviderServerError> {
                let _ = ledger;
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
                let mut builder = http1::Builder::new();
                builder.timer(TokioTimer::new())
                    .header_read_timeout(HEADER_READ_TIMEOUT)
                    .keep_alive(true);
                timeout(
                    CONNECTION_LIFETIME,
                    builder.serve_connection(TokioIo::new(IdleIo::new(stream)), service),
                ).await.map_err(|_| Error)?
            }
            struct AppState { requests: Semaphore }
            impl AppState {
                fn new(provider: ProviderState) -> Self {
                    let permits = usize::from(provider.max_concurrent_requests());
                    Self { requests: Semaphore::new(permits) }
                }
                fn admit(&self) {
                    Arc::clone(&self.requests).try_acquire_owned();
                }
            }
            struct IdleIo<T> { inner: T, deadline: Pin<Box<Sleep>> }
            impl<T> IdleIo<T> {
                fn new(inner: T) -> Self {
                    Self { inner, deadline: Box::pin(sleep(CONNECTION_IDLE_TIMEOUT)) }
                }
                fn check_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
                    if self.deadline.as_mut().poll(cx).is_ready() {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "idle"))
                    } else { Ok(()) }
                }
                fn made_progress(&mut self) {
                    self.deadline.as_mut().reset(Instant::now() + CONNECTION_IDLE_TIMEOUT);
                }
            }
            impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
                fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                    let this = self.get_mut();
                    this.check_deadline(cx)?;
                    let before = buffer.filled().len();
                    let result = Pin::new(&mut this.inner).poll_read(cx, buffer);
                    if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
                        this.made_progress();
                    }
                    result
                }
            }
            impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
                fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
                    let this = self.get_mut();
                    this.check_deadline(cx)?;
                    let result = Pin::new(&mut this.inner).poll_write(cx, buffer);
                    if matches!(result, Poll::Ready(Ok(count)) if count > 0) {
                        this.made_progress();
                    }
                    result
                }
                fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    let this = self.get_mut();
                    this.check_deadline(cx)?;
                    Pin::new(&mut this.inner).poll_flush(cx)
                }
                fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                    let this = self.get_mut();
                    this.check_deadline(cx)?;
                    Pin::new(&mut this.inner).poll_shutdown(cx)
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
            pub use server::{
                serve_provider_on_listener,
                serve_provider_on_listener_with_poll_barrier,
                serve_provider_on_listener_with_request_ledger,
                ProviderTestPollBarrier,
                ProviderTestRequestLedger,
                ProviderTestRequestSnapshot,
            };
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
            (
                valid_server_source().replacen("#[doc(hidden)]", "", 1),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "pub struct ProviderTestPollBarrier;",
                    "pub struct RenamedTestPollBarrier;",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "pub async fn wait_for_poll_snapshot",
                    "pub async fn wait_for_any_poll_snapshot",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().to_owned(),
                valid_library_source().replacen(
                    "serve_provider_on_listener_with_poll_barrier,",
                    "",
                    1,
                ),
            ),
            (
                valid_server_source().replacen(
                    "serve_provider_on_listener_with_request_ledger",
                    "serve_provider_on_listener_with_unbounded_ledger",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "ledger: ProviderTestRequestLedger,",
                    "ledger: String,",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "state: Arc<ProviderTestRequestLedgerState>",
                    "state: Arc<String>",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "other: AtomicUsize,",
                    "other: AtomicUsize, raw_session_id: String,",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "private_identity_sentinels: StdMutex<Vec<Vec<u8>>>,",
                    "private_identity_sentinels: StdMutex<Vec<String>>,",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen("pub callback: usize,", "pub callback: String,", 1),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "pub fn snapshot(&self)",
                    "pub fn expose_raw(&self)",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "pub fn snapshot(&self) -> ProviderTestRequestSnapshot",
                    "pub fn snapshot(&mut self, raw: &str) -> String",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(
                    "pub fn private_identity_sentinels(&self) -> Vec<Vec<u8>>",
                    "pub fn private_identity_sentinels(&self) -> Vec<String>",
                    1,
                ),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen(" && value.len() <= 64", "", 1),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().replacen("identities.len() < 4", "identities.len() < 5", 1),
                valid_library_source().to_owned(),
            ),
            (
                valid_server_source().to_owned(),
                valid_library_source().replacen("ProviderTestRequestSnapshot,", "", 1),
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
            production.replacen(
                ".https_only(origin.scheme() == \"https\")",
                ".https_only(true)",
                1,
            ),
            production.replacen(
                "fn fixed_client_builder(origin: &Url) -> reqwest::ClientBuilder",
                "fn fixed_client_builder(origin: &Url) -> reqwest::ClientBuilder { let _ = origin; reqwest::Client::builder() } fn discarded_fixed_client_builder(origin: &Url) -> reqwest::ClientBuilder",
                1,
            ),
            format!("mod reqwest {{ pub use ::reqwest::*; }}\n{production}"),
            production.replacen("Engine as _", "Engine as DecodeEngine", 1),
            format!("mod base64 {{ pub use ::base64::*; }}\n{production}"),
            production.replacen(
                "#[cfg(feature = \"owned-https-test-profile\")]\nuse base64",
                "#[cfg(any(feature = \"owned-https-test-profile\", test))]\nuse base64",
                1,
            ),
            production.replacen(".tls_built_in_root_certs(false)", "", 1),
            production.replacen(
                "OWNED_HTTPS_TEST_PROVIDER_HOST,\n                profile_port.resolved_address()",
                "other_host, profile_port.resolved_address()",
                1,
            ),
            production.replacen(
                "const OWNED_HTTPS_TEST_PROVIDER_IPV6: Ipv6Addr = Ipv6Addr::LOCALHOST;",
                "const OWNED_HTTPS_TEST_PROVIDER_IPV6: Ipv6Addr = Ipv6Addr::UNSPECIFIED;",
                1,
            ),
            production.replacen("/v1/sessions/{}/events", "/arbitrary/{}/events", 1),
            production.replacen(
                "return Err(client_initialization_error());",
                "#[cfg(any())]\n            return Err(client_initialization_error());",
                1,
            ),
            format!("{production}\npub fn arbitrary(url: Url) {{ let _ = url; }}"),
            format!("{production}\nimpl Drop for NativeOastClient {{ fn drop(&mut self) {{}} }}"),
        ] {
            assert_ne!(mutation, production, "native client mutation must alter source");
            assert!(
                !client_transport_contract_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "native client transport mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn owned_https_profile_types_are_exactly_sealed() {
        let client_source = include_str!("../../../crates/termivar-oast/src/client.rs");
        let client = production_prefix(client_source);
        assert!(
            owned_https_profile_port_surface_violations(client)
                .unwrap()
                .is_empty(),
            "repository owned HTTPS port profile drifted from its sealed surface"
        );
        for mutation in [
            client.replacen(
                "pub struct OwnedHttpsTestProfilePort(NonZeroU16);",
                "pub struct OwnedHttpsTestProfilePort(u16);",
                1,
            ),
            client.replacen(
                "pub struct OwnedHttpsTestProfilePort(NonZeroU16);",
                "pub(crate) struct OwnedHttpsTestProfilePort(NonZeroU16);",
                1,
            ),
            client.replacen(
                "#[cfg(feature = \"owned-https-test-profile\")]\n#[doc(hidden)]\n#[derive(Clone, Copy, PartialEq, Eq)]\npub struct OwnedHttpsTestProfilePort",
                "#[cfg(feature = \"client\")]\n#[doc(hidden)]\n#[derive(Clone, Copy, PartialEq, Eq)]\npub struct OwnedHttpsTestProfilePort",
                1,
            ),
            client.replacen(
                "pub const fn new(port: NonZeroU16) -> Self",
                "pub fn new(port: u16) -> Self",
                1,
            ),
            client.replacen(
                "fn resolved_address(self) -> SocketAddr",
                "pub fn resolved_address(&self) -> SocketAddr",
                1,
            ),
            client.replacen(
                "#[derive(Clone, Copy, PartialEq, Eq)]\npub struct OwnedHttpsTestProfilePort",
                "#[derive(Clone, Copy, PartialEq, Eq, serde::Deserialize)]\npub struct OwnedHttpsTestProfilePort",
                1,
            ),
            client.replacen("Self(port)", "Self(NonZeroU16::MIN)", 1),
            client.replacen(
                "SocketAddr::from((OWNED_HTTPS_TEST_PROVIDER_IPV6, self.0.get()))",
                "SocketAddr::from(([8, 8, 8, 8], self.0.get()))",
                1,
            ),
        ] {
            assert_ne!(mutation, client, "client profile mutation must alter source");
            assert!(
                !owned_https_profile_port_surface_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "owned HTTPS port profile mutation unexpectedly passed"
            );
        }

        let broker_source =
            include_str!("../../../crates/termivar-scanner/src/http_evidence/request_broker.rs");
        let broker = production_prefix(broker_source);
        assert!(
            owned_xml_https_profile_surface_violations(broker)
                .unwrap()
                .is_empty(),
            "repository owned XML HTTPS transport profile drifted from its sealed surface"
        );
        for mutation in [
            broker.replacen(
                "pub(crate) struct OwnedXmlHttpsTestTransportProfile",
                "pub struct OwnedXmlHttpsTestTransportProfile",
                1,
            ),
            broker.replacen(
                "    port: NonZeroU16,\n}",
                "    port: NonZeroU16,\n    resolver: SocketAddr,\n}",
                1,
            ),
            broker.replacen(
                "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(crate) struct OwnedXmlHttpsTestTransportProfile",
                "#[cfg(feature = \"xml-external-entity-review\")]\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(crate) struct OwnedXmlHttpsTestTransportProfile",
                1,
            ),
            broker.replacen(
                "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(crate) struct OwnedXmlHttpsTestTransportProfile",
                "#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]\npub(crate) struct OwnedXmlHttpsTestTransportProfile",
                1,
            ),
            broker.replacen(
                "application: &url::Url,",
                "application: &SocketAddr,",
                1,
            ),
            broker.replacen(
                "pub(crate) const fn port(self) -> NonZeroU16",
                "pub(crate) fn port(&self) -> NonZeroU16",
                1,
            ),
            broker.replacen(
                "fn target_address(self) -> SocketAddr",
                "fn target_address(self, address: SocketAddr) -> SocketAddr",
                1,
            ),
            broker.replacen(
                "application.scheme() == \"https\"",
                "application.scheme() == \"http\"",
                1,
            ),
            broker.replacen(
                "const OWNED_XML_HTTPS_TARGET_HOST: &str = \"xml-target.termivar.test\";",
                "const OWNED_XML_HTTPS_TARGET_HOST: &str = \"other.termivar.test\";",
                1,
            ),
            broker.replacen(
                "const OWNED_XML_HTTPS_PROVIDER_ORIGIN: &str = \"https://oast-provider.termivar.test/\";",
                "const OWNED_XML_HTTPS_PROVIDER_ORIGIN: &str = \"https://other.termivar.test/\";",
                1,
            ),
            broker.replacen("MIIBjTCCATOg", "NIIBjTCCATOg", 1),
            broker.replacen(
                "SocketAddr::from(([127, 0, 0, 1], self.port.get()))",
                "SocketAddr::from(([8, 8, 8, 8], self.port.get()))",
                1,
            ),
            broker.replacen(
                "profile: OwnedXmlHttpsTestTransportProfile,\n    ) -> Result<(), HttpEvidenceError> {",
                "mut profile: OwnedXmlHttpsTestTransportProfile,\n    ) -> Result<(), HttpEvidenceError> {\n        profile.port = NonZeroU16::new(1).unwrap();",
                1,
            ),
            broker.replacen(
                "self.owned_xml_https_test_profile = Some(profile);",
                "#[cfg(any())]\n        self.owned_xml_https_test_profile = Some(profile);",
                1,
            ),
            broker.replacen(
                "if let Some(profile) = self.owned_xml_https_test_profile {\n                broker.configure_owned_xml_https_test_profile(profile)?;",
                "if let Some(mut profile) = self.owned_xml_https_test_profile {\n                profile.port = NonZeroU16::new(1).expect(\"fixed nonzero port\");\n                broker.configure_owned_xml_https_test_profile(profile)?;",
                1,
            ),
            broker.replacen(
                "let root_der = STANDARD",
                "let HttpRequestBroker { owned_xml_https_test_profile: slot, .. } = self;\n        *slot = None;\n        let root_der = STANDARD",
                1,
            ),
            broker.replacen(
                "let root_der = STANDARD",
                "passthrough!(profile.port = NonZeroU16::new(1).unwrap());\n        let root_der = STANDARD",
                1,
            ),
            format!(
                "{broker}\n#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\nfn extra_profile(port: NonZeroU16) -> OwnedXmlHttpsTestTransportProfile {{ OwnedXmlHttpsTestTransportProfile {{ port }} }}"
            ),
            format!(
                "{broker}\n#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\npub(crate) use self::OwnedXmlHttpsTestTransportProfile as IndirectOwnedProfile;"
            ),
            format!(
                "{broker}\n#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\npub(crate) type IndirectOwnedProfile = OwnedXmlHttpsTestTransportProfile;"
            ),
            format!(
                "{broker}\ntype Identity<T> = T;\n#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\npub(crate) type IndirectOwnedProfile = Identity<OwnedXmlHttpsTestTransportProfile>;"
            ),
            format!(
                "{broker}\ntrait ProfileCarrier {{ type Profile; }}\nstruct ProfileMarker;\n#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\nimpl ProfileCarrier for ProfileMarker {{ type Profile = OwnedXmlHttpsTestTransportProfile; }}"
            ),
            format!(
                "{broker}\n#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\npub(crate) fn forge_profile(port: NonZeroU16) -> OwnedXmlHttpsTestTransportProfile {{ unsafe {{ std::mem::transmute(port) }} }}"
            ),
        ] {
            assert_ne!(mutation, broker, "scanner profile mutation must alter source");
            assert!(
                !owned_xml_https_profile_surface_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "owned XML HTTPS transport profile mutation unexpectedly passed"
            );
        }

        let http_evidence = include_str!("../../../crates/termivar-scanner/src/http_evidence.rs");
        assert!(
            owned_xml_https_profile_reexport_violations(http_evidence)
                .unwrap()
                .is_empty(),
            "repository owned XML HTTPS profile re-export drifted from its sealed surface"
        );
        for mutation in [
            http_evidence.replacen(
                "pub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                "pub use request_broker::OwnedXmlHttpsTestTransportProfile;",
                1,
            ),
            http_evidence.replacen(
                "mod request_broker;",
                "pub(crate) mod request_broker;",
                1,
            ),
            http_evidence.replacen(
                "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\npub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                "#[cfg(feature = \"xml-external-entity-review\")]\npub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                1,
            ),
            http_evidence.replacen(
                "OwnedXmlHttpsTestTransportProfile;",
                "RenamedOwnedXmlHttpsTestTransportProfile;",
                1,
            ),
            format!("{http_evidence}\npub(crate) use request_broker::*;"),
            format!("{http_evidence}\npub(crate) use self::request_broker::*;"),
            format!("{http_evidence}\npub(crate) use self::r#request_broker::*;"),
            format!(
                "{http_evidence}\npub(crate) use crate::http_evidence::request_broker::*;"
            ),
            format!(
                "{http_evidence}\nuse request_broker as broker;\npub(crate) use broker::*;"
            ),
            format!(
                "{http_evidence}\nuse self::request_broker as r#broker;\npub(crate) use r#broker::OwnedXmlHttpsTestTransportProfile;"
            ),
            format!(
                "{http_evidence}\nmod aliases {{ pub(crate) use super::request_broker::*; }}\npub(crate) use aliases::*;"
            ),
            format!(
                "{http_evidence}\npub(crate) mod aliases {{ pub(crate) use super::OwnedXmlHttpsTestTransportProfile as ExtraOwnedProfile; }}"
            ),
            format!(
                "{http_evidence}\npub(crate) mod aliases {{ pub(crate) use super::*; }}"
            ),
            format!(
                "{http_evidence}\npub(crate) use self::request_broker::OwnedXmlHttpsTestTransportProfile as OwnedProfile;"
            ),
            format!(
                "{http_evidence}\nmacro_rules! export_owned_profile {{ () => {{ pub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile as ExtraOwnedProfile; }}; }}\nexport_owned_profile!();"
            ),
            format!(
                "{http_evidence}\npub(crate) type ExtraOwnedProfile = request_broker::OwnedXmlHttpsTestTransportProfile;"
            ),
            format!(
                "{http_evidence}\npub(crate) use self::request_broker::r#OwnedXmlHttpsTestTransportProfile as OwnedProfile;"
            ),
            http_evidence.replacen(
                "pub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                "pub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile as OwnedProfile;",
                1,
            ),
            http_evidence.replacen(
                "pub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                "pub(crate) use request_broker::{OwnedXmlHttpsTestTransportProfile, *};",
                1,
            ),
        ] {
            assert_ne!(
                mutation, http_evidence,
                "scanner profile re-export mutation must alter source"
            );
            assert!(
                !owned_xml_https_profile_reexport_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "owned XML HTTPS profile re-export mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn native_adapter_authority_shape_mutations_fail_closed() {
        let source = include_str!("../../../crates/termivar-scanner/src/native_oast_provider.rs");
        let production = source_without_exact_oast_test_modules(source).unwrap();
        assert!(adapter_forbidden_authority_violations(&production).is_empty());
        assert!(adapter_private_authority_shape_violations(&production)
            .unwrap()
            .is_empty());

        for (mutation, expected) in [
            (
                format!("{production}\nfn escape() {{ let _: reqwest::Client; }}"),
                "forbidden authority surface `reqwest::`",
            ),
            (
                format!("{production}\nfn escape() {{ tokio::spawn(async {{}}); }}"),
                "must not start background work through `tokio::spawn`",
            ),
        ] {
            let violations = adapter_forbidden_authority_violations(&mutation);
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "adapter authority mutation `{expected}` was not rejected: {violations:?}"
            );
        }

        for (mutation, expected) in [
            (
                format!(
                    "{}\ntype NativeOastClient = RealNativeOastClient;",
                    production.replacen(
                        "NativeOastClient, NativeOastClientBoundary",
                        "NativeOastClient as RealNativeOastClient, NativeOastClientBoundary",
                        1,
                    )
                ),
                "import NativeOastClient exactly and unaliased",
            ),
            (
                format!("#![allow(dead_code)]\n{production}"),
                "must not suppress dead-code policy",
            ),
            (
                production.replacen("NativeOastClient::new(", "NativeOastClient::build(", 1),
                "NativeOastClient::new(",
            ),
            (
                production.replacen(
                    "#[cfg(not(feature = \"xml-external-entity-owned-https-test-profile\"))]\n        let client = NativeOastClient::new(origin.clone());",
                    "#[cfg(not(feature = \"xml-external-entity-owned-https-test-profile\"))]\n        let client = NativeOastClient::build(origin.clone());",
                    1,
                ),
                "NativeOastClient::new(",
            ),
            (
                production.replacen(
                    "NativeOastClient::new_owned_https_test_profile(origin.clone(), profile_port)",
                    "NativeOastClient::new(origin.clone())",
                    1,
                ),
                "NativeOastClient::new_owned_https_test_profile(",
            ),
            (
                production.replacen(
                    "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    "#[cfg(any(feature = \"xml-external-entity-owned-https-test-profile\", feature = \"ssrf-oast-review\"))]\n        let client = match transport {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    "macro_rules! disable_owned_transport { () => { let transport = { let _ = transport; NativeOastProviderTransport::Production }; }; }\n        disable_owned_transport!();\n        #[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "#[cfg(not(feature = \"xml-external-entity-owned-https-test-profile\"))]\n        let client = NativeOastClient::new(origin.clone());",
                    "#[cfg(all(not(feature = \"xml-external-entity-owned-https-test-profile\"), not(feature = \"websocket-review\")))]\n        let client = NativeOastClient::new(origin.clone());",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen("let client = match transport {", "let client = match other {", 1),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "NativeOastProviderTransport::Production => NativeOastClient::new(origin.clone()),",
                    "NativeOastProviderTransport::Production if enabled() => NativeOastClient::new(origin.clone()),",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "NativeOastProviderTransport::Production => NativeOastClient::new(origin.clone()),",
                    "NativeOastProviderTransport::Production => NativeOastClient::new(other.clone()),",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "NativeOastClient::new_owned_https_test_profile(origin.clone(), profile_port)",
                    "NativeOastClient::new_owned_https_test_profile(origin.clone(), other_port)",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "let client = client.map_err(|error| {",
                    "let client = helper();\n        let client = client.map_err(|error| {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "let client = client.map_err(|error| {",
                    "let (client,) = (helper(),);\n        let client = client.map_err(|error| {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "let client = client.map_err(|error| {",
                    "let (r#client,) = (helper(),);\n        let client = client.map_err(|error| {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "let client = client.map_err(|error| {",
                    "let mut client = client.map_err(|error| {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let transport = { let _ = transport; NativeOastProviderTransport::Production };\n        #[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    "let origin = origin.clone();\n        #[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\n        let client = match transport {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "        let NativeOastProviderConfiguration {",
                    "        let configuration = rewrite(configuration);\n        let NativeOastProviderConfiguration {",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "        } = configuration;",
                    "        } = other_configuration;",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "        Ok(Self {\n            client,",
                    "        let permit = permit;\n        Ok(Self {\n            client,",
                    1,
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                format!(
                    "{}\nfn preserve_permit<T>(value: T) -> T {{ value }}",
                    production.replacen(
                        "        Ok(Self {\n            client,\n            permit,",
                        "        Ok(Self {\n            client,\n            permit: preserve_permit(permit),",
                        1,
                    )
                ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production
                    .replacen(
                        "let client = client.map_err(|error| {",
                        "let constructor = NativeOastClient::new;\n        let selected_client = constructor(origin.clone()).map_err(|error| {\n            NativeOastProviderError::new(provider_client_failure_kind(\n                error.kind(),\n                error.http_failure(),\n            ))\n        })?;\n        let client = client.map_err(|error| {",
                        1,
                    )
                    .replacen(
                        "Ok(Self {\n            client,",
                        "Ok(Self {\n            client: selected_client,",
                        1,
                    ),
                "exact mutually exclusive production and owned-HTTPS client constructor partition",
            ),
            (
                production.replacen(
                    "pub(crate) struct NativeOastProviderConfiguration",
                    "pub(crate) struct MissingNativeOastProviderConfiguration",
                    1,
                ),
                "declare exactly one `NativeOastProviderConfiguration`",
            ),
            (
                production.replacen(
                    "pub(crate) struct NativeOastProviderPermit",
                    "pub struct NativeOastProviderPermit",
                    1,
                ),
                "and all of its fields must remain crate-private",
            ),
            (
                production.replacen(
                    "pub(crate) struct NativeOastProviderConfiguration",
                    "#[derive(Clone)] pub(crate) struct NativeOastProviderConfiguration",
                    1,
                ),
                "must remain move-only and non-serializable",
            ),
            (
                format!(
                    "{production}\nimpl Drop for NativeOastProviderAdapter {{ fn drop(&mut self) {{}} }}"
                ),
                "must not implement `Drop`",
            ),
            (
                production.replacen("    fn mint(", "    pub(crate) fn mint(", 1),
                "NativeOastProviderPermit::mint must remain exactly one private constructor",
            ),
            (
                production.replacen(
                    "_authority: NativeOastProviderMintToken",
                    "_authority: &NativeOastProviderMintToken",
                    1,
                ),
                "consuming the move-only authority token by value",
            ),
        ] {
            assert_ne!(
                mutation, production,
                "adapter shape mutation `{expected}` must alter source"
            );
            let violations = adapter_private_authority_shape_violations(&mutation).unwrap();
            assert!(
                violations.iter().any(|violation| violation.contains(expected)),
                "adapter shape mutation `{expected}` was not rejected: {violations:?}"
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
                "builder.serve_connection(TokioIo::new(IdleIo::new(stream)), service)",
                "axum::serve(listener, router).await",
            ),
            format!(
                "{}\nasync fn escape() {{ connections.push(serve_connection(router.clone(), stream)); }}",
                valid_server_source()
            ),
        ] {
            assert!(!server_transport_contract_violations(&mutation).is_empty());
        }
    }

    #[test]
    fn connection_deadline_and_timer_mutations_fail_closed() {
        let source = valid_server_source();
        for (before, after) in [
            ("Duration::from_secs(10)", "Duration::ZERO"),
            ("Duration::from_secs(15)", "Duration::from_secs(16)"),
            ("Duration::from_secs(30)", "Duration::from_secs(300)"),
            ("Duration::from_secs(120)", "Duration::from_secs(1200)"),
            (".timer(TokioTimer::new())", ""),
            (".header_read_timeout(HEADER_READ_TIMEOUT)", ""),
            (
                ".header_read_timeout(HEADER_READ_TIMEOUT)",
                ".header_read_timeout(None)",
            ),
            (
                ".header_read_timeout(HEADER_READ_TIMEOUT)",
                ".header_read_timeout(HEADER_READ_TIMEOUT).header_read_timeout(None)",
            ),
            (".keep_alive(true)", ".keep_alive(false)"),
            ("CONNECTION_LIFETIME,", "REQUEST_TIMEOUT,"),
            ("IdleIo::new(stream)", "stream"),
            ("sleep(CONNECTION_IDLE_TIMEOUT)", "sleep(Duration::MAX)"),
            ("this.check_deadline(cx)?;", ""),
            (
                "buffer.filled().len() > before",
                "buffer.filled().len() >= before",
            ),
            ("if count > 0", "if count >= 0"),
            (
                "reset(Instant::now() + CONNECTION_IDLE_TIMEOUT)",
                "reset(Instant::now() + CONNECTION_LIFETIME)",
            ),
        ] {
            assert!(
                source.contains(before),
                "missing fixture mutation site: {before}"
            );
            let mutation = source.replace(before, after);
            assert!(
                !server_transport_contract_violations(&mutation).is_empty(),
                "deadline mutation unexpectedly passed: {before} -> {after}"
            );
        }
    }

    #[test]
    fn request_admission_and_body_limit_mutations_fail_closed() {
        let source = valid_server_source();
        for (before, after) in [
            (".try_acquire_owned()", ".acquire_owned().await"),
            (".try_acquire_owned()", ".try_acquire()"),
            (
                ".layer(from_fn_with_state(state.clone(), bound_request))",
                "",
            ),
            (
                ".layer(DefaultBodyLimit::max(MAX_MANAGEMENT_BODY_BYTES))",
                ".layer(DefaultBodyLimit::disable())",
            ),
            (
                "DefaultBodyLimit::max(MAX_MANAGEMENT_BODY_BYTES)",
                "DefaultBodyLimit::max(usize::MAX)",
            ),
            ("request: Request<Body>", "request: Bytes"),
            (
                "timeout(REQUEST_TIMEOUT, operation)",
                "timeout(CONNECTION_LIFETIME, operation)",
            ),
            (
                "let operation = async {",
                "let body = read_body(request).await; let operation = async {",
            ),
            (
                "let Ok(_permit) = state.admit() else {",
                "let body = read_body(request).await; let Ok(_permit) = state.admit() else {",
            ),
            (
                "next.run(request).await",
                "drop(_permit); next.run(request).await",
            ),
            (
                "next.run(request).await",
                "let _extra = state.admit(); next.run(request).await",
            ),
            (
                "HeaderValue::from_static(\"close\")",
                "HeaderValue::from_static(\"keep-alive\")",
            ),
            (
                "async fn bound_request(",
                "#[cfg(any())]\nasync fn bound_request(",
            ),
        ] {
            assert!(
                source.contains(before),
                "missing fixture mutation site: {before}"
            );
            let mutation = source.replace(before, after);
            assert!(
                !server_transport_contract_violations(&mutation).is_empty(),
                "admission mutation unexpectedly passed: {before} -> {after}"
            );
        }

        for mutation in [
            format!("{source}\n#[cfg(any())]\nuse alternate::bound_request;"),
            format!("{source}\n#[cfg(any())]\nalternate_bound_request!();"),
            format!("mod axum {{ pub use ::axum::*; }}\n{source}"),
        ] {
            assert!(
                !server_transport_contract_violations(&mutation).is_empty(),
                "alternate bound_request binding unexpectedly passed"
            );
        }
    }

    #[test]
    fn admission_ast_guard_rejects_malformed_outer_operation_shapes() {
        let ledger = "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { ledger.record(&request); }";
        for source in [
            "fn bound_request(".to_owned(),
            "fn unrelated() {}".to_owned(),
            "fn bound_request() {}".to_owned(),
            format!("fn bound_request() {{ {ledger} consume_body(); let operation = async {{}}; finish(operation) }}"),
            format!("fn bound_request() {{ {ledger} let operation = async {{}}; finish(operation); }}"),
            format!("fn bound_request() {{ {ledger} let (operation,) = async {{}}; finish(operation) }}"),
            format!("fn bound_request() {{ {ledger} let other = async {{}}; finish(other) }}"),
            format!("fn bound_request() {{ {ledger} let operation; finish(operation) }}"),
            format!("fn bound_request() {{ {ledger} let operation = run(); finish(operation) }}"),
            format!("fn bound_request() {{ {ledger} let operation = async {{}}; finish(operation) }}"),
        ] {
            assert!(
                !admission_precedes_body_dispatch(&source),
                "malformed outer admission shape unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn admission_ast_guard_requires_the_owned_permit_and_awaited_body_dispatch() {
        // These standalone parser fixtures deliberately do not reproduce the
        // production module. Each varies one semantic boundary of the guard.
        let ledger = "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { ledger.record(&request); }";
        let admission = "let Ok(_permit) = state.admit() else { return rejected(); };";
        let dispatch = "next.run(request).await";
        let source = |ledger: &str, admission: &str, dispatch: &str| {
            format!(
                "use axum::{{body::Body, extract::State, middleware::Next, response::Response}}; use hyper::Request; async fn bound_request(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {{ {ledger} let operation = async {{ {admission} {dispatch} }}; finish(operation) }}"
            )
        };
        assert!(admission_precedes_body_dispatch(&source(
            ledger, admission, dispatch
        )));
        for malformed in [
            "",
            "#[cfg(test)] if let Some(ledger) = &state.test_request_ledger { ledger.record(&request); }",
            "#[cfg(any(test, feature = \"test-support\"))] if let Some(ledger) = &state.test_request_ledger { ledger.record(&request); }",
            "#[cfg(feature = \"test-support\")] if let Some(other) = &state.test_request_ledger { other.record(&request); }",
            "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.other { ledger.record(&request); }",
            "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { other.record(&request); }",
            "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { ledger.record(request); }",
            "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { ledger.record(&other); }",
            "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { ledger.record(&request); } else { consume_body(); }",
            "#[cfg(feature = \"test-support\")] if let Some(ledger) = &state.test_request_ledger { consume_body(); ledger.record(&request); }",
        ] {
            assert!(
                !admission_precedes_body_dispatch(&source(malformed, admission, dispatch)),
                "malformed test request ledger prelude unexpectedly passed: {malformed}"
            );
        }
        for malformed in [
            "let _permit = state.admit();",
            "let Some(_permit) = state.admit() else { return rejected(); };",
            "let Ok(other) = state.admit() else { return rejected(); };",
            "let Ok(_permit, extra) = state.admit() else { return rejected(); };",
            "let Ok((_permit,)) = state.admit() else { return rejected(); };",
            "let Ok(_permit);",
            "let Ok(_permit) = acquire() else { return rejected(); };",
            "let Ok(_permit) = state.admit();",
            "let Ok(_permit) = state.wait() else { return rejected(); };",
            "let Ok(_permit) = other.admit() else { return rejected(); };",
            "let Ok(_permit) = state.admit(request) else { return rejected(); };",
        ] {
            assert!(
                !admission_precedes_body_dispatch(&source(ledger, malformed, dispatch)),
                "malformed permit admission unexpectedly passed: {malformed}"
            );
        }
        for malformed in [
            "next.run(request)",
            "run(request).await",
            "next.skip(request).await",
            "other.run(request).await",
            "next.run().await",
            "next.run(request, other).await",
            "next.run(other).await",
            "next.run(build_request()).await",
            "drop(_permit); next.run(request).await",
        ] {
            assert!(
                !admission_precedes_body_dispatch(&source(ledger, admission, malformed)),
                "malformed body dispatch unexpectedly passed: {malformed}"
            );
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

        let missing = valid.replacen("struct AdminToken", "struct MissingAdminToken", 1);
        let violations = secret_surface_violations(&missing, &expected).unwrap();
        assert!(violations
            .iter()
            .any(|violation| violation.contains("declare exactly one `AdminToken`")));

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

        let widened_cli =
            format!("{cli}\n[dependencies]\n{PACKAGE} = {{ path = \"../termivar-oast\" }}");
        assert!(!release_isolation_source_violations(&widened_cli, workflow).is_empty());
        let profile_in_bundle = cli.replace(
            "release-bundle=[\"rest-review\"]",
            "release-bundle=[\"rest-review\",\"xml-external-entity-owned-https-test-profile\"]",
        );
        assert!(!release_isolation_source_violations(&profile_in_bundle, workflow).is_empty());
        let widened_workflow =
            format!("{workflow}\ncargo build -p termivar-oast --bin termivar-oast-provider");
        assert!(!release_isolation_source_violations(cli, &widened_workflow).is_empty());

        let violations = release_isolation_source_violations(cli, "cargo build --workspace");
        assert!(violations
            .iter()
            .any(|violation| violation.contains("exact termivar-cli release-bundle build")));
    }

    #[test]
    fn background_work_is_checked_only_in_production_source() {
        let production = "fn serve() { tokio::spawn(async {}); }";
        assert!(production_prefix(production).contains("tokio::spawn"));

        let test_only =
            "fn serve() {}\n#[cfg(test)]\nmod tests { fn fixture() { tokio::spawn(async {}); } }";
        assert!(!production_prefix(test_only).contains("tokio::spawn"));

        let commented_marker =
            "fn serve() { tokio::spawn(async {}); }\n// #[cfg(test)]\nmod tests {}";
        assert!(production_prefix(commented_marker).contains("tokio::spawn"));

        let raw_marker =
            "const MARKER: &str = r#\"#[cfg(test)]\nmod tests\"#;\nfn serve() { tokio::spawn(async {}); }";
        assert!(production_prefix(raw_marker).contains("tokio::spawn"));

        let decoy_and_real = "const MARKER: &str = r#\"#[cfg(test)]\nmod tests\"#;\nfn serve() {}\n#[cfg(test)]\nmod tests { fn fixture() { tokio::spawn(async {}); } }";
        assert!(production_prefix(decoy_and_real).contains("tokio::spawn"));
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
    fn exact_oast_feature_test_module_filter_rejects_malformed_guards() {
        let guard = "#[cfg(all(test, feature = \"oast-native-provider\"))]";
        for (source, expected) in [
            (guard.to_owned(), "has no following module"),
            (
                format!("{guard}\nfn fixture() {{}}"),
                "must apply directly to a module",
            ),
            (
                format!("{guard}\nmod fixtures {{"),
                "did not contain one complete module",
            ),
        ] {
            let error = source_without_exact_oast_test_modules(&source).unwrap_err();
            assert!(
                error.to_string().contains(expected),
                "malformed OAST cfg guard `{expected}` was not rejected: {error}"
            );
        }

        for source in [
            format!("// {guard}\nmod fixtures {{ fn hidden() {{}} }}"),
            format!("const MARKER: &str = r#\"{guard}\"#;\nmod fixtures {{}}"),
            format!("// {guard}\nmod decoy {{}}\n{guard}\nmod fixtures {{ fn hidden() {{}} }}"),
        ] {
            assert!(
                source_without_exact_oast_test_modules(&source).is_err(),
                "comment or raw-string OAST guard marker unexpectedly removed: {source}"
            );
        }
    }

    #[test]
    fn shared_runtime_native_oast_mint_mutations_fail_closed() {
        let source = include_str!("../../../crates/termivar-scanner/src/web_runtime/authority.rs");
        let production = production_prefix(source);
        assert!(shared_provider_mint_contract_violations(production)
            .unwrap()
            .is_empty());

        for (mutation, expected) in [
            (
                production.replacen(
                    "pub(crate) struct SharedWebRuntimeAuthority",
                    "pub(crate) struct MissingSharedWebRuntimeAuthority",
                    1,
                ),
                "declare exactly one SharedWebRuntimeAuthority",
            ),
            (
                production.replacen(
                    "native_oast_provider_minted: Arc<std::sync::Mutex<bool>>",
                    "native_oast_provider_minted: Arc<std::sync::Mutex<u8>>",
                    1,
                ),
                "Arc<Mutex<bool>> native OAST mint-once state",
            ),
            (
                production.replacen("#[derive(Clone)]", "#[derive(Debug)]", 1),
                "must clone the shared native OAST mint-once state",
            ),
            (
                production.replacen(
                    "fn mint_native_oast_provider",
                    "fn removed_native_oast_provider",
                    1,
                ),
                "expose exactly one crate-private native OAST mint method",
            ),
            (
                production.replacen(
                    "pub(crate) fn mint_native_oast_provider",
                    "pub fn mint_native_oast_provider",
                    1,
                ),
                "one feature-gated crate-private &self method",
            ),
            (
                production.replacen(
                    "        *minted = true;\n        Ok(adapter)",
                    "        let _ = &minted;\n        Ok(adapter)",
                    1,
                ),
                "exactly one mint-state commit",
            ),
        ] {
            let violations = shared_provider_mint_contract_violations(&mutation).unwrap();
            assert!(
                violations
                    .iter()
                    .any(|violation| violation.contains(expected)),
                "shared mint mutation `{expected}` was not rejected: {violations:?}"
            );
        }
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
