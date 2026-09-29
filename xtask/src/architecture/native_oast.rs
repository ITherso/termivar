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
            && has_only_exact_feature_cfg(&profile.attrs, FEATURE)
            && has_doc_hidden(&profile.attrs)
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
            })
            && methods.get("resolved_address").is_some_and(|method| {
                matches!(method.vis, Visibility::Inherited)
                    && plain_method_shape(method, false)
                    && method.sig.inputs.len() == 1
                    && owned_receiver(method.sig.inputs.first())
                    && return_type_is_path(&method.sig.output, &["SocketAddr"])
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

fn owned_xml_https_profile_surface_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    const FEATURE: &str = "xml-external-entity-owned-https-test-profile";
    const TYPE_NAME: &str = "OwnedXmlHttpsTestTransportProfile";

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
        is_crate_visibility(&profile.vis)
            && has_only_exact_feature_cfg(&profile.attrs, FEATURE)
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

    Ok(violations)
}

fn owned_xml_https_profile_reexport_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    const FEATURE: &str = "xml-external-entity-owned-https-test-profile";
    const EXPECTED_PATH: &str = "request_broker::OwnedXmlHttpsTestTransportProfile";

    let syntax = syn::parse_file(source)?;
    let exports = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Use(import) => {
                let mut paths = Vec::new();
                flatten_use_tree(&import.tree, &mut Vec::new(), &mut paths);
                paths
                    .iter()
                    .any(|path| path == EXPECTED_PATH)
                    .then_some((import, paths))
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let exact = exports.first().is_some_and(|(import, paths)| {
        is_crate_visibility(&import.vis)
            && has_only_exact_feature_cfg(&import.attrs, FEATURE)
            && paths.len() == 1
            && paths.first().is_some_and(|path| path == EXPECTED_PATH)
    });
    Ok(if exports.len() == 1 && exact {
        Vec::new()
    } else {
        vec![
            "termivar-scanner must re-export the owned XML HTTPS transport profile exactly crate-private and behind only its test-profile feature"
                .to_owned(),
        ]
    })
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
    matches!(call.receiver.as_ref(), syn::Expr::Path(path)
        if path.qself.is_none() && path.path.is_ident(receiver))
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
    method.defaultness.is_none()
        && method.sig.constness.is_some() == is_const
        && method.sig.asyncness.is_none()
        && method.sig.unsafety.is_none()
        && method.sig.abi.is_none()
        && method.sig.generics.params.is_empty()
        && method.sig.generics.where_clause.is_none()
        && method.sig.variadic.is_none()
        && has_no_conditional_cfg(&method.attrs)
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
    let Some(function) = syntax.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "bound_request" => Some(function),
        _ => None,
    }) else {
        return false;
    };
    // Require a single operation future whose first statement owns admission
    // and whose tail dispatches the untouched body. This rejects early body
    // reads, moved admission, or a permit dropped before handler extraction.
    let [syn::Stmt::Local(operation), syn::Stmt::Expr(_, None)] = function.block.stmts.as_slice()
    else {
        return false;
    };
    let syn::Pat::Ident(binding) = &operation.pat else {
        return false;
    };
    if binding.ident != "operation" {
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
    if !pattern.path.is_ident("Ok")
        || !matches!(pattern.elems.first(), Some(syn::Pat::Ident(permit)) if permit.ident == "_permit")
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
        && admit.method == "admit"
        && path_expression_name(&admit.receiver).as_deref() == Some("state")
        && admit.args.is_empty()
        && run.method == "run"
        && path_expression_name(&run.receiver).as_deref() == Some("next")
        && run.args.len() == 1
        && run.args.first().and_then(path_expression_name).as_deref() == Some("request")
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
                fn record(&self) {}
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
            production.replacen(".tls_built_in_root_certs(false)", "", 1),
            production.replacen(
                "OWNED_HTTPS_TEST_PROVIDER_HOST,\n                profile_port.resolved_address()",
                "other_host, profile_port.resolved_address()",
                1,
            ),
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
                "#[cfg(feature = \"xml-external-entity-owned-https-test-profile\")]\npub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                "#[cfg(feature = \"xml-external-entity-review\")]\npub(crate) use request_broker::OwnedXmlHttpsTestTransportProfile;",
                1,
            ),
            http_evidence.replacen(
                "OwnedXmlHttpsTestTransportProfile;",
                "RenamedOwnedXmlHttpsTestTransportProfile;",
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
                format!("#![allow(dead_code)]\n{production}"),
                "must not suppress dead-code policy",
            ),
            (
                production.replacen("NativeOastClient::new(", "NativeOastClient::build(", 1),
                "NativeOastClient::new(",
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
    }

    #[test]
    fn admission_ast_guard_rejects_malformed_outer_operation_shapes() {
        for source in [
            "fn bound_request(",
            "fn unrelated() {}",
            "fn bound_request() {}",
            "fn bound_request() { consume_body(); let operation = async {}; finish(operation) }",
            "fn bound_request() { let operation = async {}; finish(operation); }",
            "fn bound_request() { let (operation,) = async {}; finish(operation) }",
            "fn bound_request() { let other = async {}; finish(other) }",
            "fn bound_request() { let operation; finish(operation) }",
            "fn bound_request() { let operation = run(); finish(operation) }",
            "fn bound_request() { let operation = async {}; finish(operation) }",
        ] {
            assert!(
                !admission_precedes_body_dispatch(source),
                "malformed outer admission shape unexpectedly passed: {source}"
            );
        }
    }

    #[test]
    fn admission_ast_guard_requires_the_owned_permit_and_awaited_body_dispatch() {
        // These standalone parser fixtures deliberately do not reproduce the
        // production module. Each varies one semantic boundary of the guard.
        let admission = "let Ok(_permit) = state.admit() else { return rejected(); };";
        let dispatch = "next.run(request).await";
        let source = |admission: &str, dispatch: &str| {
            format!(
                "async fn bound_request() {{ let operation = async {{ {admission} {dispatch} }}; finish(operation) }}"
            )
        };
        assert!(admission_precedes_body_dispatch(&source(
            admission, dispatch
        )));
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
                !admission_precedes_body_dispatch(&source(malformed, dispatch)),
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
                !admission_precedes_body_dispatch(&source(admission, malformed)),
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
