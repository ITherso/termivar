//! Exact isolation and release-boundary checks for the self-hosted native OAST
//! provider. The provider is an auxiliary raw-free callback mailbox, never a
//! scanner or a release-bundle component.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use cargo_metadata::{CargoOpt, DependencyKind, Metadata, MetadataCommand, Package};
use syn::{Fields, Item, ReturnType, Type, UseTree, Visibility};

const PACKAGE: &str = "termivar-oast";
const MANIFEST: &str = "crates/termivar-oast/Cargo.toml";
const SOURCE_ROOT: &str = "crates/termivar-oast/src";
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
    "serde",
    "serde_json",
    "sha2",
    "subtle",
    "tokio",
    "tower",
    "url",
    "zeroize",
];

const EXPECTED_SOURCE_FILES: &[&str] = &[
    "bin/termivar-oast-provider.rs",
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
    let dependency_metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .features(CargoOpt::AllFeatures)
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    violations.extend(forbidden_crypto_dependency_violations(
        &dependency_metadata,
        &provider.id.to_string(),
    ));
    violations.extend(source_contract_violations(workspace_root)?);
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
    packages
        .iter()
        .copied()
        .filter(|package| package.name != PACKAGE)
        .filter(|package| {
            package
                .dependencies
                .iter()
                .any(|dependency| dependency.name == PACKAGE)
        })
        .map(|package| {
            format!(
                "workspace package `{}` must not depend on the PR A provider service",
                package.name
            )
        })
        .collect()
}

fn forbidden_crypto_dependency_violations(metadata: &Metadata, root: &str) -> Vec<String> {
    let names = metadata
        .packages
        .iter()
        .map(|package| (package.id.to_string(), package.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let Some(resolve) = metadata.resolve.as_ref() else {
        return vec![format!(
            "{PACKAGE} all-features dependency graph must include Cargo resolve metadata"
        )];
    };
    let edges = resolve
        .nodes
        .iter()
        .map(|node| {
            (
                node.id.to_string(),
                node.deps
                    .iter()
                    .map(|dependency| dependency.pkg.to_string())
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    dependency_closure_crypto_violations(root, &names, &edges)
}

fn dependency_closure_crypto_violations(
    root: &str,
    package_names: &BTreeMap<String, String>,
    dependency_edges: &BTreeMap<String, BTreeSet<String>>,
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
                forbidden.insert((family, name.clone()));
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
    for function in server.items.iter().filter_map(|item| match item {
        Item::Fn(function) => Some(function),
        _ => None,
    }) {
        if matches!(function.vis, Visibility::Public(_)) && function.sig.ident != "serve_provider" {
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

    let mut server_exports = Vec::new();
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
            path.starts_with("server::").then(|| path.to_owned())
        }));
    }
    server_exports.sort();
    if server_exports
        != [
            "server::ProviderServerError".to_owned(),
            "server::serve_provider".to_owned(),
        ]
    {
        violations.push(format!(
            "{PACKAGE} library must export exactly serve_provider and ProviderServerError from its private server module"
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
    fn provider_crypto_gate_is_scoped_to_its_transitive_all_features_closure() {
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
}
