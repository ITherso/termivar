//! Machine-enforced isolation for the Preview artifact-signature domain.

use std::{
    collections::BTreeSet,
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use cargo_metadata::{Dependency, DependencyKind, MetadataCommand, Package};
use syn::{
    visit::{self, Visit},
    ExprPath, ItemExternCrate, ItemUse, Macro, Path as SynPath, UseTree,
};

const ARTIFACT_PACKAGE: &str = "termivar-artifact";
const PRODUCT_PACKAGES: &[&str] = &[
    "termivar-scanner",
    "termivar-exploit",
    "termivar-api",
    "termivar-proxy",
];
const EXPECTED_RUNTIME_DEPENDENCIES: &[&str] =
    &["hex", "serde", "serde_json", "sha2", "thiserror", "toml"];
const EXPECTED_SOURCE_FILES: &[&str] = &[
    "catalog.rs",
    "lib.rs",
    "pattern.rs",
    "report.rs",
    "scanner.rs",
];
const FORBIDDEN_SOURCE_PREFIXES: &[&[&str]] = &[
    &["std", "env"],
    &["std", "fs"],
    &["std", "net"],
    &["std", "process"],
    &["std", "os"],
    &["axum"],
    &["fantoccini"],
    &["headless_chrome"],
    &["hyper"],
    &["memmap2"],
    &["playwright"],
    &["reqwest"],
    &["socket2"],
    &["thirtyfour"],
    &["tokio", "fs"],
    &["tokio", "net"],
    &["tokio", "process"],
    &["ureq"],
    &["termivar_exploit"],
    &["termivar_scanner"],
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let packages = metadata.workspace_packages();
    let Some(artifact) = packages
        .iter()
        .copied()
        .find(|package| package.name == ARTIFACT_PACKAGE)
    else {
        return Ok(vec![
            "workspace package `termivar-artifact` is missing from `crates/termivar-artifact`"
                .to_owned(),
        ]);
    };

    let mut violations = package_contract_violations(workspace_root, artifact);
    violations.extend(dependency_edge_violations(workspace_root, &packages));
    violations.extend(source_contract_violations(workspace_root)?);
    violations.extend(pack_layout_violations(workspace_root)?);
    Ok(violations)
}

fn package_contract_violations(workspace_root: &Path, artifact: &Package) -> Vec<String> {
    let mut violations = Vec::new();
    let expected_manifest = workspace_root.join("crates/termivar-artifact/Cargo.toml");
    if artifact.manifest_path.as_std_path() != expected_manifest {
        violations.push(format!(
            "termivar-artifact must remain the separate package at {}, found {}",
            expected_manifest.display(),
            artifact.manifest_path
        ));
    }
    if artifact
        .publish
        .as_ref()
        .is_none_or(|registries| !registries.is_empty())
    {
        violations
            .push("termivar-artifact must remain `publish = false` during Preview".to_owned());
    }
    if artifact.targets.len() != 1
        || artifact.targets[0].name != "termivar_artifact"
        || artifact.targets[0].kind.as_slice() != ["lib"]
    {
        violations.push(
            "termivar-artifact must expose exactly one reviewed `termivar_artifact` library target"
                .to_owned(),
        );
    }
    if !artifact.features.is_empty() {
        violations.push(format!(
            "termivar-artifact V1 must not expose crate features, found {:?}",
            artifact.features.keys().collect::<BTreeSet<_>>()
        ));
    }

    let runtime = dependency_names(artifact, DependencyKind::Normal);
    let expected: BTreeSet<_> = EXPECTED_RUNTIME_DEPENDENCIES.iter().copied().collect();
    if runtime != expected {
        violations.push(format!(
            "termivar-artifact runtime dependencies must remain exactly {expected:?}, found {runtime:?}"
        ));
    }
    for kind in [
        DependencyKind::Development,
        DependencyKind::Build,
        DependencyKind::Unknown,
    ] {
        let names = dependency_names(artifact, kind);
        if !names.is_empty() {
            violations.push(format!(
                "termivar-artifact has forbidden {kind:?} dependencies {names:?}"
            ));
        }
    }
    if artifact.dependencies.iter().any(|dependency| {
        dependency.rename.is_some()
            || dependency.target.is_some()
            || dependency.optional
            || dependency.path.is_some()
    }) {
        violations.push(
            "termivar-artifact dependencies must remain unconditional external libraries"
                .to_owned(),
        );
    }
    violations
}

fn dependency_names(package: &Package, kind: DependencyKind) -> BTreeSet<&str> {
    package
        .dependencies
        .iter()
        .filter(|dependency| dependency.kind == kind)
        .map(|dependency| dependency.name.as_str())
        .collect()
}

fn dependency_edge_violations(workspace_root: &Path, packages: &[&Package]) -> Vec<String> {
    let mut violations = Vec::new();
    for product in PRODUCT_PACKAGES {
        if packages
            .iter()
            .copied()
            .find(|package| package.name == *product)
            .is_some_and(|package| has_dependency(package, ARTIFACT_PACKAGE))
        {
            violations.push(format!(
                "{product} must not depend on the isolated termivar-artifact domain"
            ));
        }
    }

    match packages
        .iter()
        .copied()
        .find(|package| package.name == "termivar-cli")
        .and_then(|package| {
            package
                .dependencies
                .iter()
                .find(|dependency| dependency.name == ARTIFACT_PACKAGE)
                .map(|dependency| (package, dependency))
        }) {
        Some((cli, dependency)) => {
            violations.extend(adapter_dependency_violations(
                workspace_root,
                dependency,
                "crates/termivar-artifact/Cargo.toml",
                true,
                "termivar-cli",
            ));
            let members: BTreeSet<_> = cli
                .features
                .get("artifact-adapter")
                .into_iter()
                .flatten()
                .map(String::as_str)
                .collect();
            if members != BTreeSet::from(["dep:termivar-artifact"])
                || cli
                    .features
                    .get("default")
                    .is_none_or(|default| !default.is_empty())
            {
                violations.push(
                    "termivar-cli must gate its sole artifact edge behind exactly the non-default `artifact-adapter` feature"
                        .to_owned(),
                );
            }
        },
        None => violations.push(
            "termivar-cli is missing the reviewed optional termivar-artifact adapter dependency"
                .to_owned(),
        ),
    }

    match packages
        .iter()
        .copied()
        .find(|package| package.name == "xtask")
        .and_then(|package| {
            package
                .dependencies
                .iter()
                .find(|dependency| dependency.name == ARTIFACT_PACKAGE)
        }) {
        Some(dependency) => violations.extend(adapter_dependency_violations(
            workspace_root,
            dependency,
            "crates/termivar-artifact/Cargo.toml",
            false,
            "xtask",
        )),
        None => violations.push(
            "xtask is missing the reviewed termivar-artifact catalog-validation dependency"
                .to_owned(),
        ),
    }
    violations
}

fn adapter_dependency_violations(
    workspace_root: &Path,
    dependency: &Dependency,
    expected_manifest: &str,
    optional: bool,
    owner: &str,
) -> Vec<String> {
    let expected_path = workspace_root.join(expected_manifest);
    let valid = dependency.kind == DependencyKind::Normal
        && dependency.rename.is_none()
        && dependency.target.is_none()
        && dependency.optional == optional
        && dependency.req.to_string() == "=0.10.0-alpha.1"
        && dependency
            .path
            .as_ref()
            .is_some_and(|path| path.join("Cargo.toml") == expected_path);
    if valid {
        Vec::new()
    } else {
        vec![format!(
            "{owner} termivar-artifact dependency must retain its exact versioned local path and reviewed optionality"
        )]
    }
}

fn has_dependency(package: &Package, dependency_name: &str) -> bool {
    package
        .dependencies
        .iter()
        .any(|dependency| dependency.name == dependency_name)
}

fn source_contract_violations(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let source_root = workspace_root.join("crates/termivar-artifact/src");
    let mut paths = rust_sources_below(&source_root)?;
    paths.sort();
    let actual: BTreeSet<_> = paths
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .collect();
    let expected: BTreeSet<_> = EXPECTED_SOURCE_FILES.iter().copied().collect();
    let mut violations = Vec::new();
    if actual != expected || paths.len() != expected.len() {
        violations.push(format!(
            "termivar-artifact source inventory must remain exactly {expected:?}, found {actual:?}"
        ));
    }

    for path in paths {
        let source = fs::read_to_string(&path)?;
        let parsed = syn::parse_file(&source)?;
        let mut visitor = ForbiddenAuthorityVisitor::default();
        visitor.visit_file(&parsed);
        visitor.surfaces.sort();
        visitor.surfaces.dedup();
        let relative = path.strip_prefix(workspace_root)?.display();
        for surface in visitor.surfaces {
            violations.push(format!(
                "{relative} acquires forbidden artifact authority through `{surface}`"
            ));
        }
    }

    let library = fs::read_to_string(source_root.join("lib.rs"))?;
    let parsed = syn::parse_file(&library)?;
    let forbids_unsafe = parsed.attrs.iter().any(|attribute| {
        attribute.path().is_ident("forbid")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "unsafe_code")
    });
    if !forbids_unsafe {
        violations.push("termivar-artifact must retain `#![forbid(unsafe_code)]`".to_owned());
    }
    Ok(violations)
}

fn pack_layout_violations(workspace_root: &Path) -> io::Result<Vec<String>> {
    let root = workspace_root.join("artifact-signatures");
    let mut files = Vec::new();
    collect_files(&root, &mut files)?;
    let mut violations = Vec::new();
    for path in files {
        let metadata = fs::symlink_metadata(&path)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !matches!(name, "README.md" | "signatures.toml")
        {
            violations.push(format!(
                "artifact-signatures V1 contains forbidden entry {}",
                path.strip_prefix(workspace_root).unwrap_or(&path).display()
            ));
        }
    }
    Ok(violations)
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
        } else {
            files.push(entry.path());
        }
    }
    Ok(())
}

#[derive(Default)]
struct ForbiddenAuthorityVisitor {
    surfaces: Vec<String>,
}

impl ForbiddenAuthorityVisitor {
    fn inspect(&mut self, segments: &[String]) {
        if FORBIDDEN_SOURCE_PREFIXES.iter().any(|prefix| {
            segments.len() >= prefix.len()
                && segments
                    .iter()
                    .zip(prefix.iter())
                    .all(|(actual, expected)| actual.trim_start_matches("r#") == *expected)
        }) {
            self.surfaces.push(segments.join("::"));
        }
    }
}

impl<'ast> Visit<'ast> for ForbiddenAuthorityVisitor {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut prefixes = Vec::new();
        flatten_use_tree(&item.tree, &mut prefixes, &mut |segments| {
            self.inspect(segments)
        });
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        self.inspect(&[item.ident.to_string()]);
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_expr_path(&mut self, expression: &'ast ExprPath) {
        self.inspect(&path_segments(&expression.path));
        visit::visit_expr_path(self, expression);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        let segments = path_segments(&item.path);
        self.inspect(&segments);
        if matches!(segments.as_slice(), [name] if matches!(name.as_str(), "include" | "include_bytes" | "include_str"))
        {
            self.surfaces.push(segments.join("::"));
        }
        visit::visit_macro(self, item);
    }
}

fn flatten_use_tree(tree: &UseTree, prefix: &mut Vec<String>, inspect: &mut impl FnMut(&[String])) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use_tree(&path.tree, prefix, inspect);
            prefix.pop();
        },
        UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            inspect(prefix);
            prefix.pop();
        },
        UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            inspect(prefix);
            prefix.pop();
        },
        UseTree::Glob(_) => inspect(prefix),
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use_tree(item, prefix, inspect);
            }
        },
    }
}

fn path_segments(path: &SynPath) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_metadata() -> (PathBuf, cargo_metadata::Metadata) {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask is directly below workspace root")
            .to_owned();
        let metadata = MetadataCommand::new()
            .manifest_path(workspace_root.join("Cargo.toml"))
            .no_deps()
            .exec()
            .expect("workspace metadata");
        (workspace_root, metadata)
    }

    fn package_refs(packages: &[Package]) -> Vec<&Package> {
        packages.iter().collect()
    }

    fn write_artifact_source_fixture(workspace_root: &Path, library: &str) {
        let source_root = workspace_root.join("crates/termivar-artifact/src");
        fs::create_dir_all(&source_root).expect("create artifact source fixture");
        for source_file in EXPECTED_SOURCE_FILES {
            let source = if *source_file == "lib.rs" {
                library
            } else {
                "pub fn fixture() {}"
            };
            fs::write(source_root.join(source_file), source)
                .expect("write artifact source fixture");
        }
    }

    fn write_workspace_without_product_package(workspace_root: &Path) {
        let fixture_root = workspace_root.join("fixture");
        fs::create_dir_all(fixture_root.join("src")).expect("create fixture package");
        fs::write(
            workspace_root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"fixture\"]\nresolver = \"2\"\n",
        )
        .expect("write fixture workspace manifest");
        fs::write(
            fixture_root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        )
        .expect("write fixture package manifest");
        fs::write(fixture_root.join("src/lib.rs"), "pub fn fixture() {}")
            .expect("write fixture library");
        fs::write(
            workspace_root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.0.0\"\n",
        )
        .expect("write fixture lockfile");
    }

    fn forbidden(source: &str) -> Vec<String> {
        let parsed = syn::parse_file(source).expect("parse source");
        let mut visitor = ForbiddenAuthorityVisitor::default();
        visitor.visit_file(&parsed);
        visitor.surfaces.sort();
        visitor.surfaces.dedup();
        visitor.surfaces
    }

    #[test]
    fn source_policy_rejects_authority_and_allows_reader_only_logic() {
        for source in [
            "use std::fs::File;",
            "use std::{net::TcpStream, io::Read};",
            "fn run() { std::process::Command::new(\"x\"); }",
            "use memmap2 as mapped;",
            "const BYTES: &[u8] = include_bytes!(\"fixture\");",
        ] {
            assert!(!forbidden(source).is_empty(), "source={source}");
        }
        assert!(forbidden("use std::io::{self, Read}; use std::collections::BTreeMap;").is_empty());
    }

    #[test]
    fn reviewed_source_inventory_is_closed_and_executable() {
        let expected: BTreeSet<_> = EXPECTED_SOURCE_FILES.iter().copied().collect();
        assert_eq!(expected.len(), 5);
        assert!(expected.contains("lib.rs"));
        assert!(expected.contains("scanner.rs"));
        assert!(!expected.contains("detector.rs"));
    }

    #[test]
    fn product_dependency_inventory_excludes_artifact_runtime() {
        assert_eq!(PRODUCT_PACKAGES.len(), 4);
        assert!(PRODUCT_PACKAGES.contains(&"termivar-scanner"));
        assert!(PRODUCT_PACKAGES.contains(&"termivar-exploit"));
        assert!(!PRODUCT_PACKAGES.contains(&"termivar-cli"));
    }

    #[test]
    fn current_artifact_package_identity_mutations_are_rejected() {
        let (workspace_root, metadata) = workspace_metadata();
        let artifact = metadata
            .workspace_packages()
            .into_iter()
            .find(|package| package.name == ARTIFACT_PACKAGE)
            .expect("artifact package");
        assert!(package_contract_violations(&workspace_root, artifact).is_empty());

        let mut stale_manifest = artifact.clone();
        stale_manifest.manifest_path = "crates/venom-artifact/Cargo.toml".into();
        assert!(
            package_contract_violations(&workspace_root, &stale_manifest)
                .iter()
                .any(|violation| violation
                    .contains("termivar-artifact must remain the separate package"))
        );

        let mut publishable = artifact.clone();
        publishable.publish = None;
        assert!(package_contract_violations(&workspace_root, &publishable)
            .iter()
            .any(|violation| violation.contains("publish = false")));

        let mut stale_target = artifact.clone();
        stale_target.targets[0].name = "venom_artifact".to_owned();
        assert!(package_contract_violations(&workspace_root, &stale_target)
            .iter()
            .any(|violation| violation.contains("reviewed `termivar_artifact` library target")));

        let mut expanded = artifact.clone();
        expanded.features.insert("runtime".to_owned(), Vec::new());
        let dependency = expanded
            .dependencies
            .iter_mut()
            .find(|dependency| dependency.name == "hex")
            .expect("reviewed dependency");
        dependency.kind = DependencyKind::Development;
        dependency.optional = true;
        let violations = package_contract_violations(&workspace_root, &expanded).join("\n");
        for expected in [
            "termivar-artifact V1 must not expose crate features",
            "termivar-artifact runtime dependencies must remain exactly",
            "termivar-artifact has forbidden Development dependencies",
            "termivar-artifact dependencies must remain unconditional external libraries",
        ] {
            assert!(
                violations.contains(expected),
                "missing {expected:?} in {violations}"
            );
        }
    }

    #[test]
    fn architecture_check_requires_the_current_artifact_package_identity() {
        let temporary = tempfile::TempDir::new().expect("temporary workspace");
        write_workspace_without_product_package(temporary.path());
        assert_eq!(
            check(temporary.path()).expect("missing package is a typed violation"),
            ["workspace package `termivar-artifact` is missing from `crates/termivar-artifact`"]
        );
    }

    #[test]
    fn current_artifact_dependency_edges_are_mutation_locked() {
        let (workspace_root, metadata) = workspace_metadata();
        let baseline = metadata
            .workspace_packages()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        assert!(dependency_edge_violations(&workspace_root, &package_refs(&baseline)).is_empty());

        let artifact_dependency = baseline
            .iter()
            .find(|package| package.name == "termivar-cli")
            .and_then(|package| {
                package
                    .dependencies
                    .iter()
                    .find(|dependency| dependency.name == ARTIFACT_PACKAGE)
            })
            .expect("reviewed CLI artifact dependency")
            .clone();

        let mut product_edge = baseline.clone();
        product_edge
            .iter_mut()
            .find(|package| package.name == "termivar-scanner")
            .expect("scanner package")
            .dependencies
            .push(artifact_dependency.clone());
        assert!(
            dependency_edge_violations(&workspace_root, &package_refs(&product_edge))
                .iter()
                .any(|violation| violation
                    == "termivar-scanner must not depend on the isolated termivar-artifact domain")
        );

        let mut missing_cli_edge = baseline.clone();
        missing_cli_edge
            .iter_mut()
            .find(|package| package.name == "termivar-cli")
            .expect("CLI package")
            .dependencies
            .retain(|dependency| dependency.name != ARTIFACT_PACKAGE);
        assert!(
            dependency_edge_violations(&workspace_root, &package_refs(&missing_cli_edge))
                .iter()
                .any(
                    |violation| violation.contains("termivar-cli is missing the reviewed optional")
                )
        );

        let mut stale_cli_feature = baseline.clone();
        stale_cli_feature
            .iter_mut()
            .find(|package| package.name == "termivar-cli")
            .expect("CLI package")
            .features
            .insert(
                "artifact-adapter".to_owned(),
                vec!["dep:venom-artifact".to_owned()],
            );
        assert!(
            dependency_edge_violations(&workspace_root, &package_refs(&stale_cli_feature))
                .iter()
                .any(
                    |violation| violation.contains("termivar-cli must gate its sole artifact edge")
                )
        );

        let mut widened_adapter = baseline.clone();
        widened_adapter
            .iter_mut()
            .find(|package| package.name == "termivar-cli")
            .and_then(|package| {
                package
                    .dependencies
                    .iter_mut()
                    .find(|dependency| dependency.name == ARTIFACT_PACKAGE)
            })
            .expect("CLI artifact dependency")
            .optional = false;
        assert!(dependency_edge_violations(&workspace_root, &package_refs(&widened_adapter))
            .iter()
            .any(|violation| violation.contains(
                "termivar-cli termivar-artifact dependency must retain its exact versioned local path"
            )));

        let mut missing_xtask_edge = baseline;
        missing_xtask_edge
            .iter_mut()
            .find(|package| package.name == "xtask")
            .expect("xtask package")
            .dependencies
            .retain(|dependency| dependency.name != ARTIFACT_PACKAGE);
        assert!(
            dependency_edge_violations(&workspace_root, &package_refs(&missing_xtask_edge))
                .iter()
                .any(|violation| violation
                    .contains("xtask is missing the reviewed termivar-artifact"))
        );
    }

    #[test]
    fn renamed_artifact_source_root_preserves_inventory_and_authority_gates() {
        let temporary = tempfile::TempDir::new().expect("temporary workspace");
        write_artifact_source_fixture(
            temporary.path(),
            "#![forbid(unsafe_code)]\npub fn fixture() {}",
        );
        assert!(source_contract_violations(temporary.path())
            .expect("valid source fixture")
            .is_empty());

        let source_root = temporary.path().join("crates/termivar-artifact/src");
        fs::write(
            source_root.join("scanner.rs"),
            "use termivar_scanner::WebAssessmentRuntime; use termivar_exploit::Manifest;",
        )
        .expect("mutate artifact source");
        let violations = source_contract_violations(temporary.path())
            .expect("authority mutation is inspectable")
            .join("\n");
        assert!(violations.contains("termivar_scanner"), "{violations}");
        assert!(violations.contains("termivar_exploit"), "{violations}");

        fs::write(source_root.join("scanner.rs"), "pub fn fixture() {}")
            .expect("restore artifact source");
        fs::write(source_root.join("lib.rs"), "pub fn fixture() {}")
            .expect("remove unsafe-code gate");
        let violations = source_contract_violations(temporary.path())
            .expect("unsafe-code mutation is inspectable");
        assert!(violations.iter().any(
            |violation| violation == "termivar-artifact must retain `#![forbid(unsafe_code)]`"
        ));

        fs::write(source_root.join("extra.rs"), "pub fn fixture() {}")
            .expect("widen source inventory");
        assert!(source_contract_violations(temporary.path())
            .expect("inventory mutation is inspectable")
            .iter()
            .any(|violation| violation.contains("termivar-artifact source inventory")));
    }
}
