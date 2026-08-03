//! Workspace source reachability check for Rust module graphs.
//!
//! Any non-inline `.rs` file under a workspace crate `src/` directory should be
//! reachable from one of that crate's Rust targets (`lib.rs`, `main.rs`, etc.).

use std::{
    collections::{BTreeSet, VecDeque},
    error::Error,
    fs,
    io,
    path::{Path, PathBuf},
};

use cargo_metadata::MetadataCommand;
use syn::{
    visit::{self, Visit},
    Attribute, Expr, Lit, Meta, MetaNameValue, Item, ItemMod,
};

// Temporary, explicit legacy scaffolds kept out of the module graph while the
// runtime consolidation work is ongoing. These paths are intentionally quarantined
// until the migration path decides whether to wire or remove them.
const SOURCE_REACHABILITY_ALLOWLIST: &[(&str, &[&str])] = &[
    (
        "venom-scanner",
        &[
            "src/anomaly.rs",
            "src/anomaly/baseline.rs",
            "src/anomaly/confidence.rs",
            "src/anomaly/detector.rs",
            "src/anomaly/metrics.rs",
            "src/anomaly/pipeline.rs",
            "src/anomaly/rules.rs",
            "src/anomaly/statistics.rs",
            "src/distributed.rs",
            "src/distributed/heartbeat.rs",
            "src/distributed/protocol.rs",
            "src/distributed/queue.rs",
            "src/distributed/result.rs",
            "src/distributed/retry.rs",
            "src/distributed/scheduler.rs",
            "src/distributed/worker.rs",
            "src/lua.rs",
            "src/lua/cache.rs",
            "src/lua/executor.rs",
            "src/lua/history.rs",
            "src/lua/loader.rs",
            "src/lua/mod.rs",
            "src/lua/registry.rs",
            "src/lua/sandbox.rs",
            "src/lua/types.rs",
            "src/api_evidence/profiled.rs",
            "src/api_evidence/profiled/canonical.rs",
            "src/api_evidence/profiled/diff.rs",
            "src/api_evidence/profiled/policy.rs",
            "src/api_evidence/profiled_tests.rs",
            "src/semantic/entity.rs",
            "src/semantic/extractor.rs",
            "src/web_runtime/api_visibility.rs",
            "src/web_runtime/api_visibility/differential.rs",
            "src/web_runtime/api_visibility/differential/execution.rs",
            "src/web_runtime/api_visibility/differential_tests.rs",
            "src/web_runtime/api_visibility/tests.rs",
        ],
    ),
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;

    let mut violations = Vec::new();

    for package in metadata.workspace_packages() {
        let package_root = package
            .manifest_path
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "package manifest has no parent"))?;
        let package_root = package_root.as_std_path();
        let source_root = package_root.join("src");
        if !source_root.is_dir() {
            continue;
        }

        let root_sources = crate_root_targets(package, &source_root)?;
        if root_sources.is_empty() {
            continue;
        }

        let reachable = collect_reachable_sources(&source_root, &root_sources)?;
        let allowlist = allowed_sources_for(&package.name);
        let all_sources = collect_all_rust_files(&source_root)?;

        for source in all_sources {
            let relative = relative_path(&source_root, &source);
            let source = fs::canonicalize(&source)?;
            if reachable.contains(&source) || allowlist.contains(&relative) {
                continue;
            }
            violations.push(format!(
                "workspace package `{}` has unreferenced Rust source `src/{}`",
                package.name, relative
            ));
        }
    }

    Ok(violations)
}

fn allowed_sources_for(package_name: &str) -> BTreeSet<String> {
    let mut allowed = BTreeSet::new();
    for (candidate, sources) in SOURCE_REACHABILITY_ALLOWLIST {
        if *candidate == package_name {
            for source in *sources {
                allowed.insert((*source).to_owned());
            }
        }
    }
    allowed
}

fn crate_root_targets(
    package: &cargo_metadata::Package,
    source_root: &Path,
) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let mut roots = Vec::new();
    for target in &package.targets {
        let source = target.src_path.as_std_path();
        if source.extension().and_then(|extension| extension.to_str()) != Some("rs") {
            continue;
        }
        let canonical = fs::canonicalize(source).or_else(|error| match error.kind() {
            io::ErrorKind::NotFound => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("crate target source path missing: {}", source.display()),
            )),
            _ => Err(error),
        })?;
        if canonical.starts_with(fs::canonicalize(source_root)?) {
            roots.push(canonical);
        }
    }
    Ok(roots)
}

fn collect_reachable_sources(
    source_root: &Path,
    root_sources: &[PathBuf],
) -> Result<BTreeSet<PathBuf>, Box<dyn Error>> {
    let source_root = fs::canonicalize(source_root)?;
    let mut reachable = BTreeSet::new();
    let mut queue = VecDeque::new();

    for root in root_sources {
        let canonical = fs::canonicalize(root)?;
        if canonical.starts_with(&source_root) {
            reachable.insert(canonical.clone());
            queue.push_back(canonical);
        }
    }

    while let Some(source) = queue.pop_front() {
        let source_text = fs::read_to_string(&source)?;
        let syntax = syn::parse_file(&source_text)?;
        let current_dir = source
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "source file has no parent"))?
            .to_path_buf();
        let module_dir = module_children_dir(&source)?;
        let mut visitor = ReachabilityVisitor {
            source_root: &source_root,
            source_dir: current_dir,
            module_dir,
            queue: &mut queue,
            reachable: &mut reachable,
        };
        visitor.visit_file(&syntax);
    }

    Ok(reachable)
}

struct ReachabilityVisitor<'root, 'queue> {
    source_root: &'root Path,
    source_dir: PathBuf,
    module_dir: PathBuf,
    queue: &'queue mut VecDeque<PathBuf>,
    reachable: &'queue mut BTreeSet<PathBuf>,
}

impl ReachabilityVisitor<'_, '_> {
    fn resolve_module_path(&self, item: &ItemMod) -> Option<PathBuf> {
        let module_name = item.ident.to_string();
        if let Some(override_path) = item
            .attrs
            .iter()
            .find_map(parse_path_attr)
            .and_then(|path| {
                let joined = self.source_dir.join(path);
                if joined.exists() {
                    Some(joined)
                } else {
                    None
                }
            })
        {
            return Some(override_path);
        }

        let flat = self.module_dir.join(format!("{module_name}.rs"));
        if flat.exists() {
            return Some(flat);
        }

        let nested = self.module_dir.join(&module_name).join("mod.rs");
        if nested.exists() {
            return Some(nested);
        }

        None
    }

    fn enqueue_if_reachable(&mut self, path: PathBuf) {
        if let Ok(canonical) = fs::canonicalize(path) {
            if canonical.starts_with(self.source_root) && self.reachable.insert(canonical.clone()) {
                self.queue.push_back(canonical);
            }
        }
    }
}

impl Visit<'_> for ReachabilityVisitor<'_, '_> {
    fn visit_item_mod(&mut self, item: &ItemMod) {
        if item.content.is_none() {
            if let Some(path) = self.resolve_module_path(item) {
                self.enqueue_if_reachable(path);
            }
        }
        visit::visit_item_mod(self, item);
    }

    fn visit_item(&mut self, item: &Item) {
        visit::visit_item(self, item);
    }
}

fn parse_path_attr(attribute: &Attribute) -> Option<String> {
    let Meta::NameValue(MetaNameValue { value, path, .. }) = &attribute.meta else {
        return None;
    };
    if !path.is_ident("path") {
        return None;
    }
    let Expr::Lit(expression) = value else {
        return None;
    };
    let Lit::Str(path) = &expression.lit else {
        return None;
    };
    Some(path.value())
}

fn module_children_dir(source_path: &Path) -> Result<PathBuf, io::Error> {
    let source_name = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source file has no file name: {}", source_path.display()),
            )
        })?;
    let source_dir = source_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source file has no parent directory: {}", source_path.display()),
        )
    })?;
    let source_stem = source_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();

    if source_name == "lib.rs" || source_name == "main.rs" || source_name == "mod.rs" {
        Ok(source_dir.to_path_buf())
    } else if source_stem.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("source file has empty stem: {}", source_path.display()),
        ))
    } else {
        Ok(source_dir.join(source_stem))
    }
}

fn relative_path(base: &Path, target: &Path) -> String {
    let relative = target
        .strip_prefix(base)
        .map_or_else(|_| target.to_string_lossy(), |suffix| suffix.to_string_lossy())
        .replace('\\', "/");
    if relative.starts_with("src/") || relative == "src" {
        return relative;
    }
    if relative.is_empty() {
        "src".to_owned()
    } else {
        format!("src/{relative}")
    }
}

fn collect_all_rust_files(source_root: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let mut output = Vec::new();
    collect_rust_sources(source_root, &mut output)?;
    Ok(output)
}

fn collect_rust_sources(root: &Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> io::Result<PathBuf> {
        let temp_root = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = temp_root.join(format!("venom-reachability-{nanos}"));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    #[test]
    fn allowlist_has_scanner_scaffold_files() {
        let allowlist = allowed_sources_for("venom-scanner");
        assert!(allowlist.contains("src/anomaly/metrics.rs"));
        assert!(allowlist.contains("src/lua/cache.rs"));
        assert!(allowlist.contains("src/distributed/worker.rs"));
    }

    #[test]
    fn parse_path_attribute() {
        let source = r#"#[path = "foo/bar.rs"] mod custom;"#;
        let syntax: syn::File = syn::parse_file(source).unwrap();
        let Item::Mod(module) = &syntax.items[0] else {
            panic!("expected module item");
        };
        assert_eq!(parse_path_attr(&module.attrs[0]), Some("foo/bar.rs".to_owned()));
    }

    #[test]
    fn resolve_declared_module_path() {
        let root = unique_temp_dir().unwrap();
        fs::write(root.join("parent.rs"), b"").unwrap();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("custom.rs"), b"").unwrap();
        let source = r#"#[path = "nested/custom.rs"] mod custom;"#;
        let file: syn::File = syn::parse_file(source).unwrap();
        let Item::Mod(module) = &file.items[0] else {
            panic!("expected module item");
        };
        let mut queue = VecDeque::new();
        let mut reachable = BTreeSet::new();
        let visitor = ReachabilityVisitor {
            source_root: &root,
            source_dir: root.to_path_buf(),
            module_dir: module_children_dir(&root.join("parent.rs")).unwrap(),
            queue: &mut queue,
            reachable: &mut reachable,
        };
        assert!(visitor.resolve_module_path(module).is_some());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nested_module_is_resolved_from_non_root_file() {
        let root = unique_temp_dir().unwrap();
        let parent = root.join("parent.rs");
        fs::write(&parent, b"mod nested;").unwrap();
        fs::create_dir_all(root.join("parent")).unwrap();
        fs::write(root.join("parent").join("nested.rs"), b"").unwrap();

        let source = fs::read_to_string(&parent).unwrap();
        let syntax = syn::parse_file(&source).unwrap();
        let module = match &syntax.items[0] {
            Item::Mod(module) => module,
            _ => panic!("expected mod item"),
        };
        let mut queue = VecDeque::new();
        let mut reachable = BTreeSet::new();
        let visitor = ReachabilityVisitor {
            source_root: &root,
            source_dir: parent.parent().unwrap().to_path_buf(),
            module_dir: module_children_dir(&parent).unwrap(),
            queue: &mut queue,
            reachable: &mut reachable,
        };

        assert!(visitor.resolve_module_path(module).is_some());
        fs::remove_dir_all(root).unwrap();
    }
}
