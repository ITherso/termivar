//! Workspace source reachability check for Rust module graphs.
//!
//! Any non-inline `.rs` file under a workspace crate `src/` directory should be
//! reachable from one of that crate's Rust targets (`lib.rs`, `main.rs`, etc.).

use std::{
    collections::{BTreeSet, VecDeque},
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use cargo_metadata::MetadataCommand;
use syn::{visit::Visit, Attribute, Expr, ItemMod, Lit, Meta, MetaNameValue};

/// Deliberately quarantined source files that are not yet wired into the module
/// graph, keyed by workspace package. Each entry is `(relative_path, reason)`.
///
/// This is a controlled debt ledger, not a graveyard: every entry is fail-closed
/// validated by [`allowlist_violations`]. An entry that no longer exists, that has
/// become reachable, that is not a `src/`-relative Rust source, or that carries no
/// reason is itself an architecture violation. The list is therefore self-cleaning
/// — a stale exception breaks the gate instead of silently hiding a regression.
///
/// It is intentionally empty: the whole workspace is reachable today.
const SOURCE_REACHABILITY_ALLOWLIST: &[(&str, &[(&str, &str)])] = &[];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;

    let mut violations = Vec::new();

    for package in metadata.workspace_packages() {
        let package_root = package.manifest_path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "package manifest has no parent")
        })?;
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
        let exceptions = exceptions_for(&package.name);
        let allowlist = allowed_sources_for(&package.name);
        let all_sources = collect_all_rust_files(&source_root)?;

        // Relative (`src/…`) views of what exists on disk and what is reachable,
        // used both to flag orphans and to fail-closed validate the exception list.
        let canonical_root = fs::canonicalize(&source_root)?;
        let existing: BTreeSet<String> = all_sources
            .iter()
            .map(|source| relative_path(&source_root, source))
            .collect();
        let reachable_relative: BTreeSet<String> = reachable
            .iter()
            .map(|source| relative_path(&canonical_root, source))
            .collect();

        // The exception ledger must not rot: stale, reachable, or unjustified
        // entries are violations in their own right.
        violations.extend(allowlist_violations(
            &package.name,
            exceptions,
            &existing,
            &reachable_relative,
        ));

        for source in all_sources {
            let relative = relative_path(&source_root, &source);
            let source = fs::canonicalize(&source)?;
            if reachable.contains(&source) || allowlist.contains(&relative) {
                continue;
            }
            violations.push(format!(
                "workspace package `{}` has unreferenced Rust source `{}`",
                package.name, relative
            ));
        }
    }

    Ok(violations)
}

fn exceptions_for(package_name: &str) -> &'static [(&'static str, &'static str)] {
    SOURCE_REACHABILITY_ALLOWLIST
        .iter()
        .find(|(candidate, _)| *candidate == package_name)
        .map(|(_, entries)| *entries)
        .unwrap_or(&[])
}

fn allowed_sources_for(package_name: &str) -> BTreeSet<String> {
    exceptions_for(package_name)
        .iter()
        .map(|(path, _)| (*path).to_owned())
        .collect()
}

/// Fail-closed validation of a package's reachability exception list. Returns one
/// violation per malformed or stale entry so the allowlist can never silently hide
/// a regression:
///
/// 1. the entry must be a `src/`-relative path,
/// 2. it must be a Rust (`.rs`) source,
/// 3. it must carry a non-empty reason,
/// 4. it must still exist on disk (a deleted entry is stale), and
/// 5. it must still be unreachable (an entry that became reachable is stale and
///    must be removed so the graph — not the ledger — governs it).
fn allowlist_violations(
    package: &str,
    entries: &[(&str, &str)],
    existing: &BTreeSet<String>,
    reachable: &BTreeSet<String>,
) -> Vec<String> {
    let mut violations = Vec::new();
    for (path, reason) in entries {
        let path = *path;
        if !path.starts_with("src/") {
            violations.push(format!(
                "package `{package}` reachability exception `{path}` must be a `src/`-relative path"
            ));
        }
        if !path.ends_with(".rs") {
            violations.push(format!(
                "package `{package}` reachability exception `{path}` must be a Rust source (`.rs`)"
            ));
        }
        if reason.trim().is_empty() {
            violations.push(format!(
                "package `{package}` reachability exception `{path}` must carry a non-empty reason"
            ));
        }
        if !existing.contains(path) {
            violations.push(format!(
                "package `{package}` reachability exception `{path}` no longer exists; remove the stale entry"
            ));
        } else if reachable.contains(path) {
            violations.push(format!(
                "package `{package}` reachability exception `{path}` is now reachable; remove it from the allowlist"
            ));
        }
    }
    violations
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
        let canonical = fs::canonicalize(source).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("crate target source path missing: {}", source.display()),
            ),
            _ => error,
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
        match &item.content {
            // A file-based module (`mod foo;`): resolve and enqueue its backing file.
            None => {
                if let Some(path) = self.resolve_module_path(item) {
                    self.enqueue_if_reachable(path);
                }
            },
            // An inline module (`mod foo { .. }`) introduces a path component for
            // its external children, mirroring rustc's module resolution. A `#[path]`
            // on the inline module overrides that base directory (relative to the
            // current file's directory); otherwise children live in
            // `<module_dir>/<name>/`. Recurse with the adjusted directory so an
            // external child declared inside an inline module is still reachable.
            Some((_, items)) => {
                let child_dir = item
                    .attrs
                    .iter()
                    .find_map(parse_path_attr)
                    .map(|path| self.source_dir.join(path))
                    .unwrap_or_else(|| self.module_dir.join(item.ident.to_string()));
                let mut nested = ReachabilityVisitor {
                    source_root: self.source_root,
                    source_dir: child_dir.clone(),
                    module_dir: child_dir,
                    queue: self.queue,
                    reachable: self.reachable,
                };
                for inner in items {
                    nested.visit_item(inner);
                }
            },
        }
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
            format!(
                "source file has no parent directory: {}",
                source_path.display()
            ),
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
        .map_or_else(
            |_| target.to_string_lossy(),
            |suffix| suffix.to_string_lossy(),
        )
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
    use syn::Item;
    use tempfile::TempDir;

    fn assert_empty<T>(values: &[T]) {
        assert!(values.is_empty());
    }

    #[test]
    fn allowlist_is_empty_by_contract() {
        // The workspace is fully reachable today; the exception ledger stays empty.
        assert_empty(SOURCE_REACHABILITY_ALLOWLIST);
        assert!(allowed_sources_for("termivar-scanner").is_empty());
    }

    #[test]
    fn a_genuine_orphan_exception_with_a_reason_is_accepted() {
        let existing = BTreeSet::from(["src/orphan.rs".to_owned(), "src/live.rs".to_owned()]);
        let reachable = BTreeSet::from(["src/live.rs".to_owned()]);
        let violations = allowlist_violations(
            "demo",
            &[(
                "src/orphan.rs",
                "pending wiring, tracked in internal ticket",
            )],
            &existing,
            &reachable,
        );
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn a_reachable_exception_is_a_stale_violation() {
        let existing = BTreeSet::from(["src/live.rs".to_owned()]);
        let reachable = BTreeSet::from(["src/live.rs".to_owned()]);
        let violations =
            allowlist_violations("demo", &[("src/live.rs", "reason")], &existing, &reachable);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("is now reachable"));
    }

    #[test]
    fn a_deleted_exception_is_a_stale_violation() {
        let existing = BTreeSet::from(["src/live.rs".to_owned()]);
        let reachable = BTreeSet::new();
        let violations =
            allowlist_violations("demo", &[("src/gone.rs", "reason")], &existing, &reachable);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("no longer exists"));
    }

    #[test]
    fn an_exception_without_a_reason_is_rejected() {
        let existing = BTreeSet::from(["src/orphan.rs".to_owned()]);
        let reachable = BTreeSet::new();
        let violations =
            allowlist_violations("demo", &[("src/orphan.rs", "   ")], &existing, &reachable);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].contains("non-empty reason"));
    }

    #[test]
    fn a_non_src_non_rust_exception_is_rejected() {
        let existing = BTreeSet::new();
        let reachable = BTreeSet::new();
        let violations =
            allowlist_violations("demo", &[("docs/note.md", "reason")], &existing, &reachable);
        assert!(violations.iter().any(|v| v.contains("relative path")));
        assert!(violations
            .iter()
            .any(|v| v.contains("must be a Rust source")));
    }

    #[test]
    fn parse_path_attribute() {
        let source = r#"#[path = "foo/bar.rs"] mod custom;"#;
        let syntax: syn::File = syn::parse_file(source).unwrap();
        let Item::Mod(module) = &syntax.items[0] else {
            panic!("expected module item");
        };
        assert_eq!(
            parse_path_attr(&module.attrs[0]),
            Some("foo/bar.rs".to_owned())
        );
    }

    #[test]
    fn resolve_declared_module_path() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
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
    }

    #[test]
    fn nested_module_is_resolved_from_non_root_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
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
    }

    #[test]
    fn inline_module_with_external_child_is_reachable() {
        // `lib.rs` declares an inline module whose child lives in an external
        // file under `<name>/`. rustc treats the child as reachable; so must the
        // gate, otherwise it would raise a false-positive unreachable violation.
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        fs::write(root.join("lib.rs"), b"mod outer {\n    mod child;\n}\n").unwrap();
        fs::create_dir_all(root.join("outer")).unwrap();
        fs::write(root.join("outer").join("child.rs"), b"").unwrap();

        let reachable = collect_reachable_sources(&root, &[root.join("lib.rs")]).unwrap();

        let child = fs::canonicalize(root.join("outer").join("child.rs")).unwrap();
        assert!(
            reachable.contains(&child),
            "inline module's external child was not reached: {reachable:?}"
        );
    }

    #[test]
    fn violation_path_never_contains_src_src() {
        // Mirror the production contract: `relative_path` is given the crate's
        // `src` directory (the `source_root`) and must yield a single
        // `src/`-prefixed path, never a doubled `src/src/`.
        let source_root = PathBuf::from("workspace").join("crate").join("src");
        let target = source_root.join("orphan.rs");

        let relative = relative_path(&source_root, &target);
        assert_eq!(relative, "src/orphan.rs");

        let message = format!("workspace package `demo` has unreferenced Rust source `{relative}`");
        assert!(
            !message.contains("src/src/"),
            "violation message double-prefixed src/: {message}"
        );
        assert!(message.contains("`src/orphan.rs`"));
    }

    #[test]
    fn inline_module_path_attribute_changes_child_base_directory() {
        // lib.rs:
        //   #[path = "thread_files"]
        //   mod thread {
        //       #[path = "tls.rs"]
        //       mod local_data;
        //   }
        // The `#[path]` on the inline module redirects its children's base
        // directory, so the external child resolves to `thread_files/tls.rs`
        // rather than `thread/tls.rs`.
        let temp = TempDir::new().unwrap();
        let root = temp.path().to_path_buf();
        fs::write(
            root.join("lib.rs"),
            b"#[path = \"thread_files\"]\nmod thread {\n    #[path = \"tls.rs\"]\n    mod local_data;\n}\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("thread_files")).unwrap();
        fs::write(root.join("thread_files").join("tls.rs"), b"").unwrap();

        let reachable = collect_reachable_sources(&root, &[root.join("lib.rs")]).unwrap();

        let child = fs::canonicalize(root.join("thread_files").join("tls.rs")).unwrap();
        assert!(
            reachable.contains(&child),
            "inline #[path] child base directory not honored: {reachable:?}"
        );
    }
}
