//! Fail-closed source hygiene at production execution boundaries.
//!
//! Disabled test modules conceal executable contracts, while defaulting a task
//! or join failure can turn an incomplete scan into apparent success. These
//! checks parse Rust syntax rather than matching formatting-sensitive source
//! text.

use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use syn::{
    parse::Parser,
    punctuated::Punctuated,
    visit::{self, Visit},
    Attribute, Expr, ExprCall, ExprMethodCall, Item, Meta, MetaList, Token, TypePath,
};

use super::{has_cfg_test, item_attributes};

const PROGRESS_WRITER_SOURCE: &str = "crates/termivar-cli/src/progress.rs";

const SCAN_TASK_BOUNDARY_SOURCES: &[&str] = &[
    "crates/termivar-scanner/src/runner.rs",
    "crates/termivar-scanner/src/sdk.rs",
    "crates/termivar-scanner/src/decision_runner.rs",
    "crates/termivar-cli/src/main.rs",
    "crates/termivar-cli/src/assessment_scan.rs",
    "crates/termivar-cli/src/decision_scan.rs",
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let mut violations = Vec::new();
    for path in guarded_rust_sources(workspace_root)? {
        let source = fs::read_to_string(&path)?;
        violations.extend(always_disabled_cfg_violations(
            &display_path(workspace_root, &path),
            &source,
        )?);
    }
    for relative_path in SCAN_TASK_BOUNDARY_SOURCES {
        let path = workspace_root.join(relative_path);
        if !path.is_file() {
            violations.push(format!(
                "scan task/join boundary source `{relative_path}` is missing"
            ));
            continue;
        }
        let source = fs::read_to_string(path)?;
        violations.extend(unwrap_or_default_violations(relative_path, &source)?);
    }
    if !workspace_root.join(PROGRESS_WRITER_SOURCE).is_file() {
        violations.push(format!(
            "progress writer ownership source `{PROGRESS_WRITER_SOURCE}` is missing"
        ));
    }
    let cli_main = fs::read_to_string(workspace_root.join("crates/termivar-cli/src/main.rs"))?;
    violations.extend(progress_module_violations(&cli_main)?);
    let cli_sources = guarded_rust_sources(workspace_root)?
        .into_iter()
        .filter(|path| display_path(workspace_root, path).starts_with("crates/termivar-cli/src/"))
        .collect::<Vec<_>>();
    for path in cli_sources {
        let relative = display_path(workspace_root, &path);
        let source = fs::read_to_string(path)?;
        violations.extend(progress_writer_thread_violations(&relative, &source)?);
    }
    Ok(violations)
}

fn progress_module_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let modules = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == "progress" => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() == 1
        && matches!(modules[0].vis, syn::Visibility::Inherited)
        && modules[0].content.is_none()
        && modules[0].attrs.is_empty()
    {
        Ok(Vec::new())
    } else {
        Ok(vec![
            "CLI progress writer must remain one private direct `progress.rs` module".to_owned(),
        ])
    }
}

fn guarded_rust_sources(workspace_root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let crates_root = workspace_root.join("crates");
    if crates_root.is_dir() {
        for entry in fs::read_dir(crates_root)? {
            let crate_root = entry?.path();
            for guarded_directory in ["src", "tests"] {
                let source_root = crate_root.join(guarded_directory);
                if source_root.is_dir() {
                    collect_rust_sources(&source_root, &mut files)?;
                }
            }
        }
    }
    let xtask_root = workspace_root.join("xtask/src");
    if xtask_root.is_dir() {
        collect_rust_sources(&xtask_root, &mut files)?;
    }
    files.sort();
    Ok(files)
}

fn collect_rust_sources(current: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_rust_sources(&path, files)?;
        } else if file_type.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn display_path(workspace_root: &Path, path: &Path) -> String {
    path.strip_prefix(workspace_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn always_disabled_cfg_violations(path: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = DisabledTestCfgVisitor::default();
    visitor.visit_file(&syntax);
    if visitor.count == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "guarded Rust source `{path}` contains {} always-disabled cfg(any()) attribute(s)",
        visitor.count
    )])
}

#[derive(Default)]
struct DisabledTestCfgVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for DisabledTestCfgVisitor {
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        if is_always_disabled_cfg(attribute) {
            self.count += 1;
        }
        visit::visit_attribute(self, attribute);
    }
}

fn is_always_disabled_cfg(attribute: &Attribute) -> bool {
    if !attribute.path().is_ident("cfg") {
        return false;
    }
    let Meta::List(cfg) = &attribute.meta else {
        return false;
    };
    let Ok(meta) = syn::parse2::<Meta>(cfg.tokens.clone()) else {
        return false;
    };
    meta_is_always_false(&meta)
}

fn meta_is_always_false(meta: &Meta) -> bool {
    match meta {
        Meta::List(list) if list.path.is_ident("any") && list.tokens.is_empty() => true,
        Meta::List(list) if list.path.is_ident("all") => {
            nested_meta(list).is_some_and(|items| items.iter().any(meta_is_always_false))
        },
        Meta::Path(_) | Meta::NameValue(_) => false,
        Meta::List(_) => false,
    }
}

fn nested_meta(list: &MetaList) -> Option<Punctuated<Meta, Token![,]>> {
    Punctuated::<Meta, Token![,]>::parse_terminated
        .parse2(list.tokens.clone())
        .ok()
}

fn unwrap_or_default_violations(path: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = UnwrapOrDefaultVisitor::default();
    visitor.visit_file(&syntax);
    if visitor.count == 0 {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "scan task/join boundary `{path}` contains {} `unwrap_or_default()` call(s); propagate or classify failure explicitly",
        visitor.count
    )])
}

fn progress_writer_thread_violations(path: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = ProductionThreadVisitor::default();
    visitor.visit_file(&syntax);
    let owns_thread_surface = visitor.builder_new > 0
        || visitor.direct_thread_spawn > 0
        || visitor.async_spawn > 0
        || visitor.join_handles > 0;
    if path == PROGRESS_WRITER_SOURCE {
        if visitor.builder_new == 1
            && visitor.named_workers == 1
            && visitor.spawn_methods == 1
            && visitor.direct_thread_spawn == 0
            && visitor.async_spawn == 0
            && visitor.join_handles == 1
        {
            Ok(Vec::new())
        } else {
            Ok(vec![format!(
                "progress output must own exactly one named thread::Builder worker and one JoinHandle, with no direct or async spawn escape; observed builders={}, named_workers={}, spawn_methods={}, direct_spawns={}, async_spawns={}, join_handles={}",
                visitor.builder_new,
                visitor.named_workers,
                visitor.spawn_methods,
                visitor.direct_thread_spawn,
                visitor.async_spawn,
                visitor.join_handles,
            )])
        }
    } else if owns_thread_surface {
        Ok(vec![format!(
            "CLI production thread ownership escaped `{PROGRESS_WRITER_SOURCE}` into `{path}`"
        )])
    } else {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct ProductionThreadVisitor {
    builder_new: usize,
    named_workers: usize,
    spawn_methods: usize,
    direct_thread_spawn: usize,
    async_spawn: usize,
    join_handles: usize,
}

impl ProductionThreadVisitor {
    fn path_ends_with(path: &syn::Path, expected: &[&str]) -> bool {
        let actual = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        actual.ends_with(
            &expected
                .iter()
                .map(|segment| (*segment).to_owned())
                .collect::<Vec<_>>(),
        )
    }
}

impl<'ast> Visit<'ast> for ProductionThreadVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if !has_cfg_test(item_attributes(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !has_cfg_test(&item.attrs) {
            visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_expr_call(&mut self, expression: &'ast ExprCall) {
        if let Expr::Path(function) = expression.func.as_ref() {
            if Self::path_ends_with(&function.path, &["thread", "Builder", "new"]) {
                self.builder_new += 1;
            }
            if Self::path_ends_with(&function.path, &["thread", "spawn"]) {
                self.direct_thread_spawn += 1;
            }
            if Self::path_ends_with(&function.path, &["tokio", "spawn"])
                || function
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "spawn_blocking")
            {
                self.async_spawn += 1;
            }
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        if expression.method == "name"
            && expression.args.len() == 1
            && matches!(expression.args.first(), Some(Expr::MethodCall(call))
                if call.method == "to_owned"
                    && matches!(call.receiver.as_ref(), Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Str(value)
                            if value.value() == "termivar-progress")))
        {
            self.named_workers += 1;
        }
        if expression.method == "spawn" {
            self.spawn_methods += 1;
        }
        if expression.method == "spawn_blocking" {
            self.async_spawn += 1;
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_type_path(&mut self, item_type: &'ast TypePath) {
        if item_type
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "JoinHandle")
        {
            self.join_handles += 1;
        }
        visit::visit_type_path(self, item_type);
    }
}

#[derive(Default)]
struct UnwrapOrDefaultVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for UnwrapOrDefaultVisitor {
    fn visit_expr_method_call(&mut self, expression: &'ast ExprMethodCall) {
        if expression.method == "unwrap_or_default" {
            self.count += 1;
        }
        visit::visit_expr_method_call(self, expression);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_task_boundary_inventory_includes_both_cli_adapters() {
        let inventory = SCAN_TASK_BOUNDARY_SOURCES
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(inventory.len(), SCAN_TASK_BOUNDARY_SOURCES.len());
        assert!(inventory.contains("crates/termivar-cli/src/main.rs"));
        assert!(inventory.contains("crates/termivar-cli/src/decision_scan.rs"));
        assert!(inventory.contains("crates/termivar-cli/src/assessment_scan.rs"));
    }

    #[test]
    fn disabled_cfg_is_rejected_across_crate_whitespace_and_nested_variants() {
        for source in [
            "#![cfg(any())] fn hidden_crate() {}",
            "#[cfg(all(test, any()))] mod hidden {}",
            "#[cfg( all ( test , any ( ) ) )] mod hidden {}",
            "#[cfg(all(feature = \"distributed\", test, any()))] mod hidden {}",
            "#[cfg(all(test, all(feature = \"lua\", any())))] mod hidden {}",
        ] {
            let violations = always_disabled_cfg_violations("fixture.rs", source).unwrap();
            assert_eq!(violations.len(), 1, "{source}");
            assert!(violations[0].contains("always-disabled cfg(any())"));
        }
    }

    #[test]
    fn normal_test_and_feature_attributes_are_allowed() {
        let source = r#"
            #[cfg(test)] mod tests {}
            #[cfg(all(test, feature = "distributed"))] mod distributed_tests {}
            #[cfg(any(test, feature = "lua"))] mod lua_tests {}
            #[cfg(not(any()))] mod always_enabled {}
        "#;
        assert!(always_disabled_cfg_violations("fixture.rs", source)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn crate_integration_test_sources_are_guarded() {
        let temp = tempfile::TempDir::new().unwrap();
        let crate_root = temp.path().join("crates/fixture");
        fs::create_dir_all(crate_root.join("src")).unwrap();
        fs::create_dir_all(crate_root.join("tests")).unwrap();
        fs::write(crate_root.join("src/lib.rs"), b"pub fn live() {}\n").unwrap();
        fs::write(crate_root.join("tests/disabled.rs"), b"#![cfg(any())]\n").unwrap();

        let files = guarded_rust_sources(temp.path()).unwrap();
        assert!(files
            .iter()
            .any(|path| path.ends_with("crates/fixture/tests/disabled.rs")));
        let source = fs::read_to_string(
            files
                .iter()
                .find(|path| path.ends_with("crates/fixture/tests/disabled.rs"))
                .unwrap(),
        )
        .unwrap();
        assert!(!always_disabled_cfg_violations("disabled.rs", &source)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn scan_boundary_defaulting_is_rejected_syntax_aware() {
        let source = r#"
            async fn collect(handle: Handle) {
                let result = handle.await . unwrap_or_default ( );
                consume(result);
            }
        "#;
        let violations = unwrap_or_default_violations("runner.rs", source).unwrap();
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("propagate or classify failure explicitly"));
    }

    #[test]
    fn explicit_scan_boundary_failure_classification_is_allowed() {
        let source = r#"
            async fn collect(handle: Handle) -> Result<Value, JoinError> {
                match handle.await {
                    Ok(value) => Ok(value),
                    Err(error) => Err(error),
                }
            }
        "#;
        assert!(unwrap_or_default_violations("runner.rs", source)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn progress_writer_thread_ownership_is_exact_and_test_threads_are_ignored() {
        let valid = r#"
            use std::thread::{self, JoinHandle};
            struct ProgressOutput { worker: Option<JoinHandle<()>> }
            fn start() {
                let _worker = thread::Builder::new().name("termivar-progress".to_owned())
                    .spawn(|| {}).unwrap();
            }
            #[cfg(test)]
            mod tests { fn fixture() { std::thread::spawn(|| {}); } }
            impl ProgressOutput {
                #[cfg(test)]
                fn fixture() { std::thread::spawn(|| {}); }
            }
        "#;
        assert!(
            progress_writer_thread_violations(PROGRESS_WRITER_SOURCE, valid)
                .unwrap()
                .is_empty()
        );

        let direct_spawn = valid.replace(
            "let _worker = thread::Builder::new()",
            "thread::spawn(|| {}); let _worker = thread::Builder::new()",
        );
        assert_ne!(direct_spawn, valid);
        let violations = progress_writer_thread_violations(PROGRESS_WRITER_SOURCE, &direct_spawn)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("no direct or async spawn escape"),
            "{violations}"
        );

        let async_escape = valid.replace(
            "let _worker = thread::Builder::new()",
            "tokio::spawn(async {}); let _worker = thread::Builder::new()",
        );
        assert_ne!(async_escape, valid);
        let violations = progress_writer_thread_violations(PROGRESS_WRITER_SOURCE, &async_escape)
            .unwrap()
            .join("\n");
        assert!(
            violations.contains("no direct or async spawn escape"),
            "{violations}"
        );

        let violations =
            progress_writer_thread_violations("crates/termivar-cli/src/assessment_scan.rs", valid)
                .unwrap()
                .join("\n");
        assert!(
            violations.contains("thread ownership escaped"),
            "{violations}"
        );

        let detached = valid.replace("worker: Option<JoinHandle<()>>", "worker: bool");
        let violations = progress_writer_thread_violations(PROGRESS_WRITER_SOURCE, &detached)
            .unwrap()
            .join("\n");
        assert!(violations.contains("one JoinHandle"), "{violations}");
    }

    #[test]
    fn progress_module_is_private_direct_and_unconditional() {
        assert!(progress_module_violations("mod progress;")
            .unwrap()
            .is_empty());
        for source in [
            "pub mod progress;",
            "#[path = \"alternate.rs\"] mod progress;",
            "#[cfg(test)] mod progress;",
            "mod progress {}",
            "mod progress; mod progress;",
        ] {
            let violations = progress_module_violations(source).unwrap().join("\n");
            assert!(violations.contains("private direct"), "{violations}");
        }
    }
}
