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
    Attribute, ExprMethodCall, Meta, MetaList, Token,
};

const SCAN_TASK_BOUNDARY_SOURCES: &[&str] = &[
    "crates/venom-scanner/src/runner.rs",
    "crates/venom-scanner/src/sdk.rs",
    "crates/venom-scanner/src/decision_runner.rs",
    "crates/venom-cli/src/main.rs",
    "crates/venom-cli/src/assessment_scan.rs",
    "crates/venom-cli/src/decision_scan.rs",
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
    Ok(violations)
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
        assert!(inventory.contains("crates/venom-cli/src/main.rs"));
        assert!(inventory.contains("crates/venom-cli/src/decision_scan.rs"));
        assert!(inventory.contains("crates/venom-cli/src/assessment_scan.rs"));
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
}
