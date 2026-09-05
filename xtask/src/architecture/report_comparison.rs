//! Exact additive boundary for offline, display-only report comparison.
//!
//! Imported JSON is not an authoritative runtime model. This module's narrowly
//! enumerated source ownership does not relax the existing reporting facade.

use std::{collections::BTreeSet, error::Error, fs, path::Path};

use proc_macro2::{TokenStream, TokenTree};
use sha2::{Digest, Sha256};
use syn::{visit::Visit, Item, UseTree, Visibility};

pub(super) const SCANNER_SOURCES: &[&str] = &[
    "reporting/comparison.rs",
    "reporting/comparison/import.rs",
    "reporting/comparison/import/audits.rs",
    "reporting/comparison/html.rs",
    "reporting/comparison/tests.rs",
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let scanner = workspace_root.join("crates/termivar-scanner/src");
    let mut violations = Vec::new();
    let mut actual = BTreeSet::new();
    collect_sources(&scanner.join("reporting"), &scanner, &mut actual)?;
    let expected = SCANNER_SOURCES
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    if actual != expected {
        violations.push(
            "comparison source ownership must remain the exact five audited files".to_owned(),
        );
    }
    for relative in SCANNER_SOURCES
        .iter()
        .filter(|path| !path.ends_with("/tests.rs"))
    {
        match fs::read_to_string(scanner.join(relative)) {
            Ok(source) => {
                violations.extend(source_violations(relative, &source)?);
                if *relative == "reporting/comparison/html.rs" {
                    violations.extend(html_violations(&source)?);
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                violations.push(format!("comparison source `{relative}` is missing"))
            },
            Err(error) => return Err(error.into()),
        }
    }
    violations.extend(cli_violations(
        &fs::read_to_string(workspace_root.join("crates/termivar-cli/src/main.rs"))?,
        &fs::read_to_string(workspace_root.join("crates/termivar-cli/src/report_compare.rs"))?,
    )?);
    Ok(violations)
}

fn cli_violations(main: &str, comparison: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(main)?;
    let main_items: Vec<_> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(item) if item.sig.ident == "main" => Some(item),
            _ => None,
        })
        .collect();
    let expected = r#"fn main() -> Result<(), Box<dyn std::error::Error>> {
        let cli = Cli::parse();
        if let Some(Commands::Report { command }) = cli.command {
            return report_compare::run(command).map_err(Into::into);
        }
        run_existing_command(cli.command)
    }"#;
    let mut violations = Vec::new();
    if main_items.len() != 1
        || !main_items[0].attrs.is_empty()
        || main_items[0].sig.asyncness.is_some()
        || function_tokens(main, "main") != function_tokens(expected, "main")
    {
        violations.push("comparison CLI must dispatch the exact offline Report arm synchronously before runtime initialization".to_owned());
    }
    let mut visitor = CliVisitor {
        violations: BTreeSet::new(),
    };
    visitor.visit_file(&syn::parse_file(comparison)?);
    violations.extend(visitor.violations);
    Ok(violations)
}

fn function_tokens(source: &str, name: &str) -> Option<String> {
    let tokens: Vec<_> = source.parse::<TokenStream>().ok()?.into_iter().collect();
    for (index, pair) in tokens.windows(2).enumerate() {
        if matches!(&pair[0], TokenTree::Ident(ident) if ident == "fn")
            && matches!(&pair[1], TokenTree::Ident(ident) if ident == name)
        {
            let end = tokens.iter().enumerate().skip(index + 2).find_map(|(index, token)| {
                matches!(token, TokenTree::Group(group) if group.delimiter() == proc_macro2::Delimiter::Brace).then_some(index)
            })?;
            return Some(
                tokens[index..=end]
                    .iter()
                    .cloned()
                    .collect::<TokenStream>()
                    .to_string(),
            );
        }
    }
    None
}

fn html_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let scripts: Vec<_> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item) if item.ident == "SCRIPT" => match &*item.expr {
                syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(value),
                    ..
                }) if matches!(item.vis, Visibility::Inherited) => Some(value.value()),
                _ => None,
            },
            _ => None,
        })
        .collect();
    let mut violations = Vec::new();
    if scripts.len() != 1
        || format!("{:x}", Sha256::digest(scripts[0].as_bytes()))
            != "666fdb36b8ec2d24ea3a31cbb8fcb490de2a5ba6ffee7fd6b6fc9c788e33d05f"
    {
        violations.push("comparison HTML may execute only the exact audited fixed filter/search/print script literal".to_owned());
    }
    let render = function_tokens(source, "render").unwrap_or_default();
    for required in [
        "STANDARD . encode (Sha256 :: digest (SCRIPT . as_bytes ()))",
        "STANDARD . encode (Sha256 :: digest (STYLE . as_bytes ()))",
        "default-src 'none'; base-uri 'none'; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; script-src 'sha256-",
        "output . push_str (SCRIPT) ?",
        "output . push_str (STYLE) ?",
    ] {
        if !render.contains(required) {
            violations.push("comparison HTML must preserve exact digest-bound script/style CSP and static program emission".to_owned());
        }
    }
    if render.matches("<script>").count() != 1 || render.matches("</script>").count() != 1 {
        violations.push("comparison HTML must have exactly one fixed script element".to_owned());
    }
    Ok(violations)
}

struct CliVisitor {
    violations: BTreeSet<String>,
}

impl CliVisitor {
    fn inspect_path(&mut self, path: &syn::Path) {
        let joined = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let root = path
            .segments
            .first()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        let allowed = if root == "crate" {
            [
                "crate::auth_input::open_regular_file",
                "crate::preflight_report_output",
                "crate::write_report_atomically",
            ]
            .contains(&joined.as_str())
        } else if root == "termivar_scanner" {
            [
                "termivar_scanner::reporting::comparison::compare_reports",
                "termivar_scanner::reporting::comparison::ComparisonError",
                "termivar_scanner::reporting::comparison::ComparisonFormat",
                "termivar_scanner::reporting::comparison::MAX_COMPARISON_INPUT_BYTES",
            ]
            .contains(&joined.as_str())
        } else if root == "std" {
            ["std::fmt", "std::io", "std::path", "std::error::Error"]
                .iter()
                .any(|prefix| joined == *prefix || joined.starts_with(&format!("{prefix}::")))
        } else {
            !root.starts_with("termivar_")
                && !root.starts_with("venom_")
                && ![
                    "super", "tokio", "reqwest", "hyper", "axum", "url", "libc", "windows",
                    "chrono", "rand",
                ]
                .contains(&root.as_str())
        };
        if !allowed {
            self.violations.insert("comparison CLI may access only comparison bytes API, the shared no-follow opener, and existing atomic-output helpers; no runtime or credential initialization".to_owned());
        }
    }
}

impl<'ast> Visit<'ast> for CliVisitor {
    fn visit_visibility(&mut self, visibility: &'ast Visibility) {
        if matches!(visibility, Visibility::Restricted(visibility) if !visibility.path.is_ident("crate"))
        {
            self.violations.insert(
                "comparison CLI visibility may not escape its private command module".to_owned(),
            );
        }
    }
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.inspect_path(path);
        syn::visit::visit_path(self, path);
    }
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, String::new(), &mut paths);
        for path in paths {
            if let Ok(path) = syn::parse_str::<syn::Path>(&path) {
                self.inspect_path(&path);
            } else {
                self.violations.insert(
                    "comparison CLI cannot add renamed or wildcard authority imports".to_owned(),
                );
            }
        }
        syn::visit::visit_item_use(self, item);
    }
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.ident == "tests"
            && item.content.is_some()
            && item.attrs.len() == 1
            && matches!(&item.attrs[0].meta, syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string() == "test")
        {
            return;
        }
        self.violations
            .insert("comparison CLI cannot delegate to additional modules".to_owned());
    }
    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        if signature.asyncness.is_some() || signature.unsafety.is_some() || signature.abi.is_some()
        {
            self.violations.insert(
                "comparison CLI must remain synchronous safe local-file composition".to_owned(),
            );
        }
        syn::visit::visit_signature(self, signature);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !["matches", "format", "write", "writeln"]
            .iter()
            .any(|name| mac.path.is_ident(name))
        {
            self.violations.insert(
                "comparison CLI cannot hide authority through macros or source indirection"
                    .to_owned(),
            );
        }
        let mut guard = ComparisonVisitor {
            relative: "CLI macro",
            violations: BTreeSet::new(),
            deserialize_impls: 0,
        };
        guard.inspect_tokens(mac.tokens.clone());
        self.violations.extend(guard.violations);
    }
}

fn collect_sources(
    directory: &Path,
    root: &Path,
    result: &mut BTreeSet<String>,
) -> Result<(), Box<dyn Error>> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_sources(&path, root, result)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            result.insert(
                path.strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn source_violations(relative: &str, source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = ComparisonVisitor {
        relative,
        violations: BTreeSet::new(),
        deserialize_impls: 0,
    };
    visitor.visit_file(&syntax);
    let expected_deserialize = usize::from(relative.ends_with("/import.rs"));
    if visitor.deserialize_impls != expected_deserialize {
        visitor.reject(
            "only import.rs may implement DeserializeSeed, exactly once for private ValueSeed",
        );
    }
    let actual_public: BTreeSet<_> = syntax.items.iter().filter_map(public_item_name).collect();
    let expected_public: BTreeSet<_> = if relative == "reporting/comparison.rs" {
        [
            "COMPARISON_DOCUMENT_SCHEMA",
            "MAX_COMPARISON_INPUT_BYTES",
            "ComparisonFormat",
            "ComparisonError",
            "compare_reports",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    } else {
        BTreeSet::new()
    };
    if actual_public != expected_public {
        visitor.reject("public API must remain the byte-input comparison function, formats, bounded errors, and two constants only");
    }
    if relative == "reporting/comparison.rs" {
        let expected = "fn compare_reports(before: &[u8], after: &[u8], format: ComparisonFormat,) -> Result<String, ComparisonError> {}";
        let signature = |source| {
            function_tokens(source, "compare_reports").and_then(|source| {
                let mut tokens: Vec<_> = source.parse::<TokenStream>().ok()?.into_iter().collect();
                tokens.pop();
                Some(tokens.into_iter().collect::<TokenStream>().to_string())
            })
        };
        if signature(source) != signature(expected) {
            visitor.reject("public compare_reports must accept exactly two byte slices plus format and return only rendered text or a bounded error");
        }
    }
    if relative.ends_with("/import.rs") {
        let wrappers: Vec<_> = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(item) if item.ident == "ValueSeed" => Some(item),
                _ => None,
            })
            .collect();
        if wrappers.len() != 1
            || !matches!(wrappers[0].vis, Visibility::Inherited)
            || !matches!(&wrappers[0].fields, syn::Fields::Named(fields) if fields.named.len() == 1 && fields.named[0].ident.as_ref().is_some_and(|ident| ident == "depth") && matches!(fields.named[0].vis, Visibility::Inherited) && matches!(&fields.named[0].ty, syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident("usize")))
        {
            visitor.reject(
                "the only deserialization seed must remain private ValueSeed { depth: usize }",
            );
        }
    }
    Ok(visitor.violations.into_iter().collect())
}

fn public_item_name(item: &Item) -> Option<String> {
    let (visibility, name) = match item {
        Item::Const(item) => (&item.vis, item.ident.to_string()),
        Item::Enum(item) => (&item.vis, item.ident.to_string()),
        Item::Struct(item) => (&item.vis, item.ident.to_string()),
        Item::Fn(item) => (&item.vis, item.sig.ident.to_string()),
        Item::Mod(item) => (&item.vis, item.ident.to_string()),
        Item::Type(item) => (&item.vis, item.ident.to_string()),
        Item::Use(item) => (&item.vis, "reexport".to_owned()),
        Item::Trait(item) => (&item.vis, item.ident.to_string()),
        Item::Static(item) => (&item.vis, item.ident.to_string()),
        _ => return None,
    };
    matches!(visibility, Visibility::Public(_)).then_some(name)
}

struct ComparisonVisitor<'a> {
    relative: &'a str,
    violations: BTreeSet<String>,
    deserialize_impls: usize,
}

impl ComparisonVisitor<'_> {
    fn reject(&mut self, reason: &str) {
        self.violations
            .insert(format!("{}: comparison {reason}", self.relative));
    }

    fn inspect_path(&mut self, path: &syn::Path) {
        let parts: Vec<_> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let joined = parts.join("::");
        if parts.first().is_some_and(|root| {
            root == "crate"
                || root.starts_with("termivar_")
                || root.starts_with("venom_")
                || [
                    "tokio",
                    "reqwest",
                    "hyper",
                    "hyper_util",
                    "axum",
                    "url",
                    "rand",
                    "getrandom",
                    "chrono",
                    "time",
                    "libc",
                    "windows",
                ]
                .contains(&root.as_str())
        }) {
            self.reject(
                "cannot import or construct runtime, network, clock, random, or platform authority",
            );
        }
        if parts.first().is_some_and(|root| root == "std")
            && ![
                "std::collections::BTreeMap",
                "std::collections::BTreeSet",
                "std::error::Error",
                "std::fmt",
                "std::str",
                "std::cmp",
                "std::convert",
            ]
            .iter()
            .any(|prefix| joined == *prefix || joined.starts_with(&format!("{prefix}::")))
        {
            self.reject("must remain filesystem-, process-, environment-, and network-free");
        }
        if parts.first().is_some_and(|root| root == "super") {
            let allowed = match self.relative {
                "reporting/comparison.rs" => &[
                    "super::render_serializable_json",
                    "super::write_markdown_code_span",
                    "super::RenderBuffer",
                    "super::ReportError",
                    "super::MAX_RENDERED_REPORT_BYTES",
                ][..],
                "reporting/comparison/import.rs" => &[
                    "super::ComparisonError",
                    "super::EvidenceMetadata",
                    "super::ImportedDocument",
                    "super::ImportedItem",
                    "super::ItemProjection",
                    "super::RemediationProjection",
                    "super::SourceMetadata",
                    "super::MAX_COMPARISON_INPUT_BYTES",
                ][..],
                "reporting/comparison/import/audits.rs" => &[
                    "super::boolean",
                    "super::check",
                    "super::digest",
                    "super::keys",
                    "super::number",
                    "super::object",
                    "super::optional_boolean",
                    "super::optional_text",
                    "super::optional_token",
                    "super::string",
                    "super::text",
                    "super::token",
                    "super::ComparisonError",
                    "super::ImportedItem",
                    "super::Value",
                    "super::MAX_IDENTIFIER_BYTES",
                ][..],
                "reporting/comparison/html.rs" => &[
                    "super::ComparisonDocument",
                    "super::ComparisonError",
                    "super::ComparisonItem",
                    "super::ItemProjection",
                    "super::SourceMetadata",
                    "super::super::write_html_text",
                    "super::super::RenderBuffer",
                    "super::super::ReportError",
                ][..],
                _ => &[],
            };
            if !allowed
                .iter()
                .any(|prefix| joined == *prefix || joined.starts_with(&format!("{prefix}::")))
            {
                self.reject("may delegate only to its exact private projection and existing bounded escaping helpers");
            }
        }
    }

    fn inspect_tokens(&mut self, tokens: TokenStream) {
        for token in tokens {
            match token {
                TokenTree::Ident(ident) => {
                    let identifier = ident.to_string();
                    if [
                        "std", "core", "crate", "super", "reqwest", "tokio", "hyper", "axum",
                        "libc", "windows",
                    ]
                    .contains(&identifier.as_str())
                    {
                        self.reject(
                            "cannot hide ambient or delegated authority inside macro tokens",
                        );
                    }
                    self.inspect_identifier(&identifier);
                },
                TokenTree::Group(group) => self.inspect_tokens(group.stream()),
                _ => {},
            }
        }
    }

    fn inspect_identifier(&mut self, identifier: &str) {
        if [
            "Deserialize",
            "EvidenceId",
            "AssessmentItem",
            "AssessmentRunReport",
            "RunReport",
            "RunOutcomeRecord",
            "CaseId",
            "VerifiedFinding",
            "VerificationResult",
            "WebAssessmentRunReport",
            "AuthorizedTarget",
            "TargetAuthority",
            "Client",
            "TcpStream",
            "TcpListener",
            "UdpSocket",
            "File",
            "OpenOptions",
            "Command",
            "SystemTime",
            "Instant",
            "UnsafeCell",
            "unsafe",
            "env",
            "include",
            "include_str",
            "include_bytes",
            "option_env",
            "macro_rules",
        ]
        .contains(&identifier)
            || identifier.starts_with("termivar_")
            || identifier.starts_with("venom_")
        {
            self.reject("cannot mint authoritative models, access ambient authority, or hide code through source indirection");
        }
    }
}

impl<'ast> Visit<'ast> for ComparisonVisitor<'_> {
    fn visit_visibility(&mut self, visibility: &'ast Visibility) {
        if matches!(visibility, Visibility::Restricted(visibility) if !visibility.path.is_ident("super"))
        {
            self.reject("projection visibility must remain private or parent-only, never crate-wide authority");
        }
    }
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let exact_test = item.ident == "tests"
            && item.attrs.len() == 1
            && matches!(&item.attrs[0].meta, syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string() == "test")
            && matches!(item.vis, Visibility::Inherited);
        if exact_test && (item.content.is_some() || self.relative == "reporting/comparison.rs") {
            return;
        }
        if self.relative == "reporting/comparison.rs"
            && ["html", "import"].contains(&item.ident.to_string().as_str())
            && item.content.is_none()
            && item.attrs.is_empty()
            && matches!(item.vis, Visibility::Inherited)
        {
            return;
        }
        if self.relative == "reporting/comparison/import.rs"
            && item.ident == "audits"
            && item.content.is_none()
            && item.attrs.is_empty()
            && matches!(item.vis, Visibility::Inherited)
        {
            return;
        }
        self.reject("may use only its exact private html/import modules and cfg(test) tests");
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, String::new(), &mut paths);
        for path in paths {
            if path.ends_with("::*") || path.contains(" as ") {
                self.reject("cannot rename or wildcard-import dependencies");
            } else if let Ok(path) = syn::parse_str::<syn::Path>(&path) {
                self.inspect_path(&path);
            }
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        if attribute.path().is_ident("doc") {
            return;
        }
        if !["derive", "serde", "non_exhaustive"]
            .iter()
            .any(|name| attribute.path().is_ident(name))
        {
            self.reject("cannot add conditional, source-path, or procedural authority attributes");
        }
        if let syn::Meta::List(meta) = &attribute.meta {
            if meta
                .tokens
                .to_string()
                .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .any(|part| part == "Deserialize")
            {
                self.reject("cannot derive Deserialize for projection or authoritative models");
            }
            self.inspect_tokens(meta.tokens.clone());
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item.trait_.as_ref().is_some_and(|(_, path, _)| {
            path.segments
                .last()
                .is_some_and(|segment| segment.ident == "DeserializeSeed")
        }) {
            self.deserialize_impls += 1;
            let only_value = item.items.iter().any(|item| matches!(item, syn::ImplItem::Type(item) if item.ident == "Value" && matches!(&item.ty, syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident("Value"))));
            if self.relative != "reporting/comparison/import.rs"
                || !matches!(&*item.self_ty, syn::Type::Path(path) if path.qself.is_none() && path.path.is_ident("ValueSeed"))
                || !only_value
            {
                self.reject("DeserializeSeed is reserved for the private display-only ValueSeed yielding JSON Value");
            }
        }
        syn::visit::visit_item_impl(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.inspect_path(path);
        syn::visit::visit_path(self, path);
    }
    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.inspect_identifier(&ident.to_string());
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if ![
            "format",
            "format_args",
            "write",
            "writeln",
            "matches",
            "vec",
        ]
        .iter()
        .any(|name| mac.path.is_ident(name))
        {
            self.reject("may invoke only fixed formatting and collection macros");
        }
        self.inspect_tokens(mac.tokens.clone());
    }
    fn visit_item_static(&mut self, _: &'ast syn::ItemStatic) {
        self.reject("cannot carry static mutable or ambient state");
    }
    fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) {
        self.reject("cannot use unsafe authority");
    }
    fn visit_item_extern_crate(&mut self, _: &'ast syn::ItemExternCrate) {
        self.reject("cannot introduce external crate aliases");
    }
    fn visit_item_foreign_mod(&mut self, _: &'ast syn::ItemForeignMod) {
        self.reject("cannot introduce foreign authority");
    }
}

fn collect_use_paths(tree: &UseTree, prefix: String, output: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            collect_use_paths(&path.tree, format!("{prefix}{}::", path.ident), output)
        },
        UseTree::Name(name) => output.push(format!("{prefix}{}", name.ident)),
        UseTree::Rename(rename) => {
            output.push(format!("{prefix}{} as {}", rename.ident, rename.rename))
        },
        UseTree::Glob(_) => output.push(format!("{prefix}*")),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix.clone(), output);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = include_str!("../../../crates/termivar-scanner/src/reporting/comparison.rs");
    const IMPORT: &str =
        include_str!("../../../crates/termivar-scanner/src/reporting/comparison/import.rs");
    const AUDITS: &str =
        include_str!("../../../crates/termivar-scanner/src/reporting/comparison/import/audits.rs");
    const HTML: &str =
        include_str!("../../../crates/termivar-scanner/src/reporting/comparison/html.rs");
    const MAIN: &str = include_str!("../../../crates/termivar-cli/src/main.rs");
    const CLI: &str = include_str!("../../../crates/termivar-cli/src/report_compare.rs");

    fn mutate(source: &str, from: &str, to: &str) -> String {
        assert!(source.contains(from), "stale mutation anchor: {from}");
        source.replacen(from, to, 1)
    }

    #[test]
    fn checked_in_comparison_boundary_is_accepted() {
        for (relative, source) in [
            ("reporting/comparison.rs", ROOT),
            ("reporting/comparison/import.rs", IMPORT),
            ("reporting/comparison/import/audits.rs", AUDITS),
            ("reporting/comparison/html.rs", HTML),
        ] {
            let violations = source_violations(relative, source).unwrap();
            assert!(violations.is_empty(), "{violations:#?}");
        }
        let violations = cli_violations(MAIN, CLI).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
        let violations = html_violations(HTML).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let violations = check(root).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
    }

    #[test]
    fn deserialization_cannot_become_an_authoritative_or_public_model() {
        for (from, to) in [
            ("struct ValueSeed {", "pub struct ValueSeed {"),
            ("struct ValueSeed {", "pub(crate) struct ValueSeed {"),
            ("depth: usize,", "depth: usize, authority: String,"),
            (
                "DeserializeSeed<'de> for ValueSeed",
                "DeserializeSeed<'de> for ImportedDocument",
            ),
            ("type Value = Value;", "type Value = EvidenceId;"),
            ("type Value = Value;", "type Value = ImportedDocument;"),
        ] {
            assert!(
                !source_violations("reporting/comparison/import.rs", &mutate(IMPORT, from, to))
                    .unwrap()
                    .is_empty(),
                "accepted {to}"
            );
        }
        for owner in [
            "ComparisonDocument",
            "SourceMetadata",
            "ComparisonItem",
            "ItemProjection",
            "RemediationProjection",
            "EvidenceMetadata",
        ] {
            let mutation = format!("{ROOT}\nimpl<'de> serde::Deserialize<'de> for {owner} {{}}");
            assert!(
                !source_violations("reporting/comparison.rs", &mutation)
                    .unwrap()
                    .is_empty(),
                "accepted {owner}"
            );
        }
        let mutation = mutate(
            ROOT,
            "#[derive(Debug, Serialize)]",
            "#[derive(Debug, Serialize, Deserialize)]",
        );
        assert!(!source_violations("reporting/comparison.rs", &mutation)
            .unwrap()
            .is_empty());
        for (from, to) in [
            ("before: &[u8]", "before: &str"),
            ("after: &[u8]", "after: &mut Vec<u8>"),
            (
                "format: ComparisonFormat,",
                "format: ComparisonFormat, authority: bool,",
            ),
        ] {
            assert!(
                !source_violations("reporting/comparison.rs", &mutate(ROOT, from, to))
                    .unwrap()
                    .is_empty(),
                "accepted signature {to}"
            );
        }
    }

    #[test]
    fn offline_cli_cannot_initialize_runtime_or_credentials() {
        for (from, to) in [
            (
                "let cli = Cli::parse();",
                "let cli = Cli::parse(); let runtime = tokio::runtime::Runtime::new()?;",
            ),
            ("fn main()", "#[tokio::main] async fn main()"),
            (
                "return report_compare::run(command).map_err(Into::into);",
                "return run_existing_command(Some(Commands::Report { command }));",
            ),
        ] {
            assert!(
                !cli_violations(&mutate(MAIN, from, to), CLI)
                    .unwrap()
                    .is_empty(),
                "accepted {to}"
            );
        }
        for addition in [
            "use termivar_scanner::web_runtime::WebAssessmentRunReport;",
            "use crate::auth_input::AuthorizationInputSource;",
            "fn load() { crate::auth_input::read_environment(\"x\"); }",
            "fn load() { crate::auth_input::AuthorizationInputError::SourceUnavailable; }",
            "fn run_network() { reqwest::get(\"http://127.0.0.1\"); }",
            "fn load() { std::env::var(\"x\"); }",
            "fn load() { std::fs::read(\"x\"); }",
            "async fn runtime() {}",
            "include!(\"hidden.rs\");",
        ] {
            assert!(
                !cli_violations(MAIN, &format!("{CLI}\n{addition}"))
                    .unwrap()
                    .is_empty(),
                "accepted {addition}"
            );
        }
    }

    #[test]
    fn html_script_exception_is_exact_and_csp_cannot_be_widened() {
        for (from, to) in [
            (
                "const SCRIPT: &str =",
                "const SCRIPT: &str = include_str!(\"program.js\"); const OTHER: &str =",
            ),
            ("controls.hidden=false;", "controls.innerHTML=search.value;"),
            ("controls.hidden=false;", "eval(search.value);"),
            ("connect-src 'none'", "connect-src *"),
            ("form-action 'none'", "form-action 'self'"),
            (
                "Sha256::digest(SCRIPT.as_bytes())",
                "Sha256::digest(STYLE.as_bytes())",
            ),
            (
                "output.push_str(SCRIPT)?;",
                "output.push_str(&document.schema)?;",
            ),
            (
                "</script></body></html>",
                "</script><script>unexpected()</script></body></html>",
            ),
        ] {
            assert!(
                !html_violations(&mutate(HTML, from, to)).unwrap().is_empty(),
                "accepted {to}"
            );
        }
    }

    #[test]
    fn comparison_rejects_ambient_authority_and_runtime_minting() {
        for addition in [
            "use std::fs::File;",
            "use std::net::TcpStream;",
            "use std::env::var;",
            "use std::process::Command;",
            "use reqwest::Client;",
            "use termivar_core::EvidenceId;",
            "use crate::web_runtime::AssessmentItem;",
            "use super::super::web_runtime::AssessmentItem;",
            "fn forged() { termivar_core::RunReport::new(); }",
            "fn read() { std::fs::read(\"x\"); }",
            "fn hidden() { format_args!(\"{}\", std::env::var(\"x\").unwrap()); }",
            "fn hidden() { format_args!(\"{:?}\", std::fs::read(\"x\")); }",
            "fn hidden() { format_args!(\"{:?}\", crate::helper()); }",
            "include!(\"hidden.rs\");",
            "#[path = \"hidden.rs\"] mod hidden;",
            "extern crate std as ambient;",
            "#[derive(Deserialize)] struct Wire { value: String }",
            "pub struct JsonValue(Value);",
        ] {
            let violations = source_violations("reporting/comparison/html.rs", addition).unwrap();
            assert!(!violations.is_empty(), "accepted {addition}");
        }
    }

    #[test]
    fn comparison_test_exemption_is_exact_and_not_a_production_escape() {
        assert!(source_violations(
            "reporting/comparison/html.rs",
            "#[cfg(test)] mod tests { use std::fs::File; }"
        )
        .unwrap()
        .is_empty());
        for source in [
            "mod tests { use std::fs::File; }",
            "#[cfg(any(test, unix))] mod tests { use std::fs::File; }",
            "#[cfg(test)] pub mod tests { use std::fs::File; }",
            "mod hidden;",
            "pub use super::ComparisonDocument;",
            "use std::fmt::*;",
        ] {
            assert!(
                !source_violations("reporting/comparison/html.rs", source)
                    .unwrap()
                    .is_empty(),
                "accepted {source}"
            );
        }
    }
}
