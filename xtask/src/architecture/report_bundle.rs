//! Exact CLI-owned boundary for one-assessment HTML/JSON report bundles.
//!
//! The bundle publisher may render one already-composed assessment and publish
//! bounded local files. It must not acquire scanner, credential, process, or
//! network authority, and `manifest.json` remains the sole completion marker.

use std::{collections::BTreeSet, error::Error, fs, path::Path};

use syn::{visit::Visit, Expr, ImplItem, Item, ItemFn, Lit, Type, UseTree, Visibility};

const CLI_MAIN_SOURCE: &str = "crates/termivar-cli/src/main.rs";
const ASSESSMENT_SCAN_SOURCE: &str = "crates/termivar-cli/src/assessment_scan.rs";
const REPORT_BUNDLE_SOURCE: &str = "crates/termivar-cli/src/report_bundle.rs";

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let main = fs::read_to_string(workspace_root.join(CLI_MAIN_SOURCE))?;
    let assessment_scan = fs::read_to_string(workspace_root.join(ASSESSMENT_SCAN_SOURCE))?;
    let bundle = fs::read_to_string(workspace_root.join(REPORT_BUNDLE_SOURCE))?;
    let mut violations = main_module_violations(&main)?;
    violations.extend(assessment_flow_violations(&assessment_scan)?);
    violations.extend(bundle_violations(&bundle)?);
    Ok(violations)
}

fn assessment_flow_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let functions: Vec<_> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "run_web_review" => Some(function),
            _ => None,
        })
        .collect();
    let Some(function) = functions.first() else {
        return Ok(vec![
            "web-review report bundle boundary must retain `run_web_review`".to_owned(),
        ]);
    };
    let mut visitor = AssessmentFlowVisitor::default();
    visitor.visit_block(&function.block);
    if functions.len() != 1
        || visitor.invalid
        || visitor.order != ["analyze", "compose", "bundle"]
        || visitor.analyze != 1
        || visitor.compose != 1
        || visitor.bundle != 1
    {
        Ok(vec![
            "completed web-review output must await one runtime analysis, compose one AssessmentRunReport, and delegate one bundle render from `&product`"
                .to_owned(),
        ])
    } else {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct AssessmentFlowVisitor {
    analyze: usize,
    compose: usize,
    bundle: usize,
    invalid: bool,
    order: Vec<&'static str>,
}

impl<'ast> Visit<'ast> for AssessmentFlowVisitor {
    fn visit_expr_await(&mut self, item: &'ast syn::ExprAwait) {
        match item.base.as_ref() {
            Expr::MethodCall(call) if call.method == "analyze" => {
                self.analyze += 1;
                self.order.push("analyze");
                if !expression_is_path(call.receiver.as_ref(), "runtime") || !call.args.is_empty() {
                    self.invalid = true;
                }
                return;
            },
            _ => {},
        }
        syn::visit::visit_expr_await(self, item);
    }

    fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
        if item.method == "analyze" {
            self.analyze += 1;
            self.order.push("analyze");
            self.invalid = true;
        }
        syn::visit::visit_expr_method_call(self, item);
    }

    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
        match expression_path(item.func.as_ref()).as_deref() {
            Some("ReportGenerator::compose_assessment") => {
                self.compose += 1;
                self.order.push("compose");
                if !call_arguments_are_paths(item, &["report", "profile"]) {
                    self.invalid = true;
                }
            },
            Some("report_bundle::render_report_bundle") => {
                self.bundle += 1;
                self.order.push("bundle");
                if item.args.len() != 1
                    || !item.args.first().is_some_and(|argument| {
                        matches!(argument, Expr::Reference(reference)
                            if reference.mutability.is_none()
                                && expression_is_path(reference.expr.as_ref(), "product"))
                    })
                {
                    self.invalid = true;
                }
            },
            _ => {},
        }
        syn::visit::visit_expr_call(self, item);
    }
}

fn render_wrapper_is_exact(function: &ItemFn) -> bool {
    let mut visitor = RenderWrapperVisitor::default();
    visitor.visit_block(&function.block);
    visitor.calls == 1 && !visitor.invalid
}

#[derive(Default)]
struct RenderWrapperVisitor {
    calls: usize,
    invalid: bool,
}

impl<'ast> Visit<'ast> for RenderWrapperVisitor {
    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
        if expression_path(item.func.as_ref()).as_deref() == Some("render_report_bundle_with") {
            self.calls += 1;
            if !call_arguments_are_paths(item, &["report", "existing_assessment_renderer"]) {
                self.invalid = true;
            }
        }
        syn::visit::visit_expr_call(self, item);
    }
}

fn existing_renderer_is_exact(function: &ItemFn) -> bool {
    let mut visitor = ExistingRendererVisitor::default();
    visitor.visit_block(&function.block);
    visitor.calls == 1 && !visitor.invalid
}

#[derive(Default)]
struct ExistingRendererVisitor {
    calls: usize,
    invalid: bool,
}

impl<'ast> Visit<'ast> for ExistingRendererVisitor {
    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
        if expression_path(item.func.as_ref()).as_deref()
            == Some("ReportGenerator::generate_assessment")
        {
            self.calls += 1;
            if !call_arguments_are_paths(item, &["report", "format"]) {
                self.invalid = true;
            }
        }
        syn::visit::visit_expr_call(self, item);
    }
}

fn dual_render_calls_are_exact(function: &ItemFn) -> bool {
    let mut visitor = DualRenderVisitor::default();
    visitor.visit_block(&function.block);
    visitor.formats == ["Html", "Json"] && !visitor.invalid
}

#[derive(Default)]
struct DualRenderVisitor {
    formats: Vec<String>,
    invalid: bool,
}

impl<'ast> Visit<'ast> for DualRenderVisitor {
    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
        if expression_path(item.func.as_ref()).as_deref() == Some("render") {
            let format = item.args.iter().nth(1).and_then(expression_path);
            if item.args.len() != 2
                || !item
                    .args
                    .first()
                    .is_some_and(|argument| expression_is_path(argument, "report"))
                || !matches!(
                    format.as_deref(),
                    Some("ReportFormat::Html" | "ReportFormat::Json")
                )
            {
                self.invalid = true;
            }
            if let Some(format) = format {
                self.formats
                    .push(format.rsplit("::").next().unwrap_or_default().to_owned());
            }
        }
        syn::visit::visit_expr_call(self, item);
    }
}

fn expression_path(expression: &Expr) -> Option<String> {
    let Expr::Path(path) = expression else {
        return None;
    };
    (path.qself.is_none()).then(|| {
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::")
    })
}

fn expression_is_path(expression: &Expr, name: &str) -> bool {
    matches!(expression, Expr::Path(path) if path.qself.is_none() && path.path.is_ident(name))
}

fn call_arguments_are_paths(call: &syn::ExprCall, names: &[&str]) -> bool {
    call.args.len() == names.len()
        && call
            .args
            .iter()
            .zip(names)
            .all(|(argument, name)| expression_is_path(argument, name))
}

fn main_module_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let modules: Vec<_> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(item) if item.ident == "report_bundle" => Some(item),
            _ => None,
        })
        .collect();
    if modules.len() == 1
        && matches!(modules[0].vis, Visibility::Inherited)
        && modules[0].attrs.is_empty()
        && modules[0].content.is_none()
    {
        Ok(Vec::new())
    } else {
        Ok(vec![
            "report bundle must remain one private, non-redirected CLI source module".to_owned(),
        ])
    }
}

fn bundle_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let compact = compact_source(source);
    let mut violations = Vec::new();

    for (name, expected) in [
        ("REPORT_BUNDLE_SCHEMA", "termivar-report-bundle/v1"),
        ("ASSESSMENT_HTML_NAME", "assessment.html"),
        ("ASSESSMENT_JSON_NAME", "assessment.json"),
        ("MANIFEST_NAME", "manifest.json"),
    ] {
        if string_constant(&syntax, name).as_deref() != Some(expected) {
            violations.push(format!(
                "report bundle constant `{name}` must remain the exact value `{expected}`"
            ));
        }
    }
    if integer_constant(&syntax, "MAX_MANIFEST_BYTES") != Some(64 * 1024) {
        violations.push("report bundle manifest ceiling must remain exactly 64 KiB".to_owned());
    }
    let aggregate = constant_identifiers(&syntax, "MAX_REPORT_BUNDLE_BYTES");
    if aggregate.is_none_or(|identifiers| {
        !identifiers.contains("MAX_RENDERED_REPORT_BYTES")
            || !identifiers.contains("MAX_MANIFEST_BYTES")
    }) || !compact.contains("checked_add")
    {
        violations.push(
            "report bundle aggregate bound must combine two existing report ceilings with the manifest ceiling using checked arithmetic"
                .to_owned(),
        );
    }

    for type_name in ["RenderedReportBundle", "ReportBundleReservation"] {
        let matching: Vec<_> = syntax
            .items
            .iter()
            .filter(|item| item_name(item).as_deref() == Some(type_name))
            .collect();
        if matching.len() != 1
            || matches!(item_visibility(matching[0]), Some(Visibility::Public(_)))
        {
            violations.push(format!(
                "report bundle type `{type_name}` must exist exactly once without becoming public API"
            ));
        }
    }

    let render = find_function(&syntax, "render_report_bundle");
    if render.is_none_or(|function| {
        matches!(function.vis, Visibility::Public(_))
            || function.sig.asyncness.is_some()
            || function.sig.unsafety.is_some()
            || function.sig.abi.is_some()
            || function.sig.inputs.len() != 1
            || !function
                .sig
                .inputs
                .first()
                .is_some_and(argument_is_shared_assessment_report)
    }) {
        violations.push(
            "report bundle rendering must remain one non-public safe synchronous pure function over `&AssessmentRunReport`"
                .to_owned(),
        );
    }
    let existing_renderer = find_function(&syntax, "existing_assessment_renderer");
    let render_with = find_function(&syntax, "render_report_bundle_with");
    if render.is_none_or(|function| !render_wrapper_is_exact(function))
        || existing_renderer.is_none_or(|function| !existing_renderer_is_exact(function))
        || render_with.is_none_or(|function| !dual_render_calls_are_exact(function))
    {
        violations.push(
            "report bundle must delegate to the existing ReportGenerator and render exactly HTML and JSON from the same borrowed assessment"
                .to_owned(),
        );
    }

    let reservation = find_function(&syntax, "reserve_report_bundle");
    if reservation.is_none_or(|function| {
        matches!(function.vis, Visibility::Public(_))
            || function.sig.asyncness.is_some()
            || function.sig.unsafety.is_some()
            || function.sig.abi.is_some()
    }) {
        violations.push(
            "report bundle reservation must remain a non-public safe synchronous CLI boundary"
                .to_owned(),
        );
    }

    let publish_inner = find_method(&syntax, "ReportBundleReservation", "publish_inner");
    let publish_file = find_method(&syntax, "ReportBundleReservation", "publish_file");
    if publish_inner.is_none_or(|function| !manifest_is_published_last(function))
        || publish_file.is_none_or(|function| !manifest_commit_is_explicit(function))
    {
        violations.push(
            "report bundle publication must publish assessment.html and assessment.json before manifest.json, then record the commit point"
                .to_owned(),
        );
    }

    let mut visitor = BundleVisitor::default();
    visitor.visit_file(&syntax);
    violations.extend(visitor.violations);

    for required in [
        "create_dir",
        "create_new(true)",
        "hard_link",
        "sync_all",
        "Handle::from_file",
        "Handle::from_path",
        "verify_owned_path",
        "Sha256",
    ] {
        if !compact.contains(required) {
            violations.push(format!(
                "report bundle publisher must retain required exclusive publication primitive `{required}`"
            ));
        }
    }
    for forbidden in ["include!", "include_str!", "include_bytes!", "option_env!"] {
        if compact.contains(forbidden) {
            violations.push(format!(
                "report bundle source contains forbidden authority or unsafe publication primitive `{forbidden}`"
            ));
        }
    }

    Ok(violations)
}

#[derive(Default)]
struct BundleVisitor {
    violations: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for BundleVisitor {
    fn visit_visibility(&mut self, _item: &'ast Visibility) {
        // `pub(crate)` is the intended sibling-module boundary. The `crate`
        // token here is not an executable path and must not be mistaken for a
        // dependency on another CLI authority module.
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.ident == "tests"
            && matches!(item.vis, Visibility::Inherited)
            && item.content.is_some()
            && item.attrs.len() == 1
            && matches!(&item.attrs[0].meta, syn::Meta::List(meta)
                if meta.path.is_ident("cfg") && meta.tokens.to_string() == "test")
        {
            return;
        }
        self.violations.insert(format!(
            "report bundle source cannot delegate publication authority to module `{}`",
            item.ident
        ));
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        let derives = derive_names(&item.attrs);
        if derives.contains("Deserialize") {
            self.violations.insert(
                "report bundle source must not deserialize or re-import authoritative reports"
                    .to_owned(),
            );
        }
        if derives.contains("Serialize")
            && (!item.ident.to_string().contains("Manifest")
                || item
                    .fields
                    .iter()
                    .any(|field| !matches!(field.vis, Visibility::Inherited)))
        {
            self.violations.insert(
                "only private manifest projection structs with private fields may derive Serialize"
                    .to_owned(),
            );
        }
        syn::visit::visit_item_struct(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let joined = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let forbidden = [
            "crate",
            "std::env",
            "std::net",
            "std::process",
            "std::thread",
            "std::time",
            "axum",
            "getrandom",
            "hyper",
            "rand",
            "reqwest",
            "termivar_api",
            "termivar_core",
            "termivar_oast",
            "termivar_proxy",
            "tokio",
            "url",
            "uuid",
        ];
        if forbidden
            .iter()
            .any(|prefix| joined == *prefix || joined.starts_with(&format!("{prefix}::")))
        {
            self.violations.insert(
                "report bundle publisher cannot initialize scanner, credential, process, clock, or network authority"
                    .to_owned(),
            );
        }
        if joined.starts_with("termivar_scanner::")
            && ![
                "termivar_scanner::web_runtime::AssessmentRunReport",
                "termivar_scanner::ReportFormat",
                "termivar_scanner::ReportGenerator",
                "termivar_scanner::MAX_RENDERED_REPORT_BYTES",
            ]
            .contains(&joined.as_str())
        {
            self.violations.insert(
                "report bundle source may reference only the read-only assessment report and existing renderer surface"
                    .to_owned(),
                );
        }
        if joined.starts_with("serde_json::from_") {
            self.violations.insert(
                "report bundle source must not deserialize or re-import authoritative reports"
                    .to_owned(),
            );
        }
        if path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.to_string().starts_with("Deserialize"))
        {
            self.violations.insert(
                "report bundle source must not deserialize or re-import authoritative reports"
                    .to_owned(),
            );
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, String::new(), &mut paths);
        for path in paths {
            let allowed = path.starts_with("std::")
                || path == "serde::Serialize"
                || path == "same_file::Handle"
                || path == "sha2::Digest"
                || path == "sha2::Sha256"
                || [
                    "termivar_scanner::web_runtime::AssessmentRunReport",
                    "termivar_scanner::ReportFormat",
                    "termivar_scanner::ReportGenerator",
                    "termivar_scanner::MAX_RENDERED_REPORT_BYTES",
                ]
                .contains(&path.as_str());
            if !allowed {
                self.violations.insert(
                    "report bundle imports must remain the exact local publication, hashing, serialization, and read-only assessment projection surface"
                        .to_owned(),
                );
            }
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if item.sig.unsafety.is_some() || item.sig.asyncness.is_some() || item.sig.abi.is_some() {
            self.violations.insert(
                "report bundle functions must remain safe and synchronous local composition"
                    .to_owned(),
            );
        }
        syn::visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if item.sig.unsafety.is_some() || item.sig.asyncness.is_some() || item.sig.abi.is_some() {
            self.violations.insert(
                "report bundle methods must remain safe and synchronous local publication"
                    .to_owned(),
            );
        }
        syn::visit::visit_impl_item_fn(self, item);
    }

    fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
        if item.method == "exists" || item.method == "try_exists" {
            self.violations.insert(
                "report bundle reservation cannot use a non-exclusive existence preflight"
                    .to_owned(),
            );
        }
        syn::visit::visit_expr_method_call(self, item);
    }

    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
        if let Expr::Path(path) = item.func.as_ref() {
            let segments = path.path.segments.iter().collect::<Vec<_>>();
            let is_fs_call = segments
                .iter()
                .rev()
                .nth(1)
                .is_some_and(|segment| segment.ident == "fs");
            let forbidden = segments.last().is_some_and(|segment| {
                ["copy", "create_dir_all", "remove_dir_all", "rename"]
                    .iter()
                    .any(|name| segment.ident == *name)
            });
            if is_fs_call && forbidden {
                self.violations.insert(
                    "report bundle source cannot use copy, recursive directory mutation, or replace-capable rename publication"
                        .to_owned(),
                );
            }
        }
        syn::visit::visit_expr_call(self, item);
    }

    fn visit_expr_unsafe(&mut self, item: &'ast syn::ExprUnsafe) {
        self.violations
            .insert("report bundle source must not contain unsafe blocks".to_owned());
        syn::visit::visit_expr_unsafe(self, item);
    }
}

fn string_constant(syntax: &syn::File, name: &str) -> Option<String> {
    syntax.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == name => match item.expr.as_ref() {
            Expr::Lit(literal) => match &literal.lit {
                Lit::Str(value) => Some(value.value()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    })
}

fn integer_constant(syntax: &syn::File, name: &str) -> Option<usize> {
    syntax.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == name => evaluate_usize(item.expr.as_ref()),
        _ => None,
    })
}

fn evaluate_usize(expression: &Expr) -> Option<usize> {
    match expression {
        Expr::Lit(literal) => match &literal.lit {
            Lit::Int(value) => value.base10_parse().ok(),
            _ => None,
        },
        Expr::Binary(binary) => {
            let left = evaluate_usize(binary.left.as_ref())?;
            let right = evaluate_usize(binary.right.as_ref())?;
            match binary.op {
                syn::BinOp::Add(_) => left.checked_add(right),
                syn::BinOp::Mul(_) => left.checked_mul(right),
                _ => None,
            }
        },
        _ => None,
    }
}

fn constant_identifiers(syntax: &syn::File, name: &str) -> Option<BTreeSet<String>> {
    syntax.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == name => {
            let mut visitor = IdentifierSetVisitor::default();
            visitor.visit_expr(item.expr.as_ref());
            Some(visitor.identifiers)
        },
        _ => None,
    })
}

fn find_function<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a ItemFn> {
    syntax.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    })
}

fn find_method<'a>(syntax: &'a syn::File, owner: &str, name: &str) -> Option<&'a syn::ImplItemFn> {
    syntax.items.iter().find_map(|item| match item {
        Item::Impl(item) if type_name(item.self_ty.as_ref()).as_deref() == Some(owner) => item
            .items
            .iter()
            .find_map(|implementation| match implementation {
                ImplItem::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            }),
        _ => None,
    })
}

fn manifest_is_published_last(function: &syn::ImplItemFn) -> bool {
    let mut visitor = IdentifierOrderVisitor::default();
    visitor.visit_block(&function.block);
    let Some(html) = visitor
        .identifiers
        .iter()
        .rposition(|identifier| identifier == "ASSESSMENT_HTML_NAME")
    else {
        return false;
    };
    let Some(json) = visitor
        .identifiers
        .iter()
        .rposition(|identifier| identifier == "ASSESSMENT_JSON_NAME")
    else {
        return false;
    };
    let Some(manifest) = visitor
        .identifiers
        .iter()
        .rposition(|identifier| identifier == "MANIFEST_NAME")
    else {
        return false;
    };
    html < json && json < manifest
}

fn manifest_commit_is_explicit(function: &syn::ImplItemFn) -> bool {
    let mut visitor = IdentifierOrderVisitor::default();
    visitor.visit_block(&function.block);
    let Some(link) = visitor
        .identifiers
        .iter()
        .position(|identifier| identifier == "hard_link")
    else {
        return false;
    };
    let Some(manifest) = visitor
        .identifiers
        .iter()
        .position(|identifier| identifier == "Manifest")
    else {
        return false;
    };
    let Some(committed) = visitor
        .identifiers
        .iter()
        .position(|identifier| identifier == "committed")
    else {
        return false;
    };
    let Some(cleanup) = visitor
        .identifiers
        .iter()
        .position(|identifier| identifier == "cleanup_stage")
    else {
        return false;
    };
    let Some(post_link_verification) =
        visitor
            .identifiers
            .iter()
            .enumerate()
            .find_map(|(index, identifier)| {
                (index > link && identifier == "verify_owned_path").then_some(index)
            })
    else {
        return false;
    };
    link < manifest
        && manifest < committed
        && committed < post_link_verification
        && post_link_verification < cleanup
}

fn argument_is_shared_assessment_report(argument: &syn::FnArg) -> bool {
    let syn::FnArg::Typed(argument) = argument else {
        return false;
    };
    matches!(argument.ty.as_ref(), Type::Reference(reference)
        if reference.mutability.is_none()
            && matches!(reference.elem.as_ref(), Type::Path(path)
                if path.qself.is_none()
                    && path.path.segments.last().is_some_and(|segment| segment.ident == "AssessmentRunReport")))
}

fn item_name(item: &Item) -> Option<String> {
    match item {
        Item::Struct(item) => Some(item.ident.to_string()),
        Item::Enum(item) => Some(item.ident.to_string()),
        _ => None,
    }
}

fn item_visibility(item: &Item) -> Option<&Visibility> {
    match item {
        Item::Struct(item) => Some(&item.vis),
        Item::Enum(item) => Some(&item.vis),
        _ => None,
    }
}

fn type_name(item_type: &Type) -> Option<String> {
    match item_type {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

#[derive(Default)]
struct IdentifierSetVisitor {
    identifiers: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for IdentifierSetVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.identifiers.extend(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string()),
        );
        syn::visit::visit_path(self, path);
    }
}

#[derive(Default)]
struct IdentifierOrderVisitor {
    identifiers: Vec<String>,
}

impl<'ast> Visit<'ast> for IdentifierOrderVisitor {
    fn visit_expr_method_call(&mut self, item: &'ast syn::ExprMethodCall) {
        self.identifiers.push(item.method.to_string());
        syn::visit::visit_expr_method_call(self, item);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.identifiers.extend(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string()),
        );
        syn::visit::visit_path(self, path);
    }

    fn visit_member(&mut self, member: &'ast syn::Member) {
        if let syn::Member::Named(identifier) = member {
            self.identifiers.push(identifier.to_string());
        }
        syn::visit::visit_member(self, member);
    }
}

fn derive_names(attributes: &[syn::Attribute]) -> BTreeSet<String> {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("derive"))
        .flat_map(|attribute| {
            attribute
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .unwrap_or_default()
        })
        .filter_map(|path| {
            path.segments
                .last()
                .map(|segment| segment.ident.to_string())
        })
        .collect()
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

fn compact_source(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKED_IN_MAIN: &str = include_str!("../../../crates/termivar-cli/src/main.rs");
    const CHECKED_IN_ASSESSMENT_SCAN: &str =
        include_str!("../../../crates/termivar-cli/src/assessment_scan.rs");
    const CHECKED_IN_BUNDLE: &str =
        include_str!("../../../crates/termivar-cli/src/report_bundle.rs");

    const VALID_ASSESSMENT_FLOW: &str = r#"
        async fn run_web_review() {
            let report = runtime.analyze().await;
            let product = ReportGenerator::compose_assessment(report, profile);
            let bundle = report_bundle::render_report_bundle(&product);
        }
    "#;

    const VALID: &str = r#"
        use same_file::Handle;
        use sha2::{Digest, Sha256};
        use std::{fs, path::{Path, PathBuf}};
        use termivar_scanner::{
            web_runtime::AssessmentRunReport, ReportFormat, ReportGenerator,
            MAX_RENDERED_REPORT_BYTES,
        };
        const REPORT_BUNDLE_SCHEMA: &str = "termivar-report-bundle/v1";
        const ASSESSMENT_HTML_NAME: &str = "assessment.html";
        const ASSESSMENT_JSON_NAME: &str = "assessment.json";
        const MANIFEST_NAME: &str = "manifest.json";
        const MAX_MANIFEST_BYTES: usize = 64 * 1024;
        const MAX_REPORT_BUNDLE_BYTES: usize = MAX_RENDERED_REPORT_BYTES * 2 + MAX_MANIFEST_BYTES;
        struct RenderedReportBundle;
        struct ReportBundleReservation { committed: bool }
        #[derive(serde::Serialize)]
        struct BundleManifest { schema: &'static str }
        fn render_report_bundle(report: &AssessmentRunReport) -> Result<RenderedReportBundle, ()> {
            render_report_bundle_with(report, existing_assessment_renderer)
        }
        fn existing_assessment_renderer(
            report: &AssessmentRunReport,
            format: ReportFormat,
        ) -> Result<String, ()> {
            ReportGenerator::generate_assessment(report, format)
        }
        fn render_report_bundle_with(
            report: &AssessmentRunReport,
            render: fn(&AssessmentRunReport, ReportFormat) -> Result<String, ()>,
        ) -> Result<RenderedReportBundle, ()> {
            let _html = render(report, ReportFormat::Html);
            let _json = render(report, ReportFormat::Json);
            let _ = 1usize.checked_add(1);
            let _ = Sha256::new();
            Ok(RenderedReportBundle)
        }
        fn reserve_report_bundle(_: Option<&Path>) -> Result<Option<ReportBundleReservation>, ()> {
            let _ = fs::create_dir("x");
            let _ = fs::OpenOptions::new().create_new(true);
            let _ = fs::hard_link("x", "y");
            let _ = fs::File::open("x").and_then(|file| file.sync_all());
            let _ = fs::File::open("x").and_then(Handle::from_file);
            let _ = Handle::from_path(PathBuf::from("x"));
            Ok(None)
        }
        impl ReportBundleReservation {
            fn verify_owned_path(&self) {}
            fn publish_inner(&mut self) {
                let _ = ASSESSMENT_HTML_NAME;
                let _ = ASSESSMENT_JSON_NAME;
                let _ = MANIFEST_NAME;
            }
            fn publish_file(&mut self, cleanup_stage: ()) {
                let _ = fs::hard_link("x", "y");
                let _ = FileKind::Manifest;
                self.committed = true;
                self.verify_owned_path();
                let _ = cleanup_stage;
            }
        }
        enum FileKind { Manifest }
    "#;

    #[test]
    fn exact_bundle_boundary_accepts_reviewed_shape() {
        assert!(bundle_violations(VALID).unwrap().is_empty());
    }

    #[test]
    fn checked_in_bundle_boundary_is_accepted() {
        let mut violations = main_module_violations(CHECKED_IN_MAIN).unwrap();
        violations.extend(assessment_flow_violations(CHECKED_IN_ASSESSMENT_SCAN).unwrap());
        violations.extend(bundle_violations(CHECKED_IN_BUNDLE).unwrap());
        assert!(violations.is_empty(), "{violations:#?}");
    }

    #[test]
    fn unsafe_publication_and_authority_mutations_fail_closed() {
        for (from, to) in [
            ("fs::create_dir(\"x\")", "fs::create_dir_all(\"x\")"),
            ("fs::hard_link(\"x\", \"y\")", "fs::rename(\"x\", \"y\")"),
            (
                "let _ = MANIFEST_NAME;",
                "let _ = MANIFEST_NAME; let _ = ASSESSMENT_HTML_NAME;",
            ),
            (
                "use sha2::{Digest, Sha256};",
                "use sha2::{Digest, Sha256}; use reqwest::Client;",
            ),
            (
                "#[derive(serde::Serialize)]",
                "#[derive(serde::Serialize, serde::Deserialize)]",
            ),
            (
                "let _json = render(report, ReportFormat::Json)",
                "let _json = render(report, ReportFormat::Html)",
            ),
            (
                "render_report_bundle_with(report, existing_assessment_renderer)",
                "render_report_bundle_with(report, replacement_renderer)",
            ),
            (
                "self.committed = true;\n                self.verify_owned_path();",
                "self.verify_owned_path();\n                self.committed = true;",
            ),
        ] {
            let changed = VALID.replacen(from, to, 1);
            assert_ne!(changed, VALID, "mutation anchor missing: {from}");
            assert!(
                !bundle_violations(&changed).unwrap().is_empty(),
                "accepted {to}"
            );
        }
    }

    #[test]
    fn exact_negative_bundle_boundaries_are_mutation_locked() {
        for (from, to, expected) in [
            (
                "const REPORT_BUNDLE_SCHEMA: &str = \"termivar-report-bundle/v1\";",
                "const REPORT_BUNDLE_SCHEMA: &str = \"termivar-report-bundle/v2\";",
                "constant `REPORT_BUNDLE_SCHEMA`",
            ),
            (
                "const MAX_MANIFEST_BYTES: usize = 64 * 1024;",
                "const MAX_MANIFEST_BYTES: usize = 32 * 1024;",
                "manifest ceiling",
            ),
            (
                "let _ = 1usize.checked_add(1);",
                "let _ = 1usize.saturating_add(1);",
                "aggregate bound",
            ),
            (
                "struct RenderedReportBundle;",
                "pub struct RenderedReportBundle;",
                "without becoming public API",
            ),
            (
                "fn render_report_bundle(report: &AssessmentRunReport)",
                "pub fn render_report_bundle(report: &AssessmentRunReport)",
                "non-public safe synchronous pure function",
            ),
            (
                "fn reserve_report_bundle(_: Option<&Path>)",
                "pub fn reserve_report_bundle(_: Option<&Path>)",
                "non-public safe synchronous CLI boundary",
            ),
            (
                "let _ = fs::create_dir(\"x\");",
                "let _ = fs::remove_dir(\"x\");",
                "required exclusive publication primitive `create_dir`",
            ),
            (
                "let _ = Sha256::new();",
                "let _ = Sha256::new(); let _ = include_str!(\"forbidden\");",
                "forbidden authority or unsafe publication primitive `include_str!`",
            ),
            (
                "enum FileKind { Manifest }",
                "mod delegated {} enum FileKind { Manifest }",
                "cannot delegate publication authority",
            ),
            (
                "struct BundleManifest { schema: &'static str }",
                "struct BundleManifest { pub schema: &'static str }",
                "only private manifest projection structs with private fields",
            ),
            (
                "let _html = render(report, ReportFormat::Html);",
                "let _html = render(report, ReportFormat::Html); let _ = termivar_scanner::WebAssessmentRuntime;",
                "may reference only the read-only assessment report",
            ),
            (
                "fn existing_assessment_renderer(",
                "async fn existing_assessment_renderer(",
                "functions must remain safe and synchronous",
            ),
            (
                "fn verify_owned_path(&self) {}",
                "async fn verify_owned_path(&self) {}",
                "methods must remain safe and synchronous",
            ),
            (
                "let _ = fs::create_dir(\"x\");",
                "let _ = fs::create_dir(\"x\"); let _ = Path::new(\"x\").exists();",
                "cannot use a non-exclusive existence preflight",
            ),
            (
                "let _ = fs::create_dir(\"x\");",
                "let _ = fs::create_dir(\"x\"); let _ = unsafe { 1 };",
                "must not contain unsafe blocks",
            ),
        ] {
            let changed = VALID.replacen(from, to, 1);
            assert_ne!(changed, VALID, "mutation anchor missing: {from}");
            let violations = bundle_violations(&changed).unwrap();
            assert!(
                violations.iter().any(|violation| violation.contains(expected)),
                "mutation `{to}` did not produce `{expected}`: {violations:#?}"
            );
        }
    }

    #[test]
    fn single_analysis_composition_and_bundle_delegation_are_mutation_locked() {
        assert!(assessment_flow_violations(VALID_ASSESSMENT_FLOW)
            .unwrap()
            .is_empty());
        for (from, to) in [
            (
                "let report = runtime.analyze().await;",
                "let report = runtime.analyze().await; let _duplicate = runtime.analyze().await;",
            ),
            (
                "let report = runtime.analyze().await;",
                "let _pending = runtime.analyze(); let report = runtime.analyze().await;",
            ),
            (
                "ReportGenerator::compose_assessment(report, profile)",
                "ReportGenerator::compose_assessment(report, other_profile)",
            ),
            (
                "report_bundle::render_report_bundle(&product)",
                "report_bundle::render_report_bundle(&report)",
            ),
            (
                "let bundle = report_bundle::render_report_bundle(&product);",
                "let bundle = report_bundle::render_report_bundle(&product); let _duplicate = report_bundle::render_report_bundle(&product);",
            ),
        ] {
            let changed = VALID_ASSESSMENT_FLOW.replacen(from, to, 1);
            assert_ne!(changed, VALID_ASSESSMENT_FLOW, "mutation anchor missing: {from}");
            assert!(
                !assessment_flow_violations(&changed).unwrap().is_empty(),
                "accepted {to}"
            );
        }
    }

    #[test]
    fn main_module_must_be_one_private_direct_source() {
        assert!(main_module_violations("mod report_bundle;")
            .unwrap()
            .is_empty());
        for source in [
            "pub mod report_bundle;",
            "#[path = \"elsewhere.rs\"] mod report_bundle;",
            "mod report_bundle {}",
            "mod report_bundle; mod report_bundle;",
        ] {
            assert!(!main_module_violations(source).unwrap().is_empty());
        }
    }
}
