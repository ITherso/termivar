//! Exact boundary for offline, read-only report-bundle verification.
//!
//! Verification may inspect only the three fixed bundle files and may import
//! only a private-field display summary. It owns no runtime, network, provider,
//! credential, repair, or filesystem-mutation authority.

use std::{collections::BTreeSet, error::Error, fs, path::Path};

use proc_macro2::{TokenStream, TokenTree};
use syn::{visit::Visit, Expr, Item, Type, UseTree, Visibility};

const VERIFIER_SOURCE: &str = "crates/termivar-cli/src/report_verify.rs";
const COMPARISON_CLI_SOURCE: &str = "crates/termivar-cli/src/report_compare.rs";

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let verifier = fs::read_to_string(workspace_root.join(VERIFIER_SOURCE))?;
    let comparison = fs::read_to_string(workspace_root.join(COMPARISON_CLI_SOURCE))?;
    let mut violations = verifier_violations(&verifier)?;
    violations.extend(dispatch_violations(&comparison)?);
    Ok(violations)
}

fn verifier_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = BTreeSet::new();

    let actual_uses = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Use(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| {
            let mut paths = Vec::new();
            collect_use_paths(&item.tree, String::new(), &mut paths);
            paths
        })
        .collect::<BTreeSet<_>>();
    let expected_uses = [
        "clap::Args",
        "clap::ValueEnum",
        "crate::report_bundle::ASSESSMENT_HTML_NAME",
        "crate::report_bundle::ASSESSMENT_JSON_NAME",
        "crate::report_bundle::MANIFEST_NAME",
        "crate::report_bundle::MAX_MANIFEST_BYTES",
        "crate::report_bundle::REPORT_BUNDLE_SCHEMA",
        "same_file::Handle",
        "semver::Version",
        "serde::Deserialize",
        "serde::Serialize",
        "sha2::Digest",
        "sha2::Sha256",
        "std::collections::BTreeSet",
        "std::fmt",
        "std::fs::File",
        "std::fs::OpenOptions",
        "std::fs::self",
        "std::io::Read",
        "std::io::Write",
        "std::io::self",
        "std::path::Path",
        "std::path::PathBuf",
        "std::process::ExitCode",
        "termivar_scanner::reporting::comparison::ComparisonError",
        "termivar_scanner::reporting::comparison::MAX_COMPARISON_INPUT_BYTES",
        "termivar_scanner::reporting::comparison::import_assessment_summary",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if actual_uses != expected_uses {
        violations.insert(
            "report verifier imports must remain the exact offline file, manifest, hash, and display-summary surface"
                .to_owned(),
        );
    }

    let crate_visible = syntax
        .items
        .iter()
        .filter_map(crate_visible_item_name)
        .collect::<BTreeSet<_>>();
    let expected_crate_visible = ["ReportVerifyArgs", "ReportVerifyError", "run"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if crate_visible != expected_crate_visible {
        violations.insert(
            "report verifier crate API must remain exactly ReportVerifyArgs, ReportVerifyError, and synchronous run"
                .to_owned(),
        );
    }
    if syntax.items.iter().any(is_public_item) {
        violations.insert("report verifier cannot expose a public API".to_owned());
    }

    pin_cli_contract(source, &syntax, &mut violations);
    pin_wire_and_result_models(&syntax, &mut violations);
    pin_constants(source, &syntax, &mut violations);
    pin_verification_sequence(source, &mut violations);

    let mut visitor = VerifierVisitor::default();
    visitor.visit_file(&syntax);
    violations.extend(visitor.violations);
    let expected_joins = [
        "\",\"",
        "ASSESSMENT_HTML_NAME",
        "ASSESSMENT_JSON_NAME",
        "MANIFEST_NAME",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    if visitor.join_arguments != expected_joins {
        violations.insert(
            "report verifier may join only the three fixed bundle filenames and the fixed reason-code delimiter"
                .to_owned(),
        );
    }

    Ok(violations.into_iter().collect())
}

fn pin_cli_contract(source: &str, syntax: &syn::File, violations: &mut BTreeSet<String>) {
    let args = find_struct(syntax, "ReportVerifyArgs");
    let expected_fields = [
        ("directory", "PathBuf"),
        ("format", "CliVerificationFormat"),
    ];
    if args.is_none_or(|item| {
        !matches_exact_fields(&item.fields, &expected_fields)
            || !has_exact_non_doc_attributes(&item.attrs, &["derive:Args"])
    }) {
        violations.insert(
            "ReportVerifyArgs must remain the exact private --dir plus text/json format payload"
                .to_owned(),
        );
    } else if let Some(item) = args {
        let syn::Fields::Named(fields) = &item.fields else {
            unreachable!("matches_exact_fields already rejected non-named fields")
        };
        let directory_attrs = non_doc_attribute_shapes(&fields.named[0].attrs);
        let format_attrs = non_doc_attribute_shapes(&fields.named[1].attrs);
        if directory_attrs != ["arg:long = \"dir\" , value_name = \"DIRECTORY\""].as_slice()
            || format_attrs
                != ["arg:long , value_enum , default_value_t = CliVerificationFormat :: Text"]
                    .as_slice()
        {
            violations.insert(
                "report verify CLI must require --dir and support only default text or explicit json"
                    .to_owned(),
            );
        }
    }

    if !enum_variants_are(syntax, "CliVerificationFormat", &["Text", "Json"])
        || find_enum(syntax, "CliVerificationFormat").is_none_or(|item| {
            !matches!(item.vis, Visibility::Inherited)
                || !has_exact_non_doc_attributes(
                    &item.attrs,
                    &[
                        "derive:Clone , Copy , Debug , PartialEq , Eq , ValueEnum",
                        "value:rename_all = \"lowercase\"",
                    ],
                )
        })
    {
        violations.insert("report verify format must remain the private text/json enum".to_owned());
    }

    let expected = "fn run(args: ReportVerifyArgs) -> Result<ExitCode, ReportVerifyError> {}";
    if function_signature_tokens(source, "run") != function_signature_tokens(expected, "run") {
        violations.insert(
            "report verifier run must remain synchronous and return only ExitCode or bounded output error"
                .to_owned(),
        );
    }
    let expected_run = r#"fn run(args: ReportVerifyArgs) -> Result<ExitCode, ReportVerifyError> {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        run_with_writer(args, &mut output)
    }"#;
    if function_tokens(source, "run") != function_tokens(expected_run, "run") {
        violations.insert(
            "report verifier run must write only through its bounded stdout writer seam".to_owned(),
        );
    }
    let expected_writer = "fn run_with_writer(args: ReportVerifyArgs, output: &mut impl Write,) -> Result<ExitCode, ReportVerifyError> {}";
    if function_signature_tokens(source, "run_with_writer")
        != function_signature_tokens(expected_writer, "run_with_writer")
    {
        violations.insert(
            "report verifier output seam must remain private, synchronous, and write-only"
                .to_owned(),
        );
    }
}

fn pin_wire_and_result_models(syntax: &syn::File, violations: &mut BTreeSet<String>) {
    for (name, fields) in [
        (
            "ManifestWire",
            [
                ("schema", "String"),
                ("producer", "ManifestProducerWire"),
                ("assessment", "ManifestAssessmentWire"),
                ("files", "[ManifestFileWire;2]"),
            ]
            .as_slice(),
        ),
        (
            "ManifestProducerWire",
            [("product", "String"), ("version", "String")].as_slice(),
        ),
        (
            "ManifestAssessmentWire",
            [
                ("profile", "String"),
                ("status", "String"),
                ("subject_count", "u64"),
                ("item_count", "u64"),
            ]
            .as_slice(),
        ),
        (
            "ManifestFileWire",
            [
                ("name", "String"),
                ("format", "String"),
                ("media_type", "String"),
                ("byte_length", "u64"),
                ("sha256", "String"),
            ]
            .as_slice(),
        ),
    ] {
        if find_struct(syntax, name).is_none_or(|item| {
            !matches!(item.vis, Visibility::Inherited)
                || !matches_exact_fields(&item.fields, fields)
                || !has_exact_non_doc_attributes(
                    &item.attrs,
                    &["derive:Deserialize", "serde:deny_unknown_fields"],
                )
        }) {
            violations.insert(format!(
                "{name} must remain the exact private deny-unknown-fields manifest wire model"
            ));
        }
    }

    for name in [
        "VerificationResult",
        "ManifestResult",
        "VerificationChecks",
        "FileCheck",
        "TrustLimits",
    ] {
        if find_struct(syntax, name).is_none_or(|item| {
            !matches!(item.vis, Visibility::Inherited)
                || item
                    .fields
                    .iter()
                    .any(|field| !matches!(field.vis, Visibility::Inherited))
                || !non_doc_attribute_shapes(&item.attrs)
                    .iter()
                    .any(|shape| shape.starts_with("derive:") && shape.contains("Serialize"))
                || non_doc_attribute_shapes(&item.attrs)
                    .iter()
                    .any(|shape| shape.contains("Deserialize"))
        }) {
            violations.insert(format!(
                "{name} must remain a private serialize-only verification projection"
            ));
        }
    }
}

fn pin_constants(source: &str, syntax: &syn::File, violations: &mut BTreeSet<String>) {
    for (name, expected) in [
        ("VERIFICATION_SCHEMA", "termivar-report-verification/v1"),
        ("EXPECTED_PRODUCT", "Termivar"),
        ("EXPECTED_PROFILE", "web-review"),
        ("EXPECTED_STATUS", "complete"),
    ] {
        if string_constant(syntax, name).as_deref() != Some(expected) {
            violations.insert(format!("report verifier must pin exact {name}"));
        }
    }
    for (name, expected) in [
        ("MAX_VERIFICATION_OUTPUT_BYTES", 64 * 1024),
        ("MAX_VERSION_BYTES", 128),
        ("MAX_SUBJECT_COUNT", 1024),
        ("MAX_ITEM_COUNT", 4096),
    ] {
        if integer_constant(syntax, name) != Some(expected) {
            violations.insert(format!("report verifier must pin exact bounded {name}"));
        }
    }

    let production_source = source
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source);
    for required in [
        "not_established",
        "not_evaluated",
        "producer/source authenticity: not established",
        "HTML equivalence or executable safety: not established",
        "original scan scope, findings, and remediation: not evaluated",
        "later filesystem state: not established; result describes bytes read during this invocation",
    ] {
        if !production_source.contains(required) {
            violations.insert(format!(
                "report verifier must preserve explicit authenticity, HTML, scan, remediation, and snapshot trust limits: missing `{required}`"
            ));
        }
    }
}

fn pin_verification_sequence(source: &str, violations: &mut BTreeSet<String>) {
    let required = [
        (
            "inspect_layout",
            &[
                "read_dir",
                "count",
                "3",
                "is_file",
                "MANIFEST_NAME",
                "ASSESSMENT_HTML_NAME",
                "ASSESSMENT_JSON_NAME",
            ] as &[&str],
        ),
        (
            "parse_manifest",
            &[
                "MAX_MANIFEST_BYTES",
                "REPORT_BUNDLE_SCHEMA",
                "EXPECTED_PRODUCT",
                "Version",
                "EXPECTED_PROFILE",
                "EXPECTED_STATUS",
                "MAX_SUBJECT_COUNT",
                "MAX_ITEM_COUNT",
                "ASSESSMENT_HTML_NAME",
                "ASSESSMENT_JSON_NAME",
                "MAX_COMPARISON_INPUT_BYTES",
                "is_lowercase_sha256",
            ],
        ),
        (
            "verify_directory_with",
            &[
                "validate_local_path",
                "open_directory",
                "inspect_layout",
                "capture_regular_file",
                "parse_manifest",
                "verify_html",
                "verify_json_payload",
                "import_assessment_summary",
                "finish_with_final_layout",
            ],
        ),
    ];
    for (function, identifiers) in required {
        let Some(tokens) = function_tokens(source, function) else {
            violations.insert(format!("report verifier is missing {function}"));
            continue;
        };
        if !identifiers_appear_in_order(&tokens, identifiers) {
            violations.insert(format!(
                "report verifier {function} must preserve the exact bounded read-only verification sequence"
            ));
        }
    }
}

fn dispatch_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    let variants = syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == "ReportCommands" => Some(
            item.variants
                .iter()
                .map(|variant| {
                    let ty = match &variant.fields {
                        syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                            type_shape(&fields.unnamed[0].ty)
                        },
                        _ => String::new(),
                    };
                    (variant.ident.to_string(), ty)
                })
                .collect::<Vec<_>>(),
        ),
        _ => None,
    });
    if variants
        != Some(vec![
            ("Compare".to_owned(), "ReportCompareArgs".to_owned()),
            (
                "Verify".to_owned(),
                "crate::report_verify::ReportVerifyArgs".to_owned(),
            ),
        ])
    {
        violations.push(
            "report command must expose exactly compare and offline verify payloads".to_owned(),
        );
    }
    let expected = r#"fn run(command: ReportCommands) -> Result<ExitCode, Box<dyn Error>> {
        match command {
            ReportCommands::Compare(args) => {
                run_compare(args)?;
                Ok(ExitCode::SUCCESS)
            },
            ReportCommands::Verify(args) => crate::report_verify::run(args).map_err(Into::into),
        }
    }"#;
    if function_tokens(source, "run") != function_tokens(expected, "run") {
        violations.push(
            "report command dispatch must route compare and verify synchronously without scan runtime initialization"
                .to_owned(),
        );
    }
    Ok(violations)
}

#[derive(Default)]
struct VerifierVisitor {
    violations: BTreeSet<String>,
    join_arguments: BTreeSet<String>,
    current_function: Option<String>,
}

impl VerifierVisitor {
    fn reject(&mut self, reason: &str) {
        self.violations.insert(reason.to_owned());
    }

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
        if [
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
        ]
        .contains(&root.as_str())
            || root.starts_with("venom_")
        {
            self.reject(
                "report verifier cannot initialize runtime, network, clock, or random authority",
            );
        }
        if root == "termivar_scanner"
            && ![
                "termivar_scanner::reporting::comparison::import_assessment_summary",
                "termivar_scanner::reporting::comparison::ComparisonError",
                "termivar_scanner::reporting::comparison::MAX_COMPARISON_INPUT_BYTES",
            ]
            .contains(&joined.as_str())
        {
            self.reject("report verifier may use only the scanner display-only summary import API");
        }
        if root.starts_with("termivar_") && root != "termivar_scanner" {
            self.reject("report verifier cannot import authoritative Termivar models");
        }
        if root == "crate"
            && joined != "crate"
            && ![
                "crate::auth_input::open_regular_file",
                "crate::report_bundle::ASSESSMENT_HTML_NAME",
                "crate::report_bundle::ASSESSMENT_JSON_NAME",
                "crate::report_bundle::MANIFEST_NAME",
                "crate::report_bundle::MAX_MANIFEST_BYTES",
                "crate::report_bundle::REPORT_BUNDLE_SCHEMA",
                "crate::report_compare::validate_local_path",
            ]
            .contains(&joined.as_str())
        {
            self.reject(&format!(
                "report verifier may delegate only to exact read-only file, bundle, and path contracts: `{joined}` is not admitted"
            ));
        }
        if root == "std"
            && [
                "std::env",
                "std::net",
                "std::process::Command",
                "std::thread",
                "std::time",
            ]
            .iter()
            .any(|prefix| joined == *prefix || joined.starts_with(&format!("{prefix}::")))
        {
            self.reject("report verifier cannot access environment, network, subprocess, thread, or time authority");
        }
        if [
            "EvidenceId",
            "AssessmentItem",
            "AssessmentRunReport",
            "WebAssessmentRuntime",
            "RuntimeBudget",
            "AuthorizedTarget",
            "TargetAuthority",
            "NativeOastProvider",
            "AuthorizationInputSource",
        ]
        .iter()
        .any(|forbidden| joined.split("::").any(|part| part == *forbidden))
        {
            self.reject("report verifier cannot mint evidence or acquire runtime, provider, target, or credential authority");
        }
        if [
            "std::fs::write",
            "std::fs::remove_file",
            "std::fs::remove_dir",
            "std::fs::remove_dir_all",
            "std::fs::rename",
            "std::fs::copy",
            "std::fs::create_dir",
            "std::fs::create_dir_all",
            "std::fs::set_permissions",
            "File::create",
        ]
        .contains(&joined.as_str())
        {
            self.reject(
                "report verifier cannot write, repair, remove, rename, copy, or chmod bundle files",
            );
        }
        if root == "fs"
            && [
                "write",
                "remove_file",
                "remove_dir",
                "remove_dir_all",
                "rename",
                "copy",
                "create_dir",
                "create_dir_all",
                "set_permissions",
            ]
            .iter()
            .any(|operation| joined == format!("fs::{operation}"))
        {
            self.reject(
                "report verifier cannot write, repair, remove, rename, copy, or chmod bundle files",
            );
        }
    }
}

impl<'ast> Visit<'ast> for VerifierVisitor {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = self.current_function.replace(item.sig.ident.to_string());
        if item.sig.asyncness.is_some() || item.sig.unsafety.is_some() || item.sig.abi.is_some() {
            self.reject("report verifier must remain synchronous safe local-file inspection");
        }
        syn::visit::visit_item_fn(self, item);
        self.current_function = previous;
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if item.ident == "tests"
            && item.content.is_some()
            && item.attrs.len() == 1
            && matches!(&item.attrs[0].meta, syn::Meta::List(meta) if meta.path.is_ident("cfg") && meta.tokens.to_string() == "test")
            && matches!(item.vis, Visibility::Inherited)
        {
            return;
        }
        self.reject("report verifier may not delegate production behavior to another module");
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.inspect_path(path);
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if [
            "write",
            "append",
            "truncate",
            "create",
            "create_new",
            "set_permissions",
        ]
        .contains(&method.as_str())
        {
            self.reject("report verifier cannot enable a filesystem mutation path");
        }
        if ["write_all", "flush"].contains(&method.as_str())
            && self.current_function.as_deref() != Some("run_with_writer")
        {
            self.reject(&format!(
                "report verifier may write only its bounded stdout result: `{method}` appeared in `{}`",
                self.current_function.as_deref().unwrap_or("non-function context")
            ));
        }
        if method == "join" && call.args.len() == 1 {
            self.join_arguments
                .insert(expr_shape(&call.args[0]).unwrap_or_default());
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if !["format", "writeln"]
            .iter()
            .any(|name| mac.path.is_ident(name))
        {
            self.reject(
                "report verifier cannot hide authority through macros or source indirection",
            );
        }
        inspect_macro_tokens(mac.tokens.clone(), &mut self.violations);
    }

    fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) {
        self.reject("report verifier cannot use unsafe authority");
    }

    fn visit_item_foreign_mod(&mut self, _: &'ast syn::ItemForeignMod) {
        self.reject("report verifier cannot introduce foreign authority");
    }

    fn visit_item_extern_crate(&mut self, _: &'ast syn::ItemExternCrate) {
        self.reject("report verifier cannot alias external crates");
    }
}

fn inspect_macro_tokens(tokens: TokenStream, violations: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Ident(ident)
                if [
                    "include",
                    "include_str",
                    "include_bytes",
                    "option_env",
                    "reqwest",
                    "tokio",
                    "WebAssessmentRuntime",
                    "RuntimeBudget",
                    "EvidenceId",
                    "AssessmentItem",
                ]
                .contains(&ident.to_string().as_str()) =>
            {
                violations.insert(
                    "report verifier cannot hide runtime, network, evidence, or source authority in macro tokens"
                        .to_owned(),
                );
            },
            TokenTree::Group(group) => inspect_macro_tokens(group.stream(), violations),
            _ => {},
        }
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

fn crate_visible_item_name(item: &Item) -> Option<String> {
    let (visibility, name) = item_visibility_and_name(item)?;
    matches!(visibility, Visibility::Restricted(restricted) if restricted.path.is_ident("crate"))
        .then_some(name)
}

fn is_public_item(item: &Item) -> bool {
    item_visibility_and_name(item)
        .is_some_and(|(visibility, _)| matches!(visibility, Visibility::Public(_)))
}

fn item_visibility_and_name(item: &Item) -> Option<(&Visibility, String)> {
    Some(match item {
        Item::Const(item) => (&item.vis, item.ident.to_string()),
        Item::Enum(item) => (&item.vis, item.ident.to_string()),
        Item::Fn(item) => (&item.vis, item.sig.ident.to_string()),
        Item::Mod(item) => (&item.vis, item.ident.to_string()),
        Item::Struct(item) => (&item.vis, item.ident.to_string()),
        Item::Trait(item) => (&item.vis, item.ident.to_string()),
        Item::Type(item) => (&item.vis, item.ident.to_string()),
        Item::Use(item) => (&item.vis, "reexport".to_owned()),
        _ => return None,
    })
}

fn find_struct<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a syn::ItemStruct> {
    syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn find_enum<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a syn::ItemEnum> {
    syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn enum_variants_are(syntax: &syn::File, name: &str, expected: &[&str]) -> bool {
    find_enum(syntax, name).is_some_and(|item| {
        item.variants
            .iter()
            .map(|variant| variant.ident.to_string())
            .collect::<Vec<_>>()
            == expected
            && item
                .variants
                .iter()
                .all(|variant| matches!(variant.fields, syn::Fields::Unit))
    })
}

fn matches_exact_fields(fields: &syn::Fields, expected: &[(&str, &str)]) -> bool {
    matches!(fields, syn::Fields::Named(fields) if fields.named.len() == expected.len() && fields.named.iter().zip(expected).all(|(field, (name, shape))| {
        field.ident.as_ref().is_some_and(|ident| ident == name)
            && matches!(field.vis, Visibility::Inherited)
            && type_shape(&field.ty) == *shape
    }))
}

fn type_shape(ty: &Type) -> String {
    match ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .iter()
            .map(|segment| {
                let mut value = segment.ident.to_string();
                if let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments {
                    let inner = arguments
                        .args
                        .iter()
                        .filter_map(|argument| match argument {
                            syn::GenericArgument::Type(ty) => Some(type_shape(ty)),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                        .join(",");
                    value.push('<');
                    value.push_str(&inner);
                    value.push('>');
                }
                value
            })
            .collect::<Vec<_>>()
            .join("::"),
        Type::Array(array) => format!(
            "[{};{}]",
            type_shape(&array.elem),
            integer_expr(&array.len).unwrap_or_default()
        ),
        Type::Reference(reference) => format!("&{}", type_shape(&reference.elem)),
        _ => String::new(),
    }
}

fn non_doc_attribute_shapes(attributes: &[syn::Attribute]) -> Vec<String> {
    attributes
        .iter()
        .filter(|attribute| !attribute.path().is_ident("doc"))
        .map(|attribute| match &attribute.meta {
            syn::Meta::Path(path) => path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
            syn::Meta::List(list) => format!(
                "{}:{}",
                list.path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default(),
                list.tokens
            ),
            syn::Meta::NameValue(value) => value
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
        })
        .collect()
}

fn has_exact_non_doc_attributes(attributes: &[syn::Attribute], expected: &[&str]) -> bool {
    non_doc_attribute_shapes(attributes) == expected
}

fn string_constant(syntax: &syn::File, name: &str) -> Option<String> {
    syntax.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == name => match &*item.expr {
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Some(value.value()),
            _ => None,
        },
        _ => None,
    })
}

fn integer_constant(syntax: &syn::File, name: &str) -> Option<usize> {
    syntax.items.iter().find_map(|item| match item {
        Item::Const(item) if item.ident == name => integer_expr(&item.expr),
        _ => None,
    })
}

fn integer_expr(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(value),
            ..
        }) => value.base10_parse().ok(),
        Expr::Binary(binary) => {
            let left = integer_expr(&binary.left)?;
            let right = integer_expr(&binary.right)?;
            match binary.op {
                syn::BinOp::Add(_) => left.checked_add(right),
                syn::BinOp::Mul(_) => left.checked_mul(right),
                _ => None,
            }
        },
        _ => None,
    }
}

fn expr_shape(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) if path.qself.is_none() => Some(
            path.path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::"),
        ),
        Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(value),
            ..
        }) => Some(format!("\"{}\"", value.value())),
        _ => None,
    }
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

fn function_signature_tokens(source: &str, name: &str) -> Option<String> {
    function_tokens(source, name).and_then(|source| {
        let mut tokens: Vec<_> = source.parse::<TokenStream>().ok()?.into_iter().collect();
        tokens.pop();
        Some(tokens.into_iter().collect::<TokenStream>().to_string())
    })
}

fn identifiers_appear_in_order(tokens: &str, expected: &[&str]) -> bool {
    let mut offset = 0usize;
    for identifier in expected {
        let Some(found) = tokens[offset..].find(identifier) else {
            return false;
        };
        offset += found + identifier.len();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFIER: &str = include_str!("../../../crates/termivar-cli/src/report_verify.rs");
    const DISPATCH: &str = include_str!("../../../crates/termivar-cli/src/report_compare.rs");

    fn mutate(source: &str, from: &str, to: &str) -> String {
        let normalized = source.replace("\r\n", "\n");
        assert!(normalized.contains(from), "stale mutation anchor: {from}");
        normalized.replacen(from, to, 1)
    }

    fn assert_rejected(source: &str, expected: &str) {
        let violations = verifier_violations(source).expect("mutation parses");
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "missing `{expected}` in {violations:#?}"
        );
    }

    #[test]
    fn checked_in_report_verification_boundary_is_accepted() {
        let violations = verifier_violations(VERIFIER).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
        let violations = dispatch_violations(DISPATCH).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let violations = check(root).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
    }

    #[test]
    fn verifier_cli_and_dispatch_are_exact_and_synchronous() {
        for (from, to, expected) in [
            (
                "pub(crate) struct ReportVerifyArgs",
                "pub struct ReportVerifyArgs",
                "public API",
            ),
            (
                "#[arg(long = \"dir\", value_name = \"DIRECTORY\")]",
                "#[arg(long = \"directory\", value_name = \"DIRECTORY\")]",
                "must require --dir",
            ),
            (
                "    Json,\n}",
                "    Json,\n    Html,\n}",
                "private text/json enum",
            ),
            (
                "pub(crate) fn run(args: ReportVerifyArgs)",
                "pub(crate) async fn run(args: ReportVerifyArgs)",
                "must remain synchronous",
            ),
        ] {
            assert_rejected(&mutate(VERIFIER, from, to), expected);
        }
        for (from, to) in [
            (
                "ReportCommands::Verify(args) => crate::report_verify::run(args).map_err(Into::into),",
                "ReportCommands::Verify(args) => run_compare(args),",
            ),
            (
                "Verify(crate::report_verify::ReportVerifyArgs),",
                "Verify(crate::auth_input::AuthorizationInputSource),",
            ),
        ] {
            let violations = dispatch_violations(&mutate(DISPATCH, from, to)).unwrap();
            assert!(!violations.is_empty(), "accepted {to}");
        }
    }

    #[test]
    fn verifier_rejects_runtime_network_provider_and_credential_authority() {
        for (addition, expected) in [
            (
                "fn bad() { reqwest::get(\"http://127.0.0.1\"); }",
                "runtime, network",
            ),
            ("async fn bad() {}", "synchronous safe"),
            (
                "fn bad() { std::env::var(\"TOKEN\"); }",
                "environment, network",
            ),
            (
                "fn bad() { std::net::TcpStream::connect(\"127.0.0.1:1\"); }",
                "environment, network",
            ),
            (
                "fn bad() { std::process::Command::new(\"termivar\"); }",
                "environment, network",
            ),
            (
                "fn bad() { termivar_scanner::web_runtime::WebAssessmentRuntime::new(); }",
                "display-only summary",
            ),
            (
                "fn bad() { crate::auth_input::read_environment(\"TOKEN\"); }",
                "exact read-only",
            ),
            (
                "fn bad(_: termivar_core::EvidenceId) {}",
                "authoritative Termivar",
            ),
            ("fn bad(_: RuntimeBudget) {}", "cannot mint evidence"),
        ] {
            assert_rejected(&format!("{VERIFIER}\n{addition}"), expected);
        }
    }

    #[test]
    fn verifier_rejects_write_repair_and_manifest_directed_paths() {
        for (addition, expected) in [
            (
                "fn bad(path: &Path) { std::fs::write(path, b\"x\"); }",
                "cannot write, repair",
            ),
            (
                "fn bad(path: &Path) { fs::write(path, b\"x\"); }",
                "cannot write, repair",
            ),
            (
                "fn bad(path: &Path) { std::fs::remove_dir_all(path); }",
                "cannot write, repair",
            ),
            (
                "fn bad(path: &Path) { std::fs::set_permissions(path, todo!()); }",
                "cannot write, repair",
            ),
        ] {
            assert_rejected(&format!("{VERIFIER}\n{addition}"), expected);
        }
        assert_rejected(
            &mutate(VERIFIER, ".read(true)", ".write(true)"),
            "filesystem mutation",
        );
        assert_rejected(
            &mutate(
                VERIFIER,
                "path.join(MANIFEST_NAME)",
                "path.join(manifest.files[0].name)",
            ),
            "three fixed bundle filenames",
        );
        assert_rejected(
            &mutate(
                VERIFIER,
                "directory.join(ASSESSMENT_JSON_NAME)",
                "directory.join(\"../assessment.json\")",
            ),
            "three fixed bundle filenames",
        );
    }

    #[test]
    fn verifier_pins_strict_wire_bounds_and_trust_limits() {
        for (from, to, expected) in [
            (
                "termivar-report-verification/v1",
                "termivar-report-verification/v2",
                "VERIFICATION_SCHEMA",
            ),
            (
                "const MAX_VERIFICATION_OUTPUT_BYTES: usize = 64 * 1_024;",
                "const MAX_VERIFICATION_OUTPUT_BYTES: usize = usize::MAX;",
                "MAX_VERIFICATION_OUTPUT_BYTES",
            ),
            (
                "files: [ManifestFileWire; 2]",
                "files: Vec<ManifestFileWire>",
                "ManifestWire",
            ),
            (
                "#[serde(deny_unknown_fields)]\nstruct ManifestWire",
                "struct ManifestWire",
                "ManifestWire",
            ),
            (
                "producer/source authenticity: not established",
                "producer/source authenticity: verified",
                "trust limits",
            ),
            (
                "result describes bytes read during this invocation",
                "directory remains verified forever",
                "trust limits",
            ),
        ] {
            assert_rejected(&mutate(VERIFIER, from, to), expected);
        }
    }
}
