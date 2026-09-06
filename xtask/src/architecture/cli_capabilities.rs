//! Closed boundary for offline, build-accurate CLI capability introspection.

use std::{collections::BTreeSet, error::Error, fs, path::Path};

use syn::{
    visit::Visit, Attribute, ExprMacro, ExprPath, Item, ItemEnum, ItemFn, ItemMod, ItemStruct,
    ItemUse, Meta, TypePath, UseTree, Visibility,
};

const CAPABILITIES_SOURCE: &str = "crates/termivar-cli/src/capabilities.rs";
const CLI_SOURCE: &str = "crates/termivar-cli/src/main.rs";
const CLI_MANIFEST: &str = "crates/termivar-cli/Cargo.toml";
const SCHEMA: &str = "termivar-cli-capabilities/v1";
const REQUIRED_NOTICE: &str = "Build inventory only. No assessment was started or evaluated.";

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let source = fs::read_to_string(workspace_root.join(CAPABILITIES_SOURCE))?;
    let main = fs::read_to_string(workspace_root.join(CLI_SOURCE))?;
    let manifest = fs::read_to_string(workspace_root.join(CLI_MANIFEST))?;
    let mut violations = capabilities_violations(&source, &manifest)?;
    violations.extend(dispatch_violations(&main)?);
    Ok(violations)
}

fn capabilities_violations(source: &str, manifest: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let syntax = syn::parse_file(source)?;
    let mut violations = BTreeSet::new();

    let crate_visible = syntax
        .items
        .iter()
        .filter_map(crate_visible_name)
        .collect::<BTreeSet<_>>();
    let expected = ["CapabilitiesArgs", "CapabilitiesError", "run"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if crate_visible != expected {
        violations.insert(
            "CLI capabilities crate API must remain exactly CapabilitiesArgs, CapabilitiesError, and synchronous run"
                .to_owned(),
        );
    }
    if syntax.items.iter().any(is_public_item) {
        violations.insert("CLI capabilities cannot expose a public Rust API".to_owned());
    }

    let args = find_struct(&syntax, "CapabilitiesArgs");
    if args.is_none_or(|item| {
        field_names(item) != ["format".to_owned()] || !struct_has_derive(item, "Args")
    }) {
        violations.insert(
            "CapabilitiesArgs must remain the one-field private --format argument payload"
                .to_owned(),
        );
    }
    let format = find_enum(&syntax, "CapabilitiesFormat");
    if format.is_none_or(|item| {
        variant_names(item) != ["Text".to_owned(), "Json".to_owned()]
            || !enum_has_derive(item, "ValueEnum")
    }) {
        violations.insert("capabilities format must remain exactly text or json".to_owned());
    }

    for (name, variants) in [
        ("BuildState", ["Compiled", "NotCompiled"].as_slice()),
        ("SurfaceGroup", ["Everyday", "Optional"].as_slice()),
        (
            "SurfaceKind",
            ["Command", "Profile", "ReportOutput", "ScanOption"].as_slice(),
        ),
        (
            "Maturity",
            [
                "Preview",
                "Deprecated",
                "Experimental",
                "Legacy",
                "Unsupported",
            ]
            .as_slice(),
        ),
        (
            "ImplementationStatus",
            [
                "Implemented",
                "ExperimentalLimited",
                "LegacyUnmetered",
                "UnsupportedStub",
            ]
            .as_slice(),
        ),
    ] {
        let expected_variants = variants
            .iter()
            .map(|variant| (*variant).to_owned())
            .collect::<Vec<_>>();
        if find_enum(&syntax, name).is_none_or(|item| {
            variant_names(item) != expected_variants || !enum_has_derive(item, "Serialize")
        }) {
            violations.insert(format!(
                "CLI capabilities `{name}` must retain its exact private serialized vocabulary"
            ));
        }
    }

    for (name, fields) in [
        (
            "CapabilitiesDocument",
            [
                "schema",
                "product",
                "package_version",
                "inventory_scope",
                "runtime_execution",
                "cli_package_features",
                "surfaces",
                "notice",
                "build_origin_authenticity",
            ]
            .as_slice(),
        ),
        ("BuildFeatureDescriptor", ["name", "build_state"].as_slice()),
        (
            "AliasDescriptor",
            ["name", "command", "maturity", "relation"].as_slice(),
        ),
        (
            "SurfaceDescriptor",
            [
                "key",
                "label",
                "group",
                "kind",
                "compile_feature",
                "build_state",
                "maturity",
                "implementation_status",
                "alias",
                "prerequisites",
                "limitation",
                "documentation",
            ]
            .as_slice(),
        ),
    ] {
        let expected_fields = fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<Vec<_>>();
        if find_struct(&syntax, name).is_none_or(|item| {
            field_names(item) != expected_fields || !struct_has_derive(item, "Serialize")
        }) {
            violations.insert(format!(
                "CLI capabilities `{name}` must remain the exact private serialized display DTO"
            ));
        }
    }
    if source.contains("Deserialize") {
        violations.insert("CLI capabilities display DTOs cannot deserialize authority".to_owned());
    }

    let run = find_fn(&syntax, "run");
    let writer = find_fn(&syntax, "run_with_writer");
    if run.is_none_or(|item| {
        !is_pub_crate(&item.vis)
            || item.sig.asyncness.is_some()
            || item.sig.inputs.len() != 1
            || matches!(item.sig.output, syn::ReturnType::Default)
    }) || writer.is_none_or(|item| {
        !matches!(item.vis, Visibility::Inherited)
            || item.sig.asyncness.is_some()
            || item.sig.inputs.len() != 2
            || matches!(item.sig.output, syn::ReturnType::Default)
    }) {
        violations.insert(
            "CLI capabilities must retain one synchronous crate entry and private writer seam"
                .to_owned(),
        );
    }

    let normalized = source.replace("\r\n", "\n");
    for required in [
        format!("const CAPABILITIES_SCHEMA: &str = \"{SCHEMA}\";"),
        "const MAX_CAPABILITIES_OUTPUT_BYTES: usize = 64 * 1024;".to_owned(),
        format!("const INVENTORY_NOTICE: &str = \"{REQUIRED_NOTICE}\";"),
        "package_version: env!(\"CARGO_PKG_VERSION\")".to_owned(),
        "inventory_scope: \"cli_surfaces\"".to_owned(),
        "runtime_execution: \"not_performed\"".to_owned(),
    ] {
        if !normalized.contains(&required) {
            violations.insert(format!(
                "CLI capabilities is missing exact bounded offline contract `{required}`"
            ));
        }
    }
    let writer_body = function_source(source, "run_with_writer").unwrap_or_default();
    for required in ["output . write_all (& rendered)", "output . flush ()"] {
        if !writer_body.contains(required) {
            violations.insert(format!(
                "CLI capabilities writer must retain exact bounded output operation `{required}`"
            ));
        }
    }
    let manifest: toml::Value = manifest.parse()?;
    let Some(features_table) = manifest.get("features").and_then(toml::Value::as_table) else {
        violations.insert("termivar-cli manifest must retain a features table".to_owned());
        return Ok(violations.into_iter().collect());
    };
    let manifest_features = features_table
        .keys()
        .filter(|name| name.as_str() != "default")
        .cloned()
        .collect::<BTreeSet<_>>();
    let feature_body = function_source(source, "build_features").unwrap_or_default();
    for feature in &manifest_features {
        if !feature_body.contains(&format!("feature = \"{feature}\""))
            || !feature_body.contains(&format!("\"{feature}\""))
        {
            violations.insert(format!(
                "CLI capabilities must derive `{feature}` from its exact package cfg"
            ));
        }
    }
    if feature_body.contains("feature = \"default\"") {
        violations.insert("the empty Cargo default marker is not a CLI capability".to_owned());
    }

    let mut visitor = OfflineVisitor::default();
    visitor.visit_file(&syntax);
    violations.extend(visitor.violations);
    Ok(violations.into_iter().collect())
}

fn dispatch_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = Vec::new();
    if !source.contains("mod capabilities;")
        || !source.contains("Capabilities(capabilities::CapabilitiesArgs)")
    {
        violations
            .push("the top-level CLI must expose exactly one capabilities command".to_owned());
    }
    let main = function_source(source, "main").unwrap_or_default();
    if find_fn(&syntax, "main").is_none_or(|item| item.sig.asyncness.is_some()) {
        violations.push("the top-level CLI entry must remain synchronous".to_owned());
    }
    let capabilities_dispatch =
        "Some (Commands :: Capabilities (args)) => capabilities :: run (args) . map_err (Into :: into)";
    let report_dispatch =
        "Some (Commands :: Report { command }) => report_compare :: run (command)";
    let runtime_dispatch = "run_existing_command (command) ?";
    let capabilities_index = main.find(capabilities_dispatch);
    let report_index = main.find(report_dispatch);
    let runtime_index = main.find(runtime_dispatch);
    if capabilities_index.is_none()
        || report_index.is_none()
        || runtime_index.is_none()
        || capabilities_index >= runtime_index
        || report_index >= runtime_index
    {
        violations.push(
            "capabilities and report commands must dispatch synchronously before runtime initialization"
                .to_owned(),
        );
    }
    let runtime = function_source(source, "run_existing_command").unwrap_or_default();
    if !runtime.contains("Commands :: Capabilities (_)")
        || !runtime.contains("Commands :: Report { .. }")
        || !runtime.contains("offline commands must be dispatched before runtime initialization")
    {
        violations
            .push("the async command dispatcher must reject misplaced offline commands".to_owned());
    }
    Ok(violations)
}

#[derive(Default)]
struct OfflineVisitor {
    violations: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for OfflineVisitor {
    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, String::new(), &mut paths);
        for path in paths {
            if forbidden_path(&path) {
                self.violations.insert(format!(
                    "CLI capabilities cannot import external-input or runtime path `{path}`"
                ));
            }
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_expr_path(&mut self, expression: &'ast ExprPath) {
        let path = path_string(&expression.path);
        if forbidden_path(&path) {
            self.violations.insert(format!(
                "CLI capabilities cannot call external-input or runtime path `{path}`"
            ));
        }
        syn::visit::visit_expr_path(self, expression);
    }

    fn visit_type_path(&mut self, value: &'ast TypePath) {
        let path = path_string(&value.path);
        if forbidden_path(&path) {
            self.violations.insert(format!(
                "CLI capabilities cannot own external-input or runtime type `{path}`"
            ));
        }
        syn::visit::visit_type_path(self, value);
    }

    fn visit_expr_macro(&mut self, expression: &'ast ExprMacro) {
        let name = path_string(&expression.mac.path);
        if matches!(
            name.as_str(),
            "include" | "include_str" | "include_bytes" | "option_env"
        ) {
            self.violations.insert(format!(
                "CLI capabilities cannot acquire generated or external data through `{name}!`"
            ));
        }
        if name == "env" && expression.mac.tokens.to_string() != "\"CARGO_PKG_VERSION\"" {
            self.violations
                .insert("CLI capabilities may use env! only for CARGO_PKG_VERSION".to_owned());
        }
        syn::visit::visit_expr_macro(self, expression);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        if item.sig.asyncness.is_some() {
            self.violations
                .insert("CLI capabilities cannot define async execution".to_owned());
        }
        syn::visit::visit_item_fn(self, item);
    }
}

fn forbidden_path(path: &str) -> bool {
    [
        "reqwest",
        "tokio",
        "termivar_scanner",
        "url",
        "crate::auth_input",
        "crate::assessment_scan",
        "crate::decision_scan",
        "std::env",
        "std::fs",
        "std::net",
        "std::path",
        "std::process::Command",
    ]
    .iter()
    .any(|forbidden| path == *forbidden || path.starts_with(&format!("{forbidden}::")))
}

fn collect_use_paths(tree: &UseTree, prefix: String, output: &mut Vec<String>) {
    match tree {
        UseTree::Path(path) => {
            let next = join_path(&prefix, &path.ident.to_string());
            collect_use_paths(&path.tree, next, output);
        },
        UseTree::Name(name) => output.push(join_path(&prefix, &name.ident.to_string())),
        UseTree::Rename(rename) => output.push(join_path(&prefix, &rename.ident.to_string())),
        UseTree::Glob(_) => output.push(join_path(&prefix, "*")),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix.clone(), output);
            }
        },
    }
}

fn join_path(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_owned()
    } else {
        format!("{prefix}::{segment}")
    }
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn crate_visible_name(item: &Item) -> Option<String> {
    match item {
        Item::Struct(item) if is_pub_crate(&item.vis) => Some(item.ident.to_string()),
        Item::Enum(item) if is_pub_crate(&item.vis) => Some(item.ident.to_string()),
        Item::Fn(item) if is_pub_crate(&item.vis) => Some(item.sig.ident.to_string()),
        _ => None,
    }
}

fn is_public_item(item: &Item) -> bool {
    match item {
        Item::Struct(item) => matches!(item.vis, Visibility::Public(_)),
        Item::Enum(item) => matches!(item.vis, Visibility::Public(_)),
        Item::Fn(item) => matches!(item.vis, Visibility::Public(_)),
        Item::Const(item) => matches!(item.vis, Visibility::Public(_)),
        Item::Static(item) => matches!(item.vis, Visibility::Public(_)),
        Item::Type(item) => matches!(item.vis, Visibility::Public(_)),
        _ => false,
    }
}

fn is_pub_crate(visibility: &Visibility) -> bool {
    matches!(
        visibility,
        Visibility::Restricted(restricted)
            if restricted.path.is_ident("crate") && restricted.in_token.is_none()
    )
}

fn find_struct<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a ItemStruct> {
    syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn find_enum<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a ItemEnum> {
    syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn find_fn<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a ItemFn> {
    syntax.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    })
}

fn function_source(source: &str, name: &str) -> Option<String> {
    use proc_macro2::{Delimiter, TokenStream, TokenTree};

    let tokens = source
        .parse::<TokenStream>()
        .ok()?
        .into_iter()
        .collect::<Vec<_>>();
    for (index, pair) in tokens.windows(2).enumerate() {
        if matches!(&pair[0], TokenTree::Ident(ident) if ident == "fn")
            && matches!(&pair[1], TokenTree::Ident(ident) if ident == name)
        {
            let end = tokens
                .iter()
                .enumerate()
                .skip(index + 2)
                .find_map(|(index, token)| {
                    matches!(token, TokenTree::Group(group) if group.delimiter() == Delimiter::Brace)
                        .then_some(index)
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

fn field_names(item: &ItemStruct) -> Vec<String> {
    item.fields
        .iter()
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect()
}

fn variant_names(item: &ItemEnum) -> Vec<String> {
    item.variants
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect()
}

fn struct_has_derive(item: &ItemStruct, derive: &str) -> bool {
    has_derive(&item.attrs, derive)
}

fn enum_has_derive(item: &ItemEnum, derive: &str) -> bool {
    has_derive(&item.attrs, derive)
}

fn has_derive(attributes: &[Attribute], derive: &str) -> bool {
    attributes.iter().any(|attribute| match &attribute.meta {
        Meta::List(list) if list.path.is_ident("derive") => {
            list.tokens.clone().into_iter().any(
                |token| matches!(token, proc_macro2::TokenTree::Ident(ident) if ident == derive),
            )
        },
        _ => false,
    })
}

fn has_cfg_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| match &attribute.meta {
        Meta::List(list) if list.path.is_ident("cfg") => list.tokens.to_string() == "test",
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("../../../crates/termivar-cli/src/capabilities.rs");
    const MAIN: &str = include_str!("../../../crates/termivar-cli/src/main.rs");
    const MANIFEST: &str = include_str!("../../../crates/termivar-cli/Cargo.toml");

    #[test]
    fn repository_capabilities_boundary_is_exact() {
        assert!(capabilities_violations(SOURCE, MANIFEST)
            .unwrap()
            .is_empty());
        assert!(dispatch_violations(MAIN).unwrap().is_empty());
    }

    #[test]
    fn runtime_input_and_generated_metadata_mutations_are_rejected() {
        for addition in [
            "fn bad() { let _ = std::fs::read(\"Cargo.toml\"); }",
            "fn bad() { let _ = std::env::var(\"CARGO_FEATURE_X\"); }",
            "fn bad() { let _ = std::net::TcpStream::connect(\"127.0.0.1:1\"); }",
            "fn bad() { let _ = reqwest::get(\"https://example.test\"); }",
            "async fn bad() { tokio::task::yield_now().await; }",
            "fn bad() { let _ = crate::auth_input::AuthorizationInputError::SourceUnavailable; }",
            "fn bad() { let _ = termivar_scanner::ReportFormat::Json; }",
            "fn bad() { let _ = std::process::Command::new(\"git\"); }",
            "const BAD: &str = include_str!(\"hidden\");",
            "const BAD: &str = env!(\"CARGO_FEATURE_X\");",
        ] {
            let mutated = format!("{SOURCE}\n{addition}");
            assert!(
                !capabilities_violations(&mutated, MANIFEST)
                    .unwrap()
                    .is_empty(),
                "accepted mutation {addition}"
            );
        }
    }

    #[test]
    fn dto_and_feature_truth_mutations_are_rejected() {
        for (from, to) in [
            (
                "pub(crate) struct CapabilitiesArgs",
                "pub struct CapabilitiesArgs",
            ),
            (
                "#[derive(Serialize)]\nstruct CapabilitiesDocument",
                "#[derive(Serialize, Deserialize)]\nstruct CapabilitiesDocument",
            ),
            ("env!(\"CARGO_PKG_VERSION\")", "env!(\"CARGO_PKG_NAME\")"),
            ("64 * 1024", "128 * 1024"),
            ("cfg!(feature = \"rest-review\")", "false"),
        ] {
            let mutated = SOURCE.replacen(from, to, 1);
            assert_ne!(mutated, SOURCE, "mutation did not apply: {from}");
            assert!(
                !capabilities_violations(&mutated, MANIFEST)
                    .unwrap()
                    .is_empty(),
                "accepted mutation {to}"
            );
        }
    }

    #[test]
    fn offline_dispatch_mutations_are_rejected() {
        for (from, to) in [
            (
                "Some(Commands::Capabilities(args)) => capabilities::run(args).map_err(Into::into),",
                "Some(Commands::Capabilities(args)) => { run_existing_command(Some(Commands::Capabilities(args)))?; Ok(std::process::ExitCode::SUCCESS) },",
            ),
            ("fn main()", "#[tokio::main] async fn main()"),
            (
                "Some(Commands::Capabilities(_) | Commands::Report { .. })",
                "Some(Commands::Report { .. })",
            ),
        ] {
            let mutated = MAIN.replacen(from, to, 1);
            assert_ne!(mutated, MAIN, "mutation did not apply: {from}");
            assert!(
                !dispatch_violations(&mutated).unwrap().is_empty(),
                "accepted mutation {to}"
            );
        }
    }
}
