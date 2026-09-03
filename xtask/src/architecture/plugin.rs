//! Machine-enforced boundaries for the opt-in native plugin contract.

use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use syn::{
    visit::{self, Visit},
    Attribute, Expr, FnArg, GenericArgument, Item, ItemExternCrate, ItemUse, Lit, PathArguments,
    ReturnType, TraitItem, Type, UseTree,
};

const REQUIRED_PLUGIN_API_VERSION: &str = "0.2.0";

const FORBIDDEN_CONSUMER_CLAIM_SURFACES: &[&str] = &[
    "ScanFinding",
    "Vec<ScanFinding>",
    "Finding",
    "Severity",
    "severity:",
    "CRITICAL",
    "HIGH",
    "Outcome::new",
    "RunOutcome",
    "RunOutcomeRecord",
    "plugin.finding",
];

const FORBIDDEN_DIRECT_TRANSPORT_SURFACES: &[&str] = &[
    "reqwest::",
    "usereqwest",
    "r#reqwest",
    "hyper::",
    "usehyper",
    "r#hyper",
    "ureq::",
    "useureq",
    "r#ureq",
    "std::net",
    "std::r#net",
    "std::process",
    "tokio::net",
    "tokio::process",
    "async_std::net",
    "TcpStream",
    "UdpSocket",
    "Client::new(",
    "Command::new(",
];

const REMOVED_PRODUCTION_PLUGIN_TYPES: &[&str] = &[
    "SQLiPlugin",
    "XSSPlugin",
    "LFIPlugin",
    "XXEPlugin",
    "SSRFPlugin",
    "SSTIPlugin",
];

/// Verifies that source-linked plugins remain observation-only host guests.
pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let scanner = workspace_root.join("crates/termivar-scanner/src");
    let plugin_source = fs::read_to_string(scanner.join("plugin.rs"))?;
    let decision_source = fs::read_to_string(scanner.join("decision_runner.rs"))?;
    let library_source = fs::read_to_string(scanner.join("lib.rs"))?;
    let production_plugin_dir = scanner.join("plugins");
    let production_plugin_sources_exist =
        production_plugin_dir.exists() && fs::read_dir(&production_plugin_dir)?.next().is_some();

    let mut violations = validate_contract_sources(
        production_plugin_sources_exist,
        &plugin_source,
        &decision_source,
        &library_source,
    );

    for path in rust_sources_below(&scanner.join("plugin"))? {
        let source = fs::read_to_string(&path)?;
        let name = path.strip_prefix(workspace_root)?.display().to_string();
        violations.extend(validate_plugin_implementation_source(&name, &source));
    }

    let mut consumer_sources = vec![
        workspace_root.join("examples/custom_plugin.rs"),
        workspace_root.join("crates/termivar-scanner/tests/plugin_integration_tests.rs"),
    ];
    consumer_sources.extend(rust_sources_below(
        &workspace_root.join("templates/termivar-plugin"),
    )?);
    consumer_sources.extend(rust_sources_below(
        &workspace_root.join("examples/plugin-fixtures"),
    )?);
    consumer_sources.sort();
    consumer_sources.dedup();

    for path in consumer_sources {
        let source = fs::read_to_string(&path)?;
        violations.extend(validate_consumer_source(
            &path.strip_prefix(workspace_root)?.display().to_string(),
            &source,
        ));
    }

    Ok(violations)
}

fn rust_sources_below(root: &Path) -> Result<Vec<PathBuf>, io::Error> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut directories = vec![root.to_owned()];
    let mut sources = Vec::new();
    while let Some(directory) = directories.pop() {
        let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_dir() {
                directories.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            {
                sources.push(path);
            }
        }
    }
    sources.sort();
    Ok(sources)
}

fn validate_contract_sources(
    production_plugin_sources_exist: bool,
    plugin_source: &str,
    decision_source: &str,
    library_source: &str,
) -> Vec<String> {
    let mut violations = Vec::new();
    if production_plugin_sources_exist {
        violations.push(
            "production scanner plugins directory still exists; marker fixtures belong under examples/plugin-fixtures"
                .to_owned(),
        );
    }

    for forbidden in [
        "ScanFinding",
        "retry_count",
        "Vec<ScanFinding>",
        "severity:",
        "Outcome::new",
        "RunOutcomeRecord",
    ] {
        if plugin_source.contains(forbidden) {
            violations.push(format!(
                "plugin contract contains forbidden claim surface {forbidden}"
            ));
        }
    }
    violations.extend(validate_direct_transport("plugin contract", plugin_source));
    violations.extend(validate_plugin_trait_contract(plugin_source));

    for forbidden in [
        "PluginExecutionInput",
        "PluginInputProvider",
        "plugin.finding",
        "ScanFinding",
    ] {
        if decision_source.contains(forbidden) {
            violations.push(format!(
                "plugin decision bridge retains forbidden legacy surface {forbidden}"
            ));
        }
    }

    if declares_plugins_module(library_source) {
        violations.push("termivar-scanner reintroduces a production plugins module".to_owned());
    }
    for removed in REMOVED_PRODUCTION_PLUGIN_TYPES {
        if library_source.contains(removed) {
            violations.push(format!(
                "termivar-scanner reexports removed fake scanner type {removed}"
            ));
        }
    }
    violations
}

fn validate_plugin_implementation_source(name: &str, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for forbidden in [
        "ScanFinding",
        "retry_count",
        "Vec<ScanFinding>",
        "severity:",
        "Outcome::new",
        "RunOutcomeRecord",
    ] {
        if source.contains(forbidden) {
            violations.push(format!(
                "plugin implementation {name} contains forbidden claim surface {forbidden}"
            ));
        }
    }
    violations.extend(validate_direct_transport(name, source));
    violations
}

fn validate_plugin_trait_contract(source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => {
            return vec![format!(
                "plugin contract could not be parsed while validating the 0.2 ABI: {error}"
            )];
        },
    };
    let mut violations = Vec::new();

    let api_versions = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item) if item.ident == "PLUGIN_API_VERSION" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let api_version_is_canonical = matches!(api_versions.as_slice(), [item]
        if !has_conditional_attribute(&item.attrs)
            && matches!(item.expr.as_ref(),
                Expr::Lit(expression)
                    if matches!(&expression.lit,
                        Lit::Str(value) if value.value() == REQUIRED_PLUGIN_API_VERSION)));
    if !api_version_is_canonical {
        violations.push(format!(
            "plugin contract must declare exactly one unconditional PLUGIN_API_VERSION as {REQUIRED_PLUGIN_API_VERSION:?}"
        ));
    }

    let plugin_traits = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Trait(item) if item.ident == "Plugin" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [plugin_trait] = plugin_traits.as_slice() else {
        violations
            .push("plugin contract must define exactly one unconditional Plugin trait".to_owned());
        return violations;
    };
    if has_conditional_attribute(&plugin_trait.attrs) {
        violations
            .push("plugin contract must define exactly one unconditional Plugin trait".to_owned());
    }
    let execute_methods = plugin_trait
        .items
        .iter()
        .filter_map(|item| match item {
            TraitItem::Fn(method) if method.sig.ident == "execute" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [execute] = execute_methods.as_slice() else {
        violations
            .push("Plugin must define exactly one unconditional 0.2 execute method".to_owned());
        return violations;
    };

    let mut inputs = execute.sig.inputs.iter();
    let receiver_is_shared = matches!(
        inputs.next(),
        Some(FnArg::Receiver(receiver))
            if receiver.reference.is_some()
                && receiver.mutability.is_none()
                && receiver.colon_token.is_none()
    );
    let context_is_shared = matches!(
        inputs.next(),
        Some(FnArg::Typed(argument)) if is_shared_reference_to(&argument.ty, "PluginContext")
    );
    let has_only_required_inputs = inputs.next().is_none();
    let returns_unit_result = is_unit_result_with_error(&execute.sig.output, "PluginError");

    if has_conditional_attribute(&execute.attrs)
        || execute.sig.asyncness.is_none()
        || !receiver_is_shared
        || !context_is_shared
        || !has_only_required_inputs
        || !returns_unit_result
    {
        violations.push(
            "Plugin::execute must use the 0.2 contract: async fn execute(&self, context: &PluginContext) -> Result<(), PluginError>; loose target/payload inputs and direct outputs are forbidden"
                .to_owned(),
        );
    }

    violations
}

fn has_conditional_attribute(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

fn is_shared_reference_to(item: &Type, expected: &str) -> bool {
    let Type::Reference(reference) = item else {
        return false;
    };
    reference.mutability.is_none() && is_plain_type_path(&reference.elem, expected)
}

fn is_plain_type_path(item: &Type, expected: &str) -> bool {
    let Type::Path(path) = item else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() == 1
        && path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == expected && segment.arguments.is_empty())
}

fn is_unit_result_with_error(output: &ReturnType, expected_error: &str) -> bool {
    let ReturnType::Type(_, item) = output else {
        return false;
    };
    let Type::Path(path) = item.as_ref() else {
        return false;
    };
    let Some(result) = path.path.segments.last() else {
        return false;
    };
    let PathArguments::AngleBracketed(arguments) = &result.arguments else {
        return false;
    };
    if path.path.segments.len() != 1 || result.ident != "Result" || arguments.args.len() != 2 {
        return false;
    }
    let mut arguments = arguments.args.iter();
    let unit = matches!(
        arguments.next(),
        Some(GenericArgument::Type(Type::Tuple(tuple))) if tuple.elems.is_empty()
    );
    let error = matches!(
        arguments.next(),
        Some(GenericArgument::Type(item)) if is_plain_type_path(item, expected_error)
    );
    unit && error
}

fn declares_plugins_module(source: &str) -> bool {
    syn::parse_file(source).is_ok_and(|file| {
        file.items
            .iter()
            .any(|item| matches!(item, Item::Mod(module) if module.ident == "plugins"))
    })
}

fn validate_consumer_source(name: &str, source: &str) -> Vec<String> {
    let compact_source = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let mut violations = FORBIDDEN_CONSUMER_CLAIM_SURFACES
        .iter()
        .filter(|forbidden| contains_surface(source, &compact_source, forbidden))
        .map(|forbidden| format!("{name} teaches forbidden plugin claim surface {forbidden}"))
        .collect::<Vec<_>>();
    violations.extend(validate_direct_transport(name, source));
    violations
}

fn validate_direct_transport(name: &str, source: &str) -> Vec<String> {
    let compact_source = source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let mut surfaces = FORBIDDEN_DIRECT_TRANSPORT_SURFACES
        .iter()
        .filter(|forbidden| contains_surface(source, &compact_source, forbidden))
        .map(|forbidden| (*forbidden).to_owned())
        .collect::<Vec<_>>();
    if let Ok(file) = syn::parse_file(source) {
        let mut visitor = DirectTransportImportVisitor::default();
        visitor.visit_file(&file);
        surfaces.extend(visitor.surfaces);
    }
    surfaces.sort();
    surfaces.dedup();
    surfaces
        .into_iter()
        .map(|surface| {
            format!(
                "{name} acquires forbidden direct transport through {surface}; use PluginContext::request"
            )
        })
        .collect()
}

#[derive(Default)]
struct DirectTransportImportVisitor {
    surfaces: Vec<String>,
}

impl<'ast> Visit<'ast> for DirectTransportImportVisitor {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        for path in use_tree_paths(&item.tree) {
            if is_forbidden_transport_import(&path) {
                self.surfaces.push(path.join("::"));
            }
        }
        visit::visit_item_use(self, item);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        let root = item.ident.to_string();
        if matches!(root.as_str(), "reqwest" | "hyper" | "ureq") {
            self.surfaces.push(format!("extern crate {root}"));
        }
        visit::visit_item_extern_crate(self, item);
    }
}

fn use_tree_paths(tree: &UseTree) -> Vec<Vec<String>> {
    collect_use_tree_paths(tree, &[])
}

fn collect_use_tree_paths(tree: &UseTree, prefix: &[String]) -> Vec<Vec<String>> {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix.to_vec();
            next.push(path.ident.to_string());
            collect_use_tree_paths(&path.tree, &next)
        },
        UseTree::Name(name) => {
            let mut path = prefix.to_vec();
            path.push(name.ident.to_string());
            vec![path]
        },
        UseTree::Rename(rename) => {
            let mut path = prefix.to_vec();
            path.push(rename.ident.to_string());
            vec![path]
        },
        UseTree::Glob(_) => vec![prefix.to_vec()],
        UseTree::Group(group) => group
            .items
            .iter()
            .flat_map(|item| collect_use_tree_paths(item, prefix))
            .collect(),
    }
}

fn is_forbidden_transport_import(path: &[String]) -> bool {
    match path {
        [root, ..] if matches!(root.as_str(), "reqwest" | "hyper" | "ureq") => true,
        [root, module, ..]
            if matches!(root.as_str(), "std" | "tokio" | "async_std")
                && matches!(module.as_str(), "net" | "process") =>
        {
            true
        },
        _ => false,
    }
}

fn contains_surface(source: &str, compact_source: &str, surface: &str) -> bool {
    source.contains(surface) || compact_source.contains(surface)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_legacy_findings_and_production_scanners() {
        let violations = validate_contract_sources(
            true,
            r#"
                pub const PLUGIN_API_VERSION: &str = "0.1.0";
                trait Plugin {
                    async fn execute(
                        &self,
                        target: &str,
                        payload: &str,
                    ) -> Result<Vec<ScanFinding>, PluginError>;
                }
                const RETRIES: &str = "retry_count";
            "#,
            "struct PluginExecutionInput; const P: &str = \"plugin.finding\";",
            "mod plugins; pub use plugins::SQLiPlugin;",
        );
        assert!(violations.iter().any(|item| item.contains("ScanFinding")));
        assert!(violations.iter().any(|item| item.contains("retry_count")));
        assert!(violations
            .iter()
            .any(|item| item.contains("production plugins")));
        assert!(violations
            .iter()
            .any(|item| item.contains("PluginExecutionInput")));
        assert!(violations
            .iter()
            .any(|item| item.contains("plugin.finding")));
        assert!(violations.iter().any(|item| item.contains("SQLiPlugin")));
        assert!(violations.iter().any(|item| item.contains("0.2.0")));
        assert!(violations
            .iter()
            .any(|item| item.contains("loose target/payload")));
    }

    #[test]
    fn rejects_direct_transport_and_consumer_claims() {
        let contract = validate_contract_sources(
            false,
            r#"
                pub const PLUGIN_API_VERSION: &str = "0.2.0";
                trait Plugin {
                    async fn execute(
                        &self,
                        context: &PluginContext,
                    ) -> Result<(), PluginError>;
                }
                fn direct_transport() { let client = reqwest::Client::new(); }
            "#,
            "struct PluginExecutionRequestProvider;",
            "pub mod plugin;",
        );
        assert!(contract.iter().any(|item| item.contains("reqwest::")));

        let consumer = validate_consumer_source(
            "template",
            "fn execute() -> Vec<ScanFinding> { let _ = std::net::TcpStream; /* CRITICAL */ }",
        );
        assert!(consumer.iter().any(|item| item.contains("ScanFinding")));
        assert!(consumer.iter().any(|item| item.contains("CRITICAL")));
        assert!(consumer.iter().any(|item| item.contains("std::net")));
        assert!(consumer.iter().any(|item| item.contains("TcpStream")));
    }

    #[test]
    fn rejects_core_transport_spacing_and_aliased_imports() {
        let contract = r#"
            pub const PLUGIN_API_VERSION: &str = "0.2.0";
            trait Plugin {
                async fn execute(
                    &self,
                    context: &PluginContext,
                ) -> Result<(), PluginError>;
            }
            use tokio :: net as direct_transport;
            fn nested_aliases() {
                use {hyper as protocol};
                use std::{process as jobs, sync::Arc};
            }
        "#;
        let violations = validate_contract_sources(
            false,
            contract,
            "struct PluginExecutionRequestProvider;",
            "pub mod plugin;",
        );
        assert!(violations.iter().any(|item| item.contains("tokio::net")));
        assert!(violations.iter().any(|item| item.contains("hyper")));
        assert!(violations.iter().any(|item| item.contains("std::process")));
    }

    #[test]
    fn rejects_cfg_dummy_first_and_duplicate_contract_declarations() {
        let violations = validate_plugin_trait_contract(
            r#"
                #[cfg(any())]
                pub const PLUGIN_API_VERSION: &str = "0.2.0";
                pub const PLUGIN_API_VERSION: &str = "0.1.0";

                #[cfg(any())]
                trait Plugin {
                    async fn execute(
                        &self,
                        context: &PluginContext,
                    ) -> Result<(), PluginError>;
                }
                trait Plugin {
                    async fn execute(
                        &self,
                        target: &str,
                        payload: &str,
                    ) -> Result<(), PluginError>;
                }
            "#,
        );
        assert!(violations
            .iter()
            .any(|item| item.contains("exactly one unconditional PLUGIN_API_VERSION")));
        assert!(violations
            .iter()
            .any(|item| item.contains("exactly one unconditional Plugin trait")));

        let conditional_execute = validate_plugin_trait_contract(
            r#"
                pub const PLUGIN_API_VERSION: &str = "0.2.0";
                trait Plugin {
                    #[cfg(feature = "legacy")]
                    async fn execute(
                        &self,
                        context: &PluginContext,
                    ) -> Result<(), PluginError>;
                }
            "#,
        );
        assert!(conditional_execute
            .iter()
            .any(|item| item.contains("Plugin::execute must use the 0.2 contract")));
    }

    #[test]
    fn rejects_every_plugins_module_visibility_and_shape() {
        for source in [
            "mod plugins;",
            "pub mod plugins;",
            "pub(crate) mod plugins;",
            "#[path = \"elsewhere.rs\"] mod plugins;",
            "mod plugins {}",
        ] {
            assert!(
                declares_plugins_module(source),
                "plugins module unexpectedly passed: {source}"
            );
        }
        assert!(!declares_plugins_module("pub mod plugin;"));
    }

    #[test]
    fn recursively_discovers_fixture_rust_sources() {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested/deeper");
        fs::create_dir_all(&nested).unwrap();
        fs::write(directory.path().join("top.rs"), "// fixture").unwrap();
        fs::write(
            nested.join("nested.rs"),
            "fn bypass() { let _ = std :: net :: TcpStream; }",
        )
        .unwrap();
        fs::write(nested.join("ignored.md"), "not Rust").unwrap();

        let sources = rust_sources_below(directory.path()).unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources.iter().any(|path| path.ends_with("top.rs")));
        assert!(sources.iter().any(|path| path.ends_with("nested.rs")));
        let violations = sources
            .iter()
            .flat_map(|path| {
                validate_consumer_source(
                    &path.display().to_string(),
                    &fs::read_to_string(path).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert!(violations.iter().any(|item| item.contains("std::net")));
    }

    #[test]
    fn rejects_qualified_context_lookalikes() {
        let violations = validate_plugin_trait_contract(
            r#"
                pub const PLUGIN_API_VERSION: &str = "0.2.0";
                trait Plugin {
                    async fn execute(
                        &self,
                        context: &foreign::PluginContext,
                    ) -> Result<(), foreign::PluginError>;
                }
            "#,
        );
        assert!(violations
            .iter()
            .any(|item| item.contains("Plugin::execute must use the 0.2 contract")));
    }

    #[test]
    fn accepts_observation_only_host_context() {
        assert!(validate_contract_sources(
            false,
            r#"
                /// Public API line.
                pub const PLUGIN_API_VERSION: &str = "0.2.0";
                #[async_trait]
                trait Plugin {
                    /// Executes with host-owned authority.
                    async fn execute(
                        &self,
                        context: &PluginContext,
                    ) -> Result<(), PluginError>;
                }
            "#,
            "struct PluginExecutionRequestProvider;",
            "pub mod plugin;",
        )
        .is_empty());
        assert!(validate_consumer_source(
            "template",
            "context.record(PluginObservation::new(...));",
        )
        .is_empty());
    }
}
