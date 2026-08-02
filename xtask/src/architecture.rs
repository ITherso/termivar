//! Machine-enforced workspace and reasoning-module dependency boundaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    path::Path,
    str::FromStr,
};

use cargo_metadata::MetadataCommand;
use proc_macro2::{TokenStream, TokenTree};
use syn::{
    visit::{self, Visit},
    Attribute, GenericParam, Item, ItemExternCrate, ItemMacro, ItemMod, ItemUse, LitStr, Macro,
    Meta, Path as SynPath, Stmt, UseTree,
};

const ALLOWED_EXTERNAL_ROOTS: &[&str] = &["core", "serde", "std", "thiserror", "venom_core"];
const ALLOWED_LIBRARY_ATTRIBUTES: &[&str] = &["allow", "cfg", "deny", "deprecated", "doc"];
const ATTRIBUTE_NON_DEPENDENCY_ROOTS: &[&str] = &["clippy", "rustdoc"];
const FORBIDDEN_STD_ROOTS: &[&str] = &["net", "process"];
const CODE_STRING_ATTRIBUTE_KEYS: &[&str] = &[
    "bound",
    "crate",
    "default",
    "deserialize",
    "deserialize_with",
    "from",
    "getter",
    "into",
    "remote",
    "serialize",
    "serialize_with",
    "skip_serializing_if",
    "try_from",
    "with",
];
const PRIMITIVE_ROOTS: &[&str] = &[
    "char", "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
];
const PRELUDE_ROOTS: &[&str] = &[
    "AsMut",
    "AsRef",
    "Box",
    "Clone",
    "Default",
    "From",
    "Into",
    "IntoIterator",
    "Iterator",
    "Option",
    "Result",
    "String",
    "ToOwned",
    "TryFrom",
    "TryInto",
    "Vec",
];

#[derive(Clone, Copy)]
struct ModulePolicy {
    source: &'static str,
    allowed_internal: &'static [&'static str],
    allowed_external: &'static [&'static str],
}

const MODULE_POLICIES: &[ModulePolicy] = &[
    ModulePolicy {
        source: "knowledge.rs",
        allowed_internal: &[],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "experience.rs",
        allowed_internal: &[],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "rules.rs",
        allowed_internal: &["knowledge"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "planner.rs",
        allowed_internal: &["knowledge", "rules"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "verification.rs",
        allowed_internal: &["knowledge", "rules"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "web_actions.rs",
        allowed_internal: &[],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "web_reasoning.rs",
        allowed_internal: &["knowledge", "rules"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "api_reasoning.rs",
        allowed_internal: &["knowledge", "rules"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "api_evidence.rs",
        allowed_internal: &[],
        allowed_external: &["serde_json", "sha2"],
    },
    ModulePolicy {
        source: "api_observation.rs",
        allowed_internal: &["knowledge", "rules"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "web_planning.rs",
        allowed_internal: &["planner", "rules", "web_actions"],
        allowed_external: &[],
    },
    ModulePolicy {
        source: "web_verification.rs",
        allowed_internal: &["rules", "verification", "web_actions"],
        allowed_external: &[],
    },
];

/// Verifies the resolved workspace graph and protected production modules.
pub(crate) fn check(workspace_root: &Path) -> Result<(), Box<dyn Error>> {
    let mut violations = workspace_graph_violations(workspace_root)?;
    violations.extend(module_boundary_violations(workspace_root)?);
    violations.sort();
    violations.dedup();

    if violations.is_empty() {
        println!("architecture boundaries passed");
        return Ok(());
    }

    Err(Box::new(ArchitectureViolations(violations)))
}

fn workspace_graph_violations(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let metadata = MetadataCommand::new()
        .manifest_path(workspace_root.join("Cargo.toml"))
        .no_deps()
        .other_options(vec!["--locked".to_owned()])
        .exec()?;
    let workspace_packages = metadata.workspace_packages();
    let workspace_names: BTreeSet<_> = workspace_packages
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    let graph = workspace_packages
        .iter()
        .map(|package| {
            let dependencies = package
                .dependencies
                .iter()
                .filter(|dependency| workspace_names.contains(dependency.name.as_str()))
                .map(|dependency| dependency.name.clone())
                .collect();
            (package.name.clone(), dependencies)
        })
        .collect();

    Ok(validate_workspace_graph(&graph))
}

fn allowed_workspace_graph() -> BTreeMap<String, BTreeSet<String>> {
    [
        ("venom-core", &[][..]),
        ("venom-scanner", &["venom-core"][..]),
        ("venom-proxy", &["venom-core"][..]),
        ("venom-api", &["venom-core", "venom-scanner"][..]),
        (
            "venom-cli",
            &["venom-api", "venom-core", "venom-proxy", "venom-scanner"][..],
        ),
        ("venom-examples", &["venom-scanner"][..]),
        ("xtask", &[][..]),
    ]
    .into_iter()
    .map(|(package, dependencies)| {
        (
            package.to_owned(),
            dependencies
                .iter()
                .map(|dependency| (*dependency).to_owned())
                .collect(),
        )
    })
    .collect()
}

fn validate_workspace_graph(graph: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let allowed = allowed_workspace_graph();
    let mut violations = Vec::new();

    for (package, dependencies) in graph {
        let Some(allowed_dependencies) = allowed.get(package) else {
            violations.push(format!(
                "workspace package {package} has no architecture policy"
            ));
            continue;
        };
        for dependency in dependencies.difference(allowed_dependencies) {
            violations.push(format!(
                "workspace dependency {package} -> {dependency} is not allowed"
            ));
        }
    }

    for package in allowed.keys() {
        if !graph.contains_key(package) {
            violations.push(format!(
                "architecture policy references missing workspace package {package}"
            ));
        }
    }

    violations
}

fn module_boundary_violations(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let source_root = workspace_root.join("crates/venom-scanner/src");
    let mut violations = Vec::new();
    let library_source = fs::read_to_string(source_root.join("lib.rs"))?;
    violations.extend(validate_module_wiring(&library_source, MODULE_POLICIES)?);

    for policy in MODULE_POLICIES {
        let source_path = source_root.join(policy.source);
        let source = fs::read_to_string(&source_path)?;
        violations.extend(inspect_module_source(policy, &source)?);
    }

    Ok(violations)
}

fn validate_module_wiring(
    library_source: &str,
    policies: &[ModulePolicy],
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(library_source)?;
    let mut violations = validate_library_root_bindings(&syntax);
    let modules: Vec<_> = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(item) => Some(item),
            _ => None,
        })
        .collect();
    for policy in policies {
        let module = policy
            .source
            .strip_suffix(".rs")
            .expect("protected module source must end in .rs");
        let declarations: Vec<_> = modules
            .iter()
            .filter(|item| normalize_identifier(&item.ident.to_string()) == module)
            .collect();
        if declarations.len() != 1 {
            violations.push(format!(
                "lib.rs must declare exactly one public external module {module}; found {}",
                declarations.len()
            ));
            continue;
        }

        let declaration = declarations[0];
        if declaration.content.is_some() {
            violations.push(format!(
                "lib.rs declares protected module {module} inline; use pub mod {module};"
            ));
        }
        if !matches!(&declaration.vis, syn::Visibility::Public(_)) {
            violations.push(format!(
                "lib.rs must expose protected module {module} as pub mod {module};"
            ));
        }
        if !declaration.attrs.is_empty() {
            violations.push(format!(
                "lib.rs protected module {module} cannot have attributes; use exactly pub mod {module};"
            ));
        }
    }

    Ok(violations)
}

fn validate_library_root_bindings(syntax: &syn::File) -> Vec<String> {
    let mut violations = Vec::new();

    for attribute in &syntax.attrs {
        if !is_allowed_library_attribute(attribute) {
            violations.push(
                "lib.rs uses an unapproved crate attribute; architecture wiring must remain explicit"
                    .to_owned(),
            );
        }
    }

    for item in &syntax.items {
        for attribute in item_attributes(item) {
            if !is_allowed_library_attribute(attribute) {
                violations.push(
                    "lib.rs uses an unapproved item attribute; architecture wiring must remain explicit"
                        .to_owned(),
                );
            }
        }

        match item {
            Item::Mod(item) => {
                reject_reserved_library_binding(&ident_name(&item.ident), &mut violations);
            },
            Item::ExternCrate(item) => {
                let binding = item
                    .rename
                    .as_ref()
                    .map_or_else(|| ident_name(&item.ident), |(_, alias)| ident_name(alias));
                reject_reserved_library_binding(&binding, &mut violations);
            },
            Item::Use(item) => {
                let mut paths = Vec::new();
                collect_use_paths(&item.tree, Vec::new(), &mut paths);
                for (segments, binding, glob) in paths {
                    if glob {
                        violations.push(
                            "lib.rs cannot use glob imports; they can hide protected root bindings"
                                .to_owned(),
                        );
                        continue;
                    }
                    let Some(mut binding) = binding else {
                        continue;
                    };
                    if normalize_identifier(&binding) == "self" && segments.len() >= 2 {
                        binding = segments[segments.len() - 2].clone();
                    }
                    reject_reserved_library_binding(&binding, &mut violations);
                }
            },
            Item::Macro(item) => {
                if let Some(identifier) = &item.ident {
                    violations.push(format!(
                        "lib.rs cannot define item macro {}; architecture wiring must remain visible to the AST policy",
                        ident_name(identifier)
                    ));
                } else {
                    violations.push(
                        "lib.rs cannot invoke item macros; architecture wiring must remain visible to the AST policy"
                            .to_owned(),
                    );
                }
            },
            _ => {
                if let Some(identifier) = item_identifier(item) {
                    reject_reserved_library_binding(&identifier, &mut violations);
                }
            },
        }
    }

    violations
}

fn is_allowed_library_attribute(attribute: &Attribute) -> bool {
    let segments = &attribute.path().segments;
    segments.len() == 1
        && segments.first().is_some_and(|segment| {
            ALLOWED_LIBRARY_ATTRIBUTES.contains(&ident_name(&segment.ident).as_str())
        })
}

fn reject_reserved_library_binding(binding: &str, violations: &mut Vec<String>) {
    let binding = normalize_identifier(binding);
    if ALLOWED_EXTERNAL_ROOTS.contains(&binding) {
        violations.push(format!(
            "lib.rs cannot bind reserved external root {binding}; protected modules must resolve it directly"
        ));
    }
}

fn inspect_module_source(policy: &ModulePolicy, source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = BoundaryVisitor::new(*policy, &syntax.items);
    for item in &syntax.items {
        if let Item::Use(item) = item {
            if !has_conditional_cfg(&item.attrs) {
                visitor.inspect_use(item, true);
            }
        }
    }
    visitor.visit_file(&syntax);
    Ok(visitor.violations.into_iter().collect())
}

struct BoundaryVisitor {
    policy: ModulePolicy,
    scopes: Vec<BTreeSet<String>>,
    violations: BTreeSet<String>,
}

impl BoundaryVisitor {
    fn new(policy: ModulePolicy, items: &[Item]) -> Self {
        let module_roots = items
            .iter()
            .filter(|item| item_is_unconditional(item))
            .filter_map(item_identifier)
            .collect();
        Self {
            policy,
            scopes: vec![module_roots],
            violations: BTreeSet::new(),
        }
    }

    fn inspect_use(&mut self, item: &ItemUse, register_aliases: bool) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for (segments, alias, glob) in paths {
            if glob {
                self.violation(format!(
                    "{} uses forbidden glob import {}",
                    self.policy.source,
                    display_path(&segments)
                ));
                continue;
            }
            if is_include_macro_segments(&segments) {
                self.violation(format!(
                    "{} imports {}; protected source must remain in its policy-owned file",
                    self.policy.source,
                    display_path(&segments)
                ));
                continue;
            }
            let dependency_allowed = self.inspect_dependency(&segments);
            if register_aliases && dependency_allowed {
                if let Some(alias) = alias {
                    self.insert_known_root(alias);
                }
            }
        }
    }

    fn insert_known_root(&mut self, root: String) {
        self.scopes
            .last_mut()
            .expect("boundary visitor always has a module scope")
            .insert(normalize_identifier(&root).to_owned());
    }

    fn is_known_root(&self, root: &str) -> bool {
        let root = normalize_identifier(root);
        self.scopes.iter().rev().any(|scope| scope.contains(root))
    }

    fn push_scope(&mut self, roots: BTreeSet<String>) {
        self.scopes.push(roots);
    }

    fn push_generic_scope(&mut self, generics: &syn::Generics) {
        self.push_scope(
            generics
                .params
                .iter()
                .filter_map(|parameter| match parameter {
                    GenericParam::Type(parameter) => Some(ident_name(&parameter.ident)),
                    GenericParam::Lifetime(_) | GenericParam::Const(_) => None,
                })
                .collect(),
        );
    }

    fn pop_scope(&mut self) {
        assert!(
            self.scopes.len() > 1,
            "the boundary visitor module scope must not be popped"
        );
        self.scopes.pop();
    }

    fn inspect_dependency(&mut self, segments: &[String]) -> bool {
        let Some(root) = segments
            .first()
            .map(String::as_str)
            .map(normalize_identifier)
        else {
            return false;
        };
        if root == "crate" {
            let Some(dependency) = segments
                .get(1)
                .map(String::as_str)
                .map(normalize_identifier)
            else {
                self.violation(format!(
                    "{} aliases or imports the crate root; use an explicit crate::<module> path",
                    self.policy.source
                ));
                return false;
            };
            if !self.policy.allowed_internal.contains(&dependency) {
                self.violation(format!(
                    "{} depends on forbidden internal path {}; allowed internal roots: {}",
                    self.policy.source,
                    display_path(segments),
                    display_allowed(self.policy.allowed_internal)
                ));
                return false;
            }
            return true;
        }
        if matches!(root, "self" | "super") {
            self.violation(format!(
                "{} uses non-canonical import {}; use an explicit crate::<module> path",
                self.policy.source,
                display_path(segments)
            ));
            return false;
        }
        if root == "std"
            && (segments.len() == 1
                || segments
                    .get(1)
                    .is_some_and(|segment| normalize_identifier(segment) == "self"))
        {
            self.violation(format!(
                "{} aliases the std root; import an explicit allowed std module",
                self.policy.source
            ));
            return false;
        }
        if is_forbidden_std_path(segments) {
            self.violation(format!(
                "{} depends on forbidden side-effect path {}",
                self.policy.source,
                display_path(segments)
            ));
            return false;
        }
        if !self.allows_external(root) {
            self.violation(format!(
                "{} depends on unapproved external root {root}",
                self.policy.source
            ));
            return false;
        }
        true
    }

    fn inspect_path(&mut self, path: &SynPath) {
        let segments: Vec<_> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.inspect_qualified_segments(&segments);
    }

    fn inspect_qualified_segments(&mut self, segments: &[String]) {
        let Some(root) = segments
            .first()
            .map(String::as_str)
            .map(normalize_identifier)
        else {
            return;
        };
        if segments.len() == 1 && matches!(root, "crate" | "self" | "super") {
            return;
        }
        if root == "crate" {
            self.inspect_dependency(segments);
            return;
        }
        if root == "std" {
            self.inspect_dependency(segments);
            return;
        }
        if segments.len() < 2
            || root == "Self"
            || self.allows_external(root)
            || PRIMITIVE_ROOTS.contains(&root)
            || PRELUDE_ROOTS.contains(&root)
            || self.is_known_root(root)
        {
            return;
        }
        self.violation(format!(
            "{} uses unresolved or unapproved path {}; import dependencies explicitly",
            self.policy.source,
            display_path(segments)
        ));
    }

    fn inspect_macro_tokens(&mut self, stream: TokenStream) {
        self.inspect_token_paths(stream, &[]);
    }

    fn inspect_token_paths(&mut self, stream: TokenStream, ignored_roots: &[&str]) {
        let tokens: Vec<_> = stream.into_iter().collect();
        for token in &tokens {
            if let TokenTree::Group(group) = token {
                self.inspect_token_paths(group.stream(), ignored_roots);
            }
        }

        for start in 0..tokens.len() {
            let TokenTree::Ident(root) = &tokens[start] else {
                continue;
            };
            if is_include_macro_name(&root.to_string())
                && tokens
                    .get(start + 1)
                    .is_some_and(|token| is_punctuation(token, '!'))
            {
                self.violation(format!(
                    "{} uses nested {}; protected source must remain in its policy-owned file",
                    self.policy.source, root
                ));
            }
            let mut segments = vec![root.to_string()];
            let mut cursor = start + 1;
            while cursor + 2 < tokens.len()
                && is_colon(&tokens[cursor])
                && is_colon(&tokens[cursor + 1])
            {
                let TokenTree::Ident(segment) = &tokens[cursor + 2] else {
                    break;
                };
                segments.push(segment.to_string());
                cursor += 3;
            }
            if segments.len() > 1 && !ignored_roots.contains(&normalize_identifier(&segments[0])) {
                self.inspect_qualified_segments(&segments);
            }
        }
    }

    fn inspect_attribute_tokens(&mut self, stream: TokenStream) {
        self.inspect_token_paths(stream.clone(), ATTRIBUTE_NON_DEPENDENCY_ROOTS);
        let tokens: Vec<_> = stream.into_iter().collect();

        for token in &tokens {
            if let TokenTree::Group(group) = token {
                self.inspect_attribute_tokens(group.stream());
            }
        }

        for window in tokens.windows(3) {
            let [TokenTree::Ident(key), equals, TokenTree::Literal(value)] = window else {
                continue;
            };
            if !is_punctuation(equals, '=')
                || !CODE_STRING_ATTRIBUTE_KEYS.contains(&normalize_identifier(&key.to_string()))
            {
                continue;
            }
            let Ok(value) = syn::parse_str::<LitStr>(&value.to_string()) else {
                continue;
            };
            let value = value.value();
            if let Ok(tokens) = TokenStream::from_str(&value) {
                self.inspect_macro_tokens(tokens);
            }
            if let Ok(path) = syn::parse_str::<SynPath>(&value) {
                let segments: Vec<_> = path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                if segments.len() == 1 {
                    let root = normalize_identifier(&segments[0]);
                    if !self.allows_external(root)
                        && !PRELUDE_ROOTS.contains(&root)
                        && !PRIMITIVE_ROOTS.contains(&root)
                        && !self.is_known_root(root)
                    {
                        self.violation(format!(
                            "{} uses unresolved or unapproved attribute path {root}",
                            self.policy.source
                        ));
                    }
                } else {
                    self.inspect_qualified_segments(&segments);
                }
            }
        }
    }

    fn violation(&mut self, message: String) {
        self.violations.insert(message);
    }

    fn allows_external(&self, root: &str) -> bool {
        ALLOWED_EXTERNAL_ROOTS.contains(&root) || self.policy.allowed_external.contains(&root)
    }
}

impl<'ast> Visit<'ast> for BoundaryVisitor {
    fn visit_attribute(&mut self, item: &'ast Attribute) {
        if let Meta::List(list) = &item.meta {
            self.inspect_attribute_tokens(list.tokens.clone());
        }
        visit::visit_attribute(self, item);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if has_cfg_test(item_attributes(item)) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_block(&mut self, item: &'ast syn::Block) {
        let roots = item
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Item(item) if item_is_unconditional(item) => item_identifier(item),
                _ => None,
            })
            .collect();
        self.push_scope(roots);
        for statement in &item.stmts {
            if let Stmt::Item(Item::Use(item)) = statement {
                if !has_conditional_cfg(&item.attrs) {
                    self.inspect_use(item, true);
                }
            }
        }
        visit::visit_block(self, item);
        self.pop_scope();
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_const(self, item);
        self.pop_scope();
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_enum(self, item);
        self.pop_scope();
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.push_generic_scope(&item.sig.generics);
        visit::visit_item_fn(self, item);
        self.pop_scope();
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_impl(self, item);
        self.pop_scope();
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_struct(self, item);
        self.pop_scope();
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_trait(self, item);
        self.pop_scope();
    }

    fn visit_item_trait_alias(&mut self, item: &'ast syn::ItemTraitAlias) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_trait_alias(self, item);
        self.pop_scope();
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_type(self, item);
        self.pop_scope();
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        self.push_generic_scope(&item.generics);
        visit::visit_item_union(self, item);
        self.pop_scope();
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        self.push_generic_scope(&item.generics);
        visit::visit_impl_item_const(self, item);
        self.pop_scope();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.push_generic_scope(&item.sig.generics);
        visit::visit_impl_item_fn(self, item);
        self.pop_scope();
    }

    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        self.push_generic_scope(&item.generics);
        visit::visit_impl_item_type(self, item);
        self.pop_scope();
    }

    fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
        self.push_generic_scope(&item.generics);
        visit::visit_trait_item_const(self, item);
        self.pop_scope();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        self.push_generic_scope(&item.sig.generics);
        visit::visit_trait_item_fn(self, item);
        self.pop_scope();
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        self.push_generic_scope(&item.generics);
        visit::visit_trait_item_type(self, item);
        self.pop_scope();
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        self.violation(format!(
            "{} declares extern crate {}; use an approved explicit import",
            self.policy.source, item.ident
        ));
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.inspect_use(item, !has_conditional_cfg(&item.attrs));
        visit::visit_item_use(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        self.violation(format!(
            "{} declares production submodule {}; add the file to the architecture policy instead",
            self.policy.source, item.ident
        ));
    }

    fn visit_item_macro(&mut self, item: &'ast ItemMacro) {
        if item.ident.is_some() || item.mac.path.is_ident("macro_rules") {
            self.violation(format!(
                "{} defines a local macro; protected dependencies must remain visible to the AST policy",
                self.policy.source
            ));
            return;
        }
        visit::visit_item_macro(self, item);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        if is_include_macro_path(&item.path) {
            self.violation(format!(
                "{} uses {}; protected source must remain in its policy-owned file",
                self.policy.source,
                display_syn_path(&item.path)
            ));
            return;
        }
        self.inspect_macro_tokens(item.tokens.clone());
        visit::visit_macro(self, item);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        self.inspect_path(path);
        visit::visit_path(self, path);
    }
}

fn is_colon(token: &TokenTree) -> bool {
    is_punctuation(token, ':')
}

fn is_punctuation(token: &TokenTree, expected: char) -> bool {
    matches!(token, TokenTree::Punct(punctuation) if punctuation.as_char() == expected)
}

fn normalize_identifier(identifier: &str) -> &str {
    identifier.strip_prefix("r#").unwrap_or(identifier)
}

fn ident_name(identifier: &proc_macro2::Ident) -> String {
    normalize_identifier(&identifier.to_string()).to_owned()
}

fn is_forbidden_std_path(segments: &[String]) -> bool {
    segments
        .first()
        .is_some_and(|root| normalize_identifier(root) == "std")
        && segments
            .get(1)
            .is_some_and(|root| FORBIDDEN_STD_ROOTS.contains(&normalize_identifier(root)))
}

fn is_include_macro_name(name: &str) -> bool {
    matches!(
        normalize_identifier(name),
        "include" | "include_str" | "include_bytes"
    )
}

fn is_include_macro_path(path: &SynPath) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| is_include_macro_name(&segment.ident.to_string()))
}

fn is_include_macro_segments(segments: &[String]) -> bool {
    segments
        .last()
        .is_some_and(|segment| is_include_macro_name(segment))
}

fn collect_use_paths(
    tree: &UseTree,
    mut prefix: Vec<String>,
    output: &mut Vec<(Vec<String>, Option<String>, bool)>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_paths(&path.tree, prefix, output);
        },
        UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            output.push((prefix, Some(name.ident.to_string()), false));
        },
        UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            output.push((prefix, Some(rename.rename.to_string()), false));
        },
        UseTree::Glob(_) => output.push((prefix, None, true)),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix.clone(), output);
            }
        },
    }
}

fn item_attributes(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn item_is_unconditional(item: &Item) -> bool {
    !has_conditional_cfg(item_attributes(item))
}

fn has_conditional_cfg(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

fn item_identifier(item: &Item) -> Option<String> {
    match item {
        Item::Const(item) => Some(ident_name(&item.ident)),
        Item::Enum(item) => Some(ident_name(&item.ident)),
        Item::Fn(item) => Some(ident_name(&item.sig.ident)),
        Item::Static(item) => Some(ident_name(&item.ident)),
        Item::Struct(item) => Some(ident_name(&item.ident)),
        Item::Trait(item) => Some(ident_name(&item.ident)),
        Item::TraitAlias(item) => Some(ident_name(&item.ident)),
        Item::Type(item) => Some(ident_name(&item.ident)),
        Item::Union(item) => Some(ident_name(&item.ident)),
        _ => None,
    }
}

fn has_cfg_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "test")
    })
}

fn display_path(segments: &[String]) -> String {
    if segments.is_empty() {
        "*".to_owned()
    } else {
        segments.join("::")
    }
}

fn display_syn_path(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn display_allowed(allowed: &[&str]) -> String {
    if allowed.is_empty() {
        "none".to_owned()
    } else {
        allowed
            .iter()
            .map(|module| format!("crate::{module}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug)]
struct ArchitectureViolations(Vec<String>);

impl fmt::Display for ArchitectureViolations {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "architecture boundary violations:")?;
        for violation in &self.0 {
            writeln!(formatter, "- {violation}")?;
        }
        Ok(())
    }
}

impl Error for ArchitectureViolations {}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(source: &'static str, allowed_internal: &'static [&'static str]) -> ModulePolicy {
        ModulePolicy {
            source,
            allowed_internal,
            allowed_external: &[],
        }
    }

    fn policy_with_external(
        source: &'static str,
        allowed_internal: &'static [&'static str],
        allowed_external: &'static [&'static str],
    ) -> ModulePolicy {
        ModulePolicy {
            source,
            allowed_internal,
            allowed_external,
        }
    }

    #[test]
    fn current_workspace_satisfies_architecture_policy() {
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask must live under the workspace root");
        check(workspace_root).unwrap();
    }

    #[test]
    fn workspace_allowlist_rejects_reverse_and_unknown_edges() {
        let mut graph = allowed_workspace_graph();
        graph
            .get_mut("venom-core")
            .unwrap()
            .insert("venom-scanner".to_owned());
        graph.insert(
            "venom-product".to_owned(),
            BTreeSet::from(["venom-core".to_owned()]),
        );

        let violations = validate_workspace_graph(&graph).join("\n");
        assert!(violations.contains("venom-core -> venom-scanner"));
        assert!(violations.contains("venom-product has no architecture policy"));
    }

    #[test]
    fn protected_modules_require_canonical_library_wiring() {
        let policies = [
            policy("experience.rs", &[]),
            policy("planner.rs", &[]),
            policy("rules.rs", &[]),
            policy("verification.rs", &[]),
            policy("web_actions.rs", &[]),
        ];
        let source = r#"
            pub mod experience;
            #[path = "planner_unchecked.rs"]
            pub mod planner;
            #[rewriter::replace]
            pub mod web_actions;
            pub mod rules {}
            mod verification;
        "#;
        let violations = validate_module_wiring(source, &policies)
            .unwrap()
            .join("\n");
        assert!(violations.contains("planner cannot have attributes"));
        assert!(violations.contains("web_actions cannot have attributes"));
        assert!(violations.contains("declares protected module rules inline"));
        assert!(violations.contains("expose protected module verification"));
        assert!(!violations.contains("experience"));
    }

    #[test]
    fn library_cannot_shadow_approved_external_roots() {
        let source = r#"
            pub mod serde {}
            pub use crate::web_execution as venom_core;
            extern crate self as std;
            use facade::{self as core, *};
            #[doc::rewrite]
            struct Placeholder;
            macro_rules! hidden_runtime { () => {} }
            rewriter::items!();
        "#;
        let violations = validate_module_wiring(source, &[]).unwrap().join("\n");
        for root in ["serde", "venom_core", "std", "core"] {
            assert!(
                violations.contains(&format!("reserved external root {root}")),
                "missing shadowing violation for {root}: {violations}"
            );
        }
        assert!(violations.contains("cannot use glob imports"));
        assert!(violations.contains("unapproved item attribute"));
        assert!(violations.contains("cannot define item macro hidden_runtime"));
        assert!(violations.contains("cannot invoke item macros"));
    }

    #[test]
    fn canonical_allowed_imports_pass() {
        let source = r#"
            use std::collections::BTreeMap;
            use venom_core::Outcome;
            use crate::{
                knowledge::KnowledgeSnapshot as Snapshot,
                rules::{Expression, RuleEngineError},
            };

            fn evaluate(_: Snapshot, _: Expression) -> Result<(), RuleEngineError> { Ok(()) }
        "#;
        assert!(
            inspect_module_source(&policy("planner.rs", &["knowledge", "rules"]), source)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn module_specific_external_roots_do_not_weaken_other_policies() {
        let source = r#"
            use serde_json::Value;
            use sha2::{Digest, Sha256};
            fn fingerprint(value: &Value) { let _ = Sha256::digest(value.to_string()); }
        "#;
        assert!(inspect_module_source(
            &policy_with_external("api_evidence.rs", &[], &["serde_json", "sha2"]),
            source,
        )
        .unwrap()
        .is_empty());

        let violations = inspect_module_source(&policy("rules.rs", &["knowledge"]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("unapproved external root serde_json"));
        assert!(violations.contains("unapproved external root sha2"));
    }

    #[test]
    fn grouped_aliases_cannot_hide_execution_dependencies() {
        let source = r#"
            use crate::{knowledge::KnowledgeSnapshot, decision_runner::DecisionRunnerAdapter as Adapter};
            use reqwest as transport;
        "#;
        let violations =
            inspect_module_source(&policy("verification.rs", &["knowledge", "rules"]), source)
                .unwrap()
                .join("\n");
        assert!(violations.contains("crate::decision_runner"));
        assert!(violations.contains("unapproved external root reqwest"));
    }

    #[test]
    fn qualified_paths_and_globs_are_checked() {
        let source = r#"
            use crate::knowledge::*;
            fn leak() { let _ = crate::planner::AttackPlanner::new(); }
        "#;
        let violations = inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("forbidden glob import"));
        assert!(violations.contains("crate::planner::AttackPlanner"));
    }

    #[test]
    fn test_modules_do_not_create_production_edges() {
        let source = r#"
            use venom_core::Outcome;
            #[cfg(test)]
            mod tests {
                use crate::decision_runner::DecisionRunnerAdapter;
            }
        "#;
        assert!(inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn crate_aliases_cannot_hide_forbidden_paths() {
        let source = r#"
            use crate as scanner;
            fn leak() { let _ = scanner::web_execution::STANDARD_WEB_DISCOVERY_ACTIONS; }
        "#;
        let violations =
            inspect_module_source(&policy("verification.rs", &["knowledge", "rules"]), source)
                .unwrap()
                .join("\n");
        assert!(violations.contains("aliases or imports the crate root"));
        assert!(violations.contains("unresolved or unapproved path scanner::web_execution"));
    }

    #[test]
    fn helper_modules_and_includes_cannot_escape_policy() {
        let source = r#"
            mod helper;
            include!("generated.rs");
            macro_rules! hidden_dependency { () => {} }
        "#;
        let violations =
            inspect_module_source(&policy("planner.rs", &["knowledge", "rules"]), source)
                .unwrap()
                .join("\n");
        assert!(violations.contains("declares production submodule helper"));
        assert!(violations.contains("uses include"));
        assert!(violations.contains("defines a local macro"));
    }

    #[test]
    fn extern_crate_aliases_and_uppercase_roots_cannot_escape_policy() {
        let source = r#"
            extern crate self as Scanner;
            extern crate reqwest as Http;
            fn leak() {
                let _ = Scanner::web_execution::STANDARD_WEB_DISCOVERY_ACTIONS;
                let _ = Http::Client::new();
            }
        "#;
        let violations =
            inspect_module_source(&policy("verification.rs", &["knowledge", "rules"]), source)
                .unwrap()
                .join("\n");
        assert!(violations.contains("declares extern crate self"));
        assert!(violations.contains("declares extern crate reqwest"));
        assert!(violations.contains("unresolved or unapproved path Scanner::web_execution"));
        assert!(violations.contains("unresolved or unapproved path Http::Client"));
    }

    #[test]
    fn test_named_modules_require_an_exact_test_cfg() {
        let source = r#"
            mod tests {
                use crate::web_execution::StandardWebDiscoveryExecutor;
            }

            #[cfg(any(test, feature = "scanning"))]
            mod conditional_tests {
                use crate::decision_runner::DecisionRunnerAdapter;
            }
        "#;
        let violations = inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("declares production submodule tests"));
        assert!(violations.contains("declares production submodule conditional_tests"));
    }

    #[test]
    fn macro_tokens_and_qualified_includes_are_checked() {
        let source = r#"
            use std::include as load;
            fn leak() {
                let _ = vec![crate::web_execution::STANDARD_WEB_DISCOVERY_ACTIONS];
                let _ = matches!(crate::decision_runner::DecisionRunnerAdapter, _);
                std::include!("generated.rs");
                load!("also-generated.rs");
            }
        "#;
        let violations = inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("imports std::include"));
        assert!(violations.contains("crate::web_execution"));
        assert!(violations.contains("crate::decision_runner"));
        assert!(violations.contains("uses std::include"));
    }

    #[test]
    fn aliases_generics_and_cfg_items_do_not_escape_their_scope() {
        let source = r#"
            fn local_alias() {
                use std::mem as Transport;
                let _ = Transport::size_of::<u8>();
            }

            fn generic<GenericRoot>() {
                let _ = GenericRoot::associated;
            }

            #[cfg(any())]
            struct ConditionalRoot;

            fn leak() {
                let _ = Transport::Client::new();
                let _ = GenericRoot::Client::new();
                let _ = ConditionalRoot::Client::new();
            }
        "#;
        let violations = inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("Transport::Client"));
        assert!(violations.contains("GenericRoot::Client"));
        assert!(violations.contains("ConditionalRoot::Client"));
        assert!(!violations.contains("Transport::size_of"));
        assert!(!violations.contains("GenericRoot::associated"));
    }

    #[test]
    fn attribute_payloads_cannot_hide_dependencies() {
        let source = r#"
            #[cfg_attr(all(), async_trait::async_trait)]
            #[serde(with = "crate::web_execution::wire")]
            struct Wire {
                #[serde(skip_serializing_if = "crate::decision_runner::is_empty")]
                value: String,
            }
        "#;
        let violations = inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("async_trait::async_trait"));
        assert!(violations.contains("crate::web_execution"));
        assert!(violations.contains("crate::decision_runner"));
    }

    #[test]
    fn side_effectful_standard_library_paths_are_rejected() {
        let source = r#"
            use std::{net::TcpStream, process::Command};
            use std as system;
            fn leak() {
                let _ = std::net::UdpSocket::bind("127.0.0.1:0");
                let _ = std::process::Command::new("curl");
                let _ = std::r#net::TcpStream::connect("127.0.0.1:80");
                let _ = std::r#process::Command::new("curl");
                let _ = system::net::TcpStream::connect("127.0.0.1:80");
            }
        "#;
        let violations =
            inspect_module_source(&policy("verification.rs", &["knowledge", "rules"]), source)
                .unwrap()
                .join("\n");
        assert!(violations.contains("std::net::TcpStream"));
        assert!(violations.contains("std::process::Command"));
        assert!(violations.contains("std::net::UdpSocket"));
        assert!(violations.contains("std::r#net::TcpStream"));
        assert!(violations.contains("std::r#process::Command"));
        assert!(violations.contains("aliases the std root"));
        assert!(violations.contains("system::net::TcpStream"));
    }

    #[test]
    fn nested_include_macros_cannot_escape_policy() {
        let source = r#"
            fn leak() {
                let _ = vec![include!("generated.rs")];
                let _ = vec![r#include!("raw-generated.rs")];
                let _ = vec![crate::r#web_execution::STANDARD_WEB_DISCOVERY_ACTIONS];
            }
        "#;
        let violations = inspect_module_source(&policy("experience.rs", &[]), source)
            .unwrap()
            .join("\n");
        assert!(violations.contains("uses nested include"));
        assert!(violations.contains("crate::r#web_execution"));
    }
}
