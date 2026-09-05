//! Machine-enforced boundary for CLI authorization-context secret input.
//!
//! The CLI may identify one out-of-band source, but it must not accept raw
//! credential bytes as an argument, expose source identifiers through common
//! traits, or read a source before every non-secret preflight has passed.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use proc_macro2::{TokenStream, TokenTree};
use syn::{
    parse::Parser,
    visit::{self, Visit},
    Attribute, Expr, Fields, FnArg, ImplItem, Item, ItemEnum, ItemFn, Meta, Pat, ReturnType, Type,
    Visibility,
};

const AUTH_INPUT_SOURCE: &str = "crates/termivar-cli/src/auth_input.rs";
const CLI_MAIN_SOURCE: &str = "crates/termivar-cli/src/main.rs";
const SCANNER_CONTEXT_SOURCE: &str =
    "crates/termivar-scanner/src/web_runtime/assessment_api_visibility.rs";
const PAYLOAD_STRATEGY_SOURCE: &str = "crates/termivar-scanner/src/payload_strategy.rs";

const AUTH_SOURCE_VARIANTS: &[(&str, Option<&str>)] = &[
    ("Environment", Some("OsString")),
    ("File", Some("PathBuf")),
    ("Stdin", None),
];
const AUTH_ERROR_VARIANTS: &[&str] = &[
    "ConflictingSources",
    "SourceNameInvalid",
    "SourceUnavailable",
    "SourceNotRegularFile",
    "SourceNotUnicode",
    "SourceReadFailed",
    "ValueTooLarge",
    "InvalidValue",
];
const CLI_AUTH_FIELDS: &[&str] = &[
    "authorization_review_policy",
    "auth_env",
    "auth_file",
    "auth_stdin",
    "authz_peer_env",
    "authz_peer_file",
    "authz_peer_stdin",
    "authz_primary_env",
    "authz_primary_file",
    "authz_primary_stdin",
];
const CLI_SCAN_FIELDS: &[&str] = &[
    "authorization_review_policy",
    "auth_env",
    "auth_file",
    "auth_stdin",
    "authz_peer_env",
    "authz_peer_file",
    "authz_peer_stdin",
    "authz_primary_env",
    "authz_primary_file",
    "authz_primary_stdin",
    "enforce_defense",
    "explain",
    "format",
    "graphql_review",
    "normalization_resilience",
    "oast_admin_token_env",
    "oast_admin_token_file",
    "oast_admin_token_stdin",
    "openapi_review",
    "rest_review",
    "profile",
    "report_dir",
    "report_format",
    "report_output",
    "ssrf_oast_policy",
    "ssrf_oast_review",
    "target",
];

pub(super) fn check(workspace_root: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let auth_input = fs::read_to_string(workspace_root.join(AUTH_INPUT_SOURCE))?;
    let cli_main = fs::read_to_string(workspace_root.join(CLI_MAIN_SOURCE))?;
    let scanner_context = fs::read_to_string(workspace_root.join(SCANNER_CONTEXT_SOURCE))?;
    let payload_strategy = fs::read_to_string(workspace_root.join(PAYLOAD_STRATEGY_SOURCE))?;

    let mut violations = inspect_auth_input_contract(&auth_input)?;
    violations.extend(inspect_cli_auth_surface(&cli_main)?);
    violations.extend(inspect_scanner_context_validation(
        &scanner_context,
        &payload_strategy,
    )?);
    violations.extend(protected_type_cross_source_violations(workspace_root)?);
    Ok(violations)
}

fn protected_type_cross_source_violations(
    workspace_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let roots = [
        (
            workspace_root.join("crates/termivar-cli/src"),
            AUTH_INPUT_SOURCE,
            &[
                "AuthorizationInputSource",
                "CredentialBytes",
                "AuthorizationInputError",
                "AuthorizationReviewInput",
                "AuthorizationReviewInputError",
                "AuthorizationSourceOptions",
            ][..],
        ),
        (
            workspace_root.join("crates/termivar-cli/src"),
            CLI_MAIN_SOURCE,
            &["Cli", "Commands", "ScanArgs"][..],
        ),
        (
            workspace_root.join("crates/termivar-scanner/src"),
            SCANNER_CONTEXT_SOURCE,
            &["WebAssessmentRootAuthorizationContext"][..],
        ),
    ];
    let mut violations = Vec::new();
    for (root, owner, protected) in roots {
        for path in rust_sources_below(&root)? {
            let relative = path
                .strip_prefix(workspace_root)?
                .to_string_lossy()
                .replace('\\', "/");
            if relative == owner {
                continue;
            }
            let source = fs::read_to_string(&path)?;
            violations.extend(external_protected_type_violations(
                &relative, &source, protected,
            )?);
        }
    }
    Ok(violations)
}

fn rust_sources_below(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut pending = vec![root.to_owned()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
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

fn external_protected_type_violations(
    path: &str,
    source: &str,
    protected: &[&str],
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut use_aliases = ProtectedUseAliasVisitor {
        protected: protected.iter().copied().collect(),
        aliases: BTreeSet::new(),
    };
    use_aliases.visit_file(&syntax);
    let renamed_imports = use_aliases.aliases.clone();
    let mut aliases = ProtectedAliasVisitor {
        protected: protected.iter().copied().collect(),
        aliases: use_aliases.aliases,
    };
    aliases.visit_file(&syntax);
    let mut visitor = ProtectedExposureVisitor {
        path,
        protected: protected.iter().copied().collect(),
        aliases: aliases.aliases,
        violations: Vec::new(),
    };
    if !renamed_imports.is_empty() {
        visitor.violations.push(format!(
            "protected CLI/scanner authorization type is imported under an alias outside its owner in `{path}`"
        ));
    }
    visitor.visit_file(&syntax);
    Ok(visitor.violations)
}

struct ProtectedUseAliasVisitor<'a> {
    protected: BTreeSet<&'a str>,
    aliases: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ProtectedUseAliasVisitor<'_> {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        collect_protected_use_aliases(&item.tree, &self.protected, &mut self.aliases);
        visit::visit_item_use(self, item);
    }
}

fn collect_protected_use_aliases(
    tree: &syn::UseTree,
    protected: &BTreeSet<&str>,
    aliases: &mut BTreeSet<String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            collect_protected_use_aliases(path.tree.as_ref(), protected, aliases);
        },
        syn::UseTree::Rename(rename) if protected.contains(rename.ident.to_string().as_str()) => {
            aliases.insert(rename.rename.to_string());
        },
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_protected_use_aliases(item, protected, aliases);
            }
        },
        syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {},
    }
}

struct ProtectedAliasVisitor<'a> {
    protected: BTreeSet<&'a str>,
    aliases: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for ProtectedAliasVisitor<'_> {
    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if type_references_any(item.ty.as_ref(), &self.protected)
            || type_references_alias(item.ty.as_ref(), &self.aliases)
        {
            self.aliases.insert(item.ident.to_string());
        }
        visit::visit_item_type(self, item);
    }
}

struct ProtectedExposureVisitor<'a> {
    path: &'a str,
    protected: BTreeSet<&'a str>,
    aliases: BTreeSet<String>,
    violations: Vec<String>,
}

impl<'ast> Visit<'ast> for ProtectedExposureVisitor<'_> {
    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if self.aliases.contains(item.ident.to_string().as_str()) {
            self.violations.push(format!(
                "protected CLI/scanner authorization type is aliased outside its owner in `{}`",
                self.path
            ));
        }
        visit::visit_item_type(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if type_references_any(item.self_ty.as_ref(), &self.protected)
            || type_references_alias(item.self_ty.as_ref(), &self.aliases)
        {
            self.violations.push(format!(
                "protected CLI/scanner authorization type gains an inherent or trait implementation outside its owner in `{}`",
                self.path
            ));
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        let tokens = compact_tokens(&item.mac.tokens);
        if macro_references_protected(&tokens, &self.protected, &self.aliases) {
            self.violations.push(format!(
                "protected CLI/scanner authorization type is referenced by an item macro outside its owner in `{}`",
                self.path
            ));
        }
        visit::visit_item_macro(self, item);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        let tokens = compact_tokens(&item.tokens);
        if macro_references_protected(&tokens, &self.protected, &self.aliases)
            && [
                "impl",
                "derive",
                "Debug",
                "Display",
                "AsRef",
                "Borrow",
                "Deref",
                "Serialize",
                "Clone",
                "Copy",
                "From",
                "Into",
            ]
            .iter()
            .any(|marker| tokens.contains(marker))
        {
            self.violations.push(format!(
                "protected CLI/scanner authorization type is referenced by a trait-generating macro outside its owner in `{}`",
                self.path
            ));
        }
        visit::visit_macro(self, item);
    }
}

fn macro_references_protected(
    tokens: &str,
    protected: &BTreeSet<&str>,
    aliases: &BTreeSet<String>,
) -> bool {
    protected.iter().any(|name| tokens.contains(name))
        || aliases.iter().any(|name| tokens.contains(name))
}

fn type_references_any(item_type: &Type, protected: &BTreeSet<&str>) -> bool {
    let mut visitor = TypeIdentifierVisitor::default();
    visitor.visit_type(item_type);
    visitor
        .identifiers
        .iter()
        .any(|identifier| protected.contains(identifier.as_str()))
}

fn type_references_alias(item_type: &Type, aliases: &BTreeSet<String>) -> bool {
    let mut visitor = TypeIdentifierVisitor::default();
    visitor.visit_type(item_type);
    visitor
        .identifiers
        .iter()
        .any(|identifier| aliases.contains(identifier))
}

fn inspect_auth_input_contract(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let compact = compact_source(source);
    let contracts = contract_items(source)?;
    let mut violations = Vec::new();

    let ceiling_is_exact = syntax.items.iter().any(|item| {
        matches!(item, Item::Const(item)
            if item.ident == "MAX_AUTHORIZATION_CONTEXT_BYTES"
                && is_pub_crate(&item.vis)
                && is_plain_type(item.ty.as_ref(), "usize")
                && is_default_payload_ceiling_cast(item.expr.as_ref()))
    });
    if !ceiling_is_exact {
        violations.push(
            "CLI authorization input ceiling must remain the exact crate-private cast of DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES"
                .to_owned(),
        );
    }

    let source_enum = find_enum(&syntax, "AuthorizationInputSource");
    if source_enum.is_none_or(|item| {
        !is_pub_crate(&item.vis)
            || has_derive_attribute(&item.attrs)
            || !enum_variants_are_exact(item, AUTH_SOURCE_VARIANTS)
    }) {
        violations.push(
            "AuthorizationInputSource must remain an underived crate-private enum of only Environment(OsString), File(PathBuf), and Stdin"
                .to_owned(),
        );
    }

    let source_traits = explicit_trait_impls(&syntax, "AuthorizationInputSource");
    if source_traits != BTreeSet::from(["Debug".to_owned()]) {
        violations.push(format!(
            "AuthorizationInputSource may implement only its exact redacted Debug trait; observed {source_traits:?}"
        ));
    }
    if !compact.contains(
        "Self::Environment(_)=>\"environment\",Self::File(_)=>\"file\",Self::Stdin=>\"stdin\",",
    ) || !compact.contains(
        "formatter.debug_struct(\"AuthorizationInputSource\").field(\"source\",&source).field(\"location\",&\"<redacted>\").finish()",
    ) {
        violations.push(
            "AuthorizationInputSource Debug must expose only the source kind and an exact <redacted> location"
                .to_owned(),
        );
    }

    let methods = inherent_methods(&syntax, "AuthorizationInputSource");
    if methods.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["load", "read_bytes", "select"])
    {
        violations.push(format!(
            "AuthorizationInputSource method inventory must remain exactly select, consuming load, and private consuming byte transfer; observed {:?}",
            methods.keys().collect::<Vec<_>>()
        ));
    }
    if methods
        .get("select")
        .is_none_or(|method| !select_signature_is_exact(method))
    {
        violations.push(
            "AuthorizationInputSource::select must accept exactly one optional OsString name, optional PathBuf, and stdin flag without reading"
                .to_owned(),
        );
    }
    if methods
        .get("load")
        .is_none_or(|method| !load_signature_is_exact(method))
        || !compact.contains(
            "WebAssessmentRootAuthorizationContext::new(bytes.into_owned()).map_err(|_|AuthorizationInputError::InvalidValue)",
        )
    {
        violations.push(
            "AuthorizationInputSource::load must consume the source and pass bounded bytes directly to the scanner-owned authorization-context constructor"
                .to_owned(),
        );
    }

    let error_enum = find_enum(&syntax, "AuthorizationInputError");
    if error_enum.is_none_or(|item| {
        !is_pub_crate(&item.vis)
            || !enum_unit_variants_are_exact(item, AUTH_ERROR_VARIANTS)
            || derive_identifiers(&item.attrs)
                != BTreeSet::from([
                    "Clone".to_owned(),
                    "Copy".to_owned(),
                    "Debug".to_owned(),
                    "Eq".to_owned(),
                    "PartialEq".to_owned(),
                ])
    }) {
        violations.push(
            "AuthorizationInputError must remain the exact value-free unit-variant error contract"
                .to_owned(),
        );
    }
    let error_traits = explicit_trait_impls(&syntax, "AuthorizationInputError");
    if error_traits != BTreeSet::from(["Display".to_owned(), "Error".to_owned()])
        || !static_error_display_is_exact(&compact)
    {
        violations.push(
            "AuthorizationInputError must expose only static credential-free Display and Error implementations"
                .to_owned(),
        );
    }

    for (function_name, message) in [
        (
            "read_environment",
            "CLI environment authorization input must remain a private bounded, value-free reader",
        ),
        (
            "read_bounded_line_source",
            "CLI file/stdin authorization input must remain one private bounded reader",
        ),
    ] {
        if find_function(&syntax, function_name)
            .is_none_or(|function| !matches!(function.vis, Visibility::Inherited))
        {
            violations.push(message.to_owned());
        }
    }

    if !guarded_intake_is_exact(&contracts) {
        violations.push(
            "CLI intake must remain a private non-cloneable Zeroizing guard with redacted Debug, live-storage wiping, and consuming allocation handoff"
                .to_owned(),
        );
    }
    if !bounded_reader_is_exact(&contracts) {
        violations.push(
            "CLI file/stdin reader must retain at most 4 KiB plus one CRLF, probe one overflow byte, remove only one terminal line ending, and fail closed"
                .to_owned(),
        );
    }
    if !environment_reader_is_exact(&contracts) {
        violations.push(
            "CLI environment reader must validate the source name, discard OS diagnostics, and enforce the 4 KiB ceiling before construction"
                .to_owned(),
        );
    }
    if !regular_file_open_is_exact(&contracts) {
        violations.push(
            "CLI file authorization source must use exact platform no-follow flags and reject reparse/non-regular opened handles before reading, without retaining filesystem diagnostics"
                .to_owned(),
        );
    }
    if !source_dispatch_is_exact(&contracts) {
        violations.push(
            "CLI authorization source dispatch must use the bounded reader for file/stdin and discard all source-location diagnostics"
                .to_owned(),
        );
    }
    for forbidden in [
        "fs::read(",
        "fs::read_to_string(",
        "std::fs::read(",
        "std::fs::read_to_string(",
        "read_to_string(",
        "from_utf8_unchecked",
    ] {
        if compact.contains(forbidden) {
            violations.push(format!(
                "CLI authorization input contains forbidden unbounded or unchecked read surface `{forbidden}`"
            ));
        }
    }

    violations.extend(inspect_authorization_review_input_contract(
        &syntax, &compact,
    ));

    Ok(violations)
}

fn inspect_authorization_review_input_contract(syntax: &syn::File, compact: &str) -> Vec<String> {
    let mut violations = Vec::new();
    for (type_name, methods, debug_marker) in [
        (
            "AuthorizationSourceOptions",
            &["new"][..],
            "formatter.write_str(\"AuthorizationSourceOptions(<redacted>)\")",
        ),
        (
            "AuthorizationReviewInput",
            &["load", "select"][..],
            "formatter.debug_struct(\"AuthorizationReviewInput\").field(\"policy_file\",&\"<redacted>\").field(\"primary\",&\"<redacted>\").field(\"peer\",&\"<redacted>\").finish()",
        ),
    ] {
        let item = syntax.items.iter().find_map(|item| match item {
            Item::Struct(item) if item.ident == type_name => Some(item),
            _ => None,
        });
        let inherent = inherent_methods(syntax, type_name);
        let observed_methods = inherent
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if item.is_none_or(|item| !is_pub_crate(&item.vis) || has_derive_attribute(&item.attrs))
            || observed_methods != methods.iter().copied().collect()
            || explicit_trait_impls(syntax, type_name) != BTreeSet::from(["Debug".to_owned()])
            || !compact.contains(debug_marker)
        {
            violations.push(format!(
                "{type_name} must remain underived, crate-private, move-only, and expose only its exact value-free redacted Debug/method surface"
            ));
        }
    }
    for marker in [
        "pub(crate)structAuthorizationSourceOptions{environment:Option<OsString>,file:Option<PathBuf>,stdin:bool,}",
        "pub(crate)structAuthorizationReviewInput{policy_file:PathBuf,primary:AuthorizationInputSource,peer:AuthorizationInputSource,}",
        "letboth_stdin=primary.stdin&&peer.stdin;",
        "ifboth_stdin{returnErr(AuthorizationReviewInputError::AmbiguousStdin);}",
        "read_bounded_regular_file(self.policy_file,HARD_MAX_AUTHORIZATION_REVIEW_POLICY_BYTES)",
        "AuthorizationReviewPolicy::parse_toml(target,policy_source.as_slice())",
        "self.primary.read_bytes()",
        "self.peer.read_bytes()",
        "PrimaryAuthorizationPrincipal::new(bytes.into_owned())",
        "PeerAuthorizationPrincipal::new(bytes.into_owned())",
        "AuthorizationPrincipalPair::new(primary,peer)",
    ] {
        if !compact.contains(marker) {
            violations.push(format!(
                "authorization-review CLI must reuse the sole bounded credential loader and preserve bounded policy parsing, stdin isolation, and distinct role construction: missing `{marker}`"
            ));
        }
    }
    for secret_shape in [
        "authorization:Option<String>",
        "credential:String",
        "token:String",
        "cookie:String",
    ] {
        if compact.contains(secret_shape) {
            violations.push(format!(
                "authorization-review CLI must not add a raw credential or cookie field `{secret_shape}`"
            ));
        }
    }
    violations
}

fn inspect_cli_auth_surface(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let compact = compact_source(source);
    let mut violations = Vec::new();

    let module_is_private = syntax.items.iter().any(|item| {
        matches!(item, Item::Mod(module)
            if module.ident == "auth_input"
                && matches!(module.vis, Visibility::Inherited)
                && module.attrs.is_empty()
                && module.content.is_none())
    });
    if !module_is_private {
        violations.push(
            "CLI auth_input module must remain a private, non-redirected source module".to_owned(),
        );
    }

    let Some(scan) = find_enum(&syntax, "Commands").and_then(|commands| {
        commands
            .variants
            .iter()
            .find(|variant| variant.ident == "Scan")
    }) else {
        violations.push(
            "CLI Scan command must remain available for secret-boundary inspection".to_owned(),
        );
        return Ok(violations);
    };
    let scan_is_boxed = matches!(&scan.fields, Fields::Unnamed(fields)
        if fields.unnamed.len() == 1
            && is_one_argument_type(&fields.unnamed[0].ty, "Box", "ScanArgs"));
    if !scan_is_boxed || !exact_command_attribute(&scan.attrs, "visible_alias=\"decision-scan\"") {
        violations.push(
            "CLI Scan command must retain the exact Box<ScanArgs> payload and decision-scan alias"
                .to_owned(),
        );
    }

    let scan_args = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "ScanArgs" => Some(item),
        _ => None,
    });
    let Some(scan_args) = scan_args else {
        violations.push("CLI ScanArgs must remain a private typed argument payload".to_owned());
        return Ok(violations);
    };
    if !matches!(scan_args.vis, Visibility::Inherited)
        || derive_identifiers(&scan_args.attrs) != BTreeSet::from(["Args".to_owned()])
    {
        violations.push(
            "CLI ScanArgs must remain a private clap::Args payload without exposing derives"
                .to_owned(),
        );
    }
    let Fields::Named(scan_fields) = &scan_args.fields else {
        violations.push("CLI ScanArgs must retain exact named fields".to_owned());
        return Ok(violations);
    };
    let fields = scan_fields
        .named
        .iter()
        .filter_map(|field| field.ident.as_ref().map(|ident| (ident.to_string(), field)))
        .collect::<BTreeMap<_, _>>();
    let exact_field_names = CLI_SCAN_FIELDS
        .iter()
        .map(|field| (*field).to_owned())
        .collect::<BTreeSet<_>>();
    let observed_field_names = fields.keys().cloned().collect::<BTreeSet<_>>();
    let ordinary_types_are_exact = [
        ("target", "Url", None),
        ("format", "OutputFormat", None),
        ("explain", "bool", None),
        ("profile", "Option", Some("CliScanProfile")),
        ("enforce_defense", "bool", None),
        ("graphql_review", "bool", None),
        ("normalization_resilience", "bool", None),
        ("oast_admin_token_env", "Option", Some("OsString")),
        ("oast_admin_token_file", "Option", Some("PathBuf")),
        ("oast_admin_token_stdin", "bool", None),
        ("openapi_review", "bool", None),
        ("ssrf_oast_policy", "Option", Some("PathBuf")),
        ("ssrf_oast_review", "bool", None),
        ("authorization_review_policy", "Option", Some("PathBuf")),
        ("authz_primary_env", "Option", Some("OsString")),
        ("authz_primary_file", "Option", Some("PathBuf")),
        ("authz_primary_stdin", "bool", None),
        ("authz_peer_env", "Option", Some("OsString")),
        ("authz_peer_file", "Option", Some("PathBuf")),
        ("authz_peer_stdin", "bool", None),
        ("report_format", "Option", Some("CliReportFormat")),
        ("report_dir", "Option", Some("PathBuf")),
        ("report_output", "Option", Some("PathBuf")),
    ]
    .iter()
    .all(|(name, outer, inner)| {
        fields.get(*name).is_some_and(|field| {
            inner.map_or_else(
                || is_plain_type(&field.ty, outer),
                |inner| is_one_argument_type(&field.ty, outer, inner),
            )
        })
    });
    if observed_field_names != exact_field_names || !ordinary_types_are_exact {
        violations.push(format!(
            "CLI Scan field inventory and types must remain exact so no raw credential, token, cookie, or header argument can be added; observed {observed_field_names:?}"
        ));
    }
    let observed_auth_fields = fields
        .keys()
        .filter(|name| name.starts_with("auth") || name.contains("authorization"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if observed_auth_fields
        != CLI_AUTH_FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect()
    {
        violations.push(format!(
            "CLI Scan may expose only the exact root and resource-review out-of-band authorization inputs; observed {observed_auth_fields:?}"
        ));
    }
    for (name, expected_type, expected_arg) in [
        (
            "auth_env",
            ("Option", Some("OsString")),
            "long,value_name=\"ENV_VAR\",requires=\"profile\",conflicts_with_all=[\"auth_file\",\"auth_stdin\"]",
        ),
        (
            "auth_file",
            ("Option", Some("PathBuf")),
            "long,value_name=\"PATH\",requires=\"profile\",conflicts_with_all=[\"auth_env\",\"auth_stdin\"]",
        ),
        (
            "auth_stdin",
            ("bool", None),
            "long,requires=\"profile\",conflicts_with_all=[\"auth_env\",\"auth_file\"]",
        ),
        (
            "authorization_review_policy",
            ("Option", Some("PathBuf")),
            "long,value_name=\"FILE\",requires=\"profile\",conflicts_with_all=[\"auth_env\",\"auth_file\",\"auth_stdin\"]",
        ),
        (
            "authz_primary_env",
            ("Option", Some("OsString")),
            "long,value_name=\"ENV_VAR\",requires=\"authorization_review_policy\",conflicts_with_all=[\"authz_primary_file\",\"authz_primary_stdin\"]",
        ),
        (
            "authz_primary_file",
            ("Option", Some("PathBuf")),
            "long,value_name=\"FILE\",requires=\"authorization_review_policy\",conflicts_with_all=[\"authz_primary_env\",\"authz_primary_stdin\"]",
        ),
        (
            "authz_primary_stdin",
            ("bool", None),
            "long,requires=\"authorization_review_policy\",conflicts_with_all=[\"authz_primary_env\",\"authz_primary_file\",\"authz_peer_stdin\"]",
        ),
        (
            "authz_peer_env",
            ("Option", Some("OsString")),
            "long,value_name=\"ENV_VAR\",requires=\"authorization_review_policy\",conflicts_with_all=[\"authz_peer_file\",\"authz_peer_stdin\"]",
        ),
        (
            "authz_peer_file",
            ("Option", Some("PathBuf")),
            "long,value_name=\"FILE\",requires=\"authorization_review_policy\",conflicts_with_all=[\"authz_peer_env\",\"authz_peer_stdin\"]",
        ),
        (
            "authz_peer_stdin",
            ("bool", None),
            "long,requires=\"authorization_review_policy\",conflicts_with_all=[\"authz_peer_env\",\"authz_peer_file\",\"authz_primary_stdin\"]",
        ),
    ] {
        let exact = fields.get(name).is_some_and(|field| {
            let type_matches = match expected_type {
                (outer, Some(inner)) => is_one_argument_type(&field.ty, outer, inner),
                (plain, None) => is_plain_type(&field.ty, plain),
            };
            type_matches && exact_arg_attribute(&field.attrs, expected_arg)
        });
        if !exact {
            violations.push(format!(
                "CLI `{name}` must retain its exact out-of-band type, profile requirement, and pairwise source conflicts"
            ));
        }
    }
    for name in [
        "authorization_review_policy",
        "authz_primary_env",
        "authz_primary_file",
        "authz_primary_stdin",
        "authz_peer_env",
        "authz_peer_file",
        "authz_peer_stdin",
    ] {
        if fields
            .get(name)
            .is_none_or(|field| !exact_cfg_feature_attribute(&field.attrs, "authorization-review"))
        {
            violations.push(format!(
                "CLI `{name}` must remain absent outside the exact non-default authorization-review feature"
            ));
        }
    }
    if fields.get("openapi_review").is_none_or(|field| {
        !is_plain_type(&field.ty, "bool")
            || !exact_cfg_feature_attribute(&field.attrs, "openapi-review")
            || !exact_arg_attribute(&field.attrs, "long,requires=\"profile\"")
    }) {
        violations.push(
            "CLI `openapi_review` must remain an exact cfg-gated bool requiring the explicit scan profile"
                .to_owned(),
        );
    }

    if fields.get("rest_review").is_none_or(|field| {
        !is_plain_type(&field.ty, "bool")
            || !exact_cfg_feature_attribute(&field.attrs, "rest-review")
            || !exact_arg_attribute(
                &field.attrs,
                "long,requires_all=[\"profile\",\"openapi_review\"]",
            )
    }) {
        violations.push(
            "CLI `rest_review` must remain an exact cfg-gated bool requiring the explicit profile and same-run OpenAPI review"
                .to_owned(),
        );
    }

    if fields.get("report_dir").is_none_or(|field| {
        !is_one_argument_type(&field.ty, "Option", "PathBuf")
            || !exact_arg_attribute(
                &field.attrs,
                "long,value_name=\"DIRECTORY\",requires=\"profile\",conflicts_with_all=[\"report_format\",\"report_output\"]",
            )
    }) {
        violations.push(
            "CLI `report_dir` must remain an exact optional directory requiring a profile and conflicting with both single-report output options"
                .to_owned(),
        );
    }

    for (name, expected_type, expected_arg) in [
        (
            "ssrf_oast_review",
            ("bool", None),
            "long,requires_all=[\"profile\",\"ssrf_oast_policy\"]",
        ),
        (
            "ssrf_oast_policy",
            ("Option", Some("PathBuf")),
            "long,value_name=\"FILE\",requires_all=[\"profile\",\"ssrf_oast_review\"]",
        ),
        (
            "oast_admin_token_env",
            ("Option", Some("OsString")),
            "long,value_name=\"ENV_VAR\",requires=\"ssrf_oast_policy\",conflicts_with_all=[\"oast_admin_token_file\",\"oast_admin_token_stdin\"]",
        ),
        (
            "oast_admin_token_file",
            ("Option", Some("PathBuf")),
            "long,value_name=\"FILE\",requires=\"ssrf_oast_policy\",conflicts_with_all=[\"oast_admin_token_env\",\"oast_admin_token_stdin\"]",
        ),
        (
            "oast_admin_token_stdin",
            ("bool", None),
            "long,requires=\"ssrf_oast_policy\",conflicts_with_all=[\"oast_admin_token_env\",\"oast_admin_token_file\",\"auth_stdin\"]",
        ),
    ] {
        let exact = fields.get(name).is_some_and(|field| {
            let type_matches = match expected_type {
                (outer, Some(inner)) => is_one_argument_type(&field.ty, outer, inner),
                (plain, None) => is_plain_type(&field.ty, plain),
            };
            type_matches
                && exact_cfg_feature_attribute(&field.attrs, "ssrf-oast-review")
                && exact_arg_attribute(&field.attrs, expected_arg)
        });
        if !exact {
            violations.push(format!(
                "CLI `{name}` must retain its exact feature-gated SSRF OAST type, explicit enablement, and out-of-band source conflicts"
            ));
        }
    }

    for type_name in ["Cli", "Commands", "ScanArgs"] {
        if item_has_sensitive_derive(&syntax, type_name)
            || !explicit_trait_impls(&syntax, type_name).is_empty()
        {
            violations.push(format!(
                "CLI secret-carrying surface {type_name} must not implement Clone, Debug, display, serialization, conversion, borrowing, or other exposing traits"
            ));
        }
    }

    if !compact
        .contains("auth_input::AuthorizationInputSource::select(auth_env,auth_file,auth_stdin)?")
        || compact
            .matches("auth_input::AuthorizationInputSource::select(")
            .count()
            != 1
    {
        violations.push(
            "CLI must select the three mutually exclusive authorization sources exactly once without reading them"
                .to_owned(),
        );
    }
    if !compact.contains("auth_input::AuthorizationReviewInput::select(authorization_review_policy,auth_input::AuthorizationSourceOptions::new(authz_primary_env,authz_primary_file,authz_primary_stdin,),auth_input::AuthorizationSourceOptions::new(authz_peer_env,authz_peer_file,authz_peer_stdin,),)?")
        || compact
            .matches("auth_input::AuthorizationReviewInput::select(")
            .count()
            != 1
        || compact
            .matches("auth_input::AuthorizationSourceOptions::new(authz_")
            .count()
            != 2
    {
        violations.push(
            "CLI must select one authorization-review policy plus exactly one primary and peer out-of-band source without reading them"
                .to_owned(),
        );
    }
    if !compact.contains("auth_input::SsrfOastReviewInput::select(ssrf_oast_review,ssrf_oast_policy,auth_input::AuthorizationSourceOptions::new(oast_admin_token_env,oast_admin_token_file,oast_admin_token_stdin,),)?")
        || compact
            .matches("auth_input::SsrfOastReviewInput::select(")
            .count()
            != 1
        || compact
            .matches("auth_input::AuthorizationSourceOptions::new(oast_admin_token_")
            .count()
            != 1
    {
        violations.push(
            "CLI must require explicit SSRF OAST enablement, one policy, and exactly one out-of-band administrator source without reading them"
                .to_owned(),
        );
    }
    if !compact.contains("preflight_report_output(report_output.as_deref())?")
        || compact
            .matches("preflight_report_output(report_output.as_deref())?")
            .count()
            != 1
    {
        violations.push(
            "CLI must preflight the selected report output before reading authorization material"
                .to_owned(),
        );
    }
    if !compact.contains(
        "letmutreport_bundle=report_bundle::reserve_report_bundle(report_dir.as_deref())?;",
    ) || compact
        .matches("report_bundle::reserve_report_bundle(report_dir.as_deref())?")
        .count()
        != 1
    {
        violations.push(
            "CLI must exclusively reserve the selected report bundle directory before reading authorization material"
                .to_owned(),
        );
    }
    if !compact.contains("authorization_source.is_some()&&!is_exact_origin_root(&target)")
        || !compact.contains(
            "authorization_source.is_some()&&!authorization_context_transport_is_allowed(&target)",
        )
    {
        violations.push(
            "CLI authorization input must be guarded by exact-root and authenticated-transport checks before source I/O"
                .to_owned(),
        );
    }

    let Some(run) = find_function(&syntax, "run_deterministic_scan") else {
        violations.push("CLI deterministic scan boundary is missing".to_owned());
        return Ok(violations);
    };
    let ordered = ordered_boundary_references(run);
    let expected = [
        "scan_flags_conflict",
        "scan_ssrf_oast_review_flags_conflict",
        "scan_profile_flags_conflict",
        "scan_report_flags_conflict",
        "scan_resource_authorization_flags_conflict",
        "select",
        "scan_authorization_flags_conflict",
        "is_exact_origin_root",
        "authorization_context_transport_is_allowed",
        "select",
        "select",
        "authorization_context_transport_is_allowed",
        "for_builtin",
        "with_defense_enforcement_enabled",
        "preflight_report_output",
        "reserve_report_bundle",
        "load",
        "load",
        "load",
        "DETERMINISTIC_SCAN_WARNING",
        "run_profile_scan",
    ];
    if !contains_ordered_subsequence(&ordered, &expected)
        || ordered
            .iter()
            .filter(|name| name.as_str() == "load")
            .count()
            != 3
        || ordered
            .iter()
            .filter(|name| name.as_str() == "select")
            .count()
            != 3
    {
        violations.push(format!(
            "CLI authorization sources must be selected without I/O and loaded exactly once each after flag, transport, profile, defense, and report preflights and before warning/network execution; observed {ordered:?}"
        ));
    }

    Ok(violations)
}

fn inspect_scanner_context_validation(
    source: &str,
    payload_strategy_source: &str,
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let compact = compact_source(source);
    let payload_compact = compact_source(payload_strategy_source);
    let mut violations = Vec::new();

    if explicit_trait_impls(&syntax, "WebAssessmentRootAuthorizationContext")
        != BTreeSet::from(["Debug".to_owned()])
        || find_struct_has_derive(&syntax, "WebAssessmentRootAuthorizationContext")
    {
        violations.push(
            "scanner authorization context must remain non-cloneable, non-serializable, and expose only exact redacted Debug"
                .to_owned(),
        );
    }
    if !compact
        .contains("formatter.write_str(\"WebAssessmentRootAuthorizationContext(<redacted>)\")")
    {
        violations.push(
            "scanner authorization context Debug must remain an exact value-free redaction"
                .to_owned(),
        );
    }

    let methods = inherent_methods(&syntax, "WebAssessmentRootAuthorizationContext");
    if methods.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["into_candidate_header_value", "new"])
    {
        violations.push(format!(
            "scanner authorization context method inventory must remain exactly checked new plus consuming private extraction; observed {:?}",
            methods.keys().collect::<Vec<_>>()
        ));
    }
    let constructor_is_exact = methods.get("new").is_some_and(|method| {
        matches!(method.vis, Visibility::Public(_))
            && method.sig.receiver().is_none()
            && method.sig.inputs.len() == 1
            && return_type_references(
                &method.sig.output,
                &["Self", "WebAssessmentAuthorizationContextError"],
            )
    });
    let extraction_is_exact = methods
        .get("into_candidate_header_value")
        .is_some_and(|method| {
            matches!(method.vis, Visibility::Inherited)
                && method.sig.receiver().is_some_and(|receiver| {
                    receiver.reference.is_none() && receiver.mutability.is_none()
                })
                && typed_inputs(method).is_empty()
                && matches!(&method.sig.output, ReturnType::Type(_, output)
                    if is_plain_type(output.as_ref(), "String"))
        });
    if !constructor_is_exact
        || !extraction_is_exact
        || !compact.contains("letlimits=PayloadStrategyLimits::default();")
        || !compact.contains("letseed=PayloadSeed::new(value,limits)")
        || !compact.contains("letstrategy=ApiAuthorizationContextPairStrategy::new();")
        || !compact.contains(
            ".derive_one(PayloadVariantRole::Control,&seed,limits).map_err(|_|WebAssessmentAuthorizationContextError::InvalidValue)?",
        )
        || !compact.contains(
            ".derive_one(PayloadVariantRole::Candidate,&seed,limits).map_err(|_|WebAssessmentAuthorizationContextError::InvalidValue)?",
        )
        || !compact.contains("String::from_utf8(candidate.as_bytes().to_vec())")
        || compact.contains("from_utf8_unchecked")
    {
        violations.push(
            "scanner authorization-context constructor must validate one bounded seed through the existing control/candidate payload strategy before retaining visible ASCII"
                .to_owned(),
        );
    }
    if !payload_compact.contains("pubconstDEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES:u32=4*1024;") {
        violations.push(
            "CLI authorization ceiling must remain aligned with the existing 4 KiB default payload-strategy limit"
                .to_owned(),
        );
    }
    Ok(violations)
}

fn find_enum<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a ItemEnum> {
    syntax.items.iter().find_map(|item| match item {
        Item::Enum(item) if item.ident == name => Some(item),
        _ => None,
    })
}

fn find_function<'a>(syntax: &'a syn::File, name: &str) -> Option<&'a ItemFn> {
    syntax.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    })
}

fn inherent_methods<'a>(
    syntax: &'a syn::File,
    type_name: &str,
) -> BTreeMap<String, &'a syn::ImplItemFn> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if item.trait_.is_none()
                    && type_last_ident_is(item.self_ty.as_ref(), type_name) =>
            {
                Some(item)
            },
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method) => Some((method.sig.ident.to_string(), method)),
            _ => None,
        })
        .collect()
}

fn explicit_trait_impls(syntax: &syn::File, type_name: &str) -> BTreeSet<String> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item) if type_last_ident_is(item.self_ty.as_ref(), type_name) => {
                item.trait_.as_ref().and_then(|(_, path, _)| {
                    path.segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                })
            },
            _ => None,
        })
        .collect()
}

fn type_last_ident_is(item_type: &Type, expected: &str) -> bool {
    matches!(item_type, Type::Path(path)
        if path.qself.is_none()
            && path.path.segments.last().is_some_and(|segment| segment.ident == expected))
}

fn is_pub_crate(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Restricted(restricted)
        if restricted.in_token.is_none() && restricted.path.is_ident("crate"))
}

fn is_plain_type(item_type: &Type, expected: &str) -> bool {
    matches!(item_type, Type::Path(path)
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path.path.is_ident(expected))
}

fn is_one_argument_type(item_type: &Type, outer: &str, inner: &str) -> bool {
    let Type::Path(path) = item_type else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    if segment.ident != outer {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    arguments.args.len() == 1
        && arguments
            .args
            .first()
            .is_some_and(|argument| matches!(argument, syn::GenericArgument::Type(item) if is_plain_type(item, inner)))
}

fn is_default_payload_ceiling_cast(expression: &Expr) -> bool {
    matches!(expression, Expr::Cast(cast)
        if matches!(cast.expr.as_ref(), Expr::Path(path)
            if path.qself.is_none() && path.path.is_ident("DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES"))
            && is_plain_type(cast.ty.as_ref(), "usize"))
}

fn enum_variants_are_exact(item: &ItemEnum, expected: &[(&str, Option<&str>)]) -> bool {
    item.variants.len() == expected.len()
        && item
            .variants
            .iter()
            .zip(expected)
            .all(|(variant, (name, field_type))| {
                variant.ident == name
                    && variant.discriminant.is_none()
                    && variant.attrs.is_empty()
                    && match (field_type, &variant.fields) {
                        (None, Fields::Unit) => true,
                        (Some(expected), Fields::Unnamed(fields)) if fields.unnamed.len() == 1 => {
                            is_plain_type(&fields.unnamed[0].ty, expected)
                        },
                        _ => false,
                    }
            })
}

fn enum_unit_variants_are_exact(item: &ItemEnum, expected: &[&str]) -> bool {
    item.variants.len() == expected.len()
        && item.variants.iter().zip(expected).all(|(variant, name)| {
            variant.ident == name
                && variant.attrs.is_empty()
                && matches!(variant.fields, Fields::Unit)
                && variant.discriminant.is_none()
        })
}

fn has_derive_attribute(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident("derive"))
}

fn derive_identifiers(attributes: &[Attribute]) -> BTreeSet<String> {
    attributes
        .iter()
        .filter_map(|attribute| match &attribute.meta {
            Meta::List(list) if list.path.is_ident("derive") => Some(list.tokens.to_string()),
            _ => None,
        })
        .flat_map(|tokens| {
            tokens
                .split(',')
                .map(|token| token.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn select_signature_is_exact(method: &syn::ImplItemFn) -> bool {
    let inputs = typed_inputs(method);
    is_pub_crate(&method.vis)
        && method.sig.receiver().is_none()
        && inputs.len() == 3
        && inputs[0].0 == "environment"
        && is_one_argument_type(inputs[0].1, "Option", "OsString")
        && inputs[1].0 == "file"
        && is_one_argument_type(inputs[1].1, "Option", "PathBuf")
        && inputs[2].0 == "stdin"
        && is_plain_type(inputs[2].1, "bool")
        && return_type_references(
            &method.sig.output,
            &["Result", "Option", "Self", "AuthorizationInputError"],
        )
}

fn load_signature_is_exact(method: &syn::ImplItemFn) -> bool {
    is_pub_crate(&method.vis)
        && method
            .sig
            .receiver()
            .is_some_and(|receiver| receiver.reference.is_none() && receiver.mutability.is_none())
        && typed_inputs(method).is_empty()
        && return_type_references(
            &method.sig.output,
            &[
                "Result",
                "WebAssessmentRootAuthorizationContext",
                "AuthorizationInputError",
            ],
        )
}

fn typed_inputs(method: &syn::ImplItemFn) -> Vec<(String, &Type)> {
    method
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            FnArg::Typed(argument) => match argument.pat.as_ref() {
                Pat::Ident(pattern) => Some((pattern.ident.to_string(), argument.ty.as_ref())),
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect()
}

fn return_type_references(output: &ReturnType, required: &[&str]) -> bool {
    let ReturnType::Type(_, output) = output else {
        return false;
    };
    let mut visitor = TypeIdentifierVisitor::default();
    visitor.visit_type(output);
    required
        .iter()
        .all(|required| visitor.identifiers.contains(*required))
}

#[derive(Default)]
struct TypeIdentifierVisitor {
    identifiers: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for TypeIdentifierVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.identifiers.extend(
            path.segments
                .iter()
                .map(|segment| segment.ident.to_string()),
        );
        visit::visit_path(self, path);
    }
}

fn exact_arg_attribute(attributes: &[Attribute], expected: &str) -> bool {
    let args = attributes
        .iter()
        .filter_map(|attribute| match &attribute.meta {
            Meta::List(list) if list.path.is_ident("arg") => Some(compact_tokens(&list.tokens)),
            _ => None,
        })
        .collect::<Vec<_>>();
    args == [expected]
}

fn exact_command_attribute(attributes: &[Attribute], expected: &str) -> bool {
    let commands = attributes
        .iter()
        .filter_map(|attribute| match &attribute.meta {
            Meta::List(list) if list.path.is_ident("command") => Some(compact_tokens(&list.tokens)),
            _ => None,
        })
        .collect::<Vec<_>>();
    commands == [expected]
}

fn exact_cfg_feature_attribute(attributes: &[Attribute], feature: &str) -> bool {
    let predicates = attributes
        .iter()
        .filter_map(|attribute| match &attribute.meta {
            Meta::List(list) if list.path.is_ident("cfg") => Some(compact_tokens(&list.tokens)),
            _ => None,
        })
        .collect::<Vec<_>>();
    predicates == [format!("feature=\"{feature}\"")]
}

fn compact_tokens(tokens: &TokenStream) -> String {
    tokens
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn compact_source(source: &str) -> String {
    source
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn item_has_sensitive_derive(syntax: &syn::File, type_name: &str) -> bool {
    let attributes = syntax.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == type_name => Some(item.attrs.as_slice()),
        Item::Enum(item) if item.ident == type_name => Some(item.attrs.as_slice()),
        _ => None,
    });
    attributes.is_some_and(|attributes| {
        let derives = derive_identifiers(attributes);
        derives.iter().any(|derive| {
            matches!(
                derive.as_str(),
                "Clone" | "Copy" | "Debug" | "Serialize" | "Deserialize" | "Display"
            )
        })
    })
}

fn static_error_display_is_exact(compact: &str) -> bool {
    compact.contains("formatter.write_str(matchself{")
        && [
            (
                "ConflictingSources",
                "selectexactlyoneauthorization-contextinputsource",
            ),
            (
                "SourceNameInvalid",
                "authorization-contextenvironmentnameisinvalid",
            ),
            (
                "SourceUnavailable",
                "authorization-contextinputsourceisunavailable",
            ),
            (
                "SourceNotRegularFile",
                "authorization-contextfilesourcemustbearegularfile",
            ),
            (
                "SourceNotUnicode",
                "authorization-contextenvironmentvalueisnotvalidUnicode",
            ),
            (
                "SourceReadFailed",
                "authorization-contextinputsourcecouldnotberead",
            ),
            (
                "ValueTooLarge",
                "authorization-contextvalueexceedsthecompiledbytelimit",
            ),
            (
                "InvalidValue",
                "authorization-contextvalueisnotasafeHTTPheadervalue",
            ),
        ]
        .iter()
        .all(|(variant, message)| {
            compact.contains(&format!("Self::{variant}"))
                && compact.contains(&format!("\"{message}\""))
        })
}

// Compare whole, top-level definitions, not free-floating markers. Comments,
// test modules, nested helper decoys and string literals cannot satisfy these
// contracts. Documentation attributes alone are omitted from the token match.
fn contract_items(source: &str) -> Result<Vec<(String, String)>, syn::Error> {
    let parser = |input: syn::parse::ParseStream<'_>| {
        for attribute in input.call(Attribute::parse_inner)? {
            if !attribute.path().is_ident("doc") {
                return Err(
                    input.error("credential contract permits only inner documentation attributes")
                );
            }
        }
        let mut items = Vec::new();
        while !input.is_empty() {
            let before = input.cursor().token_stream();
            let item: Item = input.parse()?;
            let consumed = before.clone().into_iter().count()
                - input.cursor().token_stream().into_iter().count();
            let tokens = before.into_iter().take(consumed).collect::<TokenStream>();
            let key = match item {
                Item::Fn(item) => Some(format!("fn:{}", item.sig.ident)),
                Item::Struct(item) => Some(format!("struct:{}", item.ident)),
                Item::Impl(item) => match item.self_ty.as_ref() {
                    Type::Path(path) => path
                        .path
                        .segments
                        .last()
                        .map(|segment| format!("impl:{}", segment.ident)),
                    _ => None,
                },
                _ => None,
            };
            if let Some(key) = key {
                // Keep token boundaries and literal whitespace: `return Err`
                // must not compare equal to an unrelated `returnErr` call.
                items.push((key, without_documentation(tokens).to_string()));
            }
        }
        Ok(items)
    };
    parser.parse_str(source)
}

fn without_documentation(tokens: TokenStream) -> TokenStream {
    let mut tokens = tokens.into_iter().peekable();
    let mut retained = TokenStream::new();
    while let Some(token) = tokens.next() {
        if matches!(&token, TokenTree::Punct(punctuation) if punctuation.as_char() == '#')
            && tokens.peek().is_some_and(|next| {
                matches!(next, TokenTree::Group(group)
                    if group.delimiter() == proc_macro2::Delimiter::Bracket
                        && matches!(group.stream().into_iter().next(),
                            Some(TokenTree::Ident(identifier)) if identifier == "doc"))
            })
        {
            tokens.next();
        } else if let TokenTree::Group(group) = token {
            retained.extend([TokenTree::Group(proc_macro2::Group::new(
                group.delimiter(),
                without_documentation(group.stream()),
            ))]);
        } else {
            retained.extend([token]);
        }
    }
    retained
}

fn definitions_are_exact(observed: &[(String, String)], expected: &str) -> bool {
    let Ok(expected) = contract_items(expected) else {
        return false;
    };
    let keys = expected.iter().map(|(key, _)| key).collect::<BTreeSet<_>>();
    !expected.is_empty()
        && observed
            .iter()
            .filter(|(key, _)| keys.contains(key))
            .eq(expected.iter())
}

fn guarded_intake_is_exact(items: &[(String, String)]) -> bool {
    definitions_are_exact(
        items,
        r#"
        struct CredentialBytes { bytes: Zeroizing<Vec<u8>>, }
        impl CredentialBytes {
            fn new(bytes: Vec<u8>) -> Self { Self { bytes: Zeroizing::new(bytes), } }
            fn as_slice(&self) -> &[u8] { self.bytes.as_slice() }
            fn into_owned(mut self) -> Vec<u8> { std::mem::take(&mut *self.bytes) }
        }
        impl fmt::Debug for CredentialBytes {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("CredentialBytes(<redacted>)")
            }
        }
        impl Drop for CredentialBytes {
            fn drop(&mut self) {
                self.bytes.as_mut_slice().zeroize();
                #[cfg(test)]
                INTAKE_DROPS.with(|drops| {
                    drops.borrow_mut().push((self.bytes.len(), self.bytes.iter().all(|byte| *byte == 0)));
                });
            }
        }
    "#,
    )
}

fn bounded_reader_is_exact(items: &[(String, String)]) -> bool {
    definitions_are_exact(
        items,
        r#"
        #[cfg(any(feature = "authorization-review", feature = "ssrf-oast-review"))]
        fn read_bounded_regular_file(path: PathBuf, max_bytes: usize,)
            -> Result<CredentialBytes, AuthorizationInputError> {
            let mut file = open_regular_file(path)?;
            ensure_opened_file_length(&file, max_bytes)?;
            let retained = max_bytes.saturating_add(1);
            let bytes = read_bounded_bytes(&mut file, retained)?;
            if bytes.as_slice().len() > max_bytes {
                return Err(AuthorizationInputError::ValueTooLarge);
            }
            Ok(bytes)
        }
        fn ensure_opened_file_length(file: &File, max_bytes: usize) -> Result<(), AuthorizationInputError> {
            let length = file.metadata().map_err(|_| AuthorizationInputError::SourceUnavailable)? .len();
            if length > u64::try_from(max_bytes).unwrap_or(u64::MAX) {
                return Err(AuthorizationInputError::ValueTooLarge);
            }
            Ok(())
        }
        fn read_bounded_line_source(reader: &mut impl Read,)
            -> Result<CredentialBytes, AuthorizationInputError> {
            let retained_limit = MAX_AUTHORIZATION_CONTEXT_BYTES.saturating_add(2);
            let mut bytes = read_bounded_bytes(reader, retained_limit)?;
            let mut overflow = Zeroizing::new([0_u8; 1]);
            if read_overflow_byte(reader, &mut overflow)? != 0 {
                return Err(AuthorizationInputError::ValueTooLarge);
            }
            let retained = wipe_terminal_line_ending(bytes.bytes.as_mut_slice());
            bytes.bytes.truncate(retained);
            if bytes.as_slice().len() > MAX_AUTHORIZATION_CONTEXT_BYTES {
                return Err(AuthorizationInputError::ValueTooLarge);
            }
            Ok(bytes)
        }
        fn read_bounded_bytes(reader: &mut impl Read, retained_limit: usize,)
            -> Result<CredentialBytes, AuthorizationInputError> {
            let mut bytes = CredentialBytes::new(vec![0; retained_limit]);
            let mut filled = 0;
            while filled < retained_limit {
                match reader.read(&mut bytes.bytes[filled..]) {
                    Ok(0) => break,
                    Ok(count) => {
                        filled = filled.checked_add(count).filter(|filled| *filled <= retained_limit)
                            .ok_or(AuthorizationInputError::SourceReadFailed)?;
                    },
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(AuthorizationInputError::SourceReadFailed),
                }
            }
            bytes.bytes[filled..].zeroize();
            bytes.bytes.truncate(filled);
            Ok(bytes)
        }
        fn read_overflow_byte(reader: &mut impl Read, overflow: &mut [u8; 1],)
            -> Result<usize, AuthorizationInputError> {
            let result = reader.read(overflow).map_err(|_| AuthorizationInputError::SourceReadFailed);
            overflow.zeroize();
            result
        }
        fn wipe_terminal_line_ending(bytes: &mut [u8]) -> usize {
            let removed = if bytes.ends_with(b"\r\n") { 2 }
                else if bytes.ends_with(b"\n") { 1 } else { 0 };
            let retained = bytes.len().saturating_sub(removed);
            bytes[retained..].zeroize();
            retained
        }
    "#,
    )
}

fn environment_reader_is_exact(items: &[(String, String)]) -> bool {
    definitions_are_exact(
        items,
        r#"
        fn read_environment(name: OsString) -> Result<CredentialBytes, AuthorizationInputError> {
            let name = name.into_string().map_err(|_| AuthorizationInputError::SourceNameInvalid)?;
            if name.is_empty() || name.chars().any(|character| matches!(character, '=' | '\0')) {
                return Err(AuthorizationInputError::SourceNameInvalid);
            }
            let value = std::env::var_os(name).ok_or(AuthorizationInputError::SourceUnavailable)?;
            validate_environment_value(value)
        }
        fn validate_environment_value(value: OsString) -> Result<CredentialBytes, AuthorizationInputError> {
            let bytes = CredentialBytes::new(value.into_encoded_bytes());
            std::str::from_utf8(bytes.as_slice()).map_err(|_| AuthorizationInputError::SourceNotUnicode)?;
            if bytes.as_slice().len() > MAX_AUTHORIZATION_CONTEXT_BYTES {
                return Err(AuthorizationInputError::ValueTooLarge);
            }
            Ok(bytes)
        }
    "#,
    )
}

fn regular_file_open_is_exact(items: &[(String, String)]) -> bool {
    definitions_are_exact(
        items,
        r#"
        pub(super) fn open_regular_file(path: PathBuf) -> Result<File, AuthorizationInputError> {
            validate_opened_regular_file(open_no_follow(&path)?)
        }
        #[cfg(unix)]
        fn open_no_follow(path: &std::path::Path) -> Result<File, AuthorizationInputError> {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path).map_err(|error| {
                    if error.raw_os_error() == Some(libc::ELOOP) {
                        AuthorizationInputError::SourceNotRegularFile
                    } else { AuthorizationInputError::SourceUnavailable }
                })
        }
        #[cfg(windows)]
        fn open_no_follow(path: &std::path::Path) -> Result<File, AuthorizationInputError> {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            std::fs::OpenOptions::new().read(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                .security_qos_flags(0).open(path).map_err(|_| AuthorizationInputError::SourceUnavailable)
        }
        #[cfg(not(any(unix, windows)))]
        fn open_no_follow(_: &std::path::Path) -> Result<File, AuthorizationInputError> {
            Err(AuthorizationInputError::SourceUnavailable)
        }
        fn validate_opened_regular_file(file: File) -> Result<File, AuthorizationInputError> {
            let opened_metadata = file.metadata().map_err(|_| AuthorizationInputError::SourceUnavailable)?;
            #[cfg(windows)] {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                if opened_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(AuthorizationInputError::SourceNotRegularFile);
                }
            }
            if !opened_metadata.is_file() {
                return Err(AuthorizationInputError::SourceNotRegularFile);
            }
            Ok(file)
        }
    "#,
    )
}

fn source_dispatch_is_exact(items: &[(String, String)]) -> bool {
    definitions_are_exact(
        items,
        r#"
        impl fmt::Debug for AuthorizationInputSource {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let source = match self {
                    Self::Environment(_) => "environment",
                    Self::File(_) => "file",
                    Self::Stdin => "stdin",
                };
                formatter.debug_struct("AuthorizationInputSource").field("source", &source)
                    .field("location", &"<redacted>").finish()
            }
        }
        impl AuthorizationInputSource {
            pub(crate) fn select(environment: Option<OsString>, file: Option<PathBuf>, stdin: bool,)
                -> Result<Option<Self>, AuthorizationInputError> {
                let selected = usize::from(environment.is_some())
                    .saturating_add(usize::from(file.is_some())).saturating_add(usize::from(stdin));
                if selected > 1 { return Err(AuthorizationInputError::ConflictingSources); }
                Ok(match (environment, file, stdin) {
                    (Some(name), None, false) => Some(Self::Environment(name)),
                    (None, Some(path), false) => Some(Self::File(path)),
                    (None, None, true) => Some(Self::Stdin),
                    (None, None, false) => None,
                    _ => return Err(AuthorizationInputError::ConflictingSources),
                })
            }
            pub(crate) fn load(self,)
                -> Result<WebAssessmentRootAuthorizationContext, AuthorizationInputError> {
                let bytes = self.read_bytes()?;
                WebAssessmentRootAuthorizationContext::new(bytes.into_owned())
                    .map_err(|_| AuthorizationInputError::InvalidValue)
            }
            fn read_bytes(self) -> Result<CredentialBytes, AuthorizationInputError> {
                match self {
                    Self::Environment(name) => read_environment(name),
                    Self::File(path) => {
                        let mut file = open_regular_file(path)?;
                        ensure_opened_file_length(&file, MAX_AUTHORIZATION_CONTEXT_BYTES + 2)?;
                        read_bounded_line_source(&mut file)
                    },
                    Self::Stdin => {
                        let stdin = io::stdin();
                        let mut input = stdin.lock();
                        read_bounded_line_source(&mut input)
                    },
                }
            }
        }
    "#,
    )
}

fn ordered_boundary_references(function: &ItemFn) -> Vec<String> {
    const OBSERVED: &[&str] = &[
        "scan_flags_conflict",
        "scan_ssrf_oast_review_flags_conflict",
        "scan_profile_flags_conflict",
        "scan_report_flags_conflict",
        "scan_resource_authorization_flags_conflict",
        "select",
        "scan_authorization_flags_conflict",
        "is_exact_origin_root",
        "authorization_context_transport_is_allowed",
        "for_builtin",
        "with_defense_enforcement_enabled",
        "preflight_report_output",
        "reserve_report_bundle",
        "load",
        "DETERMINISTIC_SCAN_WARNING",
        "run_profile_scan",
    ];
    let mut visitor = BoundaryOrderVisitor {
        observed: OBSERVED.iter().copied().collect(),
        order: Vec::new(),
    };
    visitor.visit_block(&function.block);
    visitor.order
}

struct BoundaryOrderVisitor {
    observed: BTreeSet<&'static str>,
    order: Vec<String>,
}

impl<'ast> Visit<'ast> for BoundaryOrderVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(name) = path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .filter(|name| self.observed.contains(name.as_str()))
        {
            self.order.push(name);
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        let name = expression.method.to_string();
        if self.observed.contains(name.as_str()) {
            self.order.push(name);
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if compact_tokens(&item.tokens).contains("DETERMINISTIC_SCAN_WARNING") {
            self.order.push("DETERMINISTIC_SCAN_WARNING".to_owned());
        }
        visit::visit_macro(self, item);
    }
}

fn contains_ordered_subsequence(observed: &[String], expected: &[&str]) -> bool {
    let mut cursor = 0;
    for item in observed {
        if expected
            .get(cursor)
            .is_some_and(|expected| item == expected)
        {
            cursor += 1;
        }
    }
    cursor == expected.len()
}

fn find_struct_has_derive(syntax: &syn::File, name: &str) -> bool {
    syntax.items.iter().any(|item| {
        matches!(item, Item::Struct(item) if item.ident == name && has_derive_attribute(&item.attrs))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTH_INPUT: &str = include_str!("../../../crates/termivar-cli/src/auth_input.rs");
    const CLI_MAIN: &str = include_str!("../../../crates/termivar-cli/src/main.rs");
    const SCANNER_CONTEXT: &str = include_str!(
        "../../../crates/termivar-scanner/src/web_runtime/assessment_api_visibility.rs"
    );
    const PAYLOAD_STRATEGY: &str =
        include_str!("../../../crates/termivar-scanner/src/payload_strategy.rs");

    fn assert_mutation_fails(
        original: &str,
        from: &str,
        to: &str,
        inspect: impl FnOnce(&str) -> Vec<String>,
        needle: &str,
    ) {
        let original = original.replace("\r\n", "\n");
        let mutated = original.replacen(from, to, 1);
        assert_ne!(mutated, original, "stale mutation marker: {from}");
        let violations = inspect(&mutated).join("\n");
        assert!(
            violations.contains(needle),
            "mutation `{from}` did not produce `{needle}`: {violations}"
        );
    }

    #[test]
    fn checked_in_secret_boundary_is_accepted() {
        let violations = inspect_auth_input_contract(AUTH_INPUT).unwrap();
        assert!(violations.is_empty(), "{violations:#?}");
        assert!(inspect_cli_auth_surface(CLI_MAIN).unwrap().is_empty());
        assert!(
            inspect_scanner_context_validation(SCANNER_CONTEXT, PAYLOAD_STRATEGY)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn source_type_and_redaction_are_mutation_locked() {
        for (from, to, needle) in [
            (
                "pub(crate) enum AuthorizationInputSource {",
                "#[derive(Clone)]\npub(crate) enum AuthorizationInputSource {",
                "underived crate-private enum",
            ),
            (
                "Environment(OsString)",
                "Environment(String)",
                "underived crate-private enum",
            ),
            (
                ".field(\"location\", &\"<redacted>\")",
                ".field(\"location\", &source)",
                "exact <redacted> location",
            ),
            (
                "impl AuthorizationInputSource {",
                "impl std::fmt::Display for AuthorizationInputSource { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, \"visible\") } }\nimpl AuthorizationInputSource {",
                "may implement only",
            ),
            (
                "    pub(crate) fn load(\n        self,",
                "    pub(crate) fn load(\n        &self,",
                "must consume the source",
            ),
        ] {
            assert_mutation_fails(
                AUTH_INPUT,
                from,
                to,
                |source| inspect_auth_input_contract(source).unwrap(),
                needle,
            );
        }
    }

    #[test]
    fn byte_ceiling_overflow_probe_and_static_errors_are_mutation_locked() {
        for (from, to, needle) in [
            (
                "DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES as usize",
                "DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES.saturating_mul(2) as usize",
                "exact crate-private cast",
            ),
            (
                "read_bounded_bytes(reader, retained_limit)?",
                "read_bounded_bytes(reader, usize::MAX)?",
                "probe one overflow byte",
            ),
            (
                "    let mut overflow = Zeroizing::new([0_u8; 1]);",
                "    let mut overflow = [0_u8; 1];",
                "probe one overflow byte",
            ),
            (
                "    SourceUnavailable,",
                "    SourceUnavailable(String),",
                "value-free unit-variant",
            ),
            (
                "validate_opened_regular_file(open_no_follow(&path)?)",
                "File::open(path).map_err(|_| AuthorizationInputError::SourceUnavailable)",
                "reject reparse/non-regular opened handles before reading",
            ),
            (
                "    let opened_metadata = file\n        .metadata()",
                "    let opened_metadata = std::fs::metadata(\"replacement\")",
                "reject reparse/non-regular opened handles before reading",
            ),
            (
                "Self::SourceReadFailed => \"authorization-context input source could not be read\"",
                "Self::SourceReadFailed => \"source failed\"",
                "static credential-free",
            ),
            (
                "WebAssessmentRootAuthorizationContext::new(bytes.into_owned())",
                "WebAssessmentRootAuthorizationContext::from_unchecked(bytes.into_owned())",
                "scanner-owned authorization-context constructor",
            ),
        ] {
            assert_mutation_fails(
                AUTH_INPUT,
                from,
                to,
                |source| inspect_auth_input_contract(source).unwrap(),
                needle,
            );
        }
    }

    #[test]
    fn complete_definitions_ignore_documentation_but_reject_decoys_and_duplicates() {
        const EXPECTED: &str = "fn bounded() { read_one(); }";
        let documented = contract_items(
            "//! module documentation\n/// function documentation\nfn bounded() { /* comment */ read_one(); }",
        ).unwrap();
        assert!(definitions_are_exact(&documented, EXPECTED));
        assert!(!definitions_are_exact(&documented, ""));
        assert!(!definitions_are_exact(&documented, "fn {"));
        assert!(contract_items("#![cfg(test)] fn bounded() {}").is_err());
        for source in [
            "// fn bounded() { read_one(); }\nfn bounded() { read_all(); }",
            "const DECOY: &str = \"fn bounded() { read_one(); }\"; fn bounded() { read_all(); }",
            "mod tests { fn bounded() { read_one(); } }",
            "fn outer() { fn bounded() { read_one(); } }",
            "generate! { fn bounded() { read_one(); } }",
            "#[cfg(test)] fn bounded() { read_one(); }",
            "pub fn bounded() { read_one(); }",
            "fn bounded() { read_one(); } fn bounded() { read_one(); }",
            "fn bounded() { return; read_one(); }",
        ] {
            let items = contract_items(source).unwrap();
            assert!(
                !definitions_are_exact(&items, EXPECTED),
                "accepted decoy: {source}"
            );
        }
        // Parsed but irrelevant item shapes cannot act as named definitions;
        // macro punctuation and non-doc attributes are not erased as comments.
        let items = contract_items(
            "impl (A, B) {} fn other() { tokens! { #value #[cfg(test)] #(value) }; }",
        )
        .unwrap();
        assert_eq!(items.len(), 1);
        assert!(!definitions_are_exact(
            &items,
            "fn other() { tokens! { value }; }"
        ));
        for (expected, mutation) in [
            (
                "fn bounded() { return Err(InputError); }",
                "fn bounded() { returnErr(InputError); }",
            ),
            (
                "fn bounded() { accept(\"two words\"); }",
                "fn bounded() { accept(\"twowords\"); }",
            ),
        ] {
            let items = contract_items(mutation).unwrap();
            assert!(
                !definitions_are_exact(&items, expected),
                "collapsed tokens: {mutation}"
            );
        }
    }

    #[test]
    fn intake_guard_and_ownership_handoff_are_mutation_locked() {
        for (from, to) in [
            ("struct CredentialBytes {", "#[derive(Clone)] struct CredentialBytes {"),
            ("struct CredentialBytes {", "pub(crate) struct CredentialBytes {"),
            ("bytes: Zeroizing<Vec<u8>>,", "bytes: Vec<u8>,"),
            ("bytes: Zeroizing::new(bytes),", "bytes: bytes.into(),"),
            ("self.bytes.as_mut_slice().zeroize();", "self.bytes.as_mut_slice().fill(0);"),
            ("std::mem::take(&mut *self.bytes)", "self.bytes.to_vec()"),
            ("fn into_owned(mut self)", "fn into_owned(&mut self)"),
            ("CredentialBytes(<redacted>)", "CredentialBytes(visible)"),
            ("impl CredentialBytes {", "impl Clone for CredentialBytes { fn clone(&self) -> Self { panic!() } } impl CredentialBytes {"),
        ] {
            assert_mutation_fails(AUTH_INPUT, from, to,
                |source| inspect_auth_input_contract(source).unwrap(),
                "private non-cloneable Zeroizing guard");
        }
        for (from, to) in [
            (
                "WebAssessmentRootAuthorizationContext::new(bytes.into_owned())",
                "WebAssessmentRootAuthorizationContext::new(bytes.as_slice().to_vec())",
            ),
            (
                "PrimaryAuthorizationPrincipal::new(bytes.into_owned())",
                "PrimaryAuthorizationPrincipal::new(bytes.as_slice().to_vec())",
            ),
            (
                "PeerAuthorizationPrincipal::new(bytes.into_owned())",
                "PeerAuthorizationPrincipal::new(bytes.as_slice().to_vec())",
            ),
            (
                "AuthorizationReviewPolicy::parse_toml(target, policy_source.as_slice())",
                "AuthorizationReviewPolicy::parse_toml(target, &policy_source)",
            ),
        ] {
            assert_mutation_fails(
                AUTH_INPUT,
                from,
                to,
                |source| inspect_auth_input_contract(source).unwrap(),
                if from.starts_with("WebAssessment") {
                    "scanner-owned authorization-context constructor"
                } else {
                    "distinct role construction"
                },
            );
        }
    }

    #[test]
    fn environment_validation_must_follow_zeroizing_ownership() {
        for (from, to) in [
            ("validate_environment_value(value)\n}", "Ok(CredentialBytes::new(value.into_encoded_bytes()))\n}"),
            ("let bytes = CredentialBytes::new(value.into_encoded_bytes());", "let bytes = value.into_encoded_bytes();"),
            ("let bytes = CredentialBytes::new(value.into_encoded_bytes());", "let bytes = CredentialBytes::new(value.into_string().unwrap().into_bytes());"),
            ("std::str::from_utf8(bytes.as_slice()).map_err(|_| AuthorizationInputError::SourceNotUnicode)?;", "let _ = std::str::from_utf8(bytes.as_slice());"),
            ("if bytes.as_slice().len() > MAX_AUTHORIZATION_CONTEXT_BYTES", "if bytes.as_slice().len() > usize::MAX"),
            ("if name.is_empty()", "if false"),
            ("std::env::var_os(name).ok_or(AuthorizationInputError::SourceUnavailable)?", "std::env::var_os(name).unwrap_or_default()"),
        ] {
            assert_mutation_fails(AUTH_INPUT, from, to,
                |source| inspect_auth_input_contract(source).unwrap(),
                "environment reader must validate");
        }
    }

    #[test]
    fn atomic_open_and_same_handle_validation_are_mutation_locked() {
        for (from, to) in [
            ("pub(super) fn open_regular_file", "pub fn open_regular_file"),
            ("pub(super) fn open_regular_file", "pub(crate) fn open_regular_file"),
            ("pub(super) fn open_regular_file", "fn open_regular_file"),
            ("fn open_no_follow", "pub(super) fn open_no_follow"),
            ("validate_opened_regular_file(open_no_follow(&path)?)", "open_no_follow(&path)"),
            ("validate_opened_regular_file(open_no_follow(&path)?)", "{ let _ = std::fs::metadata(&path); File::open(path).map_err(|_| AuthorizationInputError::SourceUnavailable) }"),
            ("libc::O_NOFOLLOW | libc::O_NONBLOCK", "libc::O_NONBLOCK"),
            ("libc::O_NOFOLLOW | libc::O_NONBLOCK", "libc::O_NOFOLLOW"),
            ("#[cfg(unix)]\nfn open_no_follow", "#[cfg(any(unix, windows))]\nfn open_no_follow"),
            ("#[cfg(windows)]\nfn open_no_follow", "#[cfg(test)]\nfn open_no_follow"),
            ("#[cfg(not(any(unix, windows)))]\nfn open_no_follow", "#[cfg(not(unix))]\nfn open_no_follow"),
            ("FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS", "FILE_FLAG_BACKUP_SEMANTICS"),
            ("FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS", "FILE_FLAG_OPEN_REPARSE_POINT"),
            ("const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;", "const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0;"),
            (".security_qos_flags(0)", ".security_qos_flags(0x0002_0000)"),
            ("if opened_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0", "if false"),
            ("if !opened_metadata.is_file()", "if false"),
            ("fn validate_opened_regular_file(file: File) -> Result<File, AuthorizationInputError> {", "fn validate_opened_regular_file(mut file: File) -> Result<File, AuthorizationInputError> { let mut bytes = Vec::new(); file.read_to_end(&mut bytes).unwrap();"),
            ("    Ok(file)\n}", "    File::open(\"replacement\").map_err(|_| AuthorizationInputError::SourceUnavailable)\n}"),
        ] {
            assert_mutation_fails(AUTH_INPUT, from, to,
                |source| inspect_auth_input_contract(source).unwrap(),
                "exact platform no-follow flags");
        }
    }

    #[test]
    fn fixed_reads_overflow_and_removed_suffix_wiping_are_mutation_locked() {
        for (from, to) in [
            ("let mut bytes = CredentialBytes::new(vec![0; retained_limit]);", "let mut bytes = CredentialBytes::new(Vec::with_capacity(retained_limit));"),
            ("let mut bytes = CredentialBytes::new(vec![0; retained_limit]);", "let mut bytes = Vec::new(); reader.read_to_end(&mut bytes).unwrap(); let mut bytes = CredentialBytes::new(bytes);"),
            ("while filled < retained_limit", "while true"),
            ("reader.read(&mut bytes.bytes[filled..])", "reader.read(&mut bytes.bytes[..])"),
            (".checked_add(count)", ".saturating_add(count)"),
            (".filter(|filled| *filled <= retained_limit)", ".filter(|_| true)"),
            ("Err(_) => return Err(AuthorizationInputError::SourceReadFailed),", "Err(_) => break,"),
            ("bytes.bytes[filled..].zeroize();", "bytes.bytes[filled..].fill(0);"),
            ("if read_overflow_byte(reader, &mut overflow)? != 0", "if false"),
            ("overflow.zeroize();", "let _ = overflow;"),
            ("bytes[retained..].zeroize();", "let _ = &bytes[retained..];"),
            ("bytes.ends_with(b\"\\r\\n\")", "bytes.ends_with(b\"\\n\\n\")"),
            ("let retained = max_bytes.saturating_add(1);", "let retained = usize::MAX;"),
            ("ensure_opened_file_length(&file, max_bytes)?;", "let _ = max_bytes;"),
            ("if length > u64::try_from(max_bytes).unwrap_or(u64::MAX)", "if false"),
            ("    bytes.bytes.truncate(retained);", "    bytes.bytes.truncate(0);"),
        ] {
            assert_mutation_fails(AUTH_INPUT, from, to,
                |source| inspect_auth_input_contract(source).unwrap(),
                "probe one overflow byte");
        }
    }

    #[test]
    fn source_selection_and_dispatch_cannot_read_before_validation() {
        for (from, to) in [
            ("let selected = usize::from(environment.is_some())", "let _ = std::env::var_os(\"PREMATURE\"); let selected = usize::from(environment.is_some())"),
            ("ensure_opened_file_length(&file, MAX_AUTHORIZATION_CONTEXT_BYTES + 2)?;", "let _ = read_bounded_line_source(&mut file)?;"),
            ("read_bounded_line_source(&mut input)\n", "{ let mut bytes = Vec::new(); input.read_to_end(&mut bytes).unwrap(); Ok(CredentialBytes::new(bytes)) }\n"),
            ("Self::Environment(name) => read_environment(name),", "Self::Environment(name) => Ok(CredentialBytes::new(std::env::var_os(name).unwrap().into_encoded_bytes())),"),
        ] {
            assert_mutation_fails(AUTH_INPUT, from, to,
                |source| inspect_auth_input_contract(source).unwrap(),
                "source dispatch must use the bounded reader");
        }
    }

    #[test]
    fn cli_sources_and_pre_io_order_are_mutation_locked() {
        for (from, to, needle) in [
            (
                "mod auth_input;",
                "pub mod auth_input;",
                "must remain a private",
            ),
            (
                "auth_env: Option<OsString>,",
                "authorization: Option<String>,",
                "exact root and resource-review",
            ),
            (
                "    auth_stdin: bool,",
                "    auth_stdin: bool,\n    credential: String,",
                "field inventory and types must remain exact",
            ),
            (
                "    #[cfg(feature = \"openapi-review\")]\n    #[arg(long, requires = \"profile\")]\n    openapi_review: bool,",
                "    #[arg(long, requires = \"profile\")]\n    openapi_review: bool,",
                "must remain an exact cfg-gated bool",
            ),
            (
                "conflicts_with_all = [\"report_format\", \"report_output\"]",
                "conflicts_with = \"report_format\"",
                "conflicting with both single-report output options",
            ),
            (
                "conflicts_with_all = [\"auth_file\", \"auth_stdin\"]",
                "conflicts_with_all = [\"auth_stdin\"]",
                "exact out-of-band type",
            ),
            (
                "preflight_report_output(report_output.as_deref())?;",
                "let _deferred_report_preflight = report_output.as_deref();",
                "preflight the selected report output",
            ),
            (
                "let mut report_bundle = report_bundle::reserve_report_bundle(report_dir.as_deref())?;",
                "let mut report_bundle = report_dir.as_deref();",
                "exclusively reserve the selected report bundle directory",
            ),
            (
                "authorization_context_transport_is_allowed(&target)",
                "is_exact_origin_root(&target)",
                "authenticated-transport checks",
            ),
            (
                "#[derive(Subcommand)]\nenum Commands",
                "#[derive(Subcommand, Debug)]\nenum Commands",
                "must not implement Clone, Debug",
            ),
            (
                "    Scan(Box<ScanArgs>),",
                "    Scan(ScanArgs),",
                "exact Box<ScanArgs> payload",
            ),
            (
                "#[derive(Args)]\nstruct ScanArgs",
                "#[derive(Args, Debug)]\nstruct ScanArgs",
                "without exposing derives",
            ),
        ] {
            assert_mutation_fails(
                CLI_MAIN,
                from,
                to,
                |source| inspect_cli_auth_surface(source).unwrap(),
                needle,
            );
        }
    }

    #[test]
    fn resource_review_policy_roles_and_raw_value_absence_are_mutation_locked() {
        for (from, to, needle) in [
            (
                "pub(crate) struct AuthorizationReviewInput {",
                "#[derive(Clone)]\npub(crate) struct AuthorizationReviewInput {",
                "underived",
            ),
            (
                ".debug_struct(\"AuthorizationReviewInput\")\n            .field(\"policy_file\", &\"<redacted>\")",
                ".debug_struct(\"AuthorizationReviewInput\")\n            .field(\"policy_file\", &self.policy_file)",
                "value-free redacted Debug",
            ),
            (
                "let both_stdin = primary.stdin && peer.stdin;",
                "let both_stdin = false;",
                "stdin isolation",
            ),
            (
                "formatter.write_str(\"AuthorizationSourceOptions(<redacted>)\")",
                "formatter.write_str(\"AuthorizationSourceOptions(visible)\")",
                "value-free redacted Debug",
            ),
            (
                "AuthorizationPrincipalPair::new(primary, peer)",
                "AuthorizationPrincipalPair::from_unchecked(primary, peer)",
                "distinct role construction",
            ),
        ] {
            assert_mutation_fails(
                AUTH_INPUT,
                from,
                to,
                |source| inspect_auth_input_contract(source).unwrap(),
                needle,
            );
        }

        assert_mutation_fails(
            CLI_MAIN,
            "    authz_peer_stdin: bool,",
            "    authz_peer_stdin: bool,\n    credential: String,",
            |source| inspect_cli_auth_surface(source).unwrap(),
            "field inventory and types must remain exact",
        );
        assert_mutation_fails(
            CLI_MAIN,
            "conflicts_with_all = [\"authz_peer_env\", \"authz_peer_file\", \"authz_primary_stdin\"]",
            "conflicts_with_all = [\"authz_peer_env\", \"authz_peer_file\"]",
            |source| inspect_cli_auth_surface(source).unwrap(),
            "exact out-of-band type",
        );
    }

    #[test]
    fn scanner_context_must_use_bounded_strategy_and_redacted_trait_surface() {
        for (from, to, needle) in [
            (
                "pub struct WebAssessmentRootAuthorizationContext {",
                "#[derive(Clone)]\npub struct WebAssessmentRootAuthorizationContext {",
                "must remain non-cloneable",
            ),
            (
                "PayloadSeed::new(value, limits)",
                "PayloadSeed::new_unbounded(value)",
                "existing control/candidate payload strategy",
            ),
            (
                "PayloadVariantRole::Candidate, &seed, limits",
                "PayloadVariantRole::Candidate, &seed, PayloadStrategyLimits::default_unbounded()",
                "existing control/candidate payload strategy",
            ),
            (
                "WebAssessmentRootAuthorizationContext(<redacted>)",
                "WebAssessmentRootAuthorizationContext(value)",
                "exact value-free redaction",
            ),
            (
                "    fn into_candidate_header_value(self) -> String {",
                "    pub(crate) fn as_str(&self) -> &str { &self.candidate_header_value }\n\n    fn into_candidate_header_value(self) -> String {",
                "method inventory must remain exactly",
            ),
            (
                "pub const DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES: u32 = 4 * 1024;",
                "pub const DEFAULT_MAX_PAYLOAD_ARTIFACT_BYTES: u32 = 8 * 1024;",
                "aligned with the existing 4 KiB",
            ),
        ] {
            if from.contains("DEFAULT_MAX_PAYLOAD") {
                assert_mutation_fails(
                    PAYLOAD_STRATEGY,
                    from,
                    to,
                    |payload| {
                        inspect_scanner_context_validation(SCANNER_CONTEXT, payload).unwrap()
                    },
                    needle,
                );
            } else {
                assert_mutation_fails(
                    SCANNER_CONTEXT,
                    from,
                    to,
                    |scanner| {
                        inspect_scanner_context_validation(scanner, PAYLOAD_STRATEGY).unwrap()
                    },
                    needle,
                );
            }
        }
    }

    #[test]
    fn protected_types_cannot_gain_cross_source_aliases_impls_or_macros() {
        let protected = &["AuthorizationInputSource", "AuthorizationInputError"];
        for (source, needle) in [
            (
                "impl AuthorizationInputSource { fn expose(&self) {} }",
                "inherent or trait implementation",
            ),
            (
                "impl std::fmt::Display for crate::auth_input::AuthorizationInputSource { fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) } }",
                "inherent or trait implementation",
            ),
            (
                "use crate::auth_input::AuthorizationInputSource as Secret; impl std::fmt::Display for Secret { fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Ok(()) } }",
                "inherent or trait implementation",
            ),
            (
                "use crate::auth_input::AuthorizationInputSource as Secret; fn consume(_: Secret) {}",
                "imported under an alias",
            ),
            (
                "type Secret = crate::auth_input::AuthorizationInputSource; impl Secret { fn expose(&self) {} }",
                "aliased outside its owner",
            ),
            (
                "expose! { impl Display for AuthorizationInputSource {} }",
                "item macro",
            ),
            (
                "fn hidden() { expose! { impl Display for AuthorizationInputSource {} } }",
                "trait-generating macro",
            ),
        ] {
            let violations =
                external_protected_type_violations("other.rs", source, protected)
                    .unwrap()
                    .join("\n");
            assert!(violations.contains(needle), "{violations}");
        }

        assert!(external_protected_type_violations(
            "consumer.rs",
            "fn consume(_: crate::auth_input::AuthorizationInputSource) {}",
            protected,
        )
        .unwrap()
        .is_empty());
    }
}
