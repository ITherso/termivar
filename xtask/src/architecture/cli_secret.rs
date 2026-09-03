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

use proc_macro2::TokenStream;
use syn::{
    visit::{self, Visit},
    Attribute, Expr, Fields, FnArg, ImplItem, Item, ItemEnum, ItemFn, Meta, Pat, ReturnType, Type,
    Visibility,
};

const AUTH_INPUT_SOURCE: &str = "crates/venom-cli/src/auth_input.rs";
const CLI_MAIN_SOURCE: &str = "crates/venom-cli/src/main.rs";
const SCANNER_CONTEXT_SOURCE: &str =
    "crates/venom-scanner/src/web_runtime/assessment_api_visibility.rs";
const PAYLOAD_STRATEGY_SOURCE: &str = "crates/venom-scanner/src/payload_strategy.rs";

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
    "openapi_review",
    "rest_review",
    "profile",
    "report_format",
    "report_output",
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
            workspace_root.join("crates/venom-cli/src"),
            AUTH_INPUT_SOURCE,
            &[
                "AuthorizationInputSource",
                "AuthorizationInputError",
                "AuthorizationReviewInput",
                "AuthorizationReviewInputError",
                "AuthorizationSourceOptions",
            ][..],
        ),
        (
            workspace_root.join("crates/venom-cli/src"),
            CLI_MAIN_SOURCE,
            &["Cli", "Commands", "ScanArgs"][..],
        ),
        (
            workspace_root.join("crates/venom-scanner/src"),
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
            "WebAssessmentRootAuthorizationContext::new(bytes).map_err(|_|AuthorizationInputError::InvalidValue)",
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
        (
            "open_regular_file",
            "CLI file authorization input must remain one private regular-file opener",
        ),
    ] {
        if find_function(&syntax, function_name)
            .is_none_or(|function| !matches!(function.vis, Visibility::Inherited))
        {
            violations.push(message.to_owned());
        }
    }

    if !bounded_reader_is_exact(&compact) {
        violations.push(
            "CLI file/stdin reader must retain at most 4 KiB plus one CRLF, probe one overflow byte, remove only one terminal line ending, and fail closed"
                .to_owned(),
        );
    }
    if !environment_reader_is_exact(&compact) {
        violations.push(
            "CLI environment reader must validate the source name, discard OS diagnostics, and enforce the 4 KiB ceiling before construction"
                .to_owned(),
        );
    }
    if !regular_file_open_is_exact(&compact) {
        violations.push(
            "CLI file authorization source must reject non-regular paths before opening and re-check the opened handle without retaining filesystem diagnostics"
                .to_owned(),
        );
    }
    if !source_dispatch_is_exact(&compact) {
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
        "AuthorizationReviewPolicy::parse_toml(target,&policy_source)",
        "self.primary.read_bytes()",
        "self.peer.read_bytes()",
        "PrimaryAuthorizationPrincipal::new(bytes)",
        "PeerAuthorizationPrincipal::new(bytes)",
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
        ("openapi_review", "bool", None),
        ("authorization_review_policy", "Option", Some("PathBuf")),
        ("authz_primary_env", "Option", Some("OsString")),
        ("authz_primary_file", "Option", Some("PathBuf")),
        ("authz_primary_stdin", "bool", None),
        ("authz_peer_env", "Option", Some("OsString")),
        ("authz_peer_file", "Option", Some("PathBuf")),
        ("authz_peer_stdin", "bool", None),
        ("report_format", "Option", Some("CliReportFormat")),
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
            .matches("auth_input::AuthorizationSourceOptions::new(")
            .count()
            != 2
    {
        violations.push(
            "CLI must select one policy plus exactly one primary and peer out-of-band source without reading them"
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
        "scan_profile_flags_conflict",
        "scan_report_flags_conflict",
        "scan_resource_authorization_flags_conflict",
        "select",
        "scan_authorization_flags_conflict",
        "is_exact_origin_root",
        "authorization_context_transport_is_allowed",
        "select",
        "authorization_context_transport_is_allowed",
        "for_builtin",
        "with_defense_enforcement_enabled",
        "preflight_report_output",
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
            != 2
        || ordered
            .iter()
            .filter(|name| name.as_str() == "select")
            .count()
            != 2
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

fn bounded_reader_is_exact(compact: &str) -> bool {
    [
        "letretained_limit=MAX_AUTHORIZATION_CONTEXT_BYTES.saturating_add(2);",
        "letmutbytes=Vec::with_capacity(retained_limit);",
        ".by_ref().take(u64::try_from(retained_limit).unwrap_or(u64::MAX)).read_to_end(&mutbytes).map_err(|_|AuthorizationInputError::SourceReadFailed)?;",
        "letmutoverflow=[0_u8;1];",
        "reader.read(&mutoverflow).map_err(|_|AuthorizationInputError::SourceReadFailed)?!=0",
        "returnErr(AuthorizationInputError::ValueTooLarge);",
        "ifbytes.ends_with(b\"\\r\\n\")",
        "bytes.truncate(bytes.len().saturating_sub(2));",
        "elseifbytes.ends_with(b\"\\n\")",
        "bytes.truncate(bytes.len().saturating_sub(1));",
        "ifbytes.len()>MAX_AUTHORIZATION_CONTEXT_BYTES",
    ]
    .iter()
    .all(|marker| compact.contains(marker))
}

fn environment_reader_is_exact(compact: &str) -> bool {
    [
        "name.into_string().map_err(|_|AuthorizationInputError::SourceNameInvalid)?",
        "ifname.is_empty()||name.chars().any(|character|matches!(character,'='|'\\0'))",
        "std::env::var_os(name).ok_or(AuthorizationInputError::SourceUnavailable)?",
        "value.into_string().map_err(|_|AuthorizationInputError::SourceNotUnicode)?",
        "letbytes=value.into_bytes();",
        "ifbytes.len()>MAX_AUTHORIZATION_CONTEXT_BYTES",
    ]
    .iter()
    .all(|marker| compact.contains(marker))
}

fn regular_file_open_is_exact(compact: &str) -> bool {
    compact
        .matches("file.metadata().map_err(|_|AuthorizationInputError::SourceUnavailable)?")
        .count()
        == 2
        && [
            "fs::symlink_metadata(&path).map_err(|_|AuthorizationInputError::SourceUnavailable)?",
            "if!metadata.file_type().is_file()",
            "returnErr(AuthorizationInputError::SourceNotRegularFile);",
            "File::open(path).map_err(|_|AuthorizationInputError::SourceUnavailable)?",
            "file.metadata().map_err(|_|AuthorizationInputError::SourceUnavailable)?",
            "if!opened_metadata.is_file()",
            "Ok(file)",
        ]
        .iter()
        .all(|marker| compact.contains(marker))
}

fn source_dispatch_is_exact(compact: &str) -> bool {
    [
        "Self::Environment(name)=>read_environment(name)",
        "Self::File(path)=>{letmutfile=open_regular_file(path)?;",
        "read_bounded_line_source(&mutfile)}",
        "Self::Stdin=>{letstdin=io::stdin();letmutinput=stdin.lock();read_bounded_line_source(&mutinput)}",
    ]
    .iter()
    .all(|marker| compact.contains(marker))
}

fn ordered_boundary_references(function: &ItemFn) -> Vec<String> {
    const OBSERVED: &[&str] = &[
        "scan_flags_conflict",
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

    const AUTH_INPUT: &str = include_str!("../../../crates/venom-cli/src/auth_input.rs");
    const CLI_MAIN: &str = include_str!("../../../crates/venom-cli/src/main.rs");
    const SCANNER_CONTEXT: &str =
        include_str!("../../../crates/venom-scanner/src/web_runtime/assessment_api_visibility.rs");
    const PAYLOAD_STRATEGY: &str =
        include_str!("../../../crates/venom-scanner/src/payload_strategy.rs");

    fn assert_mutation_fails(
        original: &str,
        from: &str,
        to: &str,
        inspect: impl FnOnce(&str) -> Vec<String>,
        needle: &str,
    ) {
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
        assert!(inspect_auth_input_contract(AUTH_INPUT).unwrap().is_empty());
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
                ".take(u64::try_from(retained_limit).unwrap_or(u64::MAX))",
                ".take(u64::MAX)",
                "probe one overflow byte",
            ),
            (
                "    let mut overflow = [0_u8; 1];",
                "    let mut overflow = [0_u8; 0];",
                "probe one overflow byte",
            ),
            (
                "    SourceUnavailable,",
                "    SourceUnavailable(String),",
                "value-free unit-variant",
            ),
            (
                "    let metadata =\n        fs::symlink_metadata(&path)",
                "    let metadata =\n        fs::metadata(&path)",
                "reject non-regular paths before opening",
            ),
            (
                "    let opened_metadata = file\n        .metadata()",
                "    let opened_metadata = metadata",
                "reject non-regular paths before opening",
            ),
            (
                "Self::SourceReadFailed => \"authorization-context input source could not be read\"",
                "Self::SourceReadFailed => \"source failed\"",
                "static credential-free",
            ),
            (
                "WebAssessmentRootAuthorizationContext::new(bytes)",
                "WebAssessmentRootAuthorizationContext::from_unchecked(bytes)",
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
                ".field(\"policy_file\", &\"<redacted>\")",
                ".field(\"policy_file\", &self.policy_file)",
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
