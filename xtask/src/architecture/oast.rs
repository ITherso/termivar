//! Exact architecture contract for the provider-neutral OAST correlation
//! foundation. The scanner module owns bounded correlation state and typed
//! observations only; hosts retain all transport, scheduling, entropy, clock,
//! reporting, and vulnerability-classification authority.

use std::{
    collections::BTreeSet,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use proc_macro2::{TokenStream, TokenTree};
use syn::{
    visit::{self, Visit},
    AngleBracketedGenericArguments, Attribute, Expr, Fields, FnArg, GenericArgument, ImplItem,
    Item, ItemImpl, ItemStruct, LitByteStr, LitStr, Macro, Member, Meta, Path as SynPath,
    PathArguments, ReturnType, Signature, Type, UseTree, Visibility,
};

const MODULE_NAME: &str = "oast";
const NATIVE_PROVIDER_ADAPTER: &str = "native_oast_provider.rs";
const FEATURE_PREDICATE: &str = "feature=\"oast-correlation\"";
const SECRET_TYPE: &str = "OastCorrelationToken";
const SECRET_FIELD: &str = "secret_bytes";
const VERIFICATION_BINDING_LIMIT: &str = "MAX_VERIFICATION_BINDING_COMPONENT_BYTES";

const EXACT_PRIVATE_STRUCT_FIELDS: &[(&str, &[(&str, &str)])] = &[
    (
        "OastDnsEvent",
        &[
            ("transport", "OastDnsTransport"),
            ("record_type", "OastDnsRecordType"),
        ],
    ),
    (
        "OastHttpEvent",
        &[
            ("scheme", "OastHttpScheme"),
            ("method", "OastHttpMethod"),
            ("body_present", "bool"),
        ],
    ),
    (
        "OastRegistrationReceipt",
        &[
            ("binding_id", "OastBindingId"),
            ("correlation_id", "OastCorrelationId"),
            ("issued_at", "OastMonotonicTime"),
            ("expires_at", "OastMonotonicTime"),
            ("poll_limit", "u16"),
            ("allowed_protocols", "OastProtocolSet"),
        ],
    ),
    (
        "OastEventReceipt",
        &[
            ("event_key", "OastEventKey"),
            ("protocol", "OastEventProtocol"),
            ("disposition", "OastEventDisposition"),
            ("observed_at", "OastMonotonicTime"),
        ],
    ),
    (
        "OastPollReceipt",
        &[
            ("binding_id", "OastBindingId"),
            ("correlation_id", "OastCorrelationId"),
            ("poll_ordinal", "u16"),
            ("completed_at", "OastMonotonicTime"),
            ("event_receipts", "Vec<OastEventReceipt>"),
            ("accepted_events", "u16"),
            ("duplicate_events", "u16"),
            ("remaining_polls", "u16"),
        ],
    ),
    (
        "OastTerminalReceipt",
        &[
            ("binding_id", "OastBindingId"),
            ("correlation_id", "OastCorrelationId"),
            ("state", "OastCorrelationState"),
            ("terminal_at", "OastMonotonicTime"),
        ],
    ),
];

const EXACT_DIGEST_DOMAINS: &[(&str, &[u8])] = &[
    (
        "TOKEN_REUSE_DOMAIN",
        b"security.oast-correlation.token-reuse.v1\0",
    ),
    (
        "BINDING_ID_DOMAIN",
        b"security.oast-correlation.binding.v1\0",
    ),
    (
        "CORRELATION_ID_DOMAIN",
        b"security.oast-correlation.id.v1\0",
    ),
];

const OPAQUE_REDACTED_TYPES: &[(&str, &[&str])] = &[
    ("OastAuthorityEpoch", &["new"]),
    ("OastBindingId", &[]),
    ("OastCorrelationId", &[]),
    ("OastEventKey", &["new"]),
];

const RAW_EXPOSING_TRAITS: &[&str] = &[
    "AsRef",
    "Borrow",
    "Deref",
    "Deserialize",
    "Display",
    "From",
    "Index",
    "Into",
    "IntoIterator",
    "Serialize",
];

const EXACT_PUBLIC_TYPES: &[&str] = &[
    "OastAssessmentId",
    "OastAuthorityEpoch",
    "OastAuthorityLimits",
    "OastBindingId",
    "OastCorrelationToken",
    "OastCorrelationId",
    "OastCorrelation",
    "OastCorrelationAuthority",
    "OastCorrelationState",
    "OastMonotonicTime",
    "OastLifetime",
    "OastPollBudget",
    "OastPollPermit",
    "OastEvent",
    "OastEventKey",
    "OastDnsEvent",
    "OastDnsTransport",
    "OastDnsRecordType",
    "OastHttpEvent",
    "OastHttpScheme",
    "OastHttpMethod",
    "OastEventProtocol",
    "OastEventDisposition",
    "OastRegistrationReceipt",
    "OastEventReceipt",
    "OastPollReceipt",
    "OastProtocolSet",
    "OastTerminalReceipt",
    "OastError",
];

const FORBIDDEN_AUTHORITY_WORDS: &[&str] = &[
    "action",
    "broker",
    "cli",
    "client",
    "command",
    "execute",
    "execution",
    "executor",
    "finding",
    "network",
    "process",
    "provider",
    "report",
    "reporter",
    "reporting",
    "runtime",
    "severity",
    "socket",
    "vulnerability",
];

const FORBIDDEN_EXTERNAL_ROOTS: &[&str] = &[
    "async_std",
    "chrono",
    "getrandom",
    "hyper",
    "mio",
    "nanoid",
    "rand",
    "reqwest",
    "smol",
    "time",
    "tokio",
    "ulid",
    "ureq",
    "uuid",
];

const FORBIDDEN_FOUNDATION_ROOTS: &[&str] =
    &["core", "serde", "serde_json", "termivar_core", "thiserror"];

const ALLOWED_STD_MODULES: &[&str] = &["collections", "error", "fmt"];

const FORBIDDEN_PROJECTION_WORDS: &[&str] = &[
    "evidence",
    "hypothesis",
    "outcome",
    "project",
    "projected",
    "projector",
    "projection",
    "transition",
];

const FORBIDDEN_AMBIENT_IDENTIFIERS: &[&str] = &[
    "HashMap",
    "HashSet",
    "Instant",
    "LazyLock",
    "OnceLock",
    "OsRng",
    "RandomState",
    "SystemTime",
    "ThreadRng",
    "UNIX_EPOCH",
    "Ulid",
    "Uuid",
];

const FORBIDDEN_STD_MODULES: &[&str] = &["env", "fs", "io", "net", "os", "process", "thread"];
const FORBIDDEN_MACROS: &[&str] = &[
    "concat",
    "concat_bytes",
    "dbg",
    "eprint",
    "eprintln",
    "env",
    "option_env",
    "print",
    "println",
    "stringify",
    "thread_local",
];

const PROVIDER_OR_TARGET_LITERALS: &[&str] = &[
    "127.0.0.1",
    "169.254.169.254",
    "::1",
    "beeceptor",
    "burp collaborator",
    "burpcollaborator",
    "canarytokens",
    "dnslog.cn",
    "interact.sh",
    "interactsh",
    "localhost",
    "oastify",
    "pingb.in",
    "requestbin",
    "webhook.site",
];

pub(super) fn foundation_contract_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut violations = public_surface_violations(&syntax);
    violations.extend(private_record_shape_violations(&syntax));
    violations.extend(secret_contract_violations(&syntax));
    violations.extend(secret_drop_contract_violations(&syntax));
    violations.extend(opaque_identifier_contract_violations(&syntax));
    violations.extend(digest_domain_violations(&syntax));
    violations.extend(verification_binding_contract_violations(&syntax));

    let mut authority = AuthorityVisitor::default();
    authority.visit_file(&syntax);
    violations.extend(authority.violations);

    Ok(violations.into_iter().collect())
}

pub(super) fn library_wiring_violations(source: &str) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let declarations = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(module) if module.ident == MODULE_NAME => Some(module),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut violations = BTreeSet::new();

    match declarations.as_slice() {
        [declaration]
            if matches!(declaration.vis, Visibility::Public(_))
                && declaration.content.is_none()
                && has_exact_cfg(&declaration.attrs, FEATURE_PREDICATE) => {},
        _ => {
            violations.insert(
                "lib.rs must expose exactly one out-of-line OAST module as `#[cfg(feature = \"oast-correlation\")] pub mod oast;`"
                    .to_owned(),
            );
        },
    }

    for item in &syntax.items {
        if matches!(item, Item::Mod(module) if module.ident == MODULE_NAME)
            || super::has_cfg_test(super::item_attributes(item))
        {
            continue;
        }
        let mut visitor = RootOastReferenceVisitor::default();
        visitor.visit_item(item);
        if visitor.references_oast {
            violations.insert(
                "lib.rs must not re-export, alias, or extend OAST types; the only public boundary is `termivar_scanner::oast`"
                    .to_owned(),
            );
        }
    }

    Ok(violations.into_iter().collect())
}

pub(super) fn repository_consumer_violations(
    source_root: &Path,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut paths = Vec::new();
    collect_rust_sources(source_root, &mut paths)?;
    paths.sort();
    let mut violations = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(source_root)?
            .to_string_lossy()
            .replace('\\', "/");
        if relative == "oast.rs" {
            continue;
        }
        let source = fs::read_to_string(&path)?;
        violations.extend(consumer_source_violations(
            &relative,
            &source,
            relative == "lib.rs",
        )?);
    }
    Ok(violations)
}

fn collect_rust_sources(root: &Path, output: &mut Vec<PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_rust_sources(&path, output)?;
        } else if metadata.is_file() && path.extension().is_some_and(|value| value == "rs") {
            output.push(path);
        }
    }
    Ok(())
}

fn consumer_source_violations(
    relative_path: &str,
    source: &str,
    is_library: bool,
) -> Result<Vec<String>, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut visitor = OastConsumerVisitor::default();
    for item in &syntax.items {
        if is_library && matches!(item, Item::Mod(module) if module.ident == MODULE_NAME) {
            continue;
        }
        visitor.visit_item(item);
    }
    if visitor.references_oast && relative_path != NATIVE_PROVIDER_ADAPTER {
        Ok(vec![format!(
            "termivar-scanner production source `{relative_path}` must not consume crate::oast or Oast* types; only the sealed native_oast_provider.rs host adapter may use the correlation boundary"
        )])
    } else if !visitor.references_oast && relative_path == NATIVE_PROVIDER_ADAPTER {
        Ok(vec![
            "the sealed native_oast_provider.rs adapter must consume the existing crate::oast correlation boundary"
                .to_owned(),
        ])
    } else {
        Ok(Vec::new())
    }
}

#[derive(Default)]
struct OastConsumerVisitor {
    references_oast: bool,
}

impl OastConsumerVisitor {
    fn inspect_segments<'a>(&mut self, segments: impl IntoIterator<Item = &'a str>) {
        let segments = segments.into_iter().collect::<Vec<_>>();
        if segments
            .windows(2)
            .any(|pair| pair == ["crate", MODULE_NAME])
            || segments.iter().any(|segment| segment.starts_with("Oast"))
        {
            self.references_oast = true;
        }
    }
}

impl<'ast> Visit<'ast> for OastConsumerVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if super::has_cfg_test(super::item_attributes(item)) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_ident(&mut self, identifier: &'ast syn::Ident) {
        if identifier.to_string().starts_with("Oast") {
            self.references_oast = true;
        }
        visit::visit_ident(self, identifier);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for segments in paths {
            self.inspect_segments(segments.iter().map(String::as_str));
        }
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.inspect_segments(segments.iter().map(String::as_str));
        visit::visit_path(self, path);
    }
}

fn public_surface_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    let mut actual = BTreeSet::new();

    for item in &syntax.items {
        if super::has_cfg_test(super::item_attributes(item)) {
            continue;
        }
        match item {
            Item::Enum(item) if is_public(&item.vis) => {
                actual.insert(item.ident.to_string());
            },
            Item::Struct(item) if is_public(&item.vis) => {
                actual.insert(item.ident.to_string());
                if item
                    .fields
                    .iter()
                    .any(|field| !matches!(field.vis, Visibility::Inherited))
                {
                    violations.insert(format!(
                        "OAST public type `{}` must keep every field private behind bounded constructors",
                        item.ident
                    ));
                }
            },
            Item::Const(item) if is_public(&item.vis) => {
                reject_public_item(&mut violations, "constant", &item.ident.to_string());
            },
            Item::Fn(item) if is_public(&item.vis) => {
                reject_public_item(
                    &mut violations,
                    "free function",
                    &item.sig.ident.to_string(),
                );
            },
            Item::Static(item) if is_public(&item.vis) => {
                reject_public_item(&mut violations, "static", &item.ident.to_string());
            },
            Item::Trait(item) if is_public(&item.vis) => {
                reject_public_item(&mut violations, "trait", &item.ident.to_string());
            },
            Item::TraitAlias(item) if is_public(&item.vis) => {
                reject_public_item(&mut violations, "trait alias", &item.ident.to_string());
            },
            Item::Type(item) if is_public(&item.vis) => {
                reject_public_item(&mut violations, "type alias", &item.ident.to_string());
            },
            Item::Union(item) if is_public(&item.vis) => {
                reject_public_item(&mut violations, "union", &item.ident.to_string());
            },
            Item::Use(item) if is_public(&item.vis) => {
                violations.insert(
                    "OAST foundation must not widen its exact public surface with re-exports"
                        .to_owned(),
                );
            },
            _ => {},
        }
    }

    let expected = EXACT_PUBLIC_TYPES.iter().copied().collect::<BTreeSet<_>>();
    let actual_names = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    for missing in expected.difference(&actual_names) {
        violations.insert(format!(
            "OAST exact public surface is missing type `{missing}`"
        ));
    }
    for unexpected in actual_names.difference(&expected) {
        violations.insert(format!(
            "OAST exact public surface contains unreviewed type `{unexpected}`"
        ));
    }
    violations
}

fn reject_public_item(violations: &mut BTreeSet<String>, kind: &str, identifier: &str) {
    violations.insert(format!(
        "OAST foundation must not expose public {kind} `{identifier}` outside its exact typed surface"
    ));
}

fn private_record_shape_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    for (type_name, expected_fields) in EXACT_PRIVATE_STRUCT_FIELDS {
        let declarations = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(item)
                    if !super::has_cfg_test(&item.attrs) && item.ident == *type_name =>
                {
                    Some(item)
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        let [declaration] = declarations.as_slice() else {
            violations.insert(format!(
                "OAST raw-free record `{type_name}` must have exactly one reviewed declaration"
            ));
            continue;
        };
        let Fields::Named(fields) = &declaration.fields else {
            violations.insert(format!(
                "OAST raw-free record `{type_name}` must use its exact private named-field shape"
            ));
            continue;
        };
        let actual = fields
            .named
            .iter()
            .map(|field| {
                (
                    field.ident.as_ref().map(ToString::to_string),
                    type_key(&field.ty),
                    matches!(field.vis, Visibility::Inherited),
                    attributes_contain_any(&field.attrs, &["serde", "serialize", "deserialize"]),
                )
            })
            .collect::<Vec<_>>();
        let expected = expected_fields
            .iter()
            .map(|(name, ty)| {
                (
                    Some((*name).to_owned()),
                    Some((*ty).to_owned()),
                    true,
                    false,
                )
            })
            .collect::<Vec<_>>();
        if actual != expected
            || attributes_contain_any(&declaration.attrs, &["Serialize", "Deserialize", "serde"])
        {
            violations.insert(format!(
                "OAST raw-free record `{type_name}` fields must remain exactly private {expected_fields:?} with no serde expansion; found {actual:?}"
            ));
        }
    }
    violations
}

fn type_key(ty: &Type) -> Option<String> {
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() || path.path.segments.len() != 1 {
        return None;
    }
    let segment = &path.path.segments[0];
    let name = segment.ident.to_string();
    match &segment.arguments {
        PathArguments::None => Some(name),
        PathArguments::AngleBracketed(arguments) => {
            let types = arguments
                .args
                .iter()
                .map(|argument| match argument {
                    GenericArgument::Type(ty) => type_key(ty),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            Some(format!("{name}<{}>", types.join(",")))
        },
        PathArguments::Parenthesized(_) => None,
    }
}

fn secret_contract_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    let tokens = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Struct(item)
                if !super::has_cfg_test(&item.attrs) && item.ident == SECRET_TYPE =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();

    match tokens.as_slice() {
        [token] => inspect_secret_token(token, &mut violations),
        _ => {
            violations.insert(format!(
                "OAST foundation must declare exactly one `{SECRET_TYPE}` secret token"
            ));
        },
    }

    let mut debug_impls = 0usize;
    let mut constructors = 0usize;
    for item in &syntax.items {
        let Item::Impl(item) = item else {
            continue;
        };
        if super::has_cfg_test(&item.attrs) {
            continue;
        }

        let trait_name = item
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .map(|segment| segment.ident.to_string());
        if trait_name.as_deref().is_some_and(|name| {
            RAW_EXPOSING_TRAITS.contains(&name) || matches!(name, "Clone" | "Copy")
        }) && impl_header_references_type(item, SECRET_TYPE)
        {
            violations.insert(format!(
                "OAST secret token must not participate in exposing, copy, display, or serde trait `{}`",
                trait_name.as_deref().expect("checked as present")
            ));
        }
        if impl_self_type(item).as_deref() != Some(SECRET_TYPE) {
            continue;
        }
        if trait_name.as_deref() == Some("Debug") {
            debug_impls += 1;
            let mut debug = SecretDebugVisitor::default();
            debug.visit_item_impl(item);
            if debug.references_secret || debug.references_self || !debug.has_redaction_marker {
                violations.insert(
                    "OAST secret token Debug implementation must be redacted and must not inspect `secret_bytes`"
                        .to_owned(),
                );
            }
        }
        if trait_name.as_deref().is_some_and(|name| {
            RAW_EXPOSING_TRAITS.contains(&name) || matches!(name, "Clone" | "Copy")
        }) {
            violations.insert(format!(
                "OAST secret token must not implement exposing, copy, display, or serde trait `{}`",
                trait_name.expect("checked as present")
            ));
        }
        if item.trait_.is_none() {
            for implementation_item in &item.items {
                if let ImplItem::Fn(method) = implementation_item {
                    if is_public(&method.vis) {
                        if method.sig.ident == "new" {
                            constructors += 1;
                            if !is_32_byte_result_constructor(&method.sig) {
                                violations.insert(
                                    "OAST secret token constructor must consume exactly one 32-byte host value and return Result<Self, OastError>"
                                        .to_owned(),
                                );
                            }
                        } else {
                            violations.insert(format!(
                                "OAST secret token must not expose raw getter or conversion method `{}`",
                                method.sig.ident
                            ));
                        }
                    }
                }
            }
        }
    }
    if debug_impls != 1 {
        violations.insert(format!(
            "OAST secret token must have exactly one custom redacted Debug implementation; found {debug_impls}"
        ));
    }
    if constructors != 1 {
        violations.insert(format!(
            "OAST secret token must expose exactly one `new` constructor; found {constructors}"
        ));
    }

    violations
}

fn secret_drop_contract_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    let token_impls = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if !super::has_cfg_test(&item.attrs)
                    && impl_self_type(item).as_deref() == Some(SECRET_TYPE) =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let drop_methods = token_impls
        .iter()
        .filter(|item| {
            item.trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .is_some_and(|segment| segment.ident == "Drop")
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "drop" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let erase_methods = token_impls
        .iter()
        .filter(|item| item.trait_.is_none())
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "erase" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();

    let drop_is_exact = matches!(drop_methods.as_slice(), [method]
    if single_method_call(&method.block).is_some_and(|call| {
        call.method == "erase" && is_self_path(&call.receiver)
    }));
    let erase_is_exact = matches!(erase_methods.as_slice(), [method]
    if matches!(method.vis, Visibility::Inherited)
        && single_method_call(&method.block).is_some_and(|call| {
            call.method == "zeroize" && is_self_secret_field(&call.receiver)
        }));
    if !drop_is_exact || !erase_is_exact {
        violations.insert(
            "OAST correlation token Drop must call one private `erase` method whose only operation is `self.secret_bytes.zeroize()`"
                .to_owned(),
        );
    }
    violations
}

fn single_method_call(block: &syn::Block) -> Option<&syn::ExprMethodCall> {
    let [syn::Stmt::Expr(expression, _)] = block.stmts.as_slice() else {
        return None;
    };
    match expression {
        Expr::MethodCall(call) => Some(call),
        _ => None,
    }
}

fn is_self_path(expression: &Expr) -> bool {
    matches!(expression, Expr::Path(path) if path.qself.is_none() && path.path.is_ident("self"))
}

fn is_self_secret_field(expression: &Expr) -> bool {
    matches!(expression, Expr::Field(field)
        if is_self_path(&field.base)
            && matches!(&field.member, Member::Named(identifier) if identifier == SECRET_FIELD))
}

fn verification_binding_contract_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    let limits = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item)
                if !super::has_cfg_test(&item.attrs)
                    && item.ident == VERIFICATION_BINDING_LIMIT =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let limit_is_exact = matches!(limits.as_slice(), [limit]
        if matches!(limit.vis, Visibility::Inherited)
            && is_single_type_path(&limit.ty, "usize")
            && integer_expression(&limit.expr) == Some(256));
    if !limit_is_exact {
        violations.insert(
            "OAST verification binding limit must be exactly private `MAX_VERIFICATION_BINDING_COMPONENT_BYTES: usize = 256`"
                .to_owned(),
        );
    }

    let validators = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(item)
                if !super::has_cfg_test(&item.attrs)
                    && item.sig.ident == "validate_verification_binding" =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let validator_is_bounded = matches!(validators.as_slice(), [validator] if {
        let mut visitor = VerificationBindingVisitor::default();
        visitor.visit_item_fn(validator);
        visitor.has_strict_limit_comparison && visitor.has_typed_error
    });
    if !validator_is_bounded {
        violations.insert(
            "OAST `validate_verification_binding` must enforce the strict 256-byte component bound and return VerificationBindingTooLarge"
                .to_owned(),
        );
    }

    let registers = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(item)
                if !super::has_cfg_test(&item.attrs)
                    && item.trait_.is_none()
                    && impl_self_type(item).as_deref() == Some("OastCorrelationAuthority") =>
            {
                Some(item)
            },
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "register" => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let validates_first = matches!(registers.as_slice(), [register]
        if register.block.stmts.first().is_some_and(is_exact_verification_validation_statement));
    if !validates_first {
        violations.insert(
            "OAST authority `register` must call `validate_verification_binding(&verification_case)?` as its first statement before hashing or cloning"
                .to_owned(),
        );
    }
    violations
}

fn is_exact_verification_validation_statement(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(Expr::Try(attempt), _) = statement else {
        return false;
    };
    let Expr::Call(call) = attempt.expr.as_ref() else {
        return false;
    };
    let Expr::Path(function) = call.func.as_ref() else {
        return false;
    };
    if call.args.len() != 1 {
        return false;
    }
    let argument = call.args.first().expect("length checked");
    function.path.is_ident("validate_verification_binding")
        && matches!(argument, Expr::Reference(reference)
            if reference.mutability.is_none()
                && matches!(reference.expr.as_ref(), Expr::Path(path)
                    if path.qself.is_none() && path.path.is_ident("verification_case")))
}

#[derive(Default)]
struct VerificationBindingVisitor {
    has_strict_limit_comparison: bool,
    has_typed_error: bool,
}

impl<'ast> Visit<'ast> for VerificationBindingVisitor {
    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if matches!(binary.op, syn::BinOp::Gt(_))
            && matches!(binary.left.as_ref(), Expr::MethodCall(call)
                if call.method == "len" && call.args.is_empty())
            && matches!(binary.right.as_ref(), Expr::Path(path)
                if path.qself.is_none() && path.path.is_ident(VERIFICATION_BINDING_LIMIT))
        {
            self.has_strict_limit_comparison = true;
        }
        visit::visit_expr_binary(self, binary);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        if path.segments.len() == 2
            && path.segments[0].ident == "OastError"
            && path.segments[1].ident == "VerificationBindingTooLarge"
        {
            self.has_typed_error = true;
        }
        visit::visit_path(self, path);
    }
}

fn opaque_identifier_contract_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    for (type_name, allowed_methods) in OPAQUE_REDACTED_TYPES {
        let declarations = syntax
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Struct(item)
                    if !super::has_cfg_test(&item.attrs) && item.ident == *type_name =>
                {
                    Some(item)
                },
                _ => None,
            })
            .collect::<Vec<_>>();
        match declarations.as_slice() {
            [declaration]
                if is_public(&declaration.vis)
                    && matches!(&declaration.fields, Fields::Unnamed(fields)
                        if fields.unnamed.len() == 1
                            && matches!(fields.unnamed[0].vis, Visibility::Inherited)
                            && is_32_byte_array(&fields.unnamed[0].ty)) => {},
            _ => {
                violations.insert(format!(
                    "OAST opaque identity `{type_name}` must be exactly a public tuple wrapper over one private `[u8; 32]` field"
                ));
            },
        }
        if declarations.first().is_some_and(|declaration| {
            attributes_contain_any(
                &declaration.attrs,
                &["Debug", "Deserialize", "Display", "Serialize"],
            )
        }) {
            violations.insert(format!(
                "OAST opaque identity `{type_name}` must use custom redacted Debug and no display or serde derive"
            ));
        }

        let mut debug_impls = 0usize;
        let mut actual_methods = BTreeSet::new();
        for item in &syntax.items {
            let Item::Impl(item) = item else {
                continue;
            };
            if super::has_cfg_test(&item.attrs) {
                continue;
            }
            let trait_name = item
                .trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .map(|segment| segment.ident.to_string());
            if trait_name
                .as_deref()
                .is_some_and(|name| RAW_EXPOSING_TRAITS.contains(&name))
                && impl_header_references_type(item, type_name)
            {
                violations.insert(format!(
                    "OAST opaque identity `{type_name}` must not participate in exposing/display/serde trait `{}`",
                    trait_name.as_deref().expect("checked as present")
                ));
            }
            if impl_self_type(item).as_deref() != Some(*type_name) {
                continue;
            }
            if trait_name.as_deref() == Some("Debug") {
                debug_impls += 1;
                let mut debug = OpaqueDebugVisitor::default();
                debug.visit_item_impl(item);
                if debug.references_field || debug.references_self || !debug.has_redaction_marker {
                    violations.insert(format!(
                        "OAST opaque identity `{type_name}` Debug must be redacted and must not inspect its private bytes"
                    ));
                }
            }
            if trait_name
                .as_deref()
                .is_some_and(|name| RAW_EXPOSING_TRAITS.contains(&name))
            {
                violations.insert(format!(
                    "OAST opaque identity `{type_name}` must not implement exposing/display/serde trait `{}`",
                    trait_name.expect("checked as present")
                ));
            }
            if item.trait_.is_none() {
                for implementation_item in &item.items {
                    if let ImplItem::Fn(method) = implementation_item {
                        if is_public(&method.vis) {
                            let method_name = method.sig.ident.to_string();
                            if !actual_methods.insert(method_name.clone()) {
                                violations.insert(format!(
                                    "OAST opaque identity `{type_name}` repeats public method `{method_name}`"
                                ));
                            }
                            if method_name == "new" && !is_32_byte_result_constructor(&method.sig) {
                                violations.insert(format!(
                                    "OAST opaque identity `{type_name}` constructor must consume exactly one 32-byte host value and return Result<Self, OastError>"
                                ));
                            }
                        }
                    }
                }
            }
        }
        if debug_impls != 1 {
            violations.insert(format!(
                "OAST opaque identity `{type_name}` must have exactly one custom redacted Debug implementation; found {debug_impls}"
            ));
        }
        let expected_methods = allowed_methods.iter().copied().collect::<BTreeSet<_>>();
        let actual_method_names = actual_methods
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual_method_names != expected_methods {
            violations.insert(format!(
                "OAST opaque identity `{type_name}` public methods must be exactly {expected_methods:?}, found {actual_method_names:?}"
            ));
        }
    }
    violations
}

fn digest_domain_violations(syntax: &syn::File) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    let domain_constants = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Const(item)
                if !super::has_cfg_test(&item.attrs)
                    && item.ident.to_string().ends_with("_DOMAIN") =>
            {
                Some(item)
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    let actual = domain_constants
        .iter()
        .map(|item| item.ident.to_string())
        .collect::<BTreeSet<_>>();
    let expected = EXACT_DIGEST_DOMAINS
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    let actual_names = actual.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_names != expected {
        violations.insert(format!(
            "OAST digest domain constant names must be exactly {expected:?}, found {actual_names:?}"
        ));
    }

    for (name, expected_value) in EXACT_DIGEST_DOMAINS {
        let matches = domain_constants
            .iter()
            .filter(|item| item.ident == *name)
            .collect::<Vec<_>>();
        let exact = matches.len() == 1;
        let value_matches = matches.as_slice().first().is_some_and(|item| {
            matches!(item.expr.as_ref(), Expr::Lit(literal)
                if matches!(&literal.lit, syn::Lit::ByteStr(value)
                    if value.value().as_slice() == *expected_value))
                && matches!(item.vis, Visibility::Inherited)
        });
        if !exact || !value_matches {
            violations.insert(format!(
                "OAST digest domain `{name}` must be one private byte-string constant with exact brand-neutral v1 bytes"
            ));
        }
    }
    violations
}

fn inspect_secret_token(token: &ItemStruct, violations: &mut BTreeSet<String>) {
    if !is_public(&token.vis) {
        violations
            .insert("OAST correlation token must remain public only as an opaque type".to_owned());
    }
    let Fields::Named(fields) = &token.fields else {
        violations.insert(
            "OAST correlation token must contain one private named 32-byte secret field".to_owned(),
        );
        return;
    };
    let fields = fields.named.iter().collect::<Vec<_>>();
    match fields.as_slice() {
        [field]
            if field
                .ident
                .as_ref()
                .is_some_and(|ident| ident == SECRET_FIELD)
                && matches!(field.vis, Visibility::Inherited)
                && is_32_byte_array(&field.ty) => {},
        _ => {
            violations.insert(
                "OAST correlation token must contain exactly `secret_bytes: [u8; 32]` as a private field"
                    .to_owned(),
            );
        },
    }
    if attributes_contain_any(
        &token.attrs,
        &[
            "Clone",
            "Copy",
            "Debug",
            "Deserialize",
            "Display",
            "Serialize",
        ],
    ) || token
        .fields
        .iter()
        .any(|field| attributes_contain_any(&field.attrs, &["serde", "serialize", "deserialize"]))
    {
        violations.insert(
            "OAST correlation token must not derive Clone/Copy/Debug/Display or participate in serde"
                .to_owned(),
        );
    }
}

fn is_32_byte_array(ty: &Type) -> bool {
    let Type::Array(array) = ty else {
        return false;
    };
    let is_byte = matches!(array.elem.as_ref(), Type::Path(path)
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path.path.segments[0].ident == "u8");
    let is_32 = integer_expression(&array.len) == Some(32)
        || matches!(&array.len, Expr::Path(path)
            if path.qself.is_none()
                && path.path.segments.len() == 1
                && matches!(path.path.segments[0].ident.to_string().as_str(),
                    "EVENT_KEY_BYTES" | "OAST_CORRELATION_TOKEN_BYTES" | "TOKEN_BYTES"));
    is_byte && is_32
}

fn is_32_byte_result_constructor(signature: &Signature) -> bool {
    if signature.constness.is_some()
        || signature.asyncness.is_some()
        || signature.unsafety.is_some()
        || signature.abi.is_some()
        || signature.variadic.is_some()
        || !signature.generics.params.is_empty()
        || signature.generics.where_clause.is_some()
    {
        return false;
    }
    let [FnArg::Typed(argument)] = signature.inputs.iter().collect::<Vec<_>>().as_slice() else {
        return false;
    };
    if !is_32_byte_array(&argument.ty) {
        return false;
    }
    let ReturnType::Type(_, output) = &signature.output else {
        return false;
    };
    let Type::Path(result) = output.as_ref() else {
        return false;
    };
    let Some(segment) = result.path.segments.last() else {
        return false;
    };
    let PathArguments::AngleBracketed(AngleBracketedGenericArguments { args, .. }) =
        &segment.arguments
    else {
        return false;
    };
    let types = args
        .iter()
        .filter_map(|argument| match argument {
            GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .collect::<Vec<_>>();
    segment.ident == "Result"
        && args.len() == 2
        && types.len() == 2
        && is_single_type_path(types[0], "Self")
        && is_single_type_path(types[1], "OastError")
}

fn is_single_type_path(ty: &Type, expected: &str) -> bool {
    matches!(ty, Type::Path(path)
        if path.qself.is_none()
            && path.path.segments.len() == 1
            && path.path.segments[0].ident == expected)
}

fn impl_header_references_type(item: &ItemImpl, expected: &str) -> bool {
    let mut visitor = TypeReferenceVisitor {
        expected,
        found: false,
    };
    visitor.visit_type(&item.self_ty);
    if let Some((_, path, _)) = &item.trait_ {
        visitor.visit_path(path);
    }
    visitor.found
}

struct TypeReferenceVisitor<'a> {
    expected: &'a str,
    found: bool,
}

impl<'ast> Visit<'ast> for TypeReferenceVisitor<'_> {
    fn visit_path(&mut self, path: &'ast SynPath) {
        if path
            .segments
            .iter()
            .any(|segment| segment.ident == self.expected)
        {
            self.found = true;
        }
        visit::visit_path(self, path);
    }
}

fn integer_expression(expression: &Expr) -> Option<u64> {
    match expression {
        Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(value) => value.base10_parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

fn attributes_contain_any(attributes: &[Attribute], forbidden: &[&str]) -> bool {
    attributes.iter().any(|attribute| {
        let root = attribute
            .path()
            .segments
            .first()
            .map(|segment| segment.ident.to_string());
        root.as_deref()
            .is_some_and(|name| forbidden.contains(&name))
            || match &attribute.meta {
                Meta::List(list) => token_identifiers(list.tokens.clone())
                    .iter()
                    .any(|identifier| forbidden.contains(&identifier.as_str())),
                Meta::Path(_) | Meta::NameValue(_) => false,
            }
    })
}

fn token_identifiers(tokens: TokenStream) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::new();
    collect_token_identifiers(tokens, &mut identifiers);
    identifiers
}

fn collect_token_identifiers(tokens: TokenStream, identifiers: &mut BTreeSet<String>) {
    for token in tokens {
        match token {
            TokenTree::Group(group) => collect_token_identifiers(group.stream(), identifiers),
            TokenTree::Ident(identifier) => {
                identifiers.insert(identifier.to_string());
            },
            TokenTree::Literal(_) | TokenTree::Punct(_) => {},
        }
    }
}

fn impl_self_type(item: &ItemImpl) -> Option<String> {
    let Type::Path(path) = item.self_ty.as_ref() else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| super::normalize_identifier(&segment.ident.to_string()).to_owned())
}

fn has_exact_cfg(attributes: &[Attribute], expected: &str) -> bool {
    let [attribute] = attributes else {
        return false;
    };
    attribute.path().is_ident("cfg")
        && attribute.meta.require_list().is_ok_and(|list| {
            list.tokens
                .to_string()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                == expected
        })
}

fn is_public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

#[derive(Default)]
struct RootOastReferenceVisitor {
    references_oast: bool,
}

impl<'ast> Visit<'ast> for RootOastReferenceVisitor {
    fn visit_path(&mut self, path: &'ast SynPath) {
        if path
            .segments
            .iter()
            .any(|segment| segment.ident == MODULE_NAME)
        {
            self.references_oast = true;
        }
        visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        if paths.iter().any(|segments| {
            segments
                .iter()
                .any(|segment| super::normalize_identifier(segment) == MODULE_NAME)
        }) {
            self.references_oast = true;
        }
        visit::visit_item_use(self, item);
    }
}

#[derive(Default)]
struct SecretDebugVisitor {
    references_secret: bool,
    references_self: bool,
    has_redaction_marker: bool,
}

impl<'ast> Visit<'ast> for SecretDebugVisitor {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if matches!(&field.member, Member::Named(identifier) if identifier == SECRET_FIELD) {
            self.references_secret = true;
        }
        visit::visit_expr_field(self, field);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none() && path.path.is_ident("self") {
            self.references_self = true;
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_lit_str(&mut self, literal: &'ast LitStr) {
        if literal.value().to_ascii_lowercase().contains("redacted") {
            self.has_redaction_marker = true;
        }
        visit::visit_lit_str(self, literal);
    }
}

#[derive(Default)]
struct OpaqueDebugVisitor {
    references_field: bool,
    references_self: bool,
    has_redaction_marker: bool,
}

impl<'ast> Visit<'ast> for OpaqueDebugVisitor {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        self.references_field = true;
        visit::visit_expr_field(self, field);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if path.qself.is_none() && path.path.is_ident("self") {
            self.references_self = true;
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_lit_str(&mut self, literal: &'ast LitStr) {
        if literal.value().to_ascii_lowercase().contains("redacted") {
            self.has_redaction_marker = true;
        }
        visit::visit_lit_str(self, literal);
    }
}

#[derive(Default)]
struct AuthorityVisitor {
    violations: BTreeSet<String>,
}

impl AuthorityVisitor {
    fn inspect_identifier(&mut self, identifier: &str) {
        let identifier = super::normalize_identifier(identifier);
        if identifier == "Default" {
            self.violations.insert(
                "OAST foundation must not provide ambient or implicit Default values".to_owned(),
            );
        }
        if FORBIDDEN_AMBIENT_IDENTIFIERS.contains(&identifier) {
            self.violations.insert(format!(
                "OAST foundation must not own ambient clock/random/global authority `{identifier}`"
            ));
        }
        let words = identifier_words(identifier);
        if identifier_words(identifier)
            .windows(2)
            .any(|words| words == ["assessment", "item"])
        {
            self.violations.insert(format!(
                "OAST foundation must not produce assessment items `{identifier}`"
            ));
        }
        for word in words {
            if FORBIDDEN_AUTHORITY_WORDS.contains(&word.as_str()) {
                self.violations.insert(format!(
                    "OAST foundation must not own network/runtime/execution/reporting/finding authority `{identifier}`"
                ));
            }
            if matches!(
                word.as_str(),
                "entropy" | "getrandom" | "nanoid" | "rand" | "random" | "rng" | "ulid" | "uuid"
            ) {
                self.violations.insert(format!(
                    "OAST foundation must receive host-minted entropy and must not own randomness `{identifier}`"
                ));
            }
            if FORBIDDEN_PROJECTION_WORDS.contains(&word.as_str()) {
                self.violations.insert(format!(
                    "OAST foundation must not produce evidence/outcomes or hypothesis projections/transitions `{identifier}`"
                ));
            }
            if matches!(
                word.as_str(),
                "deserialize"
                    | "deserialization"
                    | "deserializer"
                    | "serde"
                    | "serialize"
                    | "serialization"
                    | "serializer"
            ) {
                self.violations.insert(format!(
                    "OAST foundation must not expose or own serialization `{identifier}`"
                ));
            }
        }
    }

    fn inspect_segments(&mut self, segments: &[String]) {
        let Some(root) = segments
            .first()
            .map(|segment| super::normalize_identifier(segment))
        else {
            return;
        };
        if FORBIDDEN_EXTERNAL_ROOTS.contains(&root) {
            self.violations.insert(format!(
                "OAST foundation must not depend on network/runtime/clock/random provider root `{root}`"
            ));
        }
        if FORBIDDEN_FOUNDATION_ROOTS.contains(&root) {
            self.violations.insert(format!(
                "OAST foundation must not depend on serialization, projection, or unreviewed foundation root `{root}`"
            ));
        }
        if root == "std" {
            let module = segments
                .get(1)
                .map(|segment| super::normalize_identifier(segment));
            if module.is_none_or(|module| !ALLOWED_STD_MODULES.contains(&module)) {
                self.violations.insert(format!(
                    "OAST foundation may use only std::collections, std::error, and std::fmt; found `{}`",
                    segments.join("::")
                ));
            }
            if module.is_some_and(|module| FORBIDDEN_STD_MODULES.contains(&module)) {
                self.violations.insert(format!(
                    "OAST foundation must not access std side-effect authority `{}`",
                    segments.join("::")
                ));
            }
        }
        for (index, segment) in segments.iter().enumerate() {
            let is_exact_case_identity_accessor = index + 1 == segments.len()
                && matches!(
                    super::normalize_identifier(segment),
                    "action_id" | "applies_hypothesis_transition" | "hypothesis_id"
                )
                && index.checked_sub(1).is_some_and(|previous| {
                    super::normalize_identifier(&segments[previous]) == "VerificationCase"
                });
            if is_exact_case_identity_accessor {
                continue;
            }
            self.inspect_identifier(segment);
        }
    }

    fn inspect_literal(&mut self, value: &str) {
        let lower = value.to_ascii_lowercase();
        if let Some(marker) = PROVIDER_OR_TARGET_LITERALS
            .iter()
            .find(|marker| lower.contains(**marker))
        {
            self.violations.insert(format!(
                "OAST foundation must not hard-code provider or network target literal `{marker}`"
            ));
        }
    }
}

impl<'ast> Visit<'ast> for AuthorityVisitor {
    fn visit_attribute(&mut self, attribute: &'ast Attribute) {
        let identifiers = token_identifiers(
            attribute
                .meta
                .require_list()
                .map_or_else(|_| TokenStream::new(), |list| list.tokens.clone()),
        );
        if attribute.path().is_ident("derive") && identifiers.contains("Default") {
            self.violations.insert(
                "OAST foundation must not provide ambient or implicit Default values".to_owned(),
            );
        }
        if attribute.path().segments.iter().any(|segment| {
            matches!(
                super::normalize_identifier(&segment.ident.to_string()),
                "serde" | "Serialize" | "Deserialize"
            )
        }) || identifiers
            .iter()
            .any(|identifier| matches!(identifier.as_str(), "serde" | "Serialize" | "Deserialize"))
        {
            self.violations
                .insert("OAST foundation must not expose or derive serde serialization".to_owned());
        }
        visit::visit_attribute(self, attribute);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        let is_exact_verification_identity_accessor = matches!(
            call.receiver.as_ref(),
            Expr::Path(path)
                if path.qself.is_none()
                    && path.path.segments.last().is_some_and(|segment| {
                        segment.ident == "verification_case"
                    })
        ) && matches!(
            method.as_str(),
            "action_id" | "applies_hypothesis_transition" | "hypothesis_id"
        );
        if !is_exact_verification_identity_accessor {
            self.inspect_identifier(&method);
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if super::has_cfg_test(super::item_attributes(item)) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.inspect_identifier(&item.ident.to_string());
        for variant in &item.variants {
            self.inspect_identifier(&variant.ident.to_string());
            for field in &variant.fields {
                if let Some(identifier) = &field.ident {
                    self.inspect_identifier(&identifier.to_string());
                }
            }
        }
        visit::visit_item_enum(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.inspect_identifier(&item.sig.ident.to_string());
        if item.sig.asyncness.is_some() {
            self.violations.insert(
                "OAST foundation must not own async or runtime execution authority".to_owned(),
            );
        }
        visit::visit_item_fn(self, item);
    }

    fn visit_item_foreign_mod(&mut self, item: &'ast syn::ItemForeignMod) {
        self.violations
            .insert("OAST foundation must not reach side-effect authority through FFI".to_owned());
        visit::visit_item_foreign_mod(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        if item
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .is_some_and(|segment| segment.ident == "Default")
        {
            self.violations.insert(
                "OAST foundation must not provide ambient or implicit Default values".to_owned(),
            );
        }
        for implementation_item in &item.items {
            if let ImplItem::Fn(method) = implementation_item {
                self.inspect_identifier(&method.sig.ident.to_string());
                if method.sig.asyncness.is_some() {
                    self.violations.insert(
                        "OAST foundation must not own async or runtime execution authority"
                            .to_owned(),
                    );
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.violations.insert(format!(
            "OAST foundation must not own ambient static state `{}`",
            item.ident
        ));
        visit::visit_item_static(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast ItemStruct) {
        self.inspect_identifier(&item.ident.to_string());
        for field in &item.fields {
            if let Some(identifier) = &field.ident {
                self.inspect_identifier(&identifier.to_string());
            }
        }
        visit::visit_item_struct(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        self.inspect_identifier(&item.ident.to_string());
        visit::visit_item_trait(self, item);
    }

    fn visit_item_trait_alias(&mut self, item: &'ast syn::ItemTraitAlias) {
        self.inspect_identifier(&item.ident.to_string());
        visit::visit_item_trait_alias(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.inspect_identifier(&item.ident.to_string());
        visit::visit_item_type(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        self.inspect_identifier(&item.ident.to_string());
        visit::visit_item_union(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        collect_use_paths(&item.tree, Vec::new(), &mut paths);
        for segments in paths {
            self.inspect_segments(&segments);
        }
        visit::visit_item_use(self, item);
    }

    fn visit_macro(&mut self, item: &'ast Macro) {
        if let Some(name) = item
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        {
            if FORBIDDEN_MACROS.contains(&super::normalize_identifier(&name)) {
                self.violations.insert(format!(
                    "OAST foundation must not invoke ambient/environment/output macro `{name}`"
                ));
            }
        }
        visit::visit_macro(self, item);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.inspect_segments(&segments);
        visit::visit_path(self, path);
    }

    fn visit_lit_byte_str(&mut self, literal: &'ast LitByteStr) {
        if let Ok(value) = std::str::from_utf8(&literal.value()) {
            self.inspect_literal(value);
        }
        visit::visit_lit_byte_str(self, literal);
    }

    fn visit_lit_str(&mut self, literal: &'ast LitStr) {
        self.inspect_literal(&literal.value());
        visit::visit_lit_str(self, literal);
    }
}

fn collect_use_paths(tree: &UseTree, prefix: Vec<String>, output: &mut Vec<Vec<String>>) {
    match tree {
        UseTree::Path(path) => {
            let mut prefix = prefix;
            prefix.push(path.ident.to_string());
            collect_use_paths(&path.tree, prefix, output);
        },
        UseTree::Name(name) => {
            let mut path = prefix;
            path.push(name.ident.to_string());
            output.push(path);
        },
        UseTree::Rename(rename) => {
            let mut path = prefix;
            path.push(rename.ident.to_string());
            output.push(path);
        },
        UseTree::Glob(_) => output.push(prefix),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_paths(item, prefix.clone(), output);
            }
        },
    }
}

fn identifier_words(identifier: &str) -> Vec<String> {
    let characters = identifier.chars().collect::<Vec<_>>();
    let mut words = Vec::new();
    let mut current = String::new();
    for (index, character) in characters.iter().copied().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(current.to_ascii_lowercase());
                current.clear();
            }
            continue;
        }
        let previous = index.checked_sub(1).and_then(|value| characters.get(value));
        let next = characters.get(index + 1);
        let starts_word = character.is_ascii_uppercase()
            && !current.is_empty()
            && (previous.is_some_and(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
                || (previous.is_some_and(|value| value.is_ascii_uppercase())
                    && next.is_some_and(|value| value.is_ascii_lowercase())));
        if starts_word {
            words.push(current.to_ascii_lowercase());
            current.clear();
        }
        current.push(character);
    }
    if !current.is_empty() {
        words.push(current.to_ascii_lowercase());
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_foundation() -> String {
        let types = EXACT_PUBLIC_TYPES
            .iter()
            .filter(|name| {
                **name != SECRET_TYPE
                    && !OPAQUE_REDACTED_TYPES
                        .iter()
                        .any(|(opaque, _)| opaque == *name)
                    && !EXACT_PRIVATE_STRUCT_FIELDS
                        .iter()
                        .any(|(record, _)| record == *name)
            })
            .map(|name| format!("pub struct {name} {{ private: () }}"))
            .collect::<Vec<_>>()
            .join("\n");
        let records = EXACT_PRIVATE_STRUCT_FIELDS
            .iter()
            .map(|(name, fields)| {
                let fields = fields
                    .iter()
                    .map(|(field, ty)| format!("{field}: {ty}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("pub struct {name} {{ {fields} }}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            r#"
            use zeroize::Zeroize;
            const MAX_VERIFICATION_BINDING_COMPONENT_BYTES: usize = 256;
            const TOKEN_REUSE_DOMAIN: &[u8] = b"security.oast-correlation.token-reuse.v1\0";
            const BINDING_ID_DOMAIN: &[u8] = b"security.oast-correlation.binding.v1\0";
            const CORRELATION_ID_DOMAIN: &[u8] = b"security.oast-correlation.id.v1\0";

            pub struct OastCorrelationToken {{ secret_bytes: [u8; 32] }}
            impl OastCorrelationToken {{
                pub fn new(secret_bytes: [u8; 32]) -> Result<Self, OastError> {{ Ok(Self {{ secret_bytes }}) }}
                fn erase(&mut self) {{ self.secret_bytes.zeroize(); }}
            }}
            impl Drop for OastCorrelationToken {{ fn drop(&mut self) {{ self.erase(); }} }}
            impl std::fmt::Debug for OastCorrelationToken {{
                fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
                    formatter.write_str("OastCorrelationToken([REDACTED])")
                }}
            }}
            pub struct OastAuthorityEpoch([u8; 32]);
            impl OastAuthorityEpoch {{ pub fn new(bytes: [u8; 32]) -> Result<Self, OastError> {{ Ok(Self(bytes)) }} }}
            impl std::fmt::Debug for OastAuthorityEpoch {{
                fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
                    formatter.write_str("OastAuthorityEpoch([REDACTED])")
                }}
            }}
            pub struct OastBindingId([u8; 32]);
            impl std::fmt::Debug for OastBindingId {{
                fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
                    formatter.write_str("OastBindingId([REDACTED])")
                }}
            }}
            pub struct OastCorrelationId([u8; 32]);
            impl std::fmt::Debug for OastCorrelationId {{
                fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
                    formatter.write_str("OastCorrelationId([REDACTED])")
                }}
            }}
            pub struct OastEventKey([u8; 32]);
            impl OastEventKey {{ pub fn new(bytes: [u8; 32]) -> Result<Self, OastError> {{ Ok(Self(bytes)) }} }}
            impl std::fmt::Debug for OastEventKey {{
                fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{
                    formatter.write_str("OastEventKey([REDACTED])")
                }}
            }}
            {records}
            {types}
            impl OastCorrelationAuthority {{
                pub fn register(&mut self, verification_case: VerificationCase) -> Result<(), OastError> {{
                    validate_verification_binding(&verification_case)?;
                    Ok(())
                }}
            }}
            fn validate_verification_binding(verification_case: &VerificationCase) -> Result<(), OastError> {{
                if verification_case.id().len() > MAX_VERIFICATION_BINDING_COMPONENT_BYTES {{
                    return Err(OastError::VerificationBindingTooLarge);
                }}
                Ok(())
            }}
            fn hash_existing_case_identity(case: &VerificationCase) {{
                let _ = VerificationCase::action_id(case);
            }}
            fn consume_existing_case_identity(verification_case: &VerificationCase) {{
                let _ = verification_case.hypothesis_id();
                let _ = verification_case.applies_hypothesis_transition();
            }}
            #[cfg(test)]
            mod tests {{
                use std::net::TcpStream;
                const PROVIDER: &str = "interact.sh";
            }}
            "#
        )
    }

    #[test]
    fn safe_fixture_is_provider_and_transport_neutral() {
        let source = safe_foundation();
        assert!(foundation_contract_violations(&source).unwrap().is_empty());
    }

    #[test]
    fn repository_oast_source_and_root_wiring_satisfy_the_exact_contract() {
        let source = include_str!("../../../crates/termivar-scanner/src/oast.rs");
        assert!(
            foundation_contract_violations(source).unwrap().is_empty(),
            "repository OAST source drifted from its exact foundation contract"
        );
        let policy = super::super::MODULE_POLICIES
            .iter()
            .find(|policy| policy.source == "oast.rs")
            .expect("OAST module policy must be registered");
        assert!(
            super::super::inspect_module_source(policy, source)
                .unwrap()
                .is_empty(),
            "repository OAST source gained an unreviewed dependency edge"
        );
        let library = include_str!("../../../crates/termivar-scanner/src/lib.rs");
        assert!(
            library_wiring_violations(library).unwrap().is_empty(),
            "repository OAST module wiring drifted from its single gated path"
        );
        let source_root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/termivar-scanner/src");
        assert!(
            repository_consumer_violations(&source_root)
                .unwrap()
                .is_empty(),
            "a scanner production source consumed the host-owned OAST boundary"
        );
    }

    #[test]
    fn raw_free_record_shapes_reject_field_type_visibility_and_serde_drift() {
        let source = safe_foundation();
        for mutation in [
            source.replacen(
                "transport: OastDnsTransport",
                "pub transport: OastDnsTransport",
                1,
            ),
            source.replacen(
                "body_present: bool",
                "body_present: Vec<u8>, raw_url: String",
                1,
            ),
            source.replacen(
                "event_receipts: Vec<OastEventReceipt>",
                "event_receipts: Vec<String>",
                1,
            ),
            source.replacen(
                "pub struct OastEventReceipt",
                "#[derive(serde::Serialize)] pub struct OastEventReceipt",
                1,
            ),
            source.replacen(
                "terminal_at: OastMonotonicTime",
                "terminal_at: OastMonotonicTime, provider_timestamp: u64",
                1,
            ),
            source.replacen(
                "allowed_protocols: OastProtocolSet",
                "allowed_protocols: OastProtocolSet, headers: Vec<String>",
                1,
            ),
        ] {
            assert!(
                !foundation_contract_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "raw-free record mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn verification_bound_and_zeroizing_drop_mutations_fail_closed() {
        let source = safe_foundation();
        for mutation in [
            source.replacen(
                "MAX_VERIFICATION_BINDING_COMPONENT_BYTES: usize = 256",
                "MAX_VERIFICATION_BINDING_COMPONENT_BYTES: usize = 1024",
                1,
            ),
            source.replacen(
                "validate_verification_binding(&verification_case)?;",
                "let _ = &verification_case;",
                1,
            ),
            source.replacen(
                "verification_case.id().len() > MAX_VERIFICATION_BINDING_COMPONENT_BYTES",
                "verification_case.id().len() == MAX_VERIFICATION_BINDING_COMPONENT_BYTES",
                1,
            ),
            source.replacen(
                "self.secret_bytes.zeroize();",
                "self.secret_bytes.fill(0);",
                1,
            ),
            source.replacen(
                "impl Drop for OastCorrelationToken { fn drop(&mut self) { self.erase(); } }",
                "",
                1,
            ),
        ] {
            assert!(
                !foundation_contract_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "verification/drop mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn scanner_runtime_and_provider_consumers_fail_closed() {
        for (path, source) in [
            (
                "web_runtime.rs",
                "use crate::oast::OastCorrelation; fn poll(_: OastCorrelation) {}",
            ),
            (
                "provider_adapter.rs",
                "fn register(value: crate::oast::OastRegistrationReceipt) { let _ = value; }",
            ),
        ] {
            assert!(!consumer_source_violations(path, source, false)
                .unwrap()
                .is_empty());
        }
        assert!(consumer_source_violations(
            NATIVE_PROVIDER_ADAPTER,
            "use crate::oast::{OastEventKey, OastHttpEvent}; fn reduce(_: OastEventKey, _: OastHttpEvent) {}",
            false,
        )
        .unwrap()
        .is_empty());
        assert!(!consumer_source_violations(
            NATIVE_PROVIDER_ADAPTER,
            "fn bypasses_correlation() {}",
            false,
        )
        .unwrap()
        .is_empty());
        assert!(consumer_source_violations(
            "lib.rs",
            "#[cfg(feature = \"oast-correlation\")] pub mod oast;",
            true,
        )
        .unwrap()
        .is_empty());
        assert!(consumer_source_violations(
            "web_runtime.rs",
            "#[cfg(test)] mod tests { use crate::oast::OastCorrelation; }",
            false,
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn side_effect_clock_random_provider_and_authority_mutations_fail_closed() {
        let source = safe_foundation();
        for mutation in [
            "use std::net::TcpStream;",
            "use std::process::Command;",
            "use std::fs::File;",
            "use std::env;",
            "use std::time::SystemTime;",
            "use rand::thread_rng;",
            "use uuid::Uuid;",
            "const CALLBACK_TARGET: &str = \"interact.sh\";",
            "struct OastRuntime;",
            "struct CallbackBroker;",
            "struct CallbackExecutor;",
            "struct CallbackAction;",
            "struct ScanFinding;",
            "struct SecuritySeverity;",
            "struct OastReporter;",
            "struct OastCli;",
            "struct CallbackProvider;",
            "#[derive(Default)] struct PollDefaults;",
            "extern \"C\" { fn poll_callback(); }",
            "use std::sync::Mutex;",
            "use core::fmt::Debug;",
            "use termivar_core::Outcome;",
            "use serde::Serialize;",
            "#[derive(serde::Serialize)] struct WireReceipt;",
            "impl serde::Serialize for OastPollReceipt {}",
            "struct AssessmentItem;",
            "struct OastEvidence;",
            "struct HypothesisTransition;",
            "fn project_hypothesis() {}",
            "async fn poll_in_background() {}",
        ] {
            let mutated = format!("{source}\n{mutation}");
            assert!(
                !foundation_contract_violations(&mutated).unwrap().is_empty(),
                "mutation unexpectedly passed: {mutation}"
            );
        }
    }

    #[test]
    fn secret_shape_copy_serde_debug_and_raw_access_mutations_fail_closed() {
        let source = safe_foundation();
        let mutations = [
            source.replacen(
                "pub struct OastCorrelationToken",
                "#[derive(Clone)] pub struct OastCorrelationToken",
                1,
            ),
            source.replacen(
                "pub struct OastCorrelationToken",
                "#[derive(serde::Serialize)] pub struct OastCorrelationToken",
                1,
            ),
            source.replacen("secret_bytes: [u8; 32]", "pub secret_bytes: [u8; 32]", 1),
            source.replacen("secret_bytes: [u8; 32]", "secret_bytes: [u8; 16]", 1),
            source.replacen(
                "formatter.write_str(\"OastCorrelationToken([REDACTED])\")",
                "formatter.debug_tuple(\"OastCorrelationToken\").field(&self.secret_bytes).finish()",
                1,
            ),
            format!(
                "{source}\nimpl OastCorrelationToken {{ pub fn as_bytes(&self) -> &[u8; 32] {{ &self.secret_bytes }} }}"
            ),
            format!("{source}\nimpl serde::Serialize for OastCorrelationToken {{}}"),
            format!(
                "{source}\nimpl From<OastCorrelationToken> for [u8; 32] {{ fn from(token: OastCorrelationToken) -> Self {{ token.secret_bytes }} }}"
            ),
            source.replacen(
                "pub fn new(secret_bytes: [u8; 32]) -> Result<Self, OastError>",
                "pub fn new(&self) -> Result<Self, OastError>",
                1,
            ),
        ];
        for mutation in mutations {
            assert!(!foundation_contract_violations(&mutation)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn opaque_ids_and_digest_domains_fail_closed_on_raw_or_branded_expansion() {
        let source = safe_foundation();
        let mutations = [
            source.replacen(
                "pub struct OastAuthorityEpoch([u8; 32]);",
                "pub struct OastAuthorityEpoch([u8; 16]);",
                1,
            ),
            format!(
                "{source}\nimpl OastBindingId {{ pub fn as_bytes(&self) -> &[u8; 32] {{ &self.0 }} }}"
            ),
            format!(
                "{source}\nimpl From<OastBindingId> for [u8; 32] {{ fn from(id: OastBindingId) -> Self {{ id.0 }} }}"
            ),
            source.replacen(
                "formatter.write_str(\"OastCorrelationId([REDACTED])\")",
                "formatter.debug_tuple(\"OastCorrelationId\").field(&self.0).finish()",
                1,
            ),
            source.replacen(
                "security.oast-correlation.binding.v1\\0",
                "vendor.example.binding.v1\\0",
                1,
            ),
            source.replacen("TOKEN_REUSE_DOMAIN", "VENDOR_REUSE_DOMAIN", 1),
            format!(
                "{source}\nconst PROVIDER_DOMAIN: &[u8] = b\"security.oast-correlation.provider.v1\\0\";"
            ),
        ];
        for mutation in mutations {
            assert!(
                !foundation_contract_violations(&mutation)
                    .unwrap()
                    .is_empty(),
                "opaque/domain mutation unexpectedly passed"
            );
        }
    }

    #[test]
    fn exact_public_surface_rejects_missing_extra_or_open_fields() {
        let source = safe_foundation();
        for mutation in [
            source.replacen("pub struct OastPollReceipt", "struct RemovedPollReceipt", 1),
            format!("{source}\npub struct ExtraCorrelationType {{ private: () }}"),
            source.replacen(
                "pub struct OastEvent { private: () }",
                "pub struct OastEvent { pub event: () }",
                1,
            ),
            format!("{source}\npub fn execute() {{}}"),
        ] {
            assert!(!foundation_contract_violations(&mutation)
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn module_wiring_is_one_feature_gated_path_without_root_reexports() {
        let source = r#"
            #[cfg(feature = "oast-correlation")]
            pub mod oast;
            pub mod ordinary;
        "#;
        assert!(library_wiring_violations(source).unwrap().is_empty());

        for mutation in [
            source.replace("#[cfg(feature = \"oast-correlation\")]\n", ""),
            source.replace("oast-correlation", "scanning"),
            source.replace("pub mod oast;", "mod oast;"),
            source.replace("pub mod oast;", "pub mod oast {}"),
            format!("{source}\n#[cfg(feature = \"oast-correlation\")] pub mod oast;"),
            format!("{source}\npub use crate::oast::OastCorrelation;"),
            format!("{source}\npub type RootCorrelation = oast::OastCorrelation;"),
        ] {
            assert!(!library_wiring_violations(&mutation).unwrap().is_empty());
        }
    }

    #[test]
    fn module_policy_allows_only_the_reviewed_internal_and_external_edges() {
        let policy = super::super::MODULE_POLICIES
            .iter()
            .find(|policy| policy.source == "oast.rs")
            .expect("OAST module policy must be registered");
        assert_eq!(policy.allowed_external, &["sha2", "zeroize"]);
        let safe = r#"
            use std::collections::{BTreeMap, BTreeSet};
            use sha2::{Digest, Sha256};
            use zeroize::Zeroize;
            use crate::verification::VerificationCase;

            fn bind(case: &VerificationCase, id: [u8; 32]) {
                let _ = (BTreeMap::<u8, u8>::new(), BTreeSet::<u8>::new());
                let _ = Sha256::digest(id);
                let mut secret = id;
                secret.zeroize();
                let _ = VerificationCase::action_id(case);
            }
        "#;
        assert!(super::super::inspect_module_source(policy, safe)
            .unwrap()
            .is_empty());

        for mutation in [
            "use crate::web_runtime::WebRuntime;",
            "use crate::reporting::AssessmentReport;",
            "use reqwest::Client;",
            "use tokio::runtime::Runtime;",
        ] {
            let violations = super::super::inspect_module_source(policy, mutation)
                .unwrap()
                .join("\n");
            assert!(
                !violations.is_empty(),
                "mutation unexpectedly passed: {mutation}"
            );
        }
    }
}
