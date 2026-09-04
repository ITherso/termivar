//! Strict validation for the repository-owned scanner conformance corpus.
//!
//! The corpus is inert test data. This module performs bounded filesystem reads,
//! validates the closed schemas and safe-fixture policy, computes a deterministic
//! semantic digest, and checks the generated inventory. It owns no network or
//! scanner-runtime authority.

use crate::TaskResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Component, Path},
};
use url::{Host, Url};

const CORPUS_ROOT: &str = "test-corpus/web-assessment/v1";
const MANIFEST_PATH: &str = "test-corpus/web-assessment/v1/manifest.toml";
const INVENTORY_PATH: &str = "test-corpus/web-assessment/v1/INVENTORY.md";
const README_PATH: &str = "test-corpus/web-assessment/v1/README.md";
const MANIFEST_SCHEMA: &str = "security-assessment-corpus/v1";
const CASE_SCHEMA: &str = "security-assessment-fixture/v1";
const DIGEST_DOMAIN: &str = "security-assessment-corpus-digest/v1";
const DIGEST_PREFIX: &str = "corpus-sha256";
const REDACTION_SENTINEL: &str = "CORPUS-MUST-NOT-CONTAIN-SECRET-7B39F1";

const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_CASE_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_INVENTORY_BYTES: usize = 512 * 1024;
const MAX_README_BYTES: usize = 128 * 1024;
const MAX_CASES: usize = 128;
const MAX_TREE_FILES: usize = 512;
const MAX_ID_BYTES: usize = 96;
const MAX_TITLE_BYTES: usize = 192;
const MAX_SUMMARY_BYTES: usize = 1024;
const MAX_PURPOSE_BYTES: usize = 768;
const MAX_PATH_BYTES: usize = 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 128;
const MAX_HEADERS: usize = 32;
const MAX_HEADER_NAME_BYTES: usize = 64;
const MAX_HEADER_VALUE_BYTES: usize = 512;
const MAX_QUERY_PARAMETERS: usize = 32;
const MAX_QUERY_NAME_BYTES: usize = 96;
const MAX_QUERY_VALUE_BYTES: usize = 512;
const MAX_TAGS: usize = 24;
const MAX_TAG_BYTES: usize = 48;
const MAX_INLINE_BODY_BYTES: usize = 8 * 1024;
const MAX_AUTHORIZATION_SELECTED_PATHS: usize = 8;
const MAX_AUTHORIZATION_IGNORED_PATHS: usize = 16;
const MAX_AUTHORIZATION_UNORDERED_PATHS: usize = 8;
const MAX_AUTHORIZATION_POINTER_BYTES: usize = 256;
const MAX_AUTHORIZATION_DIFF_PATHS: u16 = 32;

const REQUEST_HEADER_ALLOWLIST: &[&str] = &["accept", "content-type", "user-agent", "x-fixture-id"];
const RESPONSE_HEADER_ALLOWLIST: &[&str] = &[
    "content-type",
    "server",
    "retry-after",
    "location",
    "www-authenticate",
    "x-powered-by",
    "cf-ray",
    "x-sucuri-id",
];

/// Validate the checked-in corpus, or rewrite only its digest and generated
/// inventory when `write` is explicitly selected.
pub(super) fn run(workspace_root: &Path, write: bool) -> TaskResult {
    let mut corpus = load_and_validate(workspace_root)?;
    if write {
        let manifest_path = workspace_root.join(MANIFEST_PATH);
        rewrite_digest(
            &manifest_path,
            &corpus.manifest_source,
            &corpus.semantic_digest,
        )?;
        corpus
            .manifest
            .corpus_digest
            .clone_from(&corpus.semantic_digest);
        fs::write(
            workspace_root.join(INVENTORY_PATH),
            render_inventory(&corpus),
        )?;
    } else {
        validate_checked_outputs(workspace_root, &corpus)?;
    }

    let mut categories = BTreeMap::<&str, usize>::new();
    let mut provenance = BTreeMap::<&str, usize>::new();
    for case in &corpus.cases {
        *categories.entry(case.case.category.wire()).or_default() += 1;
        *provenance.entry(case.case.provenance.wire()).or_default() += 1;
    }
    println!(
        "scanner corpus validated: {} case(s), categories {:?}, provenance {:?}, digest {}",
        corpus.cases.len(),
        categories,
        provenance,
        corpus.semantic_digest
    );
    Ok(())
}

struct ValidatedCorpus {
    manifest_source: Vec<u8>,
    manifest: CorpusManifest,
    cases: Vec<LoadedCase>,
    body_digests: BTreeMap<String, String>,
    semantic_digest: String,
}

struct LoadedCase {
    case: FixtureCase,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifest {
    schema: String,
    corpus_id: String,
    revision: u32,
    title: String,
    summary: String,
    corpus_digest: String,
    case_files: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    schema: String,
    id: String,
    revision: u32,
    category: CaseCategory,
    purpose: String,
    provenance: Provenance,
    support: SupportLevel,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    parent_case: Option<String>,
    #[serde(default)]
    equivalent_to: Option<String>,
    request: FixtureRequest,
    response: FixtureResponse,
    #[serde(default)]
    authorization: Option<AuthorizationFixture>,
    #[serde(default)]
    ssrf_oast: Option<SsrfOastFixture>,
    expected: ExpectedSemantics,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SsrfOastFixture {
    source: SsrfOastCandidateSourceExpectation,
    scenario: SsrfOastScenario,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationFixture {
    resource: String,
    resource_handle: String,
    expectation: AuthorizationPolicyExpectation,
    method: AuthorizationMethod,
    comparison: AuthorizationComparisonFixture,
    primary_candidate: AuthorizationViewFixture,
    peer_candidate: AuthorizationViewFixture,
    primary_replay: AuthorizationViewFixture,
    peer_replay: AuthorizationViewFixture,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationComparisonFixture {
    selected_paths: Vec<String>,
    #[serde(default)]
    ignored_paths: Vec<String>,
    #[serde(default)]
    unordered_array_paths: Vec<String>,
    max_diff_paths: u16,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationViewFixture {
    status: u16,
    media_type: String,
    completion: CompletionState,
    truncated: bool,
    state: AuthorizationBodyState,
    body_file: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureRequest {
    method: HttpMethod,
    origin: String,
    path: String,
    role: ExchangeRole,
    #[serde(default)]
    loopback_fixture: bool,
    #[serde(default)]
    query: Vec<QueryParameter>,
    #[serde(default)]
    headers: Vec<FixtureHeader>,
    #[serde(default)]
    body_media_type: Option<String>,
    #[serde(default)]
    body_file: Option<String>,
    #[serde(default)]
    inline_body: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureResponse {
    status: u16,
    media_type: String,
    role: ExchangeRole,
    completion: CompletionState,
    truncated: bool,
    #[serde(default)]
    headers: Vec<FixtureHeader>,
    #[serde(default)]
    body_file: Option<String>,
    #[serde(default)]
    inline_body: Option<String>,
    #[serde(default)]
    control_status: Option<u16>,
    #[serde(default)]
    control_body_file: Option<String>,
    #[serde(default)]
    replay_status: Option<u16>,
    #[serde(default)]
    replay_body_file: Option<String>,
    #[serde(default)]
    source_body_file: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QueryParameter {
    name: String,
    value: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureHeader {
    name: String,
    value: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedSemantics {
    #[serde(default)]
    http_media: Option<HttpMediaExpectation>,
    #[serde(default)]
    defense_state: Option<DefenseStateExpectation>,
    #[serde(default)]
    defense_transition: Option<DefenseTransitionExpectation>,
    #[serde(default)]
    reflection_context: Option<ReflectionContextExpectation>,
    #[serde(default)]
    html_quote_mode: Option<HtmlQuoteExpectation>,
    #[serde(default)]
    javascript_context: Option<JavascriptContextExpectation>,
    #[serde(default)]
    sql_relation: Option<StructuralRelationExpectation>,
    #[serde(default)]
    ssti_relation: Option<StructuralRelationExpectation>,
    #[serde(default)]
    xss_relation: Option<StructuralRelationExpectation>,
    #[serde(default)]
    normalization_outcome: Option<NormalizationExpectation>,
    #[serde(default)]
    graphql_evidence: Option<GraphqlExpectation>,
    #[serde(default)]
    openapi_outcome: Option<OpenApiExpectation>,
    #[serde(default)]
    openapi_version: Option<OpenApiVersionExpectation>,
    #[serde(default)]
    openapi_path_count: Option<u32>,
    #[serde(default)]
    openapi_operation_count: Option<u32>,
    #[serde(default)]
    openapi_required_parameter_locations: Vec<OpenApiParameterLocationExpectation>,
    #[serde(default)]
    openapi_required_security_schemes: Vec<OpenApiSecuritySchemeExpectation>,
    #[serde(default)]
    openapi_required_effective_security_schemes: Vec<OpenApiSecuritySchemeExpectation>,
    #[serde(default)]
    openapi_required_server_kinds: Vec<OpenApiServerKindExpectation>,
    #[serde(default)]
    openapi_required_candidate_tags: Vec<OpenApiCandidateTagExpectation>,
    #[serde(default)]
    openapi_digest_matches: Option<String>,
    #[serde(default)]
    openapi_generated_input: Option<OpenApiGeneratedInputExpectation>,
    #[serde(default)]
    authorization_outcome: Option<AuthorizationOutcomeExpectation>,
    #[serde(default)]
    ssrf_oast_outcome: Option<SsrfOastOutcomeExpectation>,
    #[serde(default)]
    assessment_capability: Option<String>,
    #[serde(default)]
    maximum_disposition: Option<DispositionExpectation>,
    #[serde(default)]
    maximum_authority: Option<MaximumAuthorityExpectation>,
    #[serde(default)]
    incompleteness: Option<IncompletenessExpectation>,
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "kebab-case")]
        enum $name { $($variant),+ }

        impl $name {
            fn wire(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }
    };
}

wire_enum!(CaseCategory {
    HttpMedia => "http-media",
    Defense => "defense",
    Sql => "sql",
    Ssti => "ssti",
    Xss => "xss",
    Normalization => "normalization",
    ApiGraphql => "api-graphql",
    ApiOpenapi => "api-openapi",
    Authorization => "authorization",
    SsrfOast => "ssrf-oast"
});
wire_enum!(Provenance {
    CurrentAuthored => "current-authored",
    HistoricalSanitized => "historical-sanitized",
    GeneratedBoundary => "generated-boundary"
});
wire_enum!(SupportLevel {
    Current => "current",
    MetadataOnly => "metadata-only"
});
wire_enum!(HttpMethod { Get => "get", Post => "post", Head => "head", Options => "options" });
wire_enum!(ExchangeRole {
    Bootstrap => "bootstrap",
    Control => "control",
    Candidate => "candidate",
    Replay => "replay"
});
wire_enum!(CompletionState { Complete => "complete", Incomplete => "incomplete" });
wire_enum!(HttpMediaExpectation {
    Json => "json",
    JsonSuffix => "json-suffix",
    GraphqlResponseJson => "graphql-response-json",
    Malformed => "malformed",
    Html => "html",
    UnsupportedBinary => "unsupported-binary",
    Truncated => "truncated"
});
wire_enum!(DefenseStateExpectation {
    Open => "open",
    Blocking => "blocking",
    Challenge => "challenge",
    RateLimited => "rate-limited",
    Unknown => "unknown"
});
wire_enum!(DefenseTransitionExpectation {
    None => "none",
    StandingBlock => "standing-block",
    CandidateSpecificBlock => "candidate-specific-block",
    RateLimit => "rate-limit",
    Deescalated => "deescalated"
});
wire_enum!(ReflectionContextExpectation {
    HtmlText => "html-text",
    Attribute => "attribute",
    Script => "script",
    SameContext => "same-context",
    Ambiguous => "ambiguous",
    NoneObserved => "none-observed"
});
wire_enum!(HtmlQuoteExpectation {
    Single => "single",
    Double => "double",
    Unquoted => "unquoted",
    NotApplicable => "not-applicable"
});
wire_enum!(JavascriptContextExpectation {
    SingleQuoted => "single-quoted",
    DoubleQuoted => "double-quoted",
    TemplateText => "template-text",
    Expression => "expression",
    TemplateExpression => "template-expression",
    Comment => "comment",
    Regex => "regex",
    Unknown => "unknown"
});
wire_enum!(StructuralRelationExpectation {
    Matched => "matched",
    NotMatched => "not-matched",
    CandidateOnly => "candidate-only",
    ReplayMismatch => "replay-mismatch",
    LiteralReflection => "literal-reflection",
    Contaminated => "contaminated",
    Ambiguous => "ambiguous"
});
wire_enum!(NormalizationExpectation {
    SemanticGapObserved => "semantic-gap-observed",
    AcceptedSemanticsUnknown => "accepted-semantics-unknown",
    ReplayMismatch => "replay-mismatch",
    Ineligible => "ineligible",
    StillBlocked => "still-blocked"
});
wire_enum!(GraphqlExpectation {
    ExactEnvelope => "exact-envelope",
    TypenameControl => "typename-control",
    IntrospectionAvailable => "introspection-available",
    IntrospectionRestricted => "introspection-restricted",
    GenericJson => "generic-json",
    GraphqlLikeHtml => "graphql-like-html",
    MalformedEnvelope => "malformed-envelope",
    PartialDataWithErrors => "partial-data-with-errors",
    DepthLimited => "depth-limited",
    BatchMetadataOnly => "batch-metadata-only",
    GetQueryMetadataOnly => "get-query-metadata-only"
});
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum OpenApiExpectation {
    #[serde(rename = "document")]
    Document,
    #[serde(rename = "swagger-2.0-metadata-only")]
    Swagger20MetadataOnly,
    #[serde(rename = "yaml-metadata-only")]
    YamlMetadataOnly,
    #[serde(rename = "unsupported-version")]
    UnsupportedVersion,
    #[serde(rename = "malformed")]
    Malformed,
    #[serde(rename = "limit-exceeded")]
    LimitExceeded,
    #[serde(rename = "too-large")]
    TooLarge,
}

impl OpenApiExpectation {
    const fn wire(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Swagger20MetadataOnly => "swagger-2.0-metadata-only",
            Self::YamlMetadataOnly => "yaml-metadata-only",
            Self::UnsupportedVersion => "unsupported-version",
            Self::Malformed => "malformed",
            Self::LimitExceeded => "limit-exceeded",
            Self::TooLarge => "too-large",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum OpenApiVersionExpectation {
    #[serde(rename = "openapi-3.0")]
    OpenApi30,
    #[serde(rename = "openapi-3.1")]
    OpenApi31,
}

impl OpenApiVersionExpectation {
    const fn wire(self) -> &'static str {
        match self {
            Self::OpenApi30 => "openapi-3.0",
            Self::OpenApi31 => "openapi-3.1",
        }
    }
}
wire_enum!(OpenApiParameterLocationExpectation {
    Query => "query",
    Header => "header",
    Path => "path",
    Cookie => "cookie"
});
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum OpenApiSecuritySchemeExpectation {
    #[serde(rename = "api-key-query")]
    ApiKeyQuery,
    #[serde(rename = "api-key-header")]
    ApiKeyHeader,
    #[serde(rename = "http-bearer")]
    HttpBearer,
    #[serde(rename = "oauth2")]
    Oauth2,
    #[serde(rename = "openid-connect")]
    OpenIdConnect,
}

impl OpenApiSecuritySchemeExpectation {
    const fn wire(self) -> &'static str {
        match self {
            Self::ApiKeyQuery => "api-key-query",
            Self::ApiKeyHeader => "api-key-header",
            Self::HttpBearer => "http-bearer",
            Self::Oauth2 => "oauth2",
            Self::OpenIdConnect => "openid-connect",
        }
    }
}
wire_enum!(OpenApiServerKindExpectation {
    ExactOrigin => "exact-origin",
    Relative => "relative",
    CrossOrigin => "cross-origin",
    Templated => "templated"
});
wire_enum!(OpenApiCandidateTagExpectation {
    ReadOnly => "read-only",
    BodyBearing => "body-bearing",
    Parameterized => "parameterized",
    DeclaresSecurity => "declares-security",
    DeclaresAnonymousAccess => "declares-anonymous-access",
    JsonRequest => "json-request",
    JsonResponse => "json-response",
    Deprecated => "deprecated",
    AuthorizationReviewCandidate => "authorization-review-candidate",
    SqlInputCandidate => "sql-input-candidate",
    SsrfUrlCandidate => "ssrf-url-candidate",
    UploadCandidate => "upload-candidate",
    OauthCandidate => "oauth-candidate"
});
wire_enum!(OpenApiGeneratedInputExpectation {
    DocumentSizePlusOne => "document-size-plus-one",
    PathLimitPlusOne => "path-limit-plus-one"
});
wire_enum!(AuthorizationPolicyExpectation { PrimaryOnly => "primary-only" });
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum AuthorizationMethod {
    #[serde(rename = "GET")]
    Get,
}

impl AuthorizationMethod {
    const fn wire(self) -> &'static str {
        match self {
            Self::Get => "GET",
        }
    }
}
wire_enum!(AuthorizationBodyState {
    CompleteJson => "complete-json",
    UnsupportedMedia => "unsupported-media",
    Html => "html",
    Redirect => "redirect",
    RateLimited => "rate-limited",
    ServerError => "server-error",
    MalformedJson => "malformed-json",
    Truncated => "truncated",
    Incomplete => "incomplete",
    BudgetExhausted => "budget-exhausted",
    Cancelled => "cancelled",
    DefensiveInterference => "defensive-interference"
});
wire_enum!(AuthorizationOutcomeExpectation {
    PrimaryBaselineInvalid => "primary-baseline-invalid",
    PrimaryUnstable => "primary-unstable",
    PeerDenied => "peer-denied",
    PeerUnstable => "peer-unstable",
    CrossStatusDifferent => "cross-status-different",
    CrossFieldsEquivalentOnly => "cross-fields-equivalent-only",
    CrossResourcesDifferent => "cross-resources-different",
    StableCrossPrincipalEquivalence => "stable-cross-principal-equivalence",
    DefensiveInterference => "defensive-interference",
    RateLimited => "rate-limited",
    RedirectObserved => "redirect-observed",
    UnsupportedMedia => "unsupported-media",
    MalformedJson => "malformed-json",
    GenericJsonErrorEnvelope => "generic-json-error-envelope",
    SelectedPathMissing => "selected-path-missing",
    Truncated => "truncated",
    Incomplete => "incomplete",
    BudgetExhausted => "budget-exhausted",
    Cancelled => "cancelled"
});
wire_enum!(SsrfOastCandidateSourceExpectation {
    ObservedUrlQuery => "observed-url-query"
});
wire_enum!(SsrfOastScenario {
    RepeatedCallbacksObserved => "repeated-callbacks-observed",
    ControlIncomplete => "control-incomplete",
    RegistrationIncomplete => "registration-incomplete",
    AllocationIncomplete => "allocation-incomplete",
    PreflightContaminated => "preflight-contaminated",
    TargetNotDispatched => "target-not-dispatched",
    NoCallback => "no-callback",
    CandidateOnly => "candidate-only",
    ReplayOnly => "replay-only",
    WrongCallback => "wrong-callback",
    EventIdentityConflict => "event-identity-conflict",
    CorrelationMismatch => "correlation-mismatch",
    DuplicateOnly => "duplicate-only",
    CleanupIncomplete => "cleanup-incomplete",
    DefensiveInterference => "defensive-interference",
    RateLimited => "rate-limited",
    ProviderAuthenticationFailed => "provider-authentication-failed",
    MalformedProviderResponse => "malformed-provider-response",
    PollExhausted => "poll-exhausted",
    Expired => "expired",
    Cancelled => "cancelled",
    BudgetExhausted => "budget-exhausted",
    Truncated => "truncated",
    Incomplete => "incomplete"
});
wire_enum!(SsrfOastOutcomeExpectation {
    RepeatedCallbacksObserved => "repeated-callbacks-observed",
    ControlIncomplete => "control-incomplete",
    RegistrationIncomplete => "registration-incomplete",
    AllocationIncomplete => "allocation-incomplete",
    PreflightContaminated => "preflight-contaminated",
    TargetNotDispatched => "target-not-dispatched",
    NoCallback => "no-callback",
    CandidateOnly => "candidate-only",
    ReplayOnly => "replay-only",
    WrongCallback => "wrong-callback",
    EventIdentityConflict => "event-identity-conflict",
    CorrelationMismatch => "correlation-mismatch",
    DuplicateOnly => "duplicate-only",
    CleanupIncomplete => "cleanup-incomplete",
    DefensiveInterference => "defensive-interference",
    RateLimited => "rate-limited",
    ProviderAuthenticationFailed => "provider-authentication-failed",
    MalformedProviderResponse => "malformed-provider-response",
    PollExhausted => "poll-exhausted",
    Expired => "expired",
    Cancelled => "cancelled",
    BudgetExhausted => "budget-exhausted",
    Truncated => "truncated",
    Incomplete => "incomplete"
});
wire_enum!(DispositionExpectation {
    Informational => "informational",
    NeedsReview => "needs-review",
    Confirmed => "confirmed"
});
wire_enum!(MaximumAuthorityExpectation {
    KnowledgeOnly => "knowledge-only",
    VerifierAuthorized => "verifier-authorized"
});
wire_enum!(IncompletenessExpectation {
    BodyTruncated => "body-truncated",
    ResponseIncomplete => "response-incomplete",
    UnsupportedByRuntime => "unsupported-by-runtime",
    FutureMetadataOnly => "future-metadata-only"
});

fn load_and_validate(workspace_root: &Path) -> TaskResult<ValidatedCorpus> {
    let root = workspace_root.join(CORPUS_ROOT);
    let tree = validate_tree(&root)?;
    let readme = read_bounded(&workspace_root.join(README_PATH), MAX_README_BYTES)?;
    validate_safe_fixture_bytes(&readme)?;
    canonical_text(&readme, "corpus README")?;
    let manifest_path = workspace_root.join(MANIFEST_PATH);
    let manifest_source = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    validate_safe_fixture_bytes(&manifest_source)?;
    let manifest_text = canonical_text(&manifest_source, "corpus manifest")?;
    let manifest: CorpusManifest = toml::from_str(&manifest_text)
        .map_err(|error| bounded_parse_error("corpus manifest", &error))?;
    validate_manifest(&manifest)?;

    let expected_case_paths: BTreeSet<_> = manifest.case_files.iter().cloned().collect();
    let actual_case_paths: BTreeSet<_> = tree
        .iter()
        .filter(|path| path.starts_with("cases/") && path.ends_with(".toml"))
        .cloned()
        .collect();
    if expected_case_paths != actual_case_paths {
        return Err("manifest case inventory does not match the repository case tree".into());
    }

    let mut cases = Vec::with_capacity(manifest.case_files.len());
    for source_path in &manifest.case_files {
        let source = read_bounded(&root.join(source_path), MAX_CASE_BYTES)?;
        validate_safe_fixture_bytes(&source)?;
        let text = canonical_text(&source, "fixture case")?;
        let case: FixtureCase =
            toml::from_str(&text).map_err(|error| bounded_parse_error("fixture case", &error))?;
        validate_case(source_path, &case)?;
        cases.push(LoadedCase { case });
    }
    let referenced_bodies = referenced_bodies(&cases)?;
    let actual_bodies: BTreeSet<_> = tree
        .iter()
        .filter(|path| path.starts_with("bodies/"))
        .cloned()
        .collect();
    if referenced_bodies != actual_bodies {
        return Err("body fixture inventory contains a dangling or unreferenced body".into());
    }
    let mut body_digests = BTreeMap::new();
    for body_path in referenced_bodies {
        let bytes = read_bounded(&root.join(&body_path), MAX_BODY_BYTES)?;
        reject_executable_bytes(&bytes)?;
        let allow_loopback = cases
            .iter()
            .filter(|loaded| case_references_body(&loaded.case, &body_path))
            .all(|loaded| loaded.case.request.loopback_fixture);
        validate_safe_fixture_material(&bytes, allow_loopback)?;
        let canonical = canonical_text(&bytes, "fixture body")?;
        body_digests.insert(body_path, sha256_hex(canonical.as_bytes()));
    }
    validate_case_relationships(&cases, &body_digests)?;

    let mut corpus = ValidatedCorpus {
        manifest_source,
        manifest,
        cases,
        body_digests,
        semantic_digest: String::new(),
    };
    corpus.semantic_digest = semantic_digest(&corpus);
    Ok(corpus)
}

fn validate_checked_outputs(workspace_root: &Path, corpus: &ValidatedCorpus) -> TaskResult {
    validate_digest_wire(&corpus.manifest.corpus_digest)?;
    if corpus.manifest.corpus_digest != corpus.semantic_digest {
        return Err(format!(
            "corpus digest mismatch: stored {}, computed {}",
            corpus.manifest.corpus_digest, corpus.semantic_digest
        )
        .into());
    }
    let inventory = read_bounded(&workspace_root.join(INVENTORY_PATH), MAX_INVENTORY_BYTES)?;
    validate_safe_fixture_bytes(&inventory)?;
    let actual = canonical_text(&inventory, "generated corpus inventory")?;
    if actual != render_inventory(corpus) {
        return Err("generated corpus inventory is stale; run `cargo run --locked -p xtask -- scanner-corpus --write`".into());
    }
    Ok(())
}

fn validate_tree(root: &Path) -> TaskResult<BTreeSet<String>> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("corpus root must be a real directory, not a link".into());
    }
    let mut files = BTreeSet::new();
    collect_tree(root, root, &mut files)?;
    for required in ["manifest.toml", "INVENTORY.md", "README.md"] {
        if !files.contains(required) {
            return Err(format!("corpus is missing required file {required}").into());
        }
    }
    Ok(files)
}

fn collect_tree(root: &Path, current: &Path, files: &mut BTreeSet<String>) -> TaskResult {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err("corpus symlinks are forbidden".into());
        }
        let relative = safe_relative_path(root, &path)?;
        if metadata.is_dir() {
            if !matches!(relative.as_str(), "cases" | "bodies") {
                return Err(format!("unexpected corpus directory {relative}").into());
            }
            collect_tree(root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err("corpus entries must be regular files".into());
        }
        validate_tree_file_name(&relative)?;
        reject_executable_mode(&metadata)?;
        if !files.insert(relative) || files.len() > MAX_TREE_FILES {
            return Err("corpus file inventory is duplicate or above its hard limit".into());
        }
    }
    Ok(())
}

fn safe_relative_path(root: &Path, path: &Path) -> TaskResult<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| "corpus path escaped its repository root")?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("corpus path contains traversal or a non-normal component".into());
    }
    let value = relative.to_string_lossy().replace('\\', "/");
    validate_relative_reference(&value, MAX_PATH_BYTES)?;
    Ok(value)
}

fn validate_tree_file_name(path: &str) -> TaskResult {
    let allowed = matches!(path, "manifest.toml" | "INVENTORY.md" | "README.md")
        || (path.starts_with("cases/") && path.ends_with(".toml"))
        || (path.starts_with("bodies/")
            && [".json", ".html", ".txt", ".xml", ".yaml"]
                .iter()
                .any(|extension| path.ends_with(extension)));
    if !allowed {
        return Err(format!("unexpected or executable corpus file {path}").into());
    }
    Ok(())
}

#[cfg(unix)]
fn reject_executable_mode(metadata: &fs::Metadata) -> TaskResult {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 != 0 {
        Err("corpus files must not have executable permission bits".into())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn reject_executable_mode(_metadata: &fs::Metadata) -> TaskResult {
    Ok(())
}

fn reject_executable_bytes(bytes: &[u8]) -> TaskResult {
    let executable = bytes.starts_with(b"#!")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]);
    if executable {
        Err("fixture body resembles executable content".into())
    } else {
        Ok(())
    }
}

fn validate_manifest(manifest: &CorpusManifest) -> TaskResult {
    validate_manifest_decoded_safety(manifest)?;
    if manifest.schema != MANIFEST_SCHEMA {
        return Err("unsupported corpus manifest schema".into());
    }
    validate_id(&manifest.corpus_id, "corpus_id")?;
    validate_revision(manifest.revision)?;
    validate_text(&manifest.title, "title", MAX_TITLE_BYTES)?;
    validate_text(&manifest.summary, "summary", MAX_SUMMARY_BYTES)?;
    validate_digest_wire(&manifest.corpus_digest)?;
    if manifest.case_files.is_empty() || manifest.case_files.len() > MAX_CASES {
        return Err("corpus case count is empty or above its hard limit".into());
    }
    let mut unique = BTreeSet::new();
    for path in &manifest.case_files {
        validate_relative_reference(path, MAX_PATH_BYTES)?;
        if !path.starts_with("cases/") || !path.ends_with(".toml") {
            return Err("manifest case paths must stay under cases/ and end in .toml".into());
        }
        if !unique.insert(path) {
            return Err("manifest contains a duplicate case file".into());
        }
    }
    Ok(())
}

fn validate_case(source_path: &str, case: &FixtureCase) -> TaskResult {
    validate_case_decoded_safety(case)?;
    if case.schema != CASE_SCHEMA {
        return Err("unsupported fixture-case schema".into());
    }
    validate_id(&case.id, "case id")?;
    validate_revision(case.revision)?;
    let expected_path = format!("cases/{}.toml", case.id);
    if source_path != expected_path {
        return Err("fixture case ID must match its repository file name".into());
    }
    validate_text(&case.purpose, "purpose", MAX_PURPOSE_BYTES)?;
    validate_tags(&case.tags)?;
    if let Some(parent) = &case.parent_case {
        validate_id(parent, "parent case")?;
    }
    if let Some(equivalent) = &case.equivalent_to {
        validate_id(equivalent, "equivalent case")?;
        if equivalent == &case.id {
            return Err("fixture case cannot be equivalent to itself".into());
        }
    }
    validate_request(&case.request)?;
    validate_response(&case.response)?;
    validate_authorization_contract(case)?;
    validate_ssrf_oast_contract(case)?;
    if case.response.source_body_file.is_some() && case.category != CaseCategory::Xss {
        return Err("source-body fixtures are limited to XSS source-context conformance".into());
    }
    if (case.response.control_body_file.is_some() || case.response.replay_body_file.is_some())
        && !matches!(
            case.category,
            CaseCategory::Defense
                | CaseCategory::Sql
                | CaseCategory::Ssti
                | CaseCategory::Xss
                | CaseCategory::Normalization
        )
    {
        return Err("control/replay body fixtures are outside this case category".into());
    }
    let requires_pair = case.category == CaseCategory::Ssti
        || (case.category == CaseCategory::Sql
            && case.expected.incompleteness != Some(IncompletenessExpectation::BodyTruncated))
        || case.expected.normalization_outcome.is_some();
    if requires_pair
        && (case.response.control_body_file.is_none() || case.response.replay_body_file.is_none())
    {
        return Err("paired semantic fixtures require explicit control and replay legs".into());
    }
    if matches!(
        case.expected.defense_transition,
        Some(DefenseTransitionExpectation::RateLimit | DefenseTransitionExpectation::Deescalated)
    ) && case.response.control_body_file.is_none()
    {
        return Err("comparative defense transitions require an explicit control leg".into());
    }
    if case.category == CaseCategory::Xss && case.response.control_body_file.is_none() {
        return Err("XSS semantic fixtures require an explicit control leg".into());
    }
    if case.category == CaseCategory::Xss && case.response.source_body_file.is_none() {
        return Err("XSS semantic fixtures require an explicit source-context body".into());
    }
    if case.request.role != case.response.role {
        return Err("request and response roles must match".into());
    }
    validate_expected(&case.expected)?;
    validate_graphql_support_contract(case)?;
    validate_openapi_support_contract(case)?;
    if case.support == SupportLevel::MetadataOnly
        && case.expected.incompleteness != Some(IncompletenessExpectation::FutureMetadataOnly)
    {
        return Err("metadata-only cases must declare future-metadata-only incompleteness".into());
    }
    Ok(())
}

fn validate_graphql_support_contract(case: &FixtureCase) -> TaskResult {
    if case.category != CaseCategory::ApiGraphql {
        return Ok(());
    }
    let expectation = case
        .expected
        .graphql_evidence
        .ok_or("API/GraphQL cases require an explicit GraphQL expectation")?;
    let metadata_only = matches!(
        expectation,
        GraphqlExpectation::BatchMetadataOnly | GraphqlExpectation::GetQueryMetadataOnly
    );
    if metadata_only {
        if case.support != SupportLevel::MetadataOnly
            || case.expected.incompleteness != Some(IncompletenessExpectation::FutureMetadataOnly)
        {
            return Err(
                "GraphQL batching and GET-query fixtures must remain future metadata-only".into(),
            );
        }
    } else if case.support != SupportLevel::Current
        || case.expected.incompleteness == Some(IncompletenessExpectation::FutureMetadataOnly)
    {
        return Err("executable GraphQL V1 fixtures must use current support".into());
    }
    Ok(())
}

fn validate_openapi_support_contract(case: &FixtureCase) -> TaskResult {
    let fields_present = case.expected.openapi_outcome.is_some()
        || case.expected.openapi_version.is_some()
        || case.expected.openapi_path_count.is_some()
        || case.expected.openapi_operation_count.is_some()
        || !case
            .expected
            .openapi_required_parameter_locations
            .is_empty()
        || !case.expected.openapi_required_security_schemes.is_empty()
        || !case
            .expected
            .openapi_required_effective_security_schemes
            .is_empty()
        || !case.expected.openapi_required_server_kinds.is_empty()
        || !case.expected.openapi_required_candidate_tags.is_empty()
        || case.expected.openapi_digest_matches.is_some()
        || case.expected.openapi_generated_input.is_some();
    if case.category != CaseCategory::ApiOpenapi {
        if fields_present {
            return Err("OpenAPI expectations are limited to the API/OpenAPI category".into());
        }
        return Ok(());
    }

    let outcome = case
        .expected
        .openapi_outcome
        .ok_or("API/OpenAPI cases require an explicit OpenAPI outcome")?;
    for (label, values) in [
        (
            "OpenAPI parameter-location expectations",
            case.expected
                .openapi_required_parameter_locations
                .iter()
                .map(|value| value.wire())
                .collect::<Vec<_>>(),
        ),
        (
            "OpenAPI security-scheme expectations",
            case.expected
                .openapi_required_security_schemes
                .iter()
                .map(|value| value.wire())
                .collect::<Vec<_>>(),
        ),
        (
            "OpenAPI effective-security expectations",
            case.expected
                .openapi_required_effective_security_schemes
                .iter()
                .map(|value| value.wire())
                .collect::<Vec<_>>(),
        ),
        (
            "OpenAPI server-kind expectations",
            case.expected
                .openapi_required_server_kinds
                .iter()
                .map(|value| value.wire())
                .collect::<Vec<_>>(),
        ),
        (
            "OpenAPI candidate-tag expectations",
            case.expected
                .openapi_required_candidate_tags
                .iter()
                .map(|value| value.wire())
                .collect::<Vec<_>>(),
        ),
    ] {
        if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
            return Err(format!("{label} must be unique").into());
        }
    }
    if let Some(case_id) = &case.expected.openapi_digest_matches {
        validate_id(case_id, "OpenAPI digest comparison case")?;
        if case_id == &case.id {
            return Err("OpenAPI semantic digest cannot be compared with the same case".into());
        }
    }
    let metadata_only = matches!(
        outcome,
        OpenApiExpectation::Swagger20MetadataOnly | OpenApiExpectation::YamlMetadataOnly
    );
    if metadata_only {
        if case.support != SupportLevel::MetadataOnly
            || case.expected.incompleteness != Some(IncompletenessExpectation::FutureMetadataOnly)
            || case.expected.openapi_version.is_some()
            || case.expected.openapi_path_count.is_some()
            || case.expected.openapi_operation_count.is_some()
        {
            return Err(
                "OpenAPI YAML and Swagger 2.0 fixtures must remain future metadata-only".into(),
            );
        }
        return Ok(());
    }

    if case.support != SupportLevel::Current
        || case.expected.incompleteness == Some(IncompletenessExpectation::FutureMetadataOnly)
    {
        return Err("executable OpenAPI V1 fixtures must use current support".into());
    }
    let complete = outcome == OpenApiExpectation::Document;
    let complete_shape = case.expected.openapi_version.is_some()
        && case.expected.openapi_path_count.is_some()
        && case.expected.openapi_operation_count.is_some();
    if complete != complete_shape {
        return Err(
            "complete OpenAPI documents require exact version, path, and operation expectations"
                .into(),
        );
    }
    let has_catalog_expectations = !case
        .expected
        .openapi_required_parameter_locations
        .is_empty()
        || !case.expected.openapi_required_security_schemes.is_empty()
        || !case
            .expected
            .openapi_required_effective_security_schemes
            .is_empty()
        || !case.expected.openapi_required_server_kinds.is_empty()
        || !case.expected.openapi_required_candidate_tags.is_empty()
        || case.expected.openapi_digest_matches.is_some();
    if !complete && has_catalog_expectations {
        return Err("non-document OpenAPI outcomes cannot declare catalog expectations".into());
    }
    match (outcome, case.expected.openapi_generated_input) {
        (
            OpenApiExpectation::TooLarge,
            Some(OpenApiGeneratedInputExpectation::DocumentSizePlusOne),
        )
        | (
            OpenApiExpectation::LimitExceeded,
            Some(OpenApiGeneratedInputExpectation::PathLimitPlusOne),
        )
        | (OpenApiExpectation::Document, None)
        | (OpenApiExpectation::UnsupportedVersion, None)
        | (OpenApiExpectation::Malformed, None)
        | (OpenApiExpectation::LimitExceeded, None) => {},
        _ => {
            return Err(
                "OpenAPI generated-boundary input must match its exact typed outcome".into(),
            )
        },
    }
    Ok(())
}

fn validate_authorization_contract(case: &FixtureCase) -> TaskResult {
    let is_authorization = case.category == CaseCategory::Authorization;
    if !is_authorization {
        if case.authorization.is_some() || case.expected.authorization_outcome.is_some() {
            return Err(
                "authorization fixture data is limited to the authorization category".into(),
            );
        }
        return Ok(());
    }

    let fixture = case
        .authorization
        .as_ref()
        .ok_or("authorization cases require an exact four-view fixture")?;
    if case.expected.authorization_outcome.is_none() {
        return Err("authorization cases require a typed authorization outcome".into());
    }
    if case.support != SupportLevel::Current {
        return Err("authorization differential fixtures must use current support".into());
    }
    if case.request.method != HttpMethod::Get
        || fixture.method != AuthorizationMethod::Get
        || fixture.expectation != AuthorizationPolicyExpectation::PrimaryOnly
    {
        return Err("authorization V1 fixtures require primary-only GET semantics".into());
    }
    validate_request_path(&fixture.resource)?;
    if fixture.resource != case.request.path {
        return Err("authorization fixture resource must match the request path".into());
    }
    validate_token(
        &fixture.resource_handle,
        "authorization resource handle",
        128,
    )?;
    validate_authorization_comparison(&fixture.comparison)?;
    for view in authorization_views(fixture) {
        validate_authorization_view(view)?;
    }

    let positive = case.expected.authorization_outcome
        == Some(AuthorizationOutcomeExpectation::StableCrossPrincipalEquivalence);
    if positive {
        if case.expected.assessment_capability.as_deref()
            != Some("authorization.resource-cross-principal-equivalence")
            || case.expected.maximum_disposition != Some(DispositionExpectation::NeedsReview)
            || case.expected.maximum_authority != Some(MaximumAuthorityExpectation::KnowledgeOnly)
            || case.expected.incompleteness.is_some()
        {
            return Err(
                "positive authorization equivalence requires a complete bounded review claim contract"
                    .into(),
            );
        }
    } else if case.expected.assessment_capability.is_some()
        || case.expected.maximum_disposition.is_some()
        || case.expected.maximum_authority.is_some()
    {
        return Err("non-positive authorization outcomes cannot declare an assessment item".into());
    }
    Ok(())
}

fn validate_ssrf_oast_contract(case: &FixtureCase) -> TaskResult {
    let is_ssrf_oast = case.category == CaseCategory::SsrfOast;
    if !is_ssrf_oast {
        if case.ssrf_oast.is_some() || case.expected.ssrf_oast_outcome.is_some() {
            return Err("SSRF OAST fixture data is limited to the ssrf-oast category".into());
        }
        return Ok(());
    }

    let fixture = case
        .ssrf_oast
        .as_ref()
        .ok_or("SSRF OAST cases require a typed raw-free lifecycle fixture")?;
    if fixture.source != SsrfOastCandidateSourceExpectation::ObservedUrlQuery
        || case.support != SupportLevel::Current
        || case.request.method != HttpMethod::Get
        || case.request.query.len() != 1
    {
        return Err("SSRF OAST V1 corpus cases require one observed GET URL query source".into());
    }
    let query = &case.request.query[0];
    let candidate = Url::parse(&query.value)
        .map_err(|_| "SSRF OAST observed query value must be an absolute URL")?;
    if !matches!(candidate.scheme(), "http" | "https")
        || candidate.host().is_none()
        || candidate.username() != ""
        || candidate.password().is_some()
        || candidate.fragment().is_some()
    {
        return Err("SSRF OAST observed query value must be an eligible absolute HTTP URL".into());
    }

    let expected = case
        .expected
        .ssrf_oast_outcome
        .ok_or("SSRF OAST cases require a typed outcome")?;
    if expected != ssrf_oast_scenario_outcome(fixture.scenario) {
        return Err("SSRF OAST scenario and typed outcome do not agree".into());
    }

    let positive = expected == SsrfOastOutcomeExpectation::RepeatedCallbacksObserved;
    if positive {
        if case.expected.assessment_capability.as_deref()
            != Some("ssrf.oast-repeated-outbound-interaction@1")
            || case.expected.maximum_disposition != Some(DispositionExpectation::NeedsReview)
            || case.expected.maximum_authority != Some(MaximumAuthorityExpectation::KnowledgeOnly)
            || case.expected.incompleteness.is_some()
        {
            return Err(
                "positive SSRF OAST evidence requires the bounded NeedsReview/KnowledgeOnly contract"
                    .into(),
            );
        }
    } else if case.expected.assessment_capability.is_some()
        || case.expected.maximum_disposition.is_some()
        || case.expected.maximum_authority.is_some()
    {
        return Err("non-positive SSRF OAST outcomes cannot declare an assessment item".into());
    }

    match fixture.scenario {
        SsrfOastScenario::Truncated
            if case.response.completion == CompletionState::Incomplete
                && case.response.truncated
                && case.expected.incompleteness
                    == Some(IncompletenessExpectation::BodyTruncated) => {},
        SsrfOastScenario::Incomplete
            if case.response.completion == CompletionState::Incomplete
                && !case.response.truncated
                && case.expected.incompleteness
                    == Some(IncompletenessExpectation::ResponseIncomplete) => {},
        SsrfOastScenario::Truncated | SsrfOastScenario::Incomplete => {
            return Err("SSRF OAST incomplete scenarios require exact completion metadata".into())
        },
        _ if case.response.completion != CompletionState::Complete
            || case.response.truncated
            || case.expected.incompleteness.is_some() =>
        {
            return Err("complete SSRF OAST scenarios cannot declare generic incompleteness".into())
        },
        _ => {},
    }
    Ok(())
}

const fn ssrf_oast_scenario_outcome(scenario: SsrfOastScenario) -> SsrfOastOutcomeExpectation {
    match scenario {
        SsrfOastScenario::RepeatedCallbacksObserved => {
            SsrfOastOutcomeExpectation::RepeatedCallbacksObserved
        },
        SsrfOastScenario::ControlIncomplete => SsrfOastOutcomeExpectation::ControlIncomplete,
        SsrfOastScenario::RegistrationIncomplete => {
            SsrfOastOutcomeExpectation::RegistrationIncomplete
        },
        SsrfOastScenario::AllocationIncomplete => SsrfOastOutcomeExpectation::AllocationIncomplete,
        SsrfOastScenario::PreflightContaminated => {
            SsrfOastOutcomeExpectation::PreflightContaminated
        },
        SsrfOastScenario::TargetNotDispatched => SsrfOastOutcomeExpectation::TargetNotDispatched,
        SsrfOastScenario::NoCallback => SsrfOastOutcomeExpectation::NoCallback,
        SsrfOastScenario::CandidateOnly => SsrfOastOutcomeExpectation::CandidateOnly,
        SsrfOastScenario::ReplayOnly => SsrfOastOutcomeExpectation::ReplayOnly,
        SsrfOastScenario::WrongCallback => SsrfOastOutcomeExpectation::WrongCallback,
        SsrfOastScenario::EventIdentityConflict => {
            SsrfOastOutcomeExpectation::EventIdentityConflict
        },
        SsrfOastScenario::CorrelationMismatch => SsrfOastOutcomeExpectation::CorrelationMismatch,
        SsrfOastScenario::DuplicateOnly => SsrfOastOutcomeExpectation::DuplicateOnly,
        SsrfOastScenario::CleanupIncomplete => SsrfOastOutcomeExpectation::CleanupIncomplete,
        SsrfOastScenario::DefensiveInterference => {
            SsrfOastOutcomeExpectation::DefensiveInterference
        },
        SsrfOastScenario::RateLimited => SsrfOastOutcomeExpectation::RateLimited,
        SsrfOastScenario::ProviderAuthenticationFailed => {
            SsrfOastOutcomeExpectation::ProviderAuthenticationFailed
        },
        SsrfOastScenario::MalformedProviderResponse => {
            SsrfOastOutcomeExpectation::MalformedProviderResponse
        },
        SsrfOastScenario::PollExhausted => SsrfOastOutcomeExpectation::PollExhausted,
        SsrfOastScenario::Expired => SsrfOastOutcomeExpectation::Expired,
        SsrfOastScenario::Cancelled => SsrfOastOutcomeExpectation::Cancelled,
        SsrfOastScenario::BudgetExhausted => SsrfOastOutcomeExpectation::BudgetExhausted,
        SsrfOastScenario::Truncated => SsrfOastOutcomeExpectation::Truncated,
        SsrfOastScenario::Incomplete => SsrfOastOutcomeExpectation::Incomplete,
    }
}

fn validate_authorization_comparison(comparison: &AuthorizationComparisonFixture) -> TaskResult {
    if comparison.selected_paths.is_empty()
        || comparison.selected_paths.len() > MAX_AUTHORIZATION_SELECTED_PATHS
        || comparison.ignored_paths.len() > MAX_AUTHORIZATION_IGNORED_PATHS
        || comparison.unordered_array_paths.len() > MAX_AUTHORIZATION_UNORDERED_PATHS
        || comparison.max_diff_paths == 0
        || comparison.max_diff_paths > MAX_AUTHORIZATION_DIFF_PATHS
    {
        return Err("authorization comparison profile is outside its hard limits".into());
    }
    let selected = validate_authorization_pointers(&comparison.selected_paths, "selected")?;
    let ignored = validate_authorization_pointers(&comparison.ignored_paths, "ignored")?;
    let unordered =
        validate_authorization_pointers(&comparison.unordered_array_paths, "unordered")?;
    if selected.iter().any(|path| path.is_empty()) {
        return Err("authorization selected paths must be non-root exact JSON Pointers".into());
    }
    if has_redundant_pointer_subtrees(&selected) || has_redundant_pointer_subtrees(&ignored) {
        return Err("authorization comparison paths contain redundant subtrees".into());
    }
    if ignored.iter().any(|path| {
        !selected
            .iter()
            .any(|selected| strict_pointer_descendant(path, selected))
    }) {
        return Err("authorization ignored paths must be inside a selected subtree".into());
    }
    if unordered.iter().any(|path| {
        !selected
            .iter()
            .any(|selected| path == selected || strict_pointer_descendant(path, selected))
    }) {
        return Err("authorization unordered-array paths must be inside a selected subtree".into());
    }
    if unordered.iter().any(|unordered| {
        ignored
            .iter()
            .any(|ignored| unordered == ignored || strict_pointer_descendant(unordered, ignored))
    }) {
        return Err("authorization unordered-array paths cannot be hidden by ignored paths".into());
    }
    Ok(())
}

fn validate_authorization_pointers(values: &[String], label: &str) -> TaskResult<BTreeSet<String>> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(
            value,
            "authorization JSON Pointer",
            MAX_AUTHORIZATION_POINTER_BYTES,
        )?;
        if pointer_has_wildcard_segment(value) || !valid_exact_json_pointer(value) {
            return Err(
                format!("authorization {label} path is not an exact RFC 6901 pointer").into(),
            );
        }
        if !unique.insert(value.clone()) {
            return Err(format!("authorization {label} paths must be unique").into());
        }
    }
    Ok(unique)
}

fn valid_exact_json_pointer(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if !value.starts_with('/') {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'~' {
            if !matches!(bytes.get(index + 1), Some(b'0' | b'1')) {
                return false;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    true
}

fn pointer_has_wildcard_segment(value: &str) -> bool {
    value.split('/').skip(1).any(|token| token == "*")
}

fn strict_pointer_descendant(path: &str, ancestor: &str) -> bool {
    path.len() > ancestor.len()
        && path.starts_with(ancestor)
        && path.as_bytes().get(ancestor.len()) == Some(&b'/')
}

fn has_redundant_pointer_subtrees(paths: &BTreeSet<String>) -> bool {
    paths.iter().enumerate().any(|(index, left)| {
        paths.iter().skip(index + 1).any(|right| {
            strict_pointer_descendant(left, right) || strict_pointer_descendant(right, left)
        })
    })
}

fn authorization_views(fixture: &AuthorizationFixture) -> [&AuthorizationViewFixture; 4] {
    [
        &fixture.primary_candidate,
        &fixture.peer_candidate,
        &fixture.primary_replay,
        &fixture.peer_replay,
    ]
}

fn validate_authorization_view(view: &AuthorizationViewFixture) -> TaskResult {
    if !(100..=599).contains(&view.status) {
        return Err("authorization view status is outside the HTTP range".into());
    }
    validate_text(
        &view.media_type,
        "authorization view media type",
        MAX_MEDIA_TYPE_BYTES,
    )?;
    validate_relative_reference(&view.body_file, MAX_PATH_BYTES)?;
    if !view.body_file.starts_with("bodies/") {
        return Err("authorization view body references must stay under bodies/".into());
    }
    let json_media = json_compatible_fixture_media_type(&view.media_type);
    let html_media = html_fixture_media_type(&view.media_type);
    let complete_response = view.completion == CompletionState::Complete && !view.truncated;
    let coherent = match view.state {
        AuthorizationBodyState::CompleteJson => complete_response && json_media,
        AuthorizationBodyState::UnsupportedMedia => complete_response && !json_media && !html_media,
        AuthorizationBodyState::Html => complete_response && html_media,
        AuthorizationBodyState::Redirect => complete_response && (300..=399).contains(&view.status),
        AuthorizationBodyState::RateLimited => complete_response && view.status == 429,
        AuthorizationBodyState::ServerError => {
            complete_response && (500..=599).contains(&view.status)
        },
        AuthorizationBodyState::MalformedJson => complete_response && json_media,
        AuthorizationBodyState::Truncated => {
            view.completion == CompletionState::Incomplete && view.truncated && json_media
        },
        AuthorizationBodyState::Incomplete => {
            view.completion == CompletionState::Incomplete && !view.truncated
        },
        AuthorizationBodyState::DefensiveInterference => complete_response,
        // These pre-response states carry neither response status nor body in
        // production. The current corpus view schema intentionally cannot
        // fabricate them from mandatory response fields.
        AuthorizationBodyState::BudgetExhausted | AuthorizationBodyState::Cancelled => false,
    };
    if !coherent {
        return Err(
            "authorization view state, status, media, and completion do not reconcile".into(),
        );
    }
    Ok(())
}

fn json_compatible_fixture_media_type(value: &str) -> bool {
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

fn html_fixture_media_type(value: &str) -> bool {
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    matches!(essence.as_str(), "text/html" | "application/xhtml+xml")
}

fn validate_request(request: &FixtureRequest) -> TaskResult {
    validate_origin(&request.origin, request.loopback_fixture)?;
    validate_request_path(&request.path)?;
    if request.query.len() > MAX_QUERY_PARAMETERS {
        return Err("request query parameter count exceeds its hard limit".into());
    }
    let mut names = BTreeSet::new();
    for parameter in &request.query {
        validate_token(&parameter.name, "query name", MAX_QUERY_NAME_BYTES)?;
        validate_text(&parameter.value, "query value", MAX_QUERY_VALUE_BYTES)?;
        if parameter
            .value
            .bytes()
            .any(|byte| matches!(byte, b'&' | b';' | b'#' | b'='))
        {
            return Err("fixture query values must not change request shape".into());
        }
        if !names.insert(parameter.name.to_ascii_lowercase()) {
            return Err("fixture query parameter names must be unique".into());
        }
    }
    validate_headers(&request.headers, REQUEST_HEADER_ALLOWLIST)?;
    validate_body_contract(
        request.body_media_type.as_deref(),
        request.body_file.as_deref(),
        request.inline_body.as_deref(),
    )
}

fn validate_response(response: &FixtureResponse) -> TaskResult {
    if !(100..=599).contains(&response.status) {
        return Err("fixture response status is outside the HTTP range".into());
    }
    validate_text(
        &response.media_type,
        "response media type",
        MAX_MEDIA_TYPE_BYTES,
    )?;
    validate_headers(&response.headers, RESPONSE_HEADER_ALLOWLIST)?;
    validate_body_pair(
        response.body_file.as_deref(),
        response.inline_body.as_deref(),
    )?;
    for (label, status) in [
        ("control response", response.control_status),
        ("replay response", response.replay_status),
    ] {
        if status.is_some_and(|value| !(100..=599).contains(&value)) {
            return Err(format!("{label} status is outside the HTTP range").into());
        }
    }
    if response.control_status.is_some() != response.control_body_file.is_some() {
        return Err("control response status and body must appear together".into());
    }
    if response.replay_status.is_some() != response.replay_body_file.is_some() {
        return Err("replay response status and body must appear together".into());
    }
    for body in [
        response.control_body_file.as_deref(),
        response.replay_body_file.as_deref(),
        response.source_body_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_relative_reference(body, MAX_PATH_BYTES)?;
        if !body.starts_with("bodies/") {
            return Err("fixture body references must stay under bodies/".into());
        }
    }
    if response.truncated && response.completion == CompletionState::Complete {
        return Err("truncated fixture response cannot declare complete execution".into());
    }
    Ok(())
}

fn validate_body_contract(
    media_type: Option<&str>,
    file: Option<&str>,
    inline: Option<&str>,
) -> TaskResult {
    validate_body_pair(file, inline)?;
    if let Some(media_type) = media_type {
        validate_text(media_type, "request body media type", MAX_MEDIA_TYPE_BYTES)?;
    }
    if media_type.is_some() != (file.is_some() || inline.is_some()) {
        return Err("request body media type and body content must appear together".into());
    }
    Ok(())
}

fn validate_body_pair(file: Option<&str>, inline: Option<&str>) -> TaskResult {
    if file.is_some() && inline.is_some() {
        return Err("fixture body must use either a file or an inline value, not both".into());
    }
    if let Some(path) = file {
        validate_relative_reference(path, MAX_PATH_BYTES)?;
        if !path.starts_with("bodies/") {
            return Err("fixture body references must stay under bodies/".into());
        }
    }
    if let Some(value) = inline {
        validate_text(value, "inline body", MAX_INLINE_BODY_BYTES)?;
        validate_safe_fixture_bytes(value.as_bytes())?;
    }
    Ok(())
}

fn validate_headers(headers: &[FixtureHeader], allowlist: &[&str]) -> TaskResult {
    if headers.len() > MAX_HEADERS {
        return Err("fixture header count exceeds its hard limit".into());
    }
    let mut names = BTreeSet::new();
    for header in headers {
        validate_token(&header.name, "header name", MAX_HEADER_NAME_BYTES)?;
        validate_text(&header.value, "header value", MAX_HEADER_VALUE_BYTES)?;
        let name = header.name.to_ascii_lowercase();
        if !allowlist.contains(&name.as_str()) {
            return Err(format!("fixture header `{name}` is outside the closed allowlist").into());
        }
        if !names.insert(name) {
            return Err("fixture header names must be unique".into());
        }
        validate_safe_fixture_bytes(header.value.as_bytes())?;
    }
    Ok(())
}

fn validate_expected(expected: &ExpectedSemantics) -> TaskResult {
    let populated = [
        expected.http_media.is_some(),
        expected.defense_state.is_some(),
        expected.defense_transition.is_some(),
        expected.reflection_context.is_some(),
        expected.html_quote_mode.is_some(),
        expected.javascript_context.is_some(),
        expected.sql_relation.is_some(),
        expected.ssti_relation.is_some(),
        expected.xss_relation.is_some(),
        expected.normalization_outcome.is_some(),
        expected.graphql_evidence.is_some(),
        expected.openapi_outcome.is_some(),
        expected.openapi_version.is_some(),
        expected.openapi_path_count.is_some(),
        expected.openapi_operation_count.is_some(),
        !expected.openapi_required_parameter_locations.is_empty(),
        !expected.openapi_required_security_schemes.is_empty(),
        !expected
            .openapi_required_effective_security_schemes
            .is_empty(),
        !expected.openapi_required_server_kinds.is_empty(),
        !expected.openapi_required_candidate_tags.is_empty(),
        expected.openapi_digest_matches.is_some(),
        expected.openapi_generated_input.is_some(),
        expected.authorization_outcome.is_some(),
        expected.ssrf_oast_outcome.is_some(),
        expected.assessment_capability.is_some(),
        expected.maximum_disposition.is_some(),
        expected.maximum_authority.is_some(),
        expected.incompleteness.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if populated == 0 {
        return Err("fixture case requires at least one typed semantic expectation".into());
    }
    if let Some(capability) = &expected.assessment_capability {
        validate_capability(capability)?;
    }
    if expected.maximum_disposition.is_some() && expected.maximum_authority.is_none() {
        return Err("maximum disposition requires an explicit maximum authority".into());
    }
    if expected.maximum_disposition == Some(DispositionExpectation::Confirmed) {
        match expected.maximum_authority {
            Some(MaximumAuthorityExpectation::VerifierAuthorized) => {},
            Some(MaximumAuthorityExpectation::KnowledgeOnly) | None => {
                return Err("confirmed disposition requires verifier-authorized authority".into())
            },
        }
    }
    Ok(())
}

fn validate_case_relationships(
    cases: &[LoadedCase],
    body_digests: &BTreeMap<String, String>,
) -> TaskResult {
    let mut by_id = BTreeMap::new();
    for loaded in cases {
        let key = (&loaded.case.id, loaded.case.revision);
        if by_id.insert(key, &loaded.case).is_some() {
            return Err("corpus contains a duplicate case ID and revision".into());
        }
    }
    let ids: BTreeMap<_, _> = cases
        .iter()
        .map(|loaded| (loaded.case.id.as_str(), &loaded.case))
        .collect();
    if ids.len() != cases.len() {
        return Err("corpus case IDs must be globally unique".into());
    }
    for loaded in cases {
        let case = &loaded.case;
        if let Some(expected_id) = case.expected.openapi_digest_matches.as_deref() {
            let expected_case = ids
                .get(expected_id)
                .copied()
                .ok_or("OpenAPI digest comparison references an unknown case")?;
            if case.category != CaseCategory::ApiOpenapi
                || expected_case.category != CaseCategory::ApiOpenapi
                || case.expected.openapi_outcome != Some(OpenApiExpectation::Document)
                || expected_case.expected.openapi_outcome != Some(OpenApiExpectation::Document)
            {
                return Err(
                    "OpenAPI digest comparisons require two complete OpenAPI document cases".into(),
                );
            }
        }
        match case.request.role {
            ExchangeRole::Bootstrap | ExchangeRole::Control if case.parent_case.is_some() => {
                return Err("bootstrap/control cases cannot name a parent case".into())
            },
            ExchangeRole::Candidate => {
                let parent = relationship_parent(case, &ids)?;
                if parent.request.role != ExchangeRole::Control {
                    return Err("candidate cases require a control parent".into());
                }
                validate_compatible_pair(parent, case)?;
            },
            ExchangeRole::Replay => {
                let parent = relationship_parent(case, &ids)?;
                if parent.request.role != ExchangeRole::Candidate {
                    return Err("replay cases require a candidate parent".into());
                }
                validate_compatible_pair(parent, case)?;
            },
            ExchangeRole::Bootstrap | ExchangeRole::Control => {},
        }
    }
    validate_semantic_duplicates(cases, &ids, body_digests)
}

fn relationship_parent<'a>(
    case: &FixtureCase,
    ids: &BTreeMap<&str, &'a FixtureCase>,
) -> TaskResult<&'a FixtureCase> {
    let parent = case
        .parent_case
        .as_deref()
        .ok_or("candidate/replay fixture requires a parent case")?;
    ids.get(parent)
        .copied()
        .ok_or_else(|| "fixture relationship references an unknown parent case".into())
}

fn validate_compatible_pair(parent: &FixtureCase, child: &FixtureCase) -> TaskResult {
    if parent.category != child.category
        || parent.request.origin != child.request.origin
        || parent.request.path != child.request.path
        || parent.request.method != child.request.method
    {
        return Err("fixture relationship crosses an incompatible request contract".into());
    }
    Ok(())
}

fn validate_semantic_duplicates(
    cases: &[LoadedCase],
    ids: &BTreeMap<&str, &FixtureCase>,
    body_digests: &BTreeMap<String, String>,
) -> TaskResult {
    let mut fingerprints = BTreeMap::<String, Vec<&FixtureCase>>::new();
    for loaded in cases {
        fingerprints
            .entry(case_semantic_fingerprint(&loaded.case, body_digests))
            .or_default()
            .push(&loaded.case);
    }
    for group in fingerprints.values() {
        if group.len() == 1 {
            if group[0].equivalent_to.is_some() {
                return Err("fixture equivalent_to must point to a semantic duplicate".into());
            }
            continue;
        }
        let canonical = group
            .iter()
            .filter(|case| case.equivalent_to.is_none())
            .copied()
            .collect::<Vec<_>>();
        if canonical.len() != 1 {
            return Err("duplicate semantic cases require exactly one canonical case".into());
        }
        for case in group
            .iter()
            .copied()
            .filter(|case| case.id.as_str() != canonical[0].id.as_str())
        {
            if case.equivalent_to.as_deref() != Some(canonical[0].id.as_str())
                || !ids.contains_key(canonical[0].id.as_str())
            {
                return Err("duplicate semantic case lacks an exact equivalent_to link".into());
            }
        }
    }
    Ok(())
}

fn referenced_bodies(cases: &[LoadedCase]) -> TaskResult<BTreeSet<String>> {
    let mut bodies = BTreeSet::new();
    for loaded in cases {
        let ordinary = [
            loaded.case.request.body_file.as_ref(),
            loaded.case.response.body_file.as_ref(),
            loaded.case.response.control_body_file.as_ref(),
            loaded.case.response.replay_body_file.as_ref(),
            loaded.case.response.source_body_file.as_ref(),
        ];
        let authorization = loaded
            .case
            .authorization
            .as_ref()
            .map(authorization_views)
            .into_iter()
            .flatten()
            .map(|view| &view.body_file);
        for body in ordinary.into_iter().flatten().chain(authorization) {
            validate_relative_reference(body, MAX_PATH_BYTES)?;
            if !bodies.insert(body.clone()) {
                // Sharing a sanitized body is intentional and does not make it dangling.
            }
        }
    }
    Ok(bodies)
}

fn case_references_body(case: &FixtureCase, path: &str) -> bool {
    let ordinary = [
        case.request.body_file.as_deref(),
        case.response.body_file.as_deref(),
        case.response.control_body_file.as_deref(),
        case.response.replay_body_file.as_deref(),
        case.response.source_body_file.as_deref(),
    ];
    ordinary
        .into_iter()
        .flatten()
        .any(|candidate| candidate == path)
        || case
            .authorization
            .as_ref()
            .map(authorization_views)
            .into_iter()
            .flatten()
            .any(|view| view.body_file == path)
}

fn validate_origin(value: &str, loopback_fixture: bool) -> TaskResult {
    validate_text(value, "request origin", MAX_PATH_BYTES)?;
    let url = Url::parse(value).map_err(|_| "fixture request origin is not a valid URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(
            "fixture request origin must be an exact credential-free HTTP(S) origin".into(),
        );
    }
    let host = url
        .host()
        .ok_or("fixture request origin is missing a host")?;
    let is_loopback = match host {
        Host::Ipv4(address) if IpAddr::V4(address).is_loopback() => true,
        Host::Ipv6(address) if IpAddr::V6(address).is_loopback() => true,
        Host::Ipv4(_) | Host::Ipv6(_) => {
            return Err("numeric fixture origins are limited to explicit loopback fixtures".into())
        },
        Host::Domain(domain) => {
            let domain = domain.to_ascii_lowercase();
            if domain == "example.test"
                || domain.ends_with(".example.test")
                || domain.ends_with(".invalid")
            {
                false
            } else {
                return Err("fixture request origin must use a reserved test domain".into());
            }
        },
    };
    if is_loopback != loopback_fixture {
        return Err(
            "numeric loopback origins require an explicit loopback_fixture contract".into(),
        );
    }
    Ok(())
}

fn validate_request_path(value: &str) -> TaskResult {
    validate_text(value, "request path", MAX_PATH_BYTES)?;
    if !value.starts_with('/')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
        || value.to_ascii_lowercase().contains("%2e")
    {
        return Err("fixture request path is not a bounded canonical absolute path".into());
    }
    Ok(())
}

fn validate_relative_reference(value: &str, maximum: usize) -> TaskResult {
    validate_text(value, "repository-relative fixture path", maximum)?;
    let path = Path::new(value);
    if path.is_absolute()
        || value.contains('\\')
        || value.contains("//")
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("fixture path must be a canonical repository-relative path".into());
    }
    Ok(())
}

fn validate_revision(revision: u32) -> TaskResult {
    if revision == 0 || revision > 65_535 {
        Err("fixture revision is outside its checked range".into())
    } else {
        Ok(())
    }
}

fn validate_id(value: &str, field: &str) -> TaskResult {
    validate_token(value, field, MAX_ID_BYTES)?;
    if value.starts_with('-')
        || value.ends_with('-')
        || value.contains("..")
        || value.contains("//")
        || value.contains("://")
    {
        return Err(format!("{field} has a forbidden identity shape").into());
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> TaskResult {
    if tags.len() > MAX_TAGS {
        return Err("fixture tag count exceeds its hard limit".into());
    }
    let mut unique = BTreeSet::new();
    for tag in tags {
        validate_token(tag, "tag", MAX_TAG_BYTES)?;
        if !unique.insert(tag) {
            return Err("fixture tags must be unique".into());
        }
    }
    Ok(())
}

fn validate_token(value: &str, field: &str, maximum: usize) -> TaskResult {
    validate_text(value, field, maximum)?;
    let valid = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if !valid {
        return Err(format!("{field} contains characters outside its closed ASCII set").into());
    }
    Ok(())
}

fn validate_capability(value: &str) -> TaskResult {
    validate_text(value, "assessment capability", MAX_ID_BYTES)?;
    if let Some((name, revision)) = value.split_once('@') {
        validate_token(name, "assessment capability", MAX_ID_BYTES)?;
        if revision.is_empty()
            || revision.contains('@')
            || !revision.bytes().all(|byte| byte.is_ascii_digit())
            || revision.bytes().all(|byte| byte == b'0')
        {
            return Err("assessment capability revision is not a positive decimal".into());
        }
        Ok(())
    } else {
        validate_token(value, "assessment capability", MAX_ID_BYTES)
    }
}

fn validate_text(value: &str, field: &str, maximum: usize) -> TaskResult {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(|character| {
            character == '\0' || (character.is_control() && !matches!(character, '\n' | '\t'))
        })
    {
        return Err(
            format!("{field} is empty, unbounded, padded, or contains control data").into(),
        );
    }
    Ok(())
}

fn canonical_text(bytes: &[u8], label: &str) -> TaskResult<String> {
    let source = std::str::from_utf8(bytes).map_err(|_| format!("{label} must be strict UTF-8"))?;
    let raw = source.as_bytes();
    let mut output = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'\r' {
            if raw.get(index + 1) != Some(&b'\n') {
                return Err(format!("{label} contains a lone carriage return").into());
            }
            output.push(b'\n');
            index += 2;
        } else {
            output.push(raw[index]);
            index += 1;
        }
    }
    String::from_utf8(output).map_err(Into::into)
}

fn validate_safe_fixture_bytes(bytes: &[u8]) -> TaskResult {
    let text = std::str::from_utf8(bytes).map_err(|_| "corpus fixture text must be UTF-8")?;
    let decoded = decode_policy_escapes(text);
    let lower = decoded.to_ascii_lowercase();
    let dangerous = [
        "alert(",
        "document.cookie",
        "javascript:",
        "drop table",
        "rm -rf",
        "/bin/sh",
        "powershell -",
        "reverse shell",
    ];
    if decoded.contains(REDACTION_SENTINEL)
        || contains_private_key_marker(&lower)
        || dangerous.iter().any(|marker| lower.contains(marker))
        || contains_secret_assignment(&lower)
        || contains_jwt_shaped_token(&decoded)
        || contains_credential_url(&decoded)
        || contains_non_reserved_url(&decoded, true)
        || contains_non_reserved_email(&decoded)
    {
        return Err("corpus fixture violates the deterministic secret/safety policy".into());
    }
    Ok(())
}

fn validate_safe_fixture_material(bytes: &[u8], allow_loopback: bool) -> TaskResult {
    validate_safe_fixture_bytes(bytes)?;
    let text = std::str::from_utf8(bytes).map_err(|_| "corpus fixture text must be UTF-8")?;
    let decoded = decode_policy_escapes(text);
    if contains_non_reserved_url(&decoded, allow_loopback)
        || contains_non_reserved_domain_or_ip(&decoded, allow_loopback)
    {
        return Err("corpus fixture contains a non-reserved network identity".into());
    }
    Ok(())
}

fn decode_policy_escapes(text: &str) -> String {
    let characters = text.chars().collect::<Vec<_>>();
    let mut decoded = String::with_capacity(text.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '\\' && characters.get(index + 1) == Some(&'/') {
            decoded.push('/');
            index += 2;
            continue;
        }
        if characters[index] == '\\'
            && characters.get(index + 1) == Some(&'u')
            && index + 5 < characters.len()
        {
            let digits = characters[index + 2..=index + 5].iter().collect::<String>();
            if digits
                .chars()
                .all(|character| character.is_ascii_hexdigit())
            {
                if let Ok(value) = u32::from_str_radix(&digits, 16) {
                    if let Some(character) = char::from_u32(value) {
                        decoded.push(character);
                        index += 6;
                        continue;
                    }
                }
            }
        }
        decoded.push(characters[index]);
        index += 1;
    }
    decoded
}

fn validate_manifest_decoded_safety(manifest: &CorpusManifest) -> TaskResult {
    for value in [
        manifest.schema.as_str(),
        manifest.corpus_id.as_str(),
        manifest.title.as_str(),
        manifest.summary.as_str(),
        manifest.corpus_digest.as_str(),
    ] {
        validate_safe_fixture_bytes(value.as_bytes())?;
    }
    for path in &manifest.case_files {
        validate_safe_fixture_bytes(path.as_bytes())?;
    }
    for value in [&manifest.title, &manifest.summary] {
        validate_safe_fixture_material(value.as_bytes(), false)?;
    }
    Ok(())
}

fn validate_case_decoded_safety(case: &FixtureCase) -> TaskResult {
    let allow_loopback = case.request.loopback_fixture;
    for value in [
        case.schema.as_str(),
        case.id.as_str(),
        case.purpose.as_str(),
        case.request.origin.as_str(),
        case.request.path.as_str(),
        case.response.media_type.as_str(),
    ] {
        validate_safe_fixture_bytes(value.as_bytes())?;
    }
    validate_safe_fixture_material(case.purpose.as_bytes(), allow_loopback)?;
    for value in case
        .tags
        .iter()
        .map(String::as_str)
        .chain(case.parent_case.as_deref())
        .chain(case.equivalent_to.as_deref())
        .chain(case.request.body_media_type.as_deref())
        .chain(case.request.body_file.as_deref())
        .chain(case.request.inline_body.as_deref())
        .chain(case.response.body_file.as_deref())
        .chain(case.response.inline_body.as_deref())
        .chain(case.response.control_body_file.as_deref())
        .chain(case.response.replay_body_file.as_deref())
        .chain(case.response.source_body_file.as_deref())
        .chain(case.authorization.as_ref().into_iter().flat_map(|fixture| {
            [fixture.resource.as_str(), fixture.resource_handle.as_str()]
                .into_iter()
                .chain(fixture.comparison.selected_paths.iter().map(String::as_str))
                .chain(fixture.comparison.ignored_paths.iter().map(String::as_str))
                .chain(
                    fixture
                        .comparison
                        .unordered_array_paths
                        .iter()
                        .map(String::as_str),
                )
                .chain(
                    authorization_views(fixture)
                        .into_iter()
                        .flat_map(|view| [view.media_type.as_str(), view.body_file.as_str()]),
                )
        }))
        .chain(case.expected.openapi_digest_matches.as_deref())
        .chain(case.expected.assessment_capability.as_deref())
    {
        validate_safe_fixture_bytes(value.as_bytes())?;
    }
    for parameter in &case.request.query {
        validate_safe_fixture_bytes(parameter.name.as_bytes())?;
        validate_safe_fixture_material(parameter.value.as_bytes(), allow_loopback)?;
    }
    for header in case
        .request
        .headers
        .iter()
        .chain(case.response.headers.iter())
    {
        validate_safe_fixture_bytes(header.name.as_bytes())?;
        validate_safe_fixture_material(header.value.as_bytes(), allow_loopback)?;
    }
    for value in [
        case.request.inline_body.as_deref(),
        case.response.inline_body.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_safe_fixture_material(value.as_bytes(), allow_loopback)?;
    }
    Ok(())
}

fn contains_secret_assignment(lower: &str) -> bool {
    let compact = lower
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && !matches!(character, '"' | '\'' | '\\')
        })
        .collect::<String>();
    [
        "authorization:bearer",
        "authorization=bearer",
        "authorization:basic",
        "authorization=basic",
        "api_key:",
        "api_key=",
        "api-key:",
        "api-key=",
        "apikey:",
        "apikey=",
        "access_token:",
        "access_token=",
        "client_secret:",
        "client_secret=",
        "secret_key:",
        "secret_key=",
        "session_id:",
        "session_id=",
        "csrf_token:",
        "csrf_token=",
        "password:",
        "password=",
        "cookie:",
        "cookie=",
        "set-cookie:",
        "set-cookie=",
    ]
    .iter()
    .any(|marker| compact.contains(marker))
}

fn contains_private_key_marker(lower: &str) -> bool {
    [
        "-----begin private key-----",
        "-----begin encrypted private key-----",
        "-----begin rsa private key-----",
        "-----begin dsa private key-----",
        "-----begin ec private key-----",
        "-----begin openssh private key-----",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn contains_jwt_shaped_token(text: &str) -> bool {
    text.split(|character: char| character.is_ascii_whitespace() || "\"'(),;".contains(character))
        .any(|token| {
            let parts = token.split('.').collect::<Vec<_>>();
            parts.len() == 3
                && parts[0].starts_with("eyJ")
                && parts.iter().all(|part| {
                    part.len() >= 8
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
        })
}

fn contains_credential_url(text: &str) -> bool {
    text.split_whitespace().any(|token| {
        let token = token.trim_matches(|character: char| "\"'`()[],;".contains(character));
        if !token.contains("://") {
            return false;
        }
        Url::parse(token).is_ok_and(|url| !url.username().is_empty() || url.password().is_some())
    })
}

fn contains_non_reserved_url(text: &str, allow_loopback: bool) -> bool {
    let lower = text.to_ascii_lowercase();
    ["http://", "https://"].iter().any(|scheme| {
        let mut cursor = 0;
        while let Some(relative_start) = lower[cursor..].find(scheme) {
            let start = cursor + relative_start;
            let candidate = &lower[start..];
            let end = candidate
                .find(|character: char| {
                    character.is_ascii_whitespace()
                        || matches!(
                            character,
                            '"' | '\'' | '<' | '>' | ')' | ']' | '}' | ',' | ';'
                        )
                })
                .unwrap_or(candidate.len());
            let candidate = &candidate[..end];
            if Url::parse(candidate).is_ok_and(|url| {
                !url.username().is_empty()
                    || url.password().is_some()
                    || !url_has_reserved_host(&url, allow_loopback)
            }) {
                return true;
            }
            cursor = start.saturating_add(end.max(scheme.len()));
        }
        false
    })
}

fn contains_non_reserved_domain_or_ip(text: &str, allow_loopback: bool) -> bool {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':' | '[' | ']'))
    })
    .filter(|token| !token.is_empty())
    .any(|token| {
        if let Ok(address) = token.parse::<IpAddr>() {
            return !address.is_loopback() || !allow_loopback;
        }
        if let Ok(socket) = token.parse::<SocketAddr>() {
            return !socket.ip().is_loopback() || !allow_loopback;
        }
        let token = token.to_ascii_lowercase();
        if token == "localhost" {
            return true;
        }
        let labels = token.split('.').collect::<Vec<_>>();
        if labels.len() < 2
            || labels.last().is_none_or(|label| {
                label.len() < 2 || !label.bytes().all(|byte| byte.is_ascii_alphabetic())
            })
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return false;
        }
        !reserved_domain(&token)
    })
}

fn url_has_reserved_host(url: &Url, allow_loopback: bool) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => reserved_domain(&domain.to_ascii_lowercase()),
        Some(Host::Ipv4(address)) => allow_loopback && address.is_loopback(),
        Some(Host::Ipv6(address)) => allow_loopback && address.is_loopback(),
        None => false,
    }
}

fn reserved_domain(domain: &str) -> bool {
    domain == "example.test" || domain.ends_with(".example.test") || domain.ends_with(".invalid")
}

fn contains_non_reserved_email(text: &str) -> bool {
    text.split_whitespace().any(|token| {
        let token = token.trim_matches(|character: char| "\"'`()[],;<>".contains(character));
        let Some((local, domain)) = token.rsplit_once('@') else {
            return false;
        };
        !local.is_empty()
            && domain.contains('.')
            && domain != "example.test"
            && !domain.ends_with(".example.test")
            && !domain.ends_with(".invalid")
    })
}

fn semantic_digest(corpus: &ValidatedCorpus) -> String {
    let mut writer = DigestWriter::new(DIGEST_DOMAIN);
    writer.field("schema", &corpus.manifest.schema);
    writer.field("corpus_id", &corpus.manifest.corpus_id);
    writer.number("revision", u64::from(corpus.manifest.revision));
    writer.field("title", &corpus.manifest.title);
    writer.field("summary", &corpus.manifest.summary);
    let mut cases = corpus.cases.iter().collect::<Vec<_>>();
    cases.sort_by(|left, right| {
        left.case
            .id
            .cmp(&right.case.id)
            .then(left.case.revision.cmp(&right.case.revision))
    });
    for loaded in cases {
        digest_case(&mut writer, &loaded.case, &corpus.body_digests);
    }
    format!("{DIGEST_PREFIX}:{}", writer.finish())
}

fn digest_case(writer: &mut DigestWriter, case: &FixtureCase, bodies: &BTreeMap<String, String>) {
    writer.field("case.id", &case.id);
    writer.number("case.revision", u64::from(case.revision));
    writer.field("case.category", case.category.wire());
    writer.field("case.purpose", &case.purpose);
    writer.field("case.provenance", case.provenance.wire());
    writer.field("case.support", case.support.wire());
    let mut tags = case.tags.iter().collect::<Vec<_>>();
    tags.sort_unstable();
    for tag in tags {
        writer.field("case.tag", tag);
    }
    writer.optional("case.parent", case.parent_case.as_deref());
    writer.optional("case.equivalent_to", case.equivalent_to.as_deref());
    writer.field("request.method", case.request.method.wire());
    writer.field("request.origin", &case.request.origin);
    writer.field("request.path", &case.request.path);
    writer.field("request.role", case.request.role.wire());
    writer.boolean("request.loopback", case.request.loopback_fixture);
    for query in &case.request.query {
        writer.field("request.query.name", &query.name);
        writer.field("request.query.value", &query.value);
    }
    digest_headers(writer, "request", &case.request.headers);
    writer.optional(
        "request.body.media_type",
        case.request.body_media_type.as_deref(),
    );
    digest_body(
        writer,
        "request.body",
        case.request.body_file.as_deref(),
        case.request.inline_body.as_deref(),
        bodies,
    );
    writer.number("response.status", u64::from(case.response.status));
    writer.field("response.media_type", &case.response.media_type);
    writer.field("response.role", case.response.role.wire());
    writer.field("response.completion", case.response.completion.wire());
    writer.boolean("response.truncated", case.response.truncated);
    digest_headers(writer, "response", &case.response.headers);
    digest_body(
        writer,
        "response.body",
        case.response.body_file.as_deref(),
        case.response.inline_body.as_deref(),
        bodies,
    );
    writer.optional_number(
        "response.control.status",
        case.response.control_status.map(u64::from),
    );
    digest_body(
        writer,
        "response.control.body",
        case.response.control_body_file.as_deref(),
        None,
        bodies,
    );
    writer.optional_number(
        "response.replay.status",
        case.response.replay_status.map(u64::from),
    );
    digest_body(
        writer,
        "response.replay.body",
        case.response.replay_body_file.as_deref(),
        None,
        bodies,
    );
    digest_body(
        writer,
        "response.source.body",
        case.response.source_body_file.as_deref(),
        None,
        bodies,
    );
    digest_authorization(writer, case.authorization.as_ref(), bodies);
    digest_ssrf_oast(writer, case.ssrf_oast.as_ref());
    digest_expected(writer, &case.expected);
}

fn digest_ssrf_oast(writer: &mut DigestWriter, fixture: Option<&SsrfOastFixture>) {
    let Some(fixture) = fixture else {
        writer.optional("ssrf_oast.source", None);
        return;
    };
    writer.optional("ssrf_oast.source", Some(fixture.source.wire()));
    writer.field("ssrf_oast.scenario", fixture.scenario.wire());
}

fn digest_authorization(
    writer: &mut DigestWriter,
    fixture: Option<&AuthorizationFixture>,
    bodies: &BTreeMap<String, String>,
) {
    let Some(fixture) = fixture else {
        writer.optional("authorization.resource", None);
        return;
    };
    writer.optional("authorization.resource", Some(&fixture.resource));
    writer.field("authorization.resource_handle", &fixture.resource_handle);
    writer.field("authorization.expectation", fixture.expectation.wire());
    writer.field("authorization.method", fixture.method.wire());
    let mut selected = fixture.comparison.selected_paths.iter().collect::<Vec<_>>();
    selected.sort_unstable();
    for path in selected {
        writer.field("authorization.comparison.selected", path);
    }
    let mut ignored = fixture.comparison.ignored_paths.iter().collect::<Vec<_>>();
    ignored.sort_unstable();
    for path in ignored {
        writer.field("authorization.comparison.ignored", path);
    }
    let mut unordered = fixture
        .comparison
        .unordered_array_paths
        .iter()
        .collect::<Vec<_>>();
    unordered.sort_unstable();
    for path in unordered {
        writer.field("authorization.comparison.unordered", path);
    }
    writer.number(
        "authorization.comparison.max_diff_paths",
        u64::from(fixture.comparison.max_diff_paths),
    );
    for (label, view) in [
        ("primary_candidate", &fixture.primary_candidate),
        ("peer_candidate", &fixture.peer_candidate),
        ("primary_replay", &fixture.primary_replay),
        ("peer_replay", &fixture.peer_replay),
    ] {
        writer.number(
            &format!("authorization.{label}.status"),
            u64::from(view.status),
        );
        writer.field(
            &format!("authorization.{label}.media_type"),
            &view.media_type,
        );
        writer.field(
            &format!("authorization.{label}.completion"),
            view.completion.wire(),
        );
        writer.boolean(&format!("authorization.{label}.truncated"), view.truncated);
        writer.field(&format!("authorization.{label}.state"), view.state.wire());
        digest_body(
            writer,
            &format!("authorization.{label}.body"),
            Some(&view.body_file),
            None,
            bodies,
        );
    }
}

fn digest_headers(writer: &mut DigestWriter, prefix: &str, headers: &[FixtureHeader]) {
    let mut headers = headers.iter().collect::<Vec<_>>();
    headers.sort_by_key(|header| header.name.to_ascii_lowercase());
    for header in headers {
        writer.field(
            &format!("{prefix}.header.name"),
            &header.name.to_ascii_lowercase(),
        );
        writer.field(&format!("{prefix}.header.value"), &header.value);
    }
}

fn digest_body(
    writer: &mut DigestWriter,
    label: &str,
    file: Option<&str>,
    inline: Option<&str>,
    bodies: &BTreeMap<String, String>,
) {
    let digest = file
        .and_then(|path| bodies.get(path).cloned())
        .or_else(|| inline.map(|value| sha256_hex(value.replace("\r\n", "\n").as_bytes())));
    writer.optional(label, digest.as_deref());
}

fn digest_expected(writer: &mut DigestWriter, expected: &ExpectedSemantics) {
    writer.optional(
        "expected.http_media",
        expected.http_media.map(|value| value.wire()),
    );
    writer.optional(
        "expected.defense_state",
        expected.defense_state.map(|value| value.wire()),
    );
    writer.optional(
        "expected.defense_transition",
        expected.defense_transition.map(|value| value.wire()),
    );
    writer.optional(
        "expected.reflection_context",
        expected.reflection_context.map(|value| value.wire()),
    );
    writer.optional(
        "expected.html_quote_mode",
        expected.html_quote_mode.map(|value| value.wire()),
    );
    writer.optional(
        "expected.javascript_context",
        expected.javascript_context.map(|value| value.wire()),
    );
    writer.optional(
        "expected.sql_relation",
        expected.sql_relation.map(|value| value.wire()),
    );
    writer.optional(
        "expected.ssti_relation",
        expected.ssti_relation.map(|value| value.wire()),
    );
    writer.optional(
        "expected.xss_relation",
        expected.xss_relation.map(|value| value.wire()),
    );
    writer.optional(
        "expected.normalization_outcome",
        expected.normalization_outcome.map(|value| value.wire()),
    );
    writer.optional(
        "expected.graphql_evidence",
        expected.graphql_evidence.map(|value| value.wire()),
    );
    writer.optional(
        "expected.openapi_outcome",
        expected.openapi_outcome.map(|value| value.wire()),
    );
    writer.optional(
        "expected.openapi_version",
        expected.openapi_version.map(|value| value.wire()),
    );
    writer.optional_number(
        "expected.openapi_path_count",
        expected.openapi_path_count.map(u64::from),
    );
    writer.optional_number(
        "expected.openapi_operation_count",
        expected.openapi_operation_count.map(u64::from),
    );
    let mut parameter_locations = expected
        .openapi_required_parameter_locations
        .iter()
        .map(|value| value.wire())
        .collect::<Vec<_>>();
    parameter_locations.sort_unstable();
    for value in parameter_locations {
        writer.field("expected.openapi_required_parameter_location", value);
    }
    let mut security_schemes = expected
        .openapi_required_security_schemes
        .iter()
        .map(|value| value.wire())
        .collect::<Vec<_>>();
    security_schemes.sort_unstable();
    for value in security_schemes {
        writer.field("expected.openapi_required_security_scheme", value);
    }
    let mut effective_security = expected
        .openapi_required_effective_security_schemes
        .iter()
        .map(|value| value.wire())
        .collect::<Vec<_>>();
    effective_security.sort_unstable();
    for value in effective_security {
        writer.field("expected.openapi_required_effective_security_scheme", value);
    }
    let mut server_kinds = expected
        .openapi_required_server_kinds
        .iter()
        .map(|value| value.wire())
        .collect::<Vec<_>>();
    server_kinds.sort_unstable();
    for value in server_kinds {
        writer.field("expected.openapi_required_server_kind", value);
    }
    let mut candidate_tags = expected
        .openapi_required_candidate_tags
        .iter()
        .map(|value| value.wire())
        .collect::<Vec<_>>();
    candidate_tags.sort_unstable();
    for value in candidate_tags {
        writer.field("expected.openapi_required_candidate_tag", value);
    }
    writer.optional(
        "expected.openapi_digest_matches",
        expected.openapi_digest_matches.as_deref(),
    );
    writer.optional(
        "expected.openapi_generated_input",
        expected.openapi_generated_input.map(|value| value.wire()),
    );
    writer.optional(
        "expected.authorization_outcome",
        expected.authorization_outcome.map(|value| value.wire()),
    );
    writer.optional(
        "expected.ssrf_oast_outcome",
        expected.ssrf_oast_outcome.map(|value| value.wire()),
    );
    writer.optional(
        "expected.assessment_capability",
        expected.assessment_capability.as_deref(),
    );
    writer.optional(
        "expected.maximum_disposition",
        expected.maximum_disposition.map(|value| value.wire()),
    );
    writer.optional(
        "expected.maximum_authority",
        expected.maximum_authority.map(|value| value.wire()),
    );
    writer.optional(
        "expected.incompleteness",
        expected.incompleteness.map(|value| value.wire()),
    );
}

fn case_semantic_fingerprint(
    case: &FixtureCase,
    body_digests: &BTreeMap<String, String>,
) -> String {
    let mut writer = DigestWriter::new("security-assessment-fixture-semantics/v1");
    writer.field("category", case.category.wire());
    writer.field("support", case.support.wire());
    writer.field("request.method", case.request.method.wire());
    writer.field("request.origin", &case.request.origin);
    writer.field("request.path", &case.request.path);
    writer.field("request.role", case.request.role.wire());
    writer.boolean("request.loopback", case.request.loopback_fixture);
    for query in &case.request.query {
        writer.field("query.name", &query.name);
        writer.field("query.value", &query.value);
    }
    digest_headers(&mut writer, "request", &case.request.headers);
    writer.optional(
        "request.body-media-type",
        case.request.body_media_type.as_deref(),
    );
    digest_body(
        &mut writer,
        "request.body",
        case.request.body_file.as_deref(),
        case.request.inline_body.as_deref(),
        body_digests,
    );
    writer.number("response.status", u64::from(case.response.status));
    writer.field("response.media_type", &case.response.media_type);
    writer.field("response.role", case.response.role.wire());
    writer.field("response.completion", case.response.completion.wire());
    writer.boolean("response.truncated", case.response.truncated);
    digest_headers(&mut writer, "response", &case.response.headers);
    digest_body(
        &mut writer,
        "response.body",
        case.response.body_file.as_deref(),
        case.response.inline_body.as_deref(),
        body_digests,
    );
    writer.optional_number(
        "response.control.status",
        case.response.control_status.map(u64::from),
    );
    digest_body(
        &mut writer,
        "response.control.body",
        case.response.control_body_file.as_deref(),
        None,
        body_digests,
    );
    writer.optional_number(
        "response.replay.status",
        case.response.replay_status.map(u64::from),
    );
    digest_body(
        &mut writer,
        "response.replay.body",
        case.response.replay_body_file.as_deref(),
        None,
        body_digests,
    );
    digest_body(
        &mut writer,
        "response.source.body",
        case.response.source_body_file.as_deref(),
        None,
        body_digests,
    );
    digest_authorization(&mut writer, case.authorization.as_ref(), body_digests);
    digest_ssrf_oast(&mut writer, case.ssrf_oast.as_ref());
    digest_expected(&mut writer, &case.expected);
    writer.finish()
}

fn render_inventory(corpus: &ValidatedCorpus) -> String {
    let mut output = String::new();
    output.push_str("# Scanner conformance corpus inventory\n\n");
    output.push_str(
        "This file is generated by `cargo run --locked -p xtask -- scanner-corpus --write`.\n\n",
    );
    output.push_str("| Field | Value |\n| --- | --- |\n");
    output.push_str(&format!("| Schema | `{}` |\n", corpus.manifest.schema));
    output.push_str(&format!("| Corpus | `{}` |\n", corpus.manifest.corpus_id));
    output.push_str(&format!("| Revision | {} |\n", corpus.manifest.revision));
    output.push_str(&format!("| Cases | {} |\n", corpus.cases.len()));
    output.push_str(&format!(
        "| Semantic digest | `{}` |\n",
        corpus.semantic_digest
    ));

    let mut categories = BTreeMap::<&str, (usize, usize, usize)>::new();
    for loaded in &corpus.cases {
        let counts = categories.entry(loaded.case.category.wire()).or_default();
        counts.0 += 1;
        if loaded.case.support == SupportLevel::Current {
            counts.1 += 1;
        } else {
            counts.2 += 1;
        }
    }
    output.push_str("\n## Categories\n\n| Category | Cases | Current | Metadata only |\n| --- | ---: | ---: | ---: |\n");
    for (category, (total, current, metadata)) in categories {
        output.push_str(&format!(
            "| `{category}` | {total} | {current} | {metadata} |\n"
        ));
    }

    output.push_str("\n## Cases\n\n| Case | Revision | Category | Provenance | Support | Role |\n| --- | ---: | --- | --- | --- | --- |\n");
    let mut cases = corpus.cases.iter().collect::<Vec<_>>();
    cases.sort_by_key(|loaded| (&loaded.case.id, loaded.case.revision));
    for loaded in cases {
        let case = &loaded.case;
        output.push_str(&format!(
            "| `{}` | {} | `{}` | `{}` | `{}` | `{}` |\n",
            case.id,
            case.revision,
            case.category.wire(),
            case.provenance.wire(),
            case.support.wire(),
            case.request.role.wire()
        ));
    }
    output
}

fn validate_digest_wire(value: &str) -> TaskResult {
    let Some(hex) = value.strip_prefix(&format!("{DIGEST_PREFIX}:")) else {
        return Err("corpus digest has an invalid prefix".into());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("corpus digest must contain 64 lowercase hexadecimal digits".into());
    }
    Ok(())
}

fn rewrite_digest(path: &Path, source: &[u8], digest: &str) -> TaskResult {
    validate_digest_wire(digest)?;
    let source = std::str::from_utf8(source).map_err(|_| "corpus manifest must be UTF-8")?;
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut assignments = 0;
    let mut rewritten = String::new();
    for line in source.lines() {
        if line.trim_start().starts_with("corpus_digest =") {
            assignments += 1;
            rewritten.push_str(&format!("corpus_digest = \"{digest}\"{newline}"));
        } else {
            rewritten.push_str(line);
            rewritten.push_str(newline);
        }
    }
    if assignments != 1 {
        return Err("corpus manifest must contain exactly one corpus_digest assignment".into());
    }
    fs::write(path, rewritten)?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> TaskResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((maximum as u64) + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("corpus file exceeds its compiled byte limit".into());
    }
    Ok(bytes)
}

fn bounded_parse_error(label: &str, _error: &toml::de::Error) -> String {
    format!("{label} failed strict TOML parsing")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct DigestWriter(Sha256);

impl DigestWriter {
    fn new(domain: &str) -> Self {
        let mut writer = Self(Sha256::new());
        writer.field("domain", domain);
        writer
    }

    fn field(&mut self, label: &str, value: &str) {
        self.0.update((label.len() as u64).to_be_bytes());
        self.0.update(label.as_bytes());
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value.as_bytes());
    }

    fn optional(&mut self, label: &str, value: Option<&str>) {
        self.field(
            &format!("{label}.present"),
            if value.is_some() { "1" } else { "0" },
        );
        if let Some(value) = value {
            self.field(label, value);
        }
    }

    fn number(&mut self, label: &str, value: u64) {
        self.field(label, &value.to_string());
    }

    fn optional_number(&mut self, label: &str, value: Option<u64>) {
        let rendered = value.map(|value| value.to_string());
        self.optional(label, rendered.as_deref());
    }

    fn boolean(&mut self, label: &str, value: bool) {
        self.field(label, if value { "true" } else { "false" });
    }

    fn finish(self) -> String {
        self.0
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const ZERO_DIGEST: &str =
        "corpus-sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn repository_root(directory: &TempDir) -> &Path {
        directory.path()
    }

    fn data_root(directory: &TempDir) -> PathBuf {
        directory.path().join(CORPUS_ROOT)
    }

    fn case_path(directory: &TempDir, id: &str) -> PathBuf {
        data_root(directory).join(format!("cases/{id}.toml"))
    }

    fn body_path(directory: &TempDir, name: &str) -> PathBuf {
        data_root(directory).join(format!("bodies/{name}"))
    }

    fn manifest_source(case_files: &[&str]) -> String {
        let case_files = case_files
            .iter()
            .map(|path| format!("\"{path}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "schema = \"{MANIFEST_SCHEMA}\"\n\
             corpus_id = \"web-assessment-v1\"\n\
             revision = 1\n\
             title = \"Scanner conformance corpus\"\n\
             summary = \"Sanitized deterministic request and response fixtures.\"\n\
             corpus_digest = \"{ZERO_DIGEST}\"\n\
             case_files = [{case_files}]\n"
        )
    }

    fn case_source(id: &str, body: &str) -> String {
        format!(
            "schema = \"{CASE_SCHEMA}\"\n\
             id = \"{id}\"\n\
             revision = 1\n\
             category = \"http-media\"\n\
             purpose = \"Exercise bounded JSON media observation.\"\n\
             provenance = \"current-authored\"\n\
             support = \"current\"\n\
             tags = [\"json\", \"positive\"]\n\n\
             [request]\n\
             method = \"get\"\n\
             origin = \"https://example.test\"\n\
             path = \"/fixture\"\n\
             role = \"control\"\n\n\
             [response]\n\
             status = 200\n\
             media_type = \"application/json\"\n\
             role = \"control\"\n\
             completion = \"complete\"\n\
             truncated = false\n\
             body_file = \"bodies/{body}\"\n\n\
             [expected]\n\
             http_media = \"json\"\n\
             maximum_disposition = \"informational\"\n\
             maximum_authority = \"knowledge-only\"\n"
        )
    }

    fn create_corpus(cases: &[(&str, &str, &str)]) -> TempDir {
        let directory = tempfile::tempdir().expect("temp corpus");
        let root = data_root(&directory);
        fs::create_dir_all(root.join("cases")).expect("case directory");
        fs::create_dir_all(root.join("bodies")).expect("body directory");
        fs::write(root.join("README.md"), "# Sanitized scanner fixtures\n").expect("README");
        fs::write(root.join("INVENTORY.md"), "pending generation\n").expect("inventory");
        let paths = cases
            .iter()
            .map(|(id, _, _)| format!("cases/{id}.toml"))
            .collect::<Vec<_>>();
        let path_refs = paths.iter().map(String::as_str).collect::<Vec<_>>();
        fs::write(root.join("manifest.toml"), manifest_source(&path_refs)).expect("manifest");
        for (id, body_name, body) in cases {
            fs::write(
                root.join(format!("cases/{id}.toml")),
                case_source(id, body_name),
            )
            .expect("case");
            fs::write(root.join(format!("bodies/{body_name}")), body).expect("body");
        }
        directory
    }

    fn create_one() -> TempDir {
        create_corpus(&[(
            "http-json-control",
            "http-json-control.json",
            "{\"ok\":true}\n",
        )])
    }

    fn initialize(directory: &TempDir) {
        run(repository_root(directory), true).expect("write checked corpus outputs");
    }

    fn valid_case(id: &str) -> FixtureCase {
        FixtureCase {
            schema: CASE_SCHEMA.to_owned(),
            id: id.to_owned(),
            revision: 1,
            category: CaseCategory::HttpMedia,
            purpose: "Exercise one deterministic semantic relation.".to_owned(),
            provenance: Provenance::CurrentAuthored,
            support: SupportLevel::Current,
            tags: vec!["positive".to_owned()],
            parent_case: None,
            equivalent_to: None,
            request: FixtureRequest {
                method: HttpMethod::Get,
                origin: "https://example.test".to_owned(),
                path: "/fixture".to_owned(),
                role: ExchangeRole::Control,
                loopback_fixture: false,
                query: Vec::new(),
                headers: Vec::new(),
                body_media_type: None,
                body_file: None,
                inline_body: None,
            },
            response: FixtureResponse {
                status: 200,
                media_type: "application/json".to_owned(),
                role: ExchangeRole::Control,
                completion: CompletionState::Complete,
                truncated: false,
                headers: Vec::new(),
                body_file: None,
                inline_body: Some("{\"ok\":true}".to_owned()),
                control_status: None,
                control_body_file: None,
                replay_status: None,
                replay_body_file: None,
                source_body_file: None,
            },
            authorization: None,
            ssrf_oast: None,
            expected: ExpectedSemantics {
                http_media: Some(HttpMediaExpectation::Json),
                maximum_disposition: Some(DispositionExpectation::Informational),
                maximum_authority: Some(MaximumAuthorityExpectation::KnowledgeOnly),
                ..ExpectedSemantics::default()
            },
        }
    }

    fn valid_authorization_case(id: &str) -> FixtureCase {
        let view = AuthorizationViewFixture {
            status: 200,
            media_type: "application/json".to_owned(),
            completion: CompletionState::Complete,
            truncated: false,
            state: AuthorizationBodyState::CompleteJson,
            body_file: "bodies/authorization-primary.json".to_owned(),
        };
        let mut case = valid_case(id);
        case.category = CaseCategory::Authorization;
        case.request.path = "/api/accounts/42".to_owned();
        case.request.role = ExchangeRole::Bootstrap;
        case.response.role = ExchangeRole::Bootstrap;
        case.expected.http_media = None;
        case.expected.authorization_outcome =
            Some(AuthorizationOutcomeExpectation::StableCrossPrincipalEquivalence);
        case.expected.assessment_capability =
            Some("authorization.resource-cross-principal-equivalence".to_owned());
        case.expected.maximum_disposition = Some(DispositionExpectation::NeedsReview);
        case.authorization = Some(AuthorizationFixture {
            resource: "/api/accounts/42".to_owned(),
            resource_handle: "account-self-profile".to_owned(),
            expectation: AuthorizationPolicyExpectation::PrimaryOnly,
            method: AuthorizationMethod::Get,
            comparison: AuthorizationComparisonFixture {
                selected_paths: vec!["/data/account".to_owned()],
                ignored_paths: vec!["/data/account/updated_at".to_owned()],
                unordered_array_paths: Vec::new(),
                max_diff_paths: 16,
            },
            primary_candidate: view.clone(),
            peer_candidate: view.clone(),
            primary_replay: view.clone(),
            peer_replay: view,
        });
        case
    }

    fn valid_openapi_case(id: &str) -> FixtureCase {
        let mut case = valid_case(id);
        case.category = CaseCategory::ApiOpenapi;
        case.request.role = ExchangeRole::Bootstrap;
        case.response.role = ExchangeRole::Bootstrap;
        case.response.inline_body =
            Some(r#"{"openapi":"3.1.0","paths":{"/items":{"get":{"responses":{}}}}}"#.to_owned());
        case.expected = ExpectedSemantics {
            openapi_outcome: Some(OpenApiExpectation::Document),
            openapi_version: Some(OpenApiVersionExpectation::OpenApi31),
            openapi_path_count: Some(1),
            openapi_operation_count: Some(1),
            ..ExpectedSemantics::default()
        };
        case
    }

    fn valid_ssrf_oast_case(id: &str) -> FixtureCase {
        let mut case = valid_case(id);
        case.category = CaseCategory::SsrfOast;
        case.request.role = ExchangeRole::Bootstrap;
        case.response.role = ExchangeRole::Bootstrap;
        case.request.query = vec![QueryParameter {
            name: "next".to_owned(),
            value: "https://upstream.example.test/resource".to_owned(),
        }];
        case.ssrf_oast = Some(SsrfOastFixture {
            source: SsrfOastCandidateSourceExpectation::ObservedUrlQuery,
            scenario: SsrfOastScenario::RepeatedCallbacksObserved,
        });
        case.expected = ExpectedSemantics {
            ssrf_oast_outcome: Some(SsrfOastOutcomeExpectation::RepeatedCallbacksObserved),
            assessment_capability: Some("ssrf.oast-repeated-outbound-interaction@1".to_owned()),
            maximum_disposition: Some(DispositionExpectation::NeedsReview),
            maximum_authority: Some(MaximumAuthorityExpectation::KnowledgeOnly),
            ..ExpectedSemantics::default()
        };
        case
    }

    fn validated(cases: Vec<FixtureCase>) -> ValidatedCorpus {
        ValidatedCorpus {
            manifest_source: Vec::new(),
            manifest: CorpusManifest {
                schema: MANIFEST_SCHEMA.to_owned(),
                corpus_id: "web-assessment-v1".to_owned(),
                revision: 1,
                title: "Scanner conformance corpus".to_owned(),
                summary: "Sanitized deterministic fixtures.".to_owned(),
                corpus_digest: ZERO_DIGEST.to_owned(),
                case_files: cases
                    .iter()
                    .map(|case| format!("cases/{}.toml", case.id))
                    .collect(),
            },
            cases: cases.into_iter().map(|case| LoadedCase { case }).collect(),
            body_digests: BTreeMap::new(),
            semantic_digest: String::new(),
        }
    }

    fn assert_error_contains(result: TaskResult<impl Sized>, needle: &str) {
        let error = match result {
            Ok(_) => panic!("validation should fail"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(needle), "unexpected error: {error}");
    }

    #[test]
    fn valid_gitless_corpus_writes_and_checks() {
        let directory = create_one();
        assert!(!directory.path().join(".git").exists());
        initialize(&directory);
        run(repository_root(&directory), false).expect("checked corpus");
    }

    #[test]
    fn write_mode_repairs_digest_and_inventory() {
        let directory = create_one();
        initialize(&directory);
        let manifest =
            fs::read_to_string(data_root(&directory).join("manifest.toml")).expect("manifest");
        assert!(!manifest.contains(ZERO_DIGEST));
        let inventory =
            fs::read_to_string(data_root(&directory).join("INVENTORY.md")).expect("inventory");
        assert!(inventory.contains("Scanner conformance corpus inventory"));
        assert!(inventory.contains("http-json-control"));
    }

    #[test]
    fn checked_in_repository_corpus_validates_when_present() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        if root.join(MANIFEST_PATH).is_file() {
            run(root, false).expect("checked-in corpus");
        }
    }

    #[test]
    fn checked_in_openapi_cases_parse_with_the_strict_fixture_schema() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join(CORPUS_ROOT)
            .join("cases");
        if !root.is_dir() {
            return;
        }
        let mut paths = fs::read_dir(root)
            .expect("case directory")
            .map(|entry| entry.expect("case entry").path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("openapi.") && name.ends_with(".toml"))
            })
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(paths.len(), 30, "OpenAPI V1 corpus matrix changed");
        for path in paths {
            let source = fs::read_to_string(&path).expect("OpenAPI fixture source");
            toml::from_str::<FixtureCase>(&source).unwrap_or_else(|error| {
                panic!("{} failed strict parsing: {error}", path.display())
            });
        }
    }

    #[test]
    fn unknown_manifest_schema_is_rejected() {
        let directory = create_one();
        let path = data_root(&directory).join("manifest.toml");
        let source = fs::read_to_string(&path)
            .expect("manifest")
            .replace(MANIFEST_SCHEMA, "security-assessment-corpus/v2");
        fs::write(path, source).expect("manifest mutation");
        assert_error_contains(load_and_validate(repository_root(&directory)), "schema");
    }

    #[test]
    fn unknown_case_schema_is_rejected() {
        let directory = create_one();
        let path = case_path(&directory, "http-json-control");
        let source = fs::read_to_string(&path)
            .expect("case")
            .replace(CASE_SCHEMA, "security-assessment-fixture/v2");
        fs::write(path, source).expect("case mutation");
        assert_error_contains(load_and_validate(repository_root(&directory)), "schema");
    }

    #[test]
    fn unknown_case_field_is_rejected() {
        let directory = create_one();
        let path = case_path(&directory, "http-json-control");
        let mut source = fs::read_to_string(&path).expect("case");
        source.push_str("unknown_contract = true\n");
        fs::write(path, source).expect("case mutation");
        assert_error_contains(
            load_and_validate(repository_root(&directory)),
            "strict TOML",
        );
    }

    #[test]
    fn crlf_text_has_the_same_canonical_form() {
        let lf = canonical_text(b"first\nsecond\n", "fixture").expect("LF");
        let crlf = canonical_text(b"first\r\nsecond\r\n", "fixture").expect("CRLF");
        assert_eq!(lf, crlf);
    }

    #[test]
    fn lone_carriage_return_is_rejected() {
        assert_error_contains(canonical_text(b"first\rsecond", "fixture"), "lone carriage");
    }

    #[test]
    fn bounded_reader_stops_at_limit_plus_one() {
        let directory = tempfile::tempdir().expect("temp");
        let path = directory.path().join("large.txt");
        fs::write(&path, [b'x'; 9]).expect("large file");
        assert_error_contains(read_bounded(&path, 8), "compiled byte limit");
    }

    #[test]
    fn malformed_identity_is_rejected() {
        assert_error_contains(validate_id("../case", "case id"), "closed ASCII");
        assert_error_contains(validate_id("-case", "case id"), "forbidden identity");
    }

    #[test]
    fn duplicate_tags_are_rejected() {
        assert_error_contains(
            validate_tags(&["json".to_owned(), "json".to_owned()]),
            "unique",
        );
    }

    #[test]
    fn reserved_test_origins_are_accepted() {
        validate_origin("https://example.test", false).expect("reserved root");
        validate_origin("https://api.example.test:8443", false).expect("reserved subdomain");
        validate_origin("http://fixture.invalid", false).expect("invalid TLD");
    }

    #[test]
    fn real_external_origin_is_rejected() {
        assert_error_contains(
            validate_origin("https://production.example.com", false),
            "reserved test domain",
        );
    }

    #[test]
    fn credential_bearing_origin_is_rejected() {
        assert_error_contains(
            validate_origin("https://user:password@example.test", false),
            "credential-free",
        );
    }

    #[test]
    fn loopback_origin_requires_explicit_fixture_contract() {
        assert_error_contains(
            validate_origin("http://127.0.0.1:8080", false),
            "loopback_fixture",
        );
        validate_origin("http://127.0.0.1:8080", true).expect("explicit loopback");
    }

    #[test]
    fn non_loopback_numeric_origins_are_always_rejected() {
        for origin in ["https://8.8.8.8", "https://[2001:4860:4860::8888]"] {
            assert_error_contains(
                validate_origin(origin, false),
                "limited to explicit loopback",
            );
            assert_error_contains(
                validate_origin(origin, true),
                "limited to explicit loopback",
            );
        }
    }

    #[test]
    fn canonical_request_path_rejects_traversal_and_query() {
        assert_error_contains(validate_request_path("/../secret"), "canonical");
        assert_error_contains(validate_request_path("/fixture?x=1"), "canonical");
        validate_request_path("/safe/fixture").expect("canonical path");
    }

    #[test]
    fn query_values_cannot_change_request_shape() {
        let mut case = valid_case("query-shape");
        case.request.query.push(QueryParameter {
            name: "selected".to_owned(),
            value: "one&second=two".to_owned(),
        });
        assert_error_contains(validate_request(&case.request), "request shape");
    }

    #[test]
    fn duplicate_query_names_are_rejected_case_insensitively() {
        let mut case = valid_case("query-duplicate");
        case.request.query = vec![
            QueryParameter {
                name: "Selected".to_owned(),
                value: "one".to_owned(),
            },
            QueryParameter {
                name: "selected".to_owned(),
                value: "two".to_owned(),
            },
        ];
        assert_error_contains(validate_request(&case.request), "unique");
    }

    #[test]
    fn control_leg_status_and_body_are_atomic() {
        let mut case = valid_case("orphan-control-leg");
        case.response.control_status = Some(200);
        assert_error_contains(validate_response(&case.response), "status and body");

        case.response.control_status = None;
        case.response.control_body_file = Some("bodies/control.json".to_owned());
        assert_error_contains(validate_response(&case.response), "status and body");
    }

    #[test]
    fn replay_leg_status_and_body_are_atomic() {
        let mut case = valid_case("orphan-replay-leg");
        case.response.replay_status = Some(200);
        assert_error_contains(validate_response(&case.response), "status and body");

        case.response.replay_status = None;
        case.response.replay_body_file = Some("bodies/replay.json".to_owned());
        assert_error_contains(validate_response(&case.response), "status and body");
    }

    #[test]
    fn paired_semantic_case_cannot_fall_back_to_candidate_body() {
        let mut case = valid_case("ssti-explicit-pair");
        case.category = CaseCategory::Ssti;
        case.expected.http_media = None;
        case.expected.ssti_relation = Some(StructuralRelationExpectation::NotMatched);
        assert_error_contains(
            validate_case("cases/ssti-explicit-pair.toml", &case),
            "explicit control and replay legs",
        );
    }

    #[test]
    fn xss_semantic_case_requires_explicit_control_and_source() {
        let mut case = valid_case("xss-explicit-source");
        case.category = CaseCategory::Xss;
        case.expected.http_media = None;
        case.expected.xss_relation = Some(StructuralRelationExpectation::NotMatched);
        assert_error_contains(
            validate_case("cases/xss-explicit-source.toml", &case),
            "explicit control leg",
        );

        case.response.control_status = Some(200);
        case.response.control_body_file = Some("bodies/control.html".to_owned());
        assert_error_contains(
            validate_case("cases/xss-explicit-source.toml", &case),
            "source-context body",
        );
    }

    #[test]
    fn request_header_allowlist_is_closed() {
        let headers = vec![FixtureHeader {
            name: "authorization".to_owned(),
            value: "redacted".to_owned(),
        }];
        assert_error_contains(
            validate_headers(&headers, REQUEST_HEADER_ALLOWLIST),
            "closed allowlist",
        );
    }

    #[test]
    fn bearer_assignment_is_rejected_without_literal_fixture_secret() {
        let value = ["author", "ization: be", "arer scanner-token"].concat();
        assert_error_contains(
            validate_safe_fixture_bytes(value.as_bytes()),
            "safety policy",
        );
    }

    #[test]
    fn quoted_secret_assignments_are_rejected() {
        for value in [
            [r#"{"authoriz"#, r#"ation":"Bearer opaque-value"}"#].concat(),
            [r#"authoriz"#, r#"ation = "Basic opaque-value""#].concat(),
            [r#"{"coo"#, r#"kie":"session=opaque-value"}"#].concat(),
            [r#"{"api_"#, r#"key":"opaque-value"}"#].concat(),
        ] {
            assert_error_contains(
                validate_safe_fixture_bytes(value.as_bytes()),
                "safety policy",
            );
        }
    }

    #[test]
    fn explicit_redaction_sentinel_is_rejected() {
        assert_error_contains(
            validate_safe_fixture_bytes(REDACTION_SENTINEL.as_bytes()),
            "safety policy",
        );
    }

    #[test]
    fn escaped_fixture_sentinel_and_credential_url_are_rejected_after_decoding() {
        assert_error_contains(
            validate_safe_fixture_bytes(
                br#"{"value":"\u0043ORPUS-MUST-NOT-CONTAIN-SECRET-7B39F1"}"#,
            ),
            "safety policy",
        );
        assert_error_contains(
            validate_safe_fixture_bytes(
                br#"{"endpoint":"https\u003a\u002f\u002fuser\u003apass\u0040example.test"}"#,
            ),
            "safety policy",
        );
    }

    #[test]
    fn toml_escaped_sentinel_is_rejected_after_decoding() {
        let escaped = case_source("http-json-control", "http-json-control.json").replace(
            "Exercise bounded JSON media observation.",
            "\\u0043ORPUS-MUST-NOT-CONTAIN-SECRET-7B39F1",
        );
        assert!(!escaped.contains(REDACTION_SENTINEL));
        let parsed: FixtureCase = toml::from_str(&escaped).expect("escaped fixture parses");
        assert_eq!(parsed.purpose, REDACTION_SENTINEL);
        assert_error_contains(
            validate_case("cases/http-json-control.toml", &parsed),
            "secret/safety policy",
        );
    }

    #[test]
    fn jwt_shaped_value_is_rejected_without_literal_fixture_secret() {
        let value = ["eyJheaderpart", "eyJpayloadpart", "signaturepart"].join(".");
        assert_error_contains(
            validate_safe_fixture_bytes(value.as_bytes()),
            "safety policy",
        );
    }

    #[test]
    fn private_key_marker_is_rejected_without_embedding_key_material() {
        for kind in ["", "ENCRYPTED ", "RSA ", "DSA ", "EC ", "OPENSSH "] {
            let value = ["-----BEGIN ", kind, "PRIVATE KEY", "-----"].concat();
            assert_error_contains(
                validate_safe_fixture_bytes(value.as_bytes()),
                "safety policy",
            );
        }
    }

    #[test]
    fn unsafe_cookie_assignment_is_rejected() {
        let value = ["coo", "kie: session-value"].concat();
        assert_error_contains(
            validate_safe_fixture_bytes(value.as_bytes()),
            "safety policy",
        );
    }

    #[test]
    fn credential_url_and_non_reserved_email_are_rejected() {
        let credential_url = ["https://", "user:pass", "@example.test/path"].concat();
        assert_error_contains(
            validate_safe_fixture_bytes(credential_url.as_bytes()),
            "safety policy",
        );
        let email = ["analyst@", "external.example"].concat();
        assert_error_contains(
            validate_safe_fixture_bytes(email.as_bytes()),
            "safety policy",
        );
    }

    #[test]
    fn reserved_example_email_and_inert_canary_are_accepted() {
        validate_safe_fixture_bytes(b"analyst@example.test TERMIVAR-INERT-CANARY")
            .expect("safe example fixture");
    }

    #[test]
    fn fixture_material_rejects_external_urls_domains_and_numeric_ips() {
        for material in [
            r#"{"endpoint":"https://production.example.com/review"}"#,
            r#"{"endpoint":"https://user:pass@example.test/review"}"#,
        ] {
            assert_error_contains(
                validate_safe_fixture_material(material.as_bytes(), false),
                "safety policy",
            );
        }
        for material in [
            "upstream production.example.com responded",
            "observed 203.0.113.9",
            "observed 2001:db8::5",
        ] {
            assert_error_contains(
                validate_safe_fixture_material(material.as_bytes(), false),
                "non-reserved",
            );
        }
        assert_error_contains(
            validate_safe_fixture_material(b"loopback 127.0.0.1", false),
            "non-reserved",
        );
        assert_error_contains(
            validate_safe_fixture_material(b"loopback 127.0.0.1:8080", false),
            "non-reserved",
        );
        assert_error_contains(
            validate_safe_fixture_material(b"localhost", true),
            "non-reserved",
        );
        validate_safe_fixture_material(
            br#"{"endpoint":"https://api.example.test/review","peer":"127.0.0.1:8080","peer_v6":"[::1]:8080"}"#,
            true,
        )
        .expect("explicit loopback material remains valid");
    }

    #[test]
    fn body_loopback_identity_requires_an_explicit_loopback_fixture() {
        let directory = create_one();
        fs::write(
            body_path(&directory, "http-json-control.json"),
            "{\"peer\":\"127.0.0.1\"}\n",
        )
        .expect("loopback body");
        assert_error_contains(
            load_and_validate(repository_root(&directory)),
            "non-reserved",
        );

        let path = case_path(&directory, "http-json-control");
        let source = fs::read_to_string(&path)
            .expect("case")
            .replace(
                "origin = \"https://example.test\"",
                "origin = \"http://127.0.0.1\"",
            )
            .replacen(
                "role = \"control\"",
                "role = \"control\"\nloopback_fixture = true",
                1,
            );
        fs::write(path, source).expect("explicit loopback case");
        load_and_validate(repository_root(&directory))
            .expect("explicit loopback fixture may reference loopback body material");
    }

    #[test]
    fn executable_body_magic_is_rejected() {
        assert_error_contains(reject_executable_bytes(b"MZnot-an-artifact"), "executable");
        assert_error_contains(reject_executable_bytes(b"#!/bin/fixture"), "executable");
    }

    #[test]
    fn body_reference_must_be_relative_and_under_bodies() {
        assert_error_contains(
            validate_body_pair(Some("../outside.json"), None),
            "canonical repository-relative",
        );
        assert_error_contains(
            validate_body_pair(Some("cases/not-a-body.json"), None),
            "under bodies",
        );
    }

    #[test]
    fn request_body_media_type_and_content_are_atomic() {
        assert_error_contains(
            validate_body_contract(Some("application/json"), None, None),
            "appear together",
        );
        assert_error_contains(
            validate_body_contract(None, None, Some("{}")),
            "appear together",
        );
    }

    #[test]
    fn response_status_must_be_in_http_range() {
        let mut case = valid_case("bad-status");
        case.response.status = 99;
        assert_error_contains(validate_response(&case.response), "HTTP range");
    }

    #[test]
    fn truncated_response_cannot_be_complete() {
        let mut case = valid_case("truncated-complete");
        case.response.truncated = true;
        assert_error_contains(validate_response(&case.response), "cannot declare complete");
        case.response.completion = CompletionState::Incomplete;
        validate_response(&case.response).expect("typed incomplete response");
    }

    #[test]
    fn empty_semantic_expectation_is_rejected() {
        assert_error_contains(
            validate_expected(&ExpectedSemantics::default()),
            "at least one typed",
        );
    }

    #[test]
    fn knowledge_only_authority_cannot_claim_confirmed_disposition() {
        let mut expected = ExpectedSemantics {
            maximum_disposition: Some(DispositionExpectation::Confirmed),
            maximum_authority: Some(MaximumAuthorityExpectation::KnowledgeOnly),
            ..ExpectedSemantics::default()
        };
        assert_error_contains(validate_expected(&expected), "verifier-authorized");

        expected.maximum_disposition = Some(DispositionExpectation::NeedsReview);
        validate_expected(&expected).expect("knowledge-only review remains valid");

        expected.maximum_disposition = Some(DispositionExpectation::Confirmed);
        expected.maximum_authority = Some(MaximumAuthorityExpectation::VerifierAuthorized);
        validate_expected(&expected).expect("verifier-authorized confirmation remains typed");
    }

    #[test]
    fn metadata_only_case_requires_explicit_future_incompleteness() {
        let mut case = valid_case("future-case");
        case.support = SupportLevel::MetadataOnly;
        assert_error_contains(
            validate_case("cases/future-case.toml", &case),
            "future-metadata-only",
        );
        case.expected.incompleteness = Some(IncompletenessExpectation::FutureMetadataOnly);
        validate_case("cases/future-case.toml", &case).expect("metadata-only contract");
    }

    #[test]
    fn graphql_v1_support_contract_keeps_only_batch_and_get_metadata_only() {
        let mut case = valid_case("graphql-current");
        case.category = CaseCategory::ApiGraphql;
        case.expected.http_media = None;
        case.expected.graphql_evidence = Some(GraphqlExpectation::TypenameControl);
        case.expected.maximum_authority = Some(MaximumAuthorityExpectation::KnowledgeOnly);
        validate_graphql_support_contract(&case).expect("bounded GraphQL control is current");

        case.support = SupportLevel::MetadataOnly;
        case.expected.incompleteness = Some(IncompletenessExpectation::FutureMetadataOnly);
        assert!(validate_graphql_support_contract(&case).is_err());

        case.expected.graphql_evidence = Some(GraphqlExpectation::BatchMetadataOnly);
        validate_graphql_support_contract(&case).expect("batching remains metadata-only");
        case.support = SupportLevel::Current;
        case.expected.incompleteness = None;
        assert!(validate_graphql_support_contract(&case).is_err());

        case.support = SupportLevel::MetadataOnly;
        case.expected.incompleteness = Some(IncompletenessExpectation::FutureMetadataOnly);
        case.expected.graphql_evidence = Some(GraphqlExpectation::GetQueryMetadataOnly);
        validate_graphql_support_contract(&case).expect("GET query remains metadata-only");
    }

    #[test]
    fn openapi_support_contract_separates_current_and_metadata_only_documents() {
        let mut case = valid_openapi_case("openapi-current");
        validate_openapi_support_contract(&case).expect("bounded JSON document is current");

        case.support = SupportLevel::MetadataOnly;
        case.expected.incompleteness = Some(IncompletenessExpectation::FutureMetadataOnly);
        assert!(validate_openapi_support_contract(&case).is_err());

        case.expected.openapi_outcome = Some(OpenApiExpectation::Swagger20MetadataOnly);
        case.expected.openapi_version = None;
        case.expected.openapi_path_count = None;
        case.expected.openapi_operation_count = None;
        validate_openapi_support_contract(&case).expect("Swagger 2.0 remains metadata-only");

        case.expected.openapi_outcome = Some(OpenApiExpectation::YamlMetadataOnly);
        validate_openapi_support_contract(&case).expect("YAML remains metadata-only");
    }

    #[test]
    fn openapi_generated_boundaries_require_the_exact_typed_outcome() {
        let mut case = valid_openapi_case("openapi-generated-boundary");
        case.expected.openapi_version = None;
        case.expected.openapi_path_count = None;
        case.expected.openapi_operation_count = None;
        case.expected.openapi_outcome = Some(OpenApiExpectation::TooLarge);
        case.expected.openapi_generated_input =
            Some(OpenApiGeneratedInputExpectation::DocumentSizePlusOne);
        validate_openapi_support_contract(&case).expect("document byte boundary");

        case.expected.openapi_generated_input =
            Some(OpenApiGeneratedInputExpectation::PathLimitPlusOne);
        assert!(validate_openapi_support_contract(&case).is_err());
        case.expected.openapi_outcome = Some(OpenApiExpectation::LimitExceeded);
        validate_openapi_support_contract(&case).expect("path catalog boundary");
    }

    #[test]
    fn openapi_expectation_sets_are_unique_and_digest_order_independent() {
        let mut first = valid_openapi_case("openapi-ordering");
        first.expected.openapi_required_candidate_tags = vec![
            OpenApiCandidateTagExpectation::ReadOnly,
            OpenApiCandidateTagExpectation::DeclaresAnonymousAccess,
        ];
        let mut second = first.clone();
        second.expected.openapi_required_candidate_tags.reverse();
        assert_eq!(
            semantic_digest(&validated(vec![first.clone()])),
            semantic_digest(&validated(vec![second]))
        );

        first
            .expected
            .openapi_required_candidate_tags
            .push(OpenApiCandidateTagExpectation::ReadOnly);
        assert_error_contains(validate_openapi_support_contract(&first), "must be unique");
    }

    #[test]
    fn openapi_fields_are_rejected_outside_the_openapi_category() {
        let mut case = valid_case("http-with-openapi-field");
        case.expected.openapi_outcome = Some(OpenApiExpectation::Malformed);
        assert_error_contains(
            validate_openapi_support_contract(&case),
            "limited to the API/OpenAPI category",
        );
    }

    #[test]
    fn authorization_fixture_requires_exact_four_view_current_contract() {
        let case = valid_authorization_case("authorization-valid");
        validate_case("cases/authorization-valid.toml", &case)
            .expect("bounded authorization fixture");

        let mut missing = valid_authorization_case("authorization-missing");
        missing.authorization = None;
        assert_error_contains(
            validate_case("cases/authorization-missing.toml", &missing),
            "four-view",
        );

        let mut wrong_category = valid_case("authorization-wrong-category");
        wrong_category.authorization = case.authorization;
        assert_error_contains(
            validate_case("cases/authorization-wrong-category.toml", &wrong_category),
            "limited to the authorization category",
        );
    }

    #[test]
    fn authorization_profile_rejects_root_wildcard_and_duplicate_selected_paths() {
        for selected in [
            vec![String::new()],
            vec!["/data/*".to_owned()],
            vec!["/data/account".to_owned(), "/data/account".to_owned()],
        ] {
            let comparison = AuthorizationComparisonFixture {
                selected_paths: selected,
                ignored_paths: Vec::new(),
                unordered_array_paths: Vec::new(),
                max_diff_paths: 16,
            };
            assert!(validate_authorization_comparison(&comparison).is_err());
        }

        let literal_asterisk = AuthorizationComparisonFixture {
            selected_paths: vec!["/data/account*".to_owned()],
            ignored_paths: Vec::new(),
            unordered_array_paths: Vec::new(),
            max_diff_paths: 16,
        };
        validate_authorization_comparison(&literal_asterisk)
            .expect("an asterisk inside a literal token is not the wildcard segment");
    }

    #[test]
    fn authorization_profile_rejects_invalid_pointer_and_outside_paths() {
        let mut comparison = AuthorizationComparisonFixture {
            selected_paths: vec!["/data/account".to_owned()],
            ignored_paths: vec!["/metadata/time".to_owned()],
            unordered_array_paths: Vec::new(),
            max_diff_paths: 16,
        };
        assert_error_contains(
            validate_authorization_comparison(&comparison),
            "inside a selected subtree",
        );
        comparison.ignored_paths.clear();
        comparison.unordered_array_paths = vec!["/metadata/roles".to_owned()];
        assert_error_contains(
            validate_authorization_comparison(&comparison),
            "inside a selected subtree",
        );
        comparison.unordered_array_paths.clear();
        comparison.selected_paths = vec!["/data/~2invalid".to_owned()];
        assert_error_contains(validate_authorization_comparison(&comparison), "RFC 6901");
    }

    #[test]
    fn authorization_profile_matches_production_subtree_conflicts() {
        let redundant_selected = AuthorizationComparisonFixture {
            selected_paths: vec!["/data".to_owned(), "/data/account".to_owned()],
            ignored_paths: Vec::new(),
            unordered_array_paths: Vec::new(),
            max_diff_paths: 16,
        };
        assert_error_contains(
            validate_authorization_comparison(&redundant_selected),
            "redundant subtrees",
        );

        let redundant_ignored = AuthorizationComparisonFixture {
            selected_paths: vec!["/data/account".to_owned()],
            ignored_paths: vec![
                "/data/account/volatile".to_owned(),
                "/data/account/volatile/time".to_owned(),
            ],
            unordered_array_paths: Vec::new(),
            max_diff_paths: 16,
        };
        assert_error_contains(
            validate_authorization_comparison(&redundant_ignored),
            "redundant subtrees",
        );

        let unordered_hidden = AuthorizationComparisonFixture {
            selected_paths: vec!["/data/account".to_owned()],
            ignored_paths: vec!["/data/account/roles".to_owned()],
            unordered_array_paths: vec!["/data/account/roles".to_owned()],
            max_diff_paths: 16,
        };
        assert_error_contains(
            validate_authorization_comparison(&unordered_hidden),
            "cannot be hidden",
        );
    }

    #[test]
    fn authorization_profile_limits_and_claim_semantics_fail_closed() {
        let mut case = valid_authorization_case("authorization-limits");
        case.authorization
            .as_mut()
            .unwrap()
            .comparison
            .max_diff_paths = 0;
        assert_error_contains(
            validate_case("cases/authorization-limits.toml", &case),
            "hard limits",
        );

        let mut negative = valid_authorization_case("authorization-negative");
        negative.expected.authorization_outcome = Some(AuthorizationOutcomeExpectation::PeerDenied);
        assert_error_contains(
            validate_case("cases/authorization-negative.toml", &negative),
            "cannot declare an assessment item",
        );

        negative.expected.assessment_capability = None;
        negative.expected.maximum_disposition = None;
        negative.expected.maximum_authority = None;
        validate_case("cases/authorization-negative.toml", &negative)
            .expect("negative authorization fixture makes no claim");

        let mut incomplete_positive = valid_authorization_case("authorization-incomplete-positive");
        incomplete_positive.expected.incompleteness =
            Some(IncompletenessExpectation::ResponseIncomplete);
        assert_error_contains(
            validate_case(
                "cases/authorization-incomplete-positive.toml",
                &incomplete_positive,
            ),
            "complete bounded review claim contract",
        );
    }

    #[test]
    fn authorization_view_truncation_contract_is_typed() {
        let mut view = valid_authorization_case("authorization-view")
            .authorization
            .unwrap()
            .primary_candidate;
        view.state = AuthorizationBodyState::Truncated;
        view.truncated = true;
        assert_error_contains(validate_authorization_view(&view), "do not reconcile");
        view.completion = CompletionState::Incomplete;
        validate_authorization_view(&view).expect("typed truncated view");
    }

    #[test]
    fn authorization_view_states_require_coherent_response_metadata() {
        let base = valid_authorization_case("authorization-view-state")
            .authorization
            .unwrap()
            .primary_candidate;

        for (state, status, media_type, completion, truncated) in [
            (
                AuthorizationBodyState::CompleteJson,
                200,
                "application/json",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::UnsupportedMedia,
                200,
                "application/octet-stream",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::Html,
                403,
                "text/html",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::Redirect,
                302,
                "application/json",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::RateLimited,
                429,
                "application/json",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::ServerError,
                503,
                "application/json",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::MalformedJson,
                200,
                "application/json",
                CompletionState::Complete,
                false,
            ),
            (
                AuthorizationBodyState::Truncated,
                200,
                "application/json",
                CompletionState::Incomplete,
                true,
            ),
            (
                AuthorizationBodyState::Incomplete,
                200,
                "application/json",
                CompletionState::Incomplete,
                false,
            ),
            (
                AuthorizationBodyState::DefensiveInterference,
                403,
                "text/html",
                CompletionState::Complete,
                false,
            ),
        ] {
            let mut view = base.clone();
            view.state = state;
            view.status = status;
            view.media_type = media_type.to_owned();
            view.completion = completion;
            view.truncated = truncated;
            validate_authorization_view(&view).expect("coherent authorization response state");
        }

        for state in [
            AuthorizationBodyState::BudgetExhausted,
            AuthorizationBodyState::Cancelled,
        ] {
            let mut view = base.clone();
            view.state = state;
            assert_error_contains(validate_authorization_view(&view), "do not reconcile");
        }

        for (state, status, media_type) in [
            (AuthorizationBodyState::RateLimited, 200, "application/json"),
            (AuthorizationBodyState::Redirect, 200, "application/json"),
            (AuthorizationBodyState::ServerError, 200, "application/json"),
            (AuthorizationBodyState::Html, 403, "application/json"),
            (
                AuthorizationBodyState::UnsupportedMedia,
                200,
                "application/json",
            ),
        ] {
            let mut view = base.clone();
            view.state = state;
            view.status = status;
            view.media_type = media_type.to_owned();
            assert_error_contains(validate_authorization_view(&view), "do not reconcile");
        }
    }

    #[test]
    fn candidate_requires_a_control_parent() {
        let mut candidate = valid_case("candidate");
        candidate.request.role = ExchangeRole::Candidate;
        candidate.response.role = ExchangeRole::Candidate;
        assert_error_contains(
            validate_case_relationships(&[LoadedCase { case: candidate }], &BTreeMap::new()),
            "requires a parent",
        );
    }

    #[test]
    fn candidate_control_relationship_is_validated() {
        let control = valid_case("control");
        let mut candidate = valid_case("candidate");
        candidate.request.role = ExchangeRole::Candidate;
        candidate.response.role = ExchangeRole::Candidate;
        candidate.parent_case = Some("control".to_owned());
        validate_case_relationships(
            &[LoadedCase { case: control }, LoadedCase { case: candidate }],
            &BTreeMap::new(),
        )
        .expect("control/candidate relationship");
    }

    #[test]
    fn replay_requires_candidate_parent() {
        let control = valid_case("control");
        let mut replay = valid_case("replay");
        replay.request.role = ExchangeRole::Replay;
        replay.response.role = ExchangeRole::Replay;
        replay.parent_case = Some("control".to_owned());
        assert_error_contains(
            validate_case_relationships(
                &[LoadedCase { case: control }, LoadedCase { case: replay }],
                &BTreeMap::new(),
            ),
            "candidate parent",
        );
    }

    #[test]
    fn relationship_cannot_cross_origin() {
        let control = valid_case("control");
        let mut candidate = valid_case("candidate");
        candidate.request.role = ExchangeRole::Candidate;
        candidate.response.role = ExchangeRole::Candidate;
        candidate.parent_case = Some("control".to_owned());
        candidate.request.origin = "https://other.example.test".to_owned();
        assert_error_contains(
            validate_case_relationships(
                &[LoadedCase { case: control }, LoadedCase { case: candidate }],
                &BTreeMap::new(),
            ),
            "incompatible request contract",
        );
    }

    #[test]
    fn semantic_digest_is_source_order_independent() {
        let left = valid_case("alpha");
        let mut right = valid_case("beta");
        right.request.path = "/other".to_owned();
        let first = validated(vec![left.clone(), right.clone()]);
        let second = validated(vec![right, left]);
        assert_eq!(semantic_digest(&first), semantic_digest(&second));
    }

    #[test]
    fn material_body_change_changes_semantic_digest() {
        let first = validated(vec![valid_case("body-change")]);
        let mut changed_case = valid_case("body-change");
        changed_case.response.inline_body = Some("{\"ok\":false}".to_owned());
        let second = validated(vec![changed_case]);
        assert_ne!(semantic_digest(&first), semantic_digest(&second));
    }

    #[test]
    fn material_expectation_change_changes_semantic_digest() {
        let first = validated(vec![valid_case("expectation-change")]);
        let mut changed_case = valid_case("expectation-change");
        changed_case.expected.http_media = Some(HttpMediaExpectation::Html);
        let second = validated(vec![changed_case]);
        assert_ne!(semantic_digest(&first), semantic_digest(&second));
    }

    #[test]
    fn ssrf_oast_fixture_pins_positive_and_negative_claim_contracts() {
        let positive = valid_ssrf_oast_case("ssrf-positive");
        validate_case("cases/ssrf-positive.toml", &positive).expect("positive contract");

        let mut negative = valid_ssrf_oast_case("ssrf-negative");
        let fixture = negative.ssrf_oast.as_mut().unwrap();
        fixture.scenario = SsrfOastScenario::NoCallback;
        negative.expected.ssrf_oast_outcome = Some(SsrfOastOutcomeExpectation::NoCallback);
        assert_error_contains(
            validate_case("cases/ssrf-negative.toml", &negative),
            "cannot declare an assessment item",
        );
        negative.expected.assessment_capability = None;
        negative.expected.maximum_disposition = None;
        negative.expected.maximum_authority = None;
        validate_case("cases/ssrf-negative.toml", &negative).expect("negative contract");
    }

    #[test]
    fn ssrf_oast_fixture_is_category_scoped_and_scenario_typed() {
        let mut outside = valid_ssrf_oast_case("ssrf-outside");
        outside.category = CaseCategory::HttpMedia;
        assert_error_contains(
            validate_case("cases/ssrf-outside.toml", &outside),
            "limited to the ssrf-oast category",
        );

        let mut mismatch = valid_ssrf_oast_case("ssrf-mismatch");
        mismatch.ssrf_oast.as_mut().unwrap().scenario = SsrfOastScenario::CandidateOnly;
        assert_error_contains(
            validate_case("cases/ssrf-mismatch.toml", &mismatch),
            "scenario and typed outcome",
        );
    }

    #[test]
    fn ssrf_oast_fixture_rejects_ineligible_sources_and_inexact_completion() {
        let mut ineligible = valid_ssrf_oast_case("ssrf-ineligible");
        ineligible.request.method = HttpMethod::Post;
        assert_error_contains(
            validate_case("cases/ssrf-ineligible.toml", &ineligible),
            "one observed GET URL query source",
        );

        let mut unsafe_url = valid_ssrf_oast_case("ssrf-unsafe-url");
        unsafe_url.request.query[0].value = "ftp://upstream.example.test/resource".to_owned();
        assert_error_contains(
            validate_case("cases/ssrf-unsafe-url.toml", &unsafe_url),
            "eligible absolute HTTP URL",
        );

        let mut incomplete_claim = valid_ssrf_oast_case("ssrf-incomplete-claim");
        incomplete_claim.expected.assessment_capability = None;
        assert_error_contains(
            validate_case("cases/ssrf-incomplete-claim.toml", &incomplete_claim),
            "bounded NeedsReview/KnowledgeOnly contract",
        );

        let mut truncated = valid_ssrf_oast_case("ssrf-truncated");
        truncated.ssrf_oast.as_mut().unwrap().scenario = SsrfOastScenario::Truncated;
        truncated.expected.ssrf_oast_outcome = Some(SsrfOastOutcomeExpectation::Truncated);
        truncated.expected.assessment_capability = None;
        truncated.expected.maximum_disposition = None;
        truncated.expected.maximum_authority = None;
        assert_error_contains(
            validate_case("cases/ssrf-truncated.toml", &truncated),
            "incomplete scenarios require exact completion metadata",
        );

        let mut contradictory = valid_ssrf_oast_case("ssrf-contradictory");
        contradictory.ssrf_oast.as_mut().unwrap().scenario = SsrfOastScenario::NoCallback;
        contradictory.expected.ssrf_oast_outcome = Some(SsrfOastOutcomeExpectation::NoCallback);
        contradictory.expected.assessment_capability = None;
        contradictory.expected.maximum_disposition = None;
        contradictory.expected.maximum_authority = None;
        contradictory.expected.incompleteness = Some(IncompletenessExpectation::BodyTruncated);
        assert_error_contains(
            validate_case("cases/ssrf-contradictory.toml", &contradictory),
            "complete SSRF OAST scenarios cannot declare generic incompleteness",
        );
    }

    #[test]
    fn versioned_capability_grammar_is_narrow() {
        validate_capability("ssrf.oast-repeated-outbound-interaction@1")
            .expect("positive decimal revision");
        for invalid in [
            "ssrf.oast@0",
            "ssrf.oast@alpha",
            "ssrf.oast@1@2",
            "ssrf/oast@1",
        ] {
            assert!(validate_capability(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn ssrf_oast_scenario_changes_semantic_digest() {
        let first = validated(vec![valid_ssrf_oast_case("ssrf-digest")]);
        let mut changed = valid_ssrf_oast_case("ssrf-digest");
        changed.ssrf_oast.as_mut().unwrap().scenario = SsrfOastScenario::NoCallback;
        changed.expected.ssrf_oast_outcome = Some(SsrfOastOutcomeExpectation::NoCallback);
        changed.expected.assessment_capability = None;
        changed.expected.maximum_disposition = None;
        changed.expected.maximum_authority = None;
        let second = validated(vec![changed]);
        assert_ne!(semantic_digest(&first), semantic_digest(&second));
    }

    #[test]
    fn stale_generated_inventory_is_rejected() {
        let directory = create_one();
        initialize(&directory);
        fs::write(data_root(&directory).join("INVENTORY.md"), "# stale\n")
            .expect("stale inventory");
        assert_error_contains(run(repository_root(&directory), false), "stale");
    }

    #[test]
    fn digest_wire_requires_exact_lowercase_sha256() {
        assert_error_contains(validate_digest_wire("sha256:1234"), "prefix");
        let uppercase = format!("{DIGEST_PREFIX}:{}", "A".repeat(64));
        assert_error_contains(validate_digest_wire(&uppercase), "lowercase");
        validate_digest_wire(ZERO_DIGEST).expect("valid digest wire");
    }

    #[test]
    fn unexpected_tree_extension_is_rejected() {
        let directory = create_one();
        fs::write(body_path(&directory, "unexpected.exe"), "inert").expect("unexpected file");
        assert_error_contains(
            validate_tree(&data_root(&directory)),
            "unexpected or executable",
        );
    }

    #[test]
    fn dangling_body_reference_is_rejected() {
        let directory = create_one();
        fs::remove_file(body_path(&directory, "http-json-control.json")).expect("remove body");
        assert_error_contains(load_and_validate(repository_root(&directory)), "dangling");
    }

    #[test]
    fn unreferenced_body_is_rejected() {
        let directory = create_one();
        fs::write(body_path(&directory, "unreferenced.json"), "{}\n").expect("extra body");
        assert_error_contains(
            load_and_validate(repository_root(&directory)),
            "unreferenced",
        );
    }

    #[test]
    fn duplicate_manifest_case_path_is_rejected() {
        let directory = create_one();
        let source = manifest_source(&[
            "cases/http-json-control.toml",
            "cases/http-json-control.toml",
        ]);
        fs::write(data_root(&directory).join("manifest.toml"), source).expect("manifest");
        assert_error_contains(
            load_and_validate(repository_root(&directory)),
            "duplicate case file",
        );
    }

    #[test]
    fn semantic_duplicate_requires_explicit_equivalence() {
        let first = valid_case("first");
        let second = valid_case("second");
        assert_error_contains(
            validate_case_relationships(
                &[LoadedCase { case: first }, LoadedCase { case: second }],
                &BTreeMap::new(),
            ),
            "exactly one canonical",
        );
    }

    #[test]
    fn linked_semantic_duplicate_is_accepted() {
        let first = valid_case("first");
        let mut second = valid_case("second");
        second.equivalent_to = Some("first".to_owned());
        validate_case_relationships(
            &[LoadedCase { case: first }, LoadedCase { case: second }],
            &BTreeMap::new(),
        )
        .expect("explicitly linked duplicate");
    }

    #[test]
    fn generated_inventory_is_deterministic() {
        let corpus = validated(vec![valid_case("inventory-case")]);
        assert_eq!(render_inventory(&corpus), render_inventory(&corpus));
        assert!(render_inventory(&corpus).contains("Metadata only"));
    }

    #[test]
    fn invalid_utf8_fixture_text_is_rejected() {
        assert_error_contains(canonical_text(&[0xff, 0xfe], "fixture"), "strict UTF-8");
        assert_error_contains(validate_safe_fixture_bytes(&[0xff]), "UTF-8");
    }

    #[test]
    fn request_and_response_roles_must_match() {
        let mut case = valid_case("role-mismatch");
        case.response.role = ExchangeRole::Candidate;
        assert_error_contains(
            validate_case("cases/role-mismatch.toml", &case),
            "roles must match",
        );
    }

    #[test]
    fn body_file_and_inline_body_are_mutually_exclusive() {
        assert_error_contains(
            validate_body_pair(Some("bodies/body.json"), Some("{}")),
            "either a file or an inline",
        );
    }

    #[test]
    fn manifest_case_inventory_must_match_tree() {
        let directory = create_one();
        let source = manifest_source(&["cases/not-present.toml"]);
        fs::write(data_root(&directory).join("manifest.toml"), source).expect("manifest");
        assert_error_contains(
            load_and_validate(repository_root(&directory)),
            "case inventory",
        );
    }

    #[test]
    fn manifest_rewrite_preserves_crlf_style() {
        let directory = create_one();
        let path = data_root(&directory).join("manifest.toml");
        let source = fs::read_to_string(&path)
            .expect("manifest")
            .replace('\n', "\r\n");
        fs::write(&path, source).expect("CRLF manifest");
        initialize(&directory);
        let rewritten = fs::read(&path).expect("rewritten manifest");
        assert!(rewritten.windows(2).any(|pair| pair == b"\r\n"));
        run(repository_root(&directory), false).expect("CRLF corpus");
    }

    #[cfg(unix)]
    #[test]
    fn corpus_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = create_one();
        symlink(
            body_path(&directory, "http-json-control.json"),
            body_path(&directory, "linked.json"),
        )
        .expect("fixture symlink");
        assert_error_contains(
            validate_tree(&data_root(&directory)),
            "symlinks are forbidden",
        );
    }
}
