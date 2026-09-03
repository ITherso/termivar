//! Pure OpenAPI-to-REST read-only operation selection.
//!
//! Catalog knowledge constrains this selector but grants no transport
//! authority. The selected URL remains crate-private and must still pass the
//! parent runtime's exact-origin broker policy before dispatch.

use std::fmt;

use serde::Serialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::openapi_review::{
    OpenApiDocument, OpenApiHttpMethod, OpenApiMediaFamily, OpenApiOperation, OpenApiOperationId,
    OpenApiParameterLocation, OpenApiResponseStatus, OpenApiServerKind,
};

/// Stable semantic revision for bounded REST operation selection.
pub const REST_REVIEW_SELECTION_ALGORITHM: &str = "security.openapi-rest-readonly-selection/v1";
/// V1 may retain and execute at most one selected operation.
pub const MAX_REST_REVIEW_OPERATIONS: usize = 1;
/// Bound for the fully resolved internal request target.
pub const MAX_REST_REVIEW_TARGET_BYTES: usize = 8 * 1024;

const REST_TARGET_IDENTITY_DOMAIN: &[u8] = b"security.openapi-rest-readonly-target.v1\0";

/// Documented response-media confidence used only for deterministic ranking.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RestDocumentedResponseClass {
    /// At least one explicit 2xx response offers JSON or `+json`.
    JsonCompatible,
    /// The success response media is absent or otherwise unspecified.
    Unknown,
}

/// Result of filtering one replay-stable OpenAPI catalog.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum RestOperationSelectionOutcome {
    /// Exactly one deterministic operation was selected from the eligible set.
    Selected(RestOperationSelection),
    /// No operation met every V1 safety condition.
    NoEligibleOperation,
}

impl fmt::Debug for RestOperationSelectionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Selected(selection) => {
                formatter.debug_tuple("Selected").field(selection).finish()
            },
            Self::NoEligibleOperation => formatter.write_str("NoEligibleOperation"),
        }
    }
}

/// One bounded, anonymous, bodyless REST GET selected from an OpenAPI catalog.
///
/// Debug deliberately omits the URL and its path. The URL is not serializable
/// and is available only to the in-crate runtime, which must independently
/// enforce exact-origin authority.
#[derive(Clone, Eq, PartialEq)]
pub struct RestOperationSelection {
    operation_id: OpenApiOperationId,
    execution_url: Url,
    target_identity: String,
    documented_response: RestDocumentedResponseClass,
    deprecated: bool,
    eligible_operation_count: u32,
}

impl RestOperationSelection {
    /// Returns the stable, digest-based catalog operation identity.
    pub const fn operation_id(&self) -> &OpenApiOperationId {
        &self.operation_id
    }

    /// Returns the response-media class used in deterministic ranking.
    pub const fn documented_response(&self) -> RestDocumentedResponseClass {
        self.documented_response
    }

    /// Returns whether the document marked the selected operation deprecated.
    pub const fn deprecated(&self) -> bool {
        self.deprecated
    }

    /// Returns the number of operations that passed every V1 safety filter.
    pub const fn eligible_operation_count(&self) -> u32 {
        self.eligible_operation_count
    }

    /// Returns the redacted stable scope identity used by replay comparison.
    pub fn target_identity(&self) -> &str {
        &self.target_identity
    }

    /// Returns the request target only to the parent-owned in-crate runtime.
    pub(crate) const fn execution_url(&self) -> &Url {
        &self.execution_url
    }
}

impl fmt::Debug for RestOperationSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestOperationSelection")
            .field("operation_id", &self.operation_id)
            .field("execution_url", &"<exact-origin-redacted>")
            .field("target_identity", &self.target_identity)
            .field("documented_response", &self.documented_response)
            .field("deprecated", &self.deprecated)
            .field("eligible_operation_count", &self.eligible_operation_count)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestOperationIneligibility {
    Method,
    RequiredParameter(OpenApiParameterLocation),
    RequestBody,
    Authentication,
    Server,
    ResponseMedia,
    Target,
}

#[derive(Clone)]
struct EligibleOperation {
    selection: RestOperationSelection,
    server_rank: u8,
    path_bytes: usize,
}

/// Selects at most one operation without materializing parameters, examples,
/// defaults, request bodies, credentials, cookies, or network actions.
pub fn select_rest_operation(
    document: &OpenApiDocument,
    document_url: &Url,
) -> RestOperationSelectionOutcome {
    let mut eligible = document
        .catalog()
        .operations()
        .iter()
        .filter_map(|operation| eligible_operation(document_url, operation).ok())
        .collect::<Vec<_>>();
    let eligible_operation_count = u32::try_from(eligible.len()).unwrap_or(u32::MAX);
    eligible.sort_by(|left, right| {
        left.server_rank
            .cmp(&right.server_rank)
            .then(
                left.selection
                    .documented_response
                    .cmp(&right.selection.documented_response),
            )
            .then(left.selection.deprecated.cmp(&right.selection.deprecated))
            .then(left.path_bytes.cmp(&right.path_bytes))
            .then(
                left.selection
                    .operation_id
                    .cmp(&right.selection.operation_id),
            )
    });
    match eligible.into_iter().next() {
        Some(mut selected) => {
            selected.selection.eligible_operation_count = eligible_operation_count;
            RestOperationSelectionOutcome::Selected(selected.selection)
        },
        None => RestOperationSelectionOutcome::NoEligibleOperation,
    }
}

fn eligible_operation(
    document_url: &Url,
    operation: &OpenApiOperation,
) -> Result<EligibleOperation, RestOperationIneligibility> {
    if operation.method() != OpenApiHttpMethod::Get {
        return Err(RestOperationIneligibility::Method);
    }
    if let Some(parameter) = operation
        .parameters()
        .iter()
        .find(|parameter| parameter.required())
    {
        return Err(RestOperationIneligibility::RequiredParameter(
            parameter.location(),
        ));
    }
    if operation.request_body_declared() {
        return Err(RestOperationIneligibility::RequestBody);
    }
    if !operation.security().permits_anonymous() {
        return Err(RestOperationIneligibility::Authentication);
    }
    let (execution_url, server_rank) = resolve_operation_target(document_url, operation)?;
    let documented_response = documented_response_class(operation)?;
    let target_identity = rest_target_identity(operation.id(), &execution_url);
    Ok(EligibleOperation {
        selection: RestOperationSelection {
            operation_id: operation.id().clone(),
            execution_url,
            target_identity,
            documented_response,
            deprecated: operation.deprecated(),
            eligible_operation_count: 0,
        },
        server_rank,
        path_bytes: operation.path().len(),
    })
}

fn documented_response_class(
    operation: &OpenApiOperation,
) -> Result<RestDocumentedResponseClass, RestOperationIneligibility> {
    let relevant = operation
        .responses()
        .iter()
        .filter(|response| {
            matches!(
                response.status(),
                OpenApiResponseStatus::Exact(200..=299) | OpenApiResponseStatus::Range(2)
            )
        })
        .collect::<Vec<_>>();
    if relevant.iter().any(|response| {
        response.media_families().iter().any(|family| {
            matches!(
                family,
                OpenApiMediaFamily::Json | OpenApiMediaFamily::JsonSuffix
            )
        })
    }) {
        return Ok(RestDocumentedResponseClass::JsonCompatible);
    }
    if relevant.is_empty()
        || relevant
            .iter()
            .any(|response| response.media_families().is_empty())
    {
        return Ok(RestDocumentedResponseClass::Unknown);
    }
    Err(RestOperationIneligibility::ResponseMedia)
}

fn resolve_operation_target(
    document_url: &Url,
    operation: &OpenApiOperation,
) -> Result<(Url, u8), RestOperationIneligibility> {
    if !document_url_has_safe_origin(document_url)
        || operation.path().contains(['{', '}'])
        || operation.servers().len() > 1
    {
        return Err(RestOperationIneligibility::Server);
    }
    let (mut base, server_rank) = match operation.servers() {
        [] => {
            let mut root = document_url.clone();
            root.set_path("/");
            root.set_query(None);
            root.set_fragment(None);
            (root, 0)
        },
        [server]
            if matches!(server.kind(), OpenApiServerKind::ExactOrigin)
                && server.execution_base().is_some() =>
        {
            (
                server
                    .execution_base()
                    .expect("guarded server base")
                    .clone(),
                0,
            )
        },
        [server]
            if matches!(server.kind(), OpenApiServerKind::Relative)
                && server.execution_base().is_some() =>
        {
            (
                server
                    .execution_base()
                    .expect("guarded server base")
                    .clone(),
                1,
            )
        },
        [_] => return Err(RestOperationIneligibility::Server),
        _ => unreachable!("server count was bounded above"),
    };
    let base_path = base.path().trim_end_matches('/');
    let path = if base_path.is_empty() {
        operation.path().to_owned()
    } else {
        format!("{base_path}{}", operation.path())
    };
    if !safe_execution_path(&path) {
        return Err(RestOperationIneligibility::Target);
    }
    base.set_path(&path);
    base.set_query(None);
    base.set_fragment(None);
    if base.as_str().len() > MAX_REST_REVIEW_TARGET_BYTES
        || !same_origin(document_url, &base)
        || !document_url_has_safe_origin(&base)
    {
        return Err(RestOperationIneligibility::Target);
    }
    Ok((base, server_rank))
}

fn document_url_has_safe_origin(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn safe_execution_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains(['?', '#', '%', '\\', '\r', '\n', '\0'])
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn rest_target_identity(operation: &OpenApiOperationId, target: &Url) -> String {
    let mut digest = Sha256::new();
    update_framed(&mut digest, REST_TARGET_IDENTITY_DOMAIN);
    update_framed(&mut digest, REST_REVIEW_SELECTION_ALGORITHM.as_bytes());
    update_framed(&mut digest, operation.as_str().as_bytes());
    update_framed(&mut digest, target.as_str().as_bytes());
    format!("rest-readonly-target-sha256:{:x}", digest.finalize())
}

fn update_framed(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::openapi_review::{parse_openapi_document, OpenApiCandidateTag, OpenApiParseOutcome};

    fn document_at(value: Value, document_url: &Url) -> OpenApiDocument {
        match parse_openapi_document(&serde_json::to_vec(&value).unwrap(), document_url) {
            OpenApiParseOutcome::Complete(document) => document,
            outcome => panic!("expected complete OpenAPI document, got {outcome:?}"),
        }
    }

    fn operation(path: &str, method: &str, body: Value) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {"title": "Fixture", "version": "1"},
            "paths": {(path): {(method): body}}
        })
    }

    fn selected(value: Value, document_url: &Url) -> RestOperationSelection {
        let document = document_at(value, document_url);
        match select_rest_operation(&document, document_url) {
            RestOperationSelectionOutcome::Selected(selection) => selection,
            RestOperationSelectionOutcome::NoEligibleOperation => panic!("expected selection"),
        }
    }

    fn assert_none(value: Value, document_url: &Url) {
        let document = document_at(value, document_url);
        assert_eq!(
            select_rest_operation(&document, document_url),
            RestOperationSelectionOutcome::NoEligibleOperation
        );
    }

    #[test]
    fn selects_one_anonymous_bodyless_get_with_json_response() {
        let url = Url::parse("https://example.test/docs/openapi.json").unwrap();
        let selection = selected(
            operation(
                "/health",
                "get",
                json!({"responses":{"200":{"content":{"application/json":{}}}}}),
            ),
            &url,
        );
        assert_eq!(
            selection.execution_url().as_str(),
            "https://example.test/health"
        );
        assert_eq!(selection.eligible_operation_count(), 1);
        assert_eq!(
            selection.documented_response(),
            RestDocumentedResponseClass::JsonCompatible
        );
        assert!(!selection.deprecated());
        assert!(selection
            .operation_id()
            .as_str()
            .starts_with("openapi-operation-sha256:"));
        assert!(selection
            .target_identity()
            .starts_with("rest-readonly-target-sha256:"));
    }

    #[test]
    fn every_required_parameter_location_is_ineligible() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        for (location, path) in [
            ("path", "/items/{id}"),
            ("query", "/items"),
            ("header", "/items"),
            ("cookie", "/items"),
        ] {
            assert_none(
                operation(
                    path,
                    "get",
                    json!({
                        "parameters":[{"name":"id","in":location,"required":true,"schema":{"type":"string"}}],
                        "responses":{"200":{"content":{"application/json":{}}}}
                    }),
                ),
                &url,
            );
        }
    }

    #[test]
    fn empty_request_body_is_still_declared_and_changes_identity() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        let without = document_at(
            operation("/items", "get", json!({"responses":{"200":{}}})),
            &url,
        );
        let with = document_at(
            operation(
                "/items",
                "get",
                json!({"requestBody":{},"responses":{"200":{}}}),
            ),
            &url,
        );
        assert!(!without.catalog().operations()[0].request_body_declared());
        assert!(with.catalog().operations()[0].request_body_declared());
        assert!(with.catalog().operations()[0]
            .candidate_tags()
            .contains(&OpenApiCandidateTag::BodyBearing));
        assert_ne!(without.semantic_digest(), with.semantic_digest());
        assert_eq!(
            select_rest_operation(&with, &url),
            RestOperationSelectionOutcome::NoEligibleOperation
        );
    }

    #[test]
    fn required_security_is_ineligible_but_explicit_anonymous_is_eligible() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        for (name, scheme) in [
            ("bearer", json!({"type":"http","scheme":"bearer"})),
            ("key", json!({"type":"apiKey","in":"header","name":"X-Key"})),
            ("oauth", json!({"type":"oauth2","flows":{}})),
        ] {
            let value = json!({
                "openapi":"3.1.0",
                "info":{"title":"Fixture","version":"1"},
                "components":{"securitySchemes":{(name):scheme}},
                "security":[{(name):[]}],
                "paths":{"/health":{"get":{"responses":{"200":{}}}}}
            });
            assert_none(value, &url);
        }
        let anonymous = json!({
            "openapi":"3.1.0",
            "info":{"title":"Fixture","version":"1"},
            "security":[{"unknown":[]}],
            "paths":{"/health":{"get":{"security":[],"responses":{"200":{}}}}}
        });
        assert_eq!(selected(anonymous, &url).eligible_operation_count(), 1);
    }

    #[test]
    fn unsafe_or_ambiguous_servers_are_ineligible() {
        let url = Url::parse("https://example.test/docs/openapi.json").unwrap();
        for servers in [
            json!([{"url":"https://elsewhere.invalid"}]),
            json!([{"url":"https://{tenant}.example.test","variables":{"tenant":{}}}]),
            json!([{"url":"/v1"},{"url":"/v2"}]),
            json!([{"url":"https://user:secret@example.test/api"}]),
            json!([{"url":"/api?variant=1"}]),
            json!([{"url":"/api#fragment"}]),
        ] {
            let value = json!({
                "openapi":"3.1.0",
                "info":{"title":"Fixture","version":"1"},
                "servers":servers,
                "paths":{"/health":{"get":{"responses":{"200":{}}}}}
            });
            assert_none(value, &url);
        }
    }

    #[test]
    fn relative_server_base_is_concatenated_without_losing_its_path() {
        let url = Url::parse("https://example.test/docs/openapi.json").unwrap();
        let value = json!({
            "openapi":"3.1.0",
            "info":{"title":"Fixture","version":"1"},
            "servers":[{"url":"/api/v1"}],
            "paths":{"/health":{"get":{"responses":{"200":{}}}}}
        });
        let selection = selected(value, &url);
        assert_eq!(
            selection.execution_url().as_str(),
            "https://example.test/api/v1/health"
        );
    }

    #[test]
    fn post_and_known_non_json_response_are_ineligible() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        assert_none(
            operation("/items", "post", json!({"responses":{"200":{}}})),
            &url,
        );
        assert_none(
            operation(
                "/items",
                "get",
                json!({"responses":{"200":{"content":{"text/html":{}}}}}),
            ),
            &url,
        );
    }

    #[test]
    fn ranking_prefers_json_then_non_deprecated_then_shortest_path() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        let value = json!({
            "openapi":"3.1.0",
            "info":{"title":"Fixture","version":"1"},
            "paths":{
                "/unknown":{"get":{"responses":{"200":{}}}},
                "/deprecated":{"get":{"deprecated":true,"responses":{"200":{"content":{"application/json":{}}}}}},
                "/longer/path":{"get":{"responses":{"200":{"content":{"application/json":{}}}}}},
                "/ok":{"get":{"responses":{"200":{"content":{"application/json":{}}}}}}
            }
        });
        let first = selected(value.clone(), &url);
        let second = selected(value, &url);
        assert_eq!(first, second);
        assert_eq!(first.execution_url().path(), "/ok");
        assert_eq!(first.eligible_operation_count(), 4);
    }

    #[test]
    fn unknown_response_media_is_a_lower_ranked_safe_observation() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        let selection = selected(
            operation("/health", "get", json!({"responses":{"200":{}}})),
            &url,
        );
        assert_eq!(
            selection.documented_response(),
            RestDocumentedResponseClass::Unknown
        );
    }

    #[test]
    fn default_response_metadata_never_outranks_explicit_json_success() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        let value = json!({
            "openapi":"3.1.0",
            "info":{"title":"Fixture","version":"1"},
            "paths":{
                "/default":{"get":{"responses":{"default":{"content":{"application/json":{}}}}}},
                "/explicit":{"get":{"responses":{"200":{"content":{"application/json":{}}}}}}
            }
        });
        let selection = selected(value, &url);
        assert_eq!(selection.execution_url().path(), "/explicit");
        assert_eq!(
            selection.documented_response(),
            RestDocumentedResponseClass::JsonCompatible
        );
    }

    #[test]
    fn optional_examples_and_defaults_are_never_materialized_into_the_target() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        let value = operation(
            "/items",
            "get",
            json!({
                "parameters":[{
                    "name":"filter",
                    "in":"query",
                    "required":false,
                    "example":"MUST-NOT-BE-MATERIALIZED",
                    "schema":{"type":"string","default":"MUST-NOT-BE-MATERIALIZED"}
                }],
                "responses":{"200":{"content":{"application/json":{}}}}
            }),
        );
        let selection = selected(value, &url);
        assert_eq!(
            selection.execution_url().as_str(),
            "https://example.test/items"
        );
        assert!(selection.execution_url().query().is_none());
        assert!(!format!("{selection:?}").contains("MUST-NOT-BE-MATERIALIZED"));
    }

    #[test]
    fn debug_redacts_execution_url_and_path() {
        let url = Url::parse("https://example.test/openapi.json").unwrap();
        let selection = selected(
            operation("/private/sentinel", "get", json!({"responses":{"200":{}}})),
            &url,
        );
        let debug = format!("{selection:?}");
        assert!(!debug.contains("example.test"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("sentinel"));

        let server_document = document_at(
            json!({
                "openapi":"3.1.0",
                "info":{"title":"Fixture","version":"1"},
                "servers":[{"url":"/private/base"}],
                "paths":{"/health":{"get":{"responses":{"200":{}}}}}
            }),
            &url,
        );
        let server_debug = format!("{:?}", server_document.servers()[0]);
        assert!(!server_debug.contains("/private/base"));
        assert!(!server_debug.contains("example.test"));
    }

    #[test]
    fn execution_path_rejects_every_encoded_or_control_ambiguous_form() {
        assert!(safe_execution_path("/plain/status"));
        for path in [
            "/encoded%2fsegment",
            "/double%252e%252e/admin",
            "/control%00byte",
            "/query?value=1",
            "/fragment#part",
            "/dot/../segment",
            "/double//segment",
            "/backslash\\segment",
        ] {
            assert!(!safe_execution_path(path), "accepted unsafe path {path}");
        }
    }
}
