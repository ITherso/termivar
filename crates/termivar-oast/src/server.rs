//! Loopback-only Axum transport for the native provider state machine.

use std::{fmt, sync::Arc};

use axum::{
    body::{Body, Bytes},
    extract::{rejection::BytesRejection, DefaultBodyLimit, OriginalUri, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Router,
};
use futures::{stream::FuturesUnordered, StreamExt};
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
};
use tower::ServiceExt;

use crate::{
    CallbackAllocation, CallbackId, CallbackMethod, CleanupResponse, ManagementBearer,
    NativeOastRoute, PollResponse, ProviderError, ProviderState, SessionId, SessionRegistration,
    SessionRequest, CALLBACK_SCHEMA, CLEANUP_SCHEMA, NATIVE_OAST_PROTOCOL_REVISION, POLL_SCHEMA,
    SESSION_SCHEMA,
};

use crate::MAX_MANAGEMENT_BODY_BYTES;

const MANAGEMENT_JSON_MEDIA_TYPE: &str = "application/json";
const SESSIONS_ROUTE: &str = "/v1/sessions";
const GENERIC_ERROR_JSON: &[u8] = br#"{"error":"request rejected"}"#;

#[derive(Clone)]
struct AppState {
    provider: Arc<Mutex<ProviderState>>,
    requests: Arc<Semaphore>,
}

impl AppState {
    fn new(provider: ProviderState) -> Self {
        let permits = usize::from(provider.max_concurrent_requests());
        Self {
            provider: Arc::new(Mutex::new(provider)),
            requests: Arc::new(Semaphore::new(permits)),
        }
    }

    async fn admit(&self) -> Result<OwnedSemaphorePermit, HttpFailure> {
        Arc::clone(&self.requests)
            .acquire_owned()
            .await
            .map_err(|_| HttpFailure::unavailable())
    }
}

/// Static, value-free listener failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderServerError {
    /// The checked loopback socket could not be bound.
    Bind,
    /// The HTTP listener ended with a transport failure.
    Serve,
}

impl fmt::Display for ProviderServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Bind => "native OAST loopback listener could not bind",
            Self::Serve => "native OAST loopback listener failed",
        })
    }
}

impl std::error::Error for ProviderServerError {}

fn provider_router(provider: ProviderState) -> Router {
    Router::new()
        .route(SESSIONS_ROUTE, post(register))
        .route("/v1/sessions/:session_id/callbacks", post(allocate))
        .route(
            "/v1/sessions/:session_id/events",
            get(poll).head(method_not_allowed),
        )
        .route("/v1/sessions/:session_id", delete(cleanup))
        .route(
            "/c/:session_id/:callback_id",
            get(callback_get).head(callback_head),
        )
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(MAX_MANAGEMENT_BODY_BYTES))
        .with_state(AppState::new(provider))
}

/// Binds and serves only the exact checked loopback socket in provider state.
pub async fn serve_provider(provider: ProviderState) -> Result<(), ProviderServerError> {
    let bind = provider.bind().socket_addr();
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|_| ProviderServerError::Bind)?;
    serve_listener(listener, provider).await
}

/// Serves a repository-owned fixture on an already-bound numeric-loopback
/// listener.
///
/// This avoids a port-selection race in cross-crate integration tests. It is
/// absent from production builds unless the non-default `test-support`
/// feature is explicitly selected.
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub async fn serve_provider_on_listener(
    listener: TcpListener,
    provider: ProviderState,
) -> Result<(), ProviderServerError> {
    let address = listener
        .local_addr()
        .map_err(|_| ProviderServerError::Bind)?;
    if !address.ip().is_loopback() || address != provider.bind().socket_addr() {
        return Err(ProviderServerError::Bind);
    }
    serve_listener(listener, provider).await
}

async fn serve_listener(
    listener: TcpListener,
    provider: ProviderState,
) -> Result<(), ProviderServerError> {
    let connection_limit = usize::from(provider.max_concurrent_requests());
    let router = provider_router(provider);
    let mut connections = FuturesUnordered::new();

    loop {
        if connections.len() >= connection_limit {
            let _ = connections.next().await;
            continue;
        }

        if connections.is_empty() {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|_| ProviderServerError::Serve)?;
            connections.push(serve_connection(router.clone(), stream));
            continue;
        }

        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| ProviderServerError::Serve)?;
                connections.push(serve_connection(router.clone(), stream));
            }
            _ = connections.next() => {}
        }
    }
}

async fn serve_connection(router: Router, stream: TcpStream) -> Result<(), hyper::Error> {
    let service = service_fn(move |request: Request<Incoming>| {
        let router = router.clone();
        async move { router.oneshot(request.map(Body::new)).await }
    });
    http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
}

async fn register(
    State(state): State<AppState>,
    original_uri: OriginalUri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, HttpFailure> {
    let _permit = state.admit().await?;
    if !matches!(canonical_route(original_uri)?, NativeOastRoute::Register) {
        return Err(HttpFailure::bad_request());
    }
    let body = body.map_err(HttpFailure::from_bytes_rejection)?;
    require_json(&headers)?;
    let bearer = admin_bearer(&headers)?;
    let request: SessionRequest =
        serde_json::from_slice(&body).map_err(|_| HttpFailure::bad_request())?;
    if request.schema() != SESSION_SCHEMA {
        return Err(HttpFailure::bad_request());
    }
    let registration = state
        .provider
        .lock()
        .await
        .register_bearer(bearer.expose_bytes(), request)
        .map_err(HttpFailure::from_provider)?;
    registration_response(registration)
}

async fn allocate(
    State(state): State<AppState>,
    original_uri: OriginalUri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, HttpFailure> {
    let _permit = state.admit().await?;
    let NativeOastRoute::Allocate { session_id } = canonical_route(original_uri)? else {
        return Err(HttpFailure::bad_request());
    };
    let body = body.map_err(HttpFailure::from_bytes_rejection)?;
    require_empty_body(&body)?;
    let bearer = session_bearer(&headers)?;
    let allocation = state
        .provider
        .lock()
        .await
        .allocate_bearer(&session_id, bearer.expose_bytes())
        .map_err(HttpFailure::from_provider)?;
    allocation_response(allocation)
}

async fn poll(
    State(state): State<AppState>,
    original_uri: OriginalUri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, HttpFailure> {
    let _permit = state.admit().await?;
    let NativeOastRoute::Poll { session_id, after } = canonical_route(original_uri)? else {
        return Err(HttpFailure::bad_request());
    };
    let body = body.map_err(HttpFailure::from_bytes_rejection)?;
    require_empty_body(&body)?;
    let bearer = session_bearer(&headers)?;
    let page = state
        .provider
        .lock()
        .await
        .poll_bearer(&session_id, bearer.expose_bytes(), after)
        .map_err(HttpFailure::from_provider)?;
    poll_response(page)
}

async fn cleanup(
    State(state): State<AppState>,
    original_uri: OriginalUri,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, HttpFailure> {
    let _permit = state.admit().await?;
    let NativeOastRoute::Cleanup { session_id } = canonical_route(original_uri)? else {
        return Err(HttpFailure::bad_request());
    };
    let body = body.map_err(HttpFailure::from_bytes_rejection)?;
    require_empty_body(&body)?;
    let bearer = session_bearer(&headers)?;
    let cleanup = state
        .provider
        .lock()
        .await
        .cleanup_bearer(&session_id, bearer.expose_bytes())
        .map_err(HttpFailure::from_provider)?;
    cleanup_response(cleanup)
}

async fn callback_get(State(state): State<AppState>, original_uri: OriginalUri) -> Response {
    observe_callback_path(state, original_uri, CallbackMethod::Get).await
}

async fn callback_head(State(state): State<AppState>, original_uri: OriginalUri) -> Response {
    observe_callback_path(state, original_uri, CallbackMethod::Head).await
}

async fn observe_callback_path(
    state: AppState,
    original_uri: OriginalUri,
    method: CallbackMethod,
) -> Response {
    let Ok(NativeOastRoute::Callback {
        session_id,
        callback_id,
    }) = canonical_route(original_uri)
    else {
        return callback_no_content();
    };
    observe_callback(state, session_id, callback_id, method).await
}

async fn observe_callback(
    state: AppState,
    session_id: SessionId,
    callback_id: CallbackId,
    method: CallbackMethod,
) -> Response {
    let Ok(_permit) = state.admit().await else {
        state
            .provider
            .lock()
            .await
            .mark_callback_observation_incomplete(&session_id, &callback_id);
        return callback_no_content();
    };
    // Every internal disposition, including entropy/capacity failure, is
    // deliberately collapsed to the same public response. Retention failures
    // are sticky in provider state and prevent a later complete poll.
    let _ = state
        .provider
        .lock()
        .await
        .observe_callback(&session_id, &callback_id, method);
    callback_no_content()
}

fn canonical_route(original_uri: OriginalUri) -> Result<NativeOastRoute, HttpFailure> {
    original_uri
        .0
        .to_string()
        .parse()
        .map_err(|_| HttpFailure::bad_request())
}

async fn not_found() -> Response {
    generic_error(StatusCode::NOT_FOUND)
}

async fn method_not_allowed() -> Response {
    generic_error(StatusCode::METHOD_NOT_ALLOWED)
}

fn require_json(headers: &HeaderMap) -> Result<(), HttpFailure> {
    match headers
        .get_all(CONTENT_TYPE)
        .iter()
        .collect::<Vec<_>>()
        .as_slice()
    {
        [value] if value.as_bytes() == MANAGEMENT_JSON_MEDIA_TYPE.as_bytes() => Ok(()),
        _ => Err(HttpFailure::unsupported_media()),
    }
}

fn require_empty_body(body: &[u8]) -> Result<(), HttpFailure> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(HttpFailure::bad_request())
    }
}

fn authorization_value(headers: &HeaderMap) -> Result<&[u8], HttpFailure> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or_else(HttpFailure::unauthorized)?;
    if values.next().is_some() {
        return Err(HttpFailure::unauthorized());
    }
    Ok(value.as_bytes())
}

fn admin_bearer(headers: &HeaderMap) -> Result<ManagementBearer<'_>, HttpFailure> {
    ManagementBearer::administrator(authorization_value(headers)?)
        .map_err(|_| HttpFailure::unauthorized())
}

fn session_bearer(headers: &HeaderMap) -> Result<ManagementBearer<'_>, HttpFailure> {
    ManagementBearer::session(authorization_value(headers)?)
        .map_err(|_| HttpFailure::unauthorized())
}

#[derive(Serialize)]
struct RegistrationWire<'a> {
    schema: &'static str,
    session_id: &'a str,
    session_token: &'a str,
    expires_after_ms: u64,
    protocol_revision: &'static str,
}

fn registration_response(registration: SessionRegistration) -> Result<Response, HttpFailure> {
    let session_id = registration.session_id().as_str().to_owned();
    let expires_after_ms = registration.expires_after_ms();
    let token = registration.take_session_token().into_bytes();
    let token = std::str::from_utf8(&token).map_err(|_| HttpFailure::internal())?;
    json_response(
        StatusCode::CREATED,
        &RegistrationWire {
            schema: SESSION_SCHEMA,
            session_id: &session_id,
            session_token: token,
            expires_after_ms,
            protocol_revision: NATIVE_OAST_PROTOCOL_REVISION,
        },
    )
}

#[derive(Serialize)]
struct AllocationWire<'a> {
    schema: &'static str,
    callback_id: &'a str,
    callback_target: &'a str,
}

fn allocation_response(allocation: CallbackAllocation) -> Result<Response, HttpFailure> {
    let callback_id = allocation.callback_id().as_str().to_owned();
    let target = allocation.take_target().into_string();
    json_response(
        StatusCode::CREATED,
        &AllocationWire {
            schema: CALLBACK_SCHEMA,
            callback_id: &callback_id,
            callback_target: &target,
        },
    )
}

#[derive(Serialize)]
struct PollWire<'a> {
    schema: &'static str,
    session_id: &'a str,
    next_cursor: u64,
    complete: bool,
    expired: bool,
    events: Vec<EventWire<'a>>,
}

#[derive(Serialize)]
struct EventWire<'a> {
    event_id: &'a str,
    callback_id: &'a str,
    protocol: &'static str,
    cursor: u64,
    duplicate_count: u32,
}

fn poll_response(page: PollResponse) -> Result<Response, HttpFailure> {
    let events = page
        .events()
        .iter()
        .map(|event| EventWire {
            event_id: event.event_id().as_str(),
            callback_id: event.callback_id().as_str(),
            protocol: event.protocol().as_str(),
            cursor: event.cursor().as_u64(),
            duplicate_count: event.duplicate_count(),
        })
        .collect();
    json_response(
        StatusCode::OK,
        &PollWire {
            schema: POLL_SCHEMA,
            session_id: page.session_id().as_str(),
            next_cursor: page.next_cursor().as_u64(),
            complete: page.complete(),
            expired: page.expired(),
            events,
        },
    )
}

#[derive(Serialize)]
struct CleanupWire {
    schema: &'static str,
    removed: bool,
}

fn cleanup_response(cleanup: CleanupResponse) -> Result<Response, HttpFailure> {
    json_response(
        StatusCode::OK,
        &CleanupWire {
            schema: CLEANUP_SCHEMA,
            removed: cleanup.removed(),
        },
    )
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Result<Response, HttpFailure> {
    let body = serde_json::to_vec(value).map_err(|_| HttpFailure::internal())?;
    if body.len() > crate::MAX_MANAGEMENT_RESPONSE_BYTES {
        return Err(HttpFailure::internal());
    }
    Ok((
        status,
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static(MANAGEMENT_JSON_MEDIA_TYPE),
            ),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response())
}

fn callback_no_content() -> Response {
    (
        StatusCode::NO_CONTENT,
        [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
    )
        .into_response()
}

fn generic_error(status: StatusCode) -> Response {
    (
        status,
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static(MANAGEMENT_JSON_MEDIA_TYPE),
            ),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        GENERIC_ERROR_JSON,
    )
        .into_response()
}

#[derive(Debug)]
struct HttpFailure(StatusCode);

impl HttpFailure {
    const fn bad_request() -> Self {
        Self(StatusCode::BAD_REQUEST)
    }
    const fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED)
    }
    const fn unsupported_media() -> Self {
        Self(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    }
    const fn unavailable() -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE)
    }
    const fn internal() -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn from_bytes_rejection(rejection: BytesRejection) -> Self {
        Self(rejection.status())
    }

    const fn from_provider(error: ProviderError) -> Self {
        let status = match error {
            ProviderError::Unauthorized => StatusCode::UNAUTHORIZED,
            ProviderError::SessionNotFound | ProviderError::CallbackNotFound => {
                StatusCode::NOT_FOUND
            },
            ProviderError::SessionExpired => StatusCode::GONE,
            ProviderError::SessionCapacityExhausted
            | ProviderError::CallbackCapacityExhausted
            | ProviderError::PollBudgetExhausted
            | ProviderError::EventCapacityExhausted => StatusCode::TOO_MANY_REQUESTS,
            ProviderError::InvalidSessionRequest
            | ProviderError::InvalidCursor
            | ProviderError::InvalidRequestTarget => StatusCode::BAD_REQUEST,
            ProviderError::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ProviderError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ProviderError::Cancelled => StatusCode::SERVICE_UNAVAILABLE,
            ProviderError::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            ProviderError::InvalidConfiguration
            | ProviderError::InvalidPublicOrigin
            | ProviderError::NonLoopbackBindRejected
            | ProviderError::InvalidAdminToken
            | ProviderError::ResponseTooLarge
            | ProviderError::EntropyUnavailable
            | ProviderError::InternalInvariant => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self(status)
    }
}

impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        generic_error(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdminToken, EventCursor, ProviderConfig, ProviderLimits, PublicOrigin, SessionToken,
    };
    use axum::{body::to_bytes, http::Method};
    use serde_json::Value;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{timeout, Duration},
    };

    const ADMIN: &[u8] = b"HTTP-ADMIN-MUST-NOT-LEAK-7C3A19012345";

    fn test_provider(address: std::net::SocketAddr, limits: ProviderLimits) -> ProviderState {
        let origin = PublicOrigin::test_http_loopback(&format!("http://{address}/")).unwrap();
        ProviderState::new(
            ProviderConfig::new(address.to_string().parse().unwrap(), origin, limits),
            AdminToken::new(ADMIN.to_vec()).unwrap(),
        )
        .unwrap()
    }

    fn request(
        method: Method,
        uri: &str,
        body: impl Into<Body>,
        authorization: Option<&str>,
        content_type: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization);
        }
        if let Some(content_type) = content_type {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        builder.body(body.into()).unwrap()
    }

    async fn body_bytes(response: Response) -> Bytes {
        to_bytes(response.into_body(), crate::MAX_MANAGEMENT_RESPONSE_BYTES)
            .await
            .unwrap()
    }

    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&body_bytes(response).await).unwrap()
    }

    async fn assert_generic(response: Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            HeaderValue::from_static(MANAGEMENT_JSON_MEDIA_TYPE)
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
        assert_eq!(body_bytes(response).await.as_ref(), GENERIC_ERROR_JSON);
    }

    #[test]
    fn bearer_parsing_is_exact_and_value_free() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer ADMIN-TOKEN-MUST-NOT-LEAK-4A5F19C2"),
        );
        assert_eq!(
            format!("{:?}", admin_bearer(&headers).unwrap()),
            "ManagementBearer(<redacted>)"
        );
        for invalid in ["bearer abc", "Bearer ", "Bearer two values"] {
            headers.insert(AUTHORIZATION, HeaderValue::from_str(invalid).unwrap());
            assert_eq!(
                admin_bearer(&headers).unwrap_err().0,
                StatusCode::UNAUTHORIZED
            );
        }
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", "x".repeat(4_097))).unwrap(),
        );
        assert_eq!(
            admin_bearer(&headers).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
        let token = SessionToken::from_random([7; 32]).unwrap().into_bytes();
        let session_header = [b"Bearer ".as_slice(), token.as_slice()].concat();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_bytes(&session_header).unwrap(),
        );
        assert_eq!(
            format!("{:?}", session_bearer(&headers).unwrap()),
            "ManagementBearer(<redacted>)"
        );

        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer SECOND-AUTHORIZATION-MUST-BE-REJECTED"),
        );
        assert_eq!(
            session_bearer(&headers).unwrap_err().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn provider_failures_have_closed_generic_status_mapping() {
        let cases = [
            (ProviderError::Unauthorized, StatusCode::UNAUTHORIZED),
            (ProviderError::SessionNotFound, StatusCode::NOT_FOUND),
            (ProviderError::CallbackNotFound, StatusCode::NOT_FOUND),
            (ProviderError::SessionExpired, StatusCode::GONE),
            (
                ProviderError::SessionCapacityExhausted,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ProviderError::CallbackCapacityExhausted,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ProviderError::PollBudgetExhausted,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ProviderError::EventCapacityExhausted,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ProviderError::InvalidSessionRequest,
                StatusCode::BAD_REQUEST,
            ),
            (ProviderError::InvalidCursor, StatusCode::BAD_REQUEST),
            (ProviderError::InvalidRequestTarget, StatusCode::BAD_REQUEST),
            (
                ProviderError::RequestTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                ProviderError::MethodNotAllowed,
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (ProviderError::Cancelled, StatusCode::SERVICE_UNAVAILABLE),
            (ProviderError::DeadlineExceeded, StatusCode::GATEWAY_TIMEOUT),
            (
                ProviderError::InvalidConfiguration,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ProviderError::InvalidPublicOrigin,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ProviderError::NonLoopbackBindRejected,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ProviderError::InvalidAdminToken,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ProviderError::ResponseTooLarge,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ProviderError::EntropyUnavailable,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ProviderError::InternalInvariant,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(HttpFailure::from_provider(error).0, expected);
        }
        assert_eq!(HttpFailure::internal().0, StatusCode::INTERNAL_SERVER_ERROR);
        let response = generic_error(StatusCode::BAD_REQUEST);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
    }

    #[test]
    fn listener_errors_are_static_and_value_free() {
        assert_eq!(
            ProviderServerError::Bind.to_string(),
            "native OAST loopback listener could not bind"
        );
        assert_eq!(
            ProviderServerError::Serve.to_string(),
            "native OAST loopback listener failed"
        );
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn prebound_listener_must_match_the_provider_bind() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_address = listener.local_addr().unwrap();
        let provider_port = if listener_address.port() == 1 { 2 } else { 1 };
        let provider_address = std::net::SocketAddr::new(listener_address.ip(), provider_port);
        let provider = test_provider(
            provider_address,
            ProviderLimits::new(1, 1, 1, 1, 1, 5_000, 1).unwrap(),
        );

        assert_eq!(
            serve_provider_on_listener(listener, provider).await,
            Err(ProviderServerError::Bind)
        );
    }

    #[test]
    fn callback_response_is_constant_and_non_reflective() {
        let response = callback_no_content();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            HeaderValue::from_static("no-store")
        );
    }

    #[tokio::test]
    async fn callback_admission_failure_is_sticky_and_never_reports_complete() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let mut provider = test_provider(
            address,
            ProviderLimits::new(1, 1, 1, 2, 1, 5_000, 1).unwrap(),
        );
        let registration = provider
            .register(
                &AdminToken::new(ADMIN.to_vec()).unwrap(),
                SessionRequest::new(5_000, 1, 1, 2),
            )
            .unwrap();
        let session_id = registration.session_id().clone();
        let session_token = registration.take_session_token();
        let allocation = provider.allocate(&session_id, &session_token).unwrap();
        let callback_id = allocation.callback_id().clone();
        let state = AppState::new(provider);
        state.requests.close();

        let response = observe_callback(
            state.clone(),
            session_id.clone(),
            callback_id.clone(),
            CallbackMethod::Get,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let page = state
            .provider
            .lock()
            .await
            .poll(&session_id, &session_token, EventCursor::default())
            .unwrap();
        assert!(page.events().is_empty());
        assert!(!page.complete());
    }

    #[tokio::test]
    async fn native_http_round_trip_is_fixed_bounded_and_raw_free() {
        const HEADER_SENTINEL: &str = "RAW-HEADER-MUST-NOT-LEAK-9017";
        const QUERY_SENTINEL: &str = "RAW-QUERY-MUST-NOT-LEAK-3918";
        let limits = ProviderLimits::new(2, 3, 4, 4, 4, 5_000, 16).unwrap();
        let address = "127.0.0.1:8080".parse().unwrap();
        let router = provider_router(test_provider(address, limits));
        let admin = format!("Bearer {}", std::str::from_utf8(ADMIN).unwrap());
        let registration_response = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                serde_json::to_vec(&SessionRequest::new(5_000, 3, 4, 4)).unwrap(),
                Some(&admin),
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_eq!(registration_response.status(), StatusCode::CREATED);
        let registration = json_body(registration_response).await;
        let session_id = registration["session_id"].as_str().unwrap();
        let session_token = registration["session_token"].as_str().unwrap();
        let session_bearer = format!("Bearer {session_token}");

        let allocation_response = router
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/sessions/{session_id}/callbacks"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(allocation_response.status(), StatusCode::CREATED);
        let allocation = json_body(allocation_response).await;
        let callback_id = allocation["callback_id"].as_str().unwrap();
        let target = allocation["callback_target"].as_str().unwrap();
        let callback_path = url::Url::parse(target).unwrap().path().to_owned();
        let callback_uri = format!("{callback_path}?private={QUERY_SENTINEL}");
        let mut callback_request = request(
            Method::GET,
            &callback_uri,
            "RAW-BODY-MUST-NOT-LEAK-7821",
            None,
            None,
        );
        callback_request
            .headers_mut()
            .insert("x-private-test", HeaderValue::from_static(HEADER_SENTINEL));
        let first = router.clone().oneshot(callback_request).await.unwrap();
        assert_eq!(first.status(), StatusCode::NO_CONTENT);
        let duplicate = router
            .clone()
            .oneshot(request(
                Method::HEAD,
                &callback_path,
                Body::empty(),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);

        let poll_response = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/v1/sessions/{session_id}/events?after=0"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        let page = json_body(poll_response).await;
        assert_eq!(page["complete"], true);
        assert_eq!(page["expired"], false);
        assert_eq!(page["events"].as_array().unwrap().len(), 1);
        assert_eq!(page["events"][0]["callback_id"], callback_id);
        assert_eq!(page["events"][0]["duplicate_count"], 1);
        let rendered = format!("{page:?}");
        for forbidden in [
            HEADER_SENTINEL,
            QUERY_SENTINEL,
            "RAW-BODY-MUST-NOT-LEAK-7821",
        ] {
            assert!(!rendered.contains(forbidden));
        }

        let cleanup = router
            .clone()
            .oneshot(request(
                Method::DELETE,
                &format!("/v1/sessions/{session_id}"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(cleanup.status(), StatusCode::OK);
        let missing = router
            .oneshot(request(
                Method::GET,
                &format!("/v1/sessions/{session_id}/events?after=0"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_generic(missing, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn raw_request_targets_reject_aliases_without_mutating_provider_state() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let router = provider_router(test_provider(
            address,
            ProviderLimits::new(1, 1, 1, 3, 1, 5_000, 8).unwrap(),
        ));
        let admin = format!("Bearer {}", std::str::from_utf8(ADMIN).unwrap());
        let registration_body = serde_json::to_vec(&SessionRequest::new(5_000, 1, 1, 3)).unwrap();

        let queried_registration = router
            .clone()
            .oneshot(request(
                Method::POST,
                "/v1/sessions?ignored=true",
                registration_body.clone(),
                Some(&admin),
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_generic(queried_registration, StatusCode::BAD_REQUEST).await;

        let registration = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                registration_body,
                Some(&admin),
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_eq!(registration.status(), StatusCode::CREATED);
        let registration = json_body(registration).await;
        let session_id = registration["session_id"].as_str().unwrap();
        let session_bearer = format!("Bearer {}", registration["session_token"].as_str().unwrap());
        let encoded_session = format!("%{:02X}{}", session_id.as_bytes()[0], &session_id[1..]);

        for alias in [
            format!("/v1/sessions/{encoded_session}/callbacks"),
            format!("/v1/sessions/{session_id}/callbacks?ignored=true"),
        ] {
            let response = router
                .clone()
                .oneshot(request(
                    Method::POST,
                    &alias,
                    Body::empty(),
                    Some(&session_bearer),
                    None,
                ))
                .await
                .unwrap();
            assert_generic(response, StatusCode::BAD_REQUEST).await;
        }

        let allocation = router
            .clone()
            .oneshot(request(
                Method::POST,
                &format!("/v1/sessions/{session_id}/callbacks"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(allocation.status(), StatusCode::CREATED);
        let allocation = json_body(allocation).await;
        let callback_id = allocation["callback_id"].as_str().unwrap();
        let encoded_callback = format!("%{:02X}{}", callback_id.as_bytes()[0], &callback_id[1..]);

        let alias_callback = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/c/{session_id}/{encoded_callback}?ignored=true"),
                Body::empty(),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(alias_callback.status(), StatusCode::NO_CONTENT);

        let empty_poll = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/v1/sessions/{session_id}/events?after=0"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert!(json_body(empty_poll).await["events"]
            .as_array()
            .unwrap()
            .is_empty());

        let canonical_callback = router
            .clone()
            .oneshot(request(
                Method::GET,
                &format!("/c/{session_id}/{callback_id}?ignored=true"),
                Body::empty(),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_eq!(canonical_callback.status(), StatusCode::NO_CONTENT);

        for alias in [
            format!("/v1/sessions/{session_id}/events?after=00"),
            format!("/v1/sessions/{session_id}/events?after=%30"),
            format!("/v1/sessions/{session_id}/events?after=0&ignored=true"),
            format!("/v1/sessions/{session_id}?ignored=true"),
        ] {
            let method = if alias.contains("/events?") {
                Method::GET
            } else {
                Method::DELETE
            };
            let response = router
                .clone()
                .oneshot(request(
                    method,
                    &alias,
                    Body::empty(),
                    Some(&session_bearer),
                    None,
                ))
                .await
                .unwrap();
            assert_generic(response, StatusCode::BAD_REQUEST).await;
        }

        let event_poll = router
            .oneshot(request(
                Method::GET,
                &format!("/v1/sessions/{session_id}/events?after=0"),
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(
            json_body(event_poll).await["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn callback_endpoint_is_not_an_identity_oracle() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let router = provider_router(test_provider(
            address,
            ProviderLimits::new(1, 1, 1, 1, 1, 5_000, 4).unwrap(),
        ));
        for path in [
            "/c/not-a-session/not-a-callback",
            "/c/AAAAAAAAAAAAAAAAAAAAAA/BBBBBBBBBBBBBBBBBBBBBB",
            "/c/%FF/BBBBBBBBBBBBBBBBBBBBBB",
        ] {
            let response = router
                .clone()
                .oneshot(request(Method::GET, path, Body::empty(), None, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(body_bytes(response).await.len(), 0);
        }
        let method = router
            .oneshot(request(
                Method::POST,
                "/c/not-a-session/not-a-callback",
                Body::empty(),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_generic(method, StatusCode::METHOD_NOT_ALLOWED).await;
    }

    #[tokio::test]
    async fn management_routes_reject_wrong_auth_media_methods_and_large_bodies() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let router = provider_router(test_provider(
            address,
            ProviderLimits::new(1, 1, 1, 1, 1, 5_000, 4).unwrap(),
        ));
        let body = serde_json::to_vec(&SessionRequest::new(1_000, 1, 1, 1)).unwrap();

        let missing = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                body.clone(),
                None,
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_generic(missing, StatusCode::UNAUTHORIZED).await;

        let wrong = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                body.clone(),
                Some("Bearer WRONG-TOKEN-MUST-NOT-LEAK-401234"),
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_generic(wrong, StatusCode::UNAUTHORIZED).await;

        let admin = format!("Bearer {}", std::str::from_utf8(ADMIN).unwrap());
        let wrong_media = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                body,
                Some(&admin),
                Some("text/plain"),
            ))
            .await
            .unwrap();
        assert_generic(wrong_media, StatusCode::UNSUPPORTED_MEDIA_TYPE).await;

        let oversized = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                vec![b'x'; MAX_MANAGEMENT_BODY_BYTES + 1],
                Some(&admin),
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_generic(oversized, StatusCode::PAYLOAD_TOO_LARGE).await;

        let malformed_query = router
            .clone()
            .oneshot(request(
                Method::GET,
                "/v1/sessions/AAAAAAAAAAAAAAAAAAAAAA/events?after=not-a-cursor",
                Body::empty(),
                Some("Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                None,
            ))
            .await
            .unwrap();
        assert_generic(malformed_query, StatusCode::BAD_REQUEST).await;

        let malformed_path = router
            .clone()
            .oneshot(request(
                Method::GET,
                "/v1/sessions/%FF/events?after=0",
                Body::empty(),
                Some("Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                None,
            ))
            .await
            .unwrap();
        assert_generic(malformed_path, StatusCode::BAD_REQUEST).await;

        let wrong_method = router
            .clone()
            .oneshot(request(
                Method::GET,
                SESSIONS_ROUTE,
                Body::empty(),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_generic(wrong_method, StatusCode::METHOD_NOT_ALLOWED).await;
        let missing_route = router
            .oneshot(request(
                Method::GET,
                "/unimplemented",
                Body::empty(),
                None,
                None,
            ))
            .await
            .unwrap();
        assert_generic(missing_route, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn poll_route_rejects_head_without_spending_poll_budget() {
        let address = "127.0.0.1:8080".parse().unwrap();
        let router = provider_router(test_provider(
            address,
            ProviderLimits::new(1, 1, 1, 1, 1, 5_000, 4).unwrap(),
        ));
        let admin = format!("Bearer {}", std::str::from_utf8(ADMIN).unwrap());
        let registration = router
            .clone()
            .oneshot(request(
                Method::POST,
                SESSIONS_ROUTE,
                serde_json::to_vec(&SessionRequest::new(1_000, 1, 1, 1)).unwrap(),
                Some(&admin),
                Some(MANAGEMENT_JSON_MEDIA_TYPE),
            ))
            .await
            .unwrap();
        assert_eq!(registration.status(), StatusCode::CREATED);
        let registration = json_body(registration).await;
        let session_id = registration["session_id"].as_str().unwrap();
        let session_bearer = format!("Bearer {}", registration["session_token"].as_str().unwrap());
        let poll_target = format!("/v1/sessions/{session_id}/events?after=0");

        let head = router
            .clone()
            .oneshot(request(
                Method::HEAD,
                &poll_target,
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(head.status(), StatusCode::METHOD_NOT_ALLOWED);

        let poll = router
            .oneshot(request(
                Method::GET,
                &poll_target,
                Body::empty(),
                Some(&session_bearer),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(poll.status(), StatusCode::OK);
        assert!(json_body(poll).await["events"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn listener_bounds_concurrently_served_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = test_provider(
            address,
            ProviderLimits::new(1, 1, 1, 1, 1, 5_000, 1).unwrap(),
        );
        let task = tokio::spawn(async move {
            serve_listener(listener, state).await.unwrap();
        });

        let first = TcpStream::connect(address).await.unwrap();
        tokio::task::yield_now().await;
        let mut second = TcpStream::connect(address).await.unwrap();
        second
            .write_all(
                b"GET /unimplemented HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();

        let mut response = [0_u8; 512];
        assert!(
            timeout(Duration::from_millis(100), second.read(&mut response))
                .await
                .is_err()
        );
        drop(first);
        let mut complete_response = Vec::new();
        timeout(
            Duration::from_secs(2),
            second.read_to_end(&mut complete_response),
        )
        .await
        .unwrap()
        .unwrap();
        let response = std::str::from_utf8(&complete_response).unwrap();
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(response.contains(MANAGEMENT_JSON_MEDIA_TYPE));
        task.abort();
    }
}
