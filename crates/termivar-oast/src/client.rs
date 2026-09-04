//! Fixed-route HTTP client for one explicitly configured native OAST provider.
//!
//! The client deliberately exposes no arbitrary URL, method, header, or body
//! surface. A caller-owned boundary admits each operation immediately before
//! dispatch, supplies the shared cancellation/deadline authority, and charges
//! every response byte as reqwest delivers it.

use std::{collections::BTreeSet, fmt};

use reqwest::{
    header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    redirect::Policy as RedirectPolicy,
    Client, Method, RequestBuilder, Response, StatusCode,
};
use serde::{de, de::DeserializeOwned, Deserialize, Deserializer};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    AdminToken, CallbackAllocation, CallbackId, CallbackTarget, CleanupResponse, EventCursor,
    EventId, HttpEventRecord, PollResponse, PublicOrigin, SessionId, SessionRegistration,
    SessionRequest, SessionToken, HARD_MAX_POLL_EVENTS_PER_RESPONSE, MAX_MANAGEMENT_RESPONSE_BYTES,
};

const JSON_MEDIA_TYPE: &str = "application/json";
const REGISTER_PATH: &str = "/v1/sessions";

#[derive(Clone, Copy)]
struct DispatchContract {
    operation: NativeOastClientOperation,
    request_bytes: u64,
    request_body_bytes: u64,
    expected_status: StatusCode,
}

/// One closed native-provider management operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeOastClientOperation {
    /// Create one bounded provider session.
    Register,
    /// Allocate one callback for the addressed session.
    AllocateCallback,
    /// Poll one bounded raw-free event page.
    Poll,
    /// Remove the addressed session and all retained state.
    Cleanup,
}

/// Static caller-authority rejection returned before transport dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeOastBoundaryRejection {
    /// The parent assessment budget cannot admit the operation.
    BudgetExhausted,
    /// The narrowing permit does not allow this operation or transition.
    OperationNotPermitted,
    /// Parent cancellation was already terminal.
    Cancelled,
    /// The shared absolute deadline was already terminal.
    DeadlineExceeded,
    /// The caller-owned accounting boundary contradicted its contract.
    AccountingInvariant,
}

/// Parent-owned authority used for one fixed native-provider operation.
///
/// `observe_response_bytes` must charge all `observed` bytes before returning
/// how many bytes may be retained. Returning less than observed makes the
/// operation fail closed; returning more is an accounting invariant failure.
pub trait NativeOastClientBoundary {
    /// Admits exactly one fixed operation immediately before network dispatch.
    fn begin(
        &mut self,
        operation: NativeOastClientOperation,
        request_bytes: u64,
        request_body_bytes: u64,
    ) -> Result<(), NativeOastBoundaryRejection>;

    /// Shared cancellation authority for the parent assessment.
    fn cancellation_token(&self) -> &CancellationToken;

    /// Shared absolute deadline, already narrowed to the provider permit.
    fn deadline(&self) -> Instant;

    /// Response bytes still available before this operation starts reading.
    fn remaining_response_bytes(&self) -> u64;

    /// Charges every just-delivered response byte and returns retention grant.
    fn observe_response_bytes(&mut self, observed: u64) -> u64;
}

/// Raw-free accounting attached to both success and failure.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeOastDispatchAccounting {
    possibly_dispatched: bool,
    request_bytes: u64,
    request_body_bytes: u64,
    response_bytes: u64,
}

impl NativeOastDispatchAccounting {
    fn planned(request_bytes: u64, request_body_bytes: u64) -> Self {
        Self {
            possibly_dispatched: false,
            request_bytes,
            request_body_bytes,
            response_bytes: 0,
        }
    }

    /// Whether reqwest may have started the wire attempt.
    pub const fn possibly_dispatched(self) -> bool {
        self.possibly_dispatched
    }

    /// Conservative canonical application-request bytes charged to the
    /// provider permit. This covers the fixed method, request target, explicit
    /// headers, and body, while excluding transport framing. Administrator
    /// credentials are charged at their protocol maximum so this value never
    /// reveals actual secret length.
    pub const fn request_bytes(self) -> u64 {
        self.request_bytes
    }

    /// Exact canonical request-body bytes admitted by the boundary.
    pub const fn request_body_bytes(self) -> u64 {
        self.request_body_bytes
    }

    /// Bytes actually delivered from the response body and charged.
    pub const fn response_bytes(self) -> u64 {
        self.response_bytes
    }
}

/// Successful typed result and its exact raw-free accounting.
pub struct NativeOastClientDispatch<T> {
    value: T,
    accounting: NativeOastDispatchAccounting,
}

impl<T> NativeOastClientDispatch<T> {
    /// Borrows the typed protocol result.
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Returns exact dispatch accounting.
    pub const fn accounting(&self) -> NativeOastDispatchAccounting {
        self.accounting
    }

    /// Consumes the dispatch and returns the typed result.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Consumes the dispatch into typed result plus raw-free accounting.
    pub fn into_parts(self) -> (T, NativeOastDispatchAccounting) {
        (self.value, self.accounting)
    }
}

impl<T> fmt::Debug for NativeOastClientDispatch<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastClientDispatch")
            .field("value", &"<typed>")
            .field("accounting", &self.accounting)
            .finish()
    }
}

/// Static, raw-free fixed-client failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeOastClientErrorKind {
    /// The hardened reqwest client could not be constructed.
    ClientInitialization,
    /// A fixed request could not be constructed.
    RequestConstruction,
    /// The caller-owned boundary rejected the operation before dispatch.
    BoundaryRejected(NativeOastBoundaryRejection),
    /// Shared cancellation became terminal.
    Cancelled,
    /// Shared deadline elapsed.
    DeadlineExceeded,
    /// The fixed wire attempt failed.
    TransportFailure,
    /// Provider status did not match the fixed operation contract.
    UnexpectedStatus,
    /// The response URL differed from the exact configured route.
    ResponseOriginMismatch,
    /// The provider response did not carry one exact JSON media type.
    UnsupportedMedia,
    /// The delivered response exceeded a protocol or parent byte ceiling.
    ResponseTooLarge,
    /// The response was not one strict bounded protocol document.
    MalformedResponse,
    /// A decoded response contradicted the requested operation.
    ProtocolMismatch,
    /// The allocated callback target was not the exact configured origin/path.
    CallbackTargetMismatch,
    /// The parent byte observer returned an impossible retention result.
    AccountingInvariant,
}

/// Fixed-client error carrying no URL, body, header, identifier, or secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NativeOastClientError {
    kind: NativeOastClientErrorKind,
    accounting: NativeOastDispatchAccounting,
}

impl NativeOastClientError {
    fn new(kind: NativeOastClientErrorKind, accounting: NativeOastDispatchAccounting) -> Self {
        Self { kind, accounting }
    }

    /// Static error classification.
    pub const fn kind(self) -> NativeOastClientErrorKind {
        self.kind
    }

    /// Exact accounting preserved even on cancellation and failure.
    pub const fn accounting(self) -> NativeOastDispatchAccounting {
        self.accounting
    }
}

impl fmt::Debug for NativeOastClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeOastClientError")
            .field("kind", &self.kind)
            .field("accounting", &self.accounting)
            .finish()
    }
}

impl fmt::Display for NativeOastClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            NativeOastClientErrorKind::ClientInitialization => {
                "native OAST client initialization failed"
            },
            NativeOastClientErrorKind::RequestConstruction => {
                "native OAST fixed request construction failed"
            },
            NativeOastClientErrorKind::BoundaryRejected(_) => {
                "native OAST parent authority rejected the operation"
            },
            NativeOastClientErrorKind::Cancelled => "native OAST operation was cancelled",
            NativeOastClientErrorKind::DeadlineExceeded => "native OAST operation deadline elapsed",
            NativeOastClientErrorKind::TransportFailure => "native OAST fixed transport failed",
            NativeOastClientErrorKind::UnexpectedStatus => {
                "native OAST provider returned an unexpected status"
            },
            NativeOastClientErrorKind::ResponseOriginMismatch => {
                "native OAST provider response origin mismatched"
            },
            NativeOastClientErrorKind::UnsupportedMedia => {
                "native OAST provider response media is unsupported"
            },
            NativeOastClientErrorKind::ResponseTooLarge => {
                "native OAST provider response exceeded a byte ceiling"
            },
            NativeOastClientErrorKind::MalformedResponse => {
                "native OAST provider response was malformed"
            },
            NativeOastClientErrorKind::ProtocolMismatch => {
                "native OAST provider response contradicted the protocol"
            },
            NativeOastClientErrorKind::CallbackTargetMismatch => {
                "native OAST callback target mismatched the configured provider"
            },
            NativeOastClientErrorKind::AccountingInvariant => {
                "native OAST response accounting invariant failed"
            },
        })
    }
}

impl std::error::Error for NativeOastClientError {}

/// Non-cloneable client with one consumed, exact provider origin.
pub struct NativeOastClient {
    public_origin: PublicOrigin,
    origin: Url,
    client: Client,
}

impl NativeOastClient {
    /// Builds a redirect-free, proxy-free, retry-free fixed-route client.
    pub fn new(public_origin: PublicOrigin) -> Result<Self, NativeOastClientError> {
        let origin = Url::parse(public_origin.as_str()).map_err(|_| {
            NativeOastClientError::new(
                NativeOastClientErrorKind::ClientInitialization,
                NativeOastDispatchAccounting::default(),
            )
        })?;
        let client = Client::builder()
            .redirect(RedirectPolicy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .https_only(origin.scheme() == "https")
            .referer(false)
            .http1_only()
            .build()
            .map_err(|_| {
                NativeOastClientError::new(
                    NativeOastClientErrorKind::ClientInitialization,
                    NativeOastDispatchAccounting::default(),
                )
            })?;
        Ok(Self {
            public_origin,
            origin,
            client,
        })
    }

    /// Registers exactly one bounded session using one move-only admin token.
    pub async fn register<B: NativeOastClientBoundary + ?Sized>(
        &self,
        admin_token: AdminToken,
        request: SessionRequest,
        boundary: &mut B,
    ) -> Result<NativeOastClientDispatch<SessionRegistration>, NativeOastClientError> {
        let body = serde_json::to_vec(&request).map_err(|_| {
            NativeOastClientError::new(
                NativeOastClientErrorKind::RequestConstruction,
                NativeOastDispatchAccounting::default(),
            )
        })?;
        let request_body_bytes = u64::try_from(body.len()).map_err(|_| {
            NativeOastClientError::new(
                NativeOastClientErrorKind::RequestConstruction,
                NativeOastDispatchAccounting::default(),
            )
        })?;
        let authorization = bearer_header(admin_token.expose_bytes()).map_err(|kind| {
            NativeOastClientError::new(
                kind,
                NativeOastDispatchAccounting::planned(0, request_body_bytes),
            )
        })?;
        drop(admin_token);
        let url = self.endpoint(REGISTER_PATH, None);
        let request_bytes = canonical_request_bytes(
            &Method::POST,
            &url,
            true,
            crate::secret::MAX_ADMIN_TOKEN_BYTES,
            body.len(),
        )
        .ok_or_else(|| {
            NativeOastClientError::new(
                NativeOastClientErrorKind::RequestConstruction,
                NativeOastDispatchAccounting::planned(0, request_body_bytes),
            )
        })?;
        let builder = self
            .client
            .post(url.clone())
            .header(ACCEPT, HeaderValue::from_static(JSON_MEDIA_TYPE))
            .header(CONTENT_TYPE, HeaderValue::from_static(JSON_MEDIA_TYPE))
            .header(AUTHORIZATION, authorization)
            .body(body);
        let dispatch: NativeOastClientDispatch<RegistrationWire> = self
            .dispatch_wire(
                DispatchContract {
                    operation: NativeOastClientOperation::Register,
                    request_bytes,
                    request_body_bytes,
                    expected_status: StatusCode::CREATED,
                },
                url,
                builder,
                boundary,
            )
            .await?;
        let (wire, accounting) = dispatch.into_parts();
        let value = validate_registration(wire, request, accounting)?;
        Ok(NativeOastClientDispatch { value, accounting })
    }

    /// Allocates exactly one callback for the addressed session.
    pub async fn allocate_callback<B: NativeOastClientBoundary + ?Sized>(
        &self,
        session_id: &SessionId,
        session_token: &SessionToken,
        boundary: &mut B,
    ) -> Result<NativeOastClientDispatch<CallbackAllocation>, NativeOastClientError> {
        let path = format!("/v1/sessions/{}/callbacks", session_id.as_str());
        let url = self.endpoint(&path, None);
        let request_bytes = canonical_request_bytes(
            &Method::POST,
            &url,
            false,
            session_token.expose_bytes().len(),
            0,
        )
        .ok_or_else(request_construction_error)?;
        let builder = self.authenticated_request(Method::POST, url.clone(), session_token)?;
        let dispatch: NativeOastClientDispatch<AllocationWire> = self
            .dispatch_wire(
                DispatchContract {
                    operation: NativeOastClientOperation::AllocateCallback,
                    request_bytes,
                    request_body_bytes: 0,
                    expected_status: StatusCode::CREATED,
                },
                url,
                builder,
                boundary,
            )
            .await?;
        let (wire, accounting) = dispatch.into_parts();
        let value = self.validate_allocation(wire, session_id, accounting)?;
        Ok(NativeOastClientDispatch { value, accounting })
    }

    /// Polls one exact session cursor without blocking or retrying.
    pub async fn poll<B: NativeOastClientBoundary + ?Sized>(
        &self,
        session_id: &SessionId,
        session_token: &SessionToken,
        after: EventCursor,
        boundary: &mut B,
    ) -> Result<NativeOastClientDispatch<PollResponse>, NativeOastClientError> {
        let path = format!("/v1/sessions/{}/events", session_id.as_str());
        let query = format!("after={}", after.as_u64());
        let url = self.endpoint(&path, Some(&query));
        let request_bytes = canonical_request_bytes(
            &Method::GET,
            &url,
            false,
            session_token.expose_bytes().len(),
            0,
        )
        .ok_or_else(request_construction_error)?;
        let builder = self.authenticated_request(Method::GET, url.clone(), session_token)?;
        let dispatch: NativeOastClientDispatch<PollWire> = self
            .dispatch_wire(
                DispatchContract {
                    operation: NativeOastClientOperation::Poll,
                    request_bytes,
                    request_body_bytes: 0,
                    expected_status: StatusCode::OK,
                },
                url,
                builder,
                boundary,
            )
            .await?;
        let (wire, accounting) = dispatch.into_parts();
        let value = validate_poll(wire, session_id, after, accounting)?;
        Ok(NativeOastClientDispatch { value, accounting })
    }

    /// Removes exactly one session. The client performs no cleanup in `Drop`.
    pub async fn cleanup<B: NativeOastClientBoundary + ?Sized>(
        &self,
        session_id: &SessionId,
        session_token: &SessionToken,
        boundary: &mut B,
    ) -> Result<NativeOastClientDispatch<CleanupResponse>, NativeOastClientError> {
        let path = format!("/v1/sessions/{}", session_id.as_str());
        let url = self.endpoint(&path, None);
        let request_bytes = canonical_request_bytes(
            &Method::DELETE,
            &url,
            false,
            session_token.expose_bytes().len(),
            0,
        )
        .ok_or_else(request_construction_error)?;
        let builder = self.authenticated_request(Method::DELETE, url.clone(), session_token)?;
        let dispatch: NativeOastClientDispatch<CleanupWire> = self
            .dispatch_wire(
                DispatchContract {
                    operation: NativeOastClientOperation::Cleanup,
                    request_bytes,
                    request_body_bytes: 0,
                    expected_status: StatusCode::OK,
                },
                url,
                builder,
                boundary,
            )
            .await?;
        let (wire, accounting) = dispatch.into_parts();
        if !wire.removed {
            return Err(NativeOastClientError::new(
                NativeOastClientErrorKind::ProtocolMismatch,
                accounting,
            ));
        }
        Ok(NativeOastClientDispatch {
            value: CleanupResponse::success(),
            accounting,
        })
    }

    fn endpoint(&self, path: &str, query: Option<&str>) -> Url {
        let mut url = self.origin.clone();
        url.set_path(path);
        url.set_query(query);
        url
    }

    fn authenticated_request(
        &self,
        method: Method,
        url: Url,
        session_token: &SessionToken,
    ) -> Result<RequestBuilder, NativeOastClientError> {
        let authorization = bearer_header(session_token.expose_bytes()).map_err(|kind| {
            NativeOastClientError::new(kind, NativeOastDispatchAccounting::default())
        })?;
        Ok(self
            .client
            .request(method, url)
            .header(ACCEPT, HeaderValue::from_static(JSON_MEDIA_TYPE))
            .header(AUTHORIZATION, authorization))
    }

    async fn dispatch_wire<W, B>(
        &self,
        contract: DispatchContract,
        expected_url: Url,
        builder: RequestBuilder,
        boundary: &mut B,
    ) -> Result<NativeOastClientDispatch<W>, NativeOastClientError>
    where
        W: DeserializeOwned,
        B: NativeOastClientBoundary + ?Sized,
    {
        let mut accounting = NativeOastDispatchAccounting::planned(
            contract.request_bytes,
            contract.request_body_bytes,
        );
        let cancellation = boundary.cancellation_token().clone();
        let deadline = boundary.deadline();
        if cancellation.is_cancelled() {
            return Err(NativeOastClientError::new(
                NativeOastClientErrorKind::Cancelled,
                accounting,
            ));
        }
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                NativeOastClientError::new(NativeOastClientErrorKind::DeadlineExceeded, accounting)
            })?;
        if timeout.is_zero() {
            return Err(NativeOastClientError::new(
                NativeOastClientErrorKind::DeadlineExceeded,
                accounting,
            ));
        }
        let request = builder.timeout(timeout).build().map_err(|_| {
            NativeOastClientError::new(NativeOastClientErrorKind::RequestConstruction, accounting)
        })?;
        boundary
            .begin(
                contract.operation,
                contract.request_bytes,
                contract.request_body_bytes,
            )
            .map_err(|rejection| {
                NativeOastClientError::new(
                    NativeOastClientErrorKind::BoundaryRejected(rejection),
                    accounting,
                )
            })?;

        accounting.possibly_dispatched = true;
        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(NativeOastClientError::new(
                    NativeOastClientErrorKind::Cancelled,
                    accounting,
                ));
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(NativeOastClientError::new(
                    NativeOastClientErrorKind::DeadlineExceeded,
                    accounting,
                ));
            }
            result = self.client.execute(request) => result.map_err(|_| {
                NativeOastClientError::new(
                    NativeOastClientErrorKind::TransportFailure,
                    accounting,
                )
            })?,
        };

        validate_response_head(
            &response,
            contract.expected_status,
            &expected_url,
            accounting,
        )?;
        let body = read_response_body(response, boundary, &cancellation, deadline, &mut accounting)
            .await?;
        let value = serde_json::from_slice::<W>(&body).map_err(|_| {
            NativeOastClientError::new(NativeOastClientErrorKind::MalformedResponse, accounting)
        })?;
        ensure_operation_live(&cancellation, deadline, accounting)?;
        Ok(NativeOastClientDispatch { value, accounting })
    }

    fn validate_allocation(
        &self,
        wire: AllocationWire,
        session_id: &SessionId,
        accounting: NativeOastDispatchAccounting,
    ) -> Result<CallbackAllocation, NativeOastClientError> {
        let expected = self
            .public_origin
            .callback_target(session_id, &wire.callback_id)
            .map_err(|_| protocol_error(accounting))?;
        if wire.callback_target.as_str() != expected.as_str() {
            return Err(NativeOastClientError::new(
                NativeOastClientErrorKind::CallbackTargetMismatch,
                accounting,
            ));
        }
        let target = CallbackTarget::from_provider(wire.callback_target.into_string())
            .map_err(|_| protocol_error(accounting))?;
        Ok(CallbackAllocation::new(wire.callback_id, target))
    }
}

impl fmt::Debug for NativeOastClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeOastClient(<configured>)")
    }
}

fn bearer_header(credential: &[u8]) -> Result<HeaderValue, NativeOastClientErrorKind> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(7 + credential.len()));
    bytes.extend_from_slice(b"Bearer ");
    bytes.extend_from_slice(credential);
    let mut value = HeaderValue::from_bytes(&bytes)
        .map_err(|_| NativeOastClientErrorKind::RequestConstruction)?;
    value.set_sensitive(true);
    Ok(value)
}

fn canonical_request_bytes(
    method: &Method,
    url: &Url,
    includes_content_type: bool,
    charged_credential_bytes: usize,
    body_bytes: usize,
) -> Option<u64> {
    let query_bytes = url.query().map_or(0, |query| 1 + query.len());
    let target_bytes = url.path().len().checked_add(query_bytes)?;
    let authorization_value_bytes = b"Bearer ".len().checked_add(charged_credential_bytes)?;
    let mut total = method
        .as_str()
        .len()
        .checked_add(1)?
        .checked_add(target_bytes)?
        .checked_add(2)?;
    total = total.checked_add(canonical_header_bytes(
        ACCEPT.as_str().len(),
        JSON_MEDIA_TYPE.len(),
    )?)?;
    total = total.checked_add(canonical_header_bytes(
        AUTHORIZATION.as_str().len(),
        authorization_value_bytes,
    )?)?;
    if includes_content_type {
        total = total.checked_add(canonical_header_bytes(
            CONTENT_TYPE.as_str().len(),
            JSON_MEDIA_TYPE.len(),
        )?)?;
    }
    total = total.checked_add(2)?.checked_add(body_bytes)?;
    u64::try_from(total).ok()
}

fn canonical_header_bytes(name_bytes: usize, value_bytes: usize) -> Option<usize> {
    name_bytes
        .checked_add(2)?
        .checked_add(value_bytes)?
        .checked_add(2)
}

fn request_construction_error() -> NativeOastClientError {
    NativeOastClientError::new(
        NativeOastClientErrorKind::RequestConstruction,
        NativeOastDispatchAccounting::default(),
    )
}

fn ensure_operation_live(
    cancellation: &CancellationToken,
    deadline: Instant,
    accounting: NativeOastDispatchAccounting,
) -> Result<(), NativeOastClientError> {
    if cancellation.is_cancelled() {
        return Err(NativeOastClientError::new(
            NativeOastClientErrorKind::Cancelled,
            accounting,
        ));
    }
    if Instant::now() >= deadline {
        return Err(NativeOastClientError::new(
            NativeOastClientErrorKind::DeadlineExceeded,
            accounting,
        ));
    }
    Ok(())
}

fn validate_response_head(
    response: &Response,
    expected_status: StatusCode,
    expected_url: &Url,
    accounting: NativeOastDispatchAccounting,
) -> Result<(), NativeOastClientError> {
    if response.url() != expected_url {
        return Err(NativeOastClientError::new(
            NativeOastClientErrorKind::ResponseOriginMismatch,
            accounting,
        ));
    }
    if response.status() != expected_status {
        return Err(NativeOastClientError::new(
            NativeOastClientErrorKind::UnexpectedStatus,
            accounting,
        ));
    }
    let mut media = response.headers().get_all(CONTENT_TYPE).iter();
    if media.next().map(HeaderValue::as_bytes) != Some(JSON_MEDIA_TYPE.as_bytes())
        || media.next().is_some()
    {
        return Err(NativeOastClientError::new(
            NativeOastClientErrorKind::UnsupportedMedia,
            accounting,
        ));
    }
    Ok(())
}

async fn read_response_body<B: NativeOastClientBoundary + ?Sized>(
    mut response: Response,
    boundary: &mut B,
    cancellation: &CancellationToken,
    deadline: Instant,
    accounting: &mut NativeOastDispatchAccounting,
) -> Result<Zeroizing<Vec<u8>>, NativeOastClientError> {
    let hard_limit = u64::try_from(MAX_MANAGEMENT_RESPONSE_BYTES).unwrap_or(u64::MAX);
    let available = boundary.remaining_response_bytes().min(hard_limit);
    if response
        .content_length()
        .is_some_and(|length| length > available)
    {
        return Err(NativeOastClientError::new(
            NativeOastClientErrorKind::ResponseTooLarge,
            *accounting,
        ));
    }

    let mut body = Zeroizing::new(Vec::new());
    loop {
        let next = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                return Err(NativeOastClientError::new(
                    NativeOastClientErrorKind::Cancelled,
                    *accounting,
                ));
            }
            _ = tokio::time::sleep_until(deadline) => {
                return Err(NativeOastClientError::new(
                    NativeOastClientErrorKind::DeadlineExceeded,
                    *accounting,
                ));
            }
            result = response.chunk() => result.map_err(|_| {
                NativeOastClientError::new(
                    NativeOastClientErrorKind::TransportFailure,
                    *accounting,
                )
            })?,
        };
        let Some(chunk) = next else {
            break;
        };
        let observed = u64::try_from(chunk.len()).map_err(|_| {
            NativeOastClientError::new(NativeOastClientErrorKind::AccountingInvariant, *accounting)
        })?;
        accounting.response_bytes =
            accounting
                .response_bytes
                .checked_add(observed)
                .ok_or_else(|| {
                    NativeOastClientError::new(
                        NativeOastClientErrorKind::AccountingInvariant,
                        *accounting,
                    )
                })?;
        let retained = boundary.observe_response_bytes(observed);
        if retained > observed {
            return Err(NativeOastClientError::new(
                NativeOastClientErrorKind::AccountingInvariant,
                *accounting,
            ));
        }
        if retained < observed || accounting.response_bytes > hard_limit {
            return Err(NativeOastClientError::new(
                NativeOastClientErrorKind::ResponseTooLarge,
                *accounting,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_registration(
    wire: RegistrationWire,
    request: SessionRequest,
    accounting: NativeOastDispatchAccounting,
) -> Result<SessionRegistration, NativeOastClientError> {
    if wire.expires_after_ms == 0 || wire.expires_after_ms > request.lifetime_ms() {
        return Err(protocol_error(accounting));
    }
    Ok(SessionRegistration::new(
        wire.session_id,
        wire.session_token.0,
        wire.expires_after_ms,
    ))
}

fn validate_poll(
    wire: PollWire,
    expected_session: &SessionId,
    after: EventCursor,
    accounting: NativeOastDispatchAccounting,
) -> Result<PollResponse, NativeOastClientError> {
    if &wire.session_id != expected_session
        || wire.events.len() > usize::from(HARD_MAX_POLL_EVENTS_PER_RESPONSE)
    {
        return Err(protocol_error(accounting));
    }
    let next_cursor = EventCursor::new(wire.next_cursor).map_err(|_| protocol_error(accounting))?;
    let mut previous = after;
    let mut event_ids = BTreeSet::new();
    let mut callback_ids = BTreeSet::new();
    let mut events = Vec::with_capacity(wire.events.len());
    for event in wire.events {
        let cursor = EventCursor::new(event.cursor).map_err(|_| protocol_error(accounting))?;
        if cursor <= previous
            || event.duplicate_count > u32::from(u16::MAX)
            || !event_ids.insert(event.event_id.clone())
            || !callback_ids.insert(event.callback_id.clone())
        {
            return Err(protocol_error(accounting));
        }
        previous = cursor;
        events.push(HttpEventRecord::new(
            event.event_id,
            event.callback_id,
            cursor,
            event.duplicate_count,
        ));
    }
    if previous != next_cursor || (events.is_empty() && next_cursor != after) {
        return Err(protocol_error(accounting));
    }
    Ok(PollResponse::new(
        wire.session_id,
        next_cursor,
        wire.complete,
        wire.expired,
        events,
    ))
}

fn protocol_error(accounting: NativeOastDispatchAccounting) -> NativeOastClientError {
    NativeOastClientError::new(NativeOastClientErrorKind::ProtocolMismatch, accounting)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationWire {
    #[serde(rename = "schema")]
    _schema: SessionResponseSchema,
    session_id: SessionId,
    session_token: WireSessionToken,
    expires_after_ms: u64,
    #[serde(rename = "protocol_revision")]
    _protocol_revision: ProtocolRevision,
}

#[derive(Deserialize)]
enum SessionResponseSchema {
    #[serde(rename = "security.termivar-oast.session/v1")]
    V1,
}

#[derive(Deserialize)]
enum ProtocolRevision {
    #[serde(rename = "termivar-native-oast/v1")]
    V1,
}

struct WireSessionToken(SessionToken);

impl<'de> Deserialize<'de> for WireSessionToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = WireSessionToken;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one canonical native OAST session token")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                SessionToken::from_encoded(value.as_bytes().to_vec())
                    .map(WireSessionToken)
                    .map_err(|_| E::custom("invalid session token"))
            }

            fn visit_string<E: de::Error>(self, mut value: String) -> Result<Self::Value, E> {
                let bytes = value.as_bytes().to_vec();
                value.zeroize();
                SessionToken::from_encoded(bytes)
                    .map(WireSessionToken)
                    .map_err(|_| E::custom("invalid session token"))
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllocationWire {
    #[serde(rename = "schema")]
    _schema: CallbackResponseSchema,
    callback_id: CallbackId,
    callback_target: WireSecretString,
}

#[derive(Deserialize)]
enum CallbackResponseSchema {
    #[serde(rename = "security.termivar-oast.callback/v1")]
    V1,
}

struct WireSecretString(Zeroizing<String>);

impl WireSecretString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_string(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

impl<'de> Deserialize<'de> for WireSecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = WireSecretString;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("one bounded callback target")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > 2_048 {
                    return Err(E::custom("callback target too large"));
                }
                Ok(WireSecretString(Zeroizing::new(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, mut value: String) -> Result<Self::Value, E> {
                if value.len() > 2_048 {
                    value.zeroize();
                    return Err(E::custom("callback target too large"));
                }
                Ok(WireSecretString(Zeroizing::new(value)))
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PollWire {
    #[serde(rename = "schema")]
    _schema: PollResponseSchema,
    session_id: SessionId,
    next_cursor: u64,
    complete: bool,
    expired: bool,
    events: Vec<EventWire>,
}

#[derive(Deserialize)]
enum PollResponseSchema {
    #[serde(rename = "security.termivar-oast.poll/v1")]
    V1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    event_id: EventId,
    callback_id: CallbackId,
    #[serde(rename = "protocol")]
    _protocol: HttpProtocol,
    cursor: u64,
    duplicate_count: u32,
}

#[derive(Deserialize)]
enum HttpProtocol {
    #[serde(rename = "http")]
    Http,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupWire {
    #[serde(rename = "schema")]
    _schema: CleanupResponseSchema,
    removed: bool,
}

#[derive(Deserialize)]
enum CleanupResponseSchema {
    #[serde(rename = "security.termivar-oast.cleanup/v1")]
    V1,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ProtocolClass, CALLBACK_SCHEMA, CLEANUP_SCHEMA, NATIVE_OAST_PROTOCOL_REVISION, POLL_SCHEMA,
        SESSION_SCHEMA,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const ADMIN_SECRET: &[u8] = b"CLIENT-ADMIN-MUST-NOT-LEAK-63A917F0";

    struct DecodeTerminalAction {
        cancellation: Option<CancellationToken>,
        deadline: Option<Instant>,
        reached: Arc<AtomicBool>,
    }

    tokio::task_local! {
        static DECODE_TERMINAL_ACTION: DecodeTerminalAction;
    }

    struct TerminalAfterDecodeWire;

    impl<'de> Deserialize<'de> for TerminalAfterDecodeWire {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            de::IgnoredAny::deserialize(deserializer)?;
            DECODE_TERMINAL_ACTION.with(|action| {
                action.reached.store(true, Ordering::SeqCst);
                if let Some(deadline) = action.deadline {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if !remaining.is_zero() {
                        std::thread::sleep(remaining + Duration::from_millis(2));
                    }
                }
                if let Some(cancellation) = &action.cancellation {
                    cancellation.cancel();
                }
            });
            Ok(Self)
        }
    }

    struct TestBoundary {
        cancellation: CancellationToken,
        deadline: Instant,
        remaining: u64,
        retain: Option<u64>,
        begun: Vec<(NativeOastClientOperation, u64, u64)>,
        observed: u64,
        rejection: Option<NativeOastBoundaryRejection>,
        cancel_on_observe: bool,
    }

    impl TestBoundary {
        fn open() -> Self {
            Self {
                cancellation: CancellationToken::new(),
                deadline: Instant::now() + Duration::from_secs(5),
                remaining: MAX_MANAGEMENT_RESPONSE_BYTES as u64,
                retain: None,
                begun: Vec::new(),
                observed: 0,
                rejection: None,
                cancel_on_observe: false,
            }
        }
    }

    impl NativeOastClientBoundary for TestBoundary {
        fn begin(
            &mut self,
            operation: NativeOastClientOperation,
            request_bytes: u64,
            request_body_bytes: u64,
        ) -> Result<(), NativeOastBoundaryRejection> {
            if let Some(rejection) = self.rejection {
                return Err(rejection);
            }
            self.begun
                .push((operation, request_bytes, request_body_bytes));
            Ok(())
        }

        fn cancellation_token(&self) -> &CancellationToken {
            &self.cancellation
        }

        fn deadline(&self) -> Instant {
            self.deadline
        }

        fn remaining_response_bytes(&self) -> u64 {
            self.remaining
        }

        fn observe_response_bytes(&mut self, observed: u64) -> u64 {
            self.observed = self.observed.saturating_add(observed);
            if self.cancel_on_observe {
                self.cancellation.cancel();
            }
            self.retain.unwrap_or(observed)
        }
    }

    fn encoded(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn session_id() -> SessionId {
        encoded(&[7; 16]).parse().unwrap()
    }

    fn callback_id() -> CallbackId {
        encoded(&[8; 16]).parse().unwrap()
    }

    fn session_token() -> SessionToken {
        SessionToken::from_encoded(encoded(&[9; 32]).into_bytes()).unwrap()
    }

    fn registration_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": SESSION_SCHEMA,
            "session_id": session_id().as_str(),
            "session_token": encoded(&[9; 32]),
            "expires_after_ms": 1000,
            "protocol_revision": NATIVE_OAST_PROTOCOL_REVISION,
        }))
        .unwrap()
    }

    async fn scripted_response(
        status: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> (
        PublicOrigin,
        Arc<Mutex<Vec<u8>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = PublicOrigin::test_http_loopback(&format!("http://{address}/")).unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_task = Arc::clone(&captured);
        let status = status.to_owned();
        let content_type = content_type.to_owned();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 16 * 1024];
            let read = stream.read(&mut request).await.unwrap();
            request.truncate(read);
            captured_task.lock().unwrap().extend_from_slice(&request);
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        (origin, captured, task)
    }

    #[test]
    fn wire_decoding_is_strict_and_secret_debug_is_redacted() {
        let wire: RegistrationWire = serde_json::from_slice(&registration_json()).unwrap();
        assert_eq!(wire.session_id, session_id());
        assert_eq!(
            format!("{:?}", wire.session_token.0),
            "SessionToken(<redacted>)"
        );
        let unknown_schema = registration_json()
            .windows(SESSION_SCHEMA.len())
            .position(|window| window == SESSION_SCHEMA.as_bytes())
            .unwrap();
        let mut invalid = registration_json();
        invalid[unknown_schema] = b'X';
        assert!(serde_json::from_slice::<RegistrationWire>(&invalid).is_err());
        let invalid_token = serde_json::json!({
            "schema": SESSION_SCHEMA,
            "session_id": session_id().as_str(),
            "session_token": "MUST-NOT-LEAK",
            "expires_after_ms": 1000,
            "protocol_revision": NATIVE_OAST_PROTOCOL_REVISION,
        });
        assert!(serde_json::from_value::<RegistrationWire>(invalid_token).is_err());
    }

    #[tokio::test]
    async fn register_uses_one_fixed_request_and_preserves_exact_accounting() {
        let body = registration_json();
        let expected_response_bytes = body.len() as u64;
        let (origin, captured, task) =
            scripted_response("201 Created", JSON_MEDIA_TYPE, body).await;
        let client = NativeOastClient::new(origin).unwrap();
        let mut boundary = TestBoundary::open();
        let request = SessionRequest::new(1_000, 1, 1, 1);
        let dispatch = client
            .register(
                AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                request,
                &mut boundary,
            )
            .await
            .unwrap();
        task.await.unwrap();

        assert_eq!(dispatch.value().session_id(), &session_id());
        assert_eq!(dispatch.value().expires_after_ms(), 1_000);
        assert!(dispatch.accounting().possibly_dispatched());
        assert_eq!(
            dispatch.accounting().response_bytes(),
            expected_response_bytes
        );
        assert_eq!(boundary.observed, expected_response_bytes);
        assert_eq!(boundary.begun.len(), 1);
        assert_eq!(boundary.begun[0].0, NativeOastClientOperation::Register);
        assert_eq!(boundary.begun[0].1, dispatch.accounting().request_bytes());
        assert_eq!(
            boundary.begun[0].2,
            dispatch.accounting().request_body_bytes()
        );
        assert!(dispatch.accounting().request_bytes() > dispatch.accounting().request_body_bytes());
        let request = captured.lock().unwrap();
        let text = String::from_utf8_lossy(&request);
        assert!(text.starts_with("POST /v1/sessions HTTP/1.1\r\n"));
        assert!(text.contains("accept: application/json\r\n"));
        assert!(text.contains("content-type: application/json\r\n"));
        assert!(text.contains("authorization: Bearer "));
        assert!(!format!("{client:?}").contains(client.public_origin.as_str()));
    }

    #[tokio::test]
    async fn boundary_rejection_and_precancel_never_dispatch() {
        let origin = PublicOrigin::test_http_loopback("http://127.0.0.1:9/").unwrap();
        let client = NativeOastClient::new(origin).unwrap();
        let request = SessionRequest::new(1_000, 1, 1, 1);

        let mut rejected = TestBoundary::open();
        rejected.rejection = Some(NativeOastBoundaryRejection::BudgetExhausted);
        let error = client
            .register(
                AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                request,
                &mut rejected,
            )
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            NativeOastClientErrorKind::BoundaryRejected(
                NativeOastBoundaryRejection::BudgetExhausted
            )
        );
        assert!(!error.accounting().possibly_dispatched());

        let mut cancelled = TestBoundary::open();
        cancelled.cancellation.cancel();
        let error = client
            .register(
                AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                request,
                &mut cancelled,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), NativeOastClientErrorKind::Cancelled);
        assert!(!error.accounting().possibly_dispatched());
        assert!(cancelled.begun.is_empty());
    }

    #[tokio::test]
    async fn response_media_status_and_malformed_wire_fail_without_raw_values() {
        for (status, media, body, expected) in [
            (
                "403 Forbidden",
                JSON_MEDIA_TYPE,
                b"{\"secret\":\"MUST-NOT-LEAK\"}".to_vec(),
                NativeOastClientErrorKind::UnexpectedStatus,
            ),
            (
                "201 Created",
                "text/plain",
                registration_json(),
                NativeOastClientErrorKind::UnsupportedMedia,
            ),
            (
                "201 Created",
                JSON_MEDIA_TYPE,
                b"{bad json MUST-NOT-LEAK".to_vec(),
                NativeOastClientErrorKind::MalformedResponse,
            ),
        ] {
            let (origin, _, task) = scripted_response(status, media, body).await;
            let client = NativeOastClient::new(origin).unwrap();
            let error = client
                .register(
                    AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                    SessionRequest::new(1_000, 1, 1, 1),
                    &mut TestBoundary::open(),
                )
                .await
                .unwrap_err();
            task.await.unwrap();
            assert_eq!(error.kind(), expected);
            assert!(!format!("{error:?}").contains("MUST-NOT-LEAK"));
            assert!(!error.to_string().contains("MUST-NOT-LEAK"));
        }
    }

    #[tokio::test]
    async fn cleanup_removed_false_and_registration_lifetime_mismatch_fail_closed() {
        let body = serde_json::to_vec(&serde_json::json!({
            "schema": CLEANUP_SCHEMA,
            "removed": false,
        }))
        .unwrap();
        let expected = body.len() as u64;
        let (origin, _, task) = scripted_response("200 OK", JSON_MEDIA_TYPE, body).await;
        let client = NativeOastClient::new(origin).unwrap();
        let error = client
            .cleanup(&session_id(), &session_token(), &mut TestBoundary::open())
            .await
            .unwrap_err();
        task.await.unwrap();
        assert_eq!(error.kind(), NativeOastClientErrorKind::ProtocolMismatch);
        assert_eq!(error.accounting().response_bytes(), expected);

        let wire: RegistrationWire = serde_json::from_slice(&registration_json()).unwrap();
        let error = validate_registration(
            wire,
            SessionRequest::new(999, 1, 1, 1),
            NativeOastDispatchAccounting::planned(173, 41),
        )
        .unwrap_err();
        assert_eq!(error.kind(), NativeOastClientErrorKind::ProtocolMismatch);
        assert_eq!(error.accounting().request_bytes(), 173);
        assert_eq!(error.accounting().request_body_bytes(), 41);
    }

    #[tokio::test]
    async fn every_delivered_byte_is_charged_before_retention_failure() {
        let body = registration_json();
        let expected = body.len() as u64;
        let (origin, _, task) = scripted_response("201 Created", JSON_MEDIA_TYPE, body).await;
        let client = NativeOastClient::new(origin).unwrap();
        let mut boundary = TestBoundary::open();
        boundary.retain = Some(0);
        let error = client
            .register(
                AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                SessionRequest::new(1_000, 1, 1, 1),
                &mut boundary,
            )
            .await
            .unwrap_err();
        task.await.unwrap();
        assert_eq!(error.kind(), NativeOastClientErrorKind::ResponseTooLarge);
        assert_eq!(error.accounting().response_bytes(), expected);
        assert_eq!(boundary.observed, expected);
    }

    #[tokio::test]
    async fn response_budget_accounting_and_midstream_cancellation_fail_closed() {
        for mode in ["remaining", "observer", "cancel"] {
            let body = registration_json();
            let expected = body.len() as u64;
            let (origin, _, task) = scripted_response("201 Created", JSON_MEDIA_TYPE, body).await;
            let client = NativeOastClient::new(origin).unwrap();
            let mut boundary = TestBoundary::open();
            match mode {
                "remaining" => boundary.remaining = expected - 1,
                "observer" => boundary.retain = Some(u64::MAX),
                "cancel" => boundary.cancel_on_observe = true,
                _ => unreachable!(),
            }
            let error = client
                .register(
                    AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                    SessionRequest::new(1_000, 1, 1, 1),
                    &mut boundary,
                )
                .await
                .unwrap_err();
            task.await.unwrap();
            match mode {
                "remaining" => {
                    assert_eq!(error.kind(), NativeOastClientErrorKind::ResponseTooLarge);
                    assert_eq!(boundary.observed, 0);
                    assert_eq!(error.accounting().response_bytes(), 0);
                },
                "observer" => {
                    assert_eq!(error.kind(), NativeOastClientErrorKind::AccountingInvariant);
                    assert_eq!(boundary.observed, expected);
                    assert_eq!(error.accounting().response_bytes(), expected);
                },
                "cancel" => {
                    assert_eq!(error.kind(), NativeOastClientErrorKind::Cancelled);
                    assert_eq!(boundary.observed, expected);
                    assert_eq!(error.accounting().response_bytes(), expected);
                },
                _ => unreachable!(),
            }
            assert!(error.accounting().possibly_dispatched());
        }
    }

    #[tokio::test]
    async fn terminal_state_after_body_decode_cannot_return_success() {
        for mode in ["cancel", "deadline"] {
            let body = b"{}".to_vec();
            let expected = body.len() as u64;
            let (origin, _, task) = scripted_response("201 Created", JSON_MEDIA_TYPE, body).await;
            let client = NativeOastClient::new(origin).unwrap();
            let mut boundary = TestBoundary::open();
            let reached = Arc::new(AtomicBool::new(false));
            if mode == "deadline" {
                boundary.deadline = Instant::now() + Duration::from_secs(1);
            }
            let url = client.endpoint(REGISTER_PATH, None);
            let builder = client
                .client
                .post(url.clone())
                .header(ACCEPT, HeaderValue::from_static(JSON_MEDIA_TYPE));
            let action = DecodeTerminalAction {
                cancellation: (mode == "cancel").then(|| boundary.cancellation.clone()),
                deadline: (mode == "deadline").then_some(boundary.deadline),
                reached: Arc::clone(&reached),
            };
            let dispatch = DECODE_TERMINAL_ACTION
                .scope(
                    action,
                    client.dispatch_wire::<TerminalAfterDecodeWire, _>(
                        DispatchContract {
                            operation: NativeOastClientOperation::Register,
                            request_bytes: 2,
                            request_body_bytes: 0,
                            expected_status: StatusCode::CREATED,
                        },
                        url,
                        builder,
                        &mut boundary,
                    ),
                )
                .await;
            task.await.unwrap();

            let error = dispatch.unwrap_err();
            assert!(reached.load(Ordering::SeqCst));
            assert_eq!(error.accounting().response_bytes(), expected);
            assert!(error.accounting().possibly_dispatched());
            assert_eq!(
                error.kind(),
                if mode == "cancel" {
                    NativeOastClientErrorKind::Cancelled
                } else {
                    NativeOastClientErrorKind::DeadlineExceeded
                }
            );
        }
    }

    #[tokio::test]
    async fn expired_deadline_is_rejected_before_boundary_or_dispatch() {
        let origin = PublicOrigin::test_http_loopback("http://127.0.0.1:9/").unwrap();
        let client = NativeOastClient::new(origin).unwrap();
        let mut boundary = TestBoundary::open();
        boundary.deadline = Instant::now() - Duration::from_millis(1);
        let error = client
            .register(
                AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                SessionRequest::new(1_000, 1, 1, 1),
                &mut boundary,
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), NativeOastClientErrorKind::DeadlineExceeded);
        assert!(!error.accounting().possibly_dispatched());
        assert!(boundary.begun.is_empty());
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn fixed_client_completes_the_real_provider_lifecycle() {
        use crate::{
            serve_provider_on_listener, LoopbackBind, ProviderConfig, ProviderLimits, ProviderState,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin = PublicOrigin::from_test_loopback(address).unwrap();
        let limits = ProviderLimits::new(1, 1, 2, 2, 2, 5_000, 4).unwrap();
        let provider = ProviderState::new(
            ProviderConfig::new(LoopbackBind::new(address).unwrap(), origin.clone(), limits),
            AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
        )
        .unwrap();
        let server = tokio::spawn(serve_provider_on_listener(listener, provider));
        let client = NativeOastClient::new(origin).unwrap();

        let registration = client
            .register(
                AdminToken::new(ADMIN_SECRET.to_vec()).unwrap(),
                SessionRequest::new(5_000, 1, 2, 2),
                &mut TestBoundary::open(),
            )
            .await
            .unwrap()
            .into_value();
        let session_id = registration.session_id().clone();
        let session_token = registration.take_session_token();
        let allocation = client
            .allocate_callback(&session_id, &session_token, &mut TestBoundary::open())
            .await
            .unwrap()
            .into_value();
        let callback_id = allocation.callback_id().clone();
        let target = allocation.take_target();

        let callback_client = Client::builder()
            .no_proxy()
            .redirect(RedirectPolicy::none())
            .retry(reqwest::retry::never())
            .build()
            .unwrap();
        assert_eq!(
            callback_client
                .get(target.as_str())
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );

        let poll = client
            .poll(
                &session_id,
                &session_token,
                EventCursor::default(),
                &mut TestBoundary::open(),
            )
            .await
            .unwrap()
            .into_value();
        assert!(poll.complete());
        assert_eq!(poll.events().len(), 1);
        assert_eq!(poll.events()[0].callback_id(), &callback_id);
        assert_eq!(poll.events()[0].protocol(), ProtocolClass::Http);

        let cleanup = client
            .cleanup(&session_id, &session_token, &mut TestBoundary::open())
            .await
            .unwrap()
            .into_value();
        assert!(cleanup.removed());
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn allocation_and_poll_validation_fail_closed() {
        let origin = PublicOrigin::test_http_loopback("http://127.0.0.1:8123/").unwrap();
        let client = NativeOastClient::new(origin).unwrap();
        let allocation: AllocationWire = serde_json::from_value(serde_json::json!({
            "schema": CALLBACK_SCHEMA,
            "callback_id": callback_id().as_str(),
            "callback_target": "https://attacker.invalid/c/session/callback",
        }))
        .unwrap();
        let error = client
            .validate_allocation(
                allocation,
                &session_id(),
                NativeOastDispatchAccounting::planned(211, 0),
            )
            .unwrap_err();
        assert_eq!(
            error.kind(),
            NativeOastClientErrorKind::CallbackTargetMismatch
        );
        assert_eq!(error.accounting().request_bytes(), 211);

        let event_id = encoded(&[4; 32]);
        let invalid_poll: PollWire = serde_json::from_value(serde_json::json!({
            "schema": POLL_SCHEMA,
            "session_id": session_id().as_str(),
            "next_cursor": 1,
            "complete": true,
            "expired": false,
            "events": [
                {"event_id": event_id, "callback_id": callback_id().as_str(), "protocol": "http", "cursor": 1, "duplicate_count": 0},
                {"event_id": event_id, "callback_id": callback_id().as_str(), "protocol": "http", "cursor": 2, "duplicate_count": 0}
            ],
        }))
        .unwrap();
        let error = validate_poll(
            invalid_poll,
            &session_id(),
            EventCursor::default(),
            NativeOastDispatchAccounting::planned(199, 0),
        )
        .unwrap_err();
        assert_eq!(error.kind(), NativeOastClientErrorKind::ProtocolMismatch);
        assert_eq!(error.accounting().request_bytes(), 199);

        for invalid_poll in [
            serde_json::json!({
                "schema": "security.termivar-oast.poll/v2",
                "session_id": session_id().as_str(),
                "next_cursor": 0,
                "complete": true,
                "expired": false,
                "events": [],
            }),
            serde_json::json!({
                "schema": POLL_SCHEMA,
                "session_id": session_id().as_str(),
                "next_cursor": 1,
                "complete": true,
                "expired": false,
                "events": [{
                    "event_id": encoded(&[4; 32]),
                    "callback_id": callback_id().as_str(),
                    "protocol": "dns",
                    "cursor": 1,
                    "duplicate_count": 0,
                }],
            }),
        ] {
            assert!(serde_json::from_value::<PollWire>(invalid_poll).is_err());
        }
    }

    #[test]
    fn public_error_and_dispatch_debug_are_raw_free() {
        let error = NativeOastClientError::new(
            NativeOastClientErrorKind::TransportFailure,
            NativeOastDispatchAccounting::planned(91, 19),
        );
        let debug = format!("{error:?}");
        assert!(!debug.contains(ADMIN_SECRET.escape_ascii().to_string().as_str()));
        assert_eq!(error.accounting().request_body_bytes(), 19);
        assert_eq!(error.accounting().request_bytes(), 91);
        assert_eq!(error.to_string(), "native OAST fixed transport failed");
        assert_eq!(SESSION_SCHEMA, "security.termivar-oast.session/v1");
        assert_eq!(CALLBACK_SCHEMA, "security.termivar-oast.callback/v1");
        assert_eq!(POLL_SCHEMA, "security.termivar-oast.poll/v1");
        assert_eq!(CLEANUP_SCHEMA, "security.termivar-oast.cleanup/v1");
        assert_eq!(NATIVE_OAST_PROTOCOL_REVISION, "termivar-native-oast/v1");
        assert_eq!(ProtocolClass::Http.as_str(), "http");
    }
}
