//! One-shot, bounded RFC 6455 execution under the shared web authority.
//!
//! The policy layer validates the operator declaration. This module repeats the
//! security-sensitive checks at the transport boundary, consumes one parent
//! request-accounting lease, and emits only value-free references and counts.

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{lookup_host, TcpStream},
};
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderValue, Response},
        protocol::WebSocketConfig,
        Error as TungsteniteError, Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use tokio_util::sync::CancellationToken;

use crate::{
    runtime_budget::{RequestAccountingBroker, RequestAccountingLease},
    websocket_review::{
        WebSocketOriginMode, WebSocketReviewPolicy, MAX_WEBSOCKET_REVIEW_CONTROL_FRAMES,
        MAX_WEBSOCKET_REVIEW_MESSAGES, MAX_WEBSOCKET_REVIEW_WALL_TIME_MS,
    },
    DecisionExecutionStage, TransportDispatchOutcome,
};

use super::authority::SharedWebRuntimeAuthority;

/// Schema of the immutable WebSocket review audit.
pub const WEBSOCKET_REVIEW_AUDIT_SCHEMA: &str = "security.websocket-review-audit/v1";
/// Stable identity of this opt-in capability.
pub const WEBSOCKET_REVIEW_CAPABILITY_ID: &str = "termivar.websocket-review/v1";
/// Semantic action charged to the parent request-accounting authority.
pub const WEBSOCKET_REVIEW_ACTION_ID: &str = "websocket.review";
/// Transport shape implemented by V1.
pub const WEBSOCKET_REVIEW_TRANSPORT: &str = "rfc6455_http1_upgrade";
/// Authentication shape implemented by V1.
pub const WEBSOCKET_REVIEW_AUTHENTICATION: &str = "anonymous";
/// HTTP/2 extended CONNECT is outside the V1 implementation.
pub const WEBSOCKET_REVIEW_HTTP2_EXTENDED_CONNECT: &str = "unsupported";
/// Byte-counting layer used for partial failures and timeouts.
pub const WEBSOCKET_REVIEW_TRANSPORT_BYTE_SCOPE: &str = "socket_wire_bytes_tls_ciphertext_when_wss";
/// Exactly one connection attempt can be made by one selected review.
pub const MAX_WEBSOCKET_REVIEW_CONNECTIONS: u8 = 1;
/// Aggregate application payload admitted in either direction.
pub const MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION: u64 = 64 * 1024;

/// Conservative limits on conclusions supported by the bounded exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketReviewClaimLimit {
    BrowserOriginSecurityNotEstablished,
    AuthenticationNotEstablished,
    AuthorizationNotEstablished,
    AvailabilityNotEstablished,
    VulnerabilityNotEstablished,
    ExploitabilityNotEstablished,
    ImpactNotEstablished,
    SourceAuthenticityNotEstablished,
}

impl WebSocketReviewClaimLimit {
    /// Stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserOriginSecurityNotEstablished => "browser_origin_security_not_established",
            Self::AuthenticationNotEstablished => "authentication_not_established",
            Self::AuthorizationNotEstablished => "authorization_not_established",
            Self::AvailabilityNotEstablished => "availability_not_established",
            Self::VulnerabilityNotEstablished => "vulnerability_not_established",
            Self::ExploitabilityNotEstablished => "exploitability_not_established",
            Self::ImpactNotEstablished => "impact_not_established",
            Self::SourceAuthenticityNotEstablished => "source_authenticity_not_established",
        }
    }
}

const WEBSOCKET_REVIEW_CLAIM_LIMITS: [WebSocketReviewClaimLimit; 8] = [
    WebSocketReviewClaimLimit::BrowserOriginSecurityNotEstablished,
    WebSocketReviewClaimLimit::AuthenticationNotEstablished,
    WebSocketReviewClaimLimit::AuthorizationNotEstablished,
    WebSocketReviewClaimLimit::AvailabilityNotEstablished,
    WebSocketReviewClaimLimit::VulnerabilityNotEstablished,
    WebSocketReviewClaimLimit::ExploitabilityNotEstablished,
    WebSocketReviewClaimLimit::ImpactNotEstablished,
    WebSocketReviewClaimLimit::SourceAuthenticityNotEstablished,
];

/// Completeness of the exact operator-configured message exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketReviewCompleteness {
    ConfiguredExchangeComplete,
    Incomplete,
}

impl WebSocketReviewCompleteness {
    /// Stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConfiguredExchangeComplete => "configured_exchange_complete",
            Self::Incomplete => "incomplete",
        }
    }
}

/// Coarse terminal state of one selected WebSocket review.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketReviewTerminal {
    /// Every configured message was sent and paired with one application response.
    Completed,
    /// A safe operational failure stopped the exchange.
    Incomplete,
    /// The host cancellation domain stopped the exchange.
    Cancelled,
    /// The lesser of the policy and parent deadlines elapsed.
    DeadlineReached,
    /// A configured, compiled, or parent byte limit stopped the exchange.
    LimitReached,
    /// The one-shot or exact-origin authority refused execution before transport.
    AuthorityRefused,
}

impl WebSocketReviewTerminal {
    /// Stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Incomplete => "incomplete",
            Self::Cancelled => "cancelled",
            Self::DeadlineReached => "deadline_reached",
            Self::LimitReached => "limit_reached",
            Self::AuthorityRefused => "authority_refused",
        }
    }
}

/// Value-free classification of the first execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketReviewFailureKind {
    AuthorityAlreadyMinted,
    EndpointOutsideAuthority,
    ParentAuthorityUnavailable,
    RequestConstruction,
    ConnectionFailed,
    HandshakeRejected,
    ExtensionNegotiationRefused,
    SubprotocolNegotiationRefused,
    SendFailed,
    ReadFailed,
    BinaryMessageUnsupported,
    CloseFailed,
    PeerClosed,
    MessageTooLarge,
    MessageLimitReached,
    ControlFrameLimitReached,
    ApplicationByteLimitReached,
    ParentResponseBudgetReached,
    Cancelled,
    DeadlineReached,
    InternalInvariant,
}

impl WebSocketReviewFailureKind {
    /// Stable reporting token. It never includes a URL, payload, or backend error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityAlreadyMinted => "authority_already_minted",
            Self::EndpointOutsideAuthority => "endpoint_outside_authority",
            Self::ParentAuthorityUnavailable => "parent_authority_unavailable",
            Self::RequestConstruction => "request_construction",
            Self::ConnectionFailed => "connection_failed",
            Self::HandshakeRejected => "handshake_rejected",
            Self::ExtensionNegotiationRefused => "extension_negotiation_refused",
            Self::SubprotocolNegotiationRefused => "subprotocol_negotiation_refused",
            Self::SendFailed => "send_failed",
            Self::ReadFailed => "read_failed",
            Self::BinaryMessageUnsupported => "binary_message_unsupported",
            Self::CloseFailed => "close_failed",
            Self::PeerClosed => "peer_closed",
            Self::MessageTooLarge => "message_too_large",
            Self::MessageLimitReached => "message_limit_reached",
            Self::ControlFrameLimitReached => "control_frame_limit_reached",
            Self::ApplicationByteLimitReached => "application_byte_limit_reached",
            Self::ParentResponseBudgetReached => "parent_response_budget_reached",
            Self::Cancelled => "cancelled",
            Self::DeadlineReached => "deadline_reached",
            Self::InternalInvariant => "internal_invariant",
        }
    }

    const fn terminal(self) -> WebSocketReviewTerminal {
        match self {
            Self::AuthorityAlreadyMinted | Self::EndpointOutsideAuthority => {
                WebSocketReviewTerminal::AuthorityRefused
            },
            Self::MessageTooLarge
            | Self::MessageLimitReached
            | Self::ControlFrameLimitReached
            | Self::ApplicationByteLimitReached
            | Self::ParentResponseBudgetReached => WebSocketReviewTerminal::LimitReached,
            Self::Cancelled => WebSocketReviewTerminal::Cancelled,
            Self::DeadlineReached => WebSocketReviewTerminal::DeadlineReached,
            _ => WebSocketReviewTerminal::Incomplete,
        }
    }
}

/// Result of one configured outbound message and its next application response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketReviewMessageStatus {
    NotSent,
    SentNoResponse,
    ResponseMatched,
    ResponseMismatched,
}

impl WebSocketReviewMessageStatus {
    /// Stable reporting token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotSent => "not_sent",
            Self::SentNoResponse => "sent_no_response",
            Self::ResponseMatched => "response_matched",
            Self::ResponseMismatched => "response_mismatched",
        }
    }
}

/// Payload-free audit of one configured exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketReviewMessageAudit {
    message_reference: String,
    expected_response_reference: String,
    observed_response_reference: Option<String>,
    outbound_length: u64,
    expected_response_length: u64,
    inbound_length: Option<u64>,
    status: WebSocketReviewMessageStatus,
}

impl WebSocketReviewMessageAudit {
    pub fn message_reference(&self) -> &str {
        &self.message_reference
    }

    pub fn expected_response_reference(&self) -> &str {
        &self.expected_response_reference
    }

    pub fn observed_response_reference(&self) -> Option<&str> {
        self.observed_response_reference.as_deref()
    }

    pub const fn outbound_length(&self) -> u64 {
        self.outbound_length
    }

    pub const fn expected_response_length(&self) -> u64 {
        self.expected_response_length
    }

    pub const fn inbound_length(&self) -> Option<u64> {
        self.inbound_length
    }

    pub const fn status(&self) -> WebSocketReviewMessageStatus {
        self.status
    }
}

/// Effective numeric ceilings attached to the audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebSocketReviewExecutionLimits {
    max_connections: u8,
    max_outbound_application_bytes: u64,
    max_inbound_application_bytes: u64,
    max_outbound_message_bytes: u64,
    max_inbound_message_bytes: u64,
    max_messages: u64,
    max_control_frames: u64,
    max_wall_time_ms: u64,
}

impl WebSocketReviewExecutionLimits {
    pub const fn max_connections(self) -> u8 {
        self.max_connections
    }

    pub const fn max_outbound_application_bytes(self) -> u64 {
        self.max_outbound_application_bytes
    }

    pub const fn max_inbound_application_bytes(self) -> u64 {
        self.max_inbound_application_bytes
    }

    pub const fn max_outbound_message_bytes(self) -> u64 {
        self.max_outbound_message_bytes
    }

    pub const fn max_inbound_message_bytes(self) -> u64 {
        self.max_inbound_message_bytes
    }

    pub const fn max_messages(self) -> u64 {
        self.max_messages
    }

    pub const fn max_control_frames(self) -> u64 {
        self.max_control_frames
    }

    pub const fn max_wall_time_ms(self) -> u64 {
        self.max_wall_time_ms
    }
}

/// Redaction-safe result of one selected WebSocket protocol review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAssessmentWebSocketReviewAudit {
    policy_reference: String,
    endpoint_reference: String,
    origin_mode: WebSocketOriginMode,
    subprotocol_requested: bool,
    subprotocol_negotiated: bool,
    request_attempt_count: u8,
    request_admitted_count: u8,
    connection_attempt_count: u8,
    handshake_completed_count: u8,
    configured_message_count: u64,
    outbound_message_count: u64,
    inbound_message_count: u64,
    outbound_control_frame_count: u64,
    inbound_control_frame_count: u64,
    outbound_application_bytes: u64,
    inbound_application_bytes: u64,
    transport_read_bytes: u64,
    transport_write_bytes: u64,
    accounted_request_body_bytes: u64,
    accounted_response_bytes: u64,
    terminal: WebSocketReviewTerminal,
    failure: Option<WebSocketReviewFailureKind>,
    messages: Vec<WebSocketReviewMessageAudit>,
    limits: WebSocketReviewExecutionLimits,
}

impl WebAssessmentWebSocketReviewAudit {
    pub const fn schema(&self) -> &'static str {
        WEBSOCKET_REVIEW_AUDIT_SCHEMA
    }

    pub const fn capability_id(&self) -> &'static str {
        WEBSOCKET_REVIEW_CAPABILITY_ID
    }

    pub const fn selected(&self) -> bool {
        true
    }

    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }

    pub fn endpoint_reference(&self) -> &str {
        &self.endpoint_reference
    }

    pub const fn origin_mode(&self) -> WebSocketOriginMode {
        self.origin_mode
    }

    pub const fn subprotocol_requested(&self) -> bool {
        self.subprotocol_requested
    }

    pub const fn subprotocol_negotiated(&self) -> bool {
        self.subprotocol_negotiated
    }

    pub const fn compression_enabled(&self) -> bool {
        false
    }

    pub const fn reconnect_enabled(&self) -> bool {
        false
    }

    pub const fn authentication(&self) -> &'static str {
        WEBSOCKET_REVIEW_AUTHENTICATION
    }

    pub const fn context(&self) -> &'static str {
        WEBSOCKET_REVIEW_AUTHENTICATION
    }

    pub const fn transport(&self) -> &'static str {
        WEBSOCKET_REVIEW_TRANSPORT
    }

    pub const fn http2_extended_connect(&self) -> &'static str {
        WEBSOCKET_REVIEW_HTTP2_EXTENDED_CONNECT
    }

    pub const fn request_count(&self) -> u8 {
        self.request_admitted_count
    }

    pub const fn request_attempt_count(&self) -> u8 {
        self.request_attempt_count
    }

    pub const fn request_admitted_count(&self) -> u8 {
        self.request_admitted_count
    }

    /// Direct connection attempts. V1 never retries or reconnects.
    pub const fn connection_count(&self) -> u8 {
        self.connection_attempt_count
    }

    pub const fn connection_attempt_count(&self) -> u8 {
        self.connection_attempt_count
    }

    pub const fn handshake_completed_count(&self) -> u8 {
        self.handshake_completed_count
    }

    pub const fn configured_message_count(&self) -> u64 {
        self.configured_message_count
    }

    pub const fn outbound_message_count(&self) -> u64 {
        self.outbound_message_count
    }

    pub const fn inbound_message_count(&self) -> u64 {
        self.inbound_message_count
    }

    pub const fn outbound_control_frame_count(&self) -> u64 {
        self.outbound_control_frame_count
    }

    pub const fn inbound_control_frame_count(&self) -> u64 {
        self.inbound_control_frame_count
    }

    pub const fn outbound_application_bytes(&self) -> u64 {
        self.outbound_application_bytes
    }

    pub const fn inbound_application_bytes(&self) -> u64 {
        self.inbound_application_bytes
    }

    /// Bytes read from the direct socket, including the HTTP Upgrade and
    /// framing; WSS counts encrypted TLS records at this layer.
    pub const fn transport_read_bytes(&self) -> u64 {
        self.transport_read_bytes
    }

    /// Bytes written to the direct socket, with the same scope as reads.
    pub const fn transport_write_bytes(&self) -> u64 {
        self.transport_write_bytes
    }

    pub const fn transport_byte_scope(&self) -> &'static str {
        WEBSOCKET_REVIEW_TRANSPORT_BYTE_SCOPE
    }

    /// HTTP request-body bytes charged to the parent lease. WebSocket payloads
    /// are child-local and this is always zero in V1.
    pub const fn accounted_request_body_bytes(&self) -> u64 {
        self.accounted_request_body_bytes
    }

    /// Raw socket bytes read and charged exactly once to the sole parent lease.
    pub const fn accounted_response_bytes(&self) -> u64 {
        self.accounted_response_bytes
    }

    pub const fn accounted_transport_response_bytes(&self) -> u64 {
        self.accounted_response_bytes
    }

    pub const fn terminal(&self) -> WebSocketReviewTerminal {
        self.terminal
    }

    pub const fn failure(&self) -> Option<WebSocketReviewFailureKind> {
        self.failure
    }

    pub const fn first_failure(&self) -> Option<WebSocketReviewFailureKind> {
        self.failure
    }

    pub const fn completeness(&self) -> WebSocketReviewCompleteness {
        if matches!(self.terminal, WebSocketReviewTerminal::Completed) {
            WebSocketReviewCompleteness::ConfiguredExchangeComplete
        } else {
            WebSocketReviewCompleteness::Incomplete
        }
    }

    pub const fn expected_response_count(&self) -> u64 {
        self.configured_message_count
    }

    pub fn matched_response_count(&self) -> u64 {
        u64::try_from(
            self.messages
                .iter()
                .filter(|message| message.status == WebSocketReviewMessageStatus::ResponseMatched)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    pub fn mismatched_response_count(&self) -> u64 {
        u64::try_from(
            self.messages
                .iter()
                .filter(|message| {
                    message.status == WebSocketReviewMessageStatus::ResponseMismatched
                })
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    pub fn messages(&self) -> &[WebSocketReviewMessageAudit] {
        &self.messages
    }

    pub const fn limits(&self) -> WebSocketReviewExecutionLimits {
        self.limits
    }

    pub const fn claim_limits(&self) -> &'static [WebSocketReviewClaimLimit] {
        &WEBSOCKET_REVIEW_CLAIM_LIMITS
    }

    /// Revalidates bounded counts and local request/response conservation.
    pub fn is_consistent(&self) -> bool {
        let configured = u64::try_from(self.messages.len()).unwrap_or(u64::MAX);
        let outbound_messages = self
            .messages
            .iter()
            .filter(|message| message.status != WebSocketReviewMessageStatus::NotSent)
            .count();
        let inbound_messages = self
            .messages
            .iter()
            .filter(|message| message.inbound_length.is_some())
            .count();
        let outbound_bytes = self
            .messages
            .iter()
            .filter(|message| message.status != WebSocketReviewMessageStatus::NotSent)
            .fold(0_u64, |total, message| {
                total.saturating_add(message.outbound_length)
            });
        let inbound_bytes = self.messages.iter().fold(0_u64, |total, message| {
            total.saturating_add(message.inbound_length.unwrap_or(0))
        });
        let message_rows_are_valid = self.messages.iter().all(|message| {
            message.outbound_length <= self.limits.max_outbound_message_bytes
                && message.expected_response_length <= self.limits.max_inbound_message_bytes
                && match message.status {
                    WebSocketReviewMessageStatus::NotSent => {
                        message.inbound_length.is_none()
                            && message.observed_response_reference.is_none()
                    },
                    WebSocketReviewMessageStatus::SentNoResponse => {
                        message.inbound_length.is_none()
                            && message.observed_response_reference.is_none()
                    },
                    WebSocketReviewMessageStatus::ResponseMatched => {
                        message.inbound_length == Some(message.expected_response_length)
                            && message.observed_response_reference.as_deref()
                                == Some(message.expected_response_reference.as_str())
                    },
                    WebSocketReviewMessageStatus::ResponseMismatched => {
                        message.inbound_length.is_some()
                            && message.observed_response_reference.is_none()
                    },
                }
        });
        let complete = self.terminal == WebSocketReviewTerminal::Completed;
        self.request_attempt_count <= 1
            && self.request_admitted_count <= self.request_attempt_count
            && self.connection_attempt_count <= self.request_admitted_count
            && self.connection_attempt_count <= self.limits.max_connections
            && self.handshake_completed_count <= self.connection_attempt_count
            && (!self.subprotocol_negotiated
                || (self.subprotocol_requested && self.handshake_completed_count == 1))
            && self.configured_message_count == configured
            && self.configured_message_count > 0
            && self.configured_message_count <= self.limits.max_messages
            && self.outbound_message_count == u64::try_from(outbound_messages).unwrap_or(u64::MAX)
            && self.inbound_message_count == u64::try_from(inbound_messages).unwrap_or(u64::MAX)
            && self.inbound_message_count <= self.outbound_message_count
            && self.outbound_application_bytes == outbound_bytes
            && self.inbound_application_bytes == inbound_bytes
            && self.accounted_request_body_bytes == 0
            && self.accounted_response_bytes == self.transport_read_bytes
            && self.transport_read_bytes >= self.inbound_application_bytes
            && self.transport_write_bytes >= self.outbound_application_bytes
            && (self.transport_read_bytes == 0 || self.connection_attempt_count == 1)
            && (self.transport_write_bytes == 0 || self.connection_attempt_count == 1)
            && (self.outbound_message_count == 0 || self.handshake_completed_count == 1)
            && self.outbound_message_count <= self.limits.max_messages
            && self.inbound_message_count <= self.limits.max_messages
            && self
                .outbound_control_frame_count
                .saturating_add(self.inbound_control_frame_count)
                <= self.limits.max_control_frames
            && self.outbound_application_bytes <= self.limits.max_outbound_application_bytes
            && self.inbound_application_bytes <= self.limits.max_inbound_application_bytes
            && self.limits.max_connections == MAX_WEBSOCKET_REVIEW_CONNECTIONS
            && self.limits.max_outbound_application_bytes
                <= MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION
            && self.limits.max_inbound_application_bytes
                <= MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION
            && self.limits.max_messages
                <= u64::try_from(MAX_WEBSOCKET_REVIEW_MESSAGES).unwrap_or(u64::MAX)
            && self.limits.max_control_frames <= u64::from(MAX_WEBSOCKET_REVIEW_CONTROL_FRAMES)
            && self.limits.max_wall_time_ms <= MAX_WEBSOCKET_REVIEW_WALL_TIME_MS
            && message_rows_are_valid
            && if complete {
                self.failure.is_none()
            } else {
                self.failure
                    .is_some_and(|failure| failure.terminal() == self.terminal)
            }
            && (!complete
                || (self.outbound_message_count == self.configured_message_count
                    && self.inbound_message_count == self.configured_message_count))
    }

    fn fail(&mut self, failure: WebSocketReviewFailureKind) {
        self.terminal = failure.terminal();
        self.failure = Some(failure);
    }

    fn cancel(&mut self) {
        self.terminal = WebSocketReviewTerminal::Cancelled;
        self.failure = Some(WebSocketReviewFailureKind::Cancelled);
    }

    fn deadline(&mut self) {
        self.terminal = WebSocketReviewTerminal::DeadlineReached;
        self.failure = Some(WebSocketReviewFailureKind::DeadlineReached);
    }
}

#[derive(Clone, Default)]
struct TransportByteCounters {
    read: Arc<AtomicU64>,
    written: Arc<AtomicU64>,
}

impl TransportByteCounters {
    fn snapshot(&self) -> TransportByteSnapshot {
        TransportByteSnapshot {
            read: self.read.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
        }
    }

    fn add_read(&self, bytes: usize) {
        saturating_atomic_add(&self.read, u64::try_from(bytes).unwrap_or(u64::MAX));
    }

    fn add_written(&self, bytes: usize) {
        saturating_atomic_add(&self.written, u64::try_from(bytes).unwrap_or(u64::MAX));
    }
}

#[derive(Clone, Copy)]
struct TransportByteSnapshot {
    read: u64,
    written: u64,
}

impl TransportByteSnapshot {
    fn delta_from(self, earlier: Self) -> Self {
        Self {
            read: self.read.saturating_sub(earlier.read),
            written: self.written.saturating_sub(earlier.written),
        }
    }
}

fn saturating_atomic_add(counter: &AtomicU64, increment: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(increment))
    });
}

struct CountingStream<T> {
    inner: T,
    counters: TransportByteCounters,
}

impl<T> CountingStream<T> {
    fn new(inner: T) -> (Self, TransportByteCounters) {
        let counters = TransportByteCounters::default();
        (
            Self {
                inner,
                counters: counters.clone(),
            },
            counters,
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        let read = buffer.filled().len().saturating_sub(before);
        if read != 0 {
            this.counters.add_read(read);
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                this.counters.add_written(written);
                Poll::Ready(Ok(written))
            },
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write_vectored(context, buffers) {
            Poll::Ready(Ok(written)) => {
                this.counters.add_written(written);
                Poll::Ready(Ok(written))
            },
            other => other,
        }
    }
}

type CountedWebSocket = WebSocketStream<MaybeTlsStream<CountingStream<TcpStream>>>;

struct RuntimeMessage {
    text: String,
    expected_response_sha256: [u8; 32],
    expected_response_length: u64,
}

/// Consuming executor minted only by [`SharedWebRuntimeAuthority`].
pub(super) struct WebSocketReviewRuntime {
    endpoint: url::Url,
    application_origin: String,
    origin_mode: WebSocketOriginMode,
    subprotocol: Option<String>,
    messages: Vec<RuntimeMessage>,
    request_accounting: RequestAccountingBroker,
    cancellation: CancellationToken,
    parent_deadline: Option<tokio::time::Instant>,
    audit: WebAssessmentWebSocketReviewAudit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WebSocketReviewRuntimeMintError {
    AuthorityAlreadyMinted,
    EndpointOutsideAuthority,
    InternalInvariant,
}

impl WebSocketReviewRuntimeMintError {
    const fn failure(self) -> WebSocketReviewFailureKind {
        match self {
            Self::AuthorityAlreadyMinted => WebSocketReviewFailureKind::AuthorityAlreadyMinted,
            Self::EndpointOutsideAuthority => WebSocketReviewFailureKind::EndpointOutsideAuthority,
            Self::InternalInvariant => WebSocketReviewFailureKind::InternalInvariant,
        }
    }
}

impl WebSocketReviewRuntime {
    pub(super) fn new(
        policy: &WebSocketReviewPolicy,
        application_origin: String,
        request_accounting: RequestAccountingBroker,
        cancellation: CancellationToken,
        parent_deadline: Option<tokio::time::Instant>,
    ) -> Result<Self, WebSocketReviewRuntimeMintError> {
        let mut messages = Vec::with_capacity(policy.message_count());
        let mut message_audits = Vec::with_capacity(policy.message_count());
        let mut configured_bytes = 0_u64;
        let mut configured_expected_bytes = 0_u64;
        for message in policy.execution_messages() {
            let outbound_length = message.outbound_length();
            configured_bytes = configured_bytes.saturating_add(outbound_length);
            configured_expected_bytes =
                configured_expected_bytes.saturating_add(message.expected_response_length());
            messages.push(RuntimeMessage {
                text: message.execution_text().to_owned(),
                expected_response_sha256: *message.expected_response_sha256(),
                expected_response_length: message.expected_response_length(),
            });
            message_audits.push(WebSocketReviewMessageAudit {
                message_reference: message.message_reference().to_owned(),
                expected_response_reference: message.expected_response_reference().to_owned(),
                observed_response_reference: None,
                outbound_length,
                expected_response_length: message.expected_response_length(),
                inbound_length: None,
                status: WebSocketReviewMessageStatus::NotSent,
            });
        }
        if configured_bytes > MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION
            || configured_expected_bytes > MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION
            || messages.len() > MAX_WEBSOCKET_REVIEW_MESSAGES
        {
            return Err(WebSocketReviewRuntimeMintError::InternalInvariant);
        }
        let configured_message_count = u64::try_from(messages.len()).unwrap_or(u64::MAX);
        let limits = WebSocketReviewExecutionLimits {
            max_connections: MAX_WEBSOCKET_REVIEW_CONNECTIONS,
            max_outbound_application_bytes: MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION,
            max_inbound_application_bytes: MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION,
            max_outbound_message_bytes: policy.max_outbound_message_bytes(),
            max_inbound_message_bytes: policy.max_inbound_message_bytes(),
            max_messages: u64::from(policy.max_messages()),
            max_control_frames: u64::from(policy.max_control_frames()),
            max_wall_time_ms: policy.max_wall_time_ms(),
        };
        if limits.max_messages > u64::try_from(MAX_WEBSOCKET_REVIEW_MESSAGES).unwrap_or(u64::MAX)
            || limits.max_control_frames > u64::from(MAX_WEBSOCKET_REVIEW_CONTROL_FRAMES)
            || limits.max_outbound_message_bytes
                > MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION
            || limits.max_inbound_message_bytes
                > MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION
            || limits.max_wall_time_ms > MAX_WEBSOCKET_REVIEW_WALL_TIME_MS
            || configured_message_count > limits.max_messages
            || message_audits.iter().any(|message| {
                message.outbound_length > limits.max_outbound_message_bytes
                    || message.expected_response_length > limits.max_inbound_message_bytes
            })
        {
            return Err(WebSocketReviewRuntimeMintError::InternalInvariant);
        }
        Ok(Self {
            endpoint: policy.execution_endpoint().clone(),
            application_origin,
            origin_mode: policy.origin_mode(),
            subprotocol: policy.execution_subprotocol().map(str::to_owned),
            messages,
            request_accounting,
            cancellation,
            parent_deadline,
            audit: WebAssessmentWebSocketReviewAudit {
                policy_reference: policy.policy_reference().to_owned(),
                endpoint_reference: policy.endpoint_reference().to_owned(),
                origin_mode: policy.origin_mode(),
                subprotocol_requested: policy.execution_subprotocol().is_some(),
                subprotocol_negotiated: false,
                request_attempt_count: 0,
                request_admitted_count: 0,
                connection_attempt_count: 0,
                handshake_completed_count: 0,
                configured_message_count,
                outbound_message_count: 0,
                inbound_message_count: 0,
                outbound_control_frame_count: 0,
                inbound_control_frame_count: 0,
                outbound_application_bytes: 0,
                inbound_application_bytes: 0,
                transport_read_bytes: 0,
                transport_write_bytes: 0,
                accounted_request_body_bytes: 0,
                accounted_response_bytes: 0,
                terminal: WebSocketReviewTerminal::Incomplete,
                failure: Some(WebSocketReviewFailureKind::InternalInvariant),
                messages: message_audits,
                limits,
            },
        })
    }

    pub(super) async fn execute(mut self) -> WebAssessmentWebSocketReviewAudit {
        let local_deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(self.audit.limits.max_wall_time_ms));
        let Some(deadline) = lesser_deadline(local_deadline, self.parent_deadline) else {
            self.audit
                .fail(WebSocketReviewFailureKind::InternalInvariant);
            return self.audit;
        };
        if self.cancellation.is_cancelled() {
            self.audit.cancel();
            return self.audit;
        }
        if tokio::time::Instant::now() >= deadline {
            self.audit.deadline();
            return self.audit;
        }
        self.audit.request_attempt_count = 1;
        let mut lease = match self.request_accounting.try_begin_with_request_body_bytes(
            WEBSOCKET_REVIEW_ACTION_ID,
            DecisionExecutionStage::Passive,
            None,
            0,
        ) {
            Ok(lease) => lease,
            Err(_) => {
                self.audit
                    .fail(WebSocketReviewFailureKind::ParentAuthorityUnavailable);
                return self.audit;
            },
        };
        self.audit.request_admitted_count = 1;
        let transport_outcome = self.execute_with_lease(&mut lease, deadline).await;
        lease.finish(transport_outcome);
        debug_assert!(self.audit.is_consistent());
        self.audit
    }

    async fn execute_with_lease(
        &mut self,
        lease: &mut RequestAccountingLease,
        deadline: tokio::time::Instant,
    ) -> TransportDispatchOutcome {
        let request = match self.client_request() {
            Ok(request) => request,
            Err(failure) => {
                self.audit.fail(failure);
                return TransportDispatchOutcome::TransportFailure;
            },
        };
        let max_inbound = usize::try_from(self.audit.limits.max_inbound_message_bytes)
            .unwrap_or(usize::MAX)
            .min(usize::try_from(MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION).unwrap());
        let websocket_config = WebSocketConfig::default()
            .read_buffer_size(max_inbound.clamp(1024, 16 * 1024))
            .write_buffer_size(0)
            .max_write_buffer_size(
                usize::try_from(MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION)
                    .unwrap()
                    .saturating_add(1024),
            )
            .max_message_size(Some(max_inbound))
            .max_frame_size(Some(max_inbound))
            .accept_unmasked_frames(false);

        let Some(host) = self.endpoint.host_str().map(str::to_owned) else {
            self.audit
                .fail(WebSocketReviewFailureKind::RequestConstruction);
            return TransportDispatchOutcome::TransportFailure;
        };
        let Some(port) = self.endpoint.port_or_known_default() else {
            self.audit
                .fail(WebSocketReviewFailureKind::RequestConstruction);
            return TransportDispatchOutcome::TransportFailure;
        };
        let resolved = match bounded(
            &self.cancellation,
            deadline,
            lookup_host((host.as_str(), port)),
        )
        .await
        {
            Ok(Ok(addresses)) => addresses.min(),
            Ok(Err(_)) => {
                self.audit
                    .fail(WebSocketReviewFailureKind::ConnectionFailed);
                return TransportDispatchOutcome::TransportFailure;
            },
            Err(StepStop::Cancelled) => {
                self.audit.cancel();
                return TransportDispatchOutcome::Cancelled;
            },
            Err(StepStop::Deadline) => {
                self.audit.deadline();
                return TransportDispatchOutcome::RequestTimeout;
            },
        };
        let Some(address) = resolved else {
            self.audit
                .fail(WebSocketReviewFailureKind::ConnectionFailed);
            return TransportDispatchOutcome::TransportFailure;
        };

        self.audit.connection_attempt_count = 1;
        let stream = match bounded(&self.cancellation, deadline, TcpStream::connect(address)).await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => {
                self.audit
                    .fail(WebSocketReviewFailureKind::ConnectionFailed);
                return TransportDispatchOutcome::TransportFailure;
            },
            Err(StepStop::Cancelled) => {
                self.audit.cancel();
                return TransportDispatchOutcome::Cancelled;
            },
            Err(StepStop::Deadline) => {
                self.audit.deadline();
                return TransportDispatchOutcome::RequestTimeout;
            },
        };

        let (stream, counters) = CountingStream::new(stream);
        let read_guard =
            match bounded(&self.cancellation, deadline, lease.acquire_response_read()).await {
                Ok(guard) => guard,
                Err(StepStop::Cancelled) => {
                    self.audit.cancel();
                    return TransportDispatchOutcome::Cancelled;
                },
                Err(StepStop::Deadline) => {
                    self.audit.deadline();
                    return TransportDispatchOutcome::RequestTimeout;
                },
            };
        if lease.remaining_response_bytes() == 0 {
            drop(read_guard);
            self.audit
                .fail(WebSocketReviewFailureKind::ParentResponseBudgetReached);
            return TransportDispatchOutcome::ResponseBudgetReached;
        }
        let before = counters.snapshot();
        let connected = bounded(
            &self.cancellation,
            deadline,
            client_async_tls_with_config(request, stream, Some(websocket_config), None),
        )
        .await;
        let accounting = self.observe_transport_delta(lease, &counters, before);
        drop(read_guard);
        if let Err(outcome) = accounting {
            return outcome;
        }
        let connected = match connected {
            Ok(Ok(connected)) => connected,
            Ok(Err(error)) => {
                self.audit.fail(classify_connect_error(&error));
                return TransportDispatchOutcome::TransportFailure;
            },
            Err(StepStop::Cancelled) => {
                self.audit.cancel();
                return TransportDispatchOutcome::Cancelled;
            },
            Err(StepStop::Deadline) => {
                self.audit.deadline();
                return TransportDispatchOutcome::RequestTimeout;
            },
        };
        let (mut socket, response) = connected;
        self.audit.handshake_completed_count = 1;
        if response.headers().contains_key("sec-websocket-extensions") {
            self.audit
                .fail(WebSocketReviewFailureKind::ExtensionNegotiationRefused);
            return self
                .close_after_failure(
                    &mut socket,
                    lease,
                    &counters,
                    deadline,
                    TransportDispatchOutcome::TransportFailure,
                )
                .await;
        }
        if !subprotocol_matches(&response, self.subprotocol.as_deref()) {
            self.audit
                .fail(WebSocketReviewFailureKind::SubprotocolNegotiationRefused);
            return self
                .close_after_failure(
                    &mut socket,
                    lease,
                    &counters,
                    deadline,
                    TransportDispatchOutcome::TransportFailure,
                )
                .await;
        }
        self.audit.subprotocol_negotiated = self.subprotocol.is_some();

        for index in 0..self.messages.len() {
            if self.audit.outbound_message_count >= self.audit.limits.max_messages {
                self.audit
                    .fail(WebSocketReviewFailureKind::MessageLimitReached);
                return self
                    .close_after_failure(
                        &mut socket,
                        lease,
                        &counters,
                        deadline,
                        TransportDispatchOutcome::TransportFailure,
                    )
                    .await;
            }
            let text = self.messages[index].text.clone();
            let read_guard =
                match bounded(&self.cancellation, deadline, lease.acquire_response_read()).await {
                    Ok(guard) => guard,
                    Err(StepStop::Cancelled) => {
                        self.audit.cancel();
                        return TransportDispatchOutcome::Cancelled;
                    },
                    Err(StepStop::Deadline) => {
                        self.audit.deadline();
                        return TransportDispatchOutcome::RequestTimeout;
                    },
                };
            if lease.remaining_response_bytes() == 0 {
                drop(read_guard);
                self.audit
                    .fail(WebSocketReviewFailureKind::ParentResponseBudgetReached);
                return TransportDispatchOutcome::ResponseBudgetReached;
            }
            let before = counters.snapshot();
            let sent = bounded(
                &self.cancellation,
                deadline,
                socket.send(Message::text(text)),
            )
            .await;
            let accounting = self.observe_transport_delta(lease, &counters, before);
            drop(read_guard);
            if let Err(outcome) = accounting {
                return outcome;
            }
            match sent {
                Ok(Ok(())) => {
                    self.audit.outbound_message_count += 1;
                    self.audit.outbound_application_bytes = self
                        .audit
                        .outbound_application_bytes
                        .saturating_add(self.audit.messages[index].outbound_length);
                    self.audit.messages[index].status =
                        WebSocketReviewMessageStatus::SentNoResponse;
                },
                Ok(Err(_)) => {
                    self.audit.fail(WebSocketReviewFailureKind::SendFailed);
                    return TransportDispatchOutcome::TransportFailure;
                },
                Err(StepStop::Cancelled) => {
                    self.audit.cancel();
                    return TransportDispatchOutcome::Cancelled;
                },
                Err(StepStop::Deadline) => {
                    self.audit.deadline();
                    return TransportDispatchOutcome::RequestTimeout;
                },
            }
            let read_outcome = self
                .read_application_response(&mut socket, lease, &counters, deadline, index)
                .await;
            if let Err(outcome) = read_outcome {
                return outcome;
            }
        }

        match self
            .send_close(
                &mut socket,
                lease,
                &counters,
                deadline,
                WebSocketReviewFailureKind::CloseFailed,
            )
            .await
        {
            Ok(()) => {
                self.audit.terminal = WebSocketReviewTerminal::Completed;
                self.audit.failure = None;
                TransportDispatchOutcome::Completed
            },
            Err(outcome) => outcome,
        }
    }

    async fn read_application_response(
        &mut self,
        socket: &mut CountedWebSocket,
        lease: &mut RequestAccountingLease,
        counters: &TransportByteCounters,
        deadline: tokio::time::Instant,
        index: usize,
    ) -> Result<(), TransportDispatchOutcome> {
        loop {
            let read_guard =
                match bounded(&self.cancellation, deadline, lease.acquire_response_read()).await {
                    Ok(guard) => guard,
                    Err(StepStop::Cancelled) => {
                        self.audit.cancel();
                        return Err(TransportDispatchOutcome::Cancelled);
                    },
                    Err(StepStop::Deadline) => {
                        self.audit.deadline();
                        return Err(TransportDispatchOutcome::RequestTimeout);
                    },
                };
            if lease.remaining_response_bytes() == 0 {
                drop(read_guard);
                self.audit
                    .fail(WebSocketReviewFailureKind::ParentResponseBudgetReached);
                return Err(TransportDispatchOutcome::ResponseBudgetReached);
            }
            let before = counters.snapshot();
            let next = bounded(&self.cancellation, deadline, socket.next()).await;
            let accounting = self.observe_transport_delta(lease, counters, before);
            drop(read_guard);
            accounting?;
            let message = match next {
                Ok(Some(Ok(message))) => message,
                Ok(Some(Err(TungsteniteError::Capacity(_)))) => {
                    self.audit.fail(WebSocketReviewFailureKind::MessageTooLarge);
                    return Err(TransportDispatchOutcome::TransportFailure);
                },
                Ok(Some(Err(_))) => {
                    self.audit.fail(WebSocketReviewFailureKind::ReadFailed);
                    return Err(TransportDispatchOutcome::TransportFailure);
                },
                Ok(None) => {
                    self.audit.fail(WebSocketReviewFailureKind::PeerClosed);
                    return Err(TransportDispatchOutcome::TransportFailure);
                },
                Err(StepStop::Cancelled) => {
                    self.audit.cancel();
                    return Err(TransportDispatchOutcome::Cancelled);
                },
                Err(StepStop::Deadline) => {
                    self.audit.deadline();
                    return Err(TransportDispatchOutcome::RequestTimeout);
                },
            };
            match message {
                Message::Text(text) => {
                    return self.observe_application_payload(index, text.as_bytes());
                },
                Message::Binary(_) => {
                    self.audit
                        .fail(WebSocketReviewFailureKind::BinaryMessageUnsupported);
                    return Err(TransportDispatchOutcome::TransportFailure);
                },
                Message::Ping(_) => {
                    self.observe_inbound_control_and_flush(socket, lease, counters, deadline)
                        .await?;
                },
                Message::Pong(_) => {
                    self.observe_inbound_control()?;
                },
                Message::Close(_) => {
                    self.observe_inbound_control()?;
                    if self
                        .audit
                        .outbound_control_frame_count
                        .saturating_add(self.audit.inbound_control_frame_count)
                        < self.audit.limits.max_control_frames
                    {
                        let read_guard = match bounded(
                            &self.cancellation,
                            deadline,
                            lease.acquire_response_read(),
                        )
                        .await
                        {
                            Ok(guard) => guard,
                            Err(StepStop::Cancelled) => {
                                self.audit.cancel();
                                return Err(TransportDispatchOutcome::Cancelled);
                            },
                            Err(StepStop::Deadline) => {
                                self.audit.deadline();
                                return Err(TransportDispatchOutcome::RequestTimeout);
                            },
                        };
                        let before = counters.snapshot();
                        let flushed = bounded(&self.cancellation, deadline, socket.flush()).await;
                        let accounting = self.observe_transport_delta(lease, counters, before);
                        drop(read_guard);
                        accounting?;
                        match flushed {
                            Ok(Ok(())) => {
                                self.audit.outbound_control_frame_count += 1;
                            },
                            Ok(Err(_)) => {},
                            Err(StepStop::Cancelled) => {
                                self.audit.cancel();
                                return Err(TransportDispatchOutcome::Cancelled);
                            },
                            Err(StepStop::Deadline) => {
                                self.audit.deadline();
                                return Err(TransportDispatchOutcome::RequestTimeout);
                            },
                        }
                    }
                    self.audit.fail(WebSocketReviewFailureKind::PeerClosed);
                    return Err(TransportDispatchOutcome::TransportFailure);
                },
                Message::Frame(_) => {
                    self.audit
                        .fail(WebSocketReviewFailureKind::InternalInvariant);
                    return Err(TransportDispatchOutcome::TransportFailure);
                },
            }
        }
    }

    fn observe_application_payload(
        &mut self,
        index: usize,
        payload: &[u8],
    ) -> Result<(), TransportDispatchOutcome> {
        if self.audit.inbound_message_count >= self.audit.limits.max_messages {
            self.audit
                .fail(WebSocketReviewFailureKind::MessageLimitReached);
            return Err(TransportDispatchOutcome::TransportFailure);
        }
        let payload_length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
        let next_total = self
            .audit
            .inbound_application_bytes
            .saturating_add(payload_length);
        if payload_length > self.audit.limits.max_inbound_message_bytes
            || next_total > self.audit.limits.max_inbound_application_bytes
        {
            self.audit.fail(
                if payload_length > self.audit.limits.max_inbound_message_bytes {
                    WebSocketReviewFailureKind::MessageTooLarge
                } else {
                    WebSocketReviewFailureKind::ApplicationByteLimitReached
                },
            );
            return Err(TransportDispatchOutcome::TransportFailure);
        }
        self.audit.inbound_message_count += 1;
        self.audit.inbound_application_bytes = next_total;
        let observed_digest: [u8; 32] = Sha256::digest(payload).into();
        let matched = payload_length == self.messages[index].expected_response_length
            && observed_digest == self.messages[index].expected_response_sha256;
        let message = &mut self.audit.messages[index];
        message.inbound_length = Some(payload_length);
        message.observed_response_reference =
            matched.then(|| message.expected_response_reference.clone());
        message.status = if matched {
            WebSocketReviewMessageStatus::ResponseMatched
        } else {
            WebSocketReviewMessageStatus::ResponseMismatched
        };
        Ok(())
    }

    fn observe_inbound_control(&mut self) -> Result<(), TransportDispatchOutcome> {
        if self
            .audit
            .inbound_control_frame_count
            .saturating_add(self.audit.outbound_control_frame_count)
            >= self.audit.limits.max_control_frames
        {
            self.audit
                .fail(WebSocketReviewFailureKind::ControlFrameLimitReached);
            return Err(TransportDispatchOutcome::TransportFailure);
        }
        self.audit.inbound_control_frame_count += 1;
        Ok(())
    }

    async fn observe_inbound_control_and_flush(
        &mut self,
        socket: &mut CountedWebSocket,
        lease: &mut RequestAccountingLease,
        counters: &TransportByteCounters,
        deadline: tokio::time::Instant,
    ) -> Result<(), TransportDispatchOutcome> {
        self.observe_inbound_control()?;
        if self
            .audit
            .outbound_control_frame_count
            .saturating_add(self.audit.inbound_control_frame_count)
            >= self.audit.limits.max_control_frames
        {
            self.audit
                .fail(WebSocketReviewFailureKind::ControlFrameLimitReached);
            return Err(TransportDispatchOutcome::TransportFailure);
        }
        let read_guard =
            match bounded(&self.cancellation, deadline, lease.acquire_response_read()).await {
                Ok(guard) => guard,
                Err(StepStop::Cancelled) => {
                    self.audit.cancel();
                    return Err(TransportDispatchOutcome::Cancelled);
                },
                Err(StepStop::Deadline) => {
                    self.audit.deadline();
                    return Err(TransportDispatchOutcome::RequestTimeout);
                },
            };
        let before = counters.snapshot();
        let flushed = bounded(&self.cancellation, deadline, socket.flush()).await;
        let accounting = self.observe_transport_delta(lease, counters, before);
        drop(read_guard);
        accounting?;
        match flushed {
            Ok(Ok(())) => {
                self.audit.outbound_control_frame_count += 1;
                Ok(())
            },
            Ok(Err(_)) => {
                self.audit.fail(WebSocketReviewFailureKind::SendFailed);
                Err(TransportDispatchOutcome::TransportFailure)
            },
            Err(StepStop::Cancelled) => {
                self.audit.cancel();
                Err(TransportDispatchOutcome::Cancelled)
            },
            Err(StepStop::Deadline) => {
                self.audit.deadline();
                Err(TransportDispatchOutcome::RequestTimeout)
            },
        }
    }

    async fn send_close(
        &mut self,
        socket: &mut CountedWebSocket,
        lease: &mut RequestAccountingLease,
        counters: &TransportByteCounters,
        deadline: tokio::time::Instant,
        failure: WebSocketReviewFailureKind,
    ) -> Result<(), TransportDispatchOutcome> {
        if self
            .audit
            .outbound_control_frame_count
            .saturating_add(self.audit.inbound_control_frame_count)
            >= self.audit.limits.max_control_frames
        {
            self.audit
                .fail(WebSocketReviewFailureKind::ControlFrameLimitReached);
            return Err(TransportDispatchOutcome::TransportFailure);
        }
        let read_guard =
            match bounded(&self.cancellation, deadline, lease.acquire_response_read()).await {
                Ok(guard) => guard,
                Err(StepStop::Cancelled) => {
                    self.audit.cancel();
                    return Err(TransportDispatchOutcome::Cancelled);
                },
                Err(StepStop::Deadline) => {
                    self.audit.deadline();
                    return Err(TransportDispatchOutcome::RequestTimeout);
                },
            };
        let before = counters.snapshot();
        let closed = bounded(&self.cancellation, deadline, socket.close(None)).await;
        let accounting = self.observe_transport_delta(lease, counters, before);
        drop(read_guard);
        accounting?;
        match closed {
            Ok(Ok(())) => {
                self.audit.outbound_control_frame_count += 1;
                Ok(())
            },
            Ok(Err(_)) => {
                self.audit.fail(failure);
                Err(TransportDispatchOutcome::TransportFailure)
            },
            Err(StepStop::Cancelled) => {
                self.audit.cancel();
                Err(TransportDispatchOutcome::Cancelled)
            },
            Err(StepStop::Deadline) => {
                self.audit.deadline();
                Err(TransportDispatchOutcome::RequestTimeout)
            },
        }
    }

    fn observe_transport_delta(
        &mut self,
        lease: &mut RequestAccountingLease,
        counters: &TransportByteCounters,
        before: TransportByteSnapshot,
    ) -> Result<(), TransportDispatchOutcome> {
        let delta = counters.snapshot().delta_from(before);
        self.audit.transport_read_bytes =
            self.audit.transport_read_bytes.saturating_add(delta.read);
        self.audit.transport_write_bytes = self
            .audit
            .transport_write_bytes
            .saturating_add(delta.written);
        if delta.read == 0 {
            return Ok(());
        }
        let retained = lease.observe_response_bytes(delta.read);
        self.audit.accounted_response_bytes = self
            .audit
            .accounted_response_bytes
            .saturating_add(delta.read);
        if retained != delta.read || lease.response_budget_reached() {
            self.audit
                .fail(WebSocketReviewFailureKind::ParentResponseBudgetReached);
            return Err(TransportDispatchOutcome::ResponseBudgetReached);
        }
        Ok(())
    }

    async fn close_after_failure(
        &mut self,
        socket: &mut CountedWebSocket,
        lease: &mut RequestAccountingLease,
        counters: &TransportByteCounters,
        deadline: tokio::time::Instant,
        outcome: TransportDispatchOutcome,
    ) -> TransportDispatchOutcome {
        if self
            .audit
            .outbound_control_frame_count
            .saturating_add(self.audit.inbound_control_frame_count)
            >= self.audit.limits.max_control_frames
        {
            return outcome;
        }
        let read_guard =
            match bounded(&self.cancellation, deadline, lease.acquire_response_read()).await {
                Ok(guard) => guard,
                Err(StepStop::Cancelled) => {
                    self.audit.cancel();
                    return TransportDispatchOutcome::Cancelled;
                },
                Err(StepStop::Deadline) => {
                    self.audit.deadline();
                    return TransportDispatchOutcome::RequestTimeout;
                },
            };
        let before = counters.snapshot();
        let closed = bounded(&self.cancellation, deadline, socket.close(None)).await;
        let accounting = self.observe_transport_delta(lease, counters, before);
        drop(read_guard);
        if let Err(accounting_outcome) = accounting {
            return accounting_outcome;
        }
        match closed {
            Ok(Ok(())) => {
                self.audit.outbound_control_frame_count += 1;
                outcome
            },
            Ok(Err(_)) => outcome,
            Err(StepStop::Cancelled) => {
                self.audit.cancel();
                TransportDispatchOutcome::Cancelled
            },
            Err(StepStop::Deadline) => {
                self.audit.deadline();
                TransportDispatchOutcome::RequestTimeout
            },
        }
    }

    fn client_request(
        &self,
    ) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, WebSocketReviewFailureKind> {
        let mut request = self
            .endpoint
            .as_str()
            .into_client_request()
            .map_err(|_| WebSocketReviewFailureKind::RequestConstruction)?;
        let headers = request.headers_mut();
        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "sec-websocket-extensions",
        ] {
            headers.remove(name);
        }
        if self.origin_mode == WebSocketOriginMode::ApplicationOrigin {
            let origin = HeaderValue::from_str(&self.application_origin)
                .map_err(|_| WebSocketReviewFailureKind::RequestConstruction)?;
            headers.insert("origin", origin);
        } else {
            headers.remove("origin");
        }
        if let Some(subprotocol) = self.subprotocol.as_deref() {
            let value = HeaderValue::from_str(subprotocol)
                .map_err(|_| WebSocketReviewFailureKind::RequestConstruction)?;
            headers.insert("sec-websocket-protocol", value);
        } else {
            headers.remove("sec-websocket-protocol");
        }
        Ok(request)
    }
}

/// Executes one selected policy or returns a value-free authority refusal audit.
pub(crate) async fn execute_websocket_review(
    authority: &SharedWebRuntimeAuthority,
    policy: &WebSocketReviewPolicy,
) -> WebAssessmentWebSocketReviewAudit {
    match authority.mint_websocket_review(policy) {
        Ok(runtime) => runtime.execute().await,
        Err(error) => {
            let audit = WebSocketReviewRuntime::new(
                policy,
                String::new(),
                authority.request_accounting().clone(),
                authority.cancellation_token(),
                authority.start().deadline(),
            );
            match audit {
                Ok(runtime) => {
                    let mut audit = runtime.audit;
                    audit.fail(error.failure());
                    audit
                },
                Err(_) => fallback_audit(policy, error.failure()),
            }
        },
    }
}

/// Produces a selected, payload-free audit when the parent assessment stops
/// before WebSocket dispatch is eligible to begin.
pub(crate) fn websocket_review_not_run(
    policy: &WebSocketReviewPolicy,
    failure: WebSocketReviewFailureKind,
) -> WebAssessmentWebSocketReviewAudit {
    fallback_audit(policy, failure)
}

fn fallback_audit(
    policy: &WebSocketReviewPolicy,
    failure: WebSocketReviewFailureKind,
) -> WebAssessmentWebSocketReviewAudit {
    let mut messages = Vec::new();
    for message in policy
        .execution_messages()
        .take(MAX_WEBSOCKET_REVIEW_MESSAGES)
    {
        messages.push(WebSocketReviewMessageAudit {
            message_reference: message.message_reference().to_owned(),
            expected_response_reference: message.expected_response_reference().to_owned(),
            observed_response_reference: None,
            outbound_length: message.outbound_length(),
            expected_response_length: message.expected_response_length(),
            inbound_length: None,
            status: WebSocketReviewMessageStatus::NotSent,
        });
    }
    let mut audit = WebAssessmentWebSocketReviewAudit {
        policy_reference: policy.policy_reference().to_owned(),
        endpoint_reference: policy.endpoint_reference().to_owned(),
        origin_mode: policy.origin_mode(),
        subprotocol_requested: policy.execution_subprotocol().is_some(),
        subprotocol_negotiated: false,
        request_attempt_count: 0,
        request_admitted_count: 0,
        connection_attempt_count: 0,
        handshake_completed_count: 0,
        configured_message_count: u64::try_from(messages.len()).unwrap_or(u64::MAX),
        outbound_message_count: 0,
        inbound_message_count: 0,
        outbound_control_frame_count: 0,
        inbound_control_frame_count: 0,
        outbound_application_bytes: 0,
        inbound_application_bytes: 0,
        transport_read_bytes: 0,
        transport_write_bytes: 0,
        accounted_request_body_bytes: 0,
        accounted_response_bytes: 0,
        terminal: failure.terminal(),
        failure: Some(failure),
        messages,
        limits: WebSocketReviewExecutionLimits {
            max_connections: 1,
            max_outbound_application_bytes: MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION,
            max_inbound_application_bytes: MAX_WEBSOCKET_REVIEW_APPLICATION_BYTES_PER_DIRECTION,
            max_outbound_message_bytes: policy.max_outbound_message_bytes(),
            max_inbound_message_bytes: policy.max_inbound_message_bytes(),
            max_messages: u64::from(policy.max_messages()),
            max_control_frames: u64::from(policy.max_control_frames()),
            max_wall_time_ms: policy.max_wall_time_ms(),
        },
    };
    audit.fail(failure);
    audit
}

fn classify_connect_error(error: &TungsteniteError) -> WebSocketReviewFailureKind {
    match error {
        TungsteniteError::Http(_) => WebSocketReviewFailureKind::HandshakeRejected,
        TungsteniteError::Capacity(_) => WebSocketReviewFailureKind::MessageTooLarge,
        TungsteniteError::Protocol(_) | TungsteniteError::HttpFormat(_) => {
            WebSocketReviewFailureKind::HandshakeRejected
        },
        _ => WebSocketReviewFailureKind::ConnectionFailed,
    }
}

fn subprotocol_matches<B>(response: &Response<B>, expected: Option<&str>) -> bool {
    let observed = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok());
    observed == expected
}

fn lesser_deadline(
    first: Option<tokio::time::Instant>,
    second: Option<tokio::time::Instant>,
) -> Option<tokio::time::Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StepStop {
    Cancelled,
    Deadline,
}

async fn bounded<F>(
    cancellation: &CancellationToken,
    deadline: tokio::time::Instant,
    future: F,
) -> Result<F::Output, StepStop>
where
    F: Future,
{
    tokio::pin!(future);
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(StepStop::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(StepStop::Deadline),
        output = &mut future => Ok(output),
    }
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{websocket_review::WebSocketReviewPolicy, RuntimeBudget};

    fn loopback_policy(
        application: &url::Url,
        endpoint: &url::Url,
        expected_response: &[u8],
        max_wall_time_ms: u64,
    ) -> WebSocketReviewPolicy {
        loopback_policy_with_options(
            application,
            endpoint,
            expected_response,
            max_wall_time_ms,
            None,
            4,
            4096,
        )
    }

    fn loopback_policy_with_options(
        application: &url::Url,
        endpoint: &url::Url,
        expected_response: &[u8],
        max_wall_time_ms: u64,
        subprotocol: Option<&str>,
        max_control_frames: u16,
        max_inbound_message_bytes: u64,
    ) -> WebSocketReviewPolicy {
        let expected_sha256 = format!("{:x}", Sha256::digest(expected_response));
        let source = serde_json::to_vec(&json!({
            "schema": "security.websocket-review-policy/v1",
            "target_authorized": true,
            "messages_read_only_acknowledged": true,
            "message_content_is_non_secret": true,
            "endpoint": endpoint.as_str(),
            "origin_mode": "application_origin",
            "subprotocol": subprotocol,
            "compression": false,
            "reconnect": false,
            "messages": [{
                "id": "loopback-message",
                "text": "request",
                "expected_response": {
                    "sha256": expected_sha256,
                    "length": expected_response.len()
                }
            }],
            "limits": {
                "max_inbound_message_bytes": max_inbound_message_bytes,
                "max_outbound_message_bytes": 4096,
                "max_messages": 1,
                "max_control_frames": max_control_frames,
                "max_wall_time_ms": max_wall_time_ms
            }
        }))
        .unwrap();
        WebSocketReviewPolicy::parse_json(application, &source).unwrap()
    }

    fn runtime(
        policy: &WebSocketReviewPolicy,
        application: &url::Url,
        accounting: RequestAccountingBroker,
    ) -> WebSocketReviewRuntime {
        WebSocketReviewRuntime::new(
            policy,
            application.origin().ascii_serialization(),
            accounting,
            CancellationToken::new(),
            None,
        )
        .unwrap()
    }

    async fn await_server(server: tokio::task::JoinHandle<()>) {
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("loopback server did not finish within the bounded test window")
            .expect("loopback server task failed");
    }

    #[test]
    fn audit_vocabulary_fallback_and_public_accessors_are_total() {
        assert_eq!(
            WebSocketReviewCompleteness::ConfiguredExchangeComplete.as_str(),
            "configured_exchange_complete"
        );
        assert_eq!(
            WebSocketReviewCompleteness::Incomplete.as_str(),
            "incomplete"
        );
        for (terminal, token) in [
            (WebSocketReviewTerminal::Completed, "completed"),
            (WebSocketReviewTerminal::Incomplete, "incomplete"),
            (WebSocketReviewTerminal::Cancelled, "cancelled"),
            (WebSocketReviewTerminal::DeadlineReached, "deadline_reached"),
            (WebSocketReviewTerminal::LimitReached, "limit_reached"),
            (
                WebSocketReviewTerminal::AuthorityRefused,
                "authority_refused",
            ),
        ] {
            assert_eq!(terminal.as_str(), token);
        }
        let failures = [
            (
                WebSocketReviewFailureKind::AuthorityAlreadyMinted,
                "authority_already_minted",
            ),
            (
                WebSocketReviewFailureKind::EndpointOutsideAuthority,
                "endpoint_outside_authority",
            ),
            (
                WebSocketReviewFailureKind::ParentAuthorityUnavailable,
                "parent_authority_unavailable",
            ),
            (
                WebSocketReviewFailureKind::RequestConstruction,
                "request_construction",
            ),
            (
                WebSocketReviewFailureKind::ConnectionFailed,
                "connection_failed",
            ),
            (
                WebSocketReviewFailureKind::HandshakeRejected,
                "handshake_rejected",
            ),
            (
                WebSocketReviewFailureKind::ExtensionNegotiationRefused,
                "extension_negotiation_refused",
            ),
            (
                WebSocketReviewFailureKind::SubprotocolNegotiationRefused,
                "subprotocol_negotiation_refused",
            ),
            (WebSocketReviewFailureKind::SendFailed, "send_failed"),
            (WebSocketReviewFailureKind::ReadFailed, "read_failed"),
            (
                WebSocketReviewFailureKind::BinaryMessageUnsupported,
                "binary_message_unsupported",
            ),
            (WebSocketReviewFailureKind::CloseFailed, "close_failed"),
            (WebSocketReviewFailureKind::PeerClosed, "peer_closed"),
            (
                WebSocketReviewFailureKind::MessageTooLarge,
                "message_too_large",
            ),
            (
                WebSocketReviewFailureKind::MessageLimitReached,
                "message_limit_reached",
            ),
            (
                WebSocketReviewFailureKind::ControlFrameLimitReached,
                "control_frame_limit_reached",
            ),
            (
                WebSocketReviewFailureKind::ApplicationByteLimitReached,
                "application_byte_limit_reached",
            ),
            (
                WebSocketReviewFailureKind::ParentResponseBudgetReached,
                "parent_response_budget_reached",
            ),
            (WebSocketReviewFailureKind::Cancelled, "cancelled"),
            (
                WebSocketReviewFailureKind::DeadlineReached,
                "deadline_reached",
            ),
            (
                WebSocketReviewFailureKind::InternalInvariant,
                "internal_invariant",
            ),
        ];
        for (failure, token) in failures {
            assert_eq!(failure.as_str(), token);
            let expected_terminal = match failure {
                WebSocketReviewFailureKind::AuthorityAlreadyMinted
                | WebSocketReviewFailureKind::EndpointOutsideAuthority => {
                    WebSocketReviewTerminal::AuthorityRefused
                },
                WebSocketReviewFailureKind::MessageTooLarge
                | WebSocketReviewFailureKind::MessageLimitReached
                | WebSocketReviewFailureKind::ControlFrameLimitReached
                | WebSocketReviewFailureKind::ApplicationByteLimitReached
                | WebSocketReviewFailureKind::ParentResponseBudgetReached => {
                    WebSocketReviewTerminal::LimitReached
                },
                WebSocketReviewFailureKind::Cancelled => WebSocketReviewTerminal::Cancelled,
                WebSocketReviewFailureKind::DeadlineReached => {
                    WebSocketReviewTerminal::DeadlineReached
                },
                _ => WebSocketReviewTerminal::Incomplete,
            };
            assert_eq!(failure.terminal(), expected_terminal);
        }
        for (status, token) in [
            (WebSocketReviewMessageStatus::NotSent, "not_sent"),
            (
                WebSocketReviewMessageStatus::SentNoResponse,
                "sent_no_response",
            ),
            (
                WebSocketReviewMessageStatus::ResponseMatched,
                "response_matched",
            ),
            (
                WebSocketReviewMessageStatus::ResponseMismatched,
                "response_mismatched",
            ),
        ] {
            assert_eq!(status.as_str(), token);
        }

        let application = url::Url::parse("http://127.0.0.1:9/application/").unwrap();
        let endpoint = url::Url::parse("ws://127.0.0.1:9/application/socket").unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 1_000);
        let audit = websocket_review_not_run(
            &policy,
            WebSocketReviewFailureKind::ParentAuthorityUnavailable,
        );
        assert_eq!(audit.schema(), WEBSOCKET_REVIEW_AUDIT_SCHEMA);
        assert_eq!(audit.capability_id(), WEBSOCKET_REVIEW_CAPABILITY_ID);
        assert!(audit.selected());
        assert_eq!(audit.policy_reference(), policy.policy_reference());
        assert_eq!(audit.endpoint_reference(), policy.endpoint_reference());
        assert_eq!(audit.origin_mode(), WebSocketOriginMode::ApplicationOrigin);
        assert!(!audit.subprotocol_requested());
        assert!(!audit.subprotocol_negotiated());
        assert!(!audit.compression_enabled());
        assert!(!audit.reconnect_enabled());
        assert_eq!(audit.authentication(), "anonymous");
        assert_eq!(audit.context(), "anonymous");
        assert_eq!(audit.transport(), WEBSOCKET_REVIEW_TRANSPORT);
        assert_eq!(audit.http2_extended_connect(), "unsupported");
        assert_eq!(audit.request_count(), 0);
        assert_eq!(audit.request_attempt_count(), 0);
        assert_eq!(audit.request_admitted_count(), 0);
        assert_eq!(audit.connection_count(), 0);
        assert_eq!(audit.connection_attempt_count(), 0);
        assert_eq!(audit.handshake_completed_count(), 0);
        assert_eq!(audit.configured_message_count(), 1);
        assert_eq!(audit.outbound_message_count(), 0);
        assert_eq!(audit.inbound_message_count(), 0);
        assert_eq!(audit.outbound_control_frame_count(), 0);
        assert_eq!(audit.inbound_control_frame_count(), 0);
        assert_eq!(audit.outbound_application_bytes(), 0);
        assert_eq!(audit.inbound_application_bytes(), 0);
        assert_eq!(audit.transport_read_bytes(), 0);
        assert_eq!(audit.transport_write_bytes(), 0);
        assert_eq!(
            audit.transport_byte_scope(),
            WEBSOCKET_REVIEW_TRANSPORT_BYTE_SCOPE
        );
        assert_eq!(audit.accounted_request_body_bytes(), 0);
        assert_eq!(audit.accounted_response_bytes(), 0);
        assert_eq!(audit.accounted_transport_response_bytes(), 0);
        assert_eq!(audit.terminal(), WebSocketReviewTerminal::Incomplete);
        assert_eq!(
            audit.failure(),
            Some(WebSocketReviewFailureKind::ParentAuthorityUnavailable)
        );
        assert_eq!(audit.first_failure(), audit.failure());
        assert_eq!(
            audit.completeness(),
            WebSocketReviewCompleteness::Incomplete
        );
        assert_eq!(audit.expected_response_count(), 1);
        assert_eq!(audit.matched_response_count(), 0);
        assert_eq!(audit.mismatched_response_count(), 0);
        assert_eq!(audit.messages().len(), 1);
        let message = &audit.messages()[0];
        assert_eq!(
            message.message_reference(),
            policy.messages().next().unwrap().message_reference()
        );
        assert_eq!(
            message.expected_response_reference(),
            policy
                .messages()
                .next()
                .unwrap()
                .expected_response_reference()
        );
        assert_eq!(message.observed_response_reference(), None);
        assert_eq!(message.outbound_length(), 7);
        assert_eq!(message.expected_response_length(), 8);
        assert_eq!(message.inbound_length(), None);
        assert_eq!(message.status(), WebSocketReviewMessageStatus::NotSent);
        let limits = audit.limits();
        assert_eq!(limits.max_connections(), 1);
        assert_eq!(limits.max_outbound_application_bytes(), 64 * 1024);
        assert_eq!(limits.max_inbound_application_bytes(), 64 * 1024);
        assert_eq!(limits.max_outbound_message_bytes(), 4096);
        assert_eq!(limits.max_inbound_message_bytes(), 4096);
        assert_eq!(limits.max_messages(), 1);
        assert_eq!(limits.max_control_frames(), 4);
        assert_eq!(limits.max_wall_time_ms(), 1_000);
        assert_eq!(audit.claim_limits().len(), 8);
        assert!(audit.is_consistent());
        assert_eq!(
            WebSocketReviewRuntimeMintError::AuthorityAlreadyMinted.failure(),
            WebSocketReviewFailureKind::AuthorityAlreadyMinted
        );
        assert_eq!(
            WebSocketReviewRuntimeMintError::EndpointOutsideAuthority.failure(),
            WebSocketReviewFailureKind::EndpointOutsideAuthority
        );
        assert_eq!(
            WebSocketReviewRuntimeMintError::InternalInvariant.failure(),
            WebSocketReviewFailureKind::InternalInvariant
        );
        assert!(lesser_deadline(None, None).is_none());
    }

    #[tokio::test]
    async fn parent_request_and_response_limits_refuse_transport_at_the_owned_boundary() {
        let application = url::Url::parse("http://127.0.0.1:9/application/").unwrap();
        let endpoint = url::Url::parse("ws://127.0.0.1:9/application/socket").unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 1_000);
        let request_refused = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_total_requests(0)),
        )
        .execute()
        .await;
        assert_eq!(request_refused.request_attempt_count(), 1);
        assert_eq!(request_refused.request_admitted_count(), 0);
        assert_eq!(request_refused.connection_attempt_count(), 0);
        assert_eq!(
            request_refused.first_failure(),
            Some(WebSocketReviewFailureKind::ParentAuthorityUnavailable)
        );
        assert!(request_refused.is_consistent());

        let response_preflight_refused = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_response_bytes(0)),
        )
        .execute()
        .await;
        assert_eq!(response_preflight_refused.request_attempt_count(), 1);
        assert_eq!(response_preflight_refused.request_admitted_count(), 0);
        assert_eq!(response_preflight_refused.connection_attempt_count(), 0);
        assert_eq!(
            response_preflight_refused.first_failure(),
            Some(WebSocketReviewFailureKind::ParentAuthorityUnavailable)
        );
        assert!(response_preflight_refused.is_consistent());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let read = stream.read(&mut request).await.unwrap();
            assert!(request[..read].starts_with(b"GET /application/socket HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });
        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 1_000);
        let response_refused = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default().with_max_response_bytes(1)),
        )
        .execute()
        .await;
        await_server(server).await;
        assert_eq!(response_refused.request_attempt_count(), 1);
        assert_eq!(response_refused.request_admitted_count(), 1);
        assert_eq!(response_refused.connection_attempt_count(), 1);
        assert_eq!(response_refused.handshake_completed_count(), 0);
        assert_eq!(
            response_refused.first_failure(),
            Some(WebSocketReviewFailureKind::ParentResponseBudgetReached)
        );
        assert_eq!(
            response_refused.terminal(),
            WebSocketReviewTerminal::LimitReached
        );
        assert!(response_refused.is_consistent());
    }

    #[tokio::test]
    async fn connection_and_http_upgrade_failures_are_distinct_and_value_free() {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unused.local_addr().unwrap();
        drop(unused);
        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 1_000);
        let refused = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default()),
        )
        .execute()
        .await;
        assert_eq!(refused.connection_attempt_count(), 1);
        assert_eq!(refused.handshake_completed_count(), 0);
        assert_eq!(
            refused.first_failure(),
            Some(WebSocketReviewFailureKind::ConnectionFailed)
        );
        assert!(refused.is_consistent());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 2048];
            let read = stream.read(&mut request).await.unwrap();
            assert!(request[..read].starts_with(b"GET /application/socket HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();
        });
        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 1_000);
        let rejected = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default()),
        )
        .execute()
        .await;
        await_server(server).await;
        assert_eq!(rejected.handshake_completed_count(), 0);
        assert_eq!(
            rejected.first_failure(),
            Some(WebSocketReviewFailureKind::HandshakeRejected)
        );
        assert!(rejected.transport_read_bytes() > 0);
        assert!(rejected.is_consistent());
    }

    #[tokio::test]
    async fn backend_rejects_a_missing_negotiated_subprotocol_before_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = socket.next().await;
        });
        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy_with_options(
            &application,
            &endpoint,
            b"expected",
            2_000,
            Some("termivar-review"),
            4,
            4096,
        );
        let audit = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default()),
        )
        .execute()
        .await;
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(audit.handshake_completed_count(), 0);
        assert!(audit.subprotocol_requested());
        assert!(!audit.subprotocol_negotiated());
        assert_eq!(
            audit.first_failure(),
            Some(WebSocketReviewFailureKind::HandshakeRejected)
        );
        assert!(audit.is_consistent());
    }

    #[test]
    fn subprotocol_comparison_requires_an_exact_selected_value() {
        let selected = Response::builder()
            .status(101)
            .header("sec-websocket-protocol", "termivar-review")
            .body(())
            .unwrap();
        let absent = Response::builder().status(101).body(()).unwrap();
        assert!(subprotocol_matches(&selected, Some("termivar-review")));
        assert!(!subprotocol_matches(&selected, Some("other")));
        assert!(!subprotocol_matches(&selected, None));
        assert!(subprotocol_matches(&absent, None));
        assert!(!subprotocol_matches(&absent, Some("termivar-review")));
    }

    #[tokio::test]
    async fn ping_pong_is_bounded_and_does_not_replace_the_text_oracle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "request"
            );
            socket.send(Message::Ping(Vec::new().into())).await.unwrap();
            socket.send(Message::text("expected")).await.unwrap();
            for _ in 0..2 {
                if matches!(
                    tokio::time::timeout(Duration::from_secs(1), socket.next()).await,
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None)
                ) {
                    break;
                }
            }
        });
        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 2_000);
        let audit = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default()),
        )
        .execute()
        .await;
        await_server(server).await;
        assert_eq!(audit.terminal(), WebSocketReviewTerminal::Completed);
        assert_eq!(audit.matched_response_count(), 1);
        assert_eq!(audit.inbound_control_frame_count(), 1);
        assert!(audit.outbound_control_frame_count() >= 2);
        assert!(audit.is_consistent());
    }

    #[tokio::test]
    async fn peer_close_and_control_limit_preserve_distinct_incomplete_evidence() {
        for control_limit in [4_u16, 1_u16] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let _ = socket.next().await;
                if control_limit == 1 {
                    socket.send(Message::Ping(Vec::new().into())).await.unwrap();
                } else {
                    socket.close(None).await.unwrap();
                }
            });
            let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
            let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
            let policy = loopback_policy_with_options(
                &application,
                &endpoint,
                b"expected",
                2_000,
                None,
                control_limit,
                4096,
            );
            let audit = runtime(
                &policy,
                &application,
                RequestAccountingBroker::new(RuntimeBudget::default()),
            )
            .execute()
            .await;
            await_server(server).await;
            let expected = if control_limit == 1 {
                WebSocketReviewFailureKind::ControlFrameLimitReached
            } else {
                WebSocketReviewFailureKind::PeerClosed
            };
            assert_eq!(audit.first_failure(), Some(expected));
            assert_eq!(audit.outbound_message_count(), 1);
            assert_eq!(audit.inbound_message_count(), 0);
            assert!(audit.is_consistent());
        }
    }

    #[tokio::test]
    async fn oversized_text_response_is_a_limit_not_a_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let _ = socket.next().await;
            socket.send(Message::text("oversized")).await.unwrap();
        });
        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy =
            loopback_policy_with_options(&application, &endpoint, b"tiny", 2_000, None, 4, 4);
        let audit = runtime(
            &policy,
            &application,
            RequestAccountingBroker::new(RuntimeBudget::default()),
        )
        .execute()
        .await;
        await_server(server).await;
        assert_eq!(
            audit.first_failure(),
            Some(WebSocketReviewFailureKind::MessageTooLarge)
        );
        assert_eq!(audit.mismatched_response_count(), 0);
        assert_eq!(audit.inbound_message_count(), 0);
        assert!(audit.is_consistent());
    }

    #[tokio::test]
    async fn loopback_exchange_accounts_raw_transport_and_redacts_mismatch_digest() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "request"
            );
            socket.send(Message::text("unexpected")).await.unwrap();
            let _ = socket.next().await;
        });

        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 2_000);
        let accounting = RequestAccountingBroker::new(
            RuntimeBudget::default().with_max_response_bytes(1024 * 1024),
        );
        let audit = runtime(&policy, &application, accounting.clone())
            .execute()
            .await;
        await_server(server).await;

        assert_eq!(audit.terminal(), WebSocketReviewTerminal::Completed);
        assert_eq!(
            audit.completeness(),
            WebSocketReviewCompleteness::ConfiguredExchangeComplete
        );
        assert_eq!(audit.request_attempt_count(), 1);
        assert_eq!(audit.request_admitted_count(), 1);
        assert_eq!(audit.connection_attempt_count(), 1);
        assert_eq!(audit.handshake_completed_count(), 1);
        assert_eq!(audit.matched_response_count(), 0);
        assert_eq!(audit.mismatched_response_count(), 1);
        assert_eq!(
            audit.messages()[0].status(),
            WebSocketReviewMessageStatus::ResponseMismatched
        );
        assert!(audit.messages()[0].observed_response_reference().is_none());
        assert!(audit.transport_read_bytes() >= audit.inbound_application_bytes());
        assert!(audit.transport_write_bytes() >= audit.outbound_application_bytes());
        assert_eq!(
            audit.accounted_transport_response_bytes(),
            audit.transport_read_bytes()
        );
        assert_eq!(
            accounting.snapshot().response_bytes(),
            audit.transport_read_bytes()
        );
        assert_eq!(accounting.snapshot().request_body_bytes(), 0);
        assert!(audit.is_consistent());
    }

    #[tokio::test]
    async fn binary_response_cannot_satisfy_the_text_response_oracle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap().into_text().unwrap(),
                "request"
            );
            socket
                .send(Message::binary(b"expected".to_vec()))
                .await
                .unwrap();
            let _ = socket.next().await;
        });

        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 2_000);
        let accounting = RequestAccountingBroker::new(
            RuntimeBudget::default().with_max_response_bytes(1024 * 1024),
        );
        let audit = runtime(&policy, &application, accounting.clone())
            .execute()
            .await;
        await_server(server).await;

        assert_eq!(audit.terminal(), WebSocketReviewTerminal::Incomplete);
        assert_eq!(
            audit.first_failure(),
            Some(WebSocketReviewFailureKind::BinaryMessageUnsupported)
        );
        assert_eq!(audit.matched_response_count(), 0);
        assert_eq!(audit.mismatched_response_count(), 0);
        assert_eq!(audit.inbound_message_count(), 0);
        assert_eq!(audit.inbound_application_bytes(), 0);
        assert!(audit.transport_read_bytes() > 0);
        assert_eq!(
            accounting.snapshot().response_bytes(),
            audit.transport_read_bytes()
        );
        assert!(audit.is_consistent());
    }

    #[tokio::test]
    async fn partial_handshake_read_is_charged_when_deadline_stops_the_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n")
                .await
                .unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });

        let application = url::Url::parse(&format!("http://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("ws://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 100);
        let accounting = RequestAccountingBroker::new(
            RuntimeBudget::default().with_max_response_bytes(1024 * 1024),
        );
        let audit = runtime(&policy, &application, accounting.clone())
            .execute()
            .await;
        server.abort();

        assert_eq!(audit.terminal(), WebSocketReviewTerminal::DeadlineReached);
        assert_eq!(
            audit.first_failure(),
            Some(WebSocketReviewFailureKind::DeadlineReached)
        );
        assert_eq!(audit.handshake_completed_count(), 0);
        assert!(audit.transport_read_bytes() > 0);
        assert_eq!(
            audit.accounted_transport_response_bytes(),
            audit.transport_read_bytes()
        );
        assert_eq!(
            accounting.snapshot().response_bytes(),
            audit.transport_read_bytes()
        );
        assert!(audit.is_consistent());
    }

    #[tokio::test]
    async fn cancellation_and_elapsed_parent_deadline_stop_before_lease_admission() {
        let application = url::Url::parse("http://127.0.0.1:9/application/").unwrap();
        let endpoint = url::Url::parse("ws://127.0.0.1:9/application/socket").unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 1_000);

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = WebSocketReviewRuntime::new(
            &policy,
            application.origin().ascii_serialization(),
            RequestAccountingBroker::new(RuntimeBudget::default()),
            cancellation,
            None,
        )
        .unwrap()
        .execute()
        .await;
        assert_eq!(cancelled.request_attempt_count(), 0);
        assert_eq!(cancelled.request_admitted_count(), 0);
        assert_eq!(cancelled.connection_attempt_count(), 0);
        assert_eq!(cancelled.terminal(), WebSocketReviewTerminal::Cancelled);
        assert!(cancelled.is_consistent());

        let deadline = WebSocketReviewRuntime::new(
            &policy,
            application.origin().ascii_serialization(),
            RequestAccountingBroker::new(RuntimeBudget::default()),
            CancellationToken::new(),
            Some(tokio::time::Instant::now()),
        )
        .unwrap()
        .execute()
        .await;
        assert_eq!(deadline.request_attempt_count(), 0);
        assert_eq!(deadline.request_admitted_count(), 0);
        assert_eq!(deadline.connection_attempt_count(), 0);
        assert_eq!(
            deadline.terminal(),
            WebSocketReviewTerminal::DeadlineReached
        );
        assert!(deadline.is_consistent());
    }

    #[tokio::test]
    async fn self_signed_wss_server_is_not_added_to_the_trust_store() {
        use rcgen::{CertificateParams, KeyPair};
        use tokio_rustls::{
            rustls::{
                pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
                ServerConfig,
            },
            TlsAcceptor,
        };

        let key = KeyPair::generate().unwrap();
        let certificate = CertificateParams::new(vec!["127.0.0.1".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await
        });

        let application = url::Url::parse(&format!("https://{address}/application/")).unwrap();
        let endpoint = url::Url::parse(&format!("wss://{address}/application/socket")).unwrap();
        let policy = loopback_policy(&application, &endpoint, b"expected", 2_000);
        let accounting = RequestAccountingBroker::new(
            RuntimeBudget::default().with_max_response_bytes(1024 * 1024),
        );
        let audit = runtime(&policy, &application, accounting.clone())
            .execute()
            .await;
        let server_result = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();

        assert!(server_result.is_err());
        assert_eq!(audit.handshake_completed_count(), 0);
        assert_eq!(
            audit.first_failure(),
            Some(WebSocketReviewFailureKind::ConnectionFailed)
        );
        assert!(audit.transport_read_bytes() > 0);
        assert_eq!(
            audit.accounted_transport_response_bytes(),
            audit.transport_read_bytes()
        );
        assert_eq!(
            accounting.snapshot().response_bytes(),
            audit.transport_read_bytes()
        );
        assert!(audit.is_consistent());
    }
}
