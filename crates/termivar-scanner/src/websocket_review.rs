//! Strict, transport-neutral policy for bounded WebSocket review.
//!
//! Parsing validates an operator-authored declaration against an already
//! selected application target. It does not open a socket, verify either
//! operator assertion, grant broader target authority, or turn an expected
//! response into observed evidence. Raw endpoints, subprotocols, message IDs,
//! message text, and expected-response digests remain private to the
//! crate-owned execution boundary. Message IDs are operator-declared,
//! non-secret revision handles: the operator must change an ID when the
//! corresponding outbound or expected-response semantics change. Public
//! references never hash the message or expected-response bytes.

use std::{collections::BTreeSet, fmt, net::IpAddr};

use serde::de::Error as _;
use serde::{
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Host, Url};

/// The only WebSocket review policy schema accepted by this module.
pub const WEBSOCKET_REVIEW_POLICY_SCHEMA: &str = "security.websocket-review-policy/v1";
/// Stable interpretation and reference algorithm applied to the V1 schema.
pub const WEBSOCKET_REVIEW_POLICY_ALGORITHM: &str = "termivar.websocket-review-policy/v1";
/// Maximum accepted exact JSON policy bytes.
pub const MAX_WEBSOCKET_REVIEW_POLICY_BYTES: usize = 128 * 1024;
/// Maximum number of ordered outbound message declarations.
pub const MAX_WEBSOCKET_REVIEW_MESSAGES: usize = 8;
/// Maximum UTF-8 bytes in one declared outbound text message.
pub const MAX_WEBSOCKET_REVIEW_MESSAGE_TEXT_BYTES: usize = 16 * 1024;
/// Maximum cumulative application-message bytes in either direction.
pub const MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES: u64 = 64 * 1024;
/// Maximum control frames admitted across the isolated connection.
pub const MAX_WEBSOCKET_REVIEW_CONTROL_FRAMES: u16 = 16;
/// Maximum wall-clock duration of one isolated review.
pub const MAX_WEBSOCKET_REVIEW_WALL_TIME_MS: u64 = 10_000;
/// Maximum bytes in one safe message identifier.
pub const MAX_WEBSOCKET_REVIEW_MESSAGE_ID_BYTES: usize = 128;
/// Maximum bytes in the optional WebSocket subprotocol token.
pub const MAX_WEBSOCKET_REVIEW_SUBPROTOCOL_BYTES: usize = 128;

/// Compatibility name for the hard per-direction application-byte ceiling.
pub const MAX_WEBSOCKET_REVIEW_MESSAGE_BYTES: u64 = MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES;
/// Compatibility name for the cumulative declared outbound-text ceiling.
pub const MAX_WEBSOCKET_REVIEW_TOTAL_OUTBOUND_BYTES: u64 = MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES;
/// Compatibility name for the cumulative expected inbound-payload ceiling.
pub const MAX_WEBSOCKET_REVIEW_TOTAL_INBOUND_BYTES: u64 = MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES;

const MAX_WEBSOCKET_REVIEW_ENDPOINT_BYTES: usize = 2048;
const DUPLICATE_KEY_SENTINEL: &str = "termivar_websocket_review_duplicate_json_key";
const POLICY_REFERENCE_DOMAIN: &[u8] = b"termivar.websocket-review.policy-reference.v1\0";
const APPLICATION_REFERENCE_DOMAIN: &[u8] = b"termivar.websocket-review.application-reference.v1\0";
const ENDPOINT_REFERENCE_DOMAIN: &[u8] = b"termivar.websocket-review.endpoint-reference.v1\0";
const MESSAGE_REFERENCE_DOMAIN: &[u8] = b"termivar.websocket-review.message-reference.v1\0";
const EXPECTED_RESPONSE_REFERENCE_DOMAIN: &[u8] =
    b"termivar.websocket-review.expected-response-reference.v1\0";

/// Origin-header behavior selected by a validated V1 policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebSocketOriginMode {
    /// Send the HTTP(S) origin of the authorized application target.
    ApplicationOrigin,
    /// Deliberately omit the `Origin` header.
    Omit,
}

impl WebSocketOriginMode {
    /// Returns the exact V1 wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationOrigin => "application_origin",
            Self::Omit => "omit",
        }
    }
}

/// Validated finite runtime ceilings from one policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebSocketReviewLimits {
    max_inbound_message_bytes: u64,
    max_outbound_message_bytes: u64,
    max_messages: u16,
    max_control_frames: u16,
    max_wall_time_ms: u64,
}

impl WebSocketReviewLimits {
    /// Maximum bytes in one inbound application message.
    #[must_use]
    pub const fn max_inbound_message_bytes(self) -> u64 {
        self.max_inbound_message_bytes
    }

    /// Maximum bytes in one outbound application message.
    #[must_use]
    pub const fn max_outbound_message_bytes(self) -> u64 {
        self.max_outbound_message_bytes
    }

    /// Shared directional application-message count ceiling.
    #[must_use]
    pub const fn max_messages(self) -> u16 {
        self.max_messages
    }

    /// Connection-wide control-frame count ceiling.
    #[must_use]
    pub const fn max_control_frames(self) -> u16 {
        self.max_control_frames
    }

    /// Wall-clock ceiling in whole milliseconds.
    #[must_use]
    pub const fn max_wall_time_ms(self) -> u64 {
        self.max_wall_time_ms
    }
}

#[derive(Clone, PartialEq, Eq)]
struct WebSocketReviewMessage {
    text: String,
    expected_response_sha256: [u8; 32],
    expected_response_length: u64,
    message_reference: String,
    expected_response_reference: String,
}

impl fmt::Debug for WebSocketReviewMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketReviewMessage")
            .field("id", &"<redacted>")
            .field("text", &"<redacted>")
            .field("expected_response", &"<redacted>")
            .field("message_reference", &self.message_reference)
            .field(
                "expected_response_reference",
                &self.expected_response_reference,
            )
            .field("outbound_length", &self.text.len())
            .field("expected_response_length", &self.expected_response_length)
            .finish()
    }
}

/// Safe borrowed metadata for one ordered message declaration.
///
/// Raw identifiers, text, and expected digests are intentionally available
/// only to the crate-owned transport boundary.
#[derive(Clone, Copy)]
pub struct WebSocketReviewMessageRef<'a> {
    message: &'a WebSocketReviewMessage,
}

impl<'a> WebSocketReviewMessageRef<'a> {
    /// Stable value-free reference for the operator-declared message revision.
    #[must_use]
    pub fn message_reference(self) -> &'a str {
        &self.message.message_reference
    }

    /// Stable value-free reference for that revision's expected response.
    #[must_use]
    pub fn expected_response_reference(self) -> &'a str {
        &self.message.expected_response_reference
    }

    /// UTF-8 byte length of the declared outbound text.
    #[must_use]
    pub fn outbound_length(self) -> u64 {
        u64::try_from(self.message.text.len()).unwrap_or(u64::MAX)
    }

    /// Exact expected inbound application-payload length.
    #[must_use]
    pub const fn expected_response_length(self) -> u64 {
        self.message.expected_response_length
    }

    pub(crate) fn execution_text(self) -> &'a str {
        &self.message.text
    }

    pub(crate) const fn expected_response_sha256(self) -> &'a [u8; 32] {
        &self.message.expected_response_sha256
    }
}

impl fmt::Debug for WebSocketReviewMessageRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketReviewMessageRef")
            .field("message_reference", &self.message.message_reference)
            .field(
                "expected_response_reference",
                &self.message.expected_response_reference,
            )
            .field("outbound_length", &self.message.text.len())
            .field(
                "expected_response_length",
                &self.message.expected_response_length,
            )
            .finish()
    }
}

/// Strict, bounded declaration for one isolated WebSocket connection.
#[derive(Clone, PartialEq, Eq)]
pub struct WebSocketReviewPolicy {
    endpoint: Url,
    application_origin: Option<String>,
    origin_mode: WebSocketOriginMode,
    subprotocol: Option<String>,
    messages: Vec<WebSocketReviewMessage>,
    limits: WebSocketReviewLimits,
    policy_reference: String,
    application_reference: String,
    endpoint_reference: String,
}

impl WebSocketReviewPolicy {
    /// Parses strict JSON and validates it as a narrowing child of the exact
    /// host, effective port, and application-path scope of `application_target`.
    ///
    /// The two required `true` values are retained only as operator
    /// assertions. Parsing does not independently verify authorization or
    /// message side effects.
    pub fn parse_json(
        application_target: &Url,
        source: &[u8],
    ) -> Result<Self, WebSocketReviewPolicyError> {
        if source.is_empty() {
            return Err(WebSocketReviewPolicyError::EmptyPolicy);
        }
        if source.len() > MAX_WEBSOCKET_REVIEW_POLICY_BYTES {
            return Err(WebSocketReviewPolicyError::PolicyTooLarge);
        }

        let application = validate_application_target(application_target)?;
        let value = parse_strict_json(source)?;
        let wire: WirePolicy = serde_json::from_value(value)
            .map_err(|_| WebSocketReviewPolicyError::MalformedPolicy)?;
        if wire.schema != WEBSOCKET_REVIEW_POLICY_SCHEMA {
            return Err(WebSocketReviewPolicyError::UnsupportedSchema);
        }
        if !wire.target_authorized {
            return Err(WebSocketReviewPolicyError::TargetAuthorizationRequired);
        }
        if !wire.messages_read_only_acknowledged {
            return Err(WebSocketReviewPolicyError::ReadOnlyAcknowledgementRequired);
        }
        if !wire.message_content_is_non_secret {
            return Err(WebSocketReviewPolicyError::NonSecretContentAcknowledgementRequired);
        }
        if wire.compression {
            return Err(WebSocketReviewPolicyError::CompressionNotPermitted);
        }
        if wire.reconnect {
            return Err(WebSocketReviewPolicyError::ReconnectNotPermitted);
        }

        let endpoint = validate_endpoint(&application, &wire.endpoint)?;
        let origin_mode = match wire.origin_mode.as_str() {
            "application_origin" => WebSocketOriginMode::ApplicationOrigin,
            "omit" => WebSocketOriginMode::Omit,
            _ => return Err(WebSocketReviewPolicyError::UnsupportedOriginMode),
        };
        if wire
            .subprotocol
            .as_deref()
            .is_some_and(|value| !valid_subprotocol(value))
        {
            return Err(WebSocketReviewPolicyError::InvalidSubprotocol);
        }

        let limits = validate_limits(&wire.limits, wire.messages.len())?;
        let mut seen_ids = BTreeSet::new();
        let mut total_outbound_bytes = 0_u64;
        let mut total_expected_inbound_bytes = 0_u64;
        let mut messages = Vec::with_capacity(wire.messages.len());
        for declaration in wire.messages {
            if !valid_message_id(&declaration.id) {
                return Err(WebSocketReviewPolicyError::InvalidMessageId);
            }
            if !seen_ids.insert(declaration.id.clone()) {
                return Err(WebSocketReviewPolicyError::DuplicateMessageId);
            }
            if declaration.text.len() > MAX_WEBSOCKET_REVIEW_MESSAGE_TEXT_BYTES {
                return Err(WebSocketReviewPolicyError::MessageTextTooLarge);
            }
            let outbound_length = u64::try_from(declaration.text.len())
                .map_err(|_| WebSocketReviewPolicyError::MessageTextTooLarge)?;
            total_outbound_bytes = total_outbound_bytes
                .checked_add(outbound_length)
                .filter(|length| *length <= MAX_WEBSOCKET_REVIEW_TOTAL_OUTBOUND_BYTES)
                .ok_or(WebSocketReviewPolicyError::MessageTextAggregateTooLarge)?;
            let expected_response_sha256 = parse_sha256(&declaration.expected_response.sha256)?;
            let expected_response_length = declaration.expected_response.length;
            total_expected_inbound_bytes = total_expected_inbound_bytes
                .checked_add(expected_response_length)
                .filter(|length| *length <= MAX_WEBSOCKET_REVIEW_TOTAL_INBOUND_BYTES)
                .ok_or(WebSocketReviewPolicyError::ExpectedResponseAggregateTooLarge)?;
            if outbound_length > limits.max_outbound_message_bytes
                || expected_response_length > limits.max_inbound_message_bytes
            {
                return Err(WebSocketReviewPolicyError::InvalidLimits);
            }
            // Public references are derived only from the operator-declared,
            // non-secret revision identifier and public lengths. Hashing the
            // message or expected-response bytes here would publish an
            // offline dictionary oracle for low-entropy private values.
            let expected_response_reference = digest_reference(
                EXPECTED_RESPONSE_REFERENCE_DOMAIN,
                "websocket-expected-response-revision-sha256",
                &[
                    declaration.id.as_bytes(),
                    &expected_response_length.to_be_bytes(),
                ],
            );
            let message_reference = digest_reference(
                MESSAGE_REFERENCE_DOMAIN,
                "websocket-message-revision-sha256",
                &[declaration.id.as_bytes()],
            );
            messages.push(WebSocketReviewMessage {
                text: declaration.text,
                expected_response_sha256,
                expected_response_length,
                message_reference,
                expected_response_reference,
            });
        }

        let application_reference = digest_reference(
            APPLICATION_REFERENCE_DOMAIN,
            "websocket-application-sha256",
            &[application.as_str().as_bytes()],
        );
        let endpoint_reference = digest_reference(
            ENDPOINT_REFERENCE_DOMAIN,
            "websocket-endpoint-sha256",
            &[endpoint.as_str().as_bytes()],
        );
        let policy_reference = policy_reference(
            &application_reference,
            &endpoint,
            origin_mode,
            wire.subprotocol.as_deref(),
            &messages,
            limits,
        );
        let application_origin = (origin_mode == WebSocketOriginMode::ApplicationOrigin)
            .then(|| application.origin().ascii_serialization());

        Ok(Self {
            endpoint,
            application_origin,
            origin_mode,
            subprotocol: wire.subprotocol,
            messages,
            limits,
            policy_reference,
            application_reference,
            endpoint_reference,
        })
    }

    /// Returns the accepted policy schema.
    #[must_use]
    pub const fn schema(&self) -> &'static str {
        WEBSOCKET_REVIEW_POLICY_SCHEMA
    }

    /// Returns the stable reference for the operator-versioned policy identity.
    #[must_use]
    pub fn policy_reference(&self) -> &str {
        &self.policy_reference
    }

    /// Returns the stable reference for the application authority scope.
    #[must_use]
    pub fn application_reference(&self) -> &str {
        &self.application_reference
    }

    /// Returns the stable reference for the exact WebSocket endpoint.
    #[must_use]
    pub fn endpoint_reference(&self) -> &str {
        &self.endpoint_reference
    }

    /// Returns the number of ordered outbound declarations.
    #[must_use]
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Returns value-free metadata for the ordered message declarations.
    pub fn messages(&self) -> impl ExactSizeIterator<Item = WebSocketReviewMessageRef<'_>> {
        self.messages
            .iter()
            .map(|message| WebSocketReviewMessageRef { message })
    }

    /// Returns the selected Origin-header behavior.
    #[must_use]
    pub const fn origin_mode(&self) -> WebSocketOriginMode {
        self.origin_mode
    }

    /// Reports whether one validated subprotocol token is present without
    /// exposing the operator-authored token.
    #[must_use]
    pub const fn has_subprotocol(&self) -> bool {
        self.subprotocol.is_some()
    }

    /// Returns the required, unverified operator authorization assertion.
    #[must_use]
    pub const fn target_authorized(&self) -> bool {
        true
    }

    /// Returns the required, unverified read-only-message acknowledgement.
    #[must_use]
    pub const fn messages_read_only_acknowledged(&self) -> bool {
        true
    }

    /// Returns the required operator assertion that message bodies are not secrets.
    #[must_use]
    pub const fn message_content_is_non_secret(&self) -> bool {
        true
    }

    /// V1 always disables WebSocket extension negotiation.
    #[must_use]
    pub const fn compression_enabled(&self) -> bool {
        false
    }

    /// V1 always owns exactly one connection attempt and never reconnects.
    #[must_use]
    pub const fn reconnect_enabled(&self) -> bool {
        false
    }

    /// Returns all validated finite runtime ceilings.
    #[must_use]
    pub const fn limits(&self) -> WebSocketReviewLimits {
        self.limits
    }

    /// Maximum bytes in one inbound application message.
    #[must_use]
    pub const fn max_inbound_message_bytes(&self) -> u64 {
        self.limits.max_inbound_message_bytes
    }

    /// Maximum bytes in one outbound application message.
    #[must_use]
    pub const fn max_outbound_message_bytes(&self) -> u64 {
        self.limits.max_outbound_message_bytes
    }

    /// Shared directional application-message count ceiling.
    #[must_use]
    pub const fn max_messages(&self) -> u16 {
        self.limits.max_messages
    }

    /// Connection-wide control-frame count ceiling.
    #[must_use]
    pub const fn max_control_frames(&self) -> u16 {
        self.limits.max_control_frames
    }

    /// Wall-clock ceiling in whole milliseconds.
    #[must_use]
    pub const fn max_wall_time_ms(&self) -> u64 {
        self.limits.max_wall_time_ms
    }

    pub(crate) const fn execution_endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Repeats the exact selected-application binding at runtime composition
    /// and again when the one-shot transport authority is minted. A policy
    /// parsed for one same-origin application directory cannot therefore be
    /// replayed under a broader or sibling assessment root.
    pub(crate) fn is_bound_to_application(&self, application_target: &Url) -> bool {
        validate_application_target(application_target).is_ok_and(|application| {
            digest_reference(
                APPLICATION_REFERENCE_DOMAIN,
                "websocket-application-sha256",
                &[application.as_str().as_bytes()],
            ) == self.application_reference
        })
    }

    pub(crate) fn execution_origin(&self) -> Option<&str> {
        self.application_origin.as_deref()
    }

    pub(crate) fn execution_subprotocol(&self) -> Option<&str> {
        self.subprotocol.as_deref()
    }

    pub(crate) fn execution_messages(
        &self,
    ) -> impl ExactSizeIterator<Item = WebSocketReviewMessageRef<'_>> {
        self.messages()
    }
}

impl fmt::Debug for WebSocketReviewPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketReviewPolicy")
            .field("application", &"<redacted>")
            .field("endpoint", &"<redacted>")
            .field("origin", &"<redacted>")
            .field("subprotocol", &"<redacted>")
            .field("messages", &"<redacted>")
            .field("schema", &WEBSOCKET_REVIEW_POLICY_SCHEMA)
            .field("origin_mode", &self.origin_mode)
            .field("subprotocol_present", &self.subprotocol.is_some())
            .field("message_count", &self.messages.len())
            .field("limits", &self.limits)
            .field("policy_reference", &self.policy_reference)
            .field("application_reference", &self.application_reference)
            .field("endpoint_reference", &self.endpoint_reference)
            .finish()
    }
}

/// Static, value-free policy parsing or validation failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebSocketReviewPolicyError {
    /// No JSON bytes were supplied.
    #[error("WebSocket review policy is empty")]
    EmptyPolicy,
    /// Exact input bytes exceeded the compiled policy ceiling.
    #[error("WebSocket review policy exceeds its compiled byte limit")]
    PolicyTooLarge,
    /// JSON syntax, type, required fields, or unknown fields were invalid.
    #[error("WebSocket review policy is malformed")]
    MalformedPolicy,
    /// A JSON object contained a duplicate decoded key.
    #[error("WebSocket review policy contains a duplicate JSON key")]
    DuplicateJsonKey,
    /// The exact schema identifier is not supported.
    #[error("WebSocket review policy schema is unsupported")]
    UnsupportedSchema,
    /// The application target cannot provide the required authority scope.
    #[error("WebSocket review application target is invalid")]
    InvalidApplicationTarget,
    /// The operator did not assert authorization for the selected target.
    #[error("WebSocket review requires the target_authorized operator assertion")]
    TargetAuthorizationRequired,
    /// The operator did not acknowledge that declared messages are read-only.
    #[error("WebSocket review requires the read-only message acknowledgement")]
    ReadOnlyAcknowledgementRequired,
    /// The operator did not assert that message bodies contain no secret material.
    #[error("WebSocket review requires the non-secret message-content acknowledgement")]
    NonSecretContentAcknowledgementRequired,
    /// The absolute endpoint was malformed or contained forbidden URL parts.
    #[error("WebSocket review endpoint is invalid")]
    InvalidEndpoint,
    /// The endpoint escaped the exact host, port, or application path scope.
    #[error("WebSocket review endpoint is outside application authority")]
    EndpointOutsideApplication,
    /// Plaintext WebSocket was selected outside numeric loopback scope.
    #[error("plaintext WebSocket review is permitted only on numeric loopback")]
    InsecureEndpoint,
    /// The Origin-header mode is not implemented by V1.
    #[error("WebSocket review origin mode is unsupported")]
    UnsupportedOriginMode,
    /// The optional subprotocol was not one bounded HTTP token.
    #[error("WebSocket review subprotocol is invalid")]
    InvalidSubprotocol,
    /// V1 prohibits compression and all other extension negotiation.
    #[error("WebSocket review compression must be disabled")]
    CompressionNotPermitted,
    /// V1 prohibits reconnects and retries.
    #[error("WebSocket review reconnect must be disabled")]
    ReconnectNotPermitted,
    /// V1 requires one through eight message declarations.
    #[error("WebSocket review message count is invalid")]
    InvalidMessageCount,
    /// A message identifier violated the bounded safe-token contract.
    #[error("WebSocket review message identifier is invalid")]
    InvalidMessageId,
    /// Two message declarations used the same identifier.
    #[error("WebSocket review message identifier is duplicated")]
    DuplicateMessageId,
    /// One declared text message exceeded its compiled byte ceiling.
    #[error("WebSocket review message text exceeds its compiled byte limit")]
    MessageTextTooLarge,
    /// Declared outbound text exceeded the connection-wide byte ceiling.
    #[error("WebSocket review outbound message bytes exceed their compiled limit")]
    MessageTextAggregateTooLarge,
    /// An expected response digest or length was invalid.
    #[error("WebSocket review expected response is invalid")]
    InvalidExpectedResponse,
    /// Expected inbound payloads exceeded the connection-wide byte ceiling.
    #[error("WebSocket review expected response bytes exceed their compiled limit")]
    ExpectedResponseAggregateTooLarge,
    /// A finite runtime limit was zero, inconsistent, or above its hard cap.
    #[error("WebSocket review runtime limits are invalid")]
    InvalidLimits,
}

impl WebSocketReviewPolicyError {
    /// Returns a stable value-free machine token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyPolicy => "empty_policy",
            Self::PolicyTooLarge => "policy_too_large",
            Self::MalformedPolicy => "malformed_policy",
            Self::DuplicateJsonKey => "duplicate_json_key",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::InvalidApplicationTarget => "invalid_application_target",
            Self::TargetAuthorizationRequired => "target_authorization_required",
            Self::ReadOnlyAcknowledgementRequired => "read_only_acknowledgement_required",
            Self::NonSecretContentAcknowledgementRequired => {
                "non_secret_content_acknowledgement_required"
            },
            Self::InvalidEndpoint => "invalid_endpoint",
            Self::EndpointOutsideApplication => "endpoint_outside_application",
            Self::InsecureEndpoint => "insecure_endpoint",
            Self::UnsupportedOriginMode => "unsupported_origin_mode",
            Self::InvalidSubprotocol => "invalid_subprotocol",
            Self::CompressionNotPermitted => "compression_not_permitted",
            Self::ReconnectNotPermitted => "reconnect_not_permitted",
            Self::InvalidMessageCount => "invalid_message_count",
            Self::InvalidMessageId => "invalid_message_id",
            Self::DuplicateMessageId => "duplicate_message_id",
            Self::MessageTextTooLarge => "message_text_too_large",
            Self::MessageTextAggregateTooLarge => "message_text_aggregate_too_large",
            Self::InvalidExpectedResponse => "invalid_expected_response",
            Self::ExpectedResponseAggregateTooLarge => "expected_response_aggregate_too_large",
            Self::InvalidLimits => "invalid_limits",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema: String,
    target_authorized: bool,
    messages_read_only_acknowledged: bool,
    message_content_is_non_secret: bool,
    endpoint: String,
    origin_mode: String,
    subprotocol: Option<String>,
    compression: bool,
    reconnect: bool,
    messages: Vec<WireMessage>,
    limits: WireLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMessage {
    id: String,
    text: String,
    expected_response: WireExpectedResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireExpectedResponse {
    sha256: String,
    length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLimits {
    max_inbound_message_bytes: u64,
    max_outbound_message_bytes: u64,
    max_messages: u16,
    max_control_frames: u16,
    max_wall_time_ms: u64,
}

fn validate_application_target(
    application_target: &Url,
) -> Result<Url, WebSocketReviewPolicyError> {
    if !matches!(application_target.scheme(), "http" | "https")
        || application_target.host().is_none()
        || application_target.port_or_known_default().is_none()
        || !application_target.username().is_empty()
        || application_target.password().is_some()
        || application_target.query().is_some()
        || application_target.fragment().is_some()
        || !valid_scoped_path(application_target.path())
    {
        return Err(WebSocketReviewPolicyError::InvalidApplicationTarget);
    }
    let mut application = application_target.clone();
    application.set_query(None);
    application.set_fragment(None);
    Ok(application)
}

fn validate_endpoint(application: &Url, raw: &str) -> Result<Url, WebSocketReviewPolicyError> {
    if raw.is_empty()
        || raw.len() > MAX_WEBSOCKET_REVIEW_ENDPOINT_BYTES
        || raw.trim() != raw
        || raw.contains('%')
        || raw.contains('\\')
        || raw
            .chars()
            .any(|character| character.is_ascii_control() || character.is_whitespace())
        || raw_url_has_dot_path_segment(raw)
    {
        return Err(WebSocketReviewPolicyError::InvalidEndpoint);
    }
    let endpoint = Url::parse(raw).map_err(|_| WebSocketReviewPolicyError::InvalidEndpoint)?;
    if !matches!(endpoint.scheme(), "ws" | "wss")
        || endpoint.host().is_none()
        || endpoint.port_or_known_default().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !valid_scoped_path(endpoint.path())
    {
        return Err(WebSocketReviewPolicyError::InvalidEndpoint);
    }
    if endpoint.host() != application.host()
        || endpoint.port_or_known_default() != application.port_or_known_default()
        || !path_is_within(application.path(), endpoint.path())
    {
        return Err(WebSocketReviewPolicyError::EndpointOutsideApplication);
    }
    if !matches!(
        (application.scheme(), endpoint.scheme()),
        ("http", "ws") | ("https", "wss")
    ) {
        return Err(WebSocketReviewPolicyError::InvalidEndpoint);
    }
    if endpoint.scheme() == "ws"
        && (application.scheme() != "http"
            || !numeric_loopback(application.host())
            || !numeric_loopback(endpoint.host()))
    {
        return Err(WebSocketReviewPolicyError::InsecureEndpoint);
    }
    Ok(endpoint)
}

fn raw_url_has_dot_path_segment(raw: &str) -> bool {
    let Some((_, after_scheme)) = raw.split_once("://") else {
        return false;
    };
    let Some(path_start) = after_scheme.find('/') else {
        return false;
    };
    after_scheme[path_start..]
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
}

fn valid_scoped_path(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && !path.contains('%')
        && !path.contains('\\')
        && !path.contains("//")
        && !path.chars().any(char::is_control)
}

fn path_is_within(application_path: &str, endpoint_path: &str) -> bool {
    if application_path == "/" {
        return endpoint_path.starts_with('/');
    }
    let application_path = application_path.trim_end_matches('/');
    endpoint_path == application_path
        || endpoint_path
            .strip_prefix(application_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn numeric_loopback(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        _ => false,
    }
}

fn valid_subprotocol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WEBSOCKET_REVIEW_SUBPROTOCOL_BYTES
        && value.bytes().all(http_token_byte)
}

fn valid_message_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WEBSOCKET_REVIEW_MESSAGE_ID_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_limits(
    wire: &WireLimits,
    message_count: usize,
) -> Result<WebSocketReviewLimits, WebSocketReviewPolicyError> {
    if message_count == 0 || message_count > MAX_WEBSOCKET_REVIEW_MESSAGES {
        return Err(WebSocketReviewPolicyError::InvalidMessageCount);
    }
    let message_count = u16::try_from(message_count)
        .map_err(|_| WebSocketReviewPolicyError::InvalidMessageCount)?;
    if wire.max_inbound_message_bytes == 0
        || wire.max_inbound_message_bytes > MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES
        || wire.max_outbound_message_bytes == 0
        || wire.max_outbound_message_bytes > MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES
        || wire.max_messages < message_count
        || usize::from(wire.max_messages) > MAX_WEBSOCKET_REVIEW_MESSAGES
        || wire.max_control_frames == 0
        || wire.max_control_frames > MAX_WEBSOCKET_REVIEW_CONTROL_FRAMES
        || wire.max_wall_time_ms == 0
        || wire.max_wall_time_ms > MAX_WEBSOCKET_REVIEW_WALL_TIME_MS
    {
        return Err(WebSocketReviewPolicyError::InvalidLimits);
    }
    Ok(WebSocketReviewLimits {
        max_inbound_message_bytes: wire.max_inbound_message_bytes,
        max_outbound_message_bytes: wire.max_outbound_message_bytes,
        max_messages: wire.max_messages,
        max_control_frames: wire.max_control_frames,
        max_wall_time_ms: wire.max_wall_time_ms,
    })
}

fn parse_sha256(value: &str) -> Result<[u8; 32], WebSocketReviewPolicyError> {
    if value.len() != 64 {
        return Err(WebSocketReviewPolicyError::InvalidExpectedResponse);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high =
            lower_hex_nibble(pair[0]).ok_or(WebSocketReviewPolicyError::InvalidExpectedResponse)?;
        let low =
            lower_hex_nibble(pair[1]).ok_or(WebSocketReviewPolicyError::InvalidExpectedResponse)?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn policy_reference(
    application_reference: &str,
    endpoint: &Url,
    origin_mode: WebSocketOriginMode,
    subprotocol: Option<&str>,
    messages: &[WebSocketReviewMessage],
    limits: WebSocketReviewLimits,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_REFERENCE_DOMAIN);
    framed(&mut hasher, WEBSOCKET_REVIEW_POLICY_SCHEMA.as_bytes());
    framed(&mut hasher, WEBSOCKET_REVIEW_POLICY_ALGORITHM.as_bytes());
    framed(&mut hasher, application_reference.as_bytes());
    framed(&mut hasher, endpoint.as_str().as_bytes());
    framed(&mut hasher, origin_mode.as_str().as_bytes());
    match subprotocol {
        Some(value) => {
            framed(&mut hasher, b"subprotocol-present");
            framed(&mut hasher, value.as_bytes());
        },
        None => framed(&mut hasher, b"subprotocol-absent"),
    }
    framed(&mut hasher, b"target-authorized-asserted");
    framed(&mut hasher, b"messages-read-only-acknowledged");
    framed(&mut hasher, b"message-content-non-secret-acknowledged");
    framed(&mut hasher, b"compression-disabled");
    framed(&mut hasher, b"reconnect-disabled");
    for message in messages {
        framed(&mut hasher, message.message_reference.as_bytes());
    }
    for value in [
        limits.max_inbound_message_bytes,
        limits.max_outbound_message_bytes,
        u64::from(limits.max_messages),
        u64::from(limits.max_control_frames),
        limits.max_wall_time_ms,
    ] {
        framed(&mut hasher, &value.to_be_bytes());
    }
    format!("websocket-policy-sha256:{}", hex(hasher.finalize().into()))
}

fn digest_reference(domain: &[u8], prefix: &str, values: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values {
        framed(&mut hasher, value);
    }
    format!("{prefix}:{}", hex(hasher.finalize().into()))
}

fn framed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hex(bytes: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Default)]
struct StrictJsonSeed;

impl<'de> DeserializeSeed<'de> for StrictJsonSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict WebSocket review policy JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictJsonSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(DUPLICATE_KEY_SENTINEL));
            }
            let value = map.next_value_seed(StrictJsonSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

fn parse_strict_json(source: &[u8]) -> Result<Value, WebSocketReviewPolicyError> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let value = StrictJsonSeed
        .deserialize(&mut deserializer)
        .map_err(classify_json_error)?;
    deserializer.end().map_err(classify_json_error)?;
    Ok(value)
}

fn classify_json_error(error: serde_json::Error) -> WebSocketReviewPolicyError {
    if error.to_string().contains(DUPLICATE_KEY_SENTINEL) {
        WebSocketReviewPolicyError::DuplicateJsonKey
    } else {
        WebSocketReviewPolicyError::MalformedPolicy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const ENDPOINT_CANARY: &str = "endpoint-canary-4f190f";
    const ID_CANARY: &str = "message-canary-2e731b";
    const TEXT_CANARY: &str = "text-canary-60bbcf";
    const SUBPROTOCOL_CANARY: &str = "protocol-canary-771a0f";
    const DIGEST_CANARY: &str = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";

    fn application() -> Url {
        Url::parse("https://example.test:8443/application/").unwrap()
    }

    fn valid_value() -> Value {
        json!({
            "schema": WEBSOCKET_REVIEW_POLICY_SCHEMA,
            "target_authorized": true,
            "messages_read_only_acknowledged": true,
            "message_content_is_non_secret": true,
            "endpoint": format!("wss://example.test:8443/application/{ENDPOINT_CANARY}"),
            "origin_mode": "application_origin",
            "subprotocol": SUBPROTOCOL_CANARY,
            "compression": false,
            "reconnect": false,
            "messages": [{
                "id": ID_CANARY,
                "text": TEXT_CANARY,
                "expected_response": {
                    "sha256": DIGEST_CANARY,
                    "length": 19
                }
            }],
            "limits": {
                "max_inbound_message_bytes": 4096,
                "max_outbound_message_bytes": 4096,
                "max_messages": 1,
                "max_control_frames": 4,
                "max_wall_time_ms": 1000
            }
        })
    }

    fn parse(value: &Value) -> Result<WebSocketReviewPolicy, WebSocketReviewPolicyError> {
        WebSocketReviewPolicy::parse_json(&application(), &serde_json::to_vec(value).unwrap())
    }

    #[test]
    fn valid_policy_exposes_only_bounded_metadata_and_redacted_debug() {
        let policy = parse(&valid_value()).unwrap();
        assert_eq!(policy.schema(), WEBSOCKET_REVIEW_POLICY_SCHEMA);
        assert_eq!(policy.origin_mode(), WebSocketOriginMode::ApplicationOrigin);
        assert!(policy.has_subprotocol());
        assert!(policy.target_authorized());
        assert!(policy.messages_read_only_acknowledged());
        assert!(policy.message_content_is_non_secret());
        assert!(!policy.compression_enabled());
        assert!(!policy.reconnect_enabled());
        assert_eq!(policy.message_count(), 1);
        assert_eq!(policy.max_messages(), 1);
        assert_eq!(policy.max_control_frames(), 4);
        assert_eq!(policy.max_wall_time_ms(), 1000);
        assert_eq!(policy.execution_origin(), Some("https://example.test:8443"));
        assert_eq!(policy.execution_subprotocol(), Some(SUBPROTOCOL_CANARY));
        let message = policy.messages().next().unwrap();
        assert!(message
            .message_reference()
            .starts_with("websocket-message-revision-sha256:"));
        assert!(message
            .expected_response_reference()
            .starts_with("websocket-expected-response-revision-sha256:"));
        assert_eq!(message.outbound_length(), TEXT_CANARY.len() as u64);
        assert_eq!(message.expected_response_length(), 19);

        let rendered = format!("{policy:?} {message:?}");
        for canary in [
            ENDPOINT_CANARY,
            ID_CANARY,
            TEXT_CANARY,
            SUBPROTOCOL_CANARY,
            DIGEST_CANARY,
            "example.test",
        ] {
            assert!(!rendered.contains(canary), "Debug leaked {canary}");
        }
        assert!(rendered.contains(policy.policy_reference()));
        assert!(rendered.contains(policy.endpoint_reference()));
    }

    #[test]
    fn public_references_do_not_form_a_dictionary_oracle_for_private_message_bytes() {
        let baseline = parse(&valid_value()).unwrap();
        let mut private_change = valid_value();
        private_change["messages"][0]["text"] = json!("x".repeat(TEXT_CANARY.len()));
        private_change["messages"][0]["expected_response"]["sha256"] = json!("1".repeat(64));
        let private_change = parse(&private_change).unwrap();

        let baseline_message = baseline.messages().next().unwrap();
        let private_message = private_change.messages().next().unwrap();
        assert_eq!(
            baseline_message.message_reference(),
            private_message.message_reference()
        );
        assert_eq!(
            baseline_message.expected_response_reference(),
            private_message.expected_response_reference()
        );
        assert_eq!(
            baseline.policy_reference(),
            private_change.policy_reference()
        );

        let mut revised = valid_value();
        revised["messages"][0]["id"] = json!("message-revision-2");
        let revised = parse(&revised).unwrap();
        let revised_message = revised.messages().next().unwrap();
        assert_ne!(
            baseline_message.message_reference(),
            revised_message.message_reference()
        );
        assert_ne!(
            baseline_message.expected_response_reference(),
            revised_message.expected_response_reference()
        );
        assert_ne!(baseline.policy_reference(), revised.policy_reference());
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_depth_after_json_unescaping() {
        let root = br#"{"schema":"security.websocket-review-policy/v1","schema":"security.websocket-review-policy/v1"}"#;
        assert_eq!(
            WebSocketReviewPolicy::parse_json(&application(), root),
            Err(WebSocketReviewPolicyError::DuplicateJsonKey)
        );
        let nested = serde_json::to_string(&valid_value()).unwrap().replacen(
            &format!("\"sha256\":\"{DIGEST_CANARY}\""),
            &format!("\"sha256\":\"{DIGEST_CANARY}\",\"sha256\":\"{DIGEST_CANARY}\""),
            1,
        );
        assert_eq!(
            WebSocketReviewPolicy::parse_json(&application(), nested.as_bytes()),
            Err(WebSocketReviewPolicyError::DuplicateJsonKey)
        );
        let escaped = serde_json::to_string(&valid_value()).unwrap().replacen(
            "\"length\":19",
            "\"length\":19,\"len\\u0067th\":19",
            1,
        );
        assert_eq!(
            WebSocketReviewPolicy::parse_json(&application(), escaped.as_bytes()),
            Err(WebSocketReviewPolicyError::DuplicateJsonKey)
        );
    }

    #[test]
    fn endpoint_is_absolute_exact_authority_and_segment_contained() {
        for endpoint in [
            "wss://other.test:8443/application/ws",
            "wss://example.test:9443/application/ws",
            "wss://example.test:8443/application-other/ws",
        ] {
            let mut value = valid_value();
            value["endpoint"] = json!(endpoint);
            assert_eq!(
                parse(&value),
                Err(WebSocketReviewPolicyError::EndpointOutsideApplication),
                "{endpoint}"
            );
        }
        for endpoint in [
            "/application/ws",
            "https://example.test:8443/application/ws",
            "wss://user@example.test:8443/application/ws",
            "wss://example.test:8443/application/ws?secret=value",
            "wss://example.test:8443/application/ws#fragment",
            "wss://example.test:8443/application/%77s",
            "wss://example.test:8443/application/../application/ws",
            "wss://example.test:8443/application/./ws",
            "wss://example.test:8443/application//ws",
            "wss:\\\\example.test:8443\\application\\ws",
            "wss://example.test:8443/application/ ws",
        ] {
            let mut value = valid_value();
            value["endpoint"] = json!(endpoint);
            assert_eq!(
                parse(&value),
                Err(WebSocketReviewPolicyError::InvalidEndpoint),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn policy_binding_cannot_be_replayed_under_a_sibling_or_broader_application() {
        let policy = parse(&valid_value()).unwrap();
        assert!(policy.is_bound_to_application(&application()));
        assert!(!policy.is_bound_to_application(&Url::parse("https://example.test:8443/").unwrap()));
        assert!(!policy.is_bound_to_application(
            &Url::parse("https://example.test:8443/application-other/").unwrap()
        ));
        assert!(!policy
            .is_bound_to_application(&Url::parse("https://other.test:8443/application/").unwrap()));
    }

    #[test]
    fn plaintext_requires_http_and_numeric_loopback_on_both_sides() {
        let mut value = valid_value();
        value["endpoint"] = json!("ws://example.test:8443/application/ws");
        let domain_application = Url::parse("http://example.test:8443/application/").unwrap();
        assert_eq!(
            WebSocketReviewPolicy::parse_json(
                &domain_application,
                &serde_json::to_vec(&value).unwrap()
            ),
            Err(WebSocketReviewPolicyError::InsecureEndpoint)
        );

        let loopback = Url::parse("http://127.0.0.1:8080/application/").unwrap();
        value["endpoint"] = json!("ws://127.0.0.1:8080/application/ws");
        WebSocketReviewPolicy::parse_json(&loopback, &serde_json::to_vec(&value).unwrap()).unwrap();

        let named_loopback = Url::parse("http://localhost:8080/application/").unwrap();
        value["endpoint"] = json!("ws://localhost:8080/application/ws");
        assert_eq!(
            WebSocketReviewPolicy::parse_json(
                &named_loopback,
                &serde_json::to_vec(&value).unwrap()
            ),
            Err(WebSocketReviewPolicyError::InsecureEndpoint)
        );

        let non_loopback = Url::parse("http://192.0.2.1:8080/application/").unwrap();
        value["endpoint"] = json!("ws://192.0.2.1:8080/application/ws");
        assert_eq!(
            WebSocketReviewPolicy::parse_json(&non_loopback, &serde_json::to_vec(&value).unwrap()),
            Err(WebSocketReviewPolicyError::InsecureEndpoint)
        );
    }

    #[test]
    fn assertions_modes_subprotocol_compression_and_reconnect_fail_closed() {
        for (field, replacement, expected) in [
            (
                "target_authorized",
                json!(false),
                WebSocketReviewPolicyError::TargetAuthorizationRequired,
            ),
            (
                "messages_read_only_acknowledged",
                json!(false),
                WebSocketReviewPolicyError::ReadOnlyAcknowledgementRequired,
            ),
            (
                "message_content_is_non_secret",
                json!(false),
                WebSocketReviewPolicyError::NonSecretContentAcknowledgementRequired,
            ),
            (
                "origin_mode",
                json!("reflect_server"),
                WebSocketReviewPolicyError::UnsupportedOriginMode,
            ),
            (
                "subprotocol",
                json!("one, two"),
                WebSocketReviewPolicyError::InvalidSubprotocol,
            ),
            (
                "compression",
                json!(true),
                WebSocketReviewPolicyError::CompressionNotPermitted,
            ),
            (
                "reconnect",
                json!(true),
                WebSocketReviewPolicyError::ReconnectNotPermitted,
            ),
        ] {
            let mut value = valid_value();
            value[field] = replacement;
            assert_eq!(parse(&value), Err(expected), "{field}");
        }
        let mut omitted = valid_value();
        omitted["origin_mode"] = json!("omit");
        omitted["subprotocol"] = Value::Null;
        let policy = parse(&omitted).unwrap();
        assert_eq!(policy.origin_mode(), WebSocketOriginMode::Omit);
        assert_eq!(policy.execution_origin(), None);
        assert_eq!(policy.execution_subprotocol(), None);
    }

    #[test]
    fn message_count_identity_and_byte_bounds_are_exact() {
        let mut empty = valid_value();
        empty["messages"] = json!([]);
        assert_eq!(
            parse(&empty),
            Err(WebSocketReviewPolicyError::InvalidMessageCount)
        );

        let message = valid_value()["messages"][0].clone();
        let mut nine = valid_value();
        nine["messages"] = Value::Array(vec![message.clone(); 9]);
        assert_eq!(
            parse(&nine),
            Err(WebSocketReviewPolicyError::InvalidMessageCount)
        );

        let mut duplicate = valid_value();
        duplicate["messages"] = Value::Array(vec![message.clone(), message.clone()]);
        duplicate["limits"]["max_messages"] = json!(2);
        assert_eq!(
            parse(&duplicate),
            Err(WebSocketReviewPolicyError::DuplicateMessageId)
        );

        let mut unsafe_id = valid_value();
        unsafe_id["messages"][0]["id"] = json!("../unsafe");
        assert_eq!(
            parse(&unsafe_id),
            Err(WebSocketReviewPolicyError::InvalidMessageId)
        );

        let mut oversized = valid_value();
        oversized["messages"][0]["text"] =
            json!("x".repeat(MAX_WEBSOCKET_REVIEW_MESSAGE_TEXT_BYTES + 1));
        assert_eq!(
            parse(&oversized),
            Err(WebSocketReviewPolicyError::MessageTextTooLarge)
        );

        let mut aggregate = valid_value();
        let mut messages = Vec::new();
        for index in 0..5 {
            let mut current = message.clone();
            current["id"] = json!(format!("message-{index}"));
            current["text"] = json!("x".repeat(MAX_WEBSOCKET_REVIEW_MESSAGE_TEXT_BYTES));
            messages.push(current);
        }
        aggregate["messages"] = Value::Array(messages);
        aggregate["limits"]["max_messages"] = json!(5);
        aggregate["limits"]["max_outbound_message_bytes"] =
            json!(MAX_WEBSOCKET_REVIEW_MESSAGE_TEXT_BYTES);
        assert_eq!(
            parse(&aggregate),
            Err(WebSocketReviewPolicyError::MessageTextAggregateTooLarge)
        );
    }

    #[test]
    fn expected_responses_and_runtime_limits_are_bounded() {
        for digest in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            let mut value = valid_value();
            value["messages"][0]["expected_response"]["sha256"] = json!(digest);
            assert_eq!(
                parse(&value),
                Err(WebSocketReviewPolicyError::InvalidExpectedResponse)
            );
        }
        for (field, invalid) in [
            ("max_inbound_message_bytes", 0_u64),
            (
                "max_inbound_message_bytes",
                MAX_WEBSOCKET_REVIEW_DIRECTION_BYTES + 1,
            ),
            ("max_outbound_message_bytes", 0),
            ("max_messages", 0),
            (
                "max_messages",
                u64::try_from(MAX_WEBSOCKET_REVIEW_MESSAGES).unwrap() + 1,
            ),
            ("max_control_frames", 0),
            (
                "max_control_frames",
                u64::from(MAX_WEBSOCKET_REVIEW_CONTROL_FRAMES) + 1,
            ),
            ("max_wall_time_ms", 0),
            ("max_wall_time_ms", MAX_WEBSOCKET_REVIEW_WALL_TIME_MS + 1),
        ] {
            let mut value = valid_value();
            value["limits"][field] = json!(invalid);
            assert_eq!(
                parse(&value),
                Err(WebSocketReviewPolicyError::InvalidLimits),
                "{field}={invalid}"
            );
        }

        let mut too_short = valid_value();
        too_short["limits"]["max_outbound_message_bytes"] = json!(TEXT_CANARY.len() - 1);
        assert_eq!(
            parse(&too_short),
            Err(WebSocketReviewPolicyError::InvalidLimits)
        );

        let mut inbound_aggregate = valid_value();
        let mut messages = Vec::new();
        for index in 0..2 {
            let mut current = valid_value()["messages"][0].clone();
            current["id"] = json!(format!("expected-{index}"));
            current["expected_response"]["length"] = json!(40_000);
            messages.push(current);
        }
        inbound_aggregate["messages"] = Value::Array(messages);
        inbound_aggregate["limits"]["max_messages"] = json!(2);
        inbound_aggregate["limits"]["max_inbound_message_bytes"] = json!(40_000);
        assert_eq!(
            parse(&inbound_aggregate),
            Err(WebSocketReviewPolicyError::ExpectedResponseAggregateTooLarge)
        );
    }

    #[test]
    fn malformed_unknown_oversized_and_invalid_application_inputs_are_static_errors() {
        assert_eq!(
            WebSocketReviewPolicy::parse_json(&application(), b""),
            Err(WebSocketReviewPolicyError::EmptyPolicy)
        );
        assert_eq!(
            WebSocketReviewPolicy::parse_json(
                &application(),
                &vec![b' '; MAX_WEBSOCKET_REVIEW_POLICY_BYTES + 1]
            ),
            Err(WebSocketReviewPolicyError::PolicyTooLarge)
        );
        assert_eq!(
            WebSocketReviewPolicy::parse_json(&application(), b"not-json"),
            Err(WebSocketReviewPolicyError::MalformedPolicy)
        );
        let mut unknown = valid_value();
        unknown["credential"] = json!("secret");
        assert_eq!(
            parse(&unknown),
            Err(WebSocketReviewPolicyError::MalformedPolicy)
        );
        let invalid_application = Url::parse("https://example.test/application/?query=1").unwrap();
        assert_eq!(
            WebSocketReviewPolicy::parse_json(
                &invalid_application,
                &serde_json::to_vec(&valid_value()).unwrap()
            ),
            Err(WebSocketReviewPolicyError::InvalidApplicationTarget)
        );
    }
}
