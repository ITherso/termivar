//! Termivar-native, bounded HTTP OAST protocol and self-hosted provider.
//!
//! The provider is an auxiliary raw-free callback mailbox. It owns no target
//! authority, scanner action, vulnerability model, persistence, or background
//! task. Production deployment is loopback-only behind an operator-managed
//! HTTPS reverse proxy.

#![forbid(unsafe_code)]

mod config;
mod protocol;
mod secret;
mod state;

#[cfg(feature = "server")]
mod server;

pub use config::{
    LoopbackBind, ProviderConfig, ProviderLimits, PublicOrigin, HARD_MAX_ACTIVE_SESSIONS,
    HARD_MAX_CALLBACKS_PER_SESSION, HARD_MAX_CONCURRENT_REQUESTS, HARD_MAX_EVENTS_PER_SESSION,
    HARD_MAX_POLLS_PER_SESSION, HARD_MAX_POLL_EVENTS_PER_RESPONSE,
    HARD_MAX_SESSION_LIFETIME_MILLIS, MAX_MANAGEMENT_BODY_BYTES, MAX_MANAGEMENT_RESPONSE_BYTES,
    MAX_PUBLIC_ORIGIN_BYTES,
};
pub use protocol::{
    CallbackAllocation, CallbackDisposition, CallbackId, CallbackMethod, CallbackTarget,
    CleanupResponse, EventCursor, EventId, HttpEventRecord, ManagementBearer, NativeOastRoute,
    PollResponse, ProtocolClass, SessionId, SessionRegistration, SessionRequest, SessionToken,
    CALLBACK_SCHEMA, CLEANUP_SCHEMA, NATIVE_OAST_PROTOCOL_REVISION, POLL_SCHEMA, SESSION_SCHEMA,
};
pub use secret::AdminToken;
pub use state::ProviderState;

#[cfg(feature = "server")]
pub use server::{serve_provider, ProviderServerError};

/// Closed failures for native-provider configuration and state transitions.
///
/// Variants deliberately carry no caller-controlled strings or secret lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    /// A checked configuration limit was zero or exceeded its hard ceiling.
    InvalidConfiguration,
    /// The externally visible provider origin violated the exact HTTPS policy.
    InvalidPublicOrigin,
    /// The provider bind was not an exact loopback socket.
    NonLoopbackBindRejected,
    /// Administrator material violated the bounded bearer-token contract.
    InvalidAdminToken,
    /// A management bearer credential was absent, malformed, or incorrect.
    Unauthorized,
    /// The configured global active-session ceiling was reached.
    SessionCapacityExhausted,
    /// A registration request violated its strict schema or checked limits.
    InvalidSessionRequest,
    /// The addressed session has expired.
    SessionExpired,
    /// The addressed session does not exist or was removed.
    SessionNotFound,
    /// The per-session callback ceiling was reached.
    CallbackCapacityExhausted,
    /// The addressed callback does not exist for the session.
    CallbackNotFound,
    /// The per-session poll allowance was consumed.
    PollBudgetExhausted,
    /// An event could not be retained under the session ceiling.
    EventCapacityExhausted,
    /// The requested cursor was not canonical for the session.
    InvalidCursor,
    /// The raw request target was not one exact canonical native-provider route.
    InvalidRequestTarget,
    /// A management request exceeded the fixed byte ceiling.
    RequestTooLarge,
    /// A management response could not fit the fixed byte ceiling.
    ResponseTooLarge,
    /// The fixed route does not permit the supplied HTTP method.
    MethodNotAllowed,
    /// Host cancellation fired before completion.
    Cancelled,
    /// A bounded provider deadline elapsed.
    DeadlineExceeded,
    /// The operating system could not provide identity entropy.
    EntropyUnavailable,
    /// Internal state contradicted a checked provider invariant.
    InternalInvariant,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfiguration => "native OAST provider configuration is invalid",
            Self::InvalidPublicOrigin => "native OAST public origin is invalid",
            Self::NonLoopbackBindRejected => "native OAST provider bind must be loopback",
            Self::InvalidAdminToken => "native OAST administrator token is invalid",
            Self::Unauthorized => "native OAST management request is unauthorized",
            Self::SessionCapacityExhausted => "native OAST session capacity is exhausted",
            Self::InvalidSessionRequest => "native OAST session request is invalid",
            Self::SessionExpired => "native OAST session is expired",
            Self::SessionNotFound => "native OAST session was not found",
            Self::CallbackCapacityExhausted => "native OAST callback capacity is exhausted",
            Self::CallbackNotFound => "native OAST callback was not found",
            Self::PollBudgetExhausted => "native OAST poll budget is exhausted",
            Self::EventCapacityExhausted => "native OAST event capacity is exhausted",
            Self::InvalidCursor => "native OAST event cursor is invalid",
            Self::InvalidRequestTarget => "native OAST request target is invalid",
            Self::RequestTooLarge => "native OAST management request is too large",
            Self::ResponseTooLarge => "native OAST management response is too large",
            Self::MethodNotAllowed => "native OAST method is not allowed",
            Self::Cancelled => "native OAST operation was cancelled",
            Self::DeadlineExceeded => "native OAST operation deadline elapsed",
            Self::EntropyUnavailable => "native OAST identity generation failed",
            Self::InternalInvariant => "native OAST provider invariant failed",
        })
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::ProviderError;

    #[test]
    fn provider_error_messages_are_static_and_exhaustive() {
        let cases = [
            (
                ProviderError::InvalidConfiguration,
                "native OAST provider configuration is invalid",
            ),
            (
                ProviderError::InvalidPublicOrigin,
                "native OAST public origin is invalid",
            ),
            (
                ProviderError::NonLoopbackBindRejected,
                "native OAST provider bind must be loopback",
            ),
            (
                ProviderError::InvalidAdminToken,
                "native OAST administrator token is invalid",
            ),
            (
                ProviderError::Unauthorized,
                "native OAST management request is unauthorized",
            ),
            (
                ProviderError::SessionCapacityExhausted,
                "native OAST session capacity is exhausted",
            ),
            (
                ProviderError::InvalidSessionRequest,
                "native OAST session request is invalid",
            ),
            (
                ProviderError::SessionExpired,
                "native OAST session is expired",
            ),
            (
                ProviderError::SessionNotFound,
                "native OAST session was not found",
            ),
            (
                ProviderError::CallbackCapacityExhausted,
                "native OAST callback capacity is exhausted",
            ),
            (
                ProviderError::CallbackNotFound,
                "native OAST callback was not found",
            ),
            (
                ProviderError::PollBudgetExhausted,
                "native OAST poll budget is exhausted",
            ),
            (
                ProviderError::EventCapacityExhausted,
                "native OAST event capacity is exhausted",
            ),
            (
                ProviderError::InvalidCursor,
                "native OAST event cursor is invalid",
            ),
            (
                ProviderError::InvalidRequestTarget,
                "native OAST request target is invalid",
            ),
            (
                ProviderError::RequestTooLarge,
                "native OAST management request is too large",
            ),
            (
                ProviderError::ResponseTooLarge,
                "native OAST management response is too large",
            ),
            (
                ProviderError::MethodNotAllowed,
                "native OAST method is not allowed",
            ),
            (
                ProviderError::Cancelled,
                "native OAST operation was cancelled",
            ),
            (
                ProviderError::DeadlineExceeded,
                "native OAST operation deadline elapsed",
            ),
            (
                ProviderError::EntropyUnavailable,
                "native OAST identity generation failed",
            ),
            (
                ProviderError::InternalInvariant,
                "native OAST provider invariant failed",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
            assert!(!error.to_string().contains("MUST-NOT-LEAK"));
        }
    }
}
