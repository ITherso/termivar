//! Provider-neutral OAST correlation state.
//!
//! The host owns entropy, transport, scheduling, and projection into findings.
//! This module only binds opaque identities, accounts for bounded polls, checks
//! injected monotonic time, and commits raw-free callback classifications.

use crate::verification::VerificationCase;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};
use zeroize::Zeroize;

const TOKEN_BYTES: usize = 32;
const EVENT_KEY_BYTES: usize = 32;
const MAX_ASSESSMENT_ID_BYTES: usize = 256;
const MAX_VERIFICATION_BINDING_COMPONENT_BYTES: usize = 256;
const HARD_MAX_REGISTRATIONS: u16 = 4_096;
const HARD_MAX_POLLS: u16 = 64;
const HARD_MAX_EVENTS_PER_POLL: u16 = 64;
const HARD_MAX_UNIQUE_EVENTS: u16 = 1_024;
const HARD_MAX_LIFETIME_MILLIS: u64 = 86_400_000;

const TOKEN_REUSE_DOMAIN: &[u8] = b"security.oast-correlation.token-reuse.v1\0";
const BINDING_ID_DOMAIN: &[u8] = b"security.oast-correlation.binding.v1\0";
const CORRELATION_ID_DOMAIN: &[u8] = b"security.oast-correlation.id.v1\0";

/// Validation and state-transition failures for OAST correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OastError {
    /// The assessment identity was empty.
    EmptyAssessmentId,
    /// The assessment identity exceeded its bound.
    AssessmentIdTooLong {
        /// Supplied byte length.
        actual: usize,
        /// Maximum byte length.
        maximum: usize,
    },
    /// The assessment identity contained a disallowed byte.
    InvalidAssessmentId,
    /// An opaque 32-byte value used the reserved all-zero sentinel.
    ZeroOpaqueId,
    /// The lifetime was zero.
    ZeroLifetime,
    /// The lifetime exceeded the hard foundation bound.
    LifetimeTooLong {
        /// Requested milliseconds.
        actual: u64,
        /// Maximum milliseconds.
        maximum: u64,
    },
    /// The poll budget was zero.
    ZeroPollBudget,
    /// The poll budget exceeded the hard foundation bound.
    PollBudgetTooLarge {
        /// Requested polls.
        actual: u16,
        /// Maximum polls.
        maximum: u16,
    },
    /// At least one authority limit was zero.
    ZeroAuthorityLimit,
    /// One authority limit exceeded its hard foundation bound.
    AuthorityLimitTooLarge,
    /// No callback protocol was allowed.
    EmptyProtocolSet,
    /// The authority epoch reached its registration limit.
    RegistrationCapacityExhausted,
    /// The token had already been consumed in this authority epoch.
    TokenAlreadyRegistered,
    /// A verification-case identity component exceeded the OAST binding bound.
    VerificationBindingTooLarge,
    /// The requested lifetime exceeded the authority grant.
    LifetimeGrantExceeded {
        /// Requested milliseconds.
        requested: u64,
        /// Granted maximum milliseconds.
        maximum: u64,
    },
    /// The requested poll budget exceeded the authority grant.
    PollGrantExceeded {
        /// Requested polls.
        requested: u16,
        /// Granted maximum polls.
        maximum: u16,
    },
    /// Adding lifetime to the issued time overflowed.
    ExpiryOverflow,
    /// Assessment or verification-case identity did not match exactly.
    BindingMismatch,
    /// A callback was routed with another correlation identity.
    CorrelationMismatch,
    /// A callback used a protocol outside the registration grant.
    ProtocolNotAllowed {
        /// Rejected protocol.
        protocol: OastEventProtocol,
    },
    /// The injected monotonic time moved backwards.
    ClockRegressed {
        /// Last accepted time.
        previous: OastMonotonicTime,
        /// Regressed time.
        current: OastMonotonicTime,
    },
    /// The correlation is expired.
    Expired {
        /// Exclusive expiry boundary.
        expires_at: OastMonotonicTime,
    },
    /// The correlation was cancelled.
    Cancelled,
    /// Every poll in the grant was spent.
    PollBudgetExhausted,
    /// A staged poll exceeded its event bound.
    PollEventLimitExceeded {
        /// Maximum events in one poll.
        maximum: u16,
    },
    /// Atomic completion would exceed the registration unique-event bound.
    UniqueEventLimitExceeded {
        /// Maximum unique event keys.
        maximum: u16,
    },
    /// One event key was observed under two distinct protocol families.
    EventKeyProtocolConflict,
}

impl fmt::Display for OastError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAssessmentId => formatter.write_str("OAST assessment id is empty"),
            Self::AssessmentIdTooLong { actual, maximum } => {
                write!(
                    formatter,
                    "OAST assessment id length {actual} exceeds {maximum}"
                )
            },
            Self::InvalidAssessmentId => formatter.write_str("OAST assessment id is invalid"),
            Self::ZeroOpaqueId => formatter.write_str("OAST opaque id must not be all zero"),
            Self::ZeroLifetime => formatter.write_str("OAST lifetime must be non-zero"),
            Self::LifetimeTooLong { actual, maximum } => {
                write!(formatter, "OAST lifetime {actual}ms exceeds {maximum}ms")
            },
            Self::ZeroPollBudget => formatter.write_str("OAST poll budget must be non-zero"),
            Self::PollBudgetTooLarge { actual, maximum } => {
                write!(formatter, "OAST poll budget {actual} exceeds {maximum}")
            },
            Self::ZeroAuthorityLimit => {
                formatter.write_str("OAST authority limits must be non-zero")
            },
            Self::AuthorityLimitTooLarge => {
                formatter.write_str("OAST authority limit exceeds a hard foundation bound")
            },
            Self::EmptyProtocolSet => formatter.write_str("OAST protocol set must not be empty"),
            Self::RegistrationCapacityExhausted => {
                formatter.write_str("OAST registration capacity is exhausted")
            },
            Self::TokenAlreadyRegistered => {
                formatter.write_str("OAST token was already registered in this authority epoch")
            },
            Self::VerificationBindingTooLarge => {
                formatter.write_str("OAST verification binding exceeds its component bound")
            },
            Self::LifetimeGrantExceeded { requested, maximum } => {
                write!(
                    formatter,
                    "OAST lifetime {requested}ms exceeds grant {maximum}ms"
                )
            },
            Self::PollGrantExceeded { requested, maximum } => {
                write!(
                    formatter,
                    "OAST poll count {requested} exceeds grant {maximum}"
                )
            },
            Self::ExpiryOverflow => formatter.write_str("OAST expiry overflowed monotonic time"),
            Self::BindingMismatch => formatter.write_str("OAST binding does not match"),
            Self::CorrelationMismatch => formatter.write_str("OAST correlation does not match"),
            Self::ProtocolNotAllowed { protocol } => {
                write!(formatter, "OAST protocol {protocol:?} is not allowed")
            },
            Self::ClockRegressed { previous, current } => write!(
                formatter,
                "OAST time regressed from {}ms to {}ms",
                previous.as_millis(),
                current.as_millis()
            ),
            Self::Expired { expires_at } => {
                write!(
                    formatter,
                    "OAST correlation expired at {}ms",
                    expires_at.as_millis()
                )
            },
            Self::Cancelled => formatter.write_str("OAST correlation is cancelled"),
            Self::PollBudgetExhausted => formatter.write_str("OAST poll budget is exhausted"),
            Self::PollEventLimitExceeded { maximum } => {
                write!(formatter, "OAST poll exceeds its {maximum}-event bound")
            },
            Self::UniqueEventLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "OAST registration exceeds its {maximum}-event bound"
                )
            },
            Self::EventKeyProtocolConflict => {
                formatter.write_str("OAST event key has conflicting protocol families")
            },
        }
    }
}

impl Error for OastError {}

/// Exact host-owned assessment identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastAssessmentId(String);

impl OastAssessmentId {
    /// Validates an exact identity without trimming or normalization.
    pub fn new(value: impl AsRef<str>) -> Result<Self, OastError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(OastError::EmptyAssessmentId);
        }
        if value.len() > MAX_ASSESSMENT_ID_BYTES {
            return Err(OastError::AssessmentIdTooLong {
                actual: value.len(),
                maximum: MAX_ASSESSMENT_ID_BYTES,
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
        {
            return Err(OastError::InvalidAssessmentId);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OastAssessmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OastAssessmentId(<redacted>)")
    }
}

/// Host-minted single-use correlation secret.
///
/// The host must use a cryptographically secure source and must not reuse the
/// bytes. The wrapper is move-only, exposes no raw getter, and is consumed by
/// registration.
pub struct OastCorrelationToken {
    secret_bytes: [u8; 32],
}

impl OastCorrelationToken {
    /// Wraps 32 unpredictable host-minted bytes.
    pub fn new(secret_bytes: [u8; TOKEN_BYTES]) -> Result<Self, OastError> {
        reject_zero(&secret_bytes)?;
        Ok(Self { secret_bytes })
    }

    fn erase(&mut self) {
        self.secret_bytes.zeroize();
    }
}

impl fmt::Debug for OastCorrelationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OastCorrelationToken(<redacted>)")
    }
}

impl Drop for OastCorrelationToken {
    fn drop(&mut self) {
        self.erase();
    }
}

/// Opaque identity for one authority lifetime.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastAuthorityEpoch([u8; 32]);

impl OastAuthorityEpoch {
    /// Wraps a host-minted, non-zero epoch identity.
    pub fn new(bytes: [u8; 32]) -> Result<Self, OastError> {
        reject_zero(&bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for OastAuthorityEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OastAuthorityEpoch(<redacted>)")
    }
}

/// Opaque digest of every semantic registration grant.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastBindingId([u8; 32]);

impl fmt::Debug for OastBindingId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OastBindingId(<redacted>)")
    }
}

/// Opaque token-keyed identity for one exact binding.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastCorrelationId([u8; 32]);

impl fmt::Debug for OastCorrelationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OastCorrelationId(<redacted>)")
    }
}

/// Opaque provider-neutral identity for one callback event.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastEventKey([u8; 32]);

impl OastEventKey {
    /// Wraps a non-zero 32-byte event identity prepared by the host.
    pub fn new(bytes: [u8; EVENT_KEY_BYTES]) -> Result<Self, OastError> {
        reject_zero(&bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for OastEventKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OastEventKey(<redacted>)")
    }
}

/// Host-supplied monotonic milliseconds from an arbitrary origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastMonotonicTime(u64);

impl OastMonotonicTime {
    /// Creates a monotonic time value.
    pub const fn from_millis(milliseconds: u64) -> Self {
        Self(milliseconds)
    }

    /// Returns the host clock value.
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Validated correlation lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OastLifetime(u64);

impl OastLifetime {
    /// Creates a non-zero, hard-bounded lifetime.
    pub fn from_millis(milliseconds: u64) -> Result<Self, OastError> {
        if milliseconds == 0 {
            return Err(OastError::ZeroLifetime);
        }
        if milliseconds > HARD_MAX_LIFETIME_MILLIS {
            return Err(OastError::LifetimeTooLong {
                actual: milliseconds,
                maximum: HARD_MAX_LIFETIME_MILLIS,
            });
        }
        Ok(Self(milliseconds))
    }

    /// Returns the lifetime in milliseconds.
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Validated poll allowance for one registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OastPollBudget(u16);

impl OastPollBudget {
    /// Creates a non-zero, hard-bounded poll allowance.
    pub fn new(polls: u16) -> Result<Self, OastError> {
        if polls == 0 {
            return Err(OastError::ZeroPollBudget);
        }
        if polls > HARD_MAX_POLLS {
            return Err(OastError::PollBudgetTooLarge {
                actual: polls,
                maximum: HARD_MAX_POLLS,
            });
        }
        Ok(Self(polls))
    }

    /// Returns the poll allowance.
    pub const fn polls(self) -> u16 {
        self.0
    }
}

/// Explicit bounds owned by one authority epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OastAuthorityLimits {
    max_registrations: u16,
    max_polls_per_registration: u16,
    max_events_per_poll: u16,
    max_unique_events_per_registration: u16,
    max_lifetime_millis: u64,
}

impl OastAuthorityLimits {
    /// Validates all authority bounds.
    pub fn new(
        max_registrations: u16,
        max_polls_per_registration: u16,
        max_events_per_poll: u16,
        max_unique_events_per_registration: u16,
        max_lifetime_millis: u64,
    ) -> Result<Self, OastError> {
        if max_registrations == 0
            || max_polls_per_registration == 0
            || max_events_per_poll == 0
            || max_unique_events_per_registration == 0
            || max_lifetime_millis == 0
        {
            return Err(OastError::ZeroAuthorityLimit);
        }
        if max_registrations > HARD_MAX_REGISTRATIONS
            || max_polls_per_registration > HARD_MAX_POLLS
            || max_events_per_poll > HARD_MAX_EVENTS_PER_POLL
            || max_unique_events_per_registration > HARD_MAX_UNIQUE_EVENTS
            || max_lifetime_millis > HARD_MAX_LIFETIME_MILLIS
        {
            return Err(OastError::AuthorityLimitTooLarge);
        }
        Ok(Self {
            max_registrations,
            max_polls_per_registration,
            max_events_per_poll,
            max_unique_events_per_registration,
            max_lifetime_millis,
        })
    }

    /// Returns the registration bound.
    pub const fn max_registrations(self) -> u16 {
        self.max_registrations
    }

    /// Returns the per-registration poll bound.
    pub const fn max_polls_per_registration(self) -> u16 {
        self.max_polls_per_registration
    }

    /// Returns the per-poll event bound.
    pub const fn max_events_per_poll(self) -> u16 {
        self.max_events_per_poll
    }

    /// Returns the per-registration unique-event bound.
    pub const fn max_unique_events_per_registration(self) -> u16 {
        self.max_unique_events_per_registration
    }

    /// Returns the lifetime bound.
    pub const fn max_lifetime_millis(self) -> u64 {
        self.max_lifetime_millis
    }
}

/// Closed non-empty set of callback protocols granted to a registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OastProtocolSet(u8);

impl OastProtocolSet {
    const DNS: u8 = 1;
    const HTTP: u8 = 2;

    /// Creates a non-empty protocol grant.
    pub fn new(allow_dns: bool, allow_http: bool) -> Result<Self, OastError> {
        let bits = (u8::from(allow_dns) * Self::DNS) | (u8::from(allow_http) * Self::HTTP);
        if bits == 0 {
            return Err(OastError::EmptyProtocolSet);
        }
        Ok(Self(bits))
    }

    /// Returns whether this grant permits a protocol.
    pub const fn allows(self, protocol: OastEventProtocol) -> bool {
        let bit = match protocol {
            OastEventProtocol::Dns => Self::DNS,
            OastEventProtocol::Http => Self::HTTP,
        };
        self.0 & bit != 0
    }

    /// Returns whether DNS is granted.
    pub const fn allows_dns(self) -> bool {
        self.0 & Self::DNS != 0
    }

    /// Returns whether HTTP is granted.
    pub const fn allows_http(self) -> bool {
        self.0 & Self::HTTP != 0
    }
}

/// Transport classification for a raw-free DNS event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OastDnsTransport {
    /// Datagram transport.
    Udp,
    /// Stream transport.
    Tcp,
}

/// Record classification for a raw-free DNS event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OastDnsRecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Canonical name.
    Cname,
    /// Mail exchange.
    Mx,
    /// Name server.
    Ns,
    /// Reverse pointer.
    Ptr,
    /// Service locator.
    Srv,
    /// Text.
    Txt,
    /// Another record type, without its raw numeric value.
    Other,
}

/// Typed DNS callback without names, addresses, or payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastDnsEvent {
    transport: OastDnsTransport,
    record_type: OastDnsRecordType,
}

impl OastDnsEvent {
    /// Creates a raw-free DNS classification.
    pub const fn new(transport: OastDnsTransport, record_type: OastDnsRecordType) -> Self {
        Self {
            transport,
            record_type,
        }
    }

    /// Returns the transport.
    pub const fn transport(self) -> OastDnsTransport {
        self.transport
    }

    /// Returns the record type.
    pub const fn record_type(self) -> OastDnsRecordType {
        self.record_type
    }
}

/// Scheme classification for a raw-free HTTP event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OastHttpScheme {
    /// Cleartext HTTP.
    Http,
    /// TLS-protected HTTP.
    Https,
}

/// Method classification for a raw-free HTTP event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum OastHttpMethod {
    /// GET.
    Get,
    /// HEAD.
    Head,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// PATCH.
    Patch,
    /// DELETE.
    Delete,
    /// OPTIONS.
    Options,
    /// TRACE.
    Trace,
    /// CONNECT.
    Connect,
    /// Another method, without its raw token.
    Other,
}

/// Typed HTTP callback without paths, headers, addresses, or body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OastHttpEvent {
    scheme: OastHttpScheme,
    method: OastHttpMethod,
    body_present: bool,
}

impl OastHttpEvent {
    /// Creates a raw-free HTTP classification.
    pub const fn new(scheme: OastHttpScheme, method: OastHttpMethod, body_present: bool) -> Self {
        Self {
            scheme,
            method,
            body_present,
        }
    }

    /// Returns the scheme.
    pub const fn scheme(self) -> OastHttpScheme {
        self.scheme
    }

    /// Returns the method.
    pub const fn method(self) -> OastHttpMethod {
        self.method
    }

    /// Returns whether a non-empty body was observed.
    pub const fn body_present(self) -> bool {
        self.body_present
    }
}

/// Callback protocol family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OastEventProtocol {
    /// DNS callback.
    Dns,
    /// HTTP callback.
    Http,
}

/// Provider-neutral event with an opaque fixed-width identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OastEvent {
    /// DNS callback.
    Dns(OastEventKey, OastDnsEvent),
    /// HTTP callback.
    Http(OastEventKey, OastHttpEvent),
}

impl OastEvent {
    /// Returns the opaque event identity.
    pub fn key(&self) -> &OastEventKey {
        match self {
            Self::Dns(key, _) | Self::Http(key, _) => key,
        }
    }

    /// Returns the raw-free protocol family.
    pub const fn protocol(&self) -> OastEventProtocol {
        match self {
            Self::Dns(_, _) => OastEventProtocol::Dns,
            Self::Http(_, _) => OastEventProtocol::Http,
        }
    }
}

/// Result of atomically committing one event key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OastEventDisposition {
    /// The key was new.
    Accepted,
    /// The same key and protocol were already committed.
    DuplicateSuppressed,
}

/// Terminal lifecycle state for one registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OastCorrelationState {
    /// The registration is neither cancelled nor expired; budget is separate.
    Active,
    /// The host cancelled the registration.
    Cancelled,
    /// The exclusive expiry boundary was reached.
    Expired,
}

/// Redacted receipt for one successful registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastRegistrationReceipt {
    binding_id: OastBindingId,
    correlation_id: OastCorrelationId,
    issued_at: OastMonotonicTime,
    expires_at: OastMonotonicTime,
    poll_limit: u16,
    allowed_protocols: OastProtocolSet,
}

impl OastRegistrationReceipt {
    /// Returns the non-secret binding identity.
    pub fn binding_id(&self) -> &OastBindingId {
        &self.binding_id
    }

    /// Returns the opaque correlation identity.
    pub fn correlation_id(&self) -> &OastCorrelationId {
        &self.correlation_id
    }

    /// Returns registration time.
    pub const fn issued_at(&self) -> OastMonotonicTime {
        self.issued_at
    }

    /// Returns exclusive expiry.
    pub const fn expires_at(&self) -> OastMonotonicTime {
        self.expires_at
    }

    /// Returns the granted poll count.
    pub const fn poll_limit(&self) -> u16 {
        self.poll_limit
    }

    /// Returns the granted protocols.
    pub const fn allowed_protocols(&self) -> OastProtocolSet {
        self.allowed_protocols
    }
}

/// Redacted receipt for one event in an atomic poll commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastEventReceipt {
    event_key: OastEventKey,
    protocol: OastEventProtocol,
    disposition: OastEventDisposition,
    observed_at: OastMonotonicTime,
}

impl OastEventReceipt {
    /// Returns the opaque event key.
    pub fn event_key(&self) -> &OastEventKey {
        &self.event_key
    }

    /// Returns the protocol.
    pub const fn protocol(&self) -> OastEventProtocol {
        self.protocol
    }

    /// Returns the duplicate disposition.
    pub const fn disposition(&self) -> OastEventDisposition {
        self.disposition
    }

    /// Returns the injected observation time.
    pub const fn observed_at(&self) -> OastMonotonicTime {
        self.observed_at
    }
}

/// Redacted receipt for one atomic poll commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastPollReceipt {
    binding_id: OastBindingId,
    correlation_id: OastCorrelationId,
    poll_ordinal: u16,
    completed_at: OastMonotonicTime,
    event_receipts: Vec<OastEventReceipt>,
    accepted_events: u16,
    duplicate_events: u16,
    remaining_polls: u16,
}

impl OastPollReceipt {
    /// Returns the binding identity.
    pub fn binding_id(&self) -> &OastBindingId {
        &self.binding_id
    }

    /// Returns the correlation identity.
    pub fn correlation_id(&self) -> &OastCorrelationId {
        &self.correlation_id
    }

    /// Returns the one-based poll ordinal.
    pub const fn poll_ordinal(&self) -> u16 {
        self.poll_ordinal
    }

    /// Returns the completion time.
    pub const fn completed_at(&self) -> OastMonotonicTime {
        self.completed_at
    }

    /// Returns ordered typed event receipts.
    pub fn event_receipts(&self) -> &[OastEventReceipt] {
        &self.event_receipts
    }

    /// Returns accepted-event count for this poll.
    pub const fn accepted_events(&self) -> u16 {
        self.accepted_events
    }

    /// Returns suppressed-duplicate count for this poll.
    pub const fn duplicate_events(&self) -> u16 {
        self.duplicate_events
    }

    /// Returns polls remaining after permit issuance.
    pub const fn remaining_polls(&self) -> u16 {
        self.remaining_polls
    }
}

/// Redacted receipt for cancellation or expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OastTerminalReceipt {
    binding_id: OastBindingId,
    correlation_id: OastCorrelationId,
    state: OastCorrelationState,
    terminal_at: OastMonotonicTime,
}

impl OastTerminalReceipt {
    /// Returns the binding identity.
    pub fn binding_id(&self) -> &OastBindingId {
        &self.binding_id
    }

    /// Returns the correlation identity.
    pub fn correlation_id(&self) -> &OastCorrelationId {
        &self.correlation_id
    }

    /// Returns the terminal state.
    pub const fn state(&self) -> OastCorrelationState {
        self.state
    }

    /// Returns cancellation time or the exact expiry boundary.
    pub const fn terminal_at(&self) -> OastMonotonicTime {
        self.terminal_at
    }
}

/// Bounded token-reuse authority for one explicit epoch.
///
/// Token fingerprints remain reserved until this value is dropped, including
/// after registrations cancel or expire. This type intentionally has no
/// Default implementation.
pub struct OastCorrelationAuthority {
    epoch: OastAuthorityEpoch,
    assessment_id: OastAssessmentId,
    limits: OastAuthorityLimits,
    registered: u16,
    token_fingerprints: BTreeSet<[u8; 32]>,
}

impl fmt::Debug for OastCorrelationAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OastCorrelationAuthority")
            .field("epoch", &self.epoch)
            .field("assessment_id", &self.assessment_id)
            .field("limits", &self.limits)
            .field("registered", &self.registered)
            .field("reserved_tokens", &self.token_fingerprints.len())
            .finish()
    }
}

impl OastCorrelationAuthority {
    /// Starts an isolated authority epoch with explicit bounds.
    pub fn new(
        epoch: OastAuthorityEpoch,
        assessment_id: OastAssessmentId,
        limits: OastAuthorityLimits,
    ) -> Self {
        Self {
            epoch,
            assessment_id,
            limits,
            registered: 0,
            token_fingerprints: BTreeSet::new(),
        }
    }

    /// Returns the epoch identity.
    pub fn epoch(&self) -> &OastAuthorityEpoch {
        &self.epoch
    }

    /// Returns the exact assessment identity bound to this epoch.
    pub fn assessment_id(&self) -> &OastAssessmentId {
        &self.assessment_id
    }

    /// Returns the configured bounds.
    pub const fn limits(&self) -> OastAuthorityLimits {
        self.limits
    }

    /// Returns the number of tokens consumed in this epoch.
    pub const fn registered(&self) -> u16 {
        self.registered
    }

    /// Consumes a token and creates one exact bounded registration.
    pub fn register(
        &mut self,
        verification_case: VerificationCase,
        token: OastCorrelationToken,
        allowed_protocols: OastProtocolSet,
        issued_at: OastMonotonicTime,
        lifetime: OastLifetime,
        poll_budget: OastPollBudget,
    ) -> Result<(OastCorrelation, OastRegistrationReceipt), OastError> {
        validate_verification_binding(&verification_case)?;
        if self.registered >= self.limits.max_registrations {
            return Err(OastError::RegistrationCapacityExhausted);
        }
        if lifetime.0 > self.limits.max_lifetime_millis {
            return Err(OastError::LifetimeGrantExceeded {
                requested: lifetime.0,
                maximum: self.limits.max_lifetime_millis,
            });
        }
        if poll_budget.0 > self.limits.max_polls_per_registration {
            return Err(OastError::PollGrantExceeded {
                requested: poll_budget.0,
                maximum: self.limits.max_polls_per_registration,
            });
        }
        let expires_at = OastMonotonicTime(
            issued_at
                .0
                .checked_add(lifetime.0)
                .ok_or(OastError::ExpiryOverflow)?,
        );
        let token_fingerprint = token_fingerprint(&token);
        if self.token_fingerprints.contains(&token_fingerprint) {
            return Err(OastError::TokenAlreadyRegistered);
        }

        let assessment_id = self.assessment_id.clone();
        let binding_id = binding_id(&BindingMaterial {
            epoch: &self.epoch,
            limits: self.limits,
            assessment_id: &assessment_id,
            verification_case: &verification_case,
            protocols: allowed_protocols,
            issued_at,
            expires_at,
            poll_budget,
        });
        let correlation_id = correlation_id(&token, &binding_id);
        let receipt = OastRegistrationReceipt {
            binding_id: binding_id.clone(),
            correlation_id: correlation_id.clone(),
            issued_at,
            expires_at,
            poll_limit: poll_budget.0,
            allowed_protocols,
        };
        self.token_fingerprints.insert(token_fingerprint);
        self.registered += 1;
        Ok((
            OastCorrelation {
                binding_id,
                correlation_id,
                assessment_id,
                verification_case,
                allowed_protocols,
                issued_at,
                expires_at,
                last_time: issued_at,
                state: OastCorrelationState::Active,
                terminal_at: None,
                poll_limit: poll_budget.0,
                remaining_polls: poll_budget.0,
                next_poll_ordinal: 1,
                max_events_per_poll: self.limits.max_events_per_poll,
                max_unique_events: self.limits.max_unique_events_per_registration,
                seen_events: BTreeMap::new(),
                accepted_events: 0,
                duplicate_events: 0,
                abandoned_polls: 0,
            },
            receipt,
        ))
    }
}

/// One exact registration and its bounded correlation state.
pub struct OastCorrelation {
    binding_id: OastBindingId,
    correlation_id: OastCorrelationId,
    assessment_id: OastAssessmentId,
    verification_case: VerificationCase,
    allowed_protocols: OastProtocolSet,
    issued_at: OastMonotonicTime,
    expires_at: OastMonotonicTime,
    last_time: OastMonotonicTime,
    state: OastCorrelationState,
    terminal_at: Option<OastMonotonicTime>,
    poll_limit: u16,
    remaining_polls: u16,
    next_poll_ordinal: u16,
    max_events_per_poll: u16,
    max_unique_events: u16,
    seen_events: BTreeMap<OastEventKey, OastEventProtocol>,
    accepted_events: u16,
    duplicate_events: u16,
    abandoned_polls: u16,
}

impl fmt::Debug for OastCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OastCorrelation")
            .field("binding_id", &self.binding_id)
            .field("correlation_id", &self.correlation_id)
            .field("assessment_id", &self.assessment_id)
            .field("verification_case", &"<redacted>")
            .field("allowed_protocols", &self.allowed_protocols)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("state", &self.state)
            .field("poll_limit", &self.poll_limit)
            .field("remaining_polls", &self.remaining_polls)
            .field("accepted_events", &self.accepted_events)
            .field("duplicate_events", &self.duplicate_events)
            .field("abandoned_polls", &self.abandoned_polls)
            .finish()
    }
}

impl OastCorrelation {
    /// Returns the binding identity.
    pub fn binding_id(&self) -> &OastBindingId {
        &self.binding_id
    }

    /// Returns the correlation identity.
    pub fn correlation_id(&self) -> &OastCorrelationId {
        &self.correlation_id
    }

    /// Returns the exact assessment identity.
    pub fn assessment_id(&self) -> &OastAssessmentId {
        &self.assessment_id
    }

    /// Returns the complete verification case.
    pub fn verification_case(&self) -> &VerificationCase {
        &self.verification_case
    }

    /// Returns the protocol grant.
    pub const fn allowed_protocols(&self) -> OastProtocolSet {
        self.allowed_protocols
    }

    /// Returns registration time.
    pub const fn issued_at(&self) -> OastMonotonicTime {
        self.issued_at
    }

    /// Returns exclusive expiry.
    pub const fn expires_at(&self) -> OastMonotonicTime {
        self.expires_at
    }

    /// Returns the lifecycle state.
    pub const fn state(&self) -> OastCorrelationState {
        self.state
    }

    /// Returns a typed terminal receipt after cancellation or observed expiry.
    pub fn terminal_receipt(&self) -> Option<OastTerminalReceipt> {
        self.terminal_at.map(|terminal_at| OastTerminalReceipt {
            binding_id: self.binding_id.clone(),
            correlation_id: self.correlation_id.clone(),
            state: self.state,
            terminal_at,
        })
    }

    /// Returns the original poll grant.
    pub const fn poll_limit(&self) -> u16 {
        self.poll_limit
    }

    /// Returns unspent polls.
    pub const fn remaining_polls(&self) -> u16 {
        self.remaining_polls
    }

    /// Returns committed unique keys.
    pub fn unique_events(&self) -> usize {
        self.seen_events.len()
    }

    /// Returns committed accepted-event count.
    pub const fn accepted_events(&self) -> u16 {
        self.accepted_events
    }

    /// Returns committed duplicate count.
    pub const fn duplicate_events(&self) -> u16 {
        self.duplicate_events
    }

    /// Returns permits dropped or consumed by a failed atomic completion.
    pub const fn abandoned_polls(&self) -> u16 {
        self.abandoned_polls
    }

    /// Cancels an active registration after exact binding validation.
    pub fn cancel(
        &mut self,
        assessment_id: &OastAssessmentId,
        verification_case: &VerificationCase,
        now: OastMonotonicTime,
    ) -> Result<OastTerminalReceipt, OastError> {
        self.ensure_binding(assessment_id, verification_case)?;
        self.ensure_active_at(now)?;
        self.last_time = now;
        self.state = OastCorrelationState::Cancelled;
        self.terminal_at = Some(now);
        Ok(OastTerminalReceipt {
            binding_id: self.binding_id.clone(),
            correlation_id: self.correlation_id.clone(),
            state: OastCorrelationState::Cancelled,
            terminal_at: now,
        })
    }

    /// Spends one poll and returns a move-only exclusive permit.
    ///
    /// Binding, state, time, expiry, and budget checks occur before the poll is
    /// spent. Dropping a permit never refunds the poll.
    pub fn begin_poll<'a>(
        &'a mut self,
        assessment_id: &OastAssessmentId,
        verification_case: &VerificationCase,
        now: OastMonotonicTime,
    ) -> Result<OastPollPermit<'a>, OastError> {
        self.ensure_binding(assessment_id, verification_case)?;
        self.ensure_active_at(now)?;
        if self.remaining_polls == 0 {
            return Err(OastError::PollBudgetExhausted);
        }
        let poll_ordinal = self.next_poll_ordinal;
        self.next_poll_ordinal += 1;
        self.remaining_polls -= 1;
        self.last_time = now;
        Ok(OastPollPermit {
            correlation: self,
            poll_ordinal,
            latest_observed_time: now,
            staged_events: Vec::new(),
            failure: None,
            committed: false,
        })
    }

    fn ensure_binding(
        &self,
        assessment_id: &OastAssessmentId,
        verification_case: &VerificationCase,
    ) -> Result<(), OastError> {
        if assessment_id != &self.assessment_id || verification_case != &self.verification_case {
            return Err(OastError::BindingMismatch);
        }
        Ok(())
    }

    fn ensure_active_at(&mut self, now: OastMonotonicTime) -> Result<(), OastError> {
        match self.state {
            OastCorrelationState::Cancelled => return Err(OastError::Cancelled),
            OastCorrelationState::Expired => {
                return Err(OastError::Expired {
                    expires_at: self.expires_at,
                });
            },
            OastCorrelationState::Active => {},
        }
        if now < self.last_time {
            return Err(OastError::ClockRegressed {
                previous: self.last_time,
                current: now,
            });
        }
        if now >= self.expires_at {
            self.state = OastCorrelationState::Expired;
            self.terminal_at = Some(self.expires_at);
            return Err(OastError::Expired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct StagedEvent {
    event: OastEvent,
    observed_at: OastMonotonicTime,
}

/// Move-only authority to prepare one atomic poll commit.
///
/// The exclusive registration borrow prevents concurrent permits. Events stay
/// local to the permit until consuming completion validates the entire batch.
pub struct OastPollPermit<'a> {
    correlation: &'a mut OastCorrelation,
    poll_ordinal: u16,
    latest_observed_time: OastMonotonicTime,
    staged_events: Vec<StagedEvent>,
    failure: Option<OastError>,
    committed: bool,
}

impl fmt::Debug for OastPollPermit<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OastPollPermit")
            .field("binding_id", &self.correlation.binding_id)
            .field("correlation_id", &self.correlation.correlation_id)
            .field("poll_ordinal", &self.poll_ordinal)
            .field("staged_events", &self.staged_events.len())
            .finish()
    }
}

impl OastPollPermit<'_> {
    /// Returns the one-based poll ordinal.
    pub const fn poll_ordinal(&self) -> u16 {
        self.poll_ordinal
    }

    /// Returns remaining polls after this permit was issued.
    pub const fn remaining_polls(&self) -> u16 {
        self.correlation.remaining_polls
    }

    /// Returns the number of locally staged events.
    pub fn staged_events(&self) -> usize {
        self.staged_events.len()
    }

    /// Stages one callback without mutating committed event state.
    pub fn stage_event(
        &mut self,
        correlation_id: &OastCorrelationId,
        event: OastEvent,
        observed_at: OastMonotonicTime,
    ) -> Result<(), OastError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if correlation_id != &self.correlation.correlation_id {
            return self.reject(OastError::CorrelationMismatch);
        }
        let protocol = event.protocol();
        if !self.correlation.allowed_protocols.allows(protocol) {
            return self.reject(OastError::ProtocolNotAllowed { protocol });
        }
        if self.staged_events.len() >= usize::from(self.correlation.max_events_per_poll) {
            return self.reject(OastError::PollEventLimitExceeded {
                maximum: self.correlation.max_events_per_poll,
            });
        }
        if let Err(error) = self.correlation.ensure_active_at(observed_at) {
            return self.reject(error);
        }
        if observed_at > self.latest_observed_time {
            self.latest_observed_time = observed_at;
        }
        self.staged_events.push(StagedEvent { event, observed_at });
        Ok(())
    }

    /// Validates and commits the staged batch atomically.
    pub fn finish(mut self, completed_at: OastMonotonicTime) -> Result<OastPollReceipt, OastError> {
        self.ensure_completion_time(completed_at)?;
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.staged_events.sort_by(|left, right| {
            left.event
                .key()
                .cmp(right.event.key())
                .then_with(|| left.event.protocol().cmp(&right.event.protocol()))
                .then_with(|| left.observed_at.cmp(&right.observed_at))
        });

        let mut batch_protocols = BTreeMap::<OastEventKey, OastEventProtocol>::new();
        let mut receipts = Vec::with_capacity(self.staged_events.len());
        let mut accepted_events = 0u16;
        let mut duplicate_events = 0u16;

        for staged in &self.staged_events {
            let key = staged.event.key();
            let protocol = staged.event.protocol();
            let known = self
                .correlation
                .seen_events
                .get(key)
                .or_else(|| batch_protocols.get(key));
            let disposition = match known {
                Some(existing) if *existing == protocol => {
                    duplicate_events += 1;
                    OastEventDisposition::DuplicateSuppressed
                },
                Some(_) => return Err(OastError::EventKeyProtocolConflict),
                None => {
                    accepted_events += 1;
                    batch_protocols.insert(key.clone(), protocol);
                    OastEventDisposition::Accepted
                },
            };
            receipts.push(OastEventReceipt {
                event_key: key.clone(),
                protocol,
                disposition,
                observed_at: staged.observed_at,
            });
        }

        if self.correlation.seen_events.len() + batch_protocols.len()
            > usize::from(self.correlation.max_unique_events)
        {
            return Err(OastError::UniqueEventLimitExceeded {
                maximum: self.correlation.max_unique_events,
            });
        }

        for (key, protocol) in batch_protocols {
            self.correlation.seen_events.insert(key, protocol);
        }
        self.correlation.accepted_events += accepted_events;
        self.correlation.duplicate_events += duplicate_events;
        self.correlation.last_time = completed_at;
        self.committed = true;

        Ok(OastPollReceipt {
            binding_id: self.correlation.binding_id.clone(),
            correlation_id: self.correlation.correlation_id.clone(),
            poll_ordinal: self.poll_ordinal,
            completed_at,
            event_receipts: receipts,
            accepted_events,
            duplicate_events,
            remaining_polls: self.correlation.remaining_polls,
        })
    }

    fn ensure_completion_time(&mut self, completed_at: OastMonotonicTime) -> Result<(), OastError> {
        self.correlation.ensure_active_at(completed_at)?;
        if completed_at < self.latest_observed_time {
            return Err(OastError::ClockRegressed {
                previous: self.latest_observed_time,
                current: completed_at,
            });
        }
        Ok(())
    }

    fn reject<T>(&mut self, error: OastError) -> Result<T, OastError> {
        self.failure = Some(error.clone());
        Err(error)
    }
}

impl Drop for OastPollPermit<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.correlation.abandoned_polls += 1;
        }
    }
}

fn reject_zero(bytes: &[u8; 32]) -> Result<(), OastError> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(OastError::ZeroOpaqueId);
    }
    Ok(())
}

fn validate_verification_binding(verification_case: &VerificationCase) -> Result<(), OastError> {
    let components = [
        verification_case.id(),
        verification_case.subject().as_str(),
        verification_case.action_id(),
        verification_case.hypothesis_id(),
    ];
    if components
        .iter()
        .any(|component| component.len() > MAX_VERIFICATION_BINDING_COMPONENT_BYTES)
    {
        return Err(OastError::VerificationBindingTooLarge);
    }
    Ok(())
}

fn token_fingerprint(token: &OastCorrelationToken) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_REUSE_DOMAIN);
    hash_field(&mut hasher, &token.secret_bytes);
    hasher.finalize().into()
}

struct BindingMaterial<'a> {
    epoch: &'a OastAuthorityEpoch,
    limits: OastAuthorityLimits,
    assessment_id: &'a OastAssessmentId,
    verification_case: &'a VerificationCase,
    protocols: OastProtocolSet,
    issued_at: OastMonotonicTime,
    expires_at: OastMonotonicTime,
    poll_budget: OastPollBudget,
}

fn binding_id(material: &BindingMaterial<'_>) -> OastBindingId {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_ID_DOMAIN);
    hash_field(&mut hasher, &material.epoch.0);
    hash_field(&mut hasher, material.assessment_id.0.as_bytes());
    hash_verification_case(&mut hasher, material.verification_case);
    hasher.update([material.protocols.0]);
    hasher.update(material.issued_at.0.to_be_bytes());
    hasher.update(material.expires_at.0.to_be_bytes());
    hasher.update(material.poll_budget.0.to_be_bytes());
    hasher.update(material.limits.max_registrations.to_be_bytes());
    hasher.update(material.limits.max_polls_per_registration.to_be_bytes());
    hasher.update(material.limits.max_events_per_poll.to_be_bytes());
    hasher.update(
        material
            .limits
            .max_unique_events_per_registration
            .to_be_bytes(),
    );
    hasher.update(material.limits.max_lifetime_millis.to_be_bytes());
    OastBindingId(hasher.finalize().into())
}

fn correlation_id(token: &OastCorrelationToken, binding_id: &OastBindingId) -> OastCorrelationId {
    let mut hasher = Sha256::new();
    hasher.update(CORRELATION_ID_DOMAIN);
    hash_field(&mut hasher, &token.secret_bytes);
    hash_field(&mut hasher, &binding_id.0);
    OastCorrelationId(hasher.finalize().into())
}

fn hash_verification_case(hasher: &mut Sha256, verification_case: &VerificationCase) {
    hash_field(hasher, verification_case.id().as_bytes());
    hash_field(hasher, verification_case.subject().as_str().as_bytes());
    hash_field(hasher, verification_case.action_id().as_bytes());
    hash_field(hasher, verification_case.hypothesis_id().as_bytes());
    hasher.update([u8::from(verification_case.applies_hypothesis_transition())]);
    match verification_case.payload_strategy() {
        Some(strategy) => {
            hasher.update([1]);
            hash_field(hasher, strategy.id().as_bytes());
            hasher.update(strategy.revision().to_be_bytes());
        },
        None => hasher.update([0]),
    }
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u128).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload_strategy::PayloadStrategyRef;
    use termivar_core::EntityId;

    const SECRET: [u8; 32] = [
        0x91, 0x2f, 0x73, 0xa4, 0x05, 0x66, 0xb7, 0x18, 0xc9, 0x2a, 0xdb, 0x3c, 0xed, 0x4e, 0xff,
        0x50, 0x11, 0x82, 0x23, 0x94, 0x35, 0xa6, 0x47, 0xb8, 0x59, 0xca, 0x6b, 0xdc, 0x7d, 0xee,
        0x8f, 0xf0,
    ];
    const EPOCH: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    fn assessment(value: &str) -> OastAssessmentId {
        OastAssessmentId::new(value).unwrap()
    }

    fn subject(value: &str) -> EntityId {
        EntityId::new(value).unwrap()
    }

    fn verification_case() -> VerificationCase {
        VerificationCase::new(
            "case:oast:1",
            subject("resource:oast:1"),
            "web.review.oast",
            "hypothesis:ssrf:1",
        )
        .unwrap()
    }

    fn token(bytes: [u8; 32]) -> OastCorrelationToken {
        OastCorrelationToken::new(bytes).unwrap()
    }

    fn epoch(bytes: [u8; 32]) -> OastAuthorityEpoch {
        OastAuthorityEpoch::new(bytes).unwrap()
    }

    fn limits(
        registrations: u16,
        polls: u16,
        events_per_poll: u16,
        unique_events: u16,
    ) -> OastAuthorityLimits {
        OastAuthorityLimits::new(registrations, polls, events_per_poll, unique_events, 100).unwrap()
    }

    fn protocols(dns: bool, http: bool) -> OastProtocolSet {
        OastProtocolSet::new(dns, http).unwrap()
    }

    fn event_key(marker: u8) -> OastEventKey {
        let mut bytes = [0; 32];
        bytes[0] = marker;
        OastEventKey::new(bytes).unwrap()
    }

    fn dns(marker: u8) -> OastEvent {
        OastEvent::Dns(
            event_key(marker),
            OastDnsEvent::new(OastDnsTransport::Udp, OastDnsRecordType::A),
        )
    }

    fn http(marker: u8) -> OastEvent {
        OastEvent::Http(
            event_key(marker),
            OastHttpEvent::new(OastHttpScheme::Https, OastHttpMethod::Get, false),
        )
    }

    fn register(
        authority: &mut OastCorrelationAuthority,
        secret: [u8; 32],
    ) -> (OastCorrelation, OastRegistrationReceipt) {
        authority
            .register(
                verification_case(),
                token(secret),
                protocols(true, true),
                OastMonotonicTime::from_millis(1_000),
                OastLifetime::from_millis(100).unwrap(),
                OastPollBudget::new(3).unwrap(),
            )
            .unwrap()
    }

    fn authority() -> OastCorrelationAuthority {
        OastCorrelationAuthority::new(epoch(EPOCH), assessment("assessment:1"), limits(8, 4, 4, 8))
    }

    #[test]
    fn constructors_enforce_exact_public_bounds() {
        assert_eq!(
            OastAssessmentId::new("").unwrap_err(),
            OastError::EmptyAssessmentId
        );
        assert_eq!(
            OastAssessmentId::new(" assessment:1").unwrap_err(),
            OastError::InvalidAssessmentId
        );
        assert_eq!(
            OastAssessmentId::new("x".repeat(MAX_ASSESSMENT_ID_BYTES + 1)).unwrap_err(),
            OastError::AssessmentIdTooLong {
                actual: MAX_ASSESSMENT_ID_BYTES + 1,
                maximum: MAX_ASSESSMENT_ID_BYTES,
            }
        );
        assert_eq!(
            OastCorrelationToken::new([0; 32]).unwrap_err(),
            OastError::ZeroOpaqueId
        );
        assert_eq!(
            OastAuthorityEpoch::new([0; 32]).unwrap_err(),
            OastError::ZeroOpaqueId
        );
        assert_eq!(
            OastEventKey::new([0; 32]).unwrap_err(),
            OastError::ZeroOpaqueId
        );
        assert_eq!(
            OastLifetime::from_millis(0).unwrap_err(),
            OastError::ZeroLifetime
        );
        assert_eq!(
            OastLifetime::from_millis(HARD_MAX_LIFETIME_MILLIS + 1).unwrap_err(),
            OastError::LifetimeTooLong {
                actual: HARD_MAX_LIFETIME_MILLIS + 1,
                maximum: HARD_MAX_LIFETIME_MILLIS,
            }
        );
        assert_eq!(
            OastPollBudget::new(0).unwrap_err(),
            OastError::ZeroPollBudget
        );
        assert_eq!(
            OastPollBudget::new(HARD_MAX_POLLS + 1).unwrap_err(),
            OastError::PollBudgetTooLarge {
                actual: HARD_MAX_POLLS + 1,
                maximum: HARD_MAX_POLLS,
            }
        );
        assert_eq!(
            OastAuthorityLimits::new(0, 1, 1, 1, 1).unwrap_err(),
            OastError::ZeroAuthorityLimit
        );
        assert_eq!(
            OastAuthorityLimits::new(HARD_MAX_REGISTRATIONS + 1, 1, 1, 1, 1).unwrap_err(),
            OastError::AuthorityLimitTooLarge
        );
        assert_eq!(
            OastProtocolSet::new(false, false).unwrap_err(),
            OastError::EmptyProtocolSet
        );
        assert_eq!(
            assessment("Assessment_1.v2:test").as_str(),
            "Assessment_1.v2:test"
        );
    }

    #[test]
    fn public_bounds_and_receipts_expose_only_typed_state() {
        let authority_limits = limits(2, 2, 3, 4);
        assert_eq!(authority_limits.max_registrations(), 2);
        assert_eq!(authority_limits.max_polls_per_registration(), 2);
        assert_eq!(authority_limits.max_events_per_poll(), 3);
        assert_eq!(authority_limits.max_unique_events_per_registration(), 4);
        assert_eq!(authority_limits.max_lifetime_millis(), 100);
        assert_eq!(OastLifetime::from_millis(100).unwrap().as_millis(), 100);
        assert_eq!(OastPollBudget::new(2).unwrap().polls(), 2);

        let mut authority = OastCorrelationAuthority::new(
            epoch(EPOCH),
            assessment("assessment:1"),
            authority_limits,
        );
        assert_eq!(authority.epoch(), &epoch(EPOCH));
        assert_eq!(authority.limits(), authority_limits);
        let (mut correlation, registration) = authority
            .register(
                verification_case(),
                token(SECRET),
                protocols(true, true),
                OastMonotonicTime::from_millis(1_000),
                OastLifetime::from_millis(100).unwrap(),
                OastPollBudget::new(2).unwrap(),
            )
            .unwrap();
        assert_eq!(registration.binding_id(), correlation.binding_id());
        assert_eq!(registration.correlation_id(), correlation.correlation_id());
        assert_eq!(registration.issued_at().as_millis(), 1_000);
        assert_eq!(registration.expires_at().as_millis(), 1_100);
        assert_eq!(registration.poll_limit(), 2);
        assert!(registration.allowed_protocols().allows_dns());
        assert!(registration.allowed_protocols().allows_http());
        assert_eq!(correlation.issued_at(), registration.issued_at());
        assert_eq!(correlation.expires_at(), registration.expires_at());
        assert_eq!(correlation.poll_limit(), registration.poll_limit());
        assert_eq!(correlation.state(), OastCorrelationState::Active);
        assert!(correlation.terminal_receipt().is_none());

        let id = correlation.correlation_id().clone();
        let bound_assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();
        let mut permit = correlation
            .begin_poll(
                &bound_assessment,
                &case,
                OastMonotonicTime::from_millis(1_001),
            )
            .unwrap();
        assert_eq!(permit.poll_ordinal(), 1);
        assert_eq!(permit.remaining_polls(), 1);
        assert_eq!(permit.staged_events(), 0);
        assert!(format!("{permit:?}").contains("staged_events: 0"));
        permit
            .stage_event(&id, http(1), OastMonotonicTime::from_millis(1_002))
            .unwrap();
        assert_eq!(permit.staged_events(), 1);
        let receipt = permit
            .finish(OastMonotonicTime::from_millis(1_003))
            .unwrap();
        assert_eq!(receipt.poll_ordinal(), 1);
        assert_eq!(receipt.completed_at().as_millis(), 1_003);
        assert_eq!(receipt.remaining_polls(), 1);
        let event = &receipt.event_receipts()[0];
        assert_eq!(event.event_key(), &event_key(1));
        assert_eq!(event.protocol(), OastEventProtocol::Http);
        assert_eq!(event.disposition(), OastEventDisposition::Accepted);
        assert_eq!(event.observed_at().as_millis(), 1_002);

        let terminal = correlation
            .cancel(
                &bound_assessment,
                &case,
                OastMonotonicTime::from_millis(1_004),
            )
            .unwrap();
        assert_eq!(terminal.binding_id(), registration.binding_id());
        assert_eq!(terminal.correlation_id(), registration.correlation_id());
    }

    #[test]
    fn every_error_has_a_value_safe_typed_display() {
        let errors = [
            (OastError::EmptyAssessmentId, "OAST assessment id is empty"),
            (
                OastError::AssessmentIdTooLong {
                    actual: 257,
                    maximum: 256,
                },
                "OAST assessment id length 257 exceeds 256",
            ),
            (
                OastError::InvalidAssessmentId,
                "OAST assessment id is invalid",
            ),
            (
                OastError::ZeroOpaqueId,
                "OAST opaque id must not be all zero",
            ),
            (OastError::ZeroLifetime, "OAST lifetime must be non-zero"),
            (
                OastError::LifetimeTooLong {
                    actual: 101,
                    maximum: 100,
                },
                "OAST lifetime 101ms exceeds 100ms",
            ),
            (
                OastError::ZeroPollBudget,
                "OAST poll budget must be non-zero",
            ),
            (
                OastError::PollBudgetTooLarge {
                    actual: 2,
                    maximum: 1,
                },
                "OAST poll budget 2 exceeds 1",
            ),
            (
                OastError::ZeroAuthorityLimit,
                "OAST authority limits must be non-zero",
            ),
            (
                OastError::AuthorityLimitTooLarge,
                "OAST authority limit exceeds a hard foundation bound",
            ),
            (
                OastError::EmptyProtocolSet,
                "OAST protocol set must not be empty",
            ),
            (
                OastError::RegistrationCapacityExhausted,
                "OAST registration capacity is exhausted",
            ),
            (
                OastError::TokenAlreadyRegistered,
                "OAST token was already registered in this authority epoch",
            ),
            (
                OastError::VerificationBindingTooLarge,
                "OAST verification binding exceeds its component bound",
            ),
            (
                OastError::LifetimeGrantExceeded {
                    requested: 101,
                    maximum: 100,
                },
                "OAST lifetime 101ms exceeds grant 100ms",
            ),
            (
                OastError::PollGrantExceeded {
                    requested: 2,
                    maximum: 1,
                },
                "OAST poll count 2 exceeds grant 1",
            ),
            (
                OastError::ExpiryOverflow,
                "OAST expiry overflowed monotonic time",
            ),
            (OastError::BindingMismatch, "OAST binding does not match"),
            (
                OastError::CorrelationMismatch,
                "OAST correlation does not match",
            ),
            (
                OastError::ProtocolNotAllowed {
                    protocol: OastEventProtocol::Http,
                },
                "OAST protocol Http is not allowed",
            ),
            (
                OastError::ClockRegressed {
                    previous: OastMonotonicTime::from_millis(2),
                    current: OastMonotonicTime::from_millis(1),
                },
                "OAST time regressed from 2ms to 1ms",
            ),
            (
                OastError::Expired {
                    expires_at: OastMonotonicTime::from_millis(9),
                },
                "OAST correlation expired at 9ms",
            ),
            (OastError::Cancelled, "OAST correlation is cancelled"),
            (
                OastError::PollBudgetExhausted,
                "OAST poll budget is exhausted",
            ),
            (
                OastError::PollEventLimitExceeded { maximum: 3 },
                "OAST poll exceeds its 3-event bound",
            ),
            (
                OastError::UniqueEventLimitExceeded { maximum: 4 },
                "OAST registration exceeds its 4-event bound",
            ),
            (
                OastError::EventKeyProtocolConflict,
                "OAST event key has conflicting protocol families",
            ),
        ];
        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
            let as_error: &dyn Error = &error;
            assert!(as_error.source().is_none());
        }
    }

    #[test]
    fn expiry_overflow_and_exhausted_poll_budget_fail_closed() {
        let mut overflow_authority = OastCorrelationAuthority::new(
            epoch(EPOCH),
            assessment("assessment:1"),
            limits(2, 1, 1, 1),
        );
        assert_eq!(
            overflow_authority
                .register(
                    verification_case(),
                    token(SECRET),
                    protocols(true, false),
                    OastMonotonicTime::from_millis(u64::MAX),
                    OastLifetime::from_millis(1).unwrap(),
                    OastPollBudget::new(1).unwrap(),
                )
                .unwrap_err(),
            OastError::ExpiryOverflow
        );
        assert_eq!(overflow_authority.registered(), 0);

        let (mut correlation, _) = overflow_authority
            .register(
                verification_case(),
                token(SECRET),
                protocols(true, false),
                OastMonotonicTime::from_millis(1_000),
                OastLifetime::from_millis(100).unwrap(),
                OastPollBudget::new(1).unwrap(),
            )
            .unwrap();
        let bound_assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();
        correlation
            .begin_poll(
                &bound_assessment,
                &case,
                OastMonotonicTime::from_millis(1_001),
            )
            .unwrap()
            .finish(OastMonotonicTime::from_millis(1_002))
            .unwrap();
        assert_eq!(correlation.remaining_polls(), 0);
        assert_eq!(
            correlation
                .begin_poll(
                    &bound_assessment,
                    &case,
                    OastMonotonicTime::from_millis(1_003),
                )
                .unwrap_err(),
            OastError::PollBudgetExhausted
        );
    }

    #[test]
    fn secret_and_opaque_debug_output_is_redacted() {
        let mut secret = token(SECRET);
        assert_eq!(format!("{secret:?}"), "OastCorrelationToken(<redacted>)");
        secret.erase();
        assert_eq!(secret.secret_bytes, [0; 32]);
        assert!(std::mem::needs_drop::<OastCorrelationToken>());

        let mut authority = authority();
        let (correlation, receipt) = register(&mut authority, SECRET);
        let rendered = format!(
            "{authority:?} {correlation:?} {receipt:?} {:?} {:?} {:?}",
            epoch(EPOCH),
            receipt.binding_id(),
            event_key(9)
        );
        for raw in [
            "assessment:1",
            "case:oast:1",
            "resource:oast:1",
            "hypothesis:ssrf:1",
            "145, 47, 115",
        ] {
            assert!(!rendered.contains(raw));
        }
        assert!(rendered.matches("<redacted>").count() >= 5);
    }

    #[test]
    fn authority_rejects_reuse_and_capacity_without_forgetting_terminal_tokens() {
        let mut authority = OastCorrelationAuthority::new(
            epoch(EPOCH),
            assessment("assessment:1"),
            limits(2, 3, 3, 3),
        );
        let (mut first, _) = register(&mut authority, SECRET);
        let bound_assessment = first.assessment_id().clone();
        let case = first.verification_case().clone();
        let cancelled = first
            .cancel(
                &bound_assessment,
                &case,
                OastMonotonicTime::from_millis(1_001),
            )
            .unwrap();
        assert_eq!(cancelled.state(), OastCorrelationState::Cancelled);
        assert_eq!(
            authority
                .register(
                    verification_case(),
                    token(SECRET),
                    protocols(true, false),
                    OastMonotonicTime::from_millis(2_000),
                    OastLifetime::from_millis(50).unwrap(),
                    OastPollBudget::new(1).unwrap(),
                )
                .unwrap_err(),
            OastError::TokenAlreadyRegistered
        );

        let mut second_secret = SECRET;
        second_secret[0] ^= 1;
        register(&mut authority, second_secret);
        let mut third_secret = SECRET;
        third_secret[1] ^= 1;
        assert_eq!(
            authority
                .register(
                    verification_case(),
                    token(third_secret),
                    protocols(true, true),
                    OastMonotonicTime::from_millis(3_000),
                    OastLifetime::from_millis(50).unwrap(),
                    OastPollBudget::new(1).unwrap(),
                )
                .unwrap_err(),
            OastError::RegistrationCapacityExhausted
        );
        assert_eq!(authority.registered(), 2);
    }

    #[test]
    fn registration_enforces_authority_grants_before_mutation() {
        let mut authority = OastCorrelationAuthority::new(
            epoch(EPOCH),
            assessment("assessment:1"),
            limits(2, 1, 1, 1),
        );
        assert_eq!(authority.assessment_id(), &assessment("assessment:1"));
        assert_eq!(
            authority
                .register(
                    verification_case(),
                    token(SECRET),
                    protocols(true, false),
                    OastMonotonicTime::from_millis(0),
                    OastLifetime::from_millis(101).unwrap(),
                    OastPollBudget::new(1).unwrap(),
                )
                .unwrap_err(),
            OastError::LifetimeGrantExceeded {
                requested: 101,
                maximum: 100,
            }
        );
        assert_eq!(
            authority
                .register(
                    verification_case(),
                    token(SECRET),
                    protocols(true, false),
                    OastMonotonicTime::from_millis(0),
                    OastLifetime::from_millis(100).unwrap(),
                    OastPollBudget::new(2).unwrap(),
                )
                .unwrap_err(),
            OastError::PollGrantExceeded {
                requested: 2,
                maximum: 1,
            }
        );
        assert_eq!(authority.registered(), 0);
        authority
            .register(
                verification_case(),
                token(SECRET),
                protocols(true, false),
                OastMonotonicTime::from_millis(0),
                OastLifetime::from_millis(100).unwrap(),
                OastPollBudget::new(1).unwrap(),
            )
            .unwrap();
        assert_eq!(authority.registered(), 1);
    }

    #[test]
    fn registration_bounds_every_verification_identity_before_hashing() {
        let oversized = "x".repeat(MAX_VERIFICATION_BINDING_COMPONENT_BYTES + 1);
        let cases = [
            VerificationCase::new(
                oversized.clone(),
                subject("resource:oast:1"),
                "action:oast:1",
                "hypothesis:ssrf:1",
            )
            .unwrap(),
            VerificationCase::new(
                "case:oast:1",
                subject(&oversized),
                "action:oast:1",
                "hypothesis:ssrf:1",
            )
            .unwrap(),
            VerificationCase::new(
                "case:oast:1",
                subject("resource:oast:1"),
                oversized.clone(),
                "hypothesis:ssrf:1",
            )
            .unwrap(),
            VerificationCase::new(
                "case:oast:1",
                subject("resource:oast:1"),
                "action:oast:1",
                oversized,
            )
            .unwrap(),
        ];
        let mut authority = authority();
        for case in cases {
            assert_eq!(
                authority
                    .register(
                        case,
                        token(SECRET),
                        protocols(true, true),
                        OastMonotonicTime::from_millis(1_000),
                        OastLifetime::from_millis(100).unwrap(),
                        OastPollBudget::new(1).unwrap(),
                    )
                    .unwrap_err(),
                OastError::VerificationBindingTooLarge
            );
            assert_eq!(authority.registered(), 0);
        }

        let maximum = "x".repeat(MAX_VERIFICATION_BINDING_COMPONENT_BYTES);
        let maximum_case =
            VerificationCase::new(maximum.clone(), subject(&maximum), maximum.clone(), maximum)
                .unwrap();
        authority
            .register(
                maximum_case,
                token(SECRET),
                protocols(true, true),
                OastMonotonicTime::from_millis(1_000),
                OastLifetime::from_millis(100).unwrap(),
                OastPollBudget::new(1).unwrap(),
            )
            .unwrap();
        assert_eq!(authority.registered(), 1);
    }

    #[test]
    fn binding_and_correlation_ids_cover_every_semantic_dimension() {
        #[derive(Clone)]
        struct IdInputs {
            epoch_bytes: [u8; 32],
            authority_limits: OastAuthorityLimits,
            assessment_id: OastAssessmentId,
            case: VerificationCase,
            secret: [u8; 32],
            allowed_protocols: OastProtocolSet,
            issued_at: u64,
            lifetime: u64,
            polls: u16,
        }

        fn ids(inputs: IdInputs) -> (OastBindingId, OastCorrelationId) {
            let mut authority = OastCorrelationAuthority::new(
                epoch(inputs.epoch_bytes),
                inputs.assessment_id.clone(),
                inputs.authority_limits,
            );
            let receipt = authority
                .register(
                    inputs.case,
                    token(inputs.secret),
                    inputs.allowed_protocols,
                    OastMonotonicTime::from_millis(inputs.issued_at),
                    OastLifetime::from_millis(inputs.lifetime).unwrap(),
                    OastPollBudget::new(inputs.polls).unwrap(),
                )
                .unwrap()
                .1;
            (receipt.binding_id, receipt.correlation_id)
        }

        let base_limits = limits(8, 4, 4, 8);
        let inputs = IdInputs {
            epoch_bytes: EPOCH,
            authority_limits: base_limits,
            assessment_id: assessment("assessment:1"),
            case: verification_case(),
            secret: SECRET,
            allowed_protocols: protocols(true, true),
            issued_at: 1_000,
            lifetime: 100,
            polls: 3,
        };
        let baseline = ids(inputs.clone());
        assert_eq!(baseline, ids(inputs.clone()));

        let mut changed_epoch = EPOCH;
        changed_epoch[0] ^= 1;
        let changed_cases = [
            VerificationCase::new(
                "case:oast:2",
                subject("resource:oast:1"),
                "web.review.oast",
                "hypothesis:ssrf:1",
            )
            .unwrap(),
            VerificationCase::new(
                "case:oast:1",
                subject("resource:oast:2"),
                "web.review.oast",
                "hypothesis:ssrf:1",
            )
            .unwrap(),
            VerificationCase::new(
                "case:oast:1",
                subject("resource:oast:1"),
                "web.review.other",
                "hypothesis:ssrf:1",
            )
            .unwrap(),
            VerificationCase::new(
                "case:oast:1",
                subject("resource:oast:1"),
                "web.review.oast",
                "hypothesis:ssrf:2",
            )
            .unwrap(),
            verification_case().without_hypothesis_transition(),
            verification_case()
                .with_payload_strategy(Some(PayloadStrategyRef::new("strategy:oast", 1).unwrap())),
        ];
        for case in changed_cases {
            let mut changed = inputs.clone();
            changed.case = case;
            assert_ne!(baseline.0, ids(changed).0);
        }

        let variations = [
            IdInputs {
                epoch_bytes: changed_epoch,
                ..inputs.clone()
            },
            IdInputs {
                assessment_id: assessment("assessment:2"),
                ..inputs.clone()
            },
            IdInputs {
                allowed_protocols: protocols(true, false),
                ..inputs.clone()
            },
            IdInputs {
                issued_at: 1_001,
                lifetime: 99,
                ..inputs.clone()
            },
            IdInputs {
                authority_limits: limits(9, 4, 4, 8),
                ..inputs.clone()
            },
            IdInputs {
                polls: 2,
                ..inputs.clone()
            },
        ];
        for variation in variations.map(ids) {
            assert_ne!(baseline.0, variation.0);
            assert_ne!(baseline.1, variation.1);
        }

        let mut changed_secret = SECRET;
        changed_secret[31] ^= 1;
        let secret_variation = ids(IdInputs {
            secret: changed_secret,
            ..inputs
        });
        assert_eq!(baseline.0, secret_variation.0);
        assert_ne!(baseline.1, secret_variation.1);
    }

    #[test]
    fn v1_identity_algorithms_match_fixed_golden_vectors() {
        assert_eq!(
            token_fingerprint(&token(SECRET)),
            [
                0x16, 0x55, 0x21, 0x51, 0xf8, 0xe5, 0xb0, 0xa6, 0x85, 0x0c, 0x39, 0x32, 0x1a, 0xbc,
                0x13, 0xa2, 0xb6, 0x03, 0xbe, 0x3b, 0x35, 0x3d, 0xc1, 0xf5, 0x88, 0x61, 0x03, 0xaf,
                0xc5, 0x57, 0xb0, 0xc9,
            ]
        );

        let mut authority = authority();
        let (_, receipt) = register(&mut authority, SECRET);
        assert_eq!(
            receipt.binding_id.0,
            [
                0x8e, 0xdd, 0xd8, 0x7b, 0x7b, 0x81, 0x66, 0x7c, 0xf3, 0xff, 0x38, 0x8b, 0x13, 0x63,
                0x5e, 0x7e, 0x61, 0xc4, 0xc6, 0xed, 0x3b, 0x89, 0xfb, 0x0a, 0x50, 0x72, 0x32, 0x4d,
                0x6e, 0x05, 0x03, 0xb3,
            ]
        );
        assert_eq!(
            receipt.correlation_id.0,
            [
                0x6e, 0x91, 0x58, 0x98, 0x5c, 0x84, 0x6f, 0xf0, 0xf0, 0x98, 0xf9, 0x37, 0xba, 0xe3,
                0x7e, 0x00, 0x5d, 0x1a, 0x6e, 0x0f, 0xf4, 0xd9, 0x33, 0x00, 0xa0, 0x11, 0x72, 0xd1,
                0x1b, 0xf0, 0x92, 0xc7,
            ]
        );
    }

    #[test]
    fn exact_binding_and_poll_budget_fail_without_accidental_spend() {
        let mut authority = authority();
        let (mut correlation, _) = register(&mut authority, SECRET);
        let correct_assessment = correlation.assessment_id().clone();
        let correct_case = correlation.verification_case().clone();
        let initial = correlation.remaining_polls();
        assert_eq!(
            correlation
                .begin_poll(
                    &assessment("assessment:wrong"),
                    &correct_case,
                    OastMonotonicTime::from_millis(1_001),
                )
                .unwrap_err(),
            OastError::BindingMismatch
        );
        let wrong_case = VerificationCase::new(
            correct_case.id(),
            subject("resource:wrong"),
            correct_case.action_id(),
            correct_case.hypothesis_id(),
        )
        .unwrap();
        assert_eq!(
            correlation
                .begin_poll(
                    &correct_assessment,
                    &wrong_case,
                    OastMonotonicTime::from_millis(1_001),
                )
                .unwrap_err(),
            OastError::BindingMismatch
        );
        assert_eq!(correlation.remaining_polls(), initial);

        drop(
            correlation
                .begin_poll(
                    &correct_assessment,
                    &correct_case,
                    OastMonotonicTime::from_millis(1_001),
                )
                .unwrap(),
        );
        assert_eq!(correlation.remaining_polls(), initial - 1);
        assert_eq!(correlation.abandoned_polls(), 1);
    }

    #[test]
    fn event_models_are_typed_raw_free_and_protocol_grants_fail_closed() {
        let dns_data = OastDnsEvent::new(OastDnsTransport::Tcp, OastDnsRecordType::Txt);
        assert_eq!(dns_data.transport(), OastDnsTransport::Tcp);
        assert_eq!(dns_data.record_type(), OastDnsRecordType::Txt);
        let http_data = OastHttpEvent::new(OastHttpScheme::Https, OastHttpMethod::Post, true);
        assert_eq!(http_data.scheme(), OastHttpScheme::Https);
        assert_eq!(http_data.method(), OastHttpMethod::Post);
        assert!(http_data.body_present());

        let mut authority = OastCorrelationAuthority::new(
            epoch(EPOCH),
            assessment("assessment:1"),
            limits(2, 2, 2, 2),
        );
        let (mut correlation, _) = authority
            .register(
                verification_case(),
                token(SECRET),
                protocols(true, false),
                OastMonotonicTime::from_millis(1_000),
                OastLifetime::from_millis(100).unwrap(),
                OastPollBudget::new(2).unwrap(),
            )
            .unwrap();
        assert!(correlation.allowed_protocols().allows_dns());
        assert!(!correlation.allowed_protocols().allows_http());
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();
        let mut permit = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
            .unwrap();
        let error = OastError::ProtocolNotAllowed {
            protocol: OastEventProtocol::Http,
        };
        assert_eq!(
            permit
                .stage_event(&id, http(1), OastMonotonicTime::from_millis(1_002))
                .unwrap_err(),
            error
        );
        assert_eq!(
            permit
                .finish(OastMonotonicTime::from_millis(1_003))
                .unwrap_err(),
            error
        );
        assert_eq!(correlation.unique_events(), 0);
    }

    #[test]
    fn atomic_completion_uses_event_key_and_protocol_family() {
        let mut authority = authority();
        let (mut correlation, registration) = register(&mut authority, SECRET);
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();

        let mut first = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
            .unwrap();
        first
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_002))
            .unwrap();
        first
            .stage_event(&id, dns(2), OastMonotonicTime::from_millis(1_003))
            .unwrap();
        let first_receipt = first.finish(OastMonotonicTime::from_millis(1_004)).unwrap();
        assert_eq!(first_receipt.accepted_events(), 2);
        assert_eq!(first_receipt.duplicate_events(), 0);
        assert_eq!(first_receipt.event_receipts().len(), 2);
        assert_eq!(first_receipt.binding_id(), registration.binding_id());
        assert_eq!(
            first_receipt.correlation_id(),
            registration.correlation_id()
        );

        let mut second = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_005))
            .unwrap();
        second
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_006))
            .unwrap();
        second
            .stage_event(
                &id,
                OastEvent::Dns(
                    event_key(3),
                    OastDnsEvent::new(OastDnsTransport::Tcp, OastDnsRecordType::Txt),
                ),
                OastMonotonicTime::from_millis(1_007),
            )
            .unwrap();
        second
            .stage_event(
                &id,
                OastEvent::Dns(
                    event_key(3),
                    OastDnsEvent::new(OastDnsTransport::Tcp, OastDnsRecordType::Txt),
                ),
                OastMonotonicTime::from_millis(1_008),
            )
            .unwrap();
        let second_receipt = second
            .finish(OastMonotonicTime::from_millis(1_009))
            .unwrap();
        assert_eq!(second_receipt.accepted_events(), 1);
        assert_eq!(second_receipt.duplicate_events(), 2);
        assert_eq!(
            second_receipt.event_receipts()[0].disposition(),
            OastEventDisposition::DuplicateSuppressed
        );
        assert_eq!(correlation.unique_events(), 3);
        assert_eq!(correlation.accepted_events(), 3);
        assert_eq!(correlation.duplicate_events(), 2);
        assert_eq!(correlation.abandoned_polls(), 0);
    }

    #[test]
    fn poll_receipts_are_canonical_across_provider_batch_order() {
        fn complete(order: [u8; 3]) -> OastPollReceipt {
            let mut authority = authority();
            let (mut correlation, _) = register(&mut authority, SECRET);
            let id = correlation.correlation_id().clone();
            let assessment = correlation.assessment_id().clone();
            let case = correlation.verification_case().clone();
            let mut permit = correlation
                .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
                .unwrap();
            for marker in order {
                permit
                    .stage_event(
                        &id,
                        dns(marker),
                        OastMonotonicTime::from_millis(1_010 + u64::from(marker)),
                    )
                    .unwrap();
            }
            permit
                .finish(OastMonotonicTime::from_millis(1_020))
                .unwrap()
        }

        let ascending = complete([1, 2, 3]);
        let reordered = complete([3, 1, 2]);
        assert_eq!(ascending, reordered);
        assert_eq!(
            ascending
                .event_receipts()
                .iter()
                .map(|receipt| receipt.event_key().clone())
                .collect::<Vec<_>>(),
            vec![event_key(1), event_key(2), event_key(3)]
        );
    }

    #[test]
    fn same_key_same_protocol_is_duplicate_despite_metadata_changes() {
        let mut authority = authority();
        let (mut correlation, _) = register(&mut authority, SECRET);
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();

        let mut permit = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
            .unwrap();
        permit
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_002))
            .unwrap();
        permit
            .stage_event(
                &id,
                OastEvent::Dns(
                    event_key(1),
                    OastDnsEvent::new(OastDnsTransport::Tcp, OastDnsRecordType::Txt),
                ),
                OastMonotonicTime::from_millis(1_003),
            )
            .unwrap();
        let receipt = permit
            .finish(OastMonotonicTime::from_millis(1_004))
            .unwrap();
        assert_eq!(receipt.accepted_events(), 1);
        assert_eq!(receipt.duplicate_events(), 1);
        assert_eq!(correlation.unique_events(), 1);
        assert_eq!(correlation.accepted_events(), 1);
        assert_eq!(correlation.duplicate_events(), 1);
        assert_eq!(correlation.abandoned_polls(), 0);
    }

    #[test]
    fn protocol_conflict_rejects_the_entire_batch_without_event_mutation() {
        let mut authority = authority();
        let (mut correlation, _) = register(&mut authority, SECRET);
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();

        let mut accepted = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
            .unwrap();
        accepted
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_002))
            .unwrap();
        accepted
            .finish(OastMonotonicTime::from_millis(1_003))
            .unwrap();

        let mut conflicting = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_004))
            .unwrap();
        conflicting
            .stage_event(&id, http(1), OastMonotonicTime::from_millis(1_005))
            .unwrap();
        assert_eq!(
            conflicting
                .finish(OastMonotonicTime::from_millis(1_006))
                .unwrap_err(),
            OastError::EventKeyProtocolConflict
        );
        assert_eq!(correlation.unique_events(), 1);
        assert_eq!(correlation.accepted_events(), 1);
        assert_eq!(correlation.duplicate_events(), 0);
        assert_eq!(correlation.abandoned_polls(), 1);
    }

    #[test]
    fn poll_and_unique_limits_reject_whole_batches() {
        let mut authority = OastCorrelationAuthority::new(
            epoch(EPOCH),
            assessment("assessment:1"),
            limits(2, 3, 2, 1),
        );
        let (mut correlation, _) = register(&mut authority, SECRET);
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();

        let mut too_many_for_poll = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
            .unwrap();
        too_many_for_poll
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_002))
            .unwrap();
        too_many_for_poll
            .stage_event(&id, dns(2), OastMonotonicTime::from_millis(1_003))
            .unwrap();
        let poll_error = OastError::PollEventLimitExceeded { maximum: 2 };
        assert_eq!(
            too_many_for_poll
                .stage_event(&id, dns(3), OastMonotonicTime::from_millis(1_004))
                .unwrap_err(),
            poll_error
        );
        assert_eq!(
            too_many_for_poll
                .finish(OastMonotonicTime::from_millis(1_005))
                .unwrap_err(),
            poll_error
        );
        assert_eq!(correlation.unique_events(), 0);
        assert_eq!(correlation.abandoned_polls(), 1);

        let mut too_many_unique = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_006))
            .unwrap();
        too_many_unique
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_007))
            .unwrap();
        too_many_unique
            .stage_event(&id, dns(2), OastMonotonicTime::from_millis(1_008))
            .unwrap();
        assert_eq!(
            too_many_unique
                .finish(OastMonotonicTime::from_millis(1_009))
                .unwrap_err(),
            OastError::UniqueEventLimitExceeded { maximum: 1 }
        );
        assert_eq!(correlation.unique_events(), 0);
        assert_eq!(correlation.abandoned_polls(), 2);
    }

    #[test]
    fn rejected_staging_poison_is_atomic_and_time_is_monotonic() {
        let mut correlation_authority = authority();
        let (mut correlation, _) = register(&mut correlation_authority, SECRET);
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();
        let mut wrong_id_bytes = SECRET;
        wrong_id_bytes[0] ^= 1;
        let mut other_authority = authority();
        let (_, other_receipt) = register(&mut other_authority, wrong_id_bytes);

        let mut wrong_route = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_001))
            .unwrap();
        assert_eq!(
            wrong_route
                .stage_event(
                    other_receipt.correlation_id(),
                    dns(1),
                    OastMonotonicTime::from_millis(1_002),
                )
                .unwrap_err(),
            OastError::CorrelationMismatch
        );
        assert_eq!(
            wrong_route
                .finish(OastMonotonicTime::from_millis(1_003))
                .unwrap_err(),
            OastError::CorrelationMismatch
        );

        let mut regressed = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_004))
            .unwrap();
        regressed
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_006))
            .unwrap();
        let regression = OastError::ClockRegressed {
            previous: OastMonotonicTime::from_millis(1_004),
            current: OastMonotonicTime::from_millis(1_003),
        };
        assert_eq!(
            regressed
                .stage_event(&id, dns(2), OastMonotonicTime::from_millis(1_003))
                .unwrap_err(),
            regression
        );
        assert_eq!(
            regressed
                .finish(OastMonotonicTime::from_millis(1_007))
                .unwrap_err(),
            regression
        );
        assert_eq!(correlation.unique_events(), 0);
        assert_eq!(correlation.abandoned_polls(), 2);
    }

    #[test]
    fn cancellation_and_expiry_are_sticky_typed_terminal_states() {
        let mut authority = authority();
        let (mut cancelled, _) = register(&mut authority, SECRET);
        let assessment = cancelled.assessment_id().clone();
        let case = cancelled.verification_case().clone();
        let receipt = cancelled
            .cancel(&assessment, &case, OastMonotonicTime::from_millis(1_010))
            .unwrap();
        assert_eq!(receipt.state(), OastCorrelationState::Cancelled);
        assert_eq!(receipt.terminal_at().as_millis(), 1_010);
        assert_eq!(cancelled.state(), OastCorrelationState::Cancelled);
        assert_eq!(cancelled.terminal_receipt(), Some(receipt));
        assert_eq!(
            cancelled
                .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_011),)
                .unwrap_err(),
            OastError::Cancelled
        );

        let mut next_secret = SECRET;
        next_secret[0] ^= 1;
        let (mut expired, _) = register(&mut authority, next_secret);
        let assessment = expired.assessment_id().clone();
        let case = expired.verification_case().clone();
        let remaining = expired.remaining_polls();
        assert_eq!(
            expired
                .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_100),)
                .unwrap_err(),
            OastError::Expired {
                expires_at: OastMonotonicTime::from_millis(1_100),
            }
        );
        assert_eq!(expired.state(), OastCorrelationState::Expired);
        assert_eq!(expired.remaining_polls(), remaining);
        let terminal = expired.terminal_receipt().unwrap();
        assert_eq!(terminal.state(), OastCorrelationState::Expired);
        assert_eq!(terminal.terminal_at().as_millis(), 1_100);
    }

    #[test]
    fn expiry_during_a_poll_commits_no_staged_events() {
        let mut authority = authority();
        let (mut correlation, _) = register(&mut authority, SECRET);
        let id = correlation.correlation_id().clone();
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();
        let mut permit = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_090))
            .unwrap();
        permit
            .stage_event(&id, dns(1), OastMonotonicTime::from_millis(1_099))
            .unwrap();
        assert_eq!(
            permit
                .finish(OastMonotonicTime::from_millis(1_100))
                .unwrap_err(),
            OastError::Expired {
                expires_at: OastMonotonicTime::from_millis(1_100),
            }
        );
        assert_eq!(correlation.unique_events(), 0);
        assert_eq!(correlation.state(), OastCorrelationState::Expired);
        assert_eq!(correlation.abandoned_polls(), 1);
    }

    #[test]
    fn terminal_expiry_outranks_a_poisoned_batch_at_completion() {
        let mut correlation_authority = authority();
        let (mut correlation, _) = register(&mut correlation_authority, SECRET);
        let assessment = correlation.assessment_id().clone();
        let case = correlation.verification_case().clone();
        let mut wrong_secret = SECRET;
        wrong_secret[0] ^= 1;
        let mut other_authority = authority();
        let (_, other) = register(&mut other_authority, wrong_secret);

        let mut permit = correlation
            .begin_poll(&assessment, &case, OastMonotonicTime::from_millis(1_090))
            .unwrap();
        assert_eq!(
            permit
                .stage_event(
                    other.correlation_id(),
                    dns(1),
                    OastMonotonicTime::from_millis(1_099),
                )
                .unwrap_err(),
            OastError::CorrelationMismatch
        );
        assert_eq!(
            permit
                .finish(OastMonotonicTime::from_millis(1_100))
                .unwrap_err(),
            OastError::Expired {
                expires_at: OastMonotonicTime::from_millis(1_100),
            }
        );
        assert_eq!(correlation.state(), OastCorrelationState::Expired);
        assert_eq!(correlation.unique_events(), 0);
        assert_eq!(correlation.abandoned_polls(), 1);
    }
}
