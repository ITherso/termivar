use crate::ProviderError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use zeroize::{Zeroize, Zeroizing};

/// Session registration schema.
pub const SESSION_SCHEMA: &str = "security.termivar-oast.session/v1";
/// Callback allocation schema.
pub const CALLBACK_SCHEMA: &str = "security.termivar-oast.callback/v1";
/// Event poll schema.
pub const POLL_SCHEMA: &str = "security.termivar-oast.poll/v1";
/// Session cleanup schema.
pub const CLEANUP_SCHEMA: &str = "security.termivar-oast.cleanup/v1";
/// Exact native protocol revision.
pub const NATIVE_OAST_PROTOCOL_REVISION: &str = "termivar-native-oast/v1";

const SHORT_ID_BYTES: usize = 16;
const EVENT_ID_BYTES: usize = 32;
const SHORT_ID_TEXT_BYTES: usize = 22;
const LONG_ID_TEXT_BYTES: usize = 43;
const MAX_CURSOR: u64 = u32::MAX as u64;
const MAX_NATIVE_OAST_REQUEST_TARGET_BYTES: usize = 4_096;

macro_rules! opaque_id {
    ($name:ident, $raw_len:expr, $text_len:expr, $label:literal) => {
        #[doc = $label]
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub(crate) fn from_random(bytes: [u8; $raw_len]) -> Result<Self, ProviderError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(ProviderError::InternalInvariant);
                }
                Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
            }

            /// Returns the canonical URL-safe identity.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = ProviderError;

            fn from_str(source: &str) -> Result<Self, Self::Err> {
                if source.len() != $text_len
                    || !source
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                {
                    return Err(ProviderError::InternalInvariant);
                }
                let decoded = URL_SAFE_NO_PAD
                    .decode(source)
                    .map_err(|_| ProviderError::InternalInvariant)?;
                if decoded.len() != $raw_len
                    || decoded.iter().all(|byte| *byte == 0)
                    || URL_SAFE_NO_PAD.encode(&decoded) != source
                {
                    return Err(ProviderError::InternalInvariant);
                }
                Ok(Self(source.to_owned()))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<opaque>)"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let source = String::deserialize(deserializer)?;
                source
                    .parse()
                    .map_err(|_| de::Error::custom("invalid opaque id"))
            }
        }
    };
}

opaque_id!(
    SessionId,
    SHORT_ID_BYTES,
    SHORT_ID_TEXT_BYTES,
    "Opaque 128-bit identity for one short-lived provider session."
);
opaque_id!(
    CallbackId,
    SHORT_ID_BYTES,
    SHORT_ID_TEXT_BYTES,
    "Opaque 128-bit identity for one allocated HTTP callback."
);
opaque_id!(
    EventId,
    EVENT_ID_BYTES,
    LONG_ID_TEXT_BYTES,
    "Opaque 256-bit identity for one retained raw-free event."
);

/// Move-only 256-bit session Bearer credential returned exactly once.
pub struct SessionToken {
    encoded: Zeroizing<Vec<u8>>,
}

impl SessionToken {
    pub(crate) fn from_random(mut bytes: [u8; 32]) -> Result<Self, ProviderError> {
        if bytes.iter().all(|byte| *byte == 0) {
            bytes.zeroize();
            return Err(ProviderError::InternalInvariant);
        }
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes).into_bytes());
        bytes.zeroize();
        Ok(Self { encoded })
    }

    pub(crate) fn expose_bytes(&self) -> &[u8] {
        self.encoded.as_slice()
    }

    #[cfg(any(feature = "server", test))]
    pub(crate) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.encoded
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionToken(<redacted>)")
    }
}

/// Borrowed, move-only validation result for one complete Authorization value.
///
/// The raw credential remains borrowed, has no public accessor, and is never
/// rendered by `Debug`.
pub struct ManagementBearer<'a> {
    _credential: &'a [u8],
}

impl<'a> ManagementBearer<'a> {
    /// Parses one exact administrator `Bearer` Authorization value.
    pub fn administrator(header_value: &'a [u8]) -> Result<Self, ProviderError> {
        let credential = bearer_credential(header_value)?;
        if !(crate::secret::MIN_ADMIN_TOKEN_BYTES..=crate::secret::MAX_ADMIN_TOKEN_BYTES)
            .contains(&credential.len())
            || !credential.iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err(ProviderError::Unauthorized);
        }
        Ok(Self {
            _credential: credential,
        })
    }

    /// Parses one exact canonical 256-bit session `Bearer` Authorization value.
    pub fn session(header_value: &'a [u8]) -> Result<Self, ProviderError> {
        let credential = bearer_credential(header_value)?;
        if !valid_session_credential(credential) {
            return Err(ProviderError::Unauthorized);
        }
        Ok(Self {
            _credential: credential,
        })
    }

    #[cfg(any(feature = "server", test))]
    pub(crate) const fn expose_bytes(&self) -> &[u8] {
        self._credential
    }
}

impl fmt::Debug for ManagementBearer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ManagementBearer(<redacted>)")
    }
}

fn bearer_credential(header_value: &[u8]) -> Result<&[u8], ProviderError> {
    header_value
        .strip_prefix(b"Bearer ")
        .filter(|credential| !credential.is_empty())
        .ok_or(ProviderError::Unauthorized)
}

fn valid_session_credential(credential: &[u8]) -> bool {
    if credential.len() != LONG_ID_TEXT_BYTES
        || !credential
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }

    let mut decoded = [0_u8; EVENT_ID_BYTES];
    let valid = URL_SAFE_NO_PAD
        .decode_slice(credential, &mut decoded)
        .is_ok_and(|written| written == EVENT_ID_BYTES && decoded.iter().any(|byte| *byte != 0));
    decoded.zeroize();
    valid
}

/// Move-only exact callback target intended for one target mutation.
pub struct CallbackTarget {
    value: Zeroizing<String>,
}

impl CallbackTarget {
    pub(crate) fn from_provider(mut value: String) -> Result<Self, ProviderError> {
        if value.len() > 2_048 {
            value.zeroize();
            return Err(ProviderError::InternalInvariant);
        }
        Ok(Self {
            value: Zeroizing::new(value),
        })
    }

    /// Borrows the exact allocated callback URL for one authorized target
    /// request. Callers must preserve the wrapper's redaction boundary.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    #[cfg(any(feature = "server", test))]
    pub(crate) fn into_string(self) -> Zeroizing<String> {
        self.value
    }
}

impl fmt::Debug for CallbackTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallbackTarget(<redacted>)")
    }
}

/// Strict non-secret registration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    schema: SessionSchema,
    lifetime_ms: u64,
    max_callbacks: u16,
    max_events: u16,
    max_polls: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum SessionSchema {
    #[serde(rename = "security.termivar-oast.session/v1")]
    V1,
}

impl SessionRequest {
    /// Constructs a request; provider policy performs authoritative validation.
    pub fn new(lifetime_ms: u64, max_callbacks: u16, max_events: u16, max_polls: u16) -> Self {
        Self {
            schema: SessionSchema::V1,
            lifetime_ms,
            max_callbacks,
            max_events,
            max_polls,
        }
    }

    /// Schema identity supplied by the client.
    pub fn schema(&self) -> &str {
        match self.schema {
            SessionSchema::V1 => SESSION_SCHEMA,
        }
    }
    /// Requested lifetime in milliseconds.
    pub const fn lifetime_ms(&self) -> u64 {
        self.lifetime_ms
    }
    /// Requested callback ceiling.
    pub const fn max_callbacks(&self) -> u16 {
        self.max_callbacks
    }
    /// Requested accepted-event ceiling.
    pub const fn max_events(&self) -> u16 {
        self.max_events
    }
    /// Requested poll ceiling.
    pub const fn max_polls(&self) -> u16 {
        self.max_polls
    }
}

/// One successful registration; its token is move-only and non-serializable.
pub struct SessionRegistration {
    session_id: SessionId,
    session_token: SessionToken,
    expires_after_ms: u64,
}

impl SessionRegistration {
    pub(crate) fn new(
        session_id: SessionId,
        session_token: SessionToken,
        expires_after_ms: u64,
    ) -> Self {
        Self {
            session_id,
            session_token,
            expires_after_ms,
        }
    }

    /// Exact response schema.
    pub const fn schema(&self) -> &'static str {
        SESSION_SCHEMA
    }
    /// Opaque session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    /// Granted lifetime.
    pub const fn expires_after_ms(&self) -> u64 {
        self.expires_after_ms
    }
    /// Exact protocol revision.
    pub const fn protocol_revision(&self) -> &'static str {
        NATIVE_OAST_PROTOCOL_REVISION
    }
    /// Consumes the response and returns its one-time credential.
    pub fn take_session_token(self) -> SessionToken {
        self.session_token
    }
}

impl fmt::Debug for SessionRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRegistration")
            .field("session_id", &self.session_id)
            .field("session_token", &"<redacted>")
            .field("expires_after_ms", &self.expires_after_ms)
            .finish()
    }
}

/// One allocated opaque callback and move-only callback target.
pub struct CallbackAllocation {
    callback_id: CallbackId,
    target: CallbackTarget,
}

impl CallbackAllocation {
    pub(crate) fn new(callback_id: CallbackId, target: CallbackTarget) -> Self {
        Self {
            callback_id,
            target,
        }
    }

    /// Exact response schema.
    pub const fn schema(&self) -> &'static str {
        CALLBACK_SCHEMA
    }
    /// Opaque callback identity.
    pub const fn callback_id(&self) -> &CallbackId {
        &self.callback_id
    }
    /// Consumes the allocation and returns its redacted target.
    pub fn take_target(self) -> CallbackTarget {
        self.target
    }
}

impl fmt::Debug for CallbackAllocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackAllocation")
            .field("callback_id", &self.callback_id)
            .field("target", &"<redacted>")
            .finish()
    }
}

/// Strict bounded non-secret event cursor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventCursor(u64);

impl EventCursor {
    /// Validates one numeric cursor.
    pub fn new(value: u64) -> Result<Self, ProviderError> {
        if value > MAX_CURSOR {
            return Err(ProviderError::InvalidCursor);
        }
        Ok(Self(value))
    }

    /// Numeric cursor value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// One exact canonical native-provider request target.
///
/// Dynamic components are already reduced to bounded opaque identities. No
/// raw path, query, or credential is retained.
#[derive(Debug, PartialEq, Eq)]
pub enum NativeOastRoute {
    /// `POST /v1/sessions`.
    Register,
    /// `POST /v1/sessions/{session_id}/callbacks`.
    Allocate {
        /// Exact opaque session identity.
        session_id: SessionId,
    },
    /// `GET /v1/sessions/{session_id}/events?after={cursor}`.
    Poll {
        /// Exact opaque session identity.
        session_id: SessionId,
        /// Exact canonical numeric event cursor.
        after: EventCursor,
    },
    /// `DELETE /v1/sessions/{session_id}`.
    Cleanup {
        /// Exact opaque session identity.
        session_id: SessionId,
    },
    /// `GET|HEAD /c/{session_id}/{callback_id}` with an ignored query.
    Callback {
        /// Exact opaque session identity.
        session_id: SessionId,
        /// Exact opaque callback identity.
        callback_id: CallbackId,
    },
}

impl FromStr for NativeOastRoute {
    type Err = ProviderError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        if source.is_empty()
            || source.len() > MAX_NATIVE_OAST_REQUEST_TARGET_BYTES
            || !source.starts_with('/')
            || source
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte) || matches!(byte, b'#' | b'\\'))
        {
            return Err(ProviderError::InvalidRequestTarget);
        }

        let (path, query) = source
            .split_once('?')
            .map_or((source, None), |(path, query)| (path, Some(query)));

        if path == "/v1/sessions" {
            return query
                .is_none()
                .then_some(Self::Register)
                .ok_or(ProviderError::InvalidRequestTarget);
        }

        if let Some(callback_path) = path.strip_prefix("/c/") {
            let (session_id, callback_id) = callback_path
                .split_once('/')
                .filter(|(_, callback_id)| !callback_id.contains('/'))
                .ok_or(ProviderError::InvalidRequestTarget)?;
            return Ok(Self::Callback {
                session_id: parse_route_id(session_id)?,
                callback_id: parse_route_id(callback_id)?,
            });
        }

        if query.is_some() && !path.ends_with("/events") {
            return Err(ProviderError::InvalidRequestTarget);
        }

        let session_route = path
            .strip_prefix("/v1/sessions/")
            .ok_or(ProviderError::InvalidRequestTarget)?;
        if let Some(session_id) = session_route.strip_suffix("/callbacks") {
            if query.is_some() || session_id.contains('/') {
                return Err(ProviderError::InvalidRequestTarget);
            }
            return Ok(Self::Allocate {
                session_id: parse_route_id(session_id)?,
            });
        }
        if let Some(session_id) = session_route.strip_suffix("/events") {
            if session_id.contains('/') {
                return Err(ProviderError::InvalidRequestTarget);
            }
            let after = parse_poll_query(query.ok_or(ProviderError::InvalidRequestTarget)?)?;
            return Ok(Self::Poll {
                session_id: parse_route_id(session_id)?,
                after,
            });
        }
        if session_route.contains('/') || query.is_some() {
            return Err(ProviderError::InvalidRequestTarget);
        }
        Ok(Self::Cleanup {
            session_id: parse_route_id(session_route)?,
        })
    }
}

fn parse_route_id<T: FromStr<Err = ProviderError>>(source: &str) -> Result<T, ProviderError> {
    source
        .parse()
        .map_err(|_| ProviderError::InvalidRequestTarget)
}

fn parse_poll_query(query: &str) -> Result<EventCursor, ProviderError> {
    let value = query
        .strip_prefix("after=")
        .filter(|value| !value.is_empty())
        .ok_or(ProviderError::InvalidRequestTarget)?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ProviderError::InvalidRequestTarget)?;
    if value != parsed.to_string() {
        return Err(ProviderError::InvalidRequestTarget);
    }
    EventCursor::new(parsed).map_err(|_| ProviderError::InvalidRequestTarget)
}

/// Only protocol retained by the native provider in V1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolClass {
    /// Raw-free HTTP callback classification.
    Http,
}

impl ProtocolClass {
    /// Stable protocol label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
        }
    }
}

/// Accepted public callback methods. Method itself is not retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallbackMethod {
    /// GET callback.
    Get,
    /// HEAD callback.
    Head,
}

/// Raw-free event returned by polling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEventRecord {
    event_id: EventId,
    callback_id: CallbackId,
    cursor: EventCursor,
    duplicate_count: u32,
}

impl HttpEventRecord {
    pub(crate) fn new(
        event_id: EventId,
        callback_id: CallbackId,
        cursor: EventCursor,
        duplicate_count: u32,
    ) -> Self {
        Self {
            event_id,
            callback_id,
            cursor,
            duplicate_count,
        }
    }

    /// Opaque random event identity.
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }
    /// Exact allocated callback identity.
    pub const fn callback_id(&self) -> &CallbackId {
        &self.callback_id
    }
    /// HTTP-only protocol classification.
    pub const fn protocol(&self) -> ProtocolClass {
        ProtocolClass::Http
    }
    /// Cursor assigned on first acceptance.
    pub const fn cursor(&self) -> EventCursor {
        self.cursor
    }
    /// Repeated HTTP hits suppressed after the first event.
    pub const fn duplicate_count(&self) -> u32 {
        self.duplicate_count
    }
}

/// One bounded, non-blocking poll page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollResponse {
    session_id: SessionId,
    next_cursor: EventCursor,
    complete: bool,
    expired: bool,
    events: Vec<HttpEventRecord>,
}

impl PollResponse {
    pub(crate) fn new(
        session_id: SessionId,
        next_cursor: EventCursor,
        complete: bool,
        expired: bool,
        events: Vec<HttpEventRecord>,
    ) -> Self {
        Self {
            session_id,
            next_cursor,
            complete,
            expired,
            events,
        }
    }

    /// Exact response schema.
    pub const fn schema(&self) -> &'static str {
        POLL_SCHEMA
    }
    /// Exact session identity.
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }
    /// Cursor for the next page.
    pub const fn next_cursor(&self) -> EventCursor {
        self.next_cursor
    }
    /// Whether every retained event after the input cursor fit this page and
    /// no event-capacity loss has occurred.
    pub const fn complete(&self) -> bool {
        self.complete
    }
    /// Whether the session lifetime elapsed before this poll.
    pub const fn expired(&self) -> bool {
        self.expired
    }
    /// Ordered raw-free events.
    pub fn events(&self) -> &[HttpEventRecord] {
        &self.events
    }
}

/// Raw-free cleanup acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupResponse {
    removed: bool,
}

impl CleanupResponse {
    pub(crate) const fn success() -> Self {
        Self { removed: true }
    }

    /// Exact response schema.
    pub const fn schema(&self) -> &'static str {
        CLEANUP_SCHEMA
    }
    /// Whether the one addressed live session was removed.
    pub const fn removed(&self) -> bool {
        self.removed
    }
}

/// Internal observation disposition; the public endpoint remains constant 204.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDisposition {
    /// First HTTP hit was retained as one raw-free event.
    Recorded,
    /// A repeated HTTP hit was counted without adding an event.
    DuplicateSuppressed,
    /// Session or callback was not live and no state changed.
    Unknown,
    /// Session lifetime elapsed and no event was retained.
    Expired,
    /// Session event capacity was already exhausted.
    CapacityExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_ids_round_trip_and_reject_malformed_text() {
        let id = SessionId::from_random([7; SHORT_ID_BYTES]).unwrap();
        assert_eq!(id.as_str().parse::<SessionId>().unwrap(), id);
        for invalid in [
            "",
            "short",
            "AAAAAAAAAAAAAAAAAAAAA=",
            "!!!!!!!!!!!!!!!!!!!!!!",
        ] {
            assert!(invalid.parse::<SessionId>().is_err());
        }
    }

    #[test]
    fn opaque_ids_round_trip_through_the_exact_wire_encoding() {
        let session_id = SessionId::from_random([7; SHORT_ID_BYTES]).unwrap();
        let callback_id = CallbackId::from_random([8; SHORT_ID_BYTES]).unwrap();
        let event_id = EventId::from_random([9; EVENT_ID_BYTES]).unwrap();

        let encoded = serde_json::to_string(&session_id).unwrap();
        assert_eq!(
            serde_json::from_str::<SessionId>(&encoded).unwrap(),
            session_id
        );
        let encoded = serde_json::to_string(&callback_id).unwrap();
        assert_eq!(
            serde_json::from_str::<CallbackId>(&encoded).unwrap(),
            callback_id
        );
        let encoded = serde_json::to_string(&event_id).unwrap();
        assert_eq!(serde_json::from_str::<EventId>(&encoded).unwrap(), event_id);
    }

    #[test]
    fn strict_request_rejects_unknown_fields() {
        let source = format!(
            r#"{{"schema":"{SESSION_SCHEMA}","lifetime_ms":1000,"max_callbacks":1,"max_events":1,"max_polls":1,"extra":true}}"#
        );
        assert!(serde_json::from_str::<SessionRequest>(&source).is_err());
        let request = SessionRequest::new(1_000, 1, 1, 1);
        assert_eq!(request.schema(), SESSION_SCHEMA);
        let valid = format!(
            r#"{{"schema":"{SESSION_SCHEMA}","lifetime_ms":1000,"max_callbacks":1,"max_events":1,"max_polls":1}}"#
        );
        assert_eq!(
            serde_json::from_str::<SessionRequest>(&valid).unwrap(),
            request
        );
        let unknown = valid.replace(SESSION_SCHEMA, "security.termivar-oast.session/v2");
        assert!(serde_json::from_str::<SessionRequest>(&unknown).is_err());
    }

    #[test]
    fn secrets_and_targets_are_fully_redacted() {
        let token = SessionToken::from_random([9; EVENT_ID_BYTES]).unwrap();
        assert_eq!(format!("{token:?}"), "SessionToken(<redacted>)");
        assert_eq!(token.into_bytes().len(), LONG_ID_TEXT_BYTES);
        let target =
            CallbackTarget::from_provider("https://provider.example/c/session/callback".to_owned())
                .unwrap();
        assert_eq!(format!("{target:?}"), "CallbackTarget(<redacted>)");
    }

    #[test]
    fn management_bearers_are_exact_canonical_and_redacted() {
        const ADMIN: &[u8] = b"Bearer ADMIN-TOKEN-MUST-NOT-LEAK-29C047F1";
        let administrator = ManagementBearer::administrator(ADMIN).unwrap();
        assert_eq!(format!("{administrator:?}"), "ManagementBearer(<redacted>)");
        assert!(!format!("{administrator:?}").contains("MUST-NOT-LEAK"));

        let session_token = SessionToken::from_random([11; EVENT_ID_BYTES])
            .unwrap()
            .into_bytes();
        let session_header = [b"Bearer ".as_slice(), session_token.as_slice()].concat();
        let session = ManagementBearer::session(&session_header).unwrap();
        assert_eq!(session.expose_bytes(), session_token.as_slice());

        let zero_token = URL_SAFE_NO_PAD.encode([0_u8; EVENT_ID_BYTES]);
        let mut noncanonical = session_header.clone();
        *noncanonical.last_mut().unwrap() = b'B';
        for invalid in [
            b"bearer ADMIN-TOKEN-MUST-NOT-LEAK-29C047F1".to_vec(),
            b"Bearer ".to_vec(),
            b"Bearer two values".to_vec(),
            [b"Bearer ".as_slice(), zero_token.as_bytes()].concat(),
            noncanonical,
        ] {
            assert_eq!(
                ManagementBearer::session(&invalid).unwrap_err(),
                ProviderError::Unauthorized
            );
        }
    }

    #[test]
    fn canonical_native_routes_reject_aliases_and_ignore_only_callback_query() {
        let session_id = SessionId::from_random([7; SHORT_ID_BYTES]).unwrap();
        let callback_id = CallbackId::from_random([9; SHORT_ID_BYTES]).unwrap();
        let allocate = format!("/v1/sessions/{session_id}/callbacks");
        let poll = format!("/v1/sessions/{session_id}/events?after=17");
        let cleanup = format!("/v1/sessions/{session_id}");
        let callback = format!("/c/{session_id}/{callback_id}");

        assert_eq!(
            "/v1/sessions".parse::<NativeOastRoute>().unwrap(),
            NativeOastRoute::Register
        );
        assert_eq!(
            allocate.parse::<NativeOastRoute>().unwrap(),
            NativeOastRoute::Allocate {
                session_id: session_id.clone(),
            }
        );
        assert_eq!(
            poll.parse::<NativeOastRoute>().unwrap(),
            NativeOastRoute::Poll {
                session_id: session_id.clone(),
                after: EventCursor::new(17).unwrap(),
            }
        );
        assert_eq!(
            cleanup.parse::<NativeOastRoute>().unwrap(),
            NativeOastRoute::Cleanup {
                session_id: session_id.clone(),
            }
        );
        assert_eq!(
            format!("{callback}?private=%2Fignored&second=value")
                .parse::<NativeOastRoute>()
                .unwrap(),
            NativeOastRoute::Callback {
                session_id: session_id.clone(),
                callback_id: callback_id.clone(),
            }
        );

        let encoded_session = format!(
            "%{:02X}{}",
            session_id.as_str().as_bytes()[0],
            &session_id.as_str()[1..]
        );
        for invalid in [
            "/v1/sessions?ignored=true".to_owned(),
            format!("{allocate}?ignored=true"),
            format!("{cleanup}?ignored=true"),
            format!("/v1/sessions/{session_id}/events"),
            format!("/v1/sessions/{session_id}/events?after=00"),
            format!("/v1/sessions/{session_id}/events?after=%30"),
            format!("/v1/sessions/{session_id}/events?after=0&extra=1"),
            format!("/v1/sessions/{encoded_session}/callbacks"),
            format!("/c/{encoded_session}/{callback_id}"),
            format!("{callback}/extra"),
            "https://provider.example/v1/sessions".to_owned(),
            "/v1/sessions\\alias".to_owned(),
            "/v1/sessions#fragment".to_owned(),
            format!("/{}", "x".repeat(MAX_NATIVE_OAST_REQUEST_TARGET_BYTES)),
        ] {
            assert_eq!(
                invalid.parse::<NativeOastRoute>(),
                Err(ProviderError::InvalidRequestTarget),
                "unexpected route acceptance"
            );
        }
    }
}
