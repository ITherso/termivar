use crate::{
    secret::SecretDigest, AdminToken, CallbackAllocation, CallbackDisposition, CallbackId,
    CallbackMethod, CleanupResponse, EventCursor, EventId, HttpEventRecord, LoopbackBind,
    PollResponse, ProviderConfig, ProviderError, PublicOrigin, SessionId, SessionRegistration,
    SessionRequest, SessionToken, SESSION_SCHEMA,
};
use std::{collections::BTreeMap, time::Instant};
use zeroize::Zeroize;

const MAX_DUPLICATE_HITS: u32 = u16::MAX as u32;
const ID_GENERATION_ATTEMPTS: usize = 8;
// Result retrieval remains available for two minutes after callback acceptance
// expires. This window is fixed, finite, and does not extend on access.
const RESULT_RETENTION_MILLIS: u64 = 120_000;

/// One bounded, in-memory, self-hosted callback provider.
///
/// The state has no persistence, background task, target authority, or network
/// work in `Drop`. All mutation occurs synchronously through the fixed protocol
/// operations. Callback acceptance expires at the requested lifetime; results
/// remain poll-visible (subject to the original poll budget) for a further
/// 120,000 milliseconds. Valid authenticated registration or authenticated
/// session management reclaims sessions at or beyond that fixed retention
/// deadline. Idle providers do not run timers.
pub struct ProviderState {
    config: ProviderConfig,
    admin_digest: SecretDigest,
    started_at: Instant,
    sessions: BTreeMap<SessionId, SessionState>,
}

impl ProviderState {
    /// Creates a provider and immediately reduces the administrator material to
    /// a domain-separated digest.
    pub fn new(config: ProviderConfig, admin_token: AdminToken) -> Result<Self, ProviderError> {
        let admin_digest = SecretDigest::admin(&admin_token);
        drop(admin_token);
        Ok(Self {
            config,
            admin_digest,
            started_at: Instant::now(),
            sessions: BTreeMap::new(),
        })
    }

    /// Exact checked loopback bind.
    pub const fn bind(&self) -> LoopbackBind {
        self.config.bind()
    }

    /// Maximum concurrently admitted management/callback requests.
    pub const fn max_concurrent_requests(&self) -> u16 {
        self.config.limits().max_concurrent_requests()
    }

    /// Exact configured public HTTPS origin.
    pub const fn public_origin(&self) -> &PublicOrigin {
        self.config.public_origin()
    }

    /// Atomically registers one checked session.
    pub fn register(
        &mut self,
        admin_token: &AdminToken,
        request: SessionRequest,
    ) -> Result<SessionRegistration, ProviderError> {
        self.register_bearer(admin_token.expose_bytes(), request)
    }

    pub(crate) fn register_bearer(
        &mut self,
        admin_bearer: &[u8],
        request: SessionRequest,
    ) -> Result<SessionRegistration, ProviderError> {
        self.register_bearer_at(admin_bearer, request, self.now_millis())
    }

    fn register_bearer_at(
        &mut self,
        admin_bearer: &[u8],
        request: SessionRequest,
        now: u64,
    ) -> Result<SessionRegistration, ProviderError> {
        if !self.admin_digest.matches_admin(admin_bearer) {
            return Err(ProviderError::Unauthorized);
        }
        let limits = self.config.limits();
        validate_session_request(&request, limits)?;
        let expires_at_millis = now
            .checked_add(request.lifetime_ms())
            .ok_or(ProviderError::InvalidSessionRequest)?;
        let retain_until_millis = expires_at_millis
            .checked_add(RESULT_RETENTION_MILLIS)
            .ok_or(ProviderError::InvalidSessionRequest)?;
        reclaim_sessions_at(&mut self.sessions, now);
        // Live sessions and results still inside their retention window both
        // consume the hard bound. Capacity never evicts either kind early.
        if self.sessions.len() >= usize::from(limits.max_active_sessions()) {
            return Err(ProviderError::SessionCapacityExhausted);
        }

        let session_id = unique_short_id(&self.sessions)?;
        let session_token = random_session_token()?;
        let token_digest = SecretDigest::session(session_token.expose_bytes());
        let session = SessionState {
            token_digest,
            expires_at_millis,
            retain_until_millis,
            max_callbacks: request.max_callbacks(),
            max_events: request.max_events(),
            max_polls: request.max_polls(),
            polls: 0,
            next_cursor: 0,
            callbacks: BTreeMap::new(),
            events: Vec::new(),
            event_retention_incomplete: false,
        };
        if self.sessions.insert(session_id.clone(), session).is_some() {
            return Err(ProviderError::InternalInvariant);
        }
        Ok(SessionRegistration::new(
            session_id,
            session_token,
            request.lifetime_ms(),
        ))
    }

    /// Atomically allocates one provider-minted callback target.
    pub fn allocate(
        &mut self,
        session_id: &SessionId,
        session_token: &SessionToken,
    ) -> Result<CallbackAllocation, ProviderError> {
        self.allocate_bearer(session_id, session_token.expose_bytes())
    }

    pub(crate) fn allocate_bearer(
        &mut self,
        session_id: &SessionId,
        session_bearer: &[u8],
    ) -> Result<CallbackAllocation, ProviderError> {
        self.allocate_bearer_at(session_id, session_bearer, self.now_millis())
    }

    fn allocate_bearer_at(
        &mut self,
        session_id: &SessionId,
        session_bearer: &[u8],
        now: u64,
    ) -> Result<CallbackAllocation, ProviderError> {
        let session =
            authenticated_session_mut(&mut self.sessions, session_id, session_bearer, now)?;
        if now >= session.expires_at_millis {
            return Err(ProviderError::SessionExpired);
        }
        if session.callbacks.len() >= usize::from(session.max_callbacks) {
            return Err(ProviderError::CallbackCapacityExhausted);
        }
        let callback_id = unique_callback_id(&session.callbacks)?;
        let target = self
            .config
            .public_origin()
            .callback_target(session_id, &callback_id)?;
        if session
            .callbacks
            .insert(callback_id.clone(), CallbackState { event_index: None })
            .is_some()
        {
            return Err(ProviderError::InternalInvariant);
        }
        Ok(CallbackAllocation::new(callback_id, target))
    }

    /// Records or suppresses one raw-free GET/HEAD callback observation.
    ///
    /// Callers must collapse every result into the same external response.
    pub fn observe_callback(
        &mut self,
        session_id: &SessionId,
        callback_id: &CallbackId,
        method: CallbackMethod,
    ) -> Result<CallbackDisposition, ProviderError> {
        self.observe_callback_at(session_id, callback_id, method, self.now_millis())
    }

    fn observe_callback_at(
        &mut self,
        session_id: &SessionId,
        callback_id: &CallbackId,
        _method: CallbackMethod,
        now: u64,
    ) -> Result<CallbackDisposition, ProviderError> {
        let Some(session) = self.sessions.get_mut(session_id) else {
            return Ok(CallbackDisposition::Unknown);
        };
        if now >= session.expires_at_millis {
            return Ok(CallbackDisposition::Expired);
        }
        let Some(event_index) = session
            .callbacks
            .get(callback_id)
            .map(|callback| callback.event_index)
        else {
            return Ok(CallbackDisposition::Unknown);
        };

        if let Some(index) = event_index {
            let Some(event) = session.events.get_mut(index) else {
                session.event_retention_incomplete = true;
                return Err(ProviderError::InternalInvariant);
            };
            if event.duplicate_count < MAX_DUPLICATE_HITS {
                event.duplicate_count += 1;
            } else {
                session.event_retention_incomplete = true;
            }
            return Ok(CallbackDisposition::DuplicateSuppressed);
        }
        if session.events.len() >= usize::from(session.max_events) {
            session.event_retention_incomplete = true;
            return Ok(CallbackDisposition::CapacityExhausted);
        }

        retain_new_event(session, callback_id, random_event_id())?;
        Ok(CallbackDisposition::Recorded)
    }

    #[cfg(feature = "server")]
    pub(crate) fn mark_callback_observation_incomplete(
        &mut self,
        session_id: &SessionId,
        callback_id: &CallbackId,
    ) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            if session.callbacks.contains_key(callback_id) {
                session.event_retention_incomplete = true;
            }
        }
    }

    /// Returns one bounded, immediately available raw-free event page.
    pub fn poll(
        &mut self,
        session_id: &SessionId,
        session_token: &SessionToken,
        after: EventCursor,
    ) -> Result<PollResponse, ProviderError> {
        self.poll_bearer(session_id, session_token.expose_bytes(), after)
    }

    pub(crate) fn poll_bearer(
        &mut self,
        session_id: &SessionId,
        session_bearer: &[u8],
        after: EventCursor,
    ) -> Result<PollResponse, ProviderError> {
        self.poll_bearer_at(session_id, session_bearer, after, self.now_millis())
    }

    fn poll_bearer_at(
        &mut self,
        session_id: &SessionId,
        session_bearer: &[u8],
        after: EventCursor,
        now: u64,
    ) -> Result<PollResponse, ProviderError> {
        let page_limit = self.config.limits().max_poll_events_per_response();
        let session =
            authenticated_session_mut(&mut self.sessions, session_id, session_bearer, now)?;
        if session.polls >= session.max_polls {
            return Err(ProviderError::PollBudgetExhausted);
        }
        session.polls = session
            .polls
            .checked_add(1)
            .ok_or(ProviderError::InternalInvariant)?;
        if after.as_u64() > session.next_cursor {
            return Err(ProviderError::InvalidCursor);
        }

        let mut matching = session
            .events
            .iter()
            .filter(|event| event.cursor > after)
            .peekable();
        let mut events = Vec::new();
        while events.len() < usize::from(page_limit) {
            let Some(event) = matching.next() else {
                break;
            };
            events.push(event.to_public());
        }
        let has_more = matching.peek().is_some();
        let next_cursor = events.last().map_or(after, |event| event.cursor());
        Ok(PollResponse::new(
            session_id.clone(),
            next_cursor,
            !has_more && !session.event_retention_incomplete,
            now >= session.expires_at_millis,
            events,
        ))
    }

    /// Authenticates and explicitly removes one session and all of its state.
    /// Also performs the same expired-retention maintenance as other management
    /// operations. A session past its retention deadline is already not found.
    pub fn cleanup(
        &mut self,
        session_id: &SessionId,
        session_token: &SessionToken,
    ) -> Result<CleanupResponse, ProviderError> {
        self.cleanup_bearer(session_id, session_token.expose_bytes())
    }

    pub(crate) fn cleanup_bearer(
        &mut self,
        session_id: &SessionId,
        session_bearer: &[u8],
    ) -> Result<CleanupResponse, ProviderError> {
        self.cleanup_bearer_at(session_id, session_bearer, self.now_millis())
    }

    fn cleanup_bearer_at(
        &mut self,
        session_id: &SessionId,
        session_bearer: &[u8],
        now: u64,
    ) -> Result<CleanupResponse, ProviderError> {
        authenticated_session_mut(&mut self.sessions, session_id, session_bearer, now)?;
        self.sessions
            .remove(session_id)
            .ok_or(ProviderError::InternalInvariant)?;
        Ok(CleanupResponse::success())
    }

    fn now_millis(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl std::fmt::Debug for ProviderState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderState")
            .field("config", &self.config)
            .field("admin_digest", &"<redacted>")
            .field("retained_sessions", &self.sessions.len())
            .finish()
    }
}

fn retain_new_event(
    session: &mut SessionState,
    callback_id: &CallbackId,
    event_id: Result<EventId, ProviderError>,
) -> Result<(), ProviderError> {
    let event_id = match event_id {
        Ok(event_id) => event_id,
        Err(error) => {
            session.event_retention_incomplete = true;
            return Err(error);
        },
    };
    let Some(next_cursor) = session.next_cursor.checked_add(1) else {
        session.event_retention_incomplete = true;
        return Err(ProviderError::InternalInvariant);
    };
    let cursor = match EventCursor::new(next_cursor) {
        Ok(cursor) => cursor,
        Err(error) => {
            session.event_retention_incomplete = true;
            return Err(error);
        },
    };
    let event_index = session.events.len();
    let Some(callback) = session.callbacks.get_mut(callback_id) else {
        session.event_retention_incomplete = true;
        return Err(ProviderError::InternalInvariant);
    };
    callback.event_index = Some(event_index);
    session.events.push(StoredEvent {
        event_id,
        callback_id: callback_id.clone(),
        cursor,
        duplicate_count: 0,
    });
    session.next_cursor = next_cursor;
    Ok(())
}

struct SessionState {
    token_digest: SecretDigest,
    expires_at_millis: u64,
    retain_until_millis: u64,
    max_callbacks: u16,
    max_events: u16,
    max_polls: u16,
    polls: u16,
    next_cursor: u64,
    callbacks: BTreeMap<CallbackId, CallbackState>,
    events: Vec<StoredEvent>,
    event_retention_incomplete: bool,
}

struct CallbackState {
    event_index: Option<usize>,
}

struct StoredEvent {
    event_id: EventId,
    callback_id: CallbackId,
    cursor: EventCursor,
    duplicate_count: u32,
}

impl StoredEvent {
    fn to_public(&self) -> HttpEventRecord {
        HttpEventRecord::new(
            self.event_id.clone(),
            self.callback_id.clone(),
            self.cursor,
            self.duplicate_count,
        )
    }
}

fn authenticated_session_mut<'a>(
    sessions: &'a mut BTreeMap<SessionId, SessionState>,
    session_id: &SessionId,
    candidate: &[u8],
    now: u64,
) -> Result<&'a mut SessionState, ProviderError> {
    let session = sessions
        .get(session_id)
        .ok_or(ProviderError::SessionNotFound)?;
    if !session.token_digest.matches_session(candidate) {
        return Err(ProviderError::Unauthorized);
    }
    reclaim_sessions_at(sessions, now);
    sessions
        .get_mut(session_id)
        .ok_or(ProviderError::SessionNotFound)
}

fn reclaim_sessions_at(sessions: &mut BTreeMap<SessionId, SessionState>, now: u64) {
    // ProviderLimits bounds the entire map to at most 256 sessions. A full
    // sweep is bounded and fair: no ordered-map prefix can starve later IDs.
    // Removing an entry drops its SecretDigest, which zeroizes itself.
    sessions.retain(|_, session| now < session.retain_until_millis);
}

fn validate_session_request(
    request: &SessionRequest,
    limits: crate::ProviderLimits,
) -> Result<(), ProviderError> {
    if request.schema() != SESSION_SCHEMA
        || request.lifetime_ms() == 0
        || request.max_callbacks() == 0
        || request.max_events() == 0
        || request.max_polls() == 0
        || request.lifetime_ms() > limits.max_session_lifetime_millis()
        || request.max_callbacks() > limits.max_callbacks_per_session()
        || request.max_events() > limits.max_events_per_session()
        || request.max_polls() > limits.max_polls_per_session()
    {
        return Err(ProviderError::InvalidSessionRequest);
    }
    Ok(())
}

fn unique_short_id<T>(existing: &BTreeMap<SessionId, T>) -> Result<SessionId, ProviderError> {
    for _ in 0..ID_GENERATION_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| ProviderError::EntropyUnavailable)?;
        let id = SessionId::from_random(bytes)?;
        if !existing.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(ProviderError::InternalInvariant)
}

fn unique_callback_id<T>(existing: &BTreeMap<CallbackId, T>) -> Result<CallbackId, ProviderError> {
    for _ in 0..ID_GENERATION_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| ProviderError::EntropyUnavailable)?;
        let id = CallbackId::from_random(bytes)?;
        if !existing.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(ProviderError::InternalInvariant)
}

fn random_session_token() -> Result<SessionToken, ProviderError> {
    let mut bytes = [0_u8; 32];
    if getrandom::getrandom(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(ProviderError::EntropyUnavailable);
    }
    let token = SessionToken::from_random(bytes);
    bytes.zeroize();
    token
}

fn random_event_id() -> Result<EventId, ProviderError> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ProviderError::EntropyUnavailable)?;
    EventId::from_random(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProviderLimits;

    const ADMIN: &[u8] = b"ADMIN-TOKEN-MUST-NOT-LEAK-4F291DB7";

    fn state(lifetime_ms: u64) -> ProviderState {
        state_with_limits(ProviderLimits::new(2, 3, 3, 4, 2, lifetime_ms, 8).unwrap())
    }

    fn state_with_limits(limits: ProviderLimits) -> ProviderState {
        let bind = "127.0.0.1:0".parse().unwrap();
        let origin = PublicOrigin::test_http_loopback("http://127.0.0.1:8080/").unwrap();
        ProviderState::new(
            ProviderConfig::new(bind, origin, limits),
            AdminToken::new(ADMIN.to_vec()).unwrap(),
        )
        .unwrap()
    }

    fn register(state: &mut ProviderState, lifetime_ms: u64) -> SessionRegistration {
        let admin = AdminToken::new(ADMIN.to_vec()).unwrap();
        state
            .register(&admin, SessionRequest::new(lifetime_ms, 3, 3, 4))
            .unwrap()
    }

    fn register_at(state: &mut ProviderState, lifetime_ms: u64, now: u64) -> SessionRegistration {
        state
            .register_bearer_at(ADMIN, SessionRequest::new(lifetime_ms, 3, 3, 4), now)
            .unwrap()
    }

    fn session_token(registration: SessionRegistration) -> SessionToken {
        registration.take_session_token()
    }

    #[test]
    fn abandoned_registration_releases_capacity_after_finite_retention() {
        let limits = ProviderLimits::new(1, 1, 1, 1, 1, 10, 1).unwrap();
        let mut state = state_with_limits(limits);
        let request = SessionRequest::new(10, 1, 1, 1);
        // The reply, including its cleanup credential, is lost by the caller.
        drop(state.register_bearer_at(ADMIN, request, 0).unwrap());
        assert!(matches!(
            state.register_bearer_at(ADMIN, request, 10 + RESULT_RETENTION_MILLIS - 1),
            Err(ProviderError::SessionCapacityExhausted)
        ));
        assert!(state
            .register_bearer_at(ADMIN, request, 10 + RESULT_RETENTION_MILLIS)
            .is_ok());
        assert_eq!(state.sessions.len(), 1);
    }

    #[test]
    fn registration_allocation_poll_and_cleanup_are_bounded() {
        let mut state = state(2_000);
        let registration = register(&mut state, 1_000);
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let first = state.allocate(&session_id, &token).unwrap();
        let callback_id = first.callback_id().clone();
        assert_eq!(
            state
                .observe_callback(&session_id, &callback_id, CallbackMethod::Get)
                .unwrap(),
            CallbackDisposition::Recorded
        );
        assert_eq!(
            state
                .observe_callback(&session_id, &callback_id, CallbackMethod::Head)
                .unwrap(),
            CallbackDisposition::DuplicateSuppressed
        );
        let poll = state
            .poll(&session_id, &token, EventCursor::default())
            .unwrap();
        assert!(poll.complete());
        assert!(!poll.expired());
        assert_eq!(poll.events().len(), 1);
        assert_eq!(poll.events()[0].protocol(), crate::ProtocolClass::Http);
        assert_eq!(poll.events()[0].duplicate_count(), 1);
        assert!(state.cleanup(&session_id, &token).unwrap().removed());
        assert_eq!(
            state.poll(&session_id, &token, EventCursor::default()),
            Err(ProviderError::SessionNotFound)
        );
    }

    #[test]
    fn invalid_auth_never_mutates_capacity() {
        let mut state = state(2_000);
        let request = SessionRequest::new(1_000, 1, 1, 1);
        let wrong = AdminToken::new(b"WRONG-TOKEN-MUST-NOT-LEAK-4F291DB7".to_vec()).unwrap();
        assert!(matches!(
            state.register(&wrong, request),
            Err(ProviderError::Unauthorized)
        ));
        let admin = AdminToken::new(ADMIN.to_vec()).unwrap();
        let registration = state.register(&admin, request).unwrap();
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        assert!(state.allocate(&session_id, &token).is_ok());
    }

    #[test]
    fn unknown_callback_is_not_an_existence_oracle() {
        let mut state = state(2_000);
        let registration = register(&mut state, 1_000);
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let unknown = CallbackId::from_random([19; 16]).unwrap();
        assert_eq!(
            state
                .observe_callback(&session_id, &unknown, CallbackMethod::Get)
                .unwrap(),
            CallbackDisposition::Unknown
        );
        assert!(state
            .poll(&session_id, &token, EventCursor::default())
            .unwrap()
            .events()
            .is_empty());
    }

    #[test]
    fn expiry_prevents_allocation_but_remains_poll_visible() {
        let mut state = state(25);
        let registration = register_at(&mut state, 10, 0);
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let bearer = token.expose_bytes();
        let allocation = state.allocate_bearer_at(&session_id, bearer, 9).unwrap();
        assert_eq!(
            state
                .observe_callback_at(
                    &session_id,
                    allocation.callback_id(),
                    CallbackMethod::Get,
                    9
                )
                .unwrap(),
            CallbackDisposition::Recorded
        );
        assert!(matches!(
            state.allocate_bearer_at(&session_id, bearer, 10),
            Err(ProviderError::SessionExpired)
        ));
        assert_eq!(
            state
                .observe_callback_at(
                    &session_id,
                    allocation.callback_id(),
                    CallbackMethod::Head,
                    10
                )
                .unwrap(),
            CallbackDisposition::Expired
        );
        for now in [10, 10 + RESULT_RETENTION_MILLIS - 1] {
            let page = state
                .poll_bearer_at(&session_id, bearer, EventCursor::default(), now)
                .unwrap();
            assert!(page.expired());
            assert!(page.complete());
            assert_eq!(page.events().len(), 1);
            assert_eq!(page.events()[0].duplicate_count(), 0);
        }
        assert_eq!(
            state.poll_bearer_at(
                &session_id,
                bearer,
                EventCursor::default(),
                10 + RESULT_RETENTION_MILLIS,
            ),
            Err(ProviderError::SessionNotFound)
        );
        assert!(state.sessions.is_empty());
        assert_eq!(
            state
                .observe_callback_at(
                    &session_id,
                    allocation.callback_id(),
                    CallbackMethod::Get,
                    10 + RESULT_RETENTION_MILLIS,
                )
                .unwrap(),
            CallbackDisposition::Unknown
        );
    }

    #[test]
    fn active_and_retained_sessions_consume_capacity_until_cleanup_or_retention() {
        let mut state = state(25);
        let first = register_at(&mut state, 10, 0);
        let second = register_at(&mut state, 10, 0);
        let first_id = first.session_id().clone();
        let first_token = session_token(first);
        let _second_token = session_token(second);
        for now in [0, 9, 10, 10 + RESULT_RETENTION_MILLIS - 1] {
            assert!(matches!(
                state.register_bearer_at(ADMIN, SessionRequest::new(10, 1, 1, 1), now),
                Err(ProviderError::SessionCapacityExhausted)
            ));
            assert_eq!(state.sessions.len(), 2);
        }
        state
            .cleanup_bearer_at(
                &first_id,
                first_token.expose_bytes(),
                10 + RESULT_RETENTION_MILLIS - 1,
            )
            .unwrap();
        assert!(state
            .register_bearer_at(
                ADMIN,
                SessionRequest::new(1, 1, 1, 1),
                10 + RESULT_RETENTION_MILLIS - 1,
            )
            .is_ok());
    }

    #[test]
    fn expired_retention_is_not_found_on_each_direct_management_operation() {
        for operation in 0..3 {
            let mut state = state(25);
            let registration = register_at(&mut state, 10, 0);
            let session_id = registration.session_id().clone();
            let token = session_token(registration);
            let bearer = token.expose_bytes();
            let now = 10 + RESULT_RETENTION_MILLIS;
            let result = match operation {
                0 => state
                    .allocate_bearer_at(&session_id, bearer, now)
                    .map(|_| ()),
                1 => state
                    .poll_bearer_at(&session_id, bearer, EventCursor::default(), now)
                    .map(|_| ()),
                _ => state
                    .cleanup_bearer_at(&session_id, bearer, now)
                    .map(|_| ()),
            };
            assert_eq!(result, Err(ProviderError::SessionNotFound));
            assert!(state.sessions.is_empty());
            assert_eq!(
                state.poll_bearer_at(&session_id, bearer, EventCursor::default(), now + 1),
                Err(ProviderError::SessionNotFound)
            );
            assert!(state.sessions.is_empty());
        }
    }

    #[test]
    fn only_authenticated_management_reclaims_abandoned_sessions() {
        for operation in 0..3 {
            let mut state = state(crate::HARD_MAX_SESSION_LIFETIME_MILLIS);
            let abandoned = register_at(&mut state, 10, 0);
            let abandoned_id = abandoned.session_id().clone();
            drop(abandoned);
            let live = register_at(&mut state, crate::HARD_MAX_SESSION_LIFETIME_MILLIS, 20);
            let live_id = live.session_id().clone();
            let live_token = session_token(live);
            let now = 10 + RESULT_RETENTION_MILLIS;
            assert!(matches!(
                state.register_bearer_at(b"invalid", SessionRequest::new(10, 1, 1, 1), now),
                Err(ProviderError::Unauthorized)
            ));
            assert!(matches!(
                state.allocate_bearer_at(&live_id, b"invalid", now),
                Err(ProviderError::Unauthorized)
            ));
            assert_eq!(
                state.poll_bearer_at(&live_id, b"invalid", EventCursor::default(), now),
                Err(ProviderError::Unauthorized)
            );
            assert_eq!(
                state.cleanup_bearer_at(&live_id, b"invalid", now),
                Err(ProviderError::Unauthorized)
            );
            assert_eq!(
                state
                    .observe_callback_at(
                        &abandoned_id,
                        &CallbackId::from_random([19; 16]).unwrap(),
                        CallbackMethod::Get,
                        now,
                    )
                    .unwrap(),
                CallbackDisposition::Expired
            );
            assert_eq!(state.sessions.len(), 2);
            let bearer = live_token.expose_bytes();
            match operation {
                0 => {
                    state.allocate_bearer_at(&live_id, bearer, now).unwrap();
                },
                1 => {
                    let page = state
                        .poll_bearer_at(&live_id, bearer, EventCursor::default(), now)
                        .unwrap();
                    assert!(!page.expired());
                },
                _ => {
                    assert!(state
                        .cleanup_bearer_at(&live_id, bearer, now)
                        .unwrap()
                        .removed());
                },
            }
            assert!(!state.sessions.contains_key(&abandoned_id));
            assert_eq!(state.sessions.len(), usize::from(operation != 2));
        }
    }

    #[test]
    fn hard_bounded_sweep_reclaims_every_eligible_session_and_preserves_other_results() {
        let limits = ProviderLimits::new(256, 3, 3, 4, 2, 120_000, 8).unwrap();
        let mut state = state_with_limits(limits);
        for _ in 0..254 {
            drop(register_at(&mut state, 10, 0));
        }
        let live = register_at(&mut state, 120_000, 20);
        let live_id = live.session_id().clone();
        let live_token = session_token(live);
        let retained = register_at(&mut state, 10, 20);
        let retained_id = retained.session_id().clone();
        let retained_token = session_token(retained);
        let callback = state
            .allocate_bearer_at(&retained_id, retained_token.expose_bytes(), 20)
            .unwrap();
        state
            .observe_callback_at(
                &retained_id,
                callback.callback_id(),
                CallbackMethod::Get,
                20,
            )
            .unwrap();
        assert_eq!(state.sessions.len(), 256);
        let now = 10 + RESULT_RETENTION_MILLIS;
        assert!(!state
            .poll_bearer_at(
                &live_id,
                live_token.expose_bytes(),
                EventCursor::default(),
                now
            )
            .unwrap()
            .expired());
        // One authenticated request examines the entire hard-bounded map,
        // regardless of the live/retained IDs' positions in its sort order.
        assert_eq!(state.sessions.len(), 2);
        let page = state
            .poll_bearer_at(
                &retained_id,
                retained_token.expose_bytes(),
                EventCursor::default(),
                now,
            )
            .unwrap();
        assert!(page.expired());
        assert!(page.complete());
        assert_eq!(page.events().len(), 1);
        assert_eq!(page.events()[0].callback_id(), callback.callback_id());
        for _ in 0..254 {
            drop(register_at(&mut state, 10, now));
        }
        assert_eq!(state.sessions.len(), 256);
    }

    #[test]
    fn explicit_cleanup_is_authenticated_before_and_after_acceptance_expiry() {
        for now in [9, 10, 10 + RESULT_RETENTION_MILLIS - 1] {
            let mut state = state(25);
            let registration = register_at(&mut state, 10, 0);
            let session_id = registration.session_id().clone();
            let token = session_token(registration);
            assert_eq!(
                state.cleanup_bearer_at(&session_id, b"invalid", now),
                Err(ProviderError::Unauthorized)
            );
            assert_eq!(state.sessions.len(), 1);
            assert!(state
                .cleanup_bearer_at(&session_id, token.expose_bytes(), now)
                .unwrap()
                .removed());
            assert!(state.sessions.is_empty());
            assert_eq!(
                state.cleanup_bearer_at(&session_id, token.expose_bytes(), now),
                Err(ProviderError::SessionNotFound)
            );
        }
    }

    #[test]
    fn acceptance_and_retention_deadlines_use_checked_arithmetic() {
        let mut state = state(25);
        let request = SessionRequest::new(10, 1, 1, 4);
        let latest_valid = u64::MAX - RESULT_RETENTION_MILLIS - 10;
        let registration = state
            .register_bearer_at(ADMIN, request, latest_valid)
            .unwrap();
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let session = state.sessions.get(&session_id).unwrap();
        assert_eq!(
            session.expires_at_millis,
            u64::MAX - RESULT_RETENTION_MILLIS
        );
        assert_eq!(session.retain_until_millis, u64::MAX);
        for now in [latest_valid + 1, u64::MAX - 9, u64::MAX] {
            assert!(matches!(
                state.register_bearer_at(ADMIN, request, now),
                Err(ProviderError::InvalidSessionRequest)
            ));
            assert_eq!(state.sessions.len(), 1);
        }
        assert!(state
            .poll_bearer_at(
                &session_id,
                token.expose_bytes(),
                EventCursor::default(),
                u64::MAX - 1,
            )
            .unwrap()
            .expired());
        assert_eq!(
            state.poll_bearer_at(
                &session_id,
                token.expose_bytes(),
                EventCursor::default(),
                u64::MAX,
            ),
            Err(ProviderError::SessionNotFound)
        );
        assert!(state.sessions.is_empty());
    }

    #[test]
    fn callback_and_poll_limits_fail_closed() {
        let mut state = state(2_000);
        let registration = state
            .register(
                &AdminToken::new(ADMIN.to_vec()).unwrap(),
                SessionRequest::new(1_000, 1, 1, 1),
            )
            .unwrap();
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let allocation = state.allocate(&session_id, &token).unwrap();
        assert!(matches!(
            state.allocate(&session_id, &token),
            Err(ProviderError::CallbackCapacityExhausted)
        ));
        state
            .observe_callback(&session_id, allocation.callback_id(), CallbackMethod::Get)
            .unwrap();
        assert_eq!(
            state
                .poll(&session_id, &token, EventCursor::default())
                .unwrap()
                .events()
                .len(),
            1
        );
        assert_eq!(
            state.poll(&session_id, &token, EventCursor::default()),
            Err(ProviderError::PollBudgetExhausted)
        );
    }

    #[test]
    fn session_and_callback_identities_are_distinct_and_targets_are_exact() {
        let mut state = state(2_000);
        let first = register(&mut state, 1_000);
        let second = register(&mut state, 1_000);
        assert_ne!(first.session_id(), second.session_id());
        let session_id = first.session_id().clone();
        let token = session_token(first);
        let first_callback = state.allocate(&session_id, &token).unwrap();
        let second_callback = state.allocate(&session_id, &token).unwrap();
        assert_ne!(first_callback.callback_id(), second_callback.callback_id());
        let callback_id = first_callback.callback_id().as_str().to_owned();
        let target = first_callback.take_target().into_string();
        assert_eq!(
            target.as_str(),
            format!(
                "http://127.0.0.1:8080/c/{}/{callback_id}",
                session_id.as_str()
            )
        );
        assert!(!format!("{second_callback:?}").contains("http://"));
    }

    #[test]
    fn strict_registration_limits_reject_without_consuming_capacity() {
        let mut state = state(2_000);
        let admin = AdminToken::new(ADMIN.to_vec()).unwrap();
        for invalid in [
            SessionRequest::new(0, 1, 1, 1),
            SessionRequest::new(2_001, 1, 1, 1),
            SessionRequest::new(1, 0, 1, 1),
            SessionRequest::new(1, 1, 4, 1),
            SessionRequest::new(1, 1, 1, 5),
        ] {
            assert!(matches!(
                state.register(&admin, invalid),
                Err(ProviderError::InvalidSessionRequest)
            ));
        }
        assert!(serde_json::from_str::<SessionRequest>(
            r#"{"schema":"security.termivar-oast.session/v2","lifetime_ms":1,"max_callbacks":1,"max_events":1,"max_polls":1}"#,
        )
        .is_err());
        assert!(state
            .register(&admin, SessionRequest::new(1_000, 1, 1, 1))
            .is_ok());
    }

    #[test]
    fn event_capacity_loss_is_explicitly_incomplete() {
        let limits = ProviderLimits::new(1, 2, 1, 2, 1, 2_000, 8).unwrap();
        let mut state = state_with_limits(limits);
        let registration = state
            .register(
                &AdminToken::new(ADMIN.to_vec()).unwrap(),
                SessionRequest::new(1_000, 2, 1, 2),
            )
            .unwrap();
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let first = state.allocate(&session_id, &token).unwrap();
        let second = state.allocate(&session_id, &token).unwrap();
        assert_eq!(
            state
                .observe_callback(&session_id, first.callback_id(), CallbackMethod::Get)
                .unwrap(),
            CallbackDisposition::Recorded
        );
        assert_eq!(
            state
                .observe_callback(&session_id, second.callback_id(), CallbackMethod::Get)
                .unwrap(),
            CallbackDisposition::CapacityExhausted
        );
        let page = state
            .poll(&session_id, &token, EventCursor::default())
            .unwrap();
        assert_eq!(page.events().len(), 1);
        assert!(!page.complete());
    }

    #[test]
    fn event_entropy_failure_is_sticky_and_poll_cannot_report_complete() {
        let mut state = state(2_000);
        let registration = register(&mut state, 1_000);
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let allocation = state.allocate(&session_id, &token).unwrap();
        let callback_id = allocation.callback_id().clone();

        let session = state.sessions.get_mut(&session_id).unwrap();
        assert_eq!(
            retain_new_event(
                session,
                &callback_id,
                Err(ProviderError::EntropyUnavailable),
            ),
            Err(ProviderError::EntropyUnavailable)
        );

        let page = state
            .poll(&session_id, &token, EventCursor::default())
            .unwrap();
        assert!(page.events().is_empty());
        assert!(!page.complete());
    }

    #[test]
    fn polls_are_ordered_paged_and_cursor_checked() {
        let limits = ProviderLimits::new(1, 3, 3, 4, 1, 2_000, 8).unwrap();
        let mut state = state_with_limits(limits);
        let registration = state
            .register(
                &AdminToken::new(ADMIN.to_vec()).unwrap(),
                SessionRequest::new(1_000, 3, 3, 4),
            )
            .unwrap();
        let session_id = registration.session_id().clone();
        let token = session_token(registration);
        let first = state.allocate(&session_id, &token).unwrap();
        let second = state.allocate(&session_id, &token).unwrap();
        state
            .observe_callback(&session_id, first.callback_id(), CallbackMethod::Get)
            .unwrap();
        state
            .observe_callback(&session_id, second.callback_id(), CallbackMethod::Head)
            .unwrap();
        assert!(matches!(
            state.poll(&session_id, &token, EventCursor::new(3).unwrap()),
            Err(ProviderError::InvalidCursor)
        ));
        let first_page = state
            .poll(&session_id, &token, EventCursor::default())
            .unwrap();
        assert_eq!(first_page.events().len(), 1);
        assert!(!first_page.complete());
        let second_page = state
            .poll(&session_id, &token, first_page.next_cursor())
            .unwrap();
        assert_eq!(second_page.events().len(), 1);
        assert!(second_page.complete());
        assert!(second_page.events()[0].cursor() > first_page.events()[0].cursor());
    }

    #[test]
    fn authenticated_invalid_cursor_consumes_the_poll_budget() {
        let limits = ProviderLimits::new(1, 1, 1, 1, 1, 2_000, 8).unwrap();
        let mut state = state_with_limits(limits);
        let registration = state
            .register(
                &AdminToken::new(ADMIN.to_vec()).unwrap(),
                SessionRequest::new(1_000, 1, 1, 1),
            )
            .unwrap();
        let session_id = registration.session_id().clone();
        let token = session_token(registration);

        assert_eq!(
            state.poll(&session_id, &token, EventCursor::new(1).unwrap()),
            Err(ProviderError::InvalidCursor)
        );
        assert_eq!(
            state.poll(&session_id, &token, EventCursor::default()),
            Err(ProviderError::PollBudgetExhausted)
        );
    }

    #[test]
    fn cleanup_is_idempotence_typed_and_session_isolated() {
        let mut state = state(2_000);
        let first = register(&mut state, 1_000);
        let second = register(&mut state, 1_000);
        let first_id = first.session_id().clone();
        let second_id = second.session_id().clone();
        let first_token = session_token(first);
        let second_token = session_token(second);
        assert!(state.cleanup(&first_id, &first_token).unwrap().removed());
        assert!(matches!(
            state.cleanup(&first_id, &first_token),
            Err(ProviderError::SessionNotFound)
        ));
        assert!(state.allocate(&second_id, &second_token).is_ok());
        assert!(matches!(
            state.cleanup_bearer(&second_id, b"SESSION-TOKEN-MUST-NOT-LEAK"),
            Err(ProviderError::Unauthorized)
        ));
        assert!(state.cleanup(&second_id, &second_token).unwrap().removed());
    }

    #[test]
    fn debug_and_errors_never_expose_secrets_or_targets() {
        let state = state(2_000);
        let rendered = format!("{state:?} {:?}", ProviderError::Unauthorized);
        for forbidden in [
            "ADMIN-TOKEN-MUST-NOT-LEAK-4F291DB7",
            "http://127.0.0.1:8080/c/",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
