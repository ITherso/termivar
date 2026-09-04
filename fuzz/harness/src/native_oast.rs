//! Bounded semantic oracle for the native OAST provider's untrusted inputs.

use termivar_oast::{
    AdminToken, CallbackDisposition, CallbackId, CallbackMethod, EventCursor, EventId,
    LoopbackBind, ManagementBearer, NativeOastRoute, ProtocolClass, ProviderConfig, ProviderLimits,
    ProviderState, PublicOrigin, SessionId, SessionRequest,
};

/// Maximum byte buffer accepted by the native-provider fuzz oracle.
pub const MAX_NATIVE_OAST_FUZZ_INPUT_BYTES: usize = 4_096;

/// Exercises native-provider configuration and secret parsers without network
/// access. All repeated classifications must be deterministic and failures must
/// stay value-free.
pub fn check_native_oast_provider(data: &[u8]) {
    if data.len() > MAX_NATIVE_OAST_FUZZ_INPUT_BYTES {
        return;
    }

    let scenario = data.first().copied().unwrap_or_default() % 11;
    let payload = data.get(1..).unwrap_or_default();
    match scenario {
        0 => check_public_origin(payload),
        1 => check_loopback_bind(payload),
        2 => check_limits(payload),
        3 => check_admin_token(payload),
        4 => check_state_transitions(payload),
        5 => check_session_request(payload),
        6 => check_opaque_ids(payload),
        7 => check_native_route(payload),
        8 => check_cursor(payload),
        9 => check_management_bearer(payload),
        _ => check_fixed_regressions(),
    }

    // Keep the exact production-safety boundary in every bounded campaign.
    check_fixed_regressions();
}

fn check_session_request(data: &[u8]) {
    let first = serde_json::from_slice::<SessionRequest>(data);
    let repeated = serde_json::from_slice::<SessionRequest>(data);
    match (first, repeated) {
        (Ok(first), Ok(repeated)) => assert_eq!(first, repeated),
        (Err(first), Err(repeated)) => assert_eq!(first.classify(), repeated.classify()),
        _ => panic!("session request classification changed across identical input"),
    }
}

fn check_opaque_ids(data: &[u8]) {
    let candidate = String::from_utf8_lossy(data);
    check_opaque_id::<SessionId>(&candidate, 22);
    check_opaque_id::<CallbackId>(&candidate, 22);
    check_opaque_id::<EventId>(&candidate, 43);
}

fn check_native_route(data: &[u8]) {
    let candidate = String::from_utf8_lossy(data);
    let first = candidate.parse::<NativeOastRoute>();
    let repeated = candidate.parse::<NativeOastRoute>();
    assert_eq!(first, repeated);
    if let Ok(route) = first {
        let rendered = format!("{route:?}");
        assert!(!rendered.contains("RAW-ROUTE-MUST-NOT-LEAK"));
    }
}

fn check_management_bearer(data: &[u8]) {
    let Some((&selector, candidate)) = data.split_first() else {
        return;
    };
    let first = if selector & 1 == 0 {
        ManagementBearer::administrator(candidate)
    } else {
        ManagementBearer::session(candidate)
    };
    let repeated = if selector & 1 == 0 {
        ManagementBearer::administrator(candidate)
    } else {
        ManagementBearer::session(candidate)
    };
    assert_eq!(first.is_ok(), repeated.is_ok());

    let rendered = match first {
        Ok(bearer) => {
            let rendered = format!("{bearer:?}");
            assert_eq!(rendered, "ManagementBearer(<redacted>)");
            rendered
        },
        Err(error) => {
            assert_eq!(error, termivar_oast::ProviderError::Unauthorized);
            let rendered = format!("{error:?}:{error}");
            assert_eq!(
                rendered,
                "Unauthorized:native OAST management request is unauthorized"
            );
            rendered
        },
    };
    assert!(!rendered.contains("FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"));
    assert!(!rendered.contains("SESSION-TOKEN-MUST-NOT-BE-ACCEPTED"));
}

fn check_opaque_id<T>(candidate: &str, encoded_bytes: usize)
where
    T: std::str::FromStr<Err = termivar_oast::ProviderError>
        + PartialEq
        + std::fmt::Debug
        + AsRefIdentity,
{
    let first = candidate.parse::<T>();
    let repeated = candidate.parse::<T>();
    assert_eq!(first, repeated);
    if let Ok(identity) = first {
        let canonical = identity.as_identity();
        assert_eq!(canonical.len(), encoded_bytes);
        assert!(canonical
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
        assert!(!format!("{identity:?}").contains(canonical));
    }
}

trait AsRefIdentity {
    fn as_identity(&self) -> &str;
}

impl AsRefIdentity for SessionId {
    fn as_identity(&self) -> &str {
        self.as_str()
    }
}

impl AsRefIdentity for CallbackId {
    fn as_identity(&self) -> &str {
        self.as_str()
    }
}

impl AsRefIdentity for EventId {
    fn as_identity(&self) -> &str {
        self.as_str()
    }
}

fn check_cursor(data: &[u8]) {
    let mut bytes = [0_u8; 8];
    let available = data.len().min(bytes.len());
    bytes[..available].copy_from_slice(&data[..available]);
    let value = u64::from_le_bytes(bytes);
    let first = EventCursor::new(value);
    let repeated = EventCursor::new(value);
    assert_eq!(first, repeated);
    match first {
        Ok(cursor) => assert_eq!(cursor.as_u64(), value),
        Err(_) => assert!(value > u64::from(u32::MAX)),
    }
}

fn check_public_origin(data: &[u8]) {
    let candidate = String::from_utf8_lossy(data);
    let first = candidate.parse::<PublicOrigin>();
    let repeated = candidate.parse::<PublicOrigin>();
    assert_eq!(first, repeated);
    if let Ok(origin) = first {
        assert!(origin.as_str().starts_with("https://"));
        assert!(origin.as_str().ends_with('/'));
        assert!(!origin.as_str().contains('@'));
        assert!(!origin.as_str().contains('?'));
        assert!(!origin.as_str().contains('#'));
    }
}

fn check_loopback_bind(data: &[u8]) {
    let candidate = String::from_utf8_lossy(data);
    let first = candidate.parse::<LoopbackBind>();
    let repeated = candidate.parse::<LoopbackBind>();
    assert_eq!(first, repeated);
    if let Ok(binding) = first {
        assert!(binding.socket_addr().ip().is_loopback());
    }
}

fn check_limits(data: &[u8]) {
    let byte = |index: usize, fallback: u8| data.get(index).copied().unwrap_or(fallback);
    let lifetime = u64::from(byte(5, 1)).saturating_mul(1_000);
    let first = ProviderLimits::new(
        u16::from(byte(0, 1)),
        u16::from(byte(1, 1)),
        u16::from(byte(2, 1)),
        u16::from(byte(3, 1)),
        u16::from(byte(4, 1)),
        lifetime,
        u16::from(byte(6, 1)),
    );
    let repeated = ProviderLimits::new(
        u16::from(byte(0, 1)),
        u16::from(byte(1, 1)),
        u16::from(byte(2, 1)),
        u16::from(byte(3, 1)),
        u16::from(byte(4, 1)),
        lifetime,
        u16::from(byte(6, 1)),
    );
    assert_eq!(first, repeated);
    if let Ok(limits) = first {
        assert!((1..=256).contains(&limits.max_active_sessions()));
        assert!((1..=8).contains(&limits.max_callbacks_per_session()));
        assert!((1..=64).contains(&limits.max_events_per_session()));
        assert!((1..=32).contains(&limits.max_polls_per_session()));
        assert!((1..=32).contains(&limits.max_poll_events_per_response()));
        assert!(limits.max_poll_events_per_response() <= limits.max_events_per_session());
        assert!((1..=120_000).contains(&limits.max_session_lifetime_millis()));
        assert!((1..=256).contains(&limits.max_concurrent_requests()));
    }
}

fn check_admin_token(data: &[u8]) {
    let first = AdminToken::new(data.to_vec());
    let repeated = AdminToken::new(data.to_vec());
    assert_eq!(first.is_ok(), repeated.is_ok());
    let rendered = match first {
        Ok(token) => format!("{token:?}"),
        Err(error) => format!("{error:?}:{error}"),
    };
    if !data.is_empty() {
        let supplied = String::from_utf8_lossy(data);
        if supplied.len() >= 32 {
            assert!(!rendered.contains(supplied.as_ref()));
        }
    }
}

fn check_state_transitions(data: &[u8]) {
    const ADMIN: &[u8] = b"FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4";

    let bind = "127.0.0.1:8080".parse::<LoopbackBind>().unwrap();
    let origin = "https://provider.example.test/"
        .parse::<PublicOrigin>()
        .unwrap();
    let limits = ProviderLimits::new(2, 2, 4, 4, 2, 60_000, 8).unwrap();
    let mut state = ProviderState::new(
        ProviderConfig::new(bind, origin, limits),
        AdminToken::new(ADMIN.to_vec()).unwrap(),
    )
    .unwrap();

    if data.first().is_some_and(|byte| byte & 1 == 1) {
        let wrong_admin = AdminToken::new(b"WRONG-FUZZ-ONLY-OAST-ADMIN-TOKEN".to_vec()).unwrap();
        assert!(state
            .register(&wrong_admin, SessionRequest::new(30_000, 2, 4, 4),)
            .is_err());
    }

    let registration_admin = AdminToken::new(ADMIN.to_vec()).unwrap();
    let Ok(registration) = state.register(
        &registration_admin,
        SessionRequest::new(
            30_000,
            1 + u16::from(data.get(1).copied().unwrap_or_default() & 1),
            4,
            4,
        ),
    ) else {
        // Entropy is an explicit host failure; it may never yield partial state
        // or a fabricated event, but the fuzz process cannot repair OS entropy.
        return;
    };
    let session_id = registration.session_id().clone();
    let token = registration.take_session_token();
    let Ok(allocation) = state.allocate(&session_id, &token) else {
        return;
    };

    assert_eq!(
        state
            .observe_callback(&session_id, allocation.callback_id(), CallbackMethod::Get)
            .unwrap(),
        CallbackDisposition::Recorded
    );
    let duplicate_hits = usize::from(data.get(2).copied().unwrap_or_default() % 4);
    for index in 0..duplicate_hits {
        let method = if index % 2 == 0 {
            CallbackMethod::Head
        } else {
            CallbackMethod::Get
        };
        assert_eq!(
            state
                .observe_callback(&session_id, allocation.callback_id(), method)
                .unwrap(),
            CallbackDisposition::DuplicateSuppressed
        );
    }

    let page = state
        .poll(&session_id, &token, EventCursor::default())
        .unwrap();
    assert!(page.complete());
    assert_eq!(page.events().len(), 1);
    assert_eq!(page.events()[0].protocol(), ProtocolClass::Http);
    assert_eq!(
        page.events()[0].duplicate_count(),
        u32::try_from(duplicate_hits).unwrap()
    );
    assert!(state.cleanup(&session_id, &token).unwrap().removed());
    assert!(state
        .poll(&session_id, &token, EventCursor::default())
        .is_err());
}

fn check_fixed_regressions() {
    const SESSION_ID: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const CALLBACK_ID: &str = "AgICAgICAgICAgICAgICAg";
    const SESSION_BEARER: &[u8] = b"Bearer AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";
    const ADMIN_BEARER: &[u8] = b"Bearer FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4";

    assert!("https://provider.example.test/"
        .parse::<PublicOrigin>()
        .is_ok());
    for forbidden in [
        "http://provider.example.test/",
        "https://127.0.0.1/",
        "https://localhost/",
        "https://user@provider.example.test/",
        "https://provider.example.test/path",
        "https://provider.example.test/?query=1",
        "https://provider.example.test/#fragment",
        "https://*.example.test/",
    ] {
        assert!(forbidden.parse::<PublicOrigin>().is_err());
    }
    assert!("127.0.0.1:8080".parse::<LoopbackBind>().is_ok());
    assert!("[::1]:8080".parse::<LoopbackBind>().is_ok());
    assert!("0.0.0.0:8080".parse::<LoopbackBind>().is_err());
    assert!("[::]:8080".parse::<LoopbackBind>().is_err());

    for canonical in [
        "/v1/sessions".to_owned(),
        format!("/v1/sessions/{SESSION_ID}/callbacks"),
        format!("/v1/sessions/{SESSION_ID}/events?after=0"),
        format!("/v1/sessions/{SESSION_ID}"),
        format!("/c/{SESSION_ID}/{CALLBACK_ID}"),
        format!("/c/{SESSION_ID}/{CALLBACK_ID}?ignored=RAW-ROUTE-MUST-NOT-LEAK"),
    ] {
        assert!(canonical.parse::<NativeOastRoute>().is_ok());
    }
    for noncanonical in [
        "/v1/sessions?ignored=1".to_owned(),
        format!("/v1/sessions/{SESSION_ID}/callbacks?ignored=1"),
        format!("/v1/sessions/{SESSION_ID}/events"),
        format!("/v1/sessions/{SESSION_ID}/events?after=00"),
        format!("/v1/sessions/{SESSION_ID}/events?after=%30"),
        format!("/v1/sessions/{SESSION_ID}/events?after=0&ignored=1"),
        "/v1/sessions/%41QEBAQEBAQEBAQEBAQEBAQ/callbacks".to_owned(),
        format!("/c/%41QEBAQEBAQEBAQEBAQEBAQ/{CALLBACK_ID}"),
        format!("/c/{SESSION_ID}/{CALLBACK_ID}/"),
        "https://provider.example.test/v1/sessions".to_owned(),
        "/v1/sessions#fragment".to_owned(),
    ] {
        assert!(noncanonical.parse::<NativeOastRoute>().is_err());
    }

    for valid in [
        ManagementBearer::administrator(ADMIN_BEARER),
        ManagementBearer::session(SESSION_BEARER),
    ] {
        assert!(valid.is_ok());
        assert_eq!(
            format!("{:?}", valid.unwrap()),
            "ManagementBearer(<redacted>)"
        );
    }
    for invalid in [
        &b"bearer FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"[..],
        &b"Bearer  FUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"[..],
        &b"Bearer\tFUZZ-ONLY-OAST-ADMIN-TOKEN-8D31C0A4"[..],
    ] {
        assert!(ManagementBearer::administrator(invalid).is_err());
    }
    for invalid in [
        &b"bearer AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"[..],
        &b"Bearer  AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"[..],
        &b"Bearer AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw="[..],
        &b"Bearer\tAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"[..],
    ] {
        assert!(ManagementBearer::session(invalid).is_err());
    }
}
