//! Bounded semantic oracle for the scanner's sealed native OAST adapter.
//!
//! The harness compiles the exact production adapter source through the parent
//! module and supplies only its scanner-private accounting seam. It never
//! calls a provider operation, so fuzz campaigns perform zero network I/O.

use std::time::Duration;

use termivar_oast::{CallbackId, EventCursor, PublicOrigin, SessionId, POLL_SCHEMA};
use tokio_util::sync::CancellationToken;

use crate::{
    oast::{OastEvent, OastHttpMethod, OastHttpScheme},
    runtime_budget::RequestAccountingBroker,
    scanner_native_oast_provider::{
        lifecycle_allows, provider_origin_fingerprint, reduce_provider_http_event,
        validate_provider_poll_page, NativeOastPollPageFacts, NativeOastProviderAdapter,
        NativeOastProviderConfiguration, NativeOastProviderErrorKind, NativeOastProviderLifecycle,
        NativeOastProviderLimits, NativeOastProviderOperation, HARD_MAX_NATIVE_OAST_CALLBACKS,
        HARD_MAX_NATIVE_OAST_POLLS, HARD_MAX_NATIVE_OAST_PROVIDER_REQUESTS,
        HARD_MAX_NATIVE_OAST_PROVIDER_REQUEST_BYTES, HARD_MAX_NATIVE_OAST_PROVIDER_RESPONSE_BYTES,
        HARD_MAX_NATIVE_OAST_PROVIDER_WALL_TIME_MS,
    },
    web_runtime::mint_native_oast_provider_token_for_fuzz,
    RuntimeBudget,
};

/// Maximum byte buffer accepted by the adapter authority oracle.
pub const MAX_NATIVE_OAST_ADAPTER_FUZZ_INPUT_BYTES: usize = 4_096;

const PROVIDER_ORIGIN: &str = "https://oast.example.test/";
const TARGET_ORIGIN: &str = "https://target.example.test/";

/// Exercises the exact limit, configuration, redaction, origin separation,
/// parent-budget, cancellation, deadline, and lifecycle contracts without a
/// provider dispatch.
pub fn check_native_oast_adapter(data: &[u8]) {
    if data.len() > MAX_NATIVE_OAST_ADAPTER_FUZZ_INPUT_BYTES {
        return;
    }

    let scenario = data.first().copied().unwrap_or_default() % 12;
    match scenario {
        0 => check_lifecycle_matrix(),
        1 => check_limits(data),
        2 => check_configuration_classification(data),
        3 => check_adapter_mint(data, TARGET_ORIGIN, false, false),
        4 => check_adapter_mint(data, PROVIDER_ORIGIN, false, false),
        5 => check_adapter_mint(data, TARGET_ORIGIN, true, false),
        6 => check_adapter_mint(data, TARGET_ORIGIN, false, true),
        7 => check_parent_budget(data),
        8 => check_invalid_provider_origins(data),
        9 => check_invalid_target_origins(data),
        10 => check_redaction(data),
        _ => check_fixed_regressions(),
    }

    // Every campaign retains the exact state-machine and authority regressions
    // even after minimization selects one narrow scenario.
    check_lifecycle_matrix();
    check_provider_event_reduction(data);
    check_poll_page_validation(data);
    check_fixed_regressions();
}

fn check_provider_event_reduction(data: &[u8]) {
    const SESSION: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const CALLBACK: &str = "AgICAgICAgICAgICAgICAg";
    const OTHER_CALLBACK: &str = "AwMDAwMDAwMDAwMDAwMDAw";
    const EVENT: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ";

    let origin: PublicOrigin = PROVIDER_ORIGIN.parse().unwrap();
    let provider = provider_origin_fingerprint(&origin);
    let callback: CallbackId = CALLBACK.parse().unwrap();
    let other_callback: CallbackId = OTHER_CALLBACK.parse().unwrap();
    let scheme = if data.get(9).copied().unwrap_or_default() & 1 == 0 {
        OastHttpScheme::Https
    } else {
        OastHttpScheme::Http
    };
    let first = reduce_provider_http_event(&provider, SESSION, &callback, EVENT, scheme).unwrap();
    let repeated =
        reduce_provider_http_event(&provider, SESSION, &callback, EVENT, scheme).unwrap();
    assert_eq!(first, repeated);
    let changed =
        reduce_provider_http_event(&provider, SESSION, &other_callback, EVENT, scheme).unwrap();
    assert_ne!(first.key(), changed.key());

    let OastEvent::Http(_, event) = first else {
        panic!("native provider reduction must remain HTTP-only")
    };
    assert_eq!(event.scheme(), scheme);
    assert_eq!(event.method(), OastHttpMethod::Unknown);
    assert!(!event.body_present());
    let rendered = format!("{provider:?} {event:?} {changed:?}");
    for forbidden in [PROVIDER_ORIGIN, SESSION, CALLBACK, OTHER_CALLBACK, EVENT] {
        assert!(!rendered.contains(forbidden));
    }
}

fn check_poll_page_validation(data: &[u8]) {
    const SESSION: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const OTHER_SESSION: &str = "BQUFBQUFBQUFBQUFBQUFBQ";
    const CALLBACK: &str = "AgICAgICAgICAgICAgICAg";
    const OTHER_CALLBACK: &str = "AwMDAwMDAwMDAwMDAwMDAw";

    let expected_session: SessionId = SESSION.parse().unwrap();
    let other_session: SessionId = OTHER_SESSION.parse().unwrap();
    let expected_callback: CallbackId = CALLBACK.parse().unwrap();
    let other_callback: CallbackId = OTHER_CALLBACK.parse().unwrap();
    let expected_callbacks = vec![expected_callback.clone()];
    let mut observed_callbacks = vec![expected_callback];
    let previous_cursor = EventCursor::new(2).unwrap();
    let mut schema = POLL_SCHEMA;
    let mut observed_session = &expected_session;
    let mut next_cursor = EventCursor::new(2).unwrap();
    let mut complete = true;
    let mut expired = false;
    let mut correlations_ready = true;
    let expected = match data.get(10).copied().unwrap_or_default() % 8 {
        0 => Ok(()),
        1 => {
            schema = "security.termivar-oast.poll/v2";
            Err(NativeOastProviderErrorKind::ProviderResponseInvalid)
        },
        2 => {
            observed_session = &other_session;
            Err(NativeOastProviderErrorKind::ProviderSessionMismatch)
        },
        3 => {
            complete = false;
            Err(NativeOastProviderErrorKind::ProviderPageIncomplete)
        },
        4 => {
            expired = true;
            Err(NativeOastProviderErrorKind::ProviderExpired)
        },
        5 => {
            next_cursor = EventCursor::new(1).unwrap();
            Err(NativeOastProviderErrorKind::ProviderResponseInvalid)
        },
        6 => {
            observed_callbacks[0] = other_callback;
            Err(NativeOastProviderErrorKind::ProviderCallbackMismatch)
        },
        _ => {
            correlations_ready = false;
            Err(NativeOastProviderErrorKind::CorrelationRejected)
        },
    };
    let validate = || {
        validate_provider_poll_page(NativeOastPollPageFacts {
            schema,
            expected_session: &expected_session,
            observed_session,
            previous_cursor,
            next_cursor,
            complete,
            expired,
            expected_callbacks: &expected_callbacks,
            observed_callbacks: &observed_callbacks,
            correlations_ready,
        })
    };
    assert_eq!(validate(), expected);
    assert_eq!(
        validate(),
        expected,
        "poll validation must be deterministic"
    );
}

fn check_lifecycle_matrix() {
    let lifecycles = [
        NativeOastProviderLifecycle::Configured,
        NativeOastProviderLifecycle::Registered,
        NativeOastProviderLifecycle::CallbackAllocated,
        NativeOastProviderLifecycle::Polling,
        NativeOastProviderLifecycle::Closing,
        NativeOastProviderLifecycle::Closed,
    ];
    let operations = [
        NativeOastProviderOperation::Register,
        NativeOastProviderOperation::AllocateCallback,
        NativeOastProviderOperation::Poll,
        NativeOastProviderOperation::Cleanup,
    ];
    for lifecycle in lifecycles {
        for operation in operations {
            let expected = match operation {
                NativeOastProviderOperation::Register => {
                    lifecycle == NativeOastProviderLifecycle::Configured
                },
                NativeOastProviderOperation::AllocateCallback => matches!(
                    lifecycle,
                    NativeOastProviderLifecycle::Registered
                        | NativeOastProviderLifecycle::CallbackAllocated
                ),
                NativeOastProviderOperation::Poll => matches!(
                    lifecycle,
                    NativeOastProviderLifecycle::CallbackAllocated
                        | NativeOastProviderLifecycle::Polling
                ),
                NativeOastProviderOperation::Cleanup => matches!(
                    lifecycle,
                    NativeOastProviderLifecycle::Registered
                        | NativeOastProviderLifecycle::CallbackAllocated
                        | NativeOastProviderLifecycle::Polling
                ),
            };
            assert_eq!(lifecycle_allows(lifecycle, operation), expected);
        }
    }
}

fn check_limits(data: &[u8]) {
    let values = limit_values(data);
    let first = NativeOastProviderLimits::new(
        values.0, values.1, values.2, values.3, values.4, values.5, values.6,
    );
    let repeated = NativeOastProviderLimits::new(
        values.0, values.1, values.2, values.3, values.4, values.5, values.6,
    );
    assert_eq!(
        first.as_ref().map(|_| ()).map_err(|error| error.kind()),
        repeated.as_ref().map(|_| ()).map_err(|error| error.kind())
    );
    if let Ok(limits) = first {
        assert_eq!(limits.max_registrations(), 1);
        assert!((1..=HARD_MAX_NATIVE_OAST_CALLBACKS).contains(&limits.max_callbacks()));
        assert!(
            (2..=HARD_MAX_NATIVE_OAST_PROVIDER_REQUESTS).contains(&limits.max_provider_requests())
        );
        assert!((1..=HARD_MAX_NATIVE_OAST_POLLS).contains(&limits.max_polls()));
        assert!(limits.max_provider_request_bytes() <= HARD_MAX_NATIVE_OAST_PROVIDER_REQUEST_BYTES);
        assert!(
            limits.max_provider_response_bytes() <= HARD_MAX_NATIVE_OAST_PROVIDER_RESPONSE_BYTES
        );
        assert!(
            limits.max_provider_wall_time()
                <= Duration::from_millis(HARD_MAX_NATIVE_OAST_PROVIDER_WALL_TIME_MS)
        );
    }
}

fn check_configuration_classification(data: &[u8]) {
    let origin = match data.get(1).copied().unwrap_or_default() % 6 {
        0 => PROVIDER_ORIGIN,
        1 => "http://oast.example.test/",
        2 => "https://user@oast.example.test/",
        3 => "https://oast.example.test/path",
        4 => "https://oast.example.test/?secret=value",
        _ => "not-an-origin",
    };
    let first = configuration(origin, data);
    let repeated = configuration(origin, data);
    assert_eq!(
        first.as_ref().map(|_| ()).map_err(|error| error.kind()),
        repeated.as_ref().map(|_| ()).map_err(|error| error.kind())
    );
    if let Ok(configuration) = first {
        let debug = format!("{configuration:?}");
        assert!(!debug.contains("oast.example.test"));
        assert!(!debug.contains("FUZZ-ADMIN"));
        assert!(debug.contains("<fingerprinted>"));
        assert!(debug.contains("<redacted>"));
    }
}

fn check_adapter_mint(data: &[u8], target: &str, cancelled: bool, elapsed: bool) {
    let Some(configuration) = configuration(PROVIDER_ORIGIN, data).ok() else {
        return;
    };
    let budget = RuntimeBudget::default();
    let accounting = RequestAccountingBroker::new(budget);
    let cancellation = CancellationToken::new();
    if cancelled {
        cancellation.cancel();
    }
    let deadline = if elapsed {
        Some(tokio::time::Instant::now())
    } else {
        tokio::time::Instant::now().checked_add(Duration::from_secs(30))
    };
    let result = NativeOastProviderAdapter::mint(
        mint_native_oast_provider_token_for_fuzz(),
        configuration,
        target,
        accounting,
        budget,
        cancellation,
        deadline,
    );
    match result {
        Ok(adapter) => {
            assert!(!cancelled && !elapsed && target == TARGET_ORIGIN);
            assert_eq!(adapter.lifecycle(), NativeOastProviderLifecycle::Configured);
            assert!(adapter.receipts().is_empty());
            assert_eq!(adapter.accounting_snapshot().total_requests(), 0);
            let debug = format!("{adapter:?}");
            assert!(!debug.contains("oast.example.test"));
            assert!(!debug.contains("target.example.test"));
            assert!(!debug.contains("FUZZ-ADMIN"));
        },
        Err(error) => {
            let expected = if target == PROVIDER_ORIGIN {
                NativeOastProviderErrorKind::ProviderTargetOriginOverlap
            } else if cancelled {
                NativeOastProviderErrorKind::Cancelled
            } else if elapsed {
                NativeOastProviderErrorKind::DeadlineExceeded
            } else {
                panic!("valid adapter authority unexpectedly failed: {error:?}");
            };
            assert_eq!(error.kind(), expected);
        },
    }
}

fn check_parent_budget(data: &[u8]) {
    let Some(configuration) = configuration(PROVIDER_ORIGIN, data).ok() else {
        return;
    };
    let selector = data.get(2).copied().unwrap_or_default();
    let budget = RuntimeBudget::default()
        .with_max_total_requests(u32::from(selector % 9))
        .with_max_response_bytes(u64::from(selector) * 4);
    let result = NativeOastProviderAdapter::mint(
        mint_native_oast_provider_token_for_fuzz(),
        configuration,
        TARGET_ORIGIN,
        RequestAccountingBroker::new(budget),
        budget,
        CancellationToken::new(),
        tokio::time::Instant::now().checked_add(Duration::from_secs(30)),
    );
    if let Err(error) = result {
        assert_eq!(
            error.kind(),
            NativeOastProviderErrorKind::ParentBudgetTooSmall
        );
    }
}

fn check_invalid_provider_origins(data: &[u8]) {
    for origin in [
        "http://oast.example.test/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://oast.example.test:444/",
        "https://user@oast.example.test/",
        "https://oast.example.test/path",
        "https://oast.example.test/?query=secret",
        "https://oast.example.test/#fragment",
    ] {
        if let Ok(configuration) = configuration(origin, data) {
            let budget = RuntimeBudget::default();
            let error = NativeOastProviderAdapter::mint(
                mint_native_oast_provider_token_for_fuzz(),
                configuration,
                TARGET_ORIGIN,
                RequestAccountingBroker::new(budget),
                budget,
                CancellationToken::new(),
                tokio::time::Instant::now().checked_add(Duration::from_secs(30)),
            )
            .unwrap_err();
            assert_eq!(
                error.kind(),
                NativeOastProviderErrorKind::InvalidProviderOrigin
            );
        }
    }
}

fn check_invalid_target_origins(data: &[u8]) {
    for target in [
        "target.example.test",
        "ftp://target.example.test/",
        "https://user@target.example.test/",
        "https://target.example.test/path",
        "https://target.example.test/?query=secret",
        "https://target.example.test/#fragment",
    ] {
        let Some(configuration) = configuration(PROVIDER_ORIGIN, data).ok() else {
            return;
        };
        let budget = RuntimeBudget::default();
        let error = NativeOastProviderAdapter::mint(
            mint_native_oast_provider_token_for_fuzz(),
            configuration,
            target,
            RequestAccountingBroker::new(budget),
            budget,
            CancellationToken::new(),
            tokio::time::Instant::now().checked_add(Duration::from_secs(30)),
        )
        .unwrap_err();
        assert_eq!(error.kind(), NativeOastProviderErrorKind::InternalInvariant);
    }
}

fn check_redaction(data: &[u8]) {
    let Some(configuration) = configuration(PROVIDER_ORIGIN, data).ok() else {
        return;
    };
    let rendered = format!("{configuration:?}");
    for forbidden in [PROVIDER_ORIGIN, TARGET_ORIGIN, "FUZZ-ADMIN", "query=secret"] {
        assert!(!rendered.contains(forbidden));
    }
}

fn check_fixed_regressions() {
    let valid = NativeOastProviderLimits::new(1, 2, 8, 3, 4_096, 4_096, 10_000).unwrap();
    assert_eq!(valid.max_registrations(), 1);
    for invalid in [
        NativeOastProviderLimits::new(0, 1, 2, 1, 1, 1, 1),
        NativeOastProviderLimits::new(2, 1, 2, 1, 1, 1, 1),
        NativeOastProviderLimits::new(1, 0, 2, 1, 1, 1, 1),
        NativeOastProviderLimits::new(1, 1, 1, 1, 1, 1, 1),
        NativeOastProviderLimits::new(1, 1, 2, 0, 1, 1, 1),
        NativeOastProviderLimits::new(1, 1, 2, 1, 0, 1, 1),
        NativeOastProviderLimits::new(1, 1, 2, 1, 1, 0, 1),
        NativeOastProviderLimits::new(1, 1, 2, 1, 1, 1, 0),
    ] {
        assert_eq!(
            invalid.unwrap_err().kind(),
            NativeOastProviderErrorKind::InvalidLimits
        );
    }
}

fn configuration(
    origin: &str,
    data: &[u8],
) -> Result<
    NativeOastProviderConfiguration,
    crate::scanner_native_oast_provider::NativeOastProviderError,
> {
    let mut epoch = [0_u8; 32];
    for (index, byte) in epoch.iter_mut().enumerate() {
        *byte = data
            .get(index + 1)
            .copied()
            .unwrap_or(index as u8)
            .wrapping_add(1);
    }
    if epoch.iter().all(|byte| *byte == 0) {
        epoch[0] = 1;
    }
    let mut administrator = vec![b'A'; 32];
    for (index, byte) in administrator.iter_mut().enumerate() {
        let input = data.get(index + 33).copied().unwrap_or_default();
        *byte = 0x21 + (input % 0x5e);
    }
    NativeOastProviderConfiguration::new(
        origin,
        "assessment:fuzz-native-adapter",
        epoch,
        administrator,
        NativeOastProviderLimits::new(1, 2, 8, 3, 4_096, 4_096, 10_000).unwrap(),
    )
}

fn limit_values(data: &[u8]) -> (u16, u16, u16, u16, u64, u64, u64) {
    let byte = |index: usize| data.get(index).copied().unwrap_or_default();
    (
        u16::from(byte(1) % 3),
        u16::from(byte(2) % (HARD_MAX_NATIVE_OAST_CALLBACKS as u8 + 2)),
        u16::from(byte(3) % (HARD_MAX_NATIVE_OAST_PROVIDER_REQUESTS as u8 + 2)),
        u16::from(byte(4) % (HARD_MAX_NATIVE_OAST_POLLS as u8 + 2)),
        u64::from(byte(5)) * 512,
        u64::from(byte(6)) * 16_384,
        u64::from(byte(7)) * 1_000,
    )
}
