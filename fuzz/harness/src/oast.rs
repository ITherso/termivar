use termivar_core::EntityId;
use termivar_scanner::{
    oast::{
        OastAssessmentId, OastAuthorityEpoch, OastAuthorityLimits, OastCorrelation,
        OastCorrelationAuthority, OastCorrelationState, OastCorrelationToken, OastDnsEvent,
        OastDnsRecordType, OastDnsTransport, OastError, OastEvent, OastEventDisposition,
        OastEventKey, OastEventProtocol, OastHttpEvent, OastHttpMethod, OastHttpScheme,
        OastLifetime, OastMonotonicTime, OastPollBudget, OastProtocolSet,
    },
    VerificationCase,
};

/// Maximum arbitrary input accepted by the OAST state-machine oracle.
pub const MAX_OAST_FUZZ_INPUT_BYTES: usize = 4 * 1024;

/// Exercises bounded registration, polling, terminal-state, and replay semantics.
pub fn check_oast_correlation(data: &[u8]) {
    if data.len() > MAX_OAST_FUZZ_INPUT_BYTES {
        return;
    }

    let model = OastModel::from_input(data);
    let expected = expected_observation(&model);
    let first = run_scenario(&model);
    let repeated = run_scenario(&model);
    assert_eq!(
        first, expected,
        "OAST implementation must match the independent scenario oracle"
    );
    assert_eq!(
        repeated, expected,
        "identical OAST input must reproduce the independent scenario oracle"
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OastModel {
    scenario: u8,
    token: [u8; 32],
    event_key: [u8; 32],
    issued_at_ms: u64,
    first_poll_at_ms: u64,
    first_observed_at_ms: u64,
    first_completed_at_ms: u64,
    second_poll_at_ms: u64,
    second_observed_at_ms: u64,
    second_completed_at_ms: u64,
    lifetime_ms: u64,
    max_registrations: u16,
    max_polls: u16,
    max_events_per_poll: u16,
    max_unique_events: u16,
    max_lifetime_ms: u64,
    poll_budget: u16,
}

impl OastModel {
    fn from_input(data: &[u8]) -> Self {
        let scenario = input_byte(data, 0, 0) % 12;
        let issued_at_ms = u64::from(u16::from_be_bytes([
            input_byte(data, 65, 0x01),
            input_byte(data, 66, 0x00),
        ]));
        let first_poll_at_ms = issued_at_ms + input_gap(data, 67);
        let first_observed_at_ms = first_poll_at_ms + input_gap(data, 68);
        let first_completed_at_ms = first_observed_at_ms + input_gap(data, 69);
        let second_poll_at_ms = first_completed_at_ms + input_gap(data, 70);
        let second_observed_at_ms = second_poll_at_ms + input_gap(data, 71);
        let second_completed_at_ms = second_observed_at_ms + input_gap(data, 72);
        let expires_at_ms = second_completed_at_ms + 1 + u64::from(input_byte(data, 73, 3) % 8);
        let lifetime_ms = expires_at_ms - issued_at_ms;
        let max_polls = 2 + u16::from(input_byte(data, 75, 3) % 8);
        let max_unique_events = if scenario == 9 {
            1
        } else {
            3 + u16::from(input_byte(data, 77, 5) % 8)
        };
        let poll_budget = if scenario == 8 {
            1
        } else {
            2 + u16::from(input_byte(data, 78, 1)) % (max_polls - 1)
        };

        Self {
            scenario,
            token: opaque_bytes(data, 1, 0x5d),
            event_key: opaque_bytes(data, 33, 0xa7),
            issued_at_ms,
            first_poll_at_ms,
            first_observed_at_ms,
            first_completed_at_ms,
            second_poll_at_ms,
            second_observed_at_ms,
            second_completed_at_ms,
            lifetime_ms,
            max_registrations: 2 + u16::from(input_byte(data, 74, 4) % 8),
            max_polls,
            max_events_per_poll: 2 + u16::from(input_byte(data, 76, 6) % 8),
            max_unique_events,
            max_lifetime_ms: lifetime_ms + u64::from(input_byte(data, 79, 7) % 8),
            poll_budget,
        }
    }

    const fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms + self.lifetime_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OastObservation {
    error: Option<OastError>,
    registered: u16,
    state: OastCorrelationState,
    terminal: Option<(OastCorrelationState, u64)>,
    remaining_polls: u16,
    unique: usize,
    accepted: u16,
    duplicates: u16,
    abandoned_polls: u16,
    receipts: Vec<(OastEventProtocol, OastEventDisposition, u64)>,
}

fn expected_observation(model: &OastModel) -> OastObservation {
    let polls_spent = match model.scenario {
        0 | 1 => 2,
        2..=6 | 8 | 9 => 1,
        7 | 10 | 11 => 0,
        _ => unreachable!("scenario is reduced modulo twelve"),
    };
    let (error, state, terminal) = match model.scenario {
        2 => (
            Some(OastError::EventKeyProtocolConflict),
            OastCorrelationState::Active,
            None,
        ),
        3 => (
            Some(OastError::CorrelationMismatch),
            OastCorrelationState::Active,
            None,
        ),
        4 => (
            Some(OastError::ProtocolNotAllowed {
                protocol: OastEventProtocol::Http,
            }),
            OastCorrelationState::Active,
            None,
        ),
        5 => (
            Some(OastError::Expired {
                expires_at: time(model.expires_at_ms()),
            }),
            OastCorrelationState::Expired,
            Some((OastCorrelationState::Expired, model.expires_at_ms())),
        ),
        7 => (
            Some(OastError::Cancelled),
            OastCorrelationState::Cancelled,
            Some((OastCorrelationState::Cancelled, model.first_poll_at_ms)),
        ),
        8 => (
            Some(OastError::PollBudgetExhausted),
            OastCorrelationState::Active,
            None,
        ),
        9 => (
            Some(OastError::UniqueEventLimitExceeded {
                maximum: model.max_unique_events,
            }),
            OastCorrelationState::Active,
            None,
        ),
        10 => (
            Some(OastError::TokenAlreadyRegistered),
            OastCorrelationState::Active,
            None,
        ),
        11 => (
            Some(OastError::BindingMismatch),
            OastCorrelationState::Active,
            None,
        ),
        0 | 1 | 6 => (None, OastCorrelationState::Active, None),
        _ => unreachable!("scenario is reduced modulo twelve"),
    };
    let (unique, accepted, duplicates, receipts) = match model.scenario {
        0 => (
            3,
            3,
            0,
            vec![(
                OastEventProtocol::Dns,
                OastEventDisposition::Accepted,
                model.second_observed_at_ms,
            )],
        ),
        1 => (
            1,
            1,
            2,
            vec![(
                OastEventProtocol::Dns,
                OastEventDisposition::DuplicateSuppressed,
                model.second_observed_at_ms,
            )],
        ),
        _ => (0, 0, 0, Vec::new()),
    };
    let abandoned_polls = u16::from(matches!(model.scenario, 2..=6 | 8 | 9));

    OastObservation {
        error,
        registered: if model.scenario == 3 { 2 } else { 1 },
        state,
        terminal,
        remaining_polls: model.poll_budget - polls_spent,
        unique,
        accepted,
        duplicates,
        abandoned_polls,
        receipts,
    }
}

fn run_scenario(model: &OastModel) -> OastObservation {
    let limits = OastAuthorityLimits::new(
        model.max_registrations,
        model.max_polls,
        model.max_events_per_poll,
        model.max_unique_events,
        model.max_lifetime_ms,
    )
    .expect("bounded fuzz authority limits are valid");
    let assessment = OastAssessmentId::new("assessment:fuzz").expect("fixed id is valid");
    let mut authority = OastCorrelationAuthority::new(
        OastAuthorityEpoch::new(opaque_bytes(&model.token, 0, 0x31))
            .expect("derived epoch is non-zero"),
        assessment.clone(),
        limits,
    );
    let case = verification_case("resource:oast:fuzz");
    let protocols = if model.scenario == 4 {
        OastProtocolSet::new(true, false)
    } else {
        OastProtocolSet::new(true, true)
    }
    .expect("fixed protocol grant is non-empty");
    let budget = OastPollBudget::new(model.poll_budget).expect("bounded poll budget is valid");
    let (mut correlation, _) = authority
        .register(
            case.clone(),
            OastCorrelationToken::new(model.token).expect("derived token is non-zero"),
            protocols,
            time(model.issued_at_ms),
            OastLifetime::from_millis(model.lifetime_ms).expect("bounded lifetime is valid"),
            budget,
        )
        .expect("initial registration is valid");

    let error = match model.scenario {
        0 => successful_poll(&mut correlation, &assessment, &case, model, false),
        1 => successful_poll(&mut correlation, &assessment, &case, model, true),
        2 => conflicting_batch(&mut correlation, &assessment, &case, model),
        3 => wrong_correlation(&mut authority, &mut correlation, &assessment, &case, model),
        4 => denied_protocol(&mut correlation, &assessment, &case, model),
        5 => expired_completion(&mut correlation, &assessment, &case, model),
        6 => {
            drop(
                correlation
                    .begin_poll(&assessment, &case, time(model.first_poll_at_ms))
                    .expect("first poll is eligible"),
            );
            None
        },
        7 => {
            correlation
                .cancel(&assessment, &case, time(model.first_poll_at_ms))
                .expect("active correlation can be cancelled");
            Some(
                correlation
                    .begin_poll(&assessment, &case, time(model.first_observed_at_ms))
                    .unwrap_err(),
            )
        },
        8 => {
            drop(
                correlation
                    .begin_poll(&assessment, &case, time(model.first_poll_at_ms))
                    .expect("first poll is eligible"),
            );
            Some(
                correlation
                    .begin_poll(&assessment, &case, time(model.first_observed_at_ms))
                    .unwrap_err(),
            )
        },
        9 => unique_limit_failure(&mut correlation, &assessment, &case, model),
        10 => Some(
            authority
                .register(
                    case.clone(),
                    OastCorrelationToken::new(model.token).expect("derived token is non-zero"),
                    protocols,
                    time(model.issued_at_ms),
                    OastLifetime::from_millis(model.lifetime_ms)
                        .expect("bounded lifetime is valid"),
                    budget,
                )
                .unwrap_err(),
        ),
        _ => {
            let wrong_case = verification_case("resource:oast:other");
            Some(
                correlation
                    .begin_poll(&assessment, &wrong_case, time(model.first_poll_at_ms))
                    .unwrap_err(),
            )
        },
    };

    let receipts = correlation_receipts(&mut correlation, &assessment, &case, model);
    let terminal = correlation
        .terminal_receipt()
        .map(|receipt| (receipt.state(), receipt.terminal_at().as_millis()));
    OastObservation {
        error,
        registered: authority.registered(),
        state: correlation.state(),
        terminal,
        remaining_polls: correlation.remaining_polls(),
        unique: correlation.unique_events(),
        accepted: correlation.accepted_events(),
        duplicates: correlation.duplicate_events(),
        abandoned_polls: correlation.abandoned_polls(),
        receipts,
    }
}

fn successful_poll(
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
    duplicate: bool,
) -> Option<OastError> {
    let id = correlation.correlation_id().clone();
    let key = event_key(model.event_key);
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.first_poll_at_ms))
        .expect("poll is eligible");
    permit
        .stage_event(&id, dns(key.clone()), time(model.first_observed_at_ms))
        .expect("DNS is granted");
    permit
        .stage_event(
            &id,
            if duplicate {
                dns(key)
            } else {
                http(second_key(model))
            },
            time(model.first_observed_at_ms),
        )
        .expect("second event is granted");
    permit
        .finish(time(model.first_completed_at_ms))
        .expect("batch is valid");
    None
}

fn conflicting_batch(
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
) -> Option<OastError> {
    let id = correlation.correlation_id().clone();
    let key = event_key(model.event_key);
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.first_poll_at_ms))
        .unwrap();
    permit
        .stage_event(&id, dns(key.clone()), time(model.first_observed_at_ms))
        .unwrap();
    permit
        .stage_event(&id, http(key), time(model.first_observed_at_ms))
        .unwrap();
    let error = permit
        .finish(time(model.first_completed_at_ms))
        .unwrap_err();
    assert_eq!(correlation.unique_events(), 0, "conflict must be atomic");
    Some(error)
}

fn wrong_correlation(
    authority: &mut OastCorrelationAuthority,
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
) -> Option<OastError> {
    let mut other_token = model.token;
    other_token[0] ^= 0x80;
    if other_token.iter().all(|byte| *byte == 0) {
        other_token[0] = 1;
    }
    let (_, other) = authority
        .register(
            case.clone(),
            OastCorrelationToken::new(other_token).unwrap(),
            OastProtocolSet::new(true, true).unwrap(),
            time(model.issued_at_ms),
            OastLifetime::from_millis(model.lifetime_ms).unwrap(),
            OastPollBudget::new(1).unwrap(),
        )
        .unwrap();
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.first_poll_at_ms))
        .unwrap();
    let error = permit
        .stage_event(
            other.correlation_id(),
            dns(event_key(model.event_key)),
            time(model.first_observed_at_ms),
        )
        .unwrap_err();
    assert_eq!(
        permit
            .finish(time(model.first_completed_at_ms))
            .unwrap_err(),
        error
    );
    Some(error)
}

fn denied_protocol(
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
) -> Option<OastError> {
    let id = correlation.correlation_id().clone();
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.first_poll_at_ms))
        .unwrap();
    let error = permit
        .stage_event(
            &id,
            http(event_key(model.event_key)),
            time(model.first_observed_at_ms),
        )
        .unwrap_err();
    assert_eq!(
        permit
            .finish(time(model.first_completed_at_ms))
            .unwrap_err(),
        error
    );
    Some(error)
}

fn expired_completion(
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
) -> Option<OastError> {
    let id = correlation.correlation_id().clone();
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.first_poll_at_ms))
        .unwrap();
    permit
        .stage_event(
            &id,
            dns(event_key(model.event_key)),
            time(model.first_observed_at_ms),
        )
        .unwrap();
    let error = permit.finish(time(model.expires_at_ms())).unwrap_err();
    assert_eq!(
        correlation.unique_events(),
        0,
        "expiry must not commit events"
    );
    Some(error)
}

fn unique_limit_failure(
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
) -> Option<OastError> {
    let id = correlation.correlation_id().clone();
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.first_poll_at_ms))
        .unwrap();
    permit
        .stage_event(
            &id,
            dns(event_key(model.event_key)),
            time(model.first_observed_at_ms),
        )
        .unwrap();
    permit
        .stage_event(
            &id,
            http(second_key(model)),
            time(model.first_observed_at_ms),
        )
        .unwrap();
    let error = permit
        .finish(time(model.first_completed_at_ms))
        .unwrap_err();
    assert_eq!(
        correlation.unique_events(),
        0,
        "limit failure must be atomic"
    );
    Some(error)
}

fn correlation_receipts(
    correlation: &mut OastCorrelation,
    assessment: &OastAssessmentId,
    case: &VerificationCase,
    model: &OastModel,
) -> Vec<(OastEventProtocol, OastEventDisposition, u64)> {
    if !matches!(model.scenario, 0 | 1) {
        return Vec::new();
    }
    let id = correlation.correlation_id().clone();
    let mut permit = correlation
        .begin_poll(assessment, case, time(model.second_poll_at_ms))
        .unwrap();
    let repeated_key = if model.scenario == 1 {
        event_key(model.event_key)
    } else {
        third_key(model)
    };
    permit
        .stage_event(&id, dns(repeated_key), time(model.second_observed_at_ms))
        .unwrap();
    permit
        .finish(time(model.second_completed_at_ms))
        .unwrap()
        .event_receipts()
        .iter()
        .map(|receipt| {
            (
                receipt.protocol(),
                receipt.disposition(),
                receipt.observed_at().as_millis(),
            )
        })
        .collect()
}

fn verification_case(resource: &str) -> VerificationCase {
    VerificationCase::new(
        "case:oast:fuzz",
        EntityId::new(resource).expect("fixed subject is valid"),
        "oast.callback.observe",
        "hypothesis:ssrf:fuzz",
    )
    .expect("fixed verification case is valid")
}

fn dns(key: OastEventKey) -> OastEvent {
    OastEvent::Dns(
        key,
        OastDnsEvent::new(OastDnsTransport::Udp, OastDnsRecordType::A),
    )
}

fn http(key: OastEventKey) -> OastEvent {
    OastEvent::Http(
        key,
        OastHttpEvent::new(OastHttpScheme::Https, OastHttpMethod::Get, false),
    )
}

fn event_key(bytes: [u8; 32]) -> OastEventKey {
    OastEventKey::new(bytes).expect("derived event key is non-zero")
}

fn second_key(model: &OastModel) -> OastEventKey {
    derived_key(model.event_key, 1)
}

fn third_key(model: &OastModel) -> OastEventKey {
    derived_key(model.event_key, 2)
}

fn derived_key(mut bytes: [u8; 32], discriminator: u8) -> OastEventKey {
    bytes[31] ^= discriminator;
    if bytes.iter().all(|byte| *byte == 0) {
        bytes[0] = discriminator;
    }
    event_key(bytes)
}

const fn time(milliseconds: u64) -> OastMonotonicTime {
    OastMonotonicTime::from_millis(milliseconds)
}

fn opaque_bytes(data: &[u8], offset: usize, fallback: u8) -> [u8; 32] {
    let mut output = [fallback; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        if let Some(input) = data.get(offset + index) {
            *byte = *input;
        }
    }
    if output.iter().all(|byte| *byte == 0) {
        output[31] = fallback.max(1);
    }
    output
}

fn input_byte(data: &[u8], index: usize, fallback: u8) -> u8 {
    data.get(index).copied().unwrap_or(fallback)
}

fn input_gap(data: &[u8], index: usize) -> u64 {
    1 + u64::from(input_byte(data, index, 0) % 3)
}
