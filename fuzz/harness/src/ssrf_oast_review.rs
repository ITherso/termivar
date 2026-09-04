//! Bounded semantic oracle for the query-only repeated-callback SSRF review.
//!
//! The harness compiles the exact private scanner domain source through the
//! parent module. It exercises policy parsing, structural candidate selection,
//! exact query materialization, correlation separation, and the raw-free
//! repeated-callback comparator without opening a socket.

use std::str::FromStr;

use sha2::{Digest, Sha256};
use termivar_oast::{CallbackId, PublicOrigin};
use url::Url;

use crate::oast::OastEventKey;
use crate::scanner_ssrf_oast_review::{
    evaluate_ssrf_oast_review, select_observed_query_candidate, SsrfOastAdminToken,
    SsrfOastCandidateSelection, SsrfOastContractError, SsrfOastCorrelationBinding,
    SsrfOastCorrelationEntropy, SsrfOastCorrelationMaterial, SsrfOastMutationPlan,
    SsrfOastObservedEvent, SsrfOastReviewFacts, SsrfOastReviewOutcome, SsrfOastReviewPolicy,
    SsrfOastReviewPolicyError, SsrfOastTargetLeg, SsrfOastTerminalState,
};

/// Maximum byte buffer accepted by the SSRF/OAST review oracle.
pub const MAX_SSRF_OAST_FUZZ_INPUT_BYTES: usize = 4_096;

const TARGET: &str = "https://target.example.test/";
const PROVIDER: &str = "https://oast.example.test/";
const SESSION: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
const CANDIDATE_CALLBACK: &str = "AwMDAwMDAwMDAwMDAwMDAw";
const REPLAY_CALLBACK: &str = "BAQEBAQEBAQEBAQEBAQEBA";
const WRONG_CALLBACK: &str = "BQUFBQUFBQUFBQUFBQUFBQ";
const CANDIDATE_EVENT: &str = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY";
const REPLAY_EVENT: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

/// Exercises bounded, deterministic SSRF/OAST review semantics on arbitrary
/// bytes. Every invocation also retains the positive and one-sided callback
/// regressions independent of corpus minimization.
pub fn check_ssrf_oast_review(data: &[u8]) {
    if data.len() > MAX_SSRF_OAST_FUZZ_INPUT_BYTES {
        return;
    }

    check_arbitrary_policy_is_deterministic(data);
    check_valid_policy_and_secret_boundary(data);
    check_observed_candidate_selection(data);
    check_query_materialization(data);
    check_correlation_material(data);
    check_repeated_callback_classification(data);
    check_fixed_regressions();
}

fn check_arbitrary_policy_is_deterministic(data: &[u8]) {
    let assessment = Url::parse(TARGET).unwrap();
    let classify = |source: &[u8]| {
        SsrfOastReviewPolicy::parse_toml(&assessment, source)
            .map(|policy| {
                (
                    policy.policy_id().to_wire(),
                    policy.polls_per_leg(),
                    policy.poll_interval_ms(),
                    policy.lifetime_ms(),
                )
            })
            .map_err(|error| error)
    };
    assert_eq!(classify(data), classify(data));
}

fn check_valid_policy_and_secret_boundary(data: &[u8]) {
    let boundary = data.get(1).copied().unwrap_or_default();
    let polls = 1 + u16::from(boundary % 4);
    let interval = 250 + u64::from(boundary) * 6;
    let lifetime = 5_000 + u64::from(boundary) * 97;
    let source = policy_source(TARGET, PROVIDER, true, polls, interval, lifetime, "");
    let assessment = Url::parse(TARGET).unwrap();
    let first = SsrfOastReviewPolicy::parse_toml(&assessment, source.as_bytes()).unwrap();
    let repeated = SsrfOastReviewPolicy::parse_toml(&assessment, source.as_bytes()).unwrap();
    assert_eq!(first.policy_id(), repeated.policy_id());
    assert_eq!(first.polls_per_leg(), polls);
    assert_eq!(first.poll_interval_ms(), interval);
    assert_eq!(first.lifetime_ms(), lifetime);
    let rendered = format!("{first:?}");
    assert!(!rendered.contains(TARGET));
    assert!(!rendered.contains(PROVIDER));

    let changed = policy_source(
        TARGET,
        PROVIDER,
        true,
        if polls == 4 { 1 } else { polls + 1 },
        interval,
        lifetime,
        "",
    );
    let changed = SsrfOastReviewPolicy::parse_toml(&assessment, changed.as_bytes()).unwrap();
    assert_ne!(first.policy_id(), changed.policy_id());

    let malformed = policy_source(
        TARGET,
        PROVIDER,
        true,
        polls,
        interval,
        lifetime,
        "extra = 1\n",
    );
    assert_eq!(
        SsrfOastReviewPolicy::parse_toml(&assessment, malformed.as_bytes()).unwrap_err(),
        SsrfOastReviewPolicyError::MalformedPolicy
    );

    let mut secret = vec![b'A'; 32 + usize::from(boundary % 32)];
    for (index, byte) in data.iter().take(secret.len()).enumerate() {
        secret[index] = b'!' + (*byte % 94);
    }
    let token = SsrfOastAdminToken::new(secret.clone()).unwrap();
    let token_debug = format!("{token:?}");
    assert_eq!(token_debug, "SsrfOastAdminToken(<redacted>)");
    assert!(!token_debug.contains(&String::from_utf8_lossy(&secret).to_string()));
    assert!(SsrfOastAdminToken::new(vec![b'A'; 31]).is_err());
    assert!(SsrfOastAdminToken::new(vec![b'\n'; 32]).is_err());
}

fn check_observed_candidate_selection(data: &[u8]) {
    let origin = Url::parse(TARGET).unwrap();
    let suffix = compact_hex(data, 48);
    let scenario = data.first().copied().unwrap_or_default() % 8;
    let (resource, complete, stable, defense_clear, eligible) = match scenario {
        0 => (
            format!("{TARGET}fetch?keep={suffix}&next=https%3A%2F%2Fpublic.example%2F{suffix}"),
            true,
            true,
            true,
            true,
        ),
        1 => (
            format!("{TARGET}fetch?next=https%3A%2F%2Fa.example&next=https%3A%2F%2Fb.example"),
            true,
            true,
            true,
            false,
        ),
        2 => (
            format!("{TARGET}fetch?next=opaque-{suffix}"),
            true,
            true,
            true,
            false,
        ),
        3 => (
            format!("{TARGET}fetch?next=ftp%3A%2F%2Fpublic.example"),
            true,
            true,
            true,
            false,
        ),
        4 => (
            format!("{TARGET}fetch?next=https%3A%2F%2Fpublic.example%2F%23fragment"),
            true,
            true,
            true,
            false,
        ),
        5 => (
            format!("https://other.example.test/fetch?next=https%3A%2F%2Fpublic.example"),
            true,
            true,
            true,
            false,
        ),
        6 => (
            format!("{TARGET}fetch?next=https%3A%2F%2Fpublic.example#ambiguous"),
            true,
            true,
            true,
            false,
        ),
        _ => (
            format!("{TARGET}fetch?next=https%ZZ"),
            true,
            true,
            true,
            false,
        ),
    };
    let resource = Url::parse(&resource).unwrap();
    let selected = select_observed_query_candidate(
        &origin,
        &resource,
        "subject-sha256:fuzz",
        complete,
        stable,
        defense_clear,
    );
    assert_eq!(
        matches!(selected, SsrfOastCandidateSelection::Selected(_)),
        eligible
    );

    for flags in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let valid = Url::parse(&format!(
            "{TARGET}fetch?next=https%3A%2F%2Fpublic.example%2F{suffix}"
        ))
        .unwrap();
        assert!(matches!(
            select_observed_query_candidate(
                &origin,
                &valid,
                "subject-sha256:fuzz",
                flags.0,
                flags.1,
                flags.2,
            ),
            SsrfOastCandidateSelection::NotEligible
        ));
    }
}

fn check_query_materialization(data: &[u8]) {
    let suffix = compact_hex(data, 32);
    let original = Url::parse(&format!(
        "{TARGET}fetch?keep=a%2Bb-{suffix}&next=https%3A%2F%2Foriginal.example%2F&tail=%2F"
    ))
    .unwrap();
    let candidate = selected_candidate(&original);
    let provider = PublicOrigin::from_str(PROVIDER).unwrap();
    let candidate_target = callback_target(CANDIDATE_CALLBACK);
    let replay_target = callback_target(REPLAY_CALLBACK);
    let control_seed = nonzero_array(data, 11);
    let control = candidate.control_execution_url(control_seed).unwrap();
    let plan = SsrfOastMutationPlan::from_callback_strings(
        candidate,
        control_seed,
        &candidate_target,
        &replay_target,
        &provider,
    )
    .unwrap();

    let candidate = plan.execution_url(SsrfOastTargetLeg::Candidate);
    let replay = plan.execution_url(SsrfOastTargetLeg::Replay);
    assert_eq!(control.origin(), original.origin());
    assert_eq!(candidate.origin(), original.origin());
    assert_eq!(replay.origin(), original.origin());
    assert_eq!(control.path(), original.path());
    assert_eq!(candidate.path(), original.path());
    assert_eq!(replay.path(), original.path());
    assert_ne!(candidate, replay);
    assert!(query_value(&control, "next").starts_with("https://c-"));
    assert!(query_value(&control, "next").ends_with(".invalid/"));
    assert_eq!(query_value(candidate, "next"), candidate_target);
    assert_eq!(query_value(replay, "next"), replay_target);
    for target in [&control, candidate, replay] {
        assert_eq!(query_value(target, "keep"), format!("a+b-{suffix}"));
        assert_eq!(query_value(target, "tail"), "/");
        assert!(target.fragment().is_none());
        assert!(target.username().is_empty());
        assert!(target.password().is_none());
    }
    assert!(!format!("{plan:?}").contains("oast.example"));
    assert_eq!(
        SsrfOastMutationPlan::from_callback_strings(
            selected_candidate(&original),
            [0; 32],
            &candidate_target,
            &replay_target,
            &provider,
        )
        .unwrap_err(),
        SsrfOastContractError::InvalidControlSeed
    );
    assert_eq!(
        SsrfOastMutationPlan::from_callback_strings(
            selected_candidate(&original),
            nonzero_array(data, 13),
            &candidate_target,
            &candidate_target,
            &provider,
        )
        .unwrap_err(),
        SsrfOastContractError::CallbackIdentityConflict
    );

    let invalid = match data.get(2).copied().unwrap_or_default() % 4 {
        0 => callback_target(CANDIDATE_CALLBACK).replacen("https://", "http://", 1),
        1 => format!("https://other.example.test/c/{SESSION}/{CANDIDATE_CALLBACK}"),
        2 => format!("{}?query=forbidden", callback_target(CANDIDATE_CALLBACK)),
        _ => format!("{PROVIDER}not-a-callback"),
    };
    assert_eq!(
        SsrfOastMutationPlan::from_callback_strings(
            selected_candidate(&original),
            nonzero_array(data, 17),
            &invalid,
            &replay_target,
            &provider,
        )
        .unwrap_err(),
        SsrfOastContractError::InvalidCallbackTarget
    );
}

fn check_correlation_material(data: &[u8]) {
    let policy = valid_policy();
    let resource = Url::parse(&format!(
        "{TARGET}fetch?next=https%3A%2F%2Foriginal.example%2F{}",
        compact_hex(data, 24)
    ))
    .unwrap();
    let candidate = selected_candidate(&resource);
    let epoch = nonzero_array(data, 29);
    let candidate_entropy = nonzero_array(data, 31);
    let mut replay_entropy = nonzero_array(data, 37);
    if replay_entropy == candidate_entropy {
        replay_entropy[0] ^= 0x80;
    }
    let material = SsrfOastCorrelationMaterial::derive(
        &policy,
        &candidate,
        SsrfOastCorrelationBinding::new(
            "assessment-sha256:fuzz",
            "ssrf-oast-query-review@1",
            "case-sha256:fuzz",
        ),
        SsrfOastCorrelationEntropy::new(epoch, candidate_entropy, replay_entropy),
    )
    .unwrap();
    assert_eq!(
        format!("{material:?}"),
        "SsrfOastCorrelationMaterial(<redacted>)"
    );
    let (authority_epoch, candidate_token, replay_token) = material.into_parts();
    assert_eq!(
        format!("{authority_epoch:?}"),
        "OastAuthorityEpoch(<redacted>)"
    );
    assert_eq!(
        format!("{candidate_token:?}"),
        "OastCorrelationToken(<redacted>)"
    );
    assert_eq!(
        format!("{replay_token:?}"),
        "OastCorrelationToken(<redacted>)"
    );

    assert_eq!(
        SsrfOastCorrelationMaterial::derive(
            &policy,
            &candidate,
            SsrfOastCorrelationBinding::new(
                "assessment-sha256:fuzz",
                "ssrf-oast-query-review@1",
                "case-sha256:fuzz",
            ),
            SsrfOastCorrelationEntropy::new(epoch, candidate_entropy, candidate_entropy),
        )
        .unwrap_err(),
        SsrfOastContractError::InvalidCorrelationMaterial
    );
}

fn check_repeated_callback_classification(data: &[u8]) {
    let selector = data.first().copied().unwrap_or_default() % 16;
    let mut facts = complete_facts();
    let expected = match selector {
        0 => SsrfOastReviewOutcome::RepeatedCallbacksObserved,
        1 => {
            facts.replay_event = None;
            SsrfOastReviewOutcome::CandidateOnly
        },
        2 => {
            facts.candidate_event = None;
            SsrfOastReviewOutcome::ReplayOnly
        },
        3 => {
            facts.candidate_event = None;
            facts.replay_event = None;
            SsrfOastReviewOutcome::NoCallback
        },
        4 => {
            facts.candidate_event = Some(observed(WRONG_CALLBACK, CANDIDATE_EVENT));
            SsrfOastReviewOutcome::WrongCallback
        },
        5 => {
            facts.duplicate_only_substitution = true;
            SsrfOastReviewOutcome::DuplicateOnly
        },
        6 => {
            facts.replay_event = Some(observed(REPLAY_CALLBACK, CANDIDATE_EVENT));
            SsrfOastReviewOutcome::EventIdentityConflict
        },
        7 => {
            facts.correlations_distinct = false;
            SsrfOastReviewOutcome::CorrelationMismatch
        },
        8 => {
            facts.same_correlation_scope = false;
            SsrfOastReviewOutcome::CorrelationMismatch
        },
        9 => {
            facts.cleanup_verified = false;
            SsrfOastReviewOutcome::CleanupIncomplete
        },
        10 => {
            facts.truncated = true;
            SsrfOastReviewOutcome::Truncated
        },
        11 => {
            facts.target_accounting_complete = false;
            SsrfOastReviewOutcome::Incomplete
        },
        12 => {
            facts.candidate_dispatched = false;
            SsrfOastReviewOutcome::TargetNotDispatched
        },
        13 => {
            facts.preflight_clean = false;
            SsrfOastReviewOutcome::PreflightContaminated
        },
        14 => {
            facts.control_complete = false;
            SsrfOastReviewOutcome::ControlIncomplete
        },
        _ => {
            let callback = callback_id(CANDIDATE_CALLBACK);
            let conflicting = SsrfOastReviewFacts::new(&callback, &callback);
            assert_eq!(
                evaluate_ssrf_oast_review(&conflicting).unwrap_err(),
                SsrfOastContractError::CallbackIdentityConflict
            );
            return;
        },
    };
    let actual = evaluate_ssrf_oast_review(&facts).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(actual.projects_item(), selector == 0);

    let terminal = match data.get(4).copied().unwrap_or_default() % 10 {
        0 => SsrfOastTerminalState::DefensiveInterference,
        1 => SsrfOastTerminalState::RateLimited,
        2 => SsrfOastTerminalState::ProviderAuthenticationFailed,
        3 => SsrfOastTerminalState::MalformedProviderResponse,
        4 => SsrfOastTerminalState::PollExhausted,
        5 => SsrfOastTerminalState::Expired,
        6 => SsrfOastTerminalState::Cancelled,
        7 => SsrfOastTerminalState::BudgetExhausted,
        8 => SsrfOastTerminalState::Incomplete,
        _ => SsrfOastTerminalState::TargetTimeoutAfterDispatch,
    };
    let mut terminal_facts = complete_facts();
    terminal_facts.terminal = Some(terminal);
    let terminal_outcome = evaluate_ssrf_oast_review(&terminal_facts).unwrap();
    assert_eq!(
        terminal_outcome.projects_item(),
        matches!(terminal, SsrfOastTerminalState::TargetTimeoutAfterDispatch)
    );
}

fn check_fixed_regressions() {
    let positive = evaluate_ssrf_oast_review(&complete_facts()).unwrap();
    assert_eq!(positive, SsrfOastReviewOutcome::RepeatedCallbacksObserved);
    assert!(positive.projects_item());

    let mut one_sided = complete_facts();
    one_sided.replay_event = None;
    assert_eq!(
        evaluate_ssrf_oast_review(&one_sided).unwrap(),
        SsrfOastReviewOutcome::CandidateOnly
    );
    assert!(!evaluate_ssrf_oast_review(&one_sided)
        .unwrap()
        .projects_item());

    let origin = Url::parse(TARGET).unwrap();
    let duplicate = Url::parse(
        "https://target.example.test/fetch?next=https%3A%2F%2Fa.example&next=https%3A%2F%2Fb.example",
    )
    .unwrap();
    assert!(matches!(
        select_observed_query_candidate(
            &origin,
            &duplicate,
            "subject-sha256:fixed",
            true,
            true,
            true,
        ),
        SsrfOastCandidateSelection::NotEligible
    ));
}

fn policy_source(
    target: &str,
    provider: &str,
    acknowledgement: bool,
    polls: u16,
    interval: u64,
    lifetime: u64,
    suffix: &str,
) -> String {
    format!(
        "schema = \"security.ssrf-oast-review-policy/v1\"\n\
         target_origin = \"{target}\"\n\
         provider_origin = \"{provider}\"\n\
         acknowledge_external_interaction = {acknowledgement}\n\
         polls_per_leg = {polls}\n\
         poll_interval_ms = {interval}\n\
         lifetime_ms = {lifetime}\n\
         {suffix}"
    )
}

fn valid_policy() -> SsrfOastReviewPolicy {
    SsrfOastReviewPolicy::parse_toml(
        &Url::parse(TARGET).unwrap(),
        policy_source(TARGET, PROVIDER, true, 2, 500, 10_000, "").as_bytes(),
    )
    .unwrap()
}

fn selected_candidate(resource: &Url) -> crate::scanner_ssrf_oast_review::SsrfOastQueryCandidate {
    let SsrfOastCandidateSelection::Selected(candidate) = select_observed_query_candidate(
        &Url::parse(TARGET).unwrap(),
        resource,
        "subject-sha256:fuzz",
        true,
        true,
        true,
    ) else {
        panic!("fixed structurally eligible query must be selected")
    };
    candidate
}

fn complete_facts() -> SsrfOastReviewFacts {
    let candidate = callback_id(CANDIDATE_CALLBACK);
    let replay = callback_id(REPLAY_CALLBACK);
    let mut facts = SsrfOastReviewFacts::new(&candidate, &replay);
    facts.control_complete = true;
    facts.provider_registered = true;
    facts.allocations_complete = true;
    facts.preflight_clean = true;
    facts.candidate_dispatched = true;
    facts.replay_dispatched = true;
    facts.candidate_event = Some(observed(CANDIDATE_CALLBACK, CANDIDATE_EVENT));
    facts.replay_event = Some(observed(REPLAY_CALLBACK, REPLAY_EVENT));
    facts.correlations_distinct = true;
    facts.same_correlation_scope = true;
    facts.cleanup_verified = true;
    facts.target_accounting_complete = true;
    facts.provider_accounting_complete = true;
    facts
}

fn observed(callback: &str, event: &str) -> SsrfOastObservedEvent {
    let digest = Sha256::digest(event.as_bytes());
    let mut event_key = [0_u8; 32];
    event_key.copy_from_slice(&digest);
    let event_key = OastEventKey::new(event_key).expect("fixed event identity must be non-zero");
    SsrfOastObservedEvent::from_reduced(&callback_id(callback), &event_key)
}

fn callback_id(value: &str) -> CallbackId {
    value
        .parse()
        .expect("fixed callback identity must be canonical")
}

fn callback_target(callback: &str) -> String {
    format!("{PROVIDER}c/{SESSION}/{callback}")
}

fn query_value(target: &Url, name: &str) -> String {
    target
        .query_pairs()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.into_owned())
        .expect("fixed query key must remain present")
}

fn compact_hex(data: &[u8], maximum: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(data.len().min(maximum) * 2 + 1);
    if data.is_empty() {
        return "0".to_owned();
    }
    for byte in data.iter().take(maximum) {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn nonzero_array(data: &[u8], domain: u8) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = data
            .get(index % data.len().max(1))
            .copied()
            .unwrap_or_default()
            .wrapping_add(domain)
            .wrapping_add(index as u8);
    }
    if output.iter().all(|byte| *byte == 0) {
        output[0] = domain.max(1);
    }
    output
}
