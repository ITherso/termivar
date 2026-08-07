//! Activation corpus for the `venom decision-scan` preview runtime.
//!
//! This is a **deterministic characterization corpus**, not a full golden of every
//! field. It changes no production runtime behavior, planner action, reasoning
//! rule, verification rule, executor route, threshold, semantic/defense
//! integration, payload binding, API-reasoning default, or CLI output. It drives
//! the existing [`StandardWebDecisionRuntime`] through a **manually mirrored
//! snapshot of the current `venom decision-scan` preview profile** (see
//! `preview_runtime` below and `crates/venom-cli/src/decision_scan.rs`) against
//! offline `127.0.0.1` fixtures, and records the observable contract: emitted
//! evidence predicates, resulting hypotheses and strength, per-turn
//! eligible/excluded planner actions with the exact exclusion reason, the actions
//! actually dispatched on the wire, executor-route availability, verification
//! outcome status, the terminal command with its stop reason, and request usage.
//! Elapsed time, the ephemeral port, and chunk-dependent byte counts are
//! deliberately not pinned so the corpus stays stable.
//!
//! The corpus is split in two.
//!
//! * **Negative / neutral fixtures** carry no activation signal and must keep
//!   halting with `no_eligible_action`.
//! * **Positive activation fixtures** deliberately trip the built-in reasoning
//!   rules. They fall into three truthful classes:
//!   * **Capability gap:** `php` / `laravel-input` create/depend on a hypothesis
//!     but their planner action is always excluded as `policy_suppressed` because
//!     no built-in discovery executor routes them — visible gap, not a runtime
//!     bug.
//!   * **Executor-backed end to end:** `nginx` / `apache` / `http-basic` /
//!     `http-bearer` / `livewire` run reasoning -> planning -> execution ->
//!     verification to a terminal verification outcome (Success / complete)
//!     without adding any capability. The nginx/apache configuration routes
//!     succeed only on a version-bearing `Server` disclosure (`nginx/<version>`,
//!     `Apache/<version>`); a bare product token gates the action but its probe
//!     resolves to `unknown` and defers to human review, and a blocked status
//!     (401/403/429) resolves to `blocked` even when a version is disclosed.
//!   * **Activated but not executed end to end:** Laravel route discovery is
//!     dispatched but resolves to `needs_review` and defers to human review;
//!     Sanctum is activated and planned but **never dispatched**, because the same
//!     cookie pair raises a higher-utility Laravel route that reaches human review
//!     first. Their executor-backed verification is proven in isolation by
//!     `web_verification::tests`, not by this end-to-end runtime path.
//!
//! ## The `Allow` header is a verification signal, not an activation signal
//!
//! The user-facing corpus brief listed an "`Allow` header for Laravel route
//! review" activation fixture. The reasoning rules (`web_reasoning.rs`) contain
//! **no** rule mapping an `Allow` header to a Laravel hypothesis: Laravel
//! activates only via `X-Powered-By: laravel` or the `laravel_session` +
//! `XSRF-TOKEN` cookie pair. The `Allow` header is consumed one layer later, by
//! the Laravel-route **verifier** (`web_verification.rs`), where it produces a
//! deliberately cautious `needs_review` outcome. This corpus therefore models
//! Laravel activation truthfully — `X-Powered-By: laravel` for activation, with an
//! `Allow` header present on the response so the route *review* has its documented
//! signal — rather than inventing an `Allow` -> Laravel rule.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use url::Url;
use venom_core::{EvidenceValue, HypothesisStrength, OutcomeStatus};
use venom_scanner::{
    DecisionActionOrigin, DecisionLoopCommand, DecisionStopReason, ExclusionReason,
    HttpBodyCapture, HttpEvidencePolicy, RuntimeBudget, StandardWebActionKind,
    StandardWebDecisionRuntime,
};

// --- Preview profile: manually mirrored snapshot of the decision-scan preview --
//
// These constants and `preview_runtime` are a MANUALLY MIRRORED SNAPSHOT of the
// current `venom decision-scan` preview profile in
// `crates/venom-cli/src/decision_scan.rs`. They are not shared code and are not
// identical "by construction" — this milestone deliberately introduces no public
// config API. Any change to the CLI preview profile (budget, body capture,
// business value, planning budget, risk limit, action cycles) MUST update this
// corpus in the same PR, or these goldens will silently describe a stale profile.

const PREVIEW_MAX_TOTAL_REQUESTS: u32 = 16;
const PREVIEW_MAX_WALL_TIME_SECS: u64 = 60;
const PREVIEW_MAX_CUMULATIVE_RESPONSE_BYTES: u64 = 1024 * 1024;
const PREVIEW_BODY_SAMPLE_CHARS: usize = 8_192;

/// Builds a runtime from the manually mirrored snapshot of the decision-scan
/// preview profile. See the module and section notes on the sync obligation.
fn preview_runtime(target: Url) -> StandardWebDecisionRuntime {
    let policy = HttpEvidencePolicy::for_origin(target.clone())
        .unwrap()
        .with_body_capture(HttpBodyCapture::TextSample {
            max_chars: PREVIEW_BODY_SAMPLE_CHARS,
        })
        .unwrap();
    let budget = RuntimeBudget::default()
        .with_max_total_requests(PREVIEW_MAX_TOTAL_REQUESTS)
        .with_max_wall_time(Duration::from_secs(PREVIEW_MAX_WALL_TIME_SECS))
        .with_max_response_bytes(PREVIEW_MAX_CUMULATIVE_RESPONSE_BYTES);
    StandardWebDecisionRuntime::builder(target)
        .http_policy(policy)
        .runtime_budget(budget)
        .business_value(80)
        .planning_budget(100)
        .risk_limit(40)
        .max_action_cycles(8)
        .build()
        .unwrap()
}

// --- Offline fixture server ---------------------------------------------------

/// A local HTTP/1.1 server bound to `127.0.0.1` that replies to *every*
/// connection with the same bytes. Serving identical bytes to each probe lets a
/// single fixture drive multi-request supported paths deterministically.
struct FixtureServer {
    url: Url,
    methods: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FixtureServer {
    async fn methods(&self) -> Vec<String> {
        self.methods.lock().await.clone()
    }
}

async fn serve(response: Vec<u8>, delay: Duration) -> FixtureServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let response = Arc::new(response);
    let methods = Arc::new(Mutex::new(Vec::new()));
    let recorded = methods.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => break,
            };
            let response = Arc::clone(&response);
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 512];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            request.extend_from_slice(&chunk[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        },
                        Err(_) => return,
                    }
                }
                let method = String::from_utf8_lossy(&request)
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                recorded.lock().await.push(method);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    FixtureServer {
        url: Url::parse(&format!("http://{address}/")).unwrap(),
        methods,
        task,
    }
}

/// Assembles a raw HTTP/1.1 response with a correct `Content-Length`.
fn response(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

// --- Observation extraction ---------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Hypothesis {
    predicate: String,
    value: String,
    strength: HypothesisStrength,
    posterior_bp: u16,
    state: String,
}

/// One planning turn: what the planner ranked as eligible (dependency-safe plan
/// steps) versus excluded, with the exact exclusion reason. Captured for *every*
/// planning turn so future replanning cannot become invisible.
#[derive(Debug, Clone, PartialEq)]
struct PlanningObservation {
    eligible: Vec<String>,
    excluded: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
struct Observation {
    evidence: BTreeSet<String>,
    hypotheses: Vec<Hypothesis>,
    /// Every planning turn, in order. `planning[0]` is the initial plan.
    planning: Vec<PlanningObservation>,
    /// Actions actually dispatched on the wire, as `(action_id, origin)` in
    /// dispatch order (includes the bootstrap probe). This is proof of what the
    /// transport executed, distinct from what the planner merely ranked eligible.
    dispatched: Vec<(String, String)>,
    /// Verification outcomes, as `(action_id, status)` in turn order.
    outcomes: Vec<(String, String)>,
    terminal: String,
    total_requests: u32,
    active_verifications: u16,
    response_bytes: u64,
    limit_dimension: Option<String>,
    methods: Vec<String>,
    unsupported: BTreeSet<String>,
}

fn value_text(value: &EvidenceValue) -> String {
    match value {
        EvidenceValue::Text(text) => text.clone(),
        other => format!("{other:?}"),
    }
}

fn reason_tag(reason: &ExclusionReason) -> &'static str {
    match reason {
        ExclusionReason::PolicySuppressed => "policy_suppressed",
        ExclusionReason::DefenseSuppressed => "defense_suppressed",
        ExclusionReason::RequirementsNotMet => "requirements_not_met",
        ExclusionReason::NoEligibleHypothesis => "no_eligible_hypothesis",
        ExclusionReason::RiskLimitExceeded { .. } => "risk_limit_exceeded",
        ExclusionReason::BelowMinimumUtility { .. } => "below_minimum_utility",
        ExclusionReason::DependencyUnavailable { .. } => "dependency_unavailable",
        ExclusionReason::BudgetExceeded { .. } => "budget_exceeded",
        _ => "other",
    }
}

fn status_label(status: OutcomeStatus) -> String {
    match status {
        OutcomeStatus::Success => "success",
        OutcomeStatus::Blocked => "blocked",
        OutcomeStatus::Unknown => "unknown",
        OutcomeStatus::FalsePositive => "false_positive",
        OutcomeStatus::NeedsReview => "needs_review",
        OutcomeStatus::ConfirmedNegative => "confirmed_negative",
        _ => "other",
    }
    .to_owned()
}

fn stop_reason_label(reason: &DecisionStopReason) -> &'static str {
    match reason {
        DecisionStopReason::ObjectiveComplete => "objective_complete",
        DecisionStopReason::NoEligibleAction => "no_eligible_action",
        DecisionStopReason::HumanReview => "human_review",
        DecisionStopReason::AdaptationLimit => "adaptation_limit",
        DecisionStopReason::ActionCycleLimit => "action_cycle_limit",
        DecisionStopReason::RuntimeBudgetLimit => "runtime_budget_limit",
        DecisionStopReason::CancelledByHost => "cancelled_by_host",
        _ => "other",
    }
}

fn origin_label(origin: Option<DecisionActionOrigin>) -> String {
    match origin {
        Some(DecisionActionOrigin::Bootstrap) => "bootstrap",
        Some(DecisionActionOrigin::Planned) => "planned",
        Some(DecisionActionOrigin::Retry) => "retry",
        Some(_) => "other",
        None => "none",
    }
    .to_owned()
}

fn terminal_label(command: &DecisionLoopCommand) -> String {
    match command {
        DecisionLoopCommand::ExecuteAction { .. } => "execute_action".to_owned(),
        DecisionLoopCommand::CollectActiveEvidence { .. } => "collect_active_evidence".to_owned(),
        DecisionLoopCommand::Replan => "replan".to_owned(),
        DecisionLoopCommand::Complete { .. } => "complete".to_owned(),
        DecisionLoopCommand::AwaitHumanReview { .. } => "await_human_review".to_owned(),
        DecisionLoopCommand::Halt { reason } => format!("halt:{}", stop_reason_label(reason)),
        _ => "other".to_owned(),
    }
}

/// Runs one fixture through the preview runtime and extracts its deterministic
/// observation.
async fn observe(fixture: Vec<u8>, delay: Duration) -> Observation {
    let server = serve(fixture, delay).await;
    let mut runtime = preview_runtime(server.url.clone());
    let report = runtime.analyze().await.expect("preview runtime analyze");

    let evidence = report
        .bootstrap()
        .map(|bootstrap| {
            bootstrap
                .evidence()
                .iter()
                .map(|evidence| evidence.predicate().dotted())
                .collect()
        })
        .unwrap_or_default();

    let snapshot = runtime.knowledge().snapshot_for_subject(runtime.subject());
    let mut hypotheses: Vec<Hypothesis> = snapshot
        .hypotheses()
        .iter()
        .map(|hypothesis| Hypothesis {
            predicate: hypothesis.predicate().dotted(),
            value: value_text(hypothesis.value()),
            strength: hypothesis.strength(),
            posterior_bp: (hypothesis.posterior().ratio() * 10_000.0).round() as u16,
            state: format!("{:?}", hypothesis.state()),
        })
        .collect();
    hypotheses.sort_by(|left, right| {
        (left.predicate.as_str(), left.value.as_str())
            .cmp(&(right.predicate.as_str(), right.value.as_str()))
    });

    let planning: Vec<PlanningObservation> = report
        .planning_reports()
        .map(|report| PlanningObservation {
            eligible: report
                .plan()
                .steps()
                .iter()
                .map(|step| step.action_id().to_owned())
                .collect(),
            excluded: report
                .plan()
                .excluded()
                .iter()
                .map(|excluded| {
                    (
                        excluded.action_id().to_owned(),
                        reason_tag(excluded.reason()).to_owned(),
                    )
                })
                .collect(),
        })
        .collect();

    let dispatched: Vec<(String, String)> = report
        .transport()
        .receipts()
        .iter()
        .map(|receipt| {
            (
                receipt.action_id().to_owned(),
                origin_label(receipt.origin()),
            )
        })
        .collect();

    let outcomes: Vec<(String, String)> = report
        .outcome_reports()
        .map(|outcome| {
            let outcome = outcome.verification().outcome();
            (
                outcome.action_id().to_owned(),
                status_label(outcome.status()),
            )
        })
        .collect();

    let terminal = terminal_label(report.terminal());
    let usage = report.usage();
    let total_requests = usage.total_requests();
    let active_verifications = usage.active_verifications();
    let response_bytes = usage.response_bytes();
    let limit_dimension = report
        .limit_exceeded()
        .map(|limit| format!("{:?}", limit.dimension()));
    let methods = server.methods().await;
    let unsupported: BTreeSet<String> = runtime.unsupported_actions().iter().cloned().collect();

    Observation {
        evidence,
        hypotheses,
        planning,
        dispatched,
        outcomes,
        terminal,
        total_requests,
        active_verifications,
        response_bytes,
        limit_dimension,
        methods,
        unsupported,
    }
}

/// The planned (dependency-safe) actions of the initial planning turn.
fn initial_eligible(observation: &Observation) -> &[String] {
    observation
        .planning
        .first()
        .map(|turn| turn.eligible.as_slice())
        .unwrap_or_default()
}

/// The exclusion reason recorded for `action` in the initial planning turn.
fn initial_exclusion<'a>(observation: &'a Observation, action: &str) -> Option<&'a str> {
    observation
        .planning
        .first()
        .and_then(|turn| turn.excluded.get(action))
        .map(String::as_str)
}

/// Actions actually dispatched with a non-bootstrap origin, in dispatch order.
fn planned_dispatched(observation: &Observation) -> Vec<String> {
    observation
        .dispatched
        .iter()
        .filter(|(_, origin)| origin != "bootstrap")
        .map(|(action, _)| action.clone())
        .collect()
}

async fn observe_instant(fixture: Vec<u8>) -> Observation {
    observe(fixture, Duration::ZERO).await
}

// --- Stable action-id shorthands ---------------------------------------------

fn nginx() -> &'static str {
    StandardWebActionKind::NginxConfiguration.action_id()
}
fn apache() -> &'static str {
    StandardWebActionKind::ApacheConfiguration.action_id()
}
fn php() -> &'static str {
    StandardWebActionKind::PhpInputDiscovery.action_id()
}
fn laravel_route() -> &'static str {
    StandardWebActionKind::LaravelRouteDiscovery.action_id()
}
fn laravel_input() -> &'static str {
    StandardWebActionKind::LaravelInputAnalysis.action_id()
}
fn livewire() -> &'static str {
    StandardWebActionKind::LivewireComponentDiscovery.action_id()
}
fn sanctum() -> &'static str {
    StandardWebActionKind::SanctumAuthBoundary.action_id()
}
fn basic() -> &'static str {
    StandardWebActionKind::HttpBasicAuthBoundary.action_id()
}
fn bearer() -> &'static str {
    StandardWebActionKind::HttpBearerAuthBoundary.action_id()
}

/// The two semantic actions with no built-in discovery executor. Always excluded
/// as `policy_suppressed`, independent of what a fixture discloses. nginx and
/// apache are no longer here: they are now executor-backed routes.
fn expected_unsupported() -> BTreeSet<String> {
    [php(), laravel_input()]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn signal_predicates() -> [&'static str; 5] {
    [
        "http.header.server",
        "http.header.www-authenticate",
        "http.header.x-powered-by",
        "http.cookie.name",
        "http.header.allow",
    ]
}

/// Asserts the shared invariants every fixture must satisfy under the preview
/// profile.
fn assert_universal(observation: &Observation) {
    assert_eq!(
        observation.unsupported,
        expected_unsupported(),
        "the unsupported-executor set is a fixed capability boundary"
    );
    // In every planning turn the four executor-less actions are excluded as
    // policy_suppressed.
    for turn in &observation.planning {
        for action in expected_unsupported() {
            assert_eq!(
                turn.excluded.get(&action).map(String::as_str),
                Some("policy_suppressed"),
                "action {action} must always be excluded as policy_suppressed"
            );
        }
    }
    // Bootstrap always records the response status and is always dispatched first.
    assert!(
        observation.evidence.contains("http.response.status"),
        "bootstrap evidence must include the response status: {:?}",
        observation.evidence
    );
    assert_eq!(
        observation
            .dispatched
            .first()
            .map(|(_, origin)| origin.as_str()),
        Some("bootstrap"),
        "the first dispatch is always the bootstrap probe: {:?}",
        observation.dispatched
    );
}

/// Asserts a fixture halted with no eligible action, dispatched nothing beyond the
/// bootstrap probe, produced no outcome, and made exactly one request.
fn assert_inert(observation: &Observation) {
    assert_universal(observation);
    assert_eq!(observation.planning.len(), 1, "a single planning turn");
    assert!(
        initial_eligible(observation).is_empty(),
        "no action should be planned"
    );
    assert!(
        planned_dispatched(observation).is_empty(),
        "nothing beyond bootstrap should dispatch: {:?}",
        observation.dispatched
    );
    assert!(observation.outcomes.is_empty(), "no verification outcome");
    assert_eq!(observation.terminal, "halt:no_eligible_action");
    assert_eq!(observation.total_requests, 1);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(observation.methods, vec!["GET".to_owned()]);
}

fn assert_no_signal_evidence(observation: &Observation) {
    for signal in signal_predicates() {
        assert!(
            !observation.evidence.contains(signal),
            "neutral fixture unexpectedly emitted {signal}"
        );
    }
}

// --- Negative / neutral fixtures ---------------------------------------------

#[tokio::test]
async fn generic_200_html_stays_inert() {
    let observation = observe_instant(response(
        "200 OK",
        &["Content-Type: text/html"],
        b"<html><body>hello</body></html>",
    ))
    .await;

    assert_inert(&observation);
    assert!(observation.hypotheses.is_empty());
    assert_no_signal_evidence(&observation);
}

#[tokio::test]
async fn not_found_404_stays_inert() {
    let observation = observe_instant(response(
        "404 Not Found",
        &["Content-Type: text/plain"],
        b"not found",
    ))
    .await;

    assert_inert(&observation);
    assert!(observation.hypotheses.is_empty());
    assert_no_signal_evidence(&observation);
}

#[tokio::test]
async fn forbidden_403_stays_inert_without_a_blocked_outcome() {
    // A bare 403 during bootstrap carries no action to correlate a Blocked
    // outcome against, so the runtime correctly stays inert.
    let observation = observe_instant(response(
        "403 Forbidden",
        &["Content-Type: text/plain"],
        b"forbidden",
    ))
    .await;

    assert_inert(&observation);
    assert!(observation.hypotheses.is_empty());
    assert_no_signal_evidence(&observation);
}

#[tokio::test]
async fn generic_json_stays_inert_without_api_reasoning() {
    // The preview profile does not enable API reasoning, so generic JSON yields no
    // hypotheses.
    let observation = observe_instant(response(
        "200 OK",
        &["Content-Type: application/json"],
        b"{\"ok\":true}",
    ))
    .await;

    assert_inert(&observation);
    assert!(observation.hypotheses.is_empty());
    assert_no_signal_evidence(&observation);
}

#[tokio::test]
async fn slow_response_within_timeout_stays_inert() {
    let observation = observe(
        response("200 OK", &["Content-Type: text/html"], b"<html>slow</html>"),
        Duration::from_millis(250),
    )
    .await;

    assert_inert(&observation);
    assert!(observation.hypotheses.is_empty());
}

#[tokio::test]
async fn large_body_is_truncated_and_stays_inert() {
    let body = vec![b'a'; 300_000];
    let observation =
        observe_instant(response("200 OK", &["Content-Type: text/html"], &body)).await;

    assert_universal(&observation);
    assert!(observation.hypotheses.is_empty());
    assert_eq!(observation.terminal, "halt:no_eligible_action");
    assert_eq!(observation.total_requests, 1);
    assert!(
        observation
            .evidence
            .contains("http.response.body-truncated"),
        "an over-limit body must record a truncation predicate: {:?}",
        observation.evidence
    );
}

#[tokio::test]
async fn repeated_identical_response_is_deterministic() {
    // "Repeated identical response": the same neutral fixture observed twice
    // against fresh servers yields a byte-for-byte identical observation (the
    // ephemeral port and elapsed time are never part of the observation).
    let fixture = || {
        response(
            "200 OK",
            &["Content-Type: text/html"],
            b"<html>repeat</html>",
        )
    };
    let first = observe_instant(fixture()).await;
    let second = observe_instant(fixture()).await;

    assert_inert(&first);
    assert_eq!(first, second, "identical fixtures must observe identically");
}

// --- Positive activation fixtures: capability gap (policy-suppressed) ---------

#[tokio::test]
async fn powered_by_php_activates_a_hypothesis_but_is_policy_suppressed() {
    let observation = observe_instant(response(
        "200 OK",
        &["X-Powered-By: PHP/8.3.7", "Content-Type: text/html"],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.x-powered-by"));
    assert_eq!(observation.hypotheses.len(), 1);
    assert_eq!(observation.hypotheses[0].predicate, "technology.language");
    assert_eq!(observation.hypotheses[0].value, "php");
    assert_eq!(observation.hypotheses[0].strength, HypothesisStrength::Weak);
    assert_eq!(
        initial_exclusion(&observation, php()),
        Some("policy_suppressed")
    );
    assert!(initial_eligible(&observation).is_empty());
    assert!(planned_dispatched(&observation).is_empty());
    assert!(observation.outcomes.is_empty());
    assert_eq!(observation.terminal, "halt:no_eligible_action");
    assert_eq!(observation.total_requests, 1);
}

// --- Positive activation fixtures: supported end-to-end paths -----------------

#[tokio::test]
async fn server_nginx_version_disclosure_drives_a_supported_success() {
    // A version-bearing `Server: nginx/<version>` token is the positive signal:
    // the HEAD probe reads it and the objective completes. Bootstrap GET + passive
    // HEAD, one Success outcome, no active verification.
    let observation = observe_instant(response(
        "200 OK",
        &["Server: nginx/1.26.0", "Content-Type: text/html"],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.server"));
    assert_eq!(observation.hypotheses.len(), 1);
    let hypothesis = &observation.hypotheses[0];
    assert_eq!(hypothesis.predicate, "technology.web-server");
    assert_eq!(hypothesis.value, "nginx");
    assert_eq!(hypothesis.strength, HypothesisStrength::Weak);
    // nginx is now an executor-backed route: planned, not excluded, dispatched.
    assert_eq!(initial_eligible(&observation), [nginx().to_owned()]);
    assert_eq!(initial_exclusion(&observation, nginx()), None);
    assert_eq!(planned_dispatched(&observation), vec![nginx().to_owned()]);
    assert_eq!(
        observation.outcomes,
        vec![(nginx().to_owned(), "success".to_owned())]
    );
    assert_eq!(observation.terminal, "complete");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn bare_server_nginx_dispatches_but_defers_to_human_review() {
    // A bare `Server: nginx` (server_tokens off) gates the action but carries no
    // version, so the version-disclosure signal never fires. The probe therefore
    // resolves to `unknown` (passive then active) and defers to human review; it
    // is NEVER promoted to success. This is the anti-circularity guarantee: the
    // token that gates the action cannot by itself confirm it.
    let observation = observe_instant(response(
        "200 OK",
        &["Server: nginx", "Content-Type: text/html"],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.server"));
    assert_eq!(observation.hypotheses.len(), 1);
    assert_eq!(observation.hypotheses[0].predicate, "technology.web-server");
    assert_eq!(observation.hypotheses[0].value, "nginx");
    // Dispatched (executor-backed) but never a success outcome.
    assert_eq!(initial_eligible(&observation), [nginx().to_owned()]);
    assert_eq!(initial_exclusion(&observation, nginx()), None);
    assert_eq!(
        planned_dispatched(&observation),
        vec![nginx().to_owned(), nginx().to_owned()]
    );
    assert_eq!(
        observation.outcomes,
        vec![
            (nginx().to_owned(), "unknown".to_owned()),
            (nginx().to_owned(), "unknown".to_owned()),
        ]
    );
    assert!(
        !observation
            .outcomes
            .iter()
            .any(|(_, status)| status == "success"),
        "a bare product token must never be promoted to success: {:?}",
        observation.outcomes
    );
    assert_eq!(observation.terminal, "await_human_review");
    assert_eq!(observation.total_requests, 3);
    assert_eq!(observation.active_verifications, 1);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn blocked_nginx_probe_reports_blocked_even_with_a_version() {
    // A denying status (403) follows the shared blocked rule and outranks the
    // version-disclosure signal: even though the response discloses a version,
    // the outcome is `blocked`, not `success`. Blocked is terminal for
    // verification, so there is no active retry.
    let observation = observe_instant(response(
        "403 Forbidden",
        &["Server: nginx/1.26.0", "Content-Type: text/html"],
        b"forbidden",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.server"));
    assert_eq!(observation.hypotheses.len(), 1);
    assert_eq!(observation.hypotheses[0].value, "nginx");
    assert_eq!(initial_eligible(&observation), [nginx().to_owned()]);
    assert_eq!(planned_dispatched(&observation), vec![nginx().to_owned()]);
    assert_eq!(
        observation.outcomes,
        vec![(nginx().to_owned(), "blocked".to_owned())]
    );
    assert_eq!(observation.terminal, "await_human_review");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn server_apache_version_disclosure_drives_a_supported_success() {
    // A version-bearing `Apache/<version>` token is the positive signal: the HEAD
    // probe reads it and the objective completes. Bootstrap GET + passive HEAD,
    // one Success outcome, no active verification.
    let observation = observe_instant(response(
        "200 OK",
        &["Server: Apache/2.4.58 (Unix)", "Content-Type: text/html"],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.server"));
    assert_eq!(observation.hypotheses.len(), 1);
    let hypothesis = &observation.hypotheses[0];
    assert_eq!(hypothesis.predicate, "technology.web-server");
    assert_eq!(hypothesis.value, "apache-http-server");
    assert_eq!(hypothesis.strength, HypothesisStrength::Weak);
    // apache is now an executor-backed route: planned, not excluded, dispatched.
    assert_eq!(initial_eligible(&observation), [apache().to_owned()]);
    assert_eq!(initial_exclusion(&observation, apache()), None);
    assert_eq!(planned_dispatched(&observation), vec![apache().to_owned()]);
    assert_eq!(
        observation.outcomes,
        vec![(apache().to_owned(), "success".to_owned())]
    );
    assert_eq!(observation.terminal, "complete");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn bare_server_apache_dispatches_but_defers_to_human_review() {
    // A bare `Server: Apache` (ServerTokens Prod) gates the action but carries no
    // version, so the version-disclosure signal never fires. The probe resolves
    // to `unknown` (passive then active) and defers to human review; it is NEVER
    // promoted to success. Same anti-circularity guarantee as nginx.
    let observation = observe_instant(response(
        "200 OK",
        &["Server: Apache", "Content-Type: text/html"],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.server"));
    assert_eq!(observation.hypotheses.len(), 1);
    assert_eq!(observation.hypotheses[0].predicate, "technology.web-server");
    assert_eq!(observation.hypotheses[0].value, "apache-http-server");
    assert_eq!(initial_eligible(&observation), [apache().to_owned()]);
    assert_eq!(initial_exclusion(&observation, apache()), None);
    assert_eq!(
        planned_dispatched(&observation),
        vec![apache().to_owned(), apache().to_owned()]
    );
    assert_eq!(
        observation.outcomes,
        vec![
            (apache().to_owned(), "unknown".to_owned()),
            (apache().to_owned(), "unknown".to_owned()),
        ]
    );
    assert!(
        !observation
            .outcomes
            .iter()
            .any(|(_, status)| status == "success"),
        "a bare product token must never be promoted to success: {:?}",
        observation.outcomes
    );
    assert_eq!(observation.terminal, "await_human_review");
    assert_eq!(observation.total_requests, 3);
    assert_eq!(observation.active_verifications, 1);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn blocked_apache_probe_reports_blocked_even_with_a_version() {
    // A denying status (403) follows the shared blocked rule and outranks the
    // version-disclosure signal: the outcome is `blocked`, not `success`. Blocked
    // is terminal for verification, so there is no active retry.
    let observation = observe_instant(response(
        "403 Forbidden",
        &["Server: Apache/2.4.58 (Unix)", "Content-Type: text/html"],
        b"forbidden",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.server"));
    assert_eq!(observation.hypotheses.len(), 1);
    assert_eq!(observation.hypotheses[0].value, "apache-http-server");
    assert_eq!(initial_eligible(&observation), [apache().to_owned()]);
    assert_eq!(planned_dispatched(&observation), vec![apache().to_owned()]);
    assert_eq!(
        observation.outcomes,
        vec![(apache().to_owned(), "blocked".to_owned())]
    );
    assert_eq!(observation.terminal, "await_human_review");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn www_authenticate_basic_drives_a_supported_success() {
    let observation = observe_instant(response(
        "401 Unauthorized",
        &["WWW-Authenticate: Basic realm=\"admin\""],
        b"",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation
        .evidence
        .contains("http.header.www-authenticate"));
    assert_eq!(observation.hypotheses.len(), 1);
    let hypothesis = &observation.hypotheses[0];
    assert_eq!(hypothesis.predicate, "authentication.mechanism");
    assert_eq!(hypothesis.value, "http-basic");
    assert_eq!(hypothesis.strength, HypothesisStrength::Strong);
    assert!(
        hypothesis.posterior_bp >= 9000,
        "strong basic posterior >= 90%"
    );
    // Supported executor: planned, dispatched (passive HEAD), confirmed Success,
    // objective complete.
    assert_eq!(initial_eligible(&observation), [basic().to_owned()]);
    assert_eq!(initial_exclusion(&observation, basic()), None);
    assert_eq!(planned_dispatched(&observation), vec![basic().to_owned()]);
    assert_eq!(
        observation.outcomes,
        vec![(basic().to_owned(), "success".to_owned())]
    );
    assert_eq!(observation.terminal, "complete");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn www_authenticate_bearer_drives_a_supported_success() {
    let observation = observe_instant(response(
        "401 Unauthorized",
        &["WWW-Authenticate: Bearer"],
        b"",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation
        .evidence
        .contains("http.header.www-authenticate"));
    assert_eq!(observation.hypotheses.len(), 1);
    assert_eq!(
        observation.hypotheses[0].predicate,
        "authentication.mechanism"
    );
    assert_eq!(observation.hypotheses[0].value, "http-bearer");
    assert_eq!(
        observation.hypotheses[0].strength,
        HypothesisStrength::Strong
    );
    assert_eq!(initial_eligible(&observation), [bearer().to_owned()]);
    assert_eq!(planned_dispatched(&observation), vec![bearer().to_owned()]);
    assert_eq!(
        observation.outcomes,
        vec![(bearer().to_owned(), "success".to_owned())]
    );
    assert_eq!(observation.terminal, "complete");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "HEAD".to_owned()]
    );
}

#[tokio::test]
async fn livewire_body_marker_drives_a_supported_path() {
    let observation = observe_instant(response(
        "200 OK",
        &["Content-Type: text/html"],
        b"<div wire:id=\"abc\"></div>",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.response.body-sample"));
    assert_eq!(observation.hypotheses.len(), 1);
    let hypothesis = &observation.hypotheses[0];
    assert_eq!(hypothesis.predicate, "technology.ui-framework");
    assert_eq!(hypothesis.value, "livewire");
    assert_eq!(hypothesis.strength, HypothesisStrength::Weak);
    // Livewire is a supported discovery action. Its probe is a GET (the marker
    // lives in the body), so a single passive GET confirms the marker and the
    // objective completes: bootstrap GET + passive GET, one Success outcome.
    assert_eq!(initial_eligible(&observation), [livewire().to_owned()]);
    assert_eq!(
        planned_dispatched(&observation),
        vec![livewire().to_owned()]
    );
    assert_eq!(
        observation.outcomes,
        vec![(livewire().to_owned(), "success".to_owned())]
    );
    assert_eq!(observation.terminal, "complete");
    assert_eq!(observation.total_requests, 2);
    assert_eq!(observation.active_verifications, 0);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "GET".to_owned()]
    );
}

#[tokio::test]
async fn laravel_route_activation_reaches_route_review() {
    // X-Powered-By activates Laravel (Strong); the Allow header is the route
    // *review* signal consumed by the verifier (-> needs_review), not an
    // activation signal.
    let observation = observe_instant(response(
        "200 OK",
        &[
            "X-Powered-By: Laravel",
            "Allow: GET,HEAD,POST,OPTIONS",
            "Content-Type: text/html",
        ],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.header.x-powered-by"));
    assert!(observation.evidence.contains("http.header.allow"));
    let laravel = observation
        .hypotheses
        .iter()
        .find(|hypothesis| hypothesis.value == "laravel")
        .expect("laravel hypothesis present");
    assert_eq!(laravel.predicate, "technology.framework");
    assert_eq!(laravel.strength, HypothesisStrength::Strong);
    // Laravel route discovery is supported; laravel input analysis is not.
    // The route probes with OPTIONS to elicit the Allow header; passive then
    // active both see it and yield the deliberately cautious needs_review, so the
    // runtime hands the case to human review rather than auto-confirming Laravel.
    assert_eq!(initial_eligible(&observation), [laravel_route().to_owned()]);
    assert_eq!(
        initial_exclusion(&observation, laravel_input()),
        Some("policy_suppressed")
    );
    // Route dispatched twice: passive (planned) then active (retry-origin) probe.
    assert_eq!(
        planned_dispatched(&observation),
        vec![laravel_route().to_owned(), laravel_route().to_owned()]
    );
    assert_eq!(
        observation.outcomes,
        vec![
            (laravel_route().to_owned(), "needs_review".to_owned()),
            (laravel_route().to_owned(), "needs_review".to_owned()),
        ]
    );
    assert_eq!(observation.terminal, "await_human_review");
    assert_eq!(observation.total_requests, 3);
    assert_eq!(observation.active_verifications, 1);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "OPTIONS".to_owned(), "OPTIONS".to_owned()]
    );
}

#[tokio::test]
async fn sanctum_cookie_pair_coactivates_laravel_and_defers_to_route_review() {
    // The `laravel_session` + `XSRF-TOKEN` cookie pair is the *only* activation
    // path for a Sanctum hypothesis, and that same pair also raises a Strong
    // Laravel hypothesis. Sanctum therefore cannot be activated in isolation from
    // the standard rules. Both discovery actions are planned, but Laravel route
    // discovery outranks Sanctum by utility (Laravel posterior ~87% vs Sanctum
    // ~51%), so the runtime executes the route first. Without an Allow header the
    // route resolves to `unknown` (passive then active) and the session is handed
    // to human review BEFORE the Sanctum action executes.
    //
    // This is a truthful capability characterization, not a runtime fault: the
    // Sanctum verification path is proven in isolation by
    // `web_verification::tests`, but it is not independently reachable end to end
    // from a single decision-scan fixture. It is intentionally left unpatched.
    let observation = observe_instant(response(
        "200 OK",
        &[
            "Set-Cookie: laravel_session=eyJ; Path=/; HttpOnly",
            "Set-Cookie: XSRF-TOKEN=abc123; Path=/",
            "Content-Type: text/html",
        ],
        b"hi",
    ))
    .await;

    assert_universal(&observation);
    assert!(observation.evidence.contains("http.cookie.name"));
    let laravel = observation
        .hypotheses
        .iter()
        .find(|hypothesis| hypothesis.value == "laravel")
        .expect("laravel hypothesis present");
    assert_eq!(laravel.predicate, "technology.framework");
    assert_eq!(laravel.strength, HypothesisStrength::Strong);
    let sanctum_hypothesis = observation
        .hypotheses
        .iter()
        .find(|hypothesis| hypothesis.value == "sanctum")
        .expect("sanctum hypothesis present");
    assert_eq!(sanctum_hypothesis.predicate, "authentication.mechanism");
    assert_eq!(sanctum_hypothesis.strength, HypothesisStrength::Weak);

    // Both discovery actions are planned (route ranked ahead of sanctum); input
    // analysis is the unsupported action.
    assert_eq!(
        initial_eligible(&observation),
        [laravel_route().to_owned(), sanctum().to_owned()]
    );
    assert_eq!(
        initial_exclusion(&observation, laravel_input()),
        Some("policy_suppressed")
    );

    // Only the route is ever dispatched; sanctum is planned-but-never-executed.
    assert_eq!(
        planned_dispatched(&observation),
        vec![laravel_route().to_owned(), laravel_route().to_owned()]
    );
    assert!(
        !planned_dispatched(&observation).contains(&sanctum().to_owned()),
        "sanctum must never dispatch: {:?}",
        observation.dispatched
    );
    assert_eq!(
        observation.outcomes,
        vec![
            (laravel_route().to_owned(), "unknown".to_owned()),
            (laravel_route().to_owned(), "unknown".to_owned()),
        ]
    );
    assert!(
        !observation
            .outcomes
            .iter()
            .any(|(action, _)| action == sanctum()),
        "sanctum is deferred behind route review and does not execute: {:?}",
        observation.outcomes
    );
    assert_eq!(observation.terminal, "await_human_review");
    assert_eq!(observation.total_requests, 3);
    assert_eq!(observation.active_verifications, 1);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "OPTIONS".to_owned(), "OPTIONS".to_owned()]
    );
}

// --- Cumulative response-budget accounting across multiple requests -----------

/// The preview per-probe retained-body cap (`HttpEvidencePolicy::for_origin` uses
/// `DEFAULT_HTTP_BODY_LIMIT`). Each probe charges roughly this much delivered body
/// plus the chunk that crosses the cap.
const HTTP_BODY_LIMIT: u64 = 256 * 1024;

#[tokio::test]
async fn cumulative_response_budget_accounting_across_multiple_requests() {
    // Complements the single-probe 256 KiB truncation fixture: this drives a
    // MULTI-REQUEST path (Laravel route: bootstrap GET + passive OPTIONS + active
    // OPTIONS) with a large body on every response, so response bytes accumulate
    // across requests under one shared session budget.
    //
    // Whether the 1 MiB *cumulative* budget is actually crossed is transport-
    // chunk-dependent and therefore NOT pinned: the runtime dispatches at most
    // three body-delivering probes before terminating (it does not chain actions),
    // and each probe's charge is bounded near the 256 KiB per-probe cap. When the
    // transport delivers large chunks (typical un-instrumented Linux/Windows runs)
    // three probes charge ~1.2 MiB and cross the budget -> RuntimeBudgetLimit; when
    // it delivers small chunks (e.g. a ptrace-instrumented coverage run) three
    // probes charge ~0.8 MiB, stay under budget, and the route defers to human
    // review. Both are controlled terminations. No threshold is changed.
    //
    // The environment-independent contract pinned here: cumulative multi-request
    // response-byte accounting (well past a single probe's cap), a bounded request
    // count, a controlled terminal, and — whenever the response-byte budget IS the
    // binding limit — the `ResponseBytes` dimension with delivered bytes at/over
    // the 1 MiB threshold.
    let body = vec![b'a'; 400 * 1024];
    let observation = observe_instant(response(
        "200 OK",
        &[
            "X-Powered-By: Laravel",
            "Allow: GET,HEAD,POST,OPTIONS",
            "Content-Type: text/html",
        ],
        &body,
    ))
    .await;

    // Three body-delivering probes, within the 16-request preview cap.
    assert_eq!(observation.total_requests, 3);
    assert!(observation.total_requests <= PREVIEW_MAX_TOTAL_REQUESTS);
    assert_eq!(
        observation.methods,
        vec!["GET".to_owned(), "OPTIONS".to_owned(), "OPTIONS".to_owned()]
    );

    // Cumulative accounting: response bytes accumulate across requests, well beyond
    // a single probe's ~256 KiB cap. Robust in every environment.
    assert!(
        observation.response_bytes >= 2 * HTTP_BODY_LIMIT,
        "cumulative delivered bytes must exceed a single probe's cap: {}",
        observation.response_bytes
    );

    // Controlled termination in either transport regime — never a panic or an
    // uncontrolled state.
    assert!(
        matches!(
            observation.terminal.as_str(),
            "halt:runtime_budget_limit" | "await_human_review"
        ),
        "unexpected terminal: {}",
        observation.terminal
    );

    // Budget-dimension correctness: if any runtime limit bound the run, it is the
    // response-bytes dimension (never another dimension for this fixture).
    if let Some(dimension) = observation.limit_dimension.as_deref() {
        assert_eq!(dimension, "ResponseBytes");
    }

    // When the budget IS the binding limit, delivered bytes reach/cross 1 MiB and
    // the terminal is the response-bytes runtime-budget halt.
    if observation.terminal == "halt:runtime_budget_limit" {
        assert_eq!(
            observation.limit_dimension.as_deref(),
            Some("ResponseBytes")
        );
        assert!(
            observation.response_bytes >= PREVIEW_MAX_CUMULATIVE_RESPONSE_BYTES,
            "a budget halt must report >= 1 MiB delivered: {}",
            observation.response_bytes
        );
    }
}
