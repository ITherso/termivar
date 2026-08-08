//! CLI adapter for the `venom decision-scan` preview command.
//!
//! ## Runtime scope
//!
//! - **Build:** `venom-cli` binary crate.
//! - **Execution:** explicit Surface B preview entry point — composes the existing
//!   `StandardWebDecisionRuntime` with a `RuntimeBudget`. Does not touch the legacy
//!   `venom scan` Surface A pipeline.
//! - **Default `venom scan`:** no.
//! - **Support:** preview of an implemented-and-tested runtime; not the default
//!   scanner and not a new scanning capability.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! This adapter exposes existing behavior: the same conservative profile the
//! `decision_scan` example demonstrates. It adds no planner actions, rules,
//! verifiers, payload strategies, semantic extraction, defense composition, or API
//! reasoning. It propagates errors instead of panicking, and it renders the
//! runtime's own vocabulary through stable snake_case labels rather than `Debug`.

use std::error::Error;
use std::time::Duration;

use serde::Serialize;
use url::Url;
use venom_core::{EvidenceValue, HypothesisState, HypothesisStrength};
use venom_scanner::{
    DecisionActionOrigin, DecisionExecutionStage, DecisionLoopCommand, DecisionStopReason,
    ExclusionReason, HttpBodyCapture, HttpEvidencePolicy, OutcomeStatus, RuntimeBudget,
    RuntimeBudgetDimension, StandardWebDecisionRuntime, StandardWebDecisionRuntimeTurn,
};

/// One hypothesis the runtime maintained. `posterior_basis_points` (0..=10000) and
/// `posterior_percent` are each derived directly from the upstream typed
/// probability — never one from the other — so the text percent matches the legacy
/// single-stage rounding exactly. `value` is the scalar string form of the value
/// (present only when the machine-output safety policy exposes it); `value_kind`
/// names the underlying `EvidenceValue` variant; `value_disposition` records the
/// safety decision. No value ever reaches output through Rust `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HypothesisView {
    pub predicate: String,
    pub value: Option<String>,
    pub value_kind: &'static str,
    pub value_disposition: &'static str,
    pub strength: &'static str,
    pub posterior_basis_points: u16,
    pub posterior_percent: u16,
    pub state: &'static str,
}

impl HypothesisView {
    /// Text display of the value, with a stable placeholder when the safety policy
    /// withheld it or the value is non-scalar/unknown. Never a `Debug` dump.
    pub fn value_display(&self) -> &str {
        self.value
            .as_deref()
            .unwrap_or(match self.value_disposition {
                "redacted" => "(redacted)",
                "non_scalar" => "(non-scalar value)",
                _ => "(unavailable value)",
            })
    }
}

/// A controlled runtime-budget stop as a typed record rather than a human string.
/// `limit`/`observed` units depend on `dimension`: bytes for
/// `response_bytes`/`request_body_bytes`, a count for the request/verification/
/// attempt dimensions, and milliseconds for `wall_time`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeLimitView {
    pub dimension: &'static str,
    pub limit: u64,
    pub observed: u64,
    pub action_id: Option<String>,
}

/// One planning turn: the dependency-safe plan steps the planner selected versus
/// the actions it excluded, each with the exact stable exclusion reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanningView {
    pub eligible: Vec<String>,
    pub excluded: Vec<(String, &'static str)>,
}

/// One verification outcome turn. `conclusive` requires both a verifier-owned
/// Success/rejection and case-level authorization to transition its hypothesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutcomeView {
    pub action_id: String,
    pub status: &'static str,
    pub conclusive: bool,
}

/// One wire dispatch. `stage` (passive/active) and `origin` (planned/bootstrap/…
/// or absent) are kept as separate facts; the text renderer derives a single
/// display label from them, but the machine surface keeps them distinct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchView {
    pub sequence: u64,
    pub action_id: String,
    pub stage: &'static str,
    pub origin: Option<&'static str>,
}

/// Deterministic, transport-truthful summary of one decision-runtime preview run.
///
/// Fields mirror the runtime's own report (evidence, planning, verification
/// outcomes, bounded terminal state, and usage). Every field except `elapsed_ms`
/// is deterministic for an equivalent server, which the end-to-end test relies on.
///
/// The `hypotheses` / `planning` / `dispatched` fields back the `--explain` view;
/// the default `render_summary` does not consume them, so the default output is
/// unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecisionScanSummary {
    pub target: String,
    pub bootstrap_writes: usize,
    pub planning_turns: usize,
    /// Total `Outcome` turns. Not every outcome is a confirmed vulnerability.
    pub verification_outcomes: usize,
    /// Transition-authorized outcomes that map to a verifier-owned hypothesis
    /// state (Success / rejected).
    pub conclusive_outcomes: usize,
    /// Outcomes that do not, including transition-suppressed Success/rejection
    /// and statuses such as Blocked / Unknown / NeedsReview.
    pub inconclusive_outcomes: usize,
    /// Each verification outcome turn, in order.
    pub outcomes: Vec<OutcomeView>,
    /// Stable snake_case terminal command label.
    pub terminal: &'static str,
    /// Stable snake_case stop reason, when the runtime halted with one.
    pub stop_reason: Option<&'static str>,
    pub total_requests: u64,
    pub active_verifications: u64,
    pub response_bytes: u64,
    pub elapsed_ms: u64,
    /// Typed runtime-budget stop for the machine surface.
    pub limit_exceeded: Option<RuntimeLimitView>,
    /// Legacy human sentence for the text surface (the exact `RuntimeLimitExceeded`
    /// Display), preserved so default text output is byte-for-byte unchanged. Never
    /// serialized to JSON.
    pub limit_exceeded_text: Option<String>,
    pub experience_records: usize,
    /// Explain view: hypotheses the runtime maintained, sorted for stability.
    pub hypotheses: Vec<HypothesisView>,
    /// Explain view: every planning turn, in order.
    pub planning: Vec<PlanningView>,
    /// Explain view: each wire dispatch in dispatch order (includes the bootstrap
    /// probe), with stage and origin as separate facts.
    pub dispatched: Vec<DispatchView>,
    /// Explain view: the runtime's explicit unavailable/unsupported executor
    /// routes — semantic actions the planner knows but the current runtime
    /// composition cannot route to an executor. This is a fixed property of the
    /// runtime (its executor registry), independent of the fixture/evidence, and
    /// distinct from a given planning turn's eligibility decision. Sourced from the
    /// runtime's own authority, never inferred from exclusion reasons.
    pub unavailable_routes: Vec<String>,
}

/// Preview budget. `max_response_bytes` is a **cumulative session threshold**, not
/// a per-response cap; the crossing chunk is charged in full. A separate per-probe
/// buffered-body limit is inherited from `HttpEvidencePolicy` (256 KiB by default).
/// Identical to the profile demonstrated by `examples/decision_scan.rs`.
pub(crate) const PREVIEW_MAX_TOTAL_REQUESTS: u32 = 16;
const PREVIEW_MAX_WALL_TIME_SECS: u64 = 60;
const PREVIEW_MAX_CUMULATIVE_RESPONSE_BYTES: u64 = 1024 * 1024;
const PREVIEW_BODY_SAMPLE_CHARS: usize = 8_192;

/// Compose and run the standard deterministic web decision runtime against one
/// authorized origin, returning a truthful summary. No legacy scan phase is
/// invoked; the runtime is bounded by a fixed conservative budget.
pub(crate) async fn run_decision_scan(target: Url) -> Result<DecisionScanSummary, Box<dyn Error>> {
    let policy = HttpEvidencePolicy::for_origin(target.clone())?.with_body_capture(
        HttpBodyCapture::TextSample {
            max_chars: PREVIEW_BODY_SAMPLE_CHARS,
        },
    )?;
    let runtime_budget = RuntimeBudget::default()
        .with_max_total_requests(PREVIEW_MAX_TOTAL_REQUESTS)
        .with_max_wall_time(Duration::from_secs(PREVIEW_MAX_WALL_TIME_SECS))
        .with_max_response_bytes(PREVIEW_MAX_CUMULATIVE_RESPONSE_BYTES);

    // Conservative profile only; API reasoning, payload binding, semantic
    // extraction, and defense-aware planning are all left absent.
    let mut runtime = StandardWebDecisionRuntime::builder(target.clone())
        .http_policy(policy)
        .runtime_budget(runtime_budget)
        .business_value(80)
        .planning_budget(100)
        .risk_limit(40)
        .max_action_cycles(8)
        .build()?;

    let report = runtime.analyze().await?;

    let bootstrap_writes = report
        .bootstrap()
        .map_or(0, |bootstrap| bootstrap.writes().len());

    let mut planning_turns = 0;
    let mut outcomes = Vec::new();
    let mut conclusive_outcomes = 0;
    let mut inconclusive_outcomes = 0;
    for turn in report.turns() {
        match turn {
            StandardWebDecisionRuntimeTurn::Planning(_) => planning_turns += 1,
            StandardWebDecisionRuntimeTurn::Outcome { decision, .. } => {
                let status = decision.verification().outcome().status();
                let conclusive = decision
                    .verification()
                    .case()
                    .applies_hypothesis_transition()
                    && status.hypothesis_state().is_some();
                if conclusive {
                    conclusive_outcomes += 1;
                } else {
                    inconclusive_outcomes += 1;
                }
                outcomes.push(OutcomeView {
                    action_id: decision.verification().outcome().action_id().to_string(),
                    status: outcome_status_code(status),
                    conclusive,
                });
            },
            _ => {},
        }
    }

    // Explain view: every planning turn's eligible/excluded actions with reasons.
    let planning: Vec<PlanningView> = report
        .planning_reports()
        .map(|planning| PlanningView {
            eligible: planning
                .plan()
                .steps()
                .iter()
                .map(|step| step.action_id().to_string())
                .collect(),
            excluded: planning
                .plan()
                .excluded()
                .iter()
                .map(|excluded| {
                    (
                        excluded.action_id().to_string(),
                        exclusion_reason_code(excluded.reason()),
                    )
                })
                .collect(),
        })
        .collect();

    // Explain view: what actually hit the wire, distinct from what was planned.
    // Stage and origin are captured as separate facts; the text renderer derives a
    // display label, while the machine surface keeps them distinct.
    let dispatched: Vec<DispatchView> = report
        .transport()
        .receipts()
        .iter()
        .map(|receipt| DispatchView {
            sequence: receipt.sequence(),
            action_id: receipt.action_id().to_string(),
            stage: stage_code(receipt.stage()),
            origin: origin_code(receipt.origin()),
        })
        .collect();

    // Explain view: hypotheses the runtime maintained, sorted for stability.
    let snapshot = runtime.knowledge().snapshot_for_subject(runtime.subject());
    let mut hypotheses: Vec<HypothesisView> = snapshot
        .hypotheses()
        .iter()
        .map(|hypothesis| {
            let predicate = hypothesis.predicate().dotted();
            let (value_kind, value, value_disposition) =
                hypothesis_value(&predicate, hypothesis.value());
            let (posterior_basis_points, posterior_percent) =
                posterior_pair(hypothesis.posterior().ratio());
            HypothesisView {
                predicate,
                value,
                value_kind,
                value_disposition,
                strength: hypothesis_strength_code(hypothesis.strength()),
                posterior_basis_points,
                posterior_percent,
                state: hypothesis_state_code(hypothesis.state()),
            }
        })
        .collect();
    hypotheses.sort_by(|left, right| {
        (left.predicate.as_str(), left.value.as_deref())
            .cmp(&(right.predicate.as_str(), right.value.as_deref()))
    });

    // Explain view: the runtime's own unavailable executor-route authority. This is
    // fixture-independent (a property of the runtime's executor registry) and is
    // never derived from planning exclusion reasons. `unsupported_actions` is a
    // sorted set, so the inventory is deterministic.
    let unavailable_routes: Vec<String> = runtime.unsupported_actions().iter().cloned().collect();

    let (terminal, stop_reason) = terminal_code(report.terminal());
    let usage = report.usage();
    Ok(DecisionScanSummary {
        target: target.origin().ascii_serialization(),
        bootstrap_writes,
        planning_turns,
        verification_outcomes: outcomes.len(),
        conclusive_outcomes,
        inconclusive_outcomes,
        outcomes,
        terminal,
        stop_reason,
        total_requests: u64::from(usage.total_requests()),
        active_verifications: u64::from(usage.active_verifications()),
        response_bytes: usage.response_bytes(),
        elapsed_ms: usage.elapsed_ms(),
        limit_exceeded: report.limit_exceeded().map(|limit| RuntimeLimitView {
            dimension: dimension_code(limit.dimension()),
            limit: limit.limit(),
            observed: limit.observed(),
            action_id: limit.action_id().map(str::to_owned),
        }),
        // The exact legacy human sentence, for byte-for-byte text output.
        limit_exceeded_text: report.limit_exceeded().map(|limit| limit.to_string()),
        experience_records: runtime.experience().len(),
        hypotheses,
        planning,
        dispatched,
        unavailable_routes,
    })
}

/// Stable snake_case label for a verification outcome status. Never a `Debug`
/// dump; `OutcomeStatus` is `#[non_exhaustive]`, so an unrecognized variant maps
/// to `other`.
fn outcome_status_code(status: OutcomeStatus) -> &'static str {
    match status {
        OutcomeStatus::Success => "success",
        OutcomeStatus::Blocked => "blocked",
        OutcomeStatus::Unknown => "unknown",
        OutcomeStatus::FalsePositive => "false_positive",
        OutcomeStatus::NeedsReview => "needs_review",
        OutcomeStatus::ConfirmedNegative => "confirmed_negative",
        _ => "other",
    }
}

/// Stable snake_case label for a deterministic stop reason.
fn stop_reason_code(reason: &DecisionStopReason) -> &'static str {
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

/// Stable snake_case label for the terminal command, plus its stop reason when it
/// halted. Deliberately does not render the command's `VerificationCase` payload.
fn terminal_code(command: &DecisionLoopCommand) -> (&'static str, Option<&'static str>) {
    match command {
        DecisionLoopCommand::ExecuteAction { .. } => ("execute_action", None),
        DecisionLoopCommand::CollectActiveEvidence { .. } => ("collect_active_evidence", None),
        DecisionLoopCommand::Replan => ("replan", None),
        DecisionLoopCommand::Complete { .. } => ("complete", None),
        DecisionLoopCommand::AwaitHumanReview { .. } => ("await_human_review", None),
        DecisionLoopCommand::Halt { reason } => ("halt", Some(stop_reason_code(reason))),
        _ => ("other", None),
    }
}

/// Stable snake_case label for a hypothesis strength. `HypothesisStrength` is
/// `#[non_exhaustive]`, so an unrecognized variant maps to `other`.
fn hypothesis_strength_code(strength: HypothesisStrength) -> &'static str {
    match strength {
        HypothesisStrength::Weak => "weak",
        HypothesisStrength::Strong => "strong",
        _ => "other",
    }
}

/// Stable snake_case label for a hypothesis lifecycle state. `HypothesisState` is
/// `#[non_exhaustive]`, so an unrecognized variant maps to `other`.
fn hypothesis_state_code(state: HypothesisState) -> &'static str {
    match state {
        HypothesisState::Proposed => "proposed",
        HypothesisState::Supported => "supported",
        HypothesisState::Contradicted => "contradicted",
        HypothesisState::Confirmed => "confirmed",
        HypothesisState::Rejected => "rejected",
        _ => "other",
    }
}

/// Stable snake_case label for why the planner excluded an action. `ExclusionReason`
/// is `#[non_exhaustive]`; the variants' payloads are intentionally not rendered.
fn exclusion_reason_code(reason: &ExclusionReason) -> &'static str {
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

/// Stable snake_case label for a transport stage. `DecisionExecutionStage` is
/// `#[non_exhaustive]`, so an unrecognized variant maps to `other`.
fn stage_code(stage: DecisionExecutionStage) -> &'static str {
    match stage {
        DecisionExecutionStage::Passive => "passive",
        DecisionExecutionStage::Active => "active",
        _ => "other",
    }
}

/// Stable snake_case label for a dispatch's action origin, or `None` when the
/// dispatch carries no passive origin (e.g. an active-verification probe).
/// `DecisionActionOrigin` is `#[non_exhaustive]`, so an unrecognized variant maps
/// to `other`.
fn origin_code(origin: Option<DecisionActionOrigin>) -> Option<&'static str> {
    match origin {
        Some(DecisionActionOrigin::Bootstrap) => Some("bootstrap"),
        Some(DecisionActionOrigin::Planned) => Some("planned"),
        Some(DecisionActionOrigin::Adaptive) => Some("adaptive"),
        Some(DecisionActionOrigin::Retry) => Some("retry"),
        Some(_) => Some("other"),
        None => None,
    }
}

/// Text-only display label for a dispatch, derived from its separate stage and
/// origin facts. An explicit origin is used directly; a dispatch with no passive
/// origin is disambiguated by its stage, so an active-verification probe reads
/// `active_verification` rather than the ambiguous `none`. The machine surface
/// keeps `stage` and `origin` as distinct fields and does not use this label.
fn dispatch_label(dispatch: &DispatchView) -> &'static str {
    match dispatch.origin {
        Some(origin) => origin,
        None if dispatch.stage == "active" => "active_verification",
        None => "unattributed",
    }
}

/// Predicates whose scalar value is safe to expose in output. The standard web
/// reasoning profile produces only these; a value under any other predicate is
/// withheld (fail-closed), so a future rule cannot leak a token, cookie, or other
/// sensitive text through the hypothesis value.
const EXPOSABLE_HYPOTHESIS_PREDICATES: [&str; 5] = [
    "authentication.mechanism",
    "technology.framework",
    "technology.language",
    "technology.ui-framework",
    "technology.web-server",
];

/// Explicit, stable mapping from an `EvidenceValue` to `(value_kind, scalar
/// value)`. Every current variant has a hand-written mapping and the wildcard is a
/// fail-closed fallback for a future `#[non_exhaustive]` variant — no value ever
/// reaches output through Rust `Debug`. A list value has no scalar form, so it maps
/// to `("text_list", None)`; an unknown variant maps to `("other", None)`.
fn evidence_value(value: &EvidenceValue) -> (&'static str, Option<String>) {
    match value {
        EvidenceValue::Text(text) => ("text", Some(text.clone())),
        EvidenceValue::Boolean(flag) => ("boolean", Some(flag.to_string())),
        EvidenceValue::Signed(number) => ("signed", Some(number.to_string())),
        EvidenceValue::Unsigned(number) => ("unsigned", Some(number.to_string())),
        EvidenceValue::TextList(_) => ("text_list", None),
        _ => ("other", None),
    }
}

/// Derives `(posterior_basis_points, posterior_percent)` directly from the
/// probability ratio. Each is a single-stage round of the same source, so the
/// percent never double-rounds through the basis points (which would drift by a
/// point at some boundaries) and matches the legacy text rounding exactly.
fn posterior_pair(ratio: f64) -> (u16, u16) {
    (
        (ratio * 10_000.0).round() as u16,
        (ratio * 100.0).round() as u16,
    )
}

/// Machine-output safety policy for a hypothesis value: returns `(value_kind,
/// exposed value, disposition)`. A scalar value is exposed only under an
/// allowlisted safe predicate; otherwise it is withheld (`redacted`, value
/// `None`). A non-scalar list is `non_scalar`; an unknown value kind is `other`.
/// This is fail-closed: an unknown predicate never exposes its value.
fn hypothesis_value(
    predicate: &str,
    value: &EvidenceValue,
) -> (&'static str, Option<String>, &'static str) {
    let (kind, scalar) = evidence_value(value);
    match scalar {
        Some(text) if EXPOSABLE_HYPOTHESIS_PREDICATES.contains(&predicate) => {
            (kind, Some(text), "exposed")
        },
        Some(_) => (kind, None, "redacted"),
        None if kind == "text_list" => (kind, None, "non_scalar"),
        None => (kind, None, "other"),
    }
}

/// Stable snake_case label for a runtime-budget dimension. `RuntimeBudgetDimension`
/// is `#[non_exhaustive]`, so an unrecognized variant maps to `other`.
fn dimension_code(dimension: RuntimeBudgetDimension) -> &'static str {
    match dimension {
        RuntimeBudgetDimension::TotalRequests => "total_requests",
        RuntimeBudgetDimension::WallTime => "wall_time",
        RuntimeBudgetDimension::ResponseBytes => "response_bytes",
        RuntimeBudgetDimension::RequestBodyBytes => "request_body_bytes",
        RuntimeBudgetDimension::ActiveVerifications => "active_verifications",
        RuntimeBudgetDimension::SameActionAttempts => "same_action_attempts",
        RuntimeBudgetDimension::ConsecutiveNoProgressTurns => "consecutive_no_progress_turns",
        _ => "other",
    }
}

/// Render a [`DecisionScanSummary`] as a concise, honest text report. It never
/// prints "Found N vulnerabilities" and never labels an outcome a vulnerability:
/// the decision runtime produces evidence, planning records, verification
/// outcomes, and a bounded terminal state.
pub(crate) fn render_summary(summary: &DecisionScanSummary) -> String {
    let mut out = String::new();
    out.push_str("== decision-scan (preview) ==\n");
    out.push_str("engine: decision-preview\n");
    out.push_str(&format!("target origin: {}\n", summary.target));
    out.push_str(&format!(
        "evidence: {} bootstrap write(s)\n",
        summary.bootstrap_writes
    ));
    out.push_str(&format!("planning: {} turn(s)\n", summary.planning_turns));
    out.push_str(&format!(
        "verification outcomes: {} (conclusive {}, inconclusive {})\n",
        summary.verification_outcomes, summary.conclusive_outcomes, summary.inconclusive_outcomes,
    ));
    for outcome in &summary.outcomes {
        out.push_str(&format!(
            "  outcome: action={} status={}\n",
            outcome.action_id, outcome.status
        ));
    }
    if summary.outcomes.is_empty() {
        out.push_str("  no verification outcome was produced before the terminal state\n");
    }
    out.push_str(&format!("terminal: {}\n", summary.terminal));
    if let Some(reason) = summary.stop_reason {
        out.push_str(&format!("stop_reason: {reason}\n"));
    }
    if let Some(text) = &summary.limit_exceeded_text {
        // The exact legacy human sentence (the JSON carries the structured object
        // instead). Preserved verbatim so default text output is byte-for-byte
        // unchanged.
        out.push_str(&format!(
            "runtime limit reached (controlled stop): {text}\n"
        ));
    }
    out.push_str(&format!(
        "usage: requests={} active_verifications={} response_bytes={} elapsed_ms={}\n",
        summary.total_requests,
        summary.active_verifications,
        summary.response_bytes,
        summary.elapsed_ms,
    ));
    out.push_str(&format!(
        "experience records: {}\n",
        summary.experience_records
    ));
    out
}

/// Render the full explainable decision chain on top of [`render_summary`] as a
/// readable hierarchy: Executor Routes (the runtime's fixed unavailable routes) ->
/// Hypotheses -> Planning (per turn: Planned, then Excluded with the exact reason)
/// -> Dispatch -> Verification -> Terminal. Like [`render_summary`] it never labels
/// an outcome a vulnerability and never dumps `Debug`; every runtime term is a
/// stable snake_case label. This is presentation only; it reads exactly the same
/// fields the default summary reads.
pub(crate) fn render_explain(summary: &DecisionScanSummary) -> String {
    let mut out = render_summary(summary);
    out.push_str("\n-- explain --\n");

    // Executor Routes: the runtime's fixed executor-registry authority. Only the
    // explicit unavailable/unsupported routes are shown — no "available" list is
    // synthesized by subtracting sets, and this is never inferred from a planning
    // turn's exclusion reasons. It is a distinct concept from planning eligibility:
    // an action can have an available route yet still be excluded this turn, and an
    // unavailable route is reported here independently of any turn's decision.
    out.push_str("Executor Routes\n");
    out.push_str(&format!(
        "  Unavailable ({})\n",
        summary.unavailable_routes.len()
    ));
    for action in &summary.unavailable_routes {
        out.push_str(&format!("    • {action}\n"));
    }

    out.push_str(&format!("Hypotheses ({})\n", summary.hypotheses.len()));
    if summary.hypotheses.is_empty() {
        out.push_str("  (no reasoning rule matched the bootstrap evidence)\n");
    }
    for hypothesis in &summary.hypotheses {
        out.push_str(&format!(
            "  {}={}\n",
            hypothesis.predicate,
            hypothesis.value_display()
        ));
        out.push_str(&format!("    {:<9}: {}\n", "strength", hypothesis.strength));
        out.push_str(&format!(
            "    {:<9}: {}%\n",
            "posterior", hypothesis.posterior_percent
        ));
        out.push_str(&format!("    {:<9}: {}\n", "state", hypothesis.state));
    }

    if summary.planning.is_empty() {
        out.push_str("Planning (none)\n");
    }
    for (index, turn) in summary.planning.iter().enumerate() {
        out.push_str(&format!("Planning (turn {index})\n"));
        // The count in each heading conveys emptiness, so no placeholder line is
        // needed for an empty section.
        out.push_str(&format!("  Planned ({})\n", turn.eligible.len()));
        for action in &turn.eligible {
            out.push_str(&format!("    ✓ {action}\n"));
        }
        // One line per excluded action: `• <action_id> — <reason>`. Order stays
        // deterministic; nothing is grouped, filtered, or hidden.
        out.push_str(&format!("  Excluded ({})\n", turn.excluded.len()));
        for (action, reason) in &turn.excluded {
            out.push_str(&format!("    • {action} — {reason}\n"));
        }
    }

    out.push_str("Dispatch\n");
    if summary.dispatched.is_empty() {
        out.push_str("  (nothing dispatched)\n");
    }
    for dispatch in &summary.dispatched {
        out.push_str(&format!(
            "  {} ({})\n",
            dispatch.action_id,
            dispatch_label(dispatch)
        ));
    }

    out.push_str("Verification\n");
    if summary.outcomes.is_empty() {
        out.push_str("  (no verification outcome before the terminal state)\n");
    }
    for outcome in &summary.outcomes {
        out.push_str(&format!("  {}: {}\n", outcome.action_id, outcome.status));
    }

    out.push_str("Terminal\n");
    match summary.stop_reason {
        Some(reason) => out.push_str(&format!("  {} ({reason})\n", summary.terminal)),
        None => out.push_str(&format!("  {}\n", summary.terminal)),
    }

    out
}

/// Stable schema version for the machine-readable output contract. Bump only on a
/// breaking change to the JSON shape.
pub(crate) const JSON_SCHEMA_VERSION: &str = "decision-scan/v1";

// --- Machine-readable (`--format json`) document -----------------------------
//
// The JSON is built from the same typed `DecisionScanSummary` the text renderer
// reads — never by parsing rendered text. Field groups are independent so a later
// consumer can evolve each. It carries no raw response body, headers, cookies,
// tokens, or evidence identifiers; only stable snake_case labels and numbers.

#[derive(Serialize)]
struct JsonDocument<'a> {
    schema_version: &'static str,
    engine: &'static str,
    target_origin: &'a str,
    summary: JsonSummary,
    executor_routes: JsonExecutorRoutes<'a>,
    hypotheses: Vec<JsonHypothesis<'a>>,
    planning_turns: Vec<JsonPlanningTurn<'a>>,
    dispatches: Vec<JsonDispatch<'a>>,
    verification_outcomes: Vec<JsonOutcome<'a>>,
    terminal: JsonTerminal<'a>,
    usage: JsonUsage,
}

#[derive(Serialize)]
struct JsonSummary {
    bootstrap_evidence_writes: usize,
    planning_turns: usize,
    verification_outcomes: usize,
    conclusive_outcomes: usize,
    inconclusive_outcomes: usize,
    experience_records: usize,
}

#[derive(Serialize)]
struct JsonExecutorRoutes<'a> {
    /// The runtime's explicit unavailable/unsupported executor routes. No
    /// `available` list is synthesized by subtracting sets.
    unavailable: &'a [String],
}

#[derive(Serialize)]
struct JsonHypothesis<'a> {
    predicate: &'a str,
    /// Scalar string form of the value, or `null` when withheld by the safety
    /// policy or when the kind is non-scalar/unknown.
    value: Option<&'a str>,
    /// The `EvidenceValue` variant: `text` / `boolean` / `signed` / `unsigned` /
    /// `text_list` / `other`.
    value_kind: &'a str,
    /// The machine-output safety decision: `exposed` / `redacted` / `non_scalar` /
    /// `other`. `value` is non-null only when `exposed`.
    value_disposition: &'a str,
    strength: &'a str,
    posterior_basis_points: u16,
    state: &'a str,
}

#[derive(Serialize)]
struct JsonPlanningTurn<'a> {
    turn: usize,
    planned: &'a [String],
    excluded: Vec<JsonExcluded<'a>>,
}

#[derive(Serialize)]
struct JsonExcluded<'a> {
    action_id: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct JsonDispatch<'a> {
    sequence: u64,
    action_id: &'a str,
    /// `passive` or `active` — kept separate from `origin` on purpose.
    stage: &'a str,
    /// The passive action origin, or `null` for a dispatch that carries none
    /// (e.g. an active-verification probe). A consumer infers "active verification"
    /// from `stage == "active"` and `origin == null`.
    origin: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonOutcome<'a> {
    action_id: &'a str,
    status: &'a str,
    conclusive: bool,
}

#[derive(Serialize)]
struct JsonTerminal<'a> {
    command: &'a str,
    stop_reason: Option<&'a str>,
    /// A structured record when a runtime budget bound the run, else `null`.
    runtime_limit: Option<JsonRuntimeLimit<'a>>,
}

#[derive(Serialize)]
struct JsonRuntimeLimit<'a> {
    dimension: &'a str,
    limit: u64,
    observed: u64,
    action_id: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonUsage {
    total_requests: u64,
    active_verifications: u64,
    response_bytes: u64,
    elapsed_ms: u64,
}

/// Render a [`DecisionScanSummary`] as the versioned `decision-scan/v1` JSON
/// document. Built from the typed summary, never from rendered text; carries no
/// raw bodies, headers, credentials, or evidence identifiers.
pub(crate) fn render_json(summary: &DecisionScanSummary) -> Result<String, serde_json::Error> {
    let document = JsonDocument {
        schema_version: JSON_SCHEMA_VERSION,
        engine: "decision-preview",
        target_origin: &summary.target,
        summary: JsonSummary {
            bootstrap_evidence_writes: summary.bootstrap_writes,
            planning_turns: summary.planning_turns,
            verification_outcomes: summary.verification_outcomes,
            conclusive_outcomes: summary.conclusive_outcomes,
            inconclusive_outcomes: summary.inconclusive_outcomes,
            experience_records: summary.experience_records,
        },
        executor_routes: JsonExecutorRoutes {
            unavailable: &summary.unavailable_routes,
        },
        hypotheses: summary
            .hypotheses
            .iter()
            .map(|hypothesis| JsonHypothesis {
                predicate: &hypothesis.predicate,
                value: hypothesis.value.as_deref(),
                value_kind: hypothesis.value_kind,
                value_disposition: hypothesis.value_disposition,
                strength: hypothesis.strength,
                posterior_basis_points: hypothesis.posterior_basis_points,
                state: hypothesis.state,
            })
            .collect(),
        planning_turns: summary
            .planning
            .iter()
            .enumerate()
            .map(|(turn, plan)| JsonPlanningTurn {
                turn,
                planned: &plan.eligible,
                excluded: plan
                    .excluded
                    .iter()
                    .map(|(action_id, reason)| JsonExcluded { action_id, reason })
                    .collect(),
            })
            .collect(),
        dispatches: summary
            .dispatched
            .iter()
            .map(|dispatch| JsonDispatch {
                sequence: dispatch.sequence,
                action_id: &dispatch.action_id,
                stage: dispatch.stage,
                origin: dispatch.origin,
            })
            .collect(),
        verification_outcomes: summary
            .outcomes
            .iter()
            .map(|outcome| JsonOutcome {
                action_id: &outcome.action_id,
                status: outcome.status,
                conclusive: outcome.conclusive,
            })
            .collect(),
        terminal: JsonTerminal {
            command: summary.terminal,
            stop_reason: summary.stop_reason,
            runtime_limit: summary
                .limit_exceeded
                .as_ref()
                .map(|limit| JsonRuntimeLimit {
                    dimension: limit.dimension,
                    limit: limit.limit,
                    observed: limit.observed,
                    action_id: limit.action_id.as_deref(),
                }),
        },
        usage: JsonUsage {
            total_requests: summary.total_requests,
            active_verifications: summary.active_verifications,
            response_bytes: summary.response_bytes,
            elapsed_ms: summary.elapsed_ms,
        },
    };
    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use venom_core::EvidenceValue;

    use super::{hypothesis_value, posterior_pair};

    #[test]
    fn posterior_percent_uses_single_stage_rounding() {
        // A ratio where two-stage rounding (percent from basis points) would
        // disagree with the legacy single-stage round of the ratio.
        let (basis_points, percent) = posterior_pair(0.944_96);
        assert_eq!(basis_points, 9450);
        assert_eq!(
            percent, 94,
            "percent must round the ratio, not the basis points"
        );
        // Double-rounding the basis points would wrongly yield 95.
        assert_ne!((f64::from(basis_points) / 100.0).round() as u16, percent);
    }

    #[test]
    fn known_safe_hypothesis_values_remain_exposed() {
        let (kind, value, disposition) = hypothesis_value(
            "authentication.mechanism",
            &EvidenceValue::Text("http-basic".to_owned()),
        );
        assert_eq!(kind, "text");
        assert_eq!(value.as_deref(), Some("http-basic"));
        assert_eq!(disposition, "exposed");
    }

    #[test]
    fn unknown_text_hypothesis_is_redacted() {
        // A text value under a predicate outside the allowlist is withheld.
        let (kind, value, disposition) = hypothesis_value(
            "secret.session-token",
            &EvidenceValue::Text("s3cr3t-value".to_owned()),
        );
        assert_eq!(kind, "text");
        assert_eq!(value, None, "the value must be withheld");
        assert_eq!(disposition, "redacted");
    }

    #[test]
    fn credential_like_hypothesis_never_reaches_output() {
        // Even a cookie/token-looking value under an unknown predicate never leaves
        // the boundary: no exposed value carries the secret text.
        let secret = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let (_, value, disposition) =
            hypothesis_value("http.cookie.value", &EvidenceValue::Text(secret.to_owned()));
        assert_eq!(disposition, "redacted");
        assert!(value.is_none());
        assert_ne!(value.as_deref(), Some(secret));
    }

    #[test]
    fn non_scalar_and_unknown_value_kinds_are_withheld() {
        let (kind, value, disposition) = hypothesis_value(
            "technology.framework",
            &EvidenceValue::TextList(vec!["a".to_owned(), "b".to_owned()]),
        );
        assert_eq!(kind, "text_list");
        assert_eq!(value, None);
        assert_eq!(disposition, "non_scalar");
    }
}
