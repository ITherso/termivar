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

use url::Url;
use venom_core::{EvidenceValue, HypothesisState, HypothesisStrength};
use venom_scanner::{
    DecisionActionOrigin, DecisionLoopCommand, DecisionStopReason, ExclusionReason,
    HttpBodyCapture, HttpEvidencePolicy, OutcomeStatus, RuntimeBudget, StandardWebDecisionRuntime,
    StandardWebDecisionRuntimeTurn,
};

/// One hypothesis the runtime maintained, rendered with stable labels for the
/// `--explain` view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HypothesisView {
    pub predicate: String,
    pub value: String,
    pub strength: &'static str,
    pub posterior_percent: u8,
    pub state: &'static str,
}

/// One planning turn: the dependency-safe plan steps the planner selected versus
/// the actions it excluded, each with the exact stable exclusion reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanningView {
    pub eligible: Vec<String>,
    pub excluded: Vec<(String, &'static str)>,
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
    /// Outcomes that map to a verifier-owned hypothesis state (Success / rejected).
    pub conclusive_outcomes: usize,
    /// Outcomes that do not (Blocked / Unknown / NeedsReview).
    pub inconclusive_outcomes: usize,
    /// `(action_id, stable status label)` for each outcome turn, in order.
    pub outcomes: Vec<(String, &'static str)>,
    /// Stable snake_case terminal command label.
    pub terminal: &'static str,
    /// Stable snake_case stop reason, when the runtime halted with one.
    pub stop_reason: Option<&'static str>,
    pub total_requests: u64,
    pub active_verifications: u64,
    pub response_bytes: u64,
    pub elapsed_ms: u64,
    pub limit_exceeded: Option<String>,
    pub experience_records: usize,
    /// Explain view: hypotheses the runtime maintained, sorted for stability.
    pub hypotheses: Vec<HypothesisView>,
    /// Explain view: every planning turn, in order.
    pub planning: Vec<PlanningView>,
    /// Explain view: `(action_id, stable origin label)` for each wire dispatch, in
    /// dispatch order (includes the bootstrap probe).
    pub dispatched: Vec<(String, &'static str)>,
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
                if status.hypothesis_state().is_some() {
                    conclusive_outcomes += 1;
                } else {
                    inconclusive_outcomes += 1;
                }
                outcomes.push((
                    decision.verification().outcome().action_id().to_string(),
                    outcome_status_code(status),
                ));
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
    let dispatched: Vec<(String, &'static str)> = report
        .transport()
        .receipts()
        .iter()
        .map(|receipt| {
            (
                receipt.action_id().to_string(),
                origin_code(receipt.origin()),
            )
        })
        .collect();

    // Explain view: hypotheses the runtime maintained, sorted for stability.
    let snapshot = runtime.knowledge().snapshot_for_subject(runtime.subject());
    let mut hypotheses: Vec<HypothesisView> = snapshot
        .hypotheses()
        .iter()
        .map(|hypothesis| HypothesisView {
            predicate: hypothesis.predicate().dotted(),
            value: value_text(hypothesis.value()),
            strength: hypothesis_strength_code(hypothesis.strength()),
            posterior_percent: (hypothesis.posterior().ratio() * 100.0).round() as u8,
            state: hypothesis_state_code(hypothesis.state()),
        })
        .collect();
    hypotheses.sort_by(|left, right| {
        (left.predicate.as_str(), left.value.as_str())
            .cmp(&(right.predicate.as_str(), right.value.as_str()))
    });

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
        limit_exceeded: report.limit_exceeded().map(|limit| limit.to_string()),
        experience_records: runtime.experience().len(),
        hypotheses,
        planning,
        dispatched,
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

/// Stable snake_case label for a wire dispatch's origin. `DecisionActionOrigin` is
/// `#[non_exhaustive]`, so an unrecognized variant maps to `other`.
fn origin_code(origin: Option<DecisionActionOrigin>) -> &'static str {
    match origin {
        Some(DecisionActionOrigin::Bootstrap) => "bootstrap",
        Some(DecisionActionOrigin::Planned) => "planned",
        Some(DecisionActionOrigin::Retry) => "retry",
        Some(_) => "other",
        None => "none",
    }
}

/// Renders a hypothesis value for display. Standard web hypotheses are textual;
/// any non-text value is rendered as a stable placeholder rather than a `Debug`
/// dump.
fn value_text(value: &EvidenceValue) -> String {
    match value {
        EvidenceValue::Text(text) => text.clone(),
        _ => "(non-text value)".to_string(),
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
    for (action_id, status) in &summary.outcomes {
        out.push_str(&format!("  outcome: action={action_id} status={status}\n"));
    }
    if summary.outcomes.is_empty() {
        out.push_str("  no verification outcome was produced before the terminal state\n");
    }
    out.push_str(&format!("terminal: {}\n", summary.terminal));
    if let Some(reason) = summary.stop_reason {
        out.push_str(&format!("stop_reason: {reason}\n"));
    }
    if let Some(limit) = &summary.limit_exceeded {
        out.push_str(&format!(
            "runtime limit reached (controlled stop): {limit}\n"
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
/// readable hierarchy: Hypotheses -> Planning (per turn: Planned, then Excluded
/// with the exact reason) -> Dispatch -> Verification -> Terminal. Like
/// [`render_summary`] it never labels an outcome a vulnerability and never dumps
/// `Debug`; every runtime term is a stable snake_case label. This is presentation
/// only; it reads exactly the same fields the default summary reads.
pub(crate) fn render_explain(summary: &DecisionScanSummary) -> String {
    let mut out = render_summary(summary);
    out.push_str("\n-- explain --\n");

    out.push_str(&format!("Hypotheses ({})\n", summary.hypotheses.len()));
    if summary.hypotheses.is_empty() {
        out.push_str("  (none — no reasoning rule matched the bootstrap evidence)\n");
    }
    for hypothesis in &summary.hypotheses {
        out.push_str(&format!(
            "  {}={}\n",
            hypothesis.predicate, hypothesis.value
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
        out.push_str("  Planned\n");
        if turn.eligible.is_empty() {
            out.push_str("    (none)\n");
        }
        for action in &turn.eligible {
            out.push_str(&format!("    ✓ {action}\n"));
        }
        out.push_str("  Excluded\n");
        if turn.excluded.is_empty() {
            out.push_str("    (none)\n");
        }
        for (action, reason) in &turn.excluded {
            out.push_str(&format!("    • {action}\n"));
            out.push_str(&format!("      reason: {reason}\n"));
        }
    }

    out.push_str("Dispatch\n");
    if summary.dispatched.is_empty() {
        out.push_str("  (none)\n");
    }
    for (action, origin) in &summary.dispatched {
        out.push_str(&format!("  {action} ({origin})\n"));
    }

    out.push_str("Verification\n");
    if summary.outcomes.is_empty() {
        out.push_str("  (no verification outcome before the terminal state)\n");
    }
    for (action, status) in &summary.outcomes {
        out.push_str(&format!("  {action}: {status}\n"));
    }

    out.push_str("Terminal\n");
    match summary.stop_reason {
        Some(reason) => out.push_str(&format!("  {} ({reason})\n", summary.terminal)),
        None => out.push_str(&format!("  {}\n", summary.terminal)),
    }

    out
}
