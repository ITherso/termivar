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
//! reasoning. It propagates errors instead of panicking.

use std::error::Error;
use std::time::Duration;

use url::Url;
use venom_scanner::{
    HttpBodyCapture, HttpEvidencePolicy, RuntimeBudget, StandardWebDecisionRuntime,
    StandardWebDecisionRuntimeTurn,
};

/// Deterministic, transport-truthful summary of one decision-runtime preview run.
///
/// Fields mirror the runtime's own report (evidence, planning, verified outcomes,
/// bounded terminal state, and usage). Every field except `elapsed_ms` is
/// deterministic for an equivalent server, which the end-to-end test relies on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecisionScanSummary {
    pub target: String,
    pub bootstrap_writes: usize,
    pub planning_turns: usize,
    pub verified_outcomes: usize,
    /// `(action_id, verification_status)` for each outcome turn, in order.
    pub outcomes: Vec<(String, String)>,
    pub terminal: String,
    pub total_requests: u64,
    pub active_verifications: u64,
    pub response_bytes: u64,
    pub elapsed_ms: u64,
    pub limit_exceeded: Option<String>,
    pub experience_records: usize,
}

/// The conservative preview budget: at most 16 requests, 60s wall time, 1 MiB per
/// response. Identical to the profile demonstrated by `examples/decision_scan.rs`.
pub(crate) const PREVIEW_MAX_TOTAL_REQUESTS: u32 = 16;
const PREVIEW_MAX_WALL_TIME_SECS: u64 = 60;
const PREVIEW_MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
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
        .with_max_response_bytes(PREVIEW_MAX_RESPONSE_BYTES);

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
    for turn in report.turns() {
        match turn {
            StandardWebDecisionRuntimeTurn::Planning(_) => planning_turns += 1,
            StandardWebDecisionRuntimeTurn::Outcome { decision, .. } => {
                let outcome = decision.verification().outcome();
                outcomes.push((
                    outcome.action_id().to_string(),
                    format!("{:?}", outcome.status()),
                ));
            },
            _ => {},
        }
    }

    let usage = report.usage();
    Ok(DecisionScanSummary {
        target: target.origin().ascii_serialization(),
        bootstrap_writes,
        planning_turns,
        verified_outcomes: outcomes.len(),
        outcomes,
        terminal: format!("{:?}", report.terminal()),
        total_requests: u64::from(usage.total_requests()),
        active_verifications: u64::from(usage.active_verifications()),
        response_bytes: usage.response_bytes(),
        elapsed_ms: usage.elapsed_ms(),
        limit_exceeded: report.limit_exceeded().map(|limit| limit.to_string()),
        experience_records: runtime.experience().len(),
    })
}

/// Render a [`DecisionScanSummary`] as a concise, honest text report. It never
/// prints "Found N vulnerabilities": the decision runtime produces evidence,
/// planning records, verified outcomes, and a bounded terminal state.
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
        "verified outcomes: {}\n",
        summary.verified_outcomes
    ));
    for (action_id, status) in &summary.outcomes {
        out.push_str(&format!("  outcome: action={action_id} status={status}\n"));
    }
    if summary.outcomes.is_empty() {
        out.push_str("  (no verified outcome; the run reached a bounded terminal state)\n");
    }
    out.push_str(&format!("terminal: {}\n", summary.terminal));
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
