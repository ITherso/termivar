//! Run the standard deterministic web decision runtime.
//!
//! ## Runtime scope
//!
//! - **Build:** example binary (`termivar-examples`).
//! - **Execution:** Surface B host — composes `StandardWebDecisionRuntime` with a
//!   `RuntimeBudget`.
//! - **Default `termivar scan`:** yes; this is a small library-host equivalent of
//!   the canonical deterministic command.
//! - **Support:** implemented and tested (reference host for the deterministic runtime).
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Use only against a target you own or are explicitly authorized to test:
//! `cargo run -p termivar-examples --bin decision_scan -- https://target.example/`

use std::{error::Error, time::Duration};

use clap::Parser;
use termivar_scanner::{
    HttpBodyCapture, HttpEvidencePolicy, RuntimeBudget, StandardWebDecisionRuntime,
    StandardWebDecisionRuntimeTurn,
};
use url::Url;

/// Run the standard deterministic web decision runtime against an authorized target.
#[derive(Debug, Parser)]
#[command(
    name = "decision_scan",
    about = "Run the standard deterministic web decision runtime against an authorized target"
)]
struct Cli {
    /// Authorized HTTP(S) target URL. Only scan targets you own or are explicitly
    /// authorized to test.
    target: Url,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let target = cli.target;
    let policy = HttpEvidencePolicy::for_origin(target.clone())?
        .with_body_capture(HttpBodyCapture::TextSample { max_chars: 8_192 })?;
    let runtime_budget = RuntimeBudget::default()
        .with_max_total_requests(16)
        .with_max_wall_time(Duration::from_secs(60))
        .with_max_response_bytes(1024 * 1024);
    let mut runtime = StandardWebDecisionRuntime::builder(target)
        .http_policy(policy)
        .runtime_budget(runtime_budget)
        .business_value(80)
        .planning_budget(100)
        .risk_limit(40)
        .max_action_cycles(8)
        .build()?;

    let report = runtime.analyze().await?;
    match report.bootstrap() {
        Some(bootstrap) => println!("bootstrap: {} evidence writes", bootstrap.writes().len()),
        None => println!("bootstrap: stopped before evidence was committed"),
    }

    for turn in report.turns() {
        match turn {
            StandardWebDecisionRuntimeTurn::Planning(planning) => {
                let selected: Vec<_> = planning
                    .plan()
                    .steps()
                    .iter()
                    .map(|step| step.action_id())
                    .collect();
                println!(
                    "planning: selected={selected:?} excluded={}",
                    planning.plan().excluded().len()
                );
            },
            StandardWebDecisionRuntimeTurn::Outcome { evidence, decision } => {
                let outcome = decision.verification().outcome();
                println!(
                    "outcome: action={} executor={} status={:?}",
                    outcome.action_id(),
                    evidence.executor_id(),
                    outcome.status()
                );
            },
            _ => {},
        }
    }

    println!("terminal: {:?}", report.terminal());
    println!(
        "usage: requests={} active={} response_bytes={} elapsed_ms={}",
        report.usage().total_requests(),
        report.usage().active_verifications(),
        report.usage().response_bytes(),
        report.usage().elapsed_ms(),
    );
    if let Some(limit) = report.limit_exceeded() {
        println!("runtime limit: {limit}");
    }
    println!("experience records: {}", runtime.experience().len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_authorized_target_url() {
        let cli = Cli::try_parse_from(["decision_scan", "https://target.example/"]).unwrap();
        assert_eq!(cli.target.as_str(), "https://target.example/");
    }

    #[test]
    fn rejects_a_non_url_argument() {
        assert!(Cli::try_parse_from(["decision_scan", "not a url"]).is_err());
    }

    #[test]
    fn requires_a_target_argument() {
        assert!(Cli::try_parse_from(["decision_scan"]).is_err());
    }
}
