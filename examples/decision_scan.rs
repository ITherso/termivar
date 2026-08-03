//! Run the standard deterministic web decision runtime.
//!
//! Use only against a target you own or are explicitly authorized to test:
//! `cargo run -p venom-examples --bin decision_scan -- https://target.example/`

use std::{error::Error, time::Duration};

use url::Url;
use venom_scanner::{
    HttpBodyCapture, HttpEvidencePolicy, RuntimeBudget, StandardWebDecisionRuntime,
    StandardWebDecisionRuntimeTurn,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(raw_target) = std::env::args_os().nth(1) else {
        eprintln!(
            "usage: cargo run -p venom-examples --bin decision_scan -- <authorized-http-url>"
        );
        return Ok(());
    };
    let target = Url::parse(&raw_target.to_string_lossy())?;
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
