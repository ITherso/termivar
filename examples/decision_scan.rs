//! Run the standard deterministic web decision runtime.
//!
//! Use only against a target you own or are explicitly authorized to test:
//! `cargo run -p venom-examples --bin decision_scan -- https://target.example/`

use std::{env, error::Error};

use url::Url;
use venom_scanner::{
    HttpBodyCapture, HttpEvidencePolicy, StandardWebDecisionRuntime, StandardWebDecisionRuntimeTurn,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(raw_target) = env::args().nth(1) else {
        eprintln!(
            "usage: cargo run -p venom-examples --bin decision_scan -- <authorized-http-url>"
        );
        return Ok(());
    };
    let target = Url::parse(&raw_target)?;
    let policy = HttpEvidencePolicy::for_origin(target.clone())?
        .with_body_capture(HttpBodyCapture::TextSample { max_chars: 8_192 })?;
    let mut runtime = StandardWebDecisionRuntime::builder(target)
        .http_policy(policy)
        .business_value(80)
        .planning_budget(100)
        .risk_limit(40)
        .max_action_cycles(8)
        .build()?;

    let report = runtime.analyze().await?;
    println!(
        "bootstrap: {} evidence writes",
        report.bootstrap().writes().len()
    );

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
    println!("experience records: {}", runtime.experience().len());
    Ok(())
}
