//! Process-level command-line composition for Venom's scanner, API, and proxy adapters.
//!
//! ## Runtime scope
//!
//! - **Build:** `venom-cli` binary crate.
//! - **Execution:** hosts four commands — `scan` runs Surface A (legacy phase
//!   pipeline), `decision-scan` is an explicit Surface B preview of the
//!   deterministic `StandardWebDecisionRuntime`, while `api` and `proxy` are
//!   separate explicit adapter commands (none of them share the scan pipeline).
//! - **Default `venom scan`:** yes for the `scan` command; `decision-scan`,
//!   `api`, and `proxy` are separate.
//! - **Support:** `scan` is legacy alpha; `decision-scan` previews an
//!   implemented-and-tested runtime (not the default scanner); the `api` listener
//!   is unsupported and the `proxy` is an experimental TCP relay (see their crates).
//!
//! See `docs/internals/runtime-map.md`.

mod decision_scan;

use clap::{Parser, Subcommand};
use url::Url;
use venom_proxy::ProxyServer;
use venom_scanner::{phases, ScanContext, ScanRunner};

const LEGACY_DIRECTORY_FUZZ_WARNING: &str = "[WARNING] Legacy directory fuzzing is enabled. This brute-force phase uses direct network I/O outside RuntimeBudget; run it only against explicitly authorized targets.";
const LEGACY_SCAN_RUNTIME_WARNING: &str = "[WARNING] The ordered CLI phase pipeline is legacy direct I/O outside StandardWebDecisionRuntime and RuntimeBudget. Use it only against an explicitly authorized exact origin.";
const DECISION_SCAN_PREVIEW_WARNING: &str = "[PREVIEW] Running the deterministic decision runtime. This is not the default `venom scan` engine. Use only against an exact origin you own or are explicitly authorized to test.";

fn scan_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[derive(Parser)]
#[command(name = "venom")]
#[command(about = "Venom - modular web security testing framework", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the scanning engine
    Scan {
        target: String,
        /// Opt in to the legacy wordlist-based directory brute-force phase.
        #[arg(long)]
        legacy_directory_fuzz: bool,
    },
    /// Preview the deterministic decision runtime against an authorized origin.
    ///
    /// This is not the default `venom scan` engine; it exposes the existing
    /// StandardWebDecisionRuntime through a bounded, conservative profile.
    DecisionScan {
        /// Authorized HTTP(S) target origin. Only scan targets you own or may test.
        target: Url,
        /// Print the full explainable decision chain: hypotheses, planned and
        /// excluded actions (with the exact reason), dispatched actions, and
        /// verification outcomes. Off by default; the default output is unchanged.
        #[arg(long)]
        explain: bool,
    },
    /// Start the API server
    Api {
        #[arg(long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
    /// Start the proxy server
    Proxy {
        #[arg(long, default_value = "127.0.0.1:8081")]
        addr: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Scan {
            target,
            legacy_directory_fuzz,
        }) => {
            eprintln!("{LEGACY_SCAN_RUNTIME_WARNING}");
            let target_url = Url::parse(&target)?;
            let client = scan_http_client()?;
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

            let ctx = ScanContext::new(target_url, client, tx);

            let mut runner = ScanRunner::new();
            runner.register_phase(Box::new(phases::ReconPhase));
            runner.register_phase(Box::new(phases::CrawlPhase));
            if legacy_directory_fuzz {
                eprintln!("{LEGACY_DIRECTORY_FUZZ_WARNING}");
                runner.register_phase(Box::new(phases::DirectoryFuzzer::with_default_wordlist(20)));
            }
            runner.register_phase(Box::new(
                phases::ParameterDiscoverer::with_default_wordlist(20),
            ));
            runner.register_phase(Box::new(phases::SqliScanner));
            runner.register_phase(Box::new(phases::XssScanner));
            runner.register_phase(Box::new(phases::SstiScanner));
            runner.register_phase(Box::new(phases::LfiXxeScanner::new()));
            runner.register_phase(Box::new(phases::SsrfScanner::new()));

            let scan_task = tokio::spawn(async move { runner.run_pipeline(ctx).await });

            let log_task = tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    println!("[LOG] {}", msg);
                }
            });

            let findings = scan_task.await.unwrap_or_default();
            println!(
                "\n[*] Scan completed. Found {} vulnerabilities.",
                findings.len()
            );

            for finding in findings {
                println!(
                    "\n[{}] {} ({})\n  Description: {}\n  Evidence: {}",
                    finding.severity,
                    finding.description,
                    finding.module_name,
                    finding.description,
                    finding.evidence
                );
            }

            log_task.abort();
        },
        Some(Commands::DecisionScan { target, explain }) => {
            eprintln!("{DECISION_SCAN_PREVIEW_WARNING}");
            let summary = decision_scan::run_decision_scan(target).await?;
            let rendered = if explain {
                decision_scan::render_explain(&summary)
            } else {
                decision_scan::render_summary(&summary)
            };
            print!("{rendered}");
        },
        Some(Commands::Api { addr }) => {
            venom_api::start_api(&addr).await?;
        },
        Some(Commands::Proxy { addr }) => {
            let parts: Vec<&str> = addr.split(':').collect();
            if parts.len() == 2 {
                let proxy = ProxyServer::new(parts[0].to_string(), parts[1].parse()?);
                proxy.start().await?;
            }
        },
        None => {
            println!("Venom v{}", env!("CARGO_PKG_VERSION"));
            println!("Use --help for more information");
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn scan_does_not_enable_legacy_directory_fuzz_by_default() {
        let cli = Cli::try_parse_from(["venom", "scan", "https://example.test"]).unwrap();

        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                legacy_directory_fuzz: false,
                ..
            })
        ));
        assert!(LEGACY_SCAN_RUNTIME_WARNING.contains("outside StandardWebDecisionRuntime"));
        assert!(LEGACY_SCAN_RUNTIME_WARNING.contains("exact origin"));
    }

    #[test]
    fn scan_accepts_explicit_legacy_directory_fuzz_opt_in() {
        let cli = Cli::try_parse_from([
            "venom",
            "scan",
            "https://example.test",
            "--legacy-directory-fuzz",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Some(Commands::Scan {
                legacy_directory_fuzz: true,
                ..
            })
        ));
        assert!(LEGACY_DIRECTORY_FUZZ_WARNING.contains("outside RuntimeBudget"));
        assert!(LEGACY_DIRECTORY_FUZZ_WARNING.contains("explicitly authorized targets"));
    }

    #[tokio::test]
    async fn scan_client_never_follows_cross_origin_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/outside\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let response = scan_http_client()
            .unwrap()
            .get(format!("http://{address}/authorized"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        server.await.unwrap();
    }

    // --- command selection (legacy command invariance) -----------------------

    #[test]
    fn scan_still_selects_the_legacy_command() {
        let cli = Cli::try_parse_from(["venom", "scan", "https://example.test"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Scan { .. })));
    }

    #[test]
    fn decision_scan_selects_the_preview_command() {
        let cli = Cli::try_parse_from(["venom", "decision-scan", "https://example.test/"]).unwrap();
        match cli.command {
            Some(Commands::DecisionScan { target, explain }) => {
                assert_eq!(target.as_str(), "https://example.test/");
                assert!(
                    !explain,
                    "explain must default off so the default output is unchanged"
                );
            },
            _ => panic!("expected the decision-scan command"),
        }
        assert!(DECISION_SCAN_PREVIEW_WARNING.contains("not the default"));
    }

    #[test]
    fn decision_scan_accepts_the_explain_flag() {
        let cli = Cli::try_parse_from([
            "venom",
            "decision-scan",
            "--explain",
            "https://example.test/",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::DecisionScan { explain, .. }) => {
                assert!(explain, "--explain must enable the explain view");
            },
            _ => panic!("expected the decision-scan command"),
        }
    }

    #[test]
    fn decision_scan_requires_a_target() {
        assert!(Cli::try_parse_from(["venom", "decision-scan"]).is_err());
    }

    #[test]
    fn decision_scan_rejects_a_malformed_url() {
        assert!(Cli::try_parse_from(["venom", "decision-scan", "not a url"]).is_err());
    }

    #[test]
    fn api_and_proxy_parsing_remain_unchanged() {
        let api = Cli::try_parse_from(["venom", "api"]).unwrap();
        assert!(matches!(api.command, Some(Commands::Api { .. })));
        let proxy = Cli::try_parse_from(["venom", "proxy"]).unwrap();
        assert!(matches!(proxy.command, Some(Commands::Proxy { .. })));
    }

    // --- offline end-to-end preview run --------------------------------------

    /// Serve one fixed HTTP/1.1 response to every connection until aborted.
    async fn serve_static() -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), handle)
    }

    #[tokio::test]
    async fn decision_scan_preview_runs_bounded_against_a_local_server() {
        let (target, server) = serve_static().await;

        let summary = decision_scan::run_decision_scan(target.clone())
            .await
            .expect("decision preview should complete against the local server");

        // Bootstrap committed evidence, and the run was bounded by the budget.
        assert!(
            summary.bootstrap_writes >= 1,
            "expected at least one bootstrap evidence write"
        );
        assert!(
            summary.total_requests > 0,
            "the runtime should make requests"
        );
        assert!(
            summary.total_requests <= u64::from(decision_scan::PREVIEW_MAX_TOTAL_REQUESTS),
            "the runtime must respect the 16-request budget"
        );
        // The summary retains the authorized input origin. Exact-origin request
        // enforcement (scheme, credentials, allowed origin) is covered by the
        // existing HttpEvidencePolicy/broker tests, not re-proved here.
        assert_eq!(summary.target, target.origin().ascii_serialization());
        // A terminal (bounded stop) state is always reported.
        assert!(!summary.terminal.is_empty());

        server.abort();
    }

    #[tokio::test]
    async fn decision_scan_preview_is_deterministic_excluding_elapsed_time() {
        // Two fresh runtimes against the *same* listener and target: only the
        // wall-clock (elapsed) field may differ.
        let (target, server) = serve_static().await;
        let mut first = decision_scan::run_decision_scan(target.clone())
            .await
            .unwrap();
        let mut second = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        first.elapsed_ms = 0;
        second.elapsed_ms = 0;
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn decision_scan_rejects_non_http_scheme_before_dispatch() {
        // The HttpEvidencePolicy contract rejects a non-HTTP(S) origin; no network
        // dispatch occurs.
        let target = Url::parse("ftp://example.test/").unwrap();
        let result = decision_scan::run_decision_scan(target).await;
        assert!(
            result.is_err(),
            "a non-http(s) scheme must be rejected before any dispatch"
        );
    }

    fn sample_summary() -> decision_scan::DecisionScanSummary {
        decision_scan::DecisionScanSummary {
            target: "https://example.test".to_string(),
            bootstrap_writes: 1,
            planning_turns: 2,
            verification_outcomes: 1,
            conclusive_outcomes: 0,
            inconclusive_outcomes: 1,
            outcomes: vec![("web.action.probe".to_string(), "unknown")],
            terminal: "halt",
            stop_reason: Some("no_eligible_action"),
            total_requests: 3,
            active_verifications: 1,
            response_bytes: 42,
            elapsed_ms: 5,
            limit_exceeded: None,
            experience_records: 1,
            hypotheses: vec![decision_scan::HypothesisView {
                predicate: "technology.web-server".to_string(),
                value: "nginx".to_string(),
                strength: "weak",
                posterior_percent: 89,
                state: "supported",
            }],
            planning: vec![decision_scan::PlanningView {
                eligible: Vec::new(),
                excluded: vec![(
                    "web.action.nginx.configuration".to_string(),
                    "policy_suppressed",
                )],
            }],
            dispatched: vec![("web.action.bootstrap".to_string(), "bootstrap")],
        }
    }

    #[test]
    fn render_summary_is_stable_and_never_labels_vulnerabilities() {
        let rendered = decision_scan::render_summary(&sample_summary());
        assert!(rendered.contains("engine: decision-preview"));
        assert!(rendered.contains("target origin: https://example.test"));
        assert!(rendered.contains("verification outcomes: 1"));
        assert!(rendered.contains("terminal: halt"));
        assert!(rendered.contains("stop_reason: no_eligible_action"));
        assert!(rendered.contains("usage: requests=3"));
        // The default summary does not include the explain section.
        assert!(!rendered.contains("-- explain --"));
        // The user surface never labels an outcome a vulnerability, and never
        // leaks a Debug dump of internal runtime types.
        assert!(!rendered.to_lowercase().contains("vulnerabilit"));
        assert!(!rendered.contains("VerificationCase {"));
    }

    #[test]
    fn render_explain_extends_the_summary_with_the_full_chain() {
        let rendered = decision_scan::render_explain(&sample_summary());
        // It is a strict superset of the default summary.
        assert!(rendered.starts_with(&decision_scan::render_summary(&sample_summary())));
        assert!(rendered.contains("-- explain --"));
        // Hierarchical hypotheses with aligned, stable labels.
        assert!(rendered.contains("Hypotheses (1)"));
        assert!(rendered.contains("  technology.web-server=nginx"));
        assert!(rendered.contains("strength : weak"));
        assert!(rendered.contains("posterior: 89%"));
        assert!(rendered.contains("state    : supported"));
        // Planning turn with planned/excluded sections and the exact reason.
        assert!(rendered.contains("Planning (turn 0)"));
        assert!(rendered.contains("  Excluded"));
        assert!(rendered.contains("• web.action.nginx.configuration"));
        assert!(rendered.contains("reason: policy_suppressed"));
        // Dispatch, Verification, and Terminal sections.
        assert!(rendered.contains("Dispatch"));
        assert!(rendered.contains("web.action.bootstrap (bootstrap)"));
        assert!(rendered.contains("Verification"));
        assert!(rendered.contains("web.action.probe: unknown"));
        assert!(rendered.contains("Terminal"));
        assert!(rendered.contains("halt (no_eligible_action)"));
        // Same honesty guarantees as the summary.
        assert!(!rendered.to_lowercase().contains("vulnerabilit"));
        assert!(!rendered.contains("VerificationCase {"));
        assert!(!rendered.contains("ExclusionReason"));
    }

    #[tokio::test]
    async fn decision_scan_explain_reports_the_chain_for_a_basic_auth_origin() {
        // A 401 Basic challenge activates the supported http-basic path end to end;
        // the explain view must surface the hypothesis, the dispatched action, and
        // a success outcome — all offline.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let mut request = [0_u8; 2048];
                let _ = socket.read(&mut request).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();

        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        let rendered = decision_scan::render_explain(&summary);
        assert!(
            rendered.contains("authentication.mechanism=http-basic"),
            "explain must surface the http-basic hypothesis:\n{rendered}"
        );
        assert!(
            rendered.contains("strength : strong"),
            "explain must surface the hypothesis strength:\n{rendered}"
        );
        assert!(
            rendered.contains("(planned)"),
            "explain must surface the planned dispatch:\n{rendered}"
        );
        assert!(
            rendered.contains(": success"),
            "explain must surface the success outcome:\n{rendered}"
        );
        assert!(!rendered.to_lowercase().contains("vulnerabilit"));
    }
}
