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
mod finding_projection;

use clap::{Parser, Subcommand, ValueEnum};
use url::Url;
use venom_proxy::ProxyServer;
use venom_scanner::{phases, ScanContext, ScanRunner};

/// Output format for `decision-scan`. `text` is the default human-readable report;
/// `json` is the versioned machine-readable `decision-scan/v1` document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum OutputFormat {
    Text,
    Json,
}

/// True when `--format json` is combined with `--explain` — an ambiguous
/// combination rejected fail-fast, because the JSON document already carries the
/// full diagnostics `--explain` adds to the text report.
fn decision_scan_flags_conflict(format: OutputFormat, explain: bool) -> bool {
    matches!(format, OutputFormat::Json) && explain
}

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
        /// Output format. `text` (default) is the human-readable report; `json` is
        /// the versioned machine-readable document with full diagnostics.
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Print the full explainable decision chain (hypotheses, planned/excluded
        /// actions with reasons, dispatched actions, outcomes). Text format only —
        /// `--format json` already contains full diagnostics. Off by default; the
        /// default text output is unchanged.
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
        Some(Commands::DecisionScan {
            target,
            format,
            explain,
        }) => {
            // `--explain` is a text-only modifier; JSON already carries full
            // diagnostics. Reject the ambiguous combination fail-fast as a Clap
            // conflict rather than silently ignoring a flag.
            if decision_scan_flags_conflict(format, explain) {
                use clap::CommandFactory;
                Cli::command()
                    .error(
                        clap::error::ErrorKind::ArgumentConflict,
                        "`--explain` applies only to `--format text`; `--format json` already includes full diagnostics",
                    )
                    .exit();
            }
            eprintln!("{DECISION_SCAN_PREVIEW_WARNING}");
            let summary = decision_scan::run_decision_scan(target).await?;
            match format {
                OutputFormat::Text => {
                    let rendered = if explain {
                        decision_scan::render_explain(&summary)
                    } else {
                        decision_scan::render_summary(&summary)
                    };
                    print!("{rendered}");
                },
                OutputFormat::Json => {
                    // JSON to stdout; the preview warning above went to stderr.
                    println!("{}", decision_scan::render_json(&summary)?);
                },
            }
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
            Some(Commands::DecisionScan {
                target,
                format,
                explain,
            }) => {
                assert_eq!(target.as_str(), "https://example.test/");
                assert_eq!(format, OutputFormat::Text, "text is the default format");
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
    fn decision_scan_accepts_the_json_format() {
        let cli = Cli::try_parse_from([
            "venom",
            "decision-scan",
            "--format",
            "json",
            "https://example.test/",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::DecisionScan { format, .. }) => {
                assert_eq!(format, OutputFormat::Json);
            },
            _ => panic!("expected the decision-scan command"),
        }
    }

    #[test]
    fn decision_scan_rejects_json_with_explain() {
        // The combination is ambiguous — JSON already contains full diagnostics —
        // and is rejected fail-fast.
        assert!(decision_scan_flags_conflict(OutputFormat::Json, true));
        assert!(!decision_scan_flags_conflict(OutputFormat::Json, false));
        assert!(!decision_scan_flags_conflict(OutputFormat::Text, true));
        assert!(!decision_scan_flags_conflict(OutputFormat::Text, false));
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
            planning_turns: 1,
            verification_outcomes: 1,
            conclusive_outcomes: 0,
            inconclusive_outcomes: 1,
            outcomes: vec![decision_scan::OutcomeView {
                action_id: "web.action.probe".to_string(),
                status: "unknown",
                conclusive: false,
            }],
            terminal: "halt",
            stop_reason: Some("no_eligible_action"),
            total_requests: 3,
            active_verifications: 1,
            response_bytes: 42,
            elapsed_ms: 5,
            limit_exceeded: None,
            limit_exceeded_text: None,
            experience_records: 1,
            hypotheses: vec![decision_scan::HypothesisView {
                predicate: "technology.web-server".to_string(),
                value: Some("nginx".to_string()),
                value_kind: "text",
                value_disposition: "exposed",
                strength: "weak",
                posterior_basis_points: 8900,
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
            dispatched: vec![decision_scan::DispatchView {
                sequence: 0,
                action_id: "web.action.bootstrap".to_string(),
                stage: "passive",
                origin: Some("bootstrap"),
            }],
            unavailable_routes: vec![
                "web.action.apache.configuration".to_string(),
                "web.action.laravel.input-analysis".to_string(),
                "web.action.nginx.configuration".to_string(),
                "web.action.php.input-discovery".to_string(),
            ],
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
        // Executor Routes: only the runtime's explicit unavailable routes, counted.
        assert!(rendered.contains("Executor Routes"));
        assert!(rendered.contains("  Unavailable (4)"));
        assert!(rendered.contains("    • web.action.nginx.configuration\n"));
        // No synthesized "available" list.
        assert!(!rendered.contains("Available"));
        // Hierarchical hypotheses with aligned, stable labels.
        assert!(rendered.contains("Hypotheses (1)"));
        assert!(rendered.contains("  technology.web-server=nginx"));
        assert!(rendered.contains("strength : weak"));
        assert!(rendered.contains("posterior: 89%"));
        assert!(rendered.contains("state    : supported"));
        // Planning turn with counted sections and one-line excluded entries.
        assert!(rendered.contains("Planning (turn 0)"));
        assert!(rendered.contains("  Planned (0)"));
        assert!(rendered.contains("  Excluded (1)"));
        assert!(rendered.contains("• web.action.nginx.configuration — policy_suppressed"));
        // The old two-line indented `reason:` form is gone (no information lost).
        assert!(!rendered.contains("      reason:"));
        // No ambiguous `(none)` token anywhere (empty sections rely on the count).
        assert!(!rendered.contains("(none)"));
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

    #[test]
    fn default_summary_output_is_byte_stable() {
        // This PR changes only `--explain`. Pin the exact default `decision-scan`
        // bytes so the default output cannot drift unnoticed.
        let expected = concat!(
            "== decision-scan (preview) ==\n",
            "engine: decision-preview\n",
            "target origin: https://example.test\n",
            "evidence: 1 bootstrap write(s)\n",
            "planning: 1 turn(s)\n",
            "verification outcomes: 1 (conclusive 0, inconclusive 1)\n",
            "  outcome: action=web.action.probe status=unknown\n",
            "terminal: halt\n",
            "stop_reason: no_eligible_action\n",
            "usage: requests=3 active_verifications=1 response_bytes=42 elapsed_ms=5\n",
            "experience records: 1\n",
        );
        assert_eq!(decision_scan::render_summary(&sample_summary()), expected);
    }

    #[test]
    fn runtime_limit_text_matches_the_legacy_display_format() {
        // The text surface emits the exact legacy `RuntimeLimitExceeded` Display
        // (which `run_decision_scan` stores verbatim via `.to_string()`); only the
        // JSON surface uses the structured object. The wall-time dimension keeps
        // its `wall_time_ms` label in text.
        let mut summary = sample_summary();
        summary.limit_exceeded_text =
            Some("runtime wall_time_ms limit 60000 reached by 60001".to_owned());
        let rendered = decision_scan::render_summary(&summary);
        assert!(rendered.contains(
            "runtime limit reached (controlled stop): runtime wall_time_ms limit 60000 reached by 60001\n"
        ));
    }

    #[test]
    fn runtime_limit_with_action_matches_the_legacy_display_format() {
        let mut summary = sample_summary();
        summary.limit_exceeded_text = Some(
            "runtime response_bytes limit 1048576 reached by 1100000 for action web.action.laravel.route-discovery"
                .to_owned(),
        );
        let rendered = decision_scan::render_summary(&summary);
        assert!(rendered.contains(
            "runtime limit reached (controlled stop): runtime response_bytes limit 1048576 reached by 1100000 for action web.action.laravel.route-discovery\n"
        ));
    }

    #[tokio::test]
    async fn decision_scan_explain_labels_the_active_verification_dispatch() {
        // The Sanctum cookie pair drives Laravel route discovery, whose second
        // probe is an active-verification dispatch with no passive origin. The
        // explain view must label it `active_verification`, never `none`.
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
                        b"HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=eyJ; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=abc123; Path=/\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
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
            rendered.contains("(active_verification)"),
            "the active probe must be labelled active_verification:\n{rendered}"
        );
        assert!(
            !rendered.contains("(none)"),
            "no dispatch may render the ambiguous (none) label:\n{rendered}"
        );
        // Planned/dispatched/outcome distinctions remain intact.
        assert!(rendered.contains("✓ web.action.laravel.route-discovery"));
        assert!(rendered.contains("✓ web.action.sanctum.auth-boundary"));
        assert!(rendered.contains("web.action.laravel.route-discovery (planned)"));
        // Sanctum is planned but never dispatched (route review defers it): it has
        // an available executor route, so it is NOT in the unavailable inventory,
        // and no dispatch line carries its action id.
        assert!(
            !summary
                .unavailable_routes
                .contains(&"web.action.sanctum.auth-boundary".to_string()),
            "sanctum has an available route: {:?}",
            summary.unavailable_routes
        );
        assert!(
            !rendered.contains("web.action.sanctum.auth-boundary ("),
            "sanctum is planned but never dispatched:\n{rendered}"
        );
    }

    /// The unavailable executor-route inventory is a fixed property of the runtime
    /// composition — identical regardless of what a fixture discloses.
    #[tokio::test]
    async fn executor_route_inventory_is_fixture_independent() {
        // A generic 200 (no hypotheses) and a Basic challenge (a full supported
        // path) must report the identical unavailable-route inventory.
        let (generic_target, generic_server) = serve_static().await;
        let generic = decision_scan::run_decision_scan(generic_target)
            .await
            .unwrap();
        generic_server.abort();

        let basic_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let basic_address = basic_listener.local_addr().unwrap();
        let basic_server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = match basic_listener.accept().await {
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
        let basic_target = Url::parse(&format!("http://{basic_address}/")).unwrap();
        let basic = decision_scan::run_decision_scan(basic_target)
            .await
            .unwrap();
        basic_server.abort();

        assert_eq!(
            generic.unavailable_routes, basic.unavailable_routes,
            "the unavailable-route inventory must not depend on the fixture"
        );
        // It is the runtime's fixed four executor-less actions, in sorted order.
        assert_eq!(
            generic.unavailable_routes,
            vec![
                "web.action.apache.configuration".to_string(),
                "web.action.laravel.input-analysis".to_string(),
                "web.action.nginx.configuration".to_string(),
                "web.action.php.input-discovery".to_string(),
            ]
        );
    }

    /// Route status (runtime composition) and planning eligibility (this turn's
    /// decision) are independent axes and must render as distinct facts.
    #[tokio::test]
    async fn decision_scan_explain_separates_route_status_from_planning_eligibility() {
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
                        b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
                    )
                    .await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();
        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        // nginx: no executor route AND excluded this turn as policy_suppressed.
        assert!(summary
            .unavailable_routes
            .contains(&"web.action.nginx.configuration".to_string()));
        // http-basic: HAS an executor route (not in the unavailable inventory) yet
        // is still excluded this turn — for a different reason (requirements not
        // met). Route availability and eligibility are orthogonal.
        assert!(!summary
            .unavailable_routes
            .contains(&"web.action.http-basic.auth-boundary".to_string()));

        let rendered = decision_scan::render_explain(&summary);
        // Both facts appear, framed distinctly: the route inventory lists nginx
        // without a reason; the planning turn excludes it with a reason.
        assert!(rendered.contains("Executor Routes"));
        assert!(rendered.contains("    • web.action.nginx.configuration\n"));
        assert!(rendered.contains("• web.action.nginx.configuration — policy_suppressed"));
        assert!(
            rendered.contains("• web.action.http-basic.auth-boundary — requirements_not_met"),
            "an available route can still be excluded this turn:\n{rendered}"
        );
    }

    // --- Machine-readable (`--format json`) tests -----------------------------

    /// Runs one fixture and returns the parsed JSON document.
    async fn json_for(response: &'static [u8]) -> serde_json::Value {
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
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
            }
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();
        let summary = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();
        let json = decision_scan::render_json(&summary).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn render_json_emits_the_versioned_schema() {
        let json = decision_scan::render_json(&sample_summary()).unwrap();
        // It is valid JSON.
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schema_version"], "decision-scan/v1");
        assert_eq!(value["engine"], "decision-preview");
        assert_eq!(value["target_origin"], "https://example.test");
        // Every top-level contract group is present with stable names.
        for key in [
            "summary",
            "executor_routes",
            "hypotheses",
            "planning_turns",
            "dispatches",
            "verification_outcomes",
            "terminal",
            "usage",
        ] {
            assert!(value.get(key).is_some(), "missing top-level key {key}");
        }
        // Basis points is the numeric source of truth; there is no percent field.
        assert_eq!(value["hypotheses"][0]["posterior_basis_points"], 8900);
        assert!(value["hypotheses"][0].get("posterior_percent").is_none());
        // Executor routes: only the unavailable set, never a synthesized available.
        assert_eq!(
            value["executor_routes"]["unavailable"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert!(value["executor_routes"].get("available").is_none());
        // Terminal and usage.
        assert_eq!(value["terminal"]["command"], "halt");
        assert_eq!(value["terminal"]["stop_reason"], "no_eligible_action");
        assert!(value["terminal"]["runtime_limit"].is_null());
        assert_eq!(value["usage"]["total_requests"], 3);
        // Hypothesis value carries an explicit kind and safety disposition.
        assert_eq!(value["hypotheses"][0]["value"], "nginx");
        assert_eq!(value["hypotheses"][0]["value_kind"], "text");
        assert_eq!(value["hypotheses"][0]["value_disposition"], "exposed");
        // Never a vulnerability claim, never a Debug dump.
        assert!(!json.to_lowercase().contains("vulnerabilit"));
        assert!(!json.contains("VerificationCase"));
    }

    #[test]
    fn render_json_matches_the_exact_v1_golden() {
        // Pins the current canonical renderer output (field set, types,
        // nullability, and the renderer's member order) — not just the presence of
        // selected keys. JSON object member order is not itself a consumer-semantic
        // contract (see the schema doc); this golden guards the renderer. Regenerate
        // deliberately on an intended change.
        let expected = concat!(
            "{\n",
            "  \"schema_version\": \"decision-scan/v1\",\n",
            "  \"engine\": \"decision-preview\",\n",
            "  \"target_origin\": \"https://example.test\",\n",
            "  \"summary\": {\n",
            "    \"bootstrap_evidence_writes\": 1,\n",
            "    \"planning_turns\": 1,\n",
            "    \"verification_outcomes\": 1,\n",
            "    \"conclusive_outcomes\": 0,\n",
            "    \"inconclusive_outcomes\": 1,\n",
            "    \"experience_records\": 1\n",
            "  },\n",
            "  \"executor_routes\": {\n",
            "    \"unavailable\": [\n",
            "      \"web.action.apache.configuration\",\n",
            "      \"web.action.laravel.input-analysis\",\n",
            "      \"web.action.nginx.configuration\",\n",
            "      \"web.action.php.input-discovery\"\n",
            "    ]\n",
            "  },\n",
            "  \"hypotheses\": [\n",
            "    {\n",
            "      \"predicate\": \"technology.web-server\",\n",
            "      \"value\": \"nginx\",\n",
            "      \"value_kind\": \"text\",\n",
            "      \"value_disposition\": \"exposed\",\n",
            "      \"strength\": \"weak\",\n",
            "      \"posterior_basis_points\": 8900,\n",
            "      \"state\": \"supported\"\n",
            "    }\n",
            "  ],\n",
            "  \"planning_turns\": [\n",
            "    {\n",
            "      \"turn\": 0,\n",
            "      \"planned\": [],\n",
            "      \"excluded\": [\n",
            "        {\n",
            "          \"action_id\": \"web.action.nginx.configuration\",\n",
            "          \"reason\": \"policy_suppressed\"\n",
            "        }\n",
            "      ]\n",
            "    }\n",
            "  ],\n",
            "  \"dispatches\": [\n",
            "    {\n",
            "      \"sequence\": 0,\n",
            "      \"action_id\": \"web.action.bootstrap\",\n",
            "      \"stage\": \"passive\",\n",
            "      \"origin\": \"bootstrap\"\n",
            "    }\n",
            "  ],\n",
            "  \"verification_outcomes\": [\n",
            "    {\n",
            "      \"action_id\": \"web.action.probe\",\n",
            "      \"status\": \"unknown\",\n",
            "      \"conclusive\": false\n",
            "    }\n",
            "  ],\n",
            "  \"terminal\": {\n",
            "    \"command\": \"halt\",\n",
            "    \"stop_reason\": \"no_eligible_action\",\n",
            "    \"runtime_limit\": null\n",
            "  },\n",
            "  \"usage\": {\n",
            "    \"total_requests\": 3,\n",
            "    \"active_verifications\": 1,\n",
            "    \"response_bytes\": 42,\n",
            "    \"elapsed_ms\": 5\n",
            "  }\n",
            "}"
        );
        assert_eq!(
            decision_scan::render_json(&sample_summary()).unwrap(),
            expected
        );
    }

    /// Structural invariants the v1 document must always satisfy on a real run.
    #[tokio::test]
    async fn json_invariants_hold_on_a_real_run() {
        // Sanctum drives multiple planning entries, dispatches, and outcomes.
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=eyJ; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=abc123; Path=/\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        )
        .await;

        // Duplicated count fields must equal their array lengths.
        assert_eq!(
            value["summary"]["planning_turns"].as_u64().unwrap(),
            value["planning_turns"].as_array().unwrap().len() as u64
        );
        let outcomes = value["verification_outcomes"].as_array().unwrap();
        assert_eq!(
            value["summary"]["verification_outcomes"].as_u64().unwrap(),
            outcomes.len() as u64
        );
        // conclusive + inconclusive == total outcomes.
        assert_eq!(
            value["summary"]["conclusive_outcomes"].as_u64().unwrap()
                + value["summary"]["inconclusive_outcomes"].as_u64().unwrap(),
            outcomes.len() as u64
        );
        // Dispatch sequences are strictly increasing.
        let sequences: Vec<u64> = value["dispatches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|dispatch| dispatch["sequence"].as_u64().unwrap())
            .collect();
        assert!(
            sequences.windows(2).all(|pair| pair[0] < pair[1]),
            "dispatch sequences must be strictly increasing: {sequences:?}"
        );
        // Posterior basis points never exceed 10000.
        for hypothesis in value["hypotheses"].as_array().unwrap() {
            assert!(hypothesis["posterior_basis_points"].as_u64().unwrap() <= 10_000);
        }
    }

    #[tokio::test]
    async fn json_generic_structure_is_inert() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        )
        .await;
        assert_eq!(value["schema_version"], "decision-scan/v1");
        assert!(value["hypotheses"].as_array().unwrap().is_empty());
        assert!(value["planning_turns"][0]["planned"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(value["verification_outcomes"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(value["terminal"]["command"], "halt");
        assert_eq!(value["terminal"]["stop_reason"], "no_eligible_action");
        // The unavailable-route inventory is present and fixture-independent.
        assert_eq!(
            value["executor_routes"]["unavailable"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
    }

    #[tokio::test]
    async fn json_basic_structure_reports_a_conclusive_success() {
        let value = json_for(
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let hypothesis = &value["hypotheses"][0];
        assert_eq!(hypothesis["predicate"], "authentication.mechanism");
        assert_eq!(hypothesis["value"], "http-basic");
        assert_eq!(hypothesis["strength"], "strong");
        assert!(hypothesis["posterior_basis_points"].as_u64().unwrap() >= 9000);
        let outcome = &value["verification_outcomes"][0];
        assert_eq!(outcome["action_id"], "web.action.http-basic.auth-boundary");
        assert_eq!(outcome["status"], "success");
        assert_eq!(outcome["conclusive"], true);
        // No raw challenge header/realm leaks into the machine surface.
        let json = value.to_string();
        assert!(!json.contains("WWW-Authenticate"));
        assert!(!json.contains("realm"));
    }

    #[tokio::test]
    async fn json_livewire_structure_reports_a_dispatched_success() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 23\r\nConnection: close\r\n\r\n<div wire:id=\"x\"></div>",
        )
        .await;
        assert_eq!(value["hypotheses"][0]["value"], "livewire");
        assert!(value["planning_turns"][0]["planned"]
            .as_array()
            .unwrap()
            .iter()
            .any(|planned| *planned == "web.action.livewire.component-discovery"));
        assert!(value["dispatches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|dispatch| {
                dispatch["action_id"] == "web.action.livewire.component-discovery"
            }));
        assert_eq!(value["verification_outcomes"][0]["status"], "success");
    }

    #[tokio::test]
    async fn json_sanctum_separates_stage_origin_and_leaks_no_secrets() {
        let value = json_for(
            b"HTTP/1.1 200 OK\r\nSet-Cookie: laravel_session=eyJ; Path=/; HttpOnly\r\nSet-Cookie: XSRF-TOKEN=abc123; Path=/\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
        )
        .await;

        let dispatches = value["dispatches"].as_array().unwrap();
        // An active-verification dispatch keeps stage/origin as separate facts:
        // stage = "active", origin = null (never a fused "active_verification").
        assert!(
            dispatches
                .iter()
                .any(|dispatch| dispatch["stage"] == "active" && dispatch["origin"].is_null()),
            "expected an active dispatch with null origin: {dispatches:?}"
        );
        // Passive/bootstrap dispatches carry an explicit origin.
        assert!(dispatches
            .iter()
            .any(|dispatch| dispatch["origin"] == "bootstrap"));

        // Sanctum is planned but never dispatched, and has an available route.
        let planned = value["planning_turns"][0]["planned"].as_array().unwrap();
        assert!(planned
            .iter()
            .any(|action| *action == "web.action.sanctum.auth-boundary"));
        assert!(!dispatches
            .iter()
            .any(|dispatch| dispatch["action_id"] == "web.action.sanctum.auth-boundary"));
        assert!(!value["executor_routes"]["unavailable"]
            .as_array()
            .unwrap()
            .iter()
            .any(|route| *route == "web.action.sanctum.auth-boundary"));

        // No raw cookies, values, or headers leak into the machine surface.
        let json = value.to_string();
        for secret in [
            "eyJ",
            "abc123",
            "Set-Cookie",
            "laravel_session",
            "XSRF-TOKEN",
        ] {
            assert!(!json.contains(secret), "json leaked `{secret}`: {json}");
        }
    }

    #[tokio::test]
    async fn json_is_deterministic_for_equivalent_non_boundary_fixture_excluding_elapsed_ms() {
        // A generic 200 sits well away from any budget boundary, so two runs agree
        // once elapsed time is excluded. (Near a boundary, chunking/scheduling may
        // affect response_bytes / runtime_limit.observed / total_requests — see the
        // schema doc.)
        let (target, server) = serve_static().await;
        let first = decision_scan::run_decision_scan(target.clone())
            .await
            .unwrap();
        let second = decision_scan::run_decision_scan(target).await.unwrap();
        server.abort();

        let mut a: serde_json::Value =
            serde_json::from_str(&decision_scan::render_json(&first).unwrap()).unwrap();
        let mut b: serde_json::Value =
            serde_json::from_str(&decision_scan::render_json(&second).unwrap()).unwrap();
        a["usage"]["elapsed_ms"] = serde_json::json!(0);
        b["usage"]["elapsed_ms"] = serde_json::json!(0);
        assert_eq!(
            a, b,
            "JSON must be deterministic once elapsed time is excluded"
        );
    }
}
