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
        Some(Commands::DecisionScan { target }) => {
            eprintln!("{DECISION_SCAN_PREVIEW_WARNING}");
            let summary = decision_scan::run_decision_scan(target).await?;
            print!("{}", decision_scan::render_summary(&summary));
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
            Some(Commands::DecisionScan { target }) => {
                assert_eq!(target.as_str(), "https://example.test/");
            },
            _ => panic!("expected the decision-scan command"),
        }
        assert!(DECISION_SCAN_PREVIEW_WARNING.contains("not the default"));
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
        // The exact-origin policy is retained (the target origin is echoed back).
        assert_eq!(summary.target, target.origin().ascii_serialization());
        // A terminal (bounded stop) state is always reported.
        assert!(!summary.terminal.is_empty());

        server.abort();
    }

    #[tokio::test]
    async fn decision_scan_preview_is_deterministic_excluding_elapsed_time() {
        let (target_a, server_a) = serve_static().await;
        let first = decision_scan::run_decision_scan(target_a).await.unwrap();
        server_a.abort();

        let (target_b, server_b) = serve_static().await;
        let mut second = decision_scan::run_decision_scan(target_b).await.unwrap();
        server_b.abort();

        // Equivalent server responses yield equivalent summaries, apart from the
        // wall-clock fields (elapsed time and the ephemeral loopback port/origin).
        second.elapsed_ms = first.elapsed_ms;
        second.target = first.target.clone();
        assert_eq!(first, second);
    }
}
