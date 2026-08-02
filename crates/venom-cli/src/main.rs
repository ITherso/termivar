//! Process-level command-line composition for Venom's scanner, API, and proxy adapters.

use clap::{Parser, Subcommand};
use url::Url;
use venom_proxy::ProxyServer;
use venom_scanner::{phases, ScanContext, ScanRunner};

const LEGACY_DIRECTORY_FUZZ_WARNING: &str = "[WARNING] Legacy directory fuzzing is enabled. This brute-force phase uses direct network I/O outside RuntimeBudget; run it only against explicitly authorized targets.";
const LEGACY_SCAN_RUNTIME_WARNING: &str = "[WARNING] The ordered CLI phase pipeline is legacy direct I/O outside StandardWebDecisionRuntime and RuntimeBudget. Use it only against an explicitly authorized exact origin.";

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
}
