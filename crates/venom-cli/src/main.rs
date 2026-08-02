use clap::{Parser, Subcommand};
use url::Url;
use venom_proxy::ProxyServer;
use venom_scanner::{phases, ScanContext, ScanRunner};

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
    Scan { target: String },
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
        Some(Commands::Scan { target }) => {
            let target_url = Url::parse(&target)?;
            let client = reqwest::Client::new();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

            let ctx = ScanContext::new(target_url, client, tx);

            let mut runner = ScanRunner::new();
            runner.register_phase(Box::new(phases::ReconPhase));
            runner.register_phase(Box::new(phases::CrawlPhase));
            runner.register_phase(Box::new(phases::DirectoryFuzzer::with_default_wordlist(20)));
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
