use async_trait::async_trait;
use clap::Parser;
use url::Url;
use termivar_scanner::{Result, ScanContext, ScanFinding, ScanPhase, ScannerSdk};

/// Authorized-target scanner generated from the Termivar Scanner SDK template.
#[derive(Debug, Parser)]
#[command(about = "Authorized-target scanner generated from the Termivar Scanner SDK template")]
struct Cli {
    /// Authorized target URL. Defaults to the safe `.test` placeholder.
    #[arg(default_value = "https://example.test")]
    target: Url,
}

struct AuthorizedTargetPhase;

#[async_trait]
impl ScanPhase for AuthorizedTargetPhase {
    fn phase_number(&self) -> u8 {
        10
    }

    fn name(&self) -> &'static str {
        "authorized-target"
    }

    async fn execute(&self, context: &ScanContext) -> Result<Vec<ScanFinding>> {
        Ok(vec![ScanFinding {
            phase: self.phase_number(),
            module_name: self.name().to_string(),
            severity: "INFO".to_string(),
            description: "Custom scanner phase executed".to_string(),
            evidence: context.target.to_string(),
        }])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let target = Cli::parse().target;

    let scanner = ScannerSdk::builder().phase(AuthorizedTargetPhase).build();
    let report = scanner.scan(target.as_ref()).await?;

    println!(
        "status={:?} observations={} target={}",
        report.status(),
        report.outcomes().len(),
        report.target()
    );
    for observation in report.outcomes() {
        println!(
            "id={} action={} disposition={:?}",
            observation.fingerprint(),
            observation.action_id(),
            observation.disposition()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generated_scanner_executes() {
        let scanner = ScannerSdk::builder().phase(AuthorizedTargetPhase).build();
        let report = scanner.scan("https://example.test").await.unwrap();
        assert_eq!(report.outcomes().len(), 1);
        assert_eq!(report.outcomes()[0].confidence().parts_per_million(), 0);
    }

    #[test]
    fn parses_an_explicit_target() {
        let cli = Cli::try_parse_from(["scanner", "https://target.test"]).unwrap();
        assert_eq!(cli.target.as_str(), "https://target.test/");
    }

    #[test]
    fn defaults_to_the_safe_test_target() {
        let cli = Cli::try_parse_from(["scanner"]).unwrap();
        assert_eq!(cli.target.as_str(), "https://example.test/");
    }
}
