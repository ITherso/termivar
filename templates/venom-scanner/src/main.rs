use async_trait::async_trait;
use venom_scanner::{Result, ScanContext, ScanFinding, ScanPhase, ScannerSdk};

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
    let target = std::env::args_os()
        .nth(1)
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "https://example.test".to_string());

    let scanner = ScannerSdk::builder().phase(AuthorizedTargetPhase).build();
    let report = scanner.scan(&target).await?;

    println!("{} finding(s) for {}", report.findings.len(), report.target);
    for finding in report.findings {
        println!("[{}] {}", finding.severity, finding.description);
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
        assert_eq!(report.findings.len(), 1);
    }
}
