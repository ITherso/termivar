//! Advanced Reporting System
//!
//! ## Runtime scope
//!
//! - **Build:** opt-in via `reporting`.
//! - **Execution:** no repository runtime caller (not on the default scan path).
//! - **Default `venom scan`:** no.
//! - **Support:** Legacy host-library renderer, separate from deterministic `RunReport`.
//!
//! See `docs/internals/runtime-map.md`.
//!
//! Generates comprehensive vulnerability reports in multiple formats:
//! JSON, HTML, CSV, and executive summaries.

use crate::ScanFinding;
use std::collections::HashMap;

/// Vulnerability report with aggregate statistics
#[derive(Debug, Clone)]
pub struct VulnerabilityReport {
    /// Scan target URL
    pub target: String,
    /// Scan timestamp (Unix seconds)
    pub timestamp: u64,
    /// All discovered vulnerabilities
    pub findings: Vec<ScanFinding>,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

impl VulnerabilityReport {
    /// Creates a new report
    pub fn new(target: String, findings: Vec<ScanFinding>, duration_ms: u64) -> Self {
        Self {
            target,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            findings,
            duration_ms,
        }
    }

    /// Calculates severity statistics
    pub fn severity_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        for finding in &self.findings {
            *stats.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        stats
    }

    /// Calculates phase statistics
    pub fn phase_stats(&self) -> HashMap<u8, usize> {
        let mut stats = HashMap::new();
        for finding in &self.findings {
            *stats.entry(finding.phase).or_insert(0) += 1;
        }
        stats
    }

    /// Generates risk score (0.0-1.0)
    pub fn risk_score(&self) -> f32 {
        if self.findings.is_empty() {
            return 0.0;
        }

        let critical_count = self
            .findings
            .iter()
            .filter(|f| f.severity == "CRITICAL")
            .count();
        let high_count = self
            .findings
            .iter()
            .filter(|f| f.severity == "HIGH")
            .count();
        let medium_count = self
            .findings
            .iter()
            .filter(|f| f.severity == "MEDIUM")
            .count();

        let score =
            (critical_count as f32 * 0.4 + high_count as f32 * 0.2 + medium_count as f32 * 0.1)
                / self.findings.len() as f32;

        score.min(1.0)
    }

    /// Generates JSON report
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "target": self.target,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "risk_score": self.risk_score(),
            "total_findings": self.findings.len(),
            "severity_stats": self.severity_stats(),
            "phase_stats": self.phase_stats(),
            "findings": self.findings,
        })
        .to_string()
    }

    /// Generates CSV report
    pub fn to_csv(&self) -> String {
        let mut csv = String::from("phase,module,severity,description,evidence\n");
        for finding in &self.findings {
            let line = format!(
                "{},{},\"{}\",\"{}\",\"{}\"\n",
                finding.phase,
                finding.module_name,
                finding.severity,
                finding.description.replace("\"", "\"\""),
                finding.evidence.replace("\"", "\"\"")
            );
            csv.push_str(&line);
        }
        csv
    }

    /// Generates HTML report
    pub fn to_html(&self) -> String {
        let severity_stats = self.severity_stats();
        let critical = severity_stats.get("CRITICAL").unwrap_or(&0);
        let high = severity_stats.get("HIGH").unwrap_or(&0);
        let medium = severity_stats.get("MEDIUM").unwrap_or(&0);
        let low = severity_stats.get("LOW").unwrap_or(&0);

        let findings_html = self
            .findings
            .iter()
            .map(|f| {
                format!(
                    r#"<div class="finding {}">
                    <div class="finding-title">Phase {}: {}</div>
                    <div class="finding-meta">{} | {}</div>
                    <div class="finding-desc">{}</div>
                    <div class="finding-evidence">{}</div>
                </div>"#,
                    f.severity.to_lowercase(),
                    f.phase,
                    f.module_name,
                    f.severity,
                    f.description,
                    f.evidence,
                    f.evidence
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>VENOM Scan Report - {}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        .header {{ border-bottom: 3px solid #dc3545; padding-bottom: 20px; }}
        .title {{ font-size: 28px; font-weight: bold; color: #333; }}
        .subtitle {{ color: #666; margin-top: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; border-radius: 4px; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding-title {{ font-weight: bold; font-size: 16px; }}
        .finding-meta {{ color: #666; font-size: 12px; margin-top: 5px; }}
        .finding-desc {{ margin-top: 10px; color: #333; }}
        .finding-evidence {{ background: #fff; padding: 10px; margin-top: 10px; border-radius: 3px; font-family: monospace; font-size: 12px; color: #666; }}
        .risk-score {{ font-size: 36px; font-weight: bold; color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">🐍 VENOM Vulnerability Report</div>
            <div class="subtitle">Target: {}</div>
            <div class="subtitle">Scanned: {}</div>
        </div>

        <div class="summary">
            <div class="stat-box">
                <div class="stat-number critical">{}</div>
                <div class="stat-label">CRITICAL</div>
            </div>
            <div class="stat-box">
                <div class="stat-number high">{}</div>
                <div class="stat-label">HIGH</div>
            </div>
            <div class="stat-box">
                <div class="stat-number medium">{}</div>
                <div class="stat-label">MEDIUM</div>
            </div>
            <div class="stat-box">
                <div class="stat-number low">{}</div>
                <div class="stat-label">LOW</div>
            </div>
        </div>

        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center;">
            <div style="font-size: 14px; color: #666;">Overall Risk Score</div>
            <div class="risk-score">{:.1}%</div>
        </div>

        <div class="findings">
            <h2>Detailed Findings</h2>
            {}
        </div>
    </div>
</body>
</html>"#,
            self.target,
            self.target,
            self.timestamp,
            critical,
            high,
            medium,
            low,
            self.risk_score() * 100.0,
            findings_html
        );

        html
    }

    /// Generates markdown report
    pub fn to_markdown(&self) -> String {
        let mut md = format!(
            "# VENOM Vulnerability Report\n\n\
            **Target:** {}\n\
            **Scanned:** {}\n\
            **Duration:** {}ms\n\
            **Risk Score:** {:.1}%\n\n",
            self.target,
            self.timestamp,
            self.duration_ms,
            self.risk_score() * 100.0
        );

        let stats = self.severity_stats();
        md.push_str("## Summary\n\n");
        md.push_str(&format!(
            "- **CRITICAL:** {}\n",
            stats.get("CRITICAL").unwrap_or(&0)
        ));
        md.push_str(&format!(
            "- **HIGH:** {}\n",
            stats.get("HIGH").unwrap_or(&0)
        ));
        md.push_str(&format!(
            "- **MEDIUM:** {}\n",
            stats.get("MEDIUM").unwrap_or(&0)
        ));
        md.push_str(&format!("- **LOW:** {}\n", stats.get("LOW").unwrap_or(&0)));
        md.push_str(&format!("- **TOTAL:** {}\n\n", self.findings.len()));

        md.push_str("## Findings\n\n");
        for finding in &self.findings {
            md.push_str(&format!(
                "### [{}] Phase {}: {}\n\n\
                **Description:** {}\n\n\
                **Evidence:** {}\n\n---\n\n",
                finding.severity,
                finding.phase,
                finding.module_name,
                finding.description,
                finding.evidence
            ));
        }

        md
    }
}

/// Report generator with format selection
pub struct ReportGenerator;

impl ReportGenerator {
    /// Generates report in specified format
    pub fn generate(report: &VulnerabilityReport, format: ReportFormat) -> String {
        match format {
            ReportFormat::Json => report.to_json(),
            ReportFormat::Csv => report.to_csv(),
            ReportFormat::Html => report.to_html(),
            ReportFormat::Markdown => report.to_markdown(),
        }
    }

    /// Lists available formats
    pub fn available_formats() -> Vec<&'static str> {
        vec!["json", "csv", "html", "markdown"]
    }
}

/// Report output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Json,
    Csv,
    Html,
    Markdown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_creation() {
        let findings = vec![ScanFinding {
            phase: 1,
            module_name: "Recon".to_string(),
            severity: "HIGH".to_string(),
            description: "Test".to_string(),
            evidence: "Evidence".to_string(),
        }];

        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn test_severity_stats() {
        let findings = vec![
            ScanFinding {
                phase: 1,
                module_name: "Test".to_string(),
                severity: "CRITICAL".to_string(),
                description: "Test".to_string(),
                evidence: "Test".to_string(),
            },
            ScanFinding {
                phase: 1,
                module_name: "Test".to_string(),
                severity: "HIGH".to_string(),
                description: "Test".to_string(),
                evidence: "Test".to_string(),
            },
        ];

        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        let stats = report.severity_stats();
        assert_eq!(stats.get("CRITICAL"), Some(&1));
        assert_eq!(stats.get("HIGH"), Some(&1));
    }

    #[test]
    fn test_risk_score() {
        let findings = vec![ScanFinding {
            phase: 1,
            module_name: "Test".to_string(),
            severity: "CRITICAL".to_string(),
            description: "Test".to_string(),
            evidence: "Test".to_string(),
        }];

        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        let score = report.risk_score();
        assert!(score > 0.0 && score <= 1.0);
    }

    #[test]
    fn test_json_export() {
        let findings = vec![];
        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        let json = report.to_json();
        assert!(json.contains("example.com"));
        assert!(json.contains("risk_score"));
    }

    #[test]
    fn test_csv_export() {
        let findings = vec![ScanFinding {
            phase: 1,
            module_name: "Module".to_string(),
            severity: "HIGH".to_string(),
            description: "Desc".to_string(),
            evidence: "Evidence".to_string(),
        }];

        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        let csv = report.to_csv();
        assert!(csv.contains("phase,module,severity"));
        assert!(csv.contains("Module"));
    }

    #[test]
    fn test_html_export() {
        let findings = vec![];
        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        let html = report.to_html();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("VENOM"));
    }

    #[test]
    fn test_markdown_export() {
        let findings = vec![];
        let report = VulnerabilityReport::new("https://example.com".to_string(), findings, 100);
        let md = report.to_markdown();
        assert!(md.contains("# VENOM Vulnerability Report"));
        assert!(md.contains("example.com"));
    }

    #[test]
    fn test_report_formats() {
        let formats = ReportGenerator::available_formats();
        assert!(formats.contains(&"json"));
        assert!(formats.contains(&"csv"));
        assert!(formats.contains(&"html"));
    }
}
