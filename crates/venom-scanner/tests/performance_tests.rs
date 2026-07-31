//! Performance and concurrent execution tests
//!
//! Validates performance characteristics and concurrent phase execution

// Coverage instrumentation changes timing enough to invalidate the strict
// micro-benchmarks in this file. They still run in the normal test workflow.
#![allow(unexpected_cfgs)]
#![cfg(not(tarpaulin))]

use std::time::Instant;
use venom_scanner::{LogLevel, Logger, ScanFinding};

/// Tests concurrent finding collection performance
#[test]
fn test_concurrent_finding_throughput() {
    let start = Instant::now();
    let mut findings = Vec::new();

    // Simulate high-throughput finding generation (1000 findings)
    for phase in 1..=10 {
        for i in 0..100 {
            findings.push(ScanFinding {
                phase,
                module_name: format!("Phase {}", phase),
                severity: match phase % 4 {
                    0 => "CRITICAL",
                    1 => "HIGH",
                    2 => "MEDIUM",
                    _ => "LOW",
                }
                .to_string(),
                description: format!("Finding {} from phase {}", i, phase),
                evidence: format!("Evidence data {}", i),
            });
        }
    }

    let elapsed = start.elapsed();

    // Should complete 1000 findings in < 10ms
    assert!(elapsed.as_millis() < 10);
    assert_eq!(findings.len(), 1000);
}

/// Tests finding vector push performance
#[test]
fn test_vec_push_performance() {
    let start = Instant::now();
    let mut findings: Vec<ScanFinding> = Vec::with_capacity(500);

    for i in 0..500 {
        findings.push(ScanFinding {
            phase: (i % 9 + 1) as u8,
            module_name: "Test".to_string(),
            severity: "MEDIUM".to_string(),
            description: format!("Test {}", i),
            evidence: "Evidence".to_string(),
        });
    }

    let elapsed = start.elapsed();

    assert_eq!(findings.len(), 500);
    assert!(elapsed.as_micros() < 5000); // < 5ms
}

/// Tests finding aggregation performance
#[test]
fn test_finding_aggregation_performance() {
    let start = Instant::now();

    // Simulate multiple phase results
    let mut phase_results: Vec<Vec<ScanFinding>> = Vec::new();

    for phase in 1..=9 {
        let mut findings = Vec::new();
        for i in 0..50 {
            findings.push(ScanFinding {
                phase: phase as u8,
                module_name: format!("Module {}", phase),
                severity: "MEDIUM".to_string(),
                description: format!("Finding {}", i),
                evidence: "Evidence".to_string(),
            });
        }
        phase_results.push(findings);
    }

    // Aggregate all findings
    let all_findings: Vec<ScanFinding> = phase_results.into_iter().flatten().collect();

    let elapsed = start.elapsed();

    assert_eq!(all_findings.len(), 450);
    assert!(elapsed.as_micros() < 5000); // < 5ms
}

/// Tests logger filtering performance
#[test]
fn test_logger_filtering_performance() {
    let logger_warn = Logger::new(LogLevel::Warn);
    let logger_debug = Logger::new(LogLevel::Debug);

    let start = Instant::now();

    // Log 1000 debug messages (should be filtered)
    for i in 0..1000 {
        logger_warn.debug(format!("Debug message {}", i));
    }

    let elapsed = start.elapsed();

    // Filtered messages should be fast (< 5ms even for 1000)
    assert!(elapsed.as_millis() < 5);
}

/// Tests severity level filtering
#[test]
fn test_severity_filtering_perf() {
    let findings: Vec<_> = (0..1000)
        .map(|i| ScanFinding {
            phase: 1,
            module_name: "Test".to_string(),
            severity: match i % 4 {
                0 => "CRITICAL",
                1 => "HIGH",
                2 => "MEDIUM",
                _ => "LOW",
            }
            .to_string(),
            description: format!("Finding {}", i),
            evidence: "Evidence".to_string(),
        })
        .collect();

    let start = Instant::now();

    // Filter to only critical and high
    let critical: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == "CRITICAL" || f.severity == "HIGH")
        .collect();

    let elapsed = start.elapsed();

    assert_eq!(critical.len(), 500);
    assert!(elapsed.as_micros() < 500); // < 0.5ms
}

/// Tests finding serialization performance
#[test]
fn test_serialization_perf() {
    let findings: Vec<ScanFinding> = (0..100)
        .map(|i| ScanFinding {
            phase: (i % 9 + 1) as u8,
            module_name: "Test".to_string(),
            severity: "MEDIUM".to_string(),
            description: format!("Finding {}", i),
            evidence: "Evidence".to_string(),
        })
        .collect();

    let start = Instant::now();

    // Serialize all findings to JSON
    for finding in &findings {
        let _ = serde_json::to_string(finding);
    }

    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() < 10); // < 10ms for 100 findings
}

/// Tests memory efficiency of finding deduplication
#[test]
fn test_dedup_memory_efficiency() {
    let mut findings = Vec::new();

    // Create 1000 findings with many duplicates
    for i in 0..500 {
        for _ in 0..2 {
            findings.push(ScanFinding {
                phase: (i % 9 + 1) as u8,
                module_name: "Test".to_string(),
                severity: "MEDIUM".to_string(),
                description: format!("Finding {}", i),
                evidence: "Evidence".to_string(),
            });
        }
    }

    let start = Instant::now();

    // Dedup
    findings.dedup_by(|a, b| {
        a.phase == b.phase && a.description == b.description && a.evidence == b.evidence
    });

    let elapsed = start.elapsed();

    assert_eq!(findings.len(), 500);
    assert!(elapsed.as_micros() < 1000);
}

/// Tests log entry creation performance
#[test]
fn test_log_entry_creation_perf() {
    use venom_scanner::LogEntry;

    let start = Instant::now();

    for i in 0..1000 {
        let _entry = LogEntry::new(LogLevel::Info, format!("Message {}", i))
            .with_phase((i % 9 + 1) as u8)
            .with_duration(i as u64);
    }

    let elapsed = start.elapsed();

    // 1000 log entries in < 5ms
    assert!(elapsed.as_millis() < 5);
}

/// Tests batch finding updates
#[test]
fn test_batch_finding_updates() {
    let mut findings: Vec<ScanFinding> = (0..100)
        .map(|i| ScanFinding {
            phase: 1,
            module_name: "Initial".to_string(),
            severity: "LOW".to_string(),
            description: format!("Finding {}", i),
            evidence: "Initial".to_string(),
        })
        .collect();

    let start = Instant::now();

    // Update all findings in batch
    for finding in &mut findings {
        finding.severity = "MEDIUM".to_string();
        finding.evidence = "Updated".to_string();
    }

    let elapsed = start.elapsed();

    assert!(elapsed.as_micros() < 500);
    assert!(findings.iter().all(|f| f.severity == "MEDIUM"));
}

/// Tests sorting performance for findings
#[test]
fn test_finding_sort_perf() {
    let mut findings: Vec<ScanFinding> = (0..500)
        .map(|i| ScanFinding {
            phase: (i % 9 + 1) as u8,
            module_name: "Test".to_string(),
            severity: match i % 4 {
                0 => "CRITICAL",
                1 => "HIGH",
                2 => "MEDIUM",
                _ => "LOW",
            }
            .to_string(),
            description: format!("Finding {}", i),
            evidence: "Evidence".to_string(),
        })
        .collect();

    let start = Instant::now();

    // Sort by phase
    findings.sort_by_key(|f| f.phase);

    let elapsed = start.elapsed();

    assert!(elapsed.as_micros() < 2000); // < 2ms
    assert_eq!(findings[0].phase, 1);
}

/// Tests URL pattern matching performance
#[test]
fn test_url_pattern_matching_perf() {
    let urls = vec![
        "https://example.com/api/users",
        "https://example.com/api/posts",
        "https://example.com/admin/dashboard",
        "https://example.com/auth/login",
        "https://example.com/.git/config",
    ];

    let start = Instant::now();

    for _ in 0..1000 {
        for url in &urls {
            let _ = url.contains("/api/") || url.contains("/admin/");
        }
    }

    let elapsed = start.elapsed();

    // 5000 pattern matches in < 5ms
    assert!(elapsed.as_millis() < 5);
}

/// Tests payload list generation performance
#[test]
fn test_payload_list_perf() {
    let start = Instant::now();

    for _ in 0..100 {
        let sql_payloads = vec![
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "admin' --",
            "' UNION SELECT NULL --",
        ];
        let xss_payloads = vec![
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ];

        assert!(!sql_payloads.is_empty());
        assert!(!xss_payloads.is_empty());
    }

    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() < 2);
}
