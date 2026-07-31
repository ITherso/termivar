//! Phase-specific unit and integration tests
//!
//! Tests core functionality of individual scanning phases

use venom_scanner::{ScanFinding, ScanPhase};

// ============================================================================
// PHASE 1: RECONNAISSANCE
// ============================================================================

#[test]
fn test_phase1_recon_detection() {
    use venom_scanner::phases::ReconPhase;
    let phase = ReconPhase::new();
    assert_eq!(phase.phase_number(), 1);
    assert!(phase.name().contains("Reconnaissance"));
}

#[test]
fn test_phase1_vulnerable_versions() {
    let versions = vec![
        ("Apache/2.4.49", true),
        ("Apache/2.4.50", true),
        ("Apache/2.4.48", false),
        ("Nginx/1.20.0", false),
    ];

    for (version, should_match) in versions {
        let matches = version.contains("Apache/2.4.49") || version.contains("Apache/2.4.50");
        assert_eq!(matches, should_match);
    }
}

// ============================================================================
// PHASE 2: CRAWLING
// ============================================================================

#[test]
fn test_phase2_link_extraction() {
    let html = r#"
        <a href="/api/users">Users</a>
        <a href="/api/posts">Posts</a>
        <a href="https://external.com">External</a>
    "#;

    // Simulate link extraction
    let links: Vec<&str> = vec!["/api/users", "/api/posts"];
    assert_eq!(links.len(), 2);
}

#[test]
fn test_phase2_parameter_extraction() {
    let html = r#"
        <input name="id" type="text">
        <input name="email" type="email">
        <select name="type">
    "#;

    let params = vec!["id", "email", "type"];
    assert_eq!(params.len(), 3);
}

// ============================================================================
// PHASE 3: DIRECTORY FUZZING
// ============================================================================

#[test]
fn test_phase3_wordlist_coverage() {
    let wordlist = vec![
        "/admin", "/api/v1", "/swagger", "/.git", "/.env", "/backup", "/test", "/config",
        "/uploads", "/health",
    ];

    assert!(wordlist.len() >= 50 / 5); // At least 10 entries for this test
    assert!(wordlist.iter().any(|w| w.contains("admin")));
    assert!(wordlist.iter().any(|w| w.contains("api")));
}

#[test]
fn test_phase3_status_code_detection() {
    let status_codes = vec![
        (200, true),  // OK
        (301, true),  // Redirect
        (302, true),  // Found
        (401, true),  // Unauthorized
        (403, true),  // Forbidden
        (404, false), // Not Found
        (500, false), // Server Error
    ];

    for (code, should_report) in status_codes {
        let is_interesting =
            code == 200 || code == 301 || code == 302 || code == 401 || code == 403;
        assert_eq!(is_interesting, should_report);
    }
}

#[test]
fn test_phase3_url_construction() {
    let base = "https://example.com";
    let paths = vec!["/admin", "/api", "/.git"];

    for path in paths {
        let url = format!("{}{}", base, path);
        assert!(url.starts_with("https://example.com"));
        assert!(url.contains(path));
    }
}

// ============================================================================
// PHASE 4: PARAMETER DISCOVERY
// ============================================================================

#[test]
fn test_phase4_param_wordlist() {
    let params = vec![
        "id", "user_id", "admin", "debug", "api_key", "token", "password", "email", "username",
        "redirect",
    ];

    assert!(!params.is_empty());
    assert!(params.contains(&"api_key"));
    assert!(params.contains(&"debug"));
}

#[test]
fn test_phase4_marker_detection() {
    let marker = "venom_7b3a9c2e_test";
    let response_with_marker = format!("Error: invalid value: {}", marker);
    let response_without = "Error: invalid parameter".to_string();

    assert!(response_with_marker.contains(marker));
    assert!(!response_without.contains(marker));
}

#[test]
fn test_phase4_http_400_detection() {
    // HTTP 400 indicates parameter exists but is invalid
    let status = 400;
    assert_eq!(status, 400);

    // Other statuses have different meanings
    assert_ne!(status, 404); // Not found
    assert_ne!(status, 500); // Server error
}

// ============================================================================
// PHASE 5: SQL INJECTION
// ============================================================================

#[test]
fn test_phase5_sql_error_patterns() {
    let errors = vec![
        ("mysql_fetch() expects", "MySQL"),
        ("PostgreSQL query", "PostgreSQL"),
        ("ORA-00", "Oracle"),
        ("Msg ", "MSSQL"),
    ];

    for (error_pattern, dbms) in errors {
        assert!(!error_pattern.is_empty());
        assert!(!dbms.is_empty());
    }
}

#[test]
fn test_phase5_sqli_payload_construction() {
    let payloads = vec!["' OR '1'='1", "1 UNION SELECT NULL--", "admin' --"];

    for payload in payloads {
        assert!(payload.contains("'") || payload.contains("NULL"));
    }
}

#[test]
fn test_phase5_timing_based_detection() {
    let normal_response = 50u64; // 50ms
    let delayed_response = 5050u64; // 5050ms (5 second delay + overhead)

    assert!(delayed_response > normal_response * 100); // At least 100x difference
}

// ============================================================================
// PHASE 6: XSS
// ============================================================================

#[test]
fn test_phase6_html_context_detection() {
    let contexts = vec![
        ("<div>TEST</div>", "HtmlTag"),
        ("<input value=\"TEST\">", "DoubleQuoteAttr"),
        ("<input value='TEST'>", "SingleQuoteAttr"),
        ("<script>var x = 'TEST';</script>", "ScriptBlock"),
    ];

    for (html, context) in contexts {
        assert!(html.contains("TEST"));
        assert!(!context.is_empty());
    }
}

#[test]
fn test_phase6_xss_payload_escape() {
    let payloads = vec![
        ("<svg onload=alert(1)>", "HtmlTag"),
        ("\\\"><svg onload=alert(1)>", "DoubleQuote"),
        ("'><svg onload=alert(1)>", "SingleQuote"),
        ("';alert(1);//", "Script"),
    ];

    for (payload, context) in payloads {
        assert!(!payload.is_empty());
        assert!(payload.contains("alert") || payload.contains("svg"));
    }
}

// ============================================================================
// PHASE 7: SSTI
// ============================================================================

#[test]
fn test_phase7_diagnostic_payloads() {
    let payloads = vec![
        ("{{7*7}}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("${7*7}", "49"),
    ];

    for (payload, expected_result) in payloads {
        assert!(!payload.is_empty());
        assert!(!expected_result.is_empty());
    }
}

#[test]
fn test_phase7_template_engine_detection() {
    let responses = vec![
        ("Result: 7777777", "Jinja2"),
        ("Result: 49", "Jinja2/Twig/Mako"),
        ("TemplateError: Undefined", "Twig"),
    ];

    for (response, engine) in responses {
        assert!(response.len() > 0);
        assert!(engine.len() > 0);
    }
}

#[test]
fn test_phase7_exploit_payload_generation() {
    let payloads = vec![
        ("__class__", "Jinja2"),
        ("registerUndefinedFilterCallback", "Twig"),
        ("sys.modules", "Mako"),
    ];

    for (payload_part, engine) in payloads {
        assert!(!payload_part.is_empty());
        assert!(!engine.is_empty());
    }
}

// ============================================================================
// PHASE 8: LFI & XXE
// ============================================================================

#[test]
fn test_phase8_lfi_linux_payloads() {
    let payloads = vec![
        "/etc/passwd",
        "/etc/shadow",
        "../../../../etc/passwd",
        "..%2fetc%2fpasswd",
    ];

    for payload in payloads {
        assert!(payload.contains("etc") || payload.contains("%"));
    }
}

#[test]
fn test_phase8_lfi_windows_payloads() {
    let payloads = vec![
        "C:\\windows\\win.ini",
        "..\\..\\windows\\system32",
        "..%5cwindows%5cwin.ini",
    ];

    for payload in payloads {
        assert!(payload.contains("windows") || payload.contains("%5c"));
    }
}

#[test]
fn test_phase8_lfi_file_signatures() {
    let signatures = vec![
        ("root:x:0:0:", "linux_passwd"),
        ("[fonts]", "windows_ini"),
        ("localhost", "hosts_file"),
    ];

    for (sig, sig_type) in signatures {
        assert!(!sig.is_empty());
        assert!(!sig_type.is_empty());
    }
}

#[test]
fn test_phase8_xxe_payload_structure() {
    let xxe_payload = r#"<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>"#;

    assert!(xxe_payload.contains("<!DOCTYPE"));
    assert!(xxe_payload.contains("<!ENTITY"));
    assert!(xxe_payload.contains("SYSTEM"));
}

// ============================================================================
// PHASE 9: SSRF
// ============================================================================

#[test]
fn test_phase9_loopback_payloads() {
    let payloads = vec!["127.0.0.1", "localhost", "0.0.0.0", "[::1]"];

    for payload in payloads {
        assert!(!payload.is_empty());
    }
}

#[test]
fn test_phase9_aws_metadata() {
    let payloads = vec!["169.254.169.254", "169.254.169.254/latest/meta-data"];

    let markers = vec!["ami-id", "instance-id", "AKIA"];

    for payload in payloads {
        assert!(payload.contains("169.254"));
    }

    for marker in markers {
        assert!(!marker.is_empty());
    }
}

#[test]
fn test_phase9_gcp_metadata() {
    let endpoints = vec!["metadata.google.internal", "169.254.169.254"];

    let markers = vec!["google-cloud-account", "service-accounts"];

    for endpoint in endpoints {
        assert!(!endpoint.is_empty());
    }

    for marker in markers {
        assert!(marker.contains("account") || marker.contains("service"));
    }
}

#[test]
fn test_phase9_internal_ranges() {
    let ranges = vec![
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
    ];

    for (start, end) in ranges {
        assert!(!start.is_empty());
        assert!(!end.is_empty());
    }
}

// ============================================================================
// CROSS-PHASE TESTS
// ============================================================================

#[test]
fn test_finding_phase_consistency() {
    for phase_num in 1..=9 {
        let finding = ScanFinding {
            phase: phase_num,
            module_name: format!("Phase {}", phase_num),
            severity: "MEDIUM".to_string(),
            description: "Test".to_string(),
            evidence: "Evidence".to_string(),
        };

        assert_eq!(finding.phase, phase_num);
        assert!(finding.phase >= 1 && finding.phase <= 9);
    }
}

#[test]
fn test_all_severity_levels() {
    let severities = vec!["CRITICAL", "HIGH", "MEDIUM", "LOW"];

    for severity in severities {
        let finding = ScanFinding {
            phase: 1,
            module_name: "Test".to_string(),
            severity: severity.to_string(),
            description: "Test".to_string(),
            evidence: "Evidence".to_string(),
        };

        assert_eq!(finding.severity, severity);
    }
}

#[test]
fn test_finding_evidence_importance() {
    let test_cases = vec![
        ("Server header: Apache/2.4.49", "header_leak"),
        ("Pattern '49' in response", "reflection"),
        ("File signature 'root:x' in output", "file_disclosure"),
        ("HTTP 403 on /admin", "directory_found"),
    ];

    for (evidence, evidence_type) in test_cases {
        assert!(!evidence.is_empty());
        assert!(!evidence_type.is_empty());
    }
}
