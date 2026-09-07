//! Process-level CLI boundaries for the opt-in WordPress evidence review.

#![cfg(feature = "wordpress-review")]

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    process::{Command, Output},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Instant,
};

use sha2::{Digest, Sha256};
use termivar_scanner::wordpress_review::{
    parse_wordpress_advisory_catalog, parse_wordpress_context,
};

fn termivar() -> Command {
    Command::new(env!("CARGO_BIN_EXE_termivar"))
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

struct TestServer {
    url: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
}

fn serve(body: &'static str) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let thread_connections = Arc::clone(&connections);
    let thread_requests = Arc::clone(&requests);
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(mut stream) = incoming else {
                break;
            };
            thread_connections.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 16 * 1024];
            let read = stream.read(&mut request).unwrap_or(0);
            let first_line = String::from_utf8_lossy(&request[..read])
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            thread_requests.lock().unwrap().push(first_line);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    TestServer {
        url: format!("http://{address}/"),
        connections,
        requests,
    }
}

fn run_with_input(server: &TestServer, flag: &str, path: &Path, report_directory: &Path) -> Output {
    termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--wordpress-review",
            flag,
        ])
        .arg(path)
        .arg("--report-dir")
        .arg(report_directory)
        .arg(&server.url)
        .output()
        .expect("termivar process must start")
}

#[test]
fn bounded_parser_cost_is_observed_without_becoming_a_timing_contract() {
    const ITERATIONS: usize = 64;
    let context = include_bytes!("../../../docs/examples/wordpress-review/context.synthetic.json");
    let catalogue =
        include_bytes!("../../../docs/examples/wordpress-review/advisories.synthetic.json");
    let started = Instant::now();
    let mut component_count = 0;
    let mut record_count = 0;
    for _ in 0..ITERATIONS {
        component_count += parse_wordpress_context(context).unwrap().components().len();
        record_count += parse_wordpress_advisory_catalog(catalogue)
            .unwrap()
            .records()
            .len();
    }
    let elapsed = started.elapsed();

    assert_eq!(component_count, ITERATIONS * 4);
    assert_eq!(record_count, ITERATIONS * 3);
    eprintln!(
        "wordpress_parser_observation iterations={ITERATIONS} input_bytes={} elapsed_ns={} timing_contract=false",
        context.len() + catalogue.len(),
        elapsed.as_nanos()
    );
}

#[test]
fn malformed_local_inputs_fail_before_runtime_and_never_echo_content_or_path() {
    for (flag, document, expected) in [
        (
            "--wordpress-context",
            br#"{"PRIVATE-WORDPRESS-DOCUMENT-5E12F9":"not a supported schema"}"#.as_slice(),
            "InvalidContext",
        ),
        (
            "--wordpress-advisories",
            br#"{"PRIVATE-WORDPRESS-DOCUMENT-5E12F9":"not a supported schema"}"#.as_slice(),
            "InvalidAdvisories",
        ),
        (
            "--wordpress-plugins-json",
            br#"[{"name":"one","name":"two","status":"active","version":"1.0"}]"#.as_slice(),
            "InvalidSavedInventory",
        ),
        (
            "--wordpress-themes-json",
            br#"[{"name":"example-theme","status":"active-network","version":"1.0"}]"#.as_slice(),
            "InvalidSavedInventory",
        ),
        (
            "--wordpress-core-version-file",
            b"6.9.4\nPRIVATE-WORDPRESS-DOCUMENT-5E12F9\n".as_slice(),
            "InvalidSavedInventory",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("PRIVATE-WORDPRESS-PATH-91A4C2.json");
        let report_directory = directory.path().join("must-not-be-reserved");
        std::fs::write(&input, document).unwrap();
        let server = serve("fixture");

        let output = run_with_input(&server, flag, &input, &report_directory);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(expected), "unexpected stderr: {stderr}");
        for forbidden in [
            "PRIVATE-WORDPRESS-DOCUMENT-5E12F9",
            "PRIVATE-WORDPRESS-PATH-91A4C2",
            "[ALPHA]",
        ] {
            assert!(!stderr.contains(forbidden), "stderr leaked {forbidden}");
        }
        assert_eq!(server.connections.load(Ordering::SeqCst), 0);
        assert!(server.requests.lock().unwrap().is_empty());
        assert!(!report_directory.exists());
    }
}

#[test]
fn non_local_inventory_path_is_rejected_before_output_reservation_or_runtime() {
    let server = serve("fixture");
    let directory = tempfile::tempdir().unwrap();
    let report_directory = directory.path().join("must-not-be-reserved");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-plugins-json",
            "https://PRIVATE-WORDPRESS-HOST/plugins.json",
            "--report-dir",
        ])
        .arg(&report_directory)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("PluginsSource"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("PRIVATE-WORDPRESS-HOST"));
    assert!(!stderr.contains("[ALPHA]"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!report_directory.exists());
}

#[test]
fn non_root_target_is_rejected_before_runtime_dispatch() {
    let server = serve("fixture");
    let target = format!("{}nested", server.url);
    let directory = tempfile::tempdir().unwrap();
    let missing_context = directory
        .path()
        .join("PRIVATE-MISSING-WORDPRESS-CONTEXT.json");
    let output = termivar()
        .args(["scan", "--profile", "web-review", "--wordpress-review"])
        .arg("--wordpress-context")
        .arg(&missing_context)
        .arg(&target)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("exact origin root target"));
    assert!(!stderr.contains("PRIVATE-MISSING-WORDPRESS-CONTEXT"));
    assert!(!stderr.contains("bounded regular local file"));
    assert!(!stderr.contains("[ALPHA]"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(server.requests.lock().unwrap().is_empty());
}

#[cfg(feature = "authorization-review")]
#[test]
fn wordpress_input_validation_precedes_secret_source_loading() {
    let directory = tempfile::tempdir().unwrap();
    let plugins = directory.path().join("PRIVATE-BAD-PLUGINS.json");
    let missing_secret = directory.path().join("PRIVATE-MISSING-SECRET.txt");
    std::fs::write(&plugins, br#"{"schema":"unsupported"}"#).unwrap();
    let server = serve("fixture");
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-plugins-json",
        ])
        .arg(&plugins)
        .arg("--auth-file")
        .arg(&missing_secret)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("InvalidSavedInventory"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("authorization-context input source"));
    assert!(!stderr.contains("PRIVATE-BAD-PLUGINS"));
    assert!(!stderr.contains("PRIVATE-MISSING-SECRET"));
    assert!(!stderr.contains("[ALPHA]"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn response_only_review_requires_no_local_files_and_reports_catalogue_gap() {
    let server = serve(
        r#"<meta name="generator" content="WordPress 6.9.4">
            <script src="/wp-content/plugins/example/app.js"></script>"#,
    );
    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--wordpress-review",
            &server.url,
        ])
        .output()
        .expect("termivar process must start");

    assert!(
        output.status.success(),
        "response-only stdout: {}\nresponse-only stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let document = serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .expect("response-only review must remain one JSON document");
    let audit = &document["wordpress_review"];
    assert_eq!(audit["catalog_status"], "catalogue_not_supplied");
    assert!(audit.get("catalog").is_none());
    assert!(audit["signal_count"].as_u64().unwrap() >= 2);
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["item_projected"], true);
    let wordpress_item = document["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["capability_id"] == "technology.wordpress-surface-observed@1")
        .unwrap();
    assert_eq!(
        wordpress_item["remediation"]["summary"],
        "Confirm the component inventory and consult an appropriate authoritative advisory source before making a security decision."
    );
}

#[test]
fn review_selection_adds_no_target_requests_and_keeps_progress_on_stderr() {
    const WORDPRESS_ROOT: &str = r#"<!doctype html><html><head>
        <meta name="generator" content="WordPress 6.9.4">
        <link rel="stylesheet" href="/wp-content/plugins/example/style.css">
        </head><body>fixture</body></html>"#;
    let without = serve(WORDPRESS_ROOT);
    let without_output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            &without.url,
        ])
        .output()
        .expect("termivar process must start");
    assert!(
        without_output.status.success(),
        "without-review stderr: {}",
        String::from_utf8_lossy(&without_output.stderr)
    );

    let with = serve(WORDPRESS_ROOT);
    let inputs = tempfile::tempdir().unwrap();
    let context = inputs
        .path()
        .join("PRIVATE-WORDPRESS-CONTEXT-PATH-7C20.json");
    let advisories = inputs
        .path()
        .join("PRIVATE-WORDPRESS-ADVISORY-PATH-8D31.json");
    std::fs::write(
        &context,
        format!(
            r#"{{"schema":"security.wordpress-context/v1","root":"{}","components":[]}}"#,
            with.url
        ),
    )
    .unwrap();
    std::fs::write(
        &advisories,
        r#"{"schema":"security.wordpress-advisory-catalog/v1","catalog":{"id":"synthetic-empty-catalog","revision":"r1","retrieved_on":"2026-09-06"},"records":[]}"#,
    )
    .unwrap();
    let with_output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--wordpress-review",
            "--progress",
        ])
        .arg("--wordpress-context")
        .arg(&context)
        .arg("--wordpress-advisories")
        .arg(&advisories)
        .arg(&with.url)
        .output()
        .expect("termivar process must start");
    assert!(
        with_output.status.success(),
        "with-review stdout: {}\nwith-review stderr: {}",
        String::from_utf8_lossy(&with_output.stdout),
        String::from_utf8_lossy(&with_output.stderr)
    );
    let document = serde_json::from_slice::<serde_json::Value>(&with_output.stdout)
        .expect("WordPress review stdout must remain one JSON document");
    let audit = &document["wordpress_review"];
    assert_eq!(audit["schema"], "security.wordpress-review-audit/v1");
    assert_eq!(audit["catalog_status"], "evaluated");
    assert_eq!(audit["catalog"]["id"], "synthetic-empty-catalog");
    assert_eq!(audit["additional_request_count"], 0);
    assert!(
        audit["signal_count"].as_u64().unwrap() >= 2,
        "WordPress signals were not retained: {document}"
    );
    assert_eq!(
        audit["item_projected"], true,
        "WordPress observation item was not projected: {document}"
    );
    let stderr = String::from_utf8(with_output.stderr).unwrap();
    assert!(stderr.contains("[ALPHA]"));
    assert!(!stderr.contains("example/style.css"));
    assert!(!stderr.contains("WordPress 6.9.4"));
    assert!(!stderr.contains("PRIVATE-WORDPRESS-CONTEXT-PATH-7C20"));
    assert!(!stderr.contains("PRIVATE-WORDPRESS-ADVISORY-PATH-8D31"));

    let without_requests = without.requests.lock().unwrap().clone();
    let with_requests = with.requests.lock().unwrap().clone();
    assert_eq!(
        without_requests,
        [
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "HEAD /wp-content/plugins/example/style.css HTTP/1.1",
        ]
        .map(str::to_owned)
    );
    assert_eq!(with_requests, without_requests);
    assert_eq!(
        with.connections.load(Ordering::SeqCst),
        without.connections.load(Ordering::SeqCst)
    );
}

#[test]
fn aggregate_saved_inventory_limit_fails_before_output_or_network() {
    let directory = tempfile::tempdir().unwrap();
    let plugins = directory.path().join("PRIVATE-LARGE-PLUGINS.json");
    let themes = directory.path().join("PRIVATE-LARGE-THEMES.json");
    fs::write(&plugins, vec![b' '; 600 * 1024]).unwrap();
    fs::write(&themes, vec![b' '; 600 * 1024]).unwrap();
    let report_directory = directory.path().join("must-not-be-reserved");
    let server = serve("fixture");

    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-plugins-json",
        ])
        .arg(&plugins)
        .arg("--wordpress-themes-json")
        .arg(&themes)
        .arg("--report-dir")
        .arg(&report_directory)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("InventoryTooLarge"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("PRIVATE-LARGE"));
    assert!(!stderr.contains("[ALPHA]"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!report_directory.exists());
}

#[test]
fn malformed_late_wordfence_record_fails_before_output_reservation_or_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let advisories = directory
        .path()
        .join("PRIVATE-WORDFENCE-LATE-FAILURE-55A1.json");
    let mut malformed = include_bytes!(
        "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
    )
    .to_vec();
    malformed.extend_from_slice(b" true PRIVATE-WORDFENCE-CONTENT-772B");
    fs::write(&advisories, &malformed).unwrap();
    let report_directory = directory.path().join("must-not-be-reserved");
    let server = serve("fixture");

    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-advisories",
        ])
        .arg(&advisories)
        .args([
            "--wordpress-advisories-format",
            "wordfence-v3-production",
            "--report-dir",
        ])
        .arg(&report_directory)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("InvalidAdvisories"),
        "unexpected stderr: {stderr}"
    );
    for forbidden in [
        "PRIVATE-WORDFENCE-LATE-FAILURE-55A1",
        "PRIVATE-WORDFENCE-CONTENT-772B",
        "[ALPHA]",
    ] {
        assert!(!stderr.contains(forbidden), "stderr leaked {forbidden}");
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!report_directory.exists());
}

#[test]
fn wordfence_production_bundle_is_source_qualified_offline_and_request_neutral() {
    const ROOT: &str = "<!doctype html><html><body>bounded fixture</body></html>";
    const PLUGINS: &[u8] =
        br#"[{"name":"termivar-fixture-component","status":"active","version":"1.1.0"}]"#;
    const WORDFENCE: &[u8] = include_bytes!(
        "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
    );

    let baseline_server = serve(ROOT);
    let baseline_directory = tempfile::tempdir().unwrap();
    let baseline_bundle = baseline_directory.path().join("baseline-assessment");
    let baseline = termivar()
        .args(["scan", "--profile", "web-review", "--report-dir"])
        .arg(&baseline_bundle)
        .arg(&baseline_server.url)
        .output()
        .expect("baseline process must start");
    assert!(
        baseline.status.success(),
        "baseline stdout: {}\nbaseline stderr: {}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );

    let server = serve(ROOT);
    let directory = tempfile::tempdir().unwrap();
    let plugins_path = directory.path().join("PRIVATE-WORDFENCE-PLUGINS-11A0.json");
    let advisories_path = directory
        .path()
        .join("PRIVATE-WORDFENCE-PRODUCTION-22B0.json");
    fs::write(&plugins_path, PLUGINS).unwrap();
    fs::write(&advisories_path, WORDFENCE).unwrap();
    let plugin_digest = sha256(PLUGINS);
    let advisory_digest = sha256(WORDFENCE);
    let bundle = directory.path().join("wordfence-assessment");

    let scan = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-plugins-json",
        ])
        .arg(&plugins_path)
        .arg("--wordpress-advisories")
        .arg(&advisories_path)
        .args([
            "--wordpress-advisories-format",
            "wordfence-v3-production",
            "--report-dir",
        ])
        .arg(&bundle)
        .arg(&server.url)
        .output()
        .expect("Wordfence production review process must start");
    assert!(
        scan.status.success(),
        "scan stdout: {}\nscan stderr: {}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(scan.stdout.is_empty());
    assert_eq!(fs::read(&plugins_path).unwrap(), PLUGINS);
    assert_eq!(fs::read(&advisories_path).unwrap(), WORDFENCE);
    assert_eq!(sha256(&fs::read(&plugins_path).unwrap()), plugin_digest);
    assert_eq!(
        sha256(&fs::read(&advisories_path).unwrap()),
        advisory_digest
    );

    let assessment_bytes = fs::read(bundle.join("assessment.json")).unwrap();
    let assessment: serde_json::Value = serde_json::from_slice(&assessment_bytes).unwrap();
    let audit = &assessment["wordpress_review"];
    assert_eq!(audit["schema"], "security.wordpress-review-audit/v4");
    assert_eq!(audit["catalog_status"], "evaluated");
    let external = &audit["external_review"];
    assert_eq!(external["source_namespace"], "wordfence-intelligence");
    assert_eq!(external["source_format"], "wordfence-v3-production");
    assert_eq!(
        external["mapping_revision"],
        "termivar-wordfence-v3-production/v1"
    );
    assert_eq!(
        external["comparison_policy"],
        "wordfence-v3/source-semantics-unresolved/v1"
    );
    assert_eq!(external["input"]["byte_length"], WORDFENCE.len());
    assert_eq!(external["input"]["sha256"], advisory_digest);
    assert_eq!(external["counts"]["parsed_records"], 2);
    assert_eq!(external["counts"]["software_associations"], 3);
    assert_eq!(external["counts"]["selected_associations"], 1);
    assert_eq!(external["counts"]["evaluable_associations"], 0);
    assert_eq!(external["counts"]["unsupported_associations"], 1);
    assert_eq!(external["counts"]["excluded_associations"], 2);
    assert_eq!(external["notices"].as_array().unwrap().len(), 1);
    let evaluation = &external["evaluations"][0];
    assert_eq!(evaluation["key"]["component"]["kind"], "plugin");
    assert_eq!(
        evaluation["key"]["component"]["slug"],
        "termivar-fixture-component"
    );
    assert_eq!(
        evaluation["version_relation"],
        "source_comparison_semantics_unresolved"
    );
    assert_eq!(evaluation["applicability"], "indeterminate_unsupported");
    assert_eq!(
        evaluation["execution"]["exploit_execution"],
        "not_performed"
    );
    assert_eq!(
        evaluation["execution"]["impact_validation"],
        "not_performed"
    );

    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(
        requests_after_scan,
        ["GET / HTTP/1.1", "GET / HTTP/1.1", "GET / HTTP/1.1"].map(str::to_owned),
        "fixture request trace changed"
    );
    assert_eq!(
        requests_after_scan,
        baseline_server.requests.lock().unwrap().clone(),
        "offline Wordfence ingestion must not change target request selection"
    );
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .output()
        .expect("bundle verifier must start");
    assert!(
        verify.status.success(),
        "verify stdout: {}\nverify stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = bundle.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("report compare must start");
    assert!(
        compare.status.success(),
        "compare stdout: {}\ncompare stderr: {}",
        String::from_utf8_lossy(&compare.stdout),
        String::from_utf8_lossy(&compare.stderr)
    );
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline Verify and Compare must not contact the target"
    );

    let private_directory = directory.path().to_string_lossy().into_owned();
    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        let rendered_bytes = fs::read(bundle.join(name)).unwrap();
        let rendered = String::from_utf8_lossy(&rendered_bytes);
        for forbidden in [
            "PRIVATE-WORDFENCE-PLUGINS-11A0",
            "PRIVATE-WORDFENCE-PRODUCTION-22B0",
            private_directory.as_str(),
        ] {
            assert!(!rendered.contains(forbidden), "{name} leaked {forbidden}");
        }
    }
}

#[test]
fn saved_inventory_bundle_is_path_free_preserves_inputs_and_adds_no_requests() {
    const ROOT: &str = "<!doctype html><html><body>bounded fixture</body></html>";
    const PLUGINS: &[u8] = br#"[
      {"name":"synthetic-active-plugin","status":"active","version":"1.4.0"},
      {"name":"synthetic-inactive-plugin","status":"inactive","version":"2.0"}
    ]"#;
    const THEMES: &[u8] =
        br#"[{"name":"synthetic-parent-theme","status":"parent","version":"3.2.1"}]"#;
    const CORE: &[u8] = b"6.9.4\r\n";
    const ADVISORIES: &[u8] = br#"{"schema":"security.wordpress-advisory-catalog/v1","catalog":{"id":"synthetic-saved-inventory-catalog","revision":"r1","retrieved_on":"2026-09-07"},"records":[]}"#;

    let baseline_server = serve(ROOT);
    let baseline_directory = tempfile::tempdir().unwrap();
    let baseline_bundle = baseline_directory.path().join("baseline-assessment");
    let baseline = termivar()
        .args(["scan", "--profile", "web-review", "--report-dir"])
        .arg(&baseline_bundle)
        .arg(&baseline_server.url)
        .output()
        .expect("baseline process must start");
    assert!(
        baseline.status.success(),
        "baseline stdout: {}\nbaseline stderr: {}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );

    let server = serve(ROOT);
    let directory = tempfile::tempdir().unwrap();
    let plugins_path = directory.path().join("PRIVATE-WP-PLUGINS-PATH-1910.json");
    let themes_path = directory.path().join("PRIVATE-WP-THEMES-PATH-2020.json");
    let core_path = directory.path().join("PRIVATE-WP-CORE-PATH-3030.txt");
    let advisories_path = directory
        .path()
        .join("PRIVATE-WP-ADVISORIES-PATH-4040.json");
    fs::write(&plugins_path, PLUGINS).unwrap();
    fs::write(&themes_path, THEMES).unwrap();
    fs::write(&core_path, CORE).unwrap();
    fs::write(&advisories_path, ADVISORIES).unwrap();
    let original_inputs = [
        (plugins_path.clone(), PLUGINS, sha256(PLUGINS)),
        (themes_path.clone(), THEMES, sha256(THEMES)),
        (core_path.clone(), CORE, sha256(CORE)),
        (advisories_path.clone(), ADVISORIES, sha256(ADVISORIES)),
    ];
    let bundle = directory.path().join("saved-inventory-assessment");

    let scan = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-plugins-json",
        ])
        .arg(&plugins_path)
        .arg("--wordpress-themes-json")
        .arg(&themes_path)
        .arg("--wordpress-core-version-file")
        .arg(&core_path)
        .arg("--wordpress-advisories")
        .arg(&advisories_path)
        .arg("--report-dir")
        .arg(&bundle)
        .arg(&server.url)
        .output()
        .expect("saved-inventory process must start");
    assert!(
        scan.status.success(),
        "scan stdout: {}\nscan stderr: {}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(scan.stdout.is_empty());

    for (path, expected_bytes, expected_digest) in &original_inputs {
        let observed = fs::read(path).unwrap();
        assert_eq!(observed, *expected_bytes);
        assert_eq!(sha256(&observed), *expected_digest);
    }
    let assessment_bytes = fs::read(bundle.join("assessment.json")).unwrap();
    let assessment: serde_json::Value = serde_json::from_slice(&assessment_bytes).unwrap();
    let audit = &assessment["wordpress_review"];
    assert_eq!(audit["schema"], "security.wordpress-review-audit/v3");
    assert_eq!(audit["catalog_status"], "evaluated");
    assert_eq!(audit["catalog"]["id"], "synthetic-saved-inventory-catalog");
    assert_eq!(audit["signal_count"], 0);
    assert_eq!(audit["evidence_reference_count"], 0);
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["item_projected"], false);
    assert_eq!(audit["inventory_import"]["component_count"], 4);
    assert_eq!(audit["inventory_import"]["coverage"]["plugins"], "supplied");
    assert_eq!(audit["inventory_import"]["coverage"]["themes"], "supplied");
    assert_eq!(audit["inventory_import"]["coverage"]["core"], "supplied");

    let inputs = audit["inventory_import"]["inputs"].as_array().unwrap();
    assert_eq!(inputs.len(), 3);
    for (class, bytes) in [
        ("wp_cli_plugins_json", PLUGINS),
        ("wp_cli_themes_json", THEMES),
        ("wp_cli_core_version_file", CORE),
    ] {
        let input = inputs
            .iter()
            .find(|input| input["class"] == class)
            .unwrap_or_else(|| panic!("missing provenance class {class}"));
        assert_eq!(input["byte_length"], bytes.len());
        assert_eq!(input["sha256"], sha256(bytes));
    }
    for (slug, version) in [
        ("wordpress", "6.9.4"),
        ("synthetic-active-plugin", "1.4.0"),
        ("synthetic-inactive-plugin", "2.0"),
        ("synthetic-parent-theme", "3.2.1"),
    ] {
        let component = audit["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["identity"]["slug"] == slug)
            .unwrap_or_else(|| panic!("missing saved component {slug}"));
        assert!(component["versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| {
                entry["value"] == version
                    && entry["source"] == "operator_context"
                    && entry["confidence"] == "operator_assertion"
            }));
    }

    let private_directory = directory.path().to_string_lossy().into_owned();
    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        let rendered_bytes = fs::read(bundle.join(name)).unwrap();
        let rendered = String::from_utf8_lossy(&rendered_bytes);
        for forbidden in [
            "PRIVATE-WP-PLUGINS-PATH-1910",
            "PRIVATE-WP-THEMES-PATH-2020",
            "PRIVATE-WP-CORE-PATH-3030",
            "PRIVATE-WP-ADVISORIES-PATH-4040",
            private_directory.as_str(),
        ] {
            assert!(!rendered.contains(forbidden), "{name} leaked {forbidden}");
        }
    }

    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(
        requests_after_scan,
        baseline_server.requests.lock().unwrap().clone(),
        "saved local inventory must not change target request selection"
    );
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .output()
        .expect("bundle verifier must start");
    assert!(
        verify.status.success(),
        "verify stdout: {}\nverify stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = bundle.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("report compare must start");
    assert!(
        compare.status.success(),
        "compare stdout: {}\ncompare stderr: {}",
        String::from_utf8_lossy(&compare.stdout),
        String::from_utf8_lossy(&compare.stderr)
    );
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline report tools must not contact the target"
    );
}

#[test]
fn real_bundle_retains_declared_match_and_indeterminate_results_for_offline_tools() {
    const WORDPRESS_ROOT: &str = r#"<!doctype html><html><head>
        <meta name="generator" content="WordPress 6.9.4">
        <link rel="stylesheet" href="/wp-content/plugins/synthetic-active-plugin/style.css">
        </head><body>bounded fixture</body></html>"#;
    let server = serve(WORDPRESS_ROOT);
    let directory = tempfile::tempdir().unwrap();
    let context_path = directory.path().join("PRIVATE-WORDPRESS-CONTEXT.json");
    let catalogue_path = directory.path().join("PRIVATE-WORDPRESS-CATALOGUE.json");
    let bundle = directory.path().join("wordpress-assessment");
    let context = include_str!("../../../docs/examples/wordpress-review/context.synthetic.json")
        .replace("https://example.test/", &server.url);
    fs::write(&context_path, context).unwrap();
    fs::write(
        &catalogue_path,
        include_bytes!("../../../docs/examples/wordpress-review/advisories.synthetic.json"),
    )
    .unwrap();

    let scan = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-context",
        ])
        .arg(&context_path)
        .arg("--wordpress-advisories")
        .arg(&catalogue_path)
        .arg("--report-dir")
        .arg(&bundle)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");
    assert!(
        scan.status.success(),
        "scan stderr: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(scan.stdout.is_empty());

    let mut names = fs::read_dir(&bundle)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        ["assessment.html", "assessment.json", "manifest.json"]
    );
    let assessment_bytes = fs::read(bundle.join("assessment.json")).unwrap();
    let assessment: serde_json::Value = serde_json::from_slice(&assessment_bytes).unwrap();
    let audit = &assessment["wordpress_review"];
    let advisories = audit["advisories"].as_array().unwrap();
    let result = |id: &str| {
        advisories
            .iter()
            .find(|advisory| advisory["id"] == id)
            .unwrap()
    };
    let matched = result("SYNTHETIC-PLUGIN-MATCH-0001");
    assert_eq!(
        matched["applicability"],
        "candidate_match_on_declared_facts"
    );
    assert_eq!(
        matched["source"]["reference"],
        "https://example.invalid/termivar/synthetic/plugin-match-0001"
    );
    assert_eq!(
        matched["prerequisites"][0]["outcome"],
        "matched_on_supplied_facts"
    );
    let unsupported = result("SYNTHETIC-PLUGIN-UNSUPPORTED-VERSION-0001");
    assert_eq!(unsupported["applicability"], "indeterminate_unsupported");
    assert_eq!(unsupported["version_relation"], "unsupported");
    assert_eq!(unsupported["prerequisites"][0]["outcome"], "unknown");
    let components = audit["components"].as_array().unwrap();
    for (slug, version) in [
        ("synthetic-active-plugin", "1.4.0"),
        ("synthetic-prerelease-plugin", "2.4.0-beta1"),
    ] {
        let component = components
            .iter()
            .find(|component| component["identity"]["slug"] == slug)
            .unwrap();
        assert!(component["versions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["value"] == version && entry["source"] == "operator_context" }));
    }
    assert!(advisories.iter().all(|advisory| {
        advisory["exploit_execution"] == "not_performed"
            && advisory["impact_validation"] == "not_performed"
    }));
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["item_projected"], true);
    assert_eq!(
        assessment["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| { item["capability_id"] == "technology.wordpress-surface-observed@1" })
            .count(),
        1
    );

    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        let bytes = fs::read(bundle.join(name)).unwrap();
        let rendered = String::from_utf8_lossy(&bytes);
        assert!(!rendered.contains("PRIVATE-WORDPRESS-CONTEXT"));
        assert!(!rendered.contains("PRIVATE-WORDPRESS-CATALOGUE"));
        assert!(!rendered.contains(&directory.path().to_string_lossy().to_string()));
    }
    let requests_after_scan = server.requests.lock().unwrap().clone();
    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .output()
        .expect("bundle verifier must start");
    assert!(
        verify.status.success(),
        "verify stderr: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = bundle.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("report compare must start");
    assert!(
        compare.status.success(),
        "compare stderr: {}",
        String::from_utf8_lossy(&compare.stderr)
    );
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan
    );
}

#[test]
fn profiled_catalogue_bundle_keeps_explicit_semantics_and_offline_tools_request_free() {
    const WORDPRESS_ROOT: &str = r#"<!doctype html><html><head>
        <meta name="generator" content="WordPress 6.9.4">
        <link rel="stylesheet" href="/wp-content/plugins/synthetic-prerelease-plugin/style.css">
        </head><body>bounded profile fixture</body></html>"#;
    const EXPECTED_REQUESTS: [&str; 4] = [
        "GET / HTTP/1.1",
        "GET / HTTP/1.1",
        "GET / HTTP/1.1",
        "HEAD /wp-content/plugins/synthetic-prerelease-plugin/style.css HTTP/1.1",
    ];

    let server = serve(WORDPRESS_ROOT);
    let directory = tempfile::tempdir().unwrap();
    let context_path = directory
        .path()
        .join("PRIVATE-WORDPRESS-PROFILE-CONTEXT.json");
    let catalogue_path = directory
        .path()
        .join("PRIVATE-WORDPRESS-PROFILE-CATALOGUE.json");
    let bundle = directory.path().join("wordpress-profile-assessment");
    let context =
        include_str!("../../../docs/examples/wordpress-review/context.profiles.synthetic.json")
            .replace("https://example.test/", &server.url);
    fs::write(&context_path, context).unwrap();
    fs::write(
        &catalogue_path,
        include_bytes!(
            "../../../docs/examples/wordpress-review/advisories.profiles.synthetic.json"
        ),
    )
    .unwrap();

    let scan = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-context",
        ])
        .arg(&context_path)
        .arg("--wordpress-advisories")
        .arg(&catalogue_path)
        .arg("--report-dir")
        .arg(&bundle)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");
    assert!(
        scan.status.success(),
        "scan stdout: {}\nscan stderr: {}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(scan.stdout.is_empty());

    let assessment_bytes = fs::read(bundle.join("assessment.json")).unwrap();
    let assessment: serde_json::Value = serde_json::from_slice(&assessment_bytes).unwrap();
    let audit = &assessment["wordpress_review"];
    assert_eq!(audit["schema"], "security.wordpress-review-audit/v2");
    assert_eq!(audit["catalog_status"], "evaluated");
    assert_eq!(
        audit["catalog"]["id"],
        "termivar-synthetic-wordpress-profile-example"
    );
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(audit["item_projected"], true);

    let advisories = audit["advisories"].as_array().unwrap();
    assert_eq!(advisories.len(), 5);
    let result = |id: &str| {
        advisories
            .iter()
            .find(|advisory| advisory["id"] == id)
            .unwrap_or_else(|| panic!("missing profiled advisory {id}"))
    };
    let assert_profiled = |id: &str,
                           profile: &str,
                           resolution: &str,
                           reason: &str,
                           relation: &str,
                           applicability: &str| {
        let advisory = result(id);
        assert_eq!(advisory["comparison_profile"], profile, "{id}");
        assert_eq!(advisory["version_resolution"], resolution, "{id}");
        assert_eq!(advisory["version_resolution_reason"], reason, "{id}");
        assert_eq!(advisory["version_relation"], relation, "{id}");
        assert_eq!(advisory["applicability"], applicability, "{id}");
        assert_eq!(advisory["exploit_execution"], "not_performed", "{id}");
        assert_eq!(advisory["impact_validation"], "not_performed", "{id}");
    };

    assert_profiled(
        "SYNTHETIC-BETA-NUMERIC-0001",
        "numeric-dotted/v1",
        "unsupported",
        "unsupported_version_evidence",
        "unsupported",
        "indeterminate_unsupported",
    );
    assert_eq!(
        result("SYNTHETIC-BETA-NUMERIC-0001")["prerequisites"][0]["outcome"],
        "matched_on_supplied_facts"
    );
    assert_profiled(
        "SYNTHETIC-BETA-PHP-SUBSET-0001",
        "php-release-subset/v1",
        "supported_equivalent",
        "single_supported_version",
        "within_declared_range",
        "candidate_match_on_declared_facts",
    );
    assert_eq!(
        result("SYNTHETIC-BETA-PHP-SUBSET-0001")["prerequisites"][0]["outcome"],
        "matched_on_supplied_facts"
    );
    assert_profiled(
        "SYNTHETIC-TRAILING-ZERO-NUMERIC-0001",
        "numeric-dotted/v1",
        "supported_equivalent",
        "single_supported_version",
        "within_declared_range",
        "candidate_match_on_declared_facts",
    );
    assert_profiled(
        "SYNTHETIC-TRAILING-ZERO-PHP-SUBSET-0001",
        "php-release-subset/v1",
        "supported_equivalent",
        "single_supported_version",
        "outside_declared_ranges",
        "contradicted_by_declared_facts",
    );
    assert_profiled(
        "SYNTHETIC-VENDOR-LABEL-UNSUPPORTED-0001",
        "php-release-subset/v1",
        "unsupported",
        "unsupported_version_evidence",
        "unsupported",
        "indeterminate_unsupported",
    );

    assert_eq!(
        assessment["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|item| item["capability_id"] == "technology.wordpress-surface-observed@1")
            .count(),
        1
    );
    for name in ["assessment.html", "assessment.json", "manifest.json"] {
        let bytes = fs::read(bundle.join(name)).unwrap();
        let rendered = String::from_utf8_lossy(&bytes);
        assert!(!rendered.contains("PRIVATE-WORDPRESS-PROFILE-CONTEXT"));
        assert!(!rendered.contains("PRIVATE-WORDPRESS-PROFILE-CATALOGUE"));
        assert!(!rendered.contains(&directory.path().to_string_lossy().to_string()));
    }
    let html = fs::read_to_string(bundle.join("assessment.html")).unwrap();
    for expected in [
        "security.wordpress-review-audit/v2",
        "numeric-dotted/v1",
        "php-release-subset/v1",
        "unsupported_version_evidence",
        "single_supported_version",
        "not_performed",
    ] {
        assert!(html.contains(expected), "HTML omitted {expected}");
    }

    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(
        requests_after_scan,
        EXPECTED_REQUESTS.map(str::to_owned),
        "profile selection must not add target requests"
    );

    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .output()
        .expect("bundle verifier must start");
    assert!(
        verify.status.success(),
        "verify stdout: {}\nverify stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = bundle.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("report compare must start");
    assert!(
        compare.status.success(),
        "compare stdout: {}\ncompare stderr: {}",
        String::from_utf8_lossy(&compare.stdout),
        String::from_utf8_lossy(&compare.stderr)
    );
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline report commands must not contact the target"
    );
}

#[test]
fn wordfence_production_bundle_is_source_qualified_and_offline_tools_preserve_requests() {
    const WORDPRESS_ROOT: &str = r#"<!doctype html><html><head>
        <meta name="generator" content="WordPress 1.0">
        <link rel="stylesheet" href="/wp-content/plugins/termivar-fixture-component/style.css">
        <link rel="stylesheet" href="/wp-content/themes/termivar-fixture-component/style.css">
        </head><body>bounded external-source fixture</body></html>"#;
    const PLUGINS: &[u8] =
        br#"[{"name":"termivar-fixture-component","status":"active","version":"1.1.0"}]"#;
    const THEMES: &[u8] =
        br#"[{"name":"termivar-fixture-component","status":"active","version":"2.9.0"}]"#;
    const CORE: &[u8] = b"1.0\r\n";
    const EXPECTED_REQUESTS: [&str; 5] = [
        "GET / HTTP/1.1",
        "GET / HTTP/1.1",
        "GET / HTTP/1.1",
        "HEAD /wp-content/plugins/termivar-fixture-component/style.css HTTP/1.1",
        "HEAD /wp-content/themes/termivar-fixture-component/style.css HTTP/1.1",
    ];
    const EXACT_SOURCE_SHA256: &str =
        "d9ed3140f44ae1e0a3746beb9937de2d829d28c068101120a9104c3349901db7";

    let baseline_server = serve(WORDPRESS_ROOT);
    let baseline_directory = tempfile::tempdir().unwrap();
    let baseline_bundle = baseline_directory.path().join("baseline-assessment");
    let baseline = termivar()
        .args(["scan", "--profile", "web-review", "--report-dir"])
        .arg(&baseline_bundle)
        .arg(&baseline_server.url)
        .output()
        .expect("baseline process must start");
    assert!(
        baseline.status.success(),
        "baseline stdout: {}\nbaseline stderr: {}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );

    let server = serve(WORDPRESS_ROOT);
    let directory = tempfile::tempdir().unwrap();
    let plugins_path = directory.path().join("PRIVATE-WORDFENCE-PLUGINS.json");
    let themes_path = directory.path().join("PRIVATE-WORDFENCE-THEMES.json");
    let core_path = directory.path().join("PRIVATE-WORDFENCE-CORE.txt");
    fs::write(&plugins_path, PLUGINS).unwrap();
    fs::write(&themes_path, THEMES).unwrap();
    fs::write(&core_path, CORE).unwrap();
    let source_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json");
    let source_before = fs::read(&source_path).unwrap();
    assert_eq!(source_before.len(), 3_883);
    assert_eq!(sha256(&source_before), EXACT_SOURCE_SHA256);
    let bundle = directory.path().join("wordfence-assessment");

    let scan = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--format",
            "json",
            "--wordpress-review",
            "--progress",
            "--wordpress-plugins-json",
        ])
        .arg(&plugins_path)
        .arg("--wordpress-themes-json")
        .arg(&themes_path)
        .arg("--wordpress-core-version-file")
        .arg(&core_path)
        .arg("--wordpress-advisories")
        .arg(&source_path)
        .args([
            "--wordpress-advisories-format",
            "wordfence-v3-production",
            "--report-dir",
        ])
        .arg(&bundle)
        .arg(&server.url)
        .output()
        .expect("Wordfence Production process must start");
    assert!(
        scan.status.success(),
        "scan stdout: {}\nscan stderr: {}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
    assert!(scan.stdout.is_empty());
    let stderr = String::from_utf8(scan.stderr).unwrap();
    assert!(stderr.contains("[ALPHA]"));
    for forbidden in [
        "PRIVATE-WORDFENCE-PLUGINS",
        "PRIVATE-WORDFENCE-THEMES",
        "PRIVATE-WORDFENCE-CORE",
        &directory.path().to_string_lossy(),
    ] {
        assert!(!stderr.contains(forbidden), "stderr leaked {forbidden}");
    }

    assert_eq!(fs::read(&source_path).unwrap(), source_before);
    assert_eq!(fs::read(&plugins_path).unwrap(), PLUGINS);
    assert_eq!(fs::read(&themes_path).unwrap(), THEMES);
    assert_eq!(fs::read(&core_path).unwrap(), CORE);
    let assessment_bytes = fs::read(bundle.join("assessment.json")).unwrap();
    let assessment: serde_json::Value = serde_json::from_slice(&assessment_bytes).unwrap();
    let audit = &assessment["wordpress_review"];
    assert_eq!(audit["schema"], "security.wordpress-review-audit/v4");
    assert_eq!(audit["catalog_status"], "evaluated");
    assert!(audit.get("catalog").is_none());
    assert_eq!(audit["additional_request_count"], 0);
    assert_eq!(
        audit["external_review"]["source_namespace"],
        "wordfence-intelligence"
    );
    assert_eq!(
        audit["external_review"]["source_format"],
        "wordfence-v3-production"
    );
    assert_eq!(
        audit["external_review"]["mapping_revision"],
        "termivar-wordfence-v3-production/v1"
    );
    assert_eq!(
        audit["external_review"]["comparison_policy"],
        "wordfence-v3/source-semantics-unresolved/v1"
    );
    assert_eq!(audit["external_review"]["input"]["byte_length"], 3_883);
    assert_eq!(
        audit["external_review"]["input"]["sha256"],
        EXACT_SOURCE_SHA256
    );
    let counts = &audit["external_review"]["counts"];
    assert_eq!(counts["parsed_records"], 2);
    assert_eq!(counts["software_associations"], 3);
    assert_eq!(counts["selected_associations"], 3);
    assert_eq!(counts["evaluable_associations"], 0);
    assert_eq!(counts["unsupported_associations"], 3);
    assert_eq!(counts["excluded_associations"], 0);
    let evaluations = audit["external_review"]["evaluations"].as_array().unwrap();
    assert_eq!(evaluations.len(), 3);
    assert!(evaluations.iter().all(|entry| {
        entry["version_relation"] == "source_comparison_semantics_unresolved"
            && entry["applicability"] == "indeterminate_unsupported"
            && entry["execution"]["exploit_execution"] == "not_performed"
            && entry["execution"]["impact_validation"] == "not_performed"
            && entry["record_reference"]
                .as_str()
                .is_some_and(|reference| reference.starts_with("https://example.invalid/"))
    }));
    let plugin = evaluations
        .iter()
        .find(|entry| {
            entry["key"]["component"]["kind"] == "plugin"
                && entry["key"]["component"]["slug"] == "termivar-fixture-component"
        })
        .unwrap();
    assert_eq!(
        plugin["version_evidence_resolution"]["status"],
        "single_declaration"
    );
    assert_eq!(
        plugin["version_evidence_resolution"]["evidence_row_count"],
        1
    );
    assert_eq!(
        plugin["version_evidence_resolution"]["distinct_spelling_count"],
        1
    );
    assert!(evaluations.iter().any(|entry| {
        entry["key"]["component"]["kind"] == "theme"
            && entry["key"]["component"]["slug"] == "termivar-fixture-component"
    }));
    let core = evaluations
        .iter()
        .find(|entry| entry["key"]["component"]["kind"] == "core")
        .unwrap();
    assert_eq!(
        core["version_evidence_resolution"]["status"],
        "repeated_exact_declaration"
    );
    assert_eq!(core["version_evidence_resolution"]["evidence_row_count"], 2);
    assert_eq!(
        core["version_evidence_resolution"]["distinct_spelling_count"],
        1
    );
    assert_eq!(
        audit["external_review"]["notices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let html = fs::read_to_string(bundle.join("assessment.html")).unwrap();
    assert!(html.contains("External source attribution"));
    assert!(
        html.contains("href=\"https://example.invalid/termivar/wordfence-v3/fixture-advisory-1\"")
    );
    assert!(html.contains("original synthetic fixture notice"));
    assert!(html.contains("fictional fixture text may be copied"));

    let requests_after_scan = server.requests.lock().unwrap().clone();
    assert_eq!(
        requests_after_scan,
        EXPECTED_REQUESTS.map(str::to_owned),
        "fixture request trace changed"
    );
    assert_eq!(
        requests_after_scan,
        baseline_server.requests.lock().unwrap().clone(),
        "external advisory interpretation must not add target requests"
    );

    let verify = termivar()
        .args(["report", "verify", "--dir"])
        .arg(&bundle)
        .args(["--format", "json"])
        .output()
        .expect("bundle verifier must start");
    assert!(
        verify.status.success(),
        "verify stdout: {}\nverify stderr: {}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verification: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verification["status"], "integrity_match");

    let assessment_path = bundle.join("assessment.json");
    let compare = termivar()
        .args(["report", "compare", "--before"])
        .arg(&assessment_path)
        .arg("--after")
        .arg(&assessment_path)
        .args(["--same-scope", "--format", "json"])
        .output()
        .expect("report compare must start");
    assert!(
        compare.status.success(),
        "compare stdout: {}\ncompare stderr: {}",
        String::from_utf8_lossy(&compare.stdout),
        String::from_utf8_lossy(&compare.stderr)
    );
    let comparison: serde_json::Value = serde_json::from_slice(&compare.stdout).unwrap();
    assert_eq!(comparison["schema"], "termivar-report-comparison/v1");
    assert_eq!(
        comparison["unchanged"].as_array().unwrap().len(),
        assessment["item_count"].as_u64().unwrap() as usize
    );
    for group in ["only_in_after", "only_in_before", "changed"] {
        assert!(comparison[group].as_array().unwrap().is_empty());
    }
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        requests_after_scan,
        "offline verification and comparison must not contact the target"
    );
}

#[test]
fn malformed_declared_wordfence_input_fails_before_runtime_or_bundle_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("PRIVATE-WORDFENCE-SOURCE.json");
    let report_directory = directory.path().join("must-not-be-reserved");
    fs::write(
        &input,
        br#"{"00000000-0000-4000-8000-000000000001":{"id":"different"}}"#,
    )
    .unwrap();
    let server = serve("fixture");

    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-advisories",
        ])
        .arg(&input)
        .args([
            "--wordpress-advisories-format",
            "wordfence-v3-production",
            "--report-dir",
        ])
        .arg(&report_directory)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("InvalidAdvisories"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("PRIVATE-WORDFENCE-SOURCE"));
    assert!(!stderr.contains("different"));
    assert!(!stderr.contains("[ALPHA]"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!report_directory.exists());
}

#[test]
fn missing_defiant_record_link_fails_before_runtime_or_bundle_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory
        .path()
        .join("PRIVATE-WORDFENCE-RIGHTS-SOURCE.json");
    let report_directory = directory.path().join("must-not-be-reserved");
    let source = include_str!(
        "../../../docs/examples/wordpress-review/wordfence-v3/production.synthetic.json"
    )
    .replace("termivar_fixture_author", "defiant");
    fs::write(&input, source).unwrap();
    let server = serve("fixture");

    let output = termivar()
        .args([
            "scan",
            "--profile",
            "web-review",
            "--wordpress-review",
            "--wordpress-advisories",
        ])
        .arg(&input)
        .args([
            "--wordpress-advisories-format",
            "wordfence-v3-production",
            "--report-dir",
        ])
        .arg(&report_directory)
        .arg(&server.url)
        .output()
        .expect("termivar process must start");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("InvalidAdvisories"),
        "unexpected stderr: {stderr}"
    );
    assert!(!stderr.contains("PRIVATE-WORDFENCE-RIGHTS-SOURCE"));
    assert!(!stderr.contains("example.invalid"));
    assert!(!stderr.contains("[ALPHA]"));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
    assert!(server.requests.lock().unwrap().is_empty());
    assert!(!report_directory.exists());
}
