//! Contract tests for the deterministic endpoint-scale measurement harness.

use std::ffi::OsString;

#[path = "../benches/endpoint_assessment_support/mod.rs"]
mod endpoint_assessment_support;

use endpoint_assessment_support::{
    parse_arguments_for_test, run_benchmark, run_fixture_benchmark,
    validate_proxy_environment_for_test, write_json_atomically, WorkloadSelection,
};

#[tokio::test]
async fn real_assessment_fixture_reconciles_complete_broker_receipts() {
    let report = run_fixture_benchmark(4, 1, 3).await.unwrap();
    assert_eq!(report.schema, "venom.endpoint-performance/v1");
    assert!(report.thresholds.is_none());
    assert_eq!(report.configuration.warmup_samples, 1);
    assert_eq!(report.configuration.measured_samples, 3);
    assert_eq!(report.configuration.runtime_concurrency, 1);
    assert_eq!(report.configuration.fixture_response_delay_ms, 1);
    assert_eq!(report.configuration.active_verifications_per_authority, 1);

    let workload = &report.workloads[0];
    assert_eq!(workload.endpoint_count, 4);
    assert_eq!(workload.total_requests, 6);
    assert_eq!(workload.requests_per_authority, [6]);
    assert_eq!(workload.authority_count, 1);
    assert_eq!(workload.profile, "web-review");
    assert_eq!(workload.samples.len(), 3);
    assert!(workload.samples.iter().all(|sample| {
        sample.total_requests == 6
            && sample.response_bytes > 0
            && sample.wall_time_ms > 0.0
            && sample.requests_per_second > 0.0
            && sample.p50_latency_ms <= sample.p95_latency_ms
            && sample.p95_latency_ms <= sample.p99_latency_ms
    }));
}

#[test]
fn production_workload_shapes_are_exact_and_ten_thousand_is_explicitly_partitioned() {
    let specs = WorkloadSelection::All.specs();
    assert_eq!(specs.len(), 3);
    assert_eq!(specs[0].id, "endpoints-100");
    assert_eq!(specs[0].endpoint_count(), 100);
    assert_eq!(specs[0].total_requests(), 102);
    assert_eq!(specs[1].id, "endpoints-1000");
    assert_eq!(specs[1].endpoint_count(), 1_000);
    assert_eq!(specs[1].total_requests(), 1_002);
    assert_eq!(specs[2].id, "requests-10000");
    assert_eq!(specs[2].endpoint_count(), 9_980);
    assert_eq!(specs[2].total_requests(), 10_000);
    assert_eq!(specs[2].authority_count(), 10);
    assert_eq!(specs[2].requests_per_authority(), [1_000; 10]);
}

#[test]
fn arguments_are_bounded_and_expose_no_target_surface() {
    endpoint_assessment_support::link_contract_test_surface();
    let parsed = parse_arguments_for_test([
        OsString::from("--workload"),
        OsString::from("100"),
        OsString::from("--warmups"),
        OsString::from("1"),
        OsString::from("--samples"),
        OsString::from("3"),
        OsString::from("--output"),
        OsString::from("report.json"),
    ])
    .unwrap();
    assert_eq!(parsed.selection(), WorkloadSelection::Endpoints100);
    assert_eq!(parsed.warmups(), 1);
    assert_eq!(parsed.samples(), 3);
    assert_eq!(
        parsed.output().unwrap(),
        std::path::Path::new("report.json")
    );
    assert!(!parsed.help_requested());
    assert!(endpoint_assessment_support::BenchmarkArguments::help().contains("127.0.0.1"));

    // Keep both process and library entrypoints type-checked in this shared
    // support module without executing the process-argument adapter here.
    let _process_entrypoint = endpoint_assessment_support::run_from_process_arguments;
    let _library_entrypoint = run_benchmark;

    for arguments in [
        vec!["--samples", "2"],
        vec!["--samples", "11"],
        vec!["--warmups", "0"],
        vec!["--warmups", "4"],
        vec!["--target", "https://example.test"],
        vec!["--workload", "public"],
    ] {
        assert!(parse_arguments_for_test(arguments.into_iter().map(OsString::from)).is_err());
    }
}

#[test]
fn proxy_configuration_fails_closed_without_echoing_its_value() {
    let secret_proxy = "http://proxy-user:PRIVATE_PROXY_SECRET@192.0.2.1:8080";
    let error = validate_proxy_environment_for_test([
        ("HTTP_PROXY", OsString::from(secret_proxy)),
        ("HTTPS_PROXY", OsString::new()),
    ])
    .unwrap_err();
    assert!(error.contains("HTTP_PROXY"));
    assert!(!error.contains(secret_proxy));
    assert!(!error.contains("PRIVATE_PROXY_SECRET"));
    assert!(validate_proxy_environment_for_test([
        ("HTTP_PROXY", OsString::new()),
        ("ALL_PROXY", OsString::new()),
    ])
    .is_ok());
}

#[tokio::test]
async fn report_write_is_complete_json_and_uses_a_sibling_temporary_file() {
    let report = run_fixture_benchmark(2, 1, 3).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("endpoint-performance.json");
    write_json_atomically(&output, &report).unwrap();
    let encoded = std::fs::read_to_string(&output).unwrap();
    let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded["schema"], "venom.endpoint-performance/v1");
    assert_eq!(decoded["thresholds"], serde_json::Value::Null);
    assert_eq!(
        decoded["workloads"][0]["samples"].as_array().unwrap().len(),
        3
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
