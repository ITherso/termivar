#![cfg(feature = "monitoring")]

use venom_scanner::{
    BenchmarkResult, BenchmarkSuite, CountComparison, DurationComparison, PerformanceAnalyzer,
    PhaseProfile, ScanProfile,
};

fn phase(number: u8, duration_ms: u64, findings: u64) -> PhaseProfile {
    PhaseProfile {
        phase_number: number,
        phase_name: format!("phase-{number}"),
        start_time: 1_000,
        end_time: 1_000 + duration_ms,
        duration_ms,
        requests_sent: 4,
        responses_received: 3,
        findings_discovered: findings,
        error_count: 1,
        response_time_samples_ms: vec![10, 20, 30],
    }
}

#[test]
fn profile_totals_and_statistics_come_from_raw_phases() {
    let mut profile = ScanProfile::new("scan".into());
    profile.add_phase(phase(1, 100, 1));
    profile.add_phase(phase(2, 200, 2));

    assert_eq!(profile.total_requests(), 8);
    assert_eq!(profile.total_responses(), 6);
    assert_eq!(profile.total_findings(), 3);
    assert_eq!(profile.total_errors(), 2);
    assert_eq!(profile.response_request_ratio_percent(), Some(75.0));
}

#[test]
fn zero_denominators_do_not_invent_percentages() {
    let empty = ScanProfile::new("empty".into());
    assert_eq!(empty.response_request_ratio_percent(), None);

    let mut no_responses = phase(1, 100, 0);
    no_responses.requests_sent = 0;
    no_responses.responses_received = 0;
    no_responses.response_time_samples_ms.clear();
    assert_eq!(no_responses.response_request_ratio_percent(), None);
    assert_eq!(no_responses.findings_per_100_responses(), None);
    assert_eq!(no_responses.mean_response_time_ms(), None);
}

#[test]
fn ties_are_preserved_instead_of_selecting_a_winner() {
    let mut profile = ScanProfile::new("tied".into());
    profile.add_phase(phase(1, 500, 3));
    profile.add_phase(phase(2, 500, 3));

    let slowest: Vec<_> = profile
        .slowest_phases()
        .into_iter()
        .map(|phase| phase.phase_number)
        .collect();
    let productive: Vec<_> = profile
        .most_productive_phases()
        .into_iter()
        .map(|phase| phase.phase_number)
        .collect();

    assert_eq!(slowest, vec![1, 2]);
    assert_eq!(productive, vec![1, 2]);
}

#[test]
fn comparison_reports_direction_and_ties_explicitly() {
    let mut catalog = PerformanceAnalyzer::new();
    let mut first = ScanProfile::new("first".into());
    first.total_duration_ms = 100;
    first.add_phase(phase(1, 100, 1));

    let mut second = ScanProfile::new("second".into());
    second.total_duration_ms = 150;
    second.add_phase(phase(1, 150, 3));

    catalog.record_profile(first).expect("valid profile");
    catalog.record_profile(second).expect("valid profile");
    let comparison = catalog.compare("first", "second").unwrap();

    assert_eq!(comparison.duration, DurationComparison::FirstFasterBy(50));
    assert_eq!(comparison.findings, CountComparison::SecondHigherBy(2));
    assert_eq!(
        comparison.response_request_ratio_difference_percentage_points,
        Some(0.0)
    );
    assert!(catalog.compare("first", "unknown").is_none());
}

#[test]
fn benchmark_statistics_are_calculated_not_declared() {
    let result = BenchmarkResult {
        benchmark_id: "fixture".into(),
        benchmark_name: "fixture benchmark".into(),
        duration_samples_micros: vec![100, 200, 300, 400],
    };

    assert_eq!(result.mean_duration_micros(), Some(250.0));
    assert_eq!(result.percentile_duration_micros(95.0), Some(400));
    assert_eq!(result.percentile_duration_micros(101.0), None);
}

#[test]
fn benchmark_catalog_applies_only_the_supplied_threshold() {
    let mut catalog = BenchmarkSuite::new();
    catalog.record_result(BenchmarkResult {
        benchmark_id: "fast".into(),
        benchmark_name: "fast".into(),
        duration_samples_micros: vec![10, 20],
    });
    catalog.record_result(BenchmarkResult {
        benchmark_id: "slow".into(),
        benchmark_name: "slow".into(),
        duration_samples_micros: vec![30, 40],
    });

    let selected = catalog.results_with_mean_above(25.0);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].benchmark_id, "slow");
}
