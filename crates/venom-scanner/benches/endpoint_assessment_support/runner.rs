use std::time::Instant;

use venom_scanner::{
    web_runtime::{
        ScanProfileV1, WebAssessmentCompletion, WebAssessmentLimits, WebAssessmentRuntime,
        WEB_ASSESSMENT_CONCURRENCY,
    },
    TransportDispatchOutcome,
};

use super::{
    fixture::LoopbackFixture,
    model::{
        require_proxy_free_environment, BenchmarkConfiguration, BenchmarkEnvironment,
        EndpointPerformanceReport, ProcessResources, SampleMeasurement, WorkloadReport,
        WorkloadSelection, WorkloadSpec, WorkloadSummary, ACTIVE_VERIFICATIONS_PER_AUTHORITY,
        ENDPOINT_PERFORMANCE_SCHEMA, FIXTURE_RESPONSE_DELAY_MS, MAX_MEASURED_SAMPLES,
        MAX_WARMUP_SAMPLES, MIN_MEASURED_SAMPLES, MIN_WARMUP_SAMPLES,
    },
};

pub(crate) async fn run_benchmark(
    selection: WorkloadSelection,
    warmups: u8,
    samples: u8,
) -> Result<EndpointPerformanceReport, String> {
    require_proxy_free_environment()?;
    validate_sample_counts(warmups, samples)?;
    let mut workloads = Vec::new();
    for spec in selection.specs() {
        workloads.push(run_workload(&spec, warmups, samples).await?);
    }
    Ok(report(warmups, samples, workloads))
}

#[cfg(test)]
pub(crate) async fn run_fixture_benchmark(
    subjects: usize,
    warmups: u8,
    samples: u8,
) -> Result<EndpointPerformanceReport, String> {
    require_proxy_free_environment()?;
    validate_sample_counts(warmups, samples)?;
    let workload = run_workload(&WorkloadSpec::fixture_test(subjects), warmups, samples).await?;
    Ok(report(warmups, samples, vec![workload]))
}

fn report(warmups: u8, samples: u8, workloads: Vec<WorkloadReport>) -> EndpointPerformanceReport {
    EndpointPerformanceReport {
        schema: ENDPOINT_PERFORMANCE_SCHEMA,
        environment: BenchmarkEnvironment::observed(),
        configuration: BenchmarkConfiguration {
            warmup_samples: warmups,
            measured_samples: samples,
            fixture: "hard-coded-127.0.0.1-http1",
            fixture_response_delay_ms: FIXTURE_RESPONSE_DELAY_MS,
            runtime_concurrency: WEB_ASSESSMENT_CONCURRENCY,
            active_verifications_per_authority: ACTIVE_VERIFICATIONS_PER_AUTHORITY,
            latency_source: "broker-dispatch-receipt-elapsed-ms",
        },
        process_resources: ProcessResources::default(),
        workloads,
        thresholds: None,
    }
}

fn validate_sample_counts(warmups: u8, samples: u8) -> Result<(), String> {
    if !(MIN_WARMUP_SAMPLES..=MAX_WARMUP_SAMPLES).contains(&warmups) {
        return Err(format!(
            "warmup count must be within {MIN_WARMUP_SAMPLES}..={MAX_WARMUP_SAMPLES}"
        ));
    }
    if !(MIN_MEASURED_SAMPLES..=MAX_MEASURED_SAMPLES).contains(&samples) {
        return Err(format!(
            "sample count must be within {MIN_MEASURED_SAMPLES}..={MAX_MEASURED_SAMPLES}"
        ));
    }
    Ok(())
}

async fn run_workload(
    spec: &WorkloadSpec,
    warmups: u8,
    samples: u8,
) -> Result<WorkloadReport, String> {
    for _ in 0..warmups {
        run_one_sample(spec, 0).await?;
    }
    let mut measurements = Vec::with_capacity(usize::from(samples));
    for sample_index in 1..=samples {
        measurements.push(run_one_sample(spec, sample_index).await?);
    }
    let summary = WorkloadSummary::from_samples(&measurements);
    Ok(WorkloadReport {
        id: spec.id,
        endpoint_count: spec.endpoint_count(),
        total_requests: spec.total_requests(),
        authority_count: spec.authority_count(),
        requests_per_authority: spec.requests_per_authority(),
        authority_model: if spec.authority_count() == 1 {
            "one-shared-authority"
        } else {
            "independent-authority-per-origin-assessment"
        },
        profile: "web-review",
        samples: measurements,
        summary,
    })
}

async fn run_one_sample(
    spec: &WorkloadSpec,
    sample_index: u8,
) -> Result<SampleMeasurement, String> {
    let mut fixtures = Vec::with_capacity(spec.authority_count());
    for subjects in spec.subjects_per_authority.iter().copied() {
        fixtures.push(LoopbackFixture::start(subjects).await?);
    }
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(spec.total_requests() as usize);
    let mut response_bytes = 0_u64;

    for (authority_index, subjects) in spec.subjects_per_authority.iter().copied().enumerate() {
        let expected_requests = u32::try_from(subjects.saturating_add(2))
            .map_err(|_| "workload request count exceeded u32".to_owned())?;
        let limits = limits_for(subjects, expected_requests)?;
        let profile = ScanProfileV1::web_review()
            .and_then(|profile| profile.with_limits(limits))
            .map_err(|error| format!("could not compose web-review profile: {error}"))?;
        let fixture = &fixtures[authority_index];
        let root = fixture.root();
        let mut runtime = WebAssessmentRuntime::builder(root.clone())
            .limits(profile.web_assessment_limits())
            .enable_low_risk_differential_review()
            .build()
            .map_err(|error| format!("could not compose web assessment runtime: {error}"))?;
        let report = runtime
            .analyze()
            .await
            .map_err(|error| format!("web assessment execution failed: {error}"))?;

        if report.authorized_root().url() != &root {
            return Err("assessment report changed the exact authorized root".to_owned());
        }
        if report.limits() != limits {
            return Err("assessment report did not retain the checked profile limits".to_owned());
        }
        if report.completion() != &WebAssessmentCompletion::Complete {
            return Err(format!(
                "assessment was not complete: {:?}",
                report.completion().reasons()
            ));
        }
        if report.subjects().len() != subjects
            || report
                .subjects()
                .iter()
                .any(|subject| !subject.was_executed() || subject.bootstrap().is_none())
        {
            return Err("assessment subject inventory was not completely executed".to_owned());
        }
        if !report.forms().is_empty() {
            return Err("fixture unexpectedly produced retained forms".to_owned());
        }
        let usage = report.usage();
        if usage.retained_subjects() != subjects
            || usage.executed_subjects() != subjects
            || usage.retained_forms() != 0
            || usage.total_requests() != expected_requests
            || usage.active_verifications() != ACTIVE_VERIFICATIONS_PER_AUTHORITY
            || usage.request_body_bytes() != 0
        {
            return Err(format!("assessment usage did not reconcile: {usage:?}"));
        }
        let audit = report.transport();
        if audit.omitted_receipt_count() != 0
            || audit.receipts().len() != expected_requests as usize
        {
            return Err("transport audit did not retain every expected receipt".to_owned());
        }
        let authority_response_bytes =
            audit
                .receipts()
                .iter()
                .enumerate()
                .try_fold(0_u64, |bytes, (sequence, receipt)| {
                    if receipt.sequence() != sequence as u64
                        || receipt.outcome() != TransportDispatchOutcome::Completed
                    {
                        return Err(
                            "transport receipt sequence or completion was invalid".to_owned()
                        );
                    }
                    latencies.push(receipt.elapsed_ms());
                    Ok(bytes.saturating_add(receipt.response_bytes()))
                })?;
        if authority_response_bytes != usage.response_bytes() {
            return Err("transport receipt bytes did not reconcile with runtime usage".to_owned());
        }
        response_bytes = response_bytes.saturating_add(authority_response_bytes);
    }

    let elapsed = started.elapsed();
    let observed_wire_requests = fixtures
        .iter()
        .map(LoopbackFixture::request_count)
        .fold(0_u64, u64::saturating_add);
    if observed_wire_requests != u64::from(spec.total_requests()) {
        return Err(format!(
            "fixture observed {observed_wire_requests} requests, expected {}",
            spec.total_requests()
        ));
    }
    if latencies.len() != spec.total_requests() as usize {
        return Err("latency receipt count did not reconcile".to_owned());
    }
    latencies.sort_unstable();
    let wall_time_ms = elapsed.as_secs_f64() * 1_000.0;
    if !wall_time_ms.is_finite() || wall_time_ms <= 0.0 {
        return Err("sample wall time was not a positive finite value".to_owned());
    }
    let requests_per_second = f64::from(spec.total_requests()) / elapsed.as_secs_f64();
    if !requests_per_second.is_finite() || requests_per_second <= 0.0 {
        return Err("sample throughput was not a positive finite value".to_owned());
    }
    Ok(SampleMeasurement {
        sample_index,
        wall_time_ms,
        requests_per_second,
        p50_latency_ms: percentile_u64(&latencies, 50),
        p95_latency_ms: percentile_u64(&latencies, 95),
        p99_latency_ms: percentile_u64(&latencies, 99),
        total_requests: spec.total_requests(),
        response_bytes,
    })
}

fn limits_for(subjects: usize, expected_requests: u32) -> Result<WebAssessmentLimits, String> {
    WebAssessmentLimits::default()
        .with_max_subjects(subjects)
        .and_then(|limits| limits.with_max_discovery_depth(1))
        .and_then(|limits| limits.with_max_references_per_document(subjects.saturating_sub(1)))
        .and_then(|limits| limits.with_max_forms(0))
        .and_then(|limits| limits.with_max_controls_per_form(0))
        .and_then(|limits| limits.with_max_query_parameter_names(0))
        .and_then(|limits| limits.with_max_total_requests(expected_requests))
        .and_then(|limits| limits.with_max_active_verifications(ACTIVE_VERIFICATIONS_PER_AUTHORITY))
        .map_err(|error| format!("workload exceeded a compiled assessment limit: {error}"))
}

fn percentile_u64(sorted: &[u64], percent: usize) -> u64 {
    let rank = percent.saturating_mul(sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}
