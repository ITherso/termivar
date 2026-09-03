#!/usr/bin/env python3
"""Validate endpoint-performance evidence and atomically render JSON/Markdown."""

from __future__ import annotations

import argparse
import html
import json
import math
import os
from pathlib import Path
import re
import statistics
import tempfile
from typing import Any, Iterable


SCHEMA = "venom.endpoint-performance/v1"
MIN_WARMUPS = 1
MAX_WARMUPS = 3
MIN_SAMPLES = 3
MAX_SAMPLES = 10
WORKLOADS = {
    "endpoints-100": {
        "endpoint_count": 100,
        "total_requests": 102,
        "authority_count": 1,
        "requests_per_authority": [102],
        "authority_model": "one-shared-authority",
    },
    "endpoints-1000": {
        "endpoint_count": 1_000,
        "total_requests": 1_002,
        "authority_count": 1,
        "requests_per_authority": [1_002],
        "authority_model": "one-shared-authority",
    },
    "requests-10000": {
        "endpoint_count": 9_980,
        "total_requests": 10_000,
        "authority_count": 10,
        "requests_per_authority": [1_000] * 10,
        "authority_model": "independent-authority-per-origin-assessment",
    },
}
METRICS = (
    "wall_time_ms",
    "requests_per_second",
    "p50_latency_ms",
    "p95_latency_ms",
    "p99_latency_ms",
    "response_bytes",
)
SUMMARY_FIELDS = {
    "minimum",
    "median",
    "maximum",
    "mean",
    "standard_deviation",
    "coefficient_of_variation_percent",
}


class ReportError(ValueError):
    """A report failed its closed schema or accounting contract."""


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReportError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_report(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"could not read benchmark JSON: {error}") from error
    if not isinstance(value, dict):
        raise ReportError("benchmark JSON root must be an object")
    return value


def _exact_fields(value: Any, fields: Iterable[str], at: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError(f"{at} must be an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ReportError(f"{at} fields differ; missing={missing}, unknown={unknown}")
    return value


def _string(value: Any, at: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > maximum
    ):
        raise ReportError(f"{at} must be a non-empty string of at most {maximum} bytes")
    if any(ord(character) < 0x20 and character not in "\t" for character in value):
        raise ReportError(f"{at} contains a control character")
    return value


def _integer(value: Any, at: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ReportError(f"{at} must be an integer >= {minimum}")
    return value


def _number(value: Any, at: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ReportError(f"{at} must be numeric")
    rendered = float(value)
    if not math.isfinite(rendered) or (positive and rendered <= 0.0) or rendered < 0.0:
        qualifier = "positive " if positive else "non-negative "
        raise ReportError(f"{at} must be a finite {qualifier}number")
    return rendered


def validate_report(report: dict[str, Any], *, require_resources: bool) -> None:
    root = _exact_fields(
        report,
        {
            "schema",
            "environment",
            "configuration",
            "process_resources",
            "workloads",
            "thresholds",
        },
        "report",
    )
    if root["schema"] != SCHEMA:
        raise ReportError(f"report.schema must be {SCHEMA}")
    if root["thresholds"] is not None:
        raise ReportError("speed thresholds must remain null until a baseline is accepted")

    environment = _exact_fields(
        root["environment"],
        {
            "commit_sha",
            "rust_version",
            "os",
            "architecture",
            "build_profile",
            "package_version",
            "hardware",
        },
        "environment",
    )
    commit = _string(environment["commit_sha"], "environment.commit_sha")
    if require_resources and not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReportError("final environment.commit_sha must be a 40-character lowercase Git SHA")
    for field in ("rust_version", "os", "architecture", "package_version"):
        value = _string(environment[field], f"environment.{field}")
        if require_resources and value == "unknown":
            raise ReportError(f"final environment.{field} must be observed")
    if environment["build_profile"] != "bench":
        raise ReportError("environment.build_profile must be bench")
    hardware = _exact_fields(
        environment["hardware"],
        {"cpu_model", "logical_cpus", "total_memory_bytes"},
        "environment.hardware",
    )
    cpu_model = _string(hardware["cpu_model"], "environment.hardware.cpu_model")
    if require_resources and cpu_model == "unknown":
        raise ReportError("final CPU model must be observed")
    _integer(hardware["logical_cpus"], "environment.hardware.logical_cpus", minimum=1)
    if hardware["total_memory_bytes"] is not None:
        _integer(
            hardware["total_memory_bytes"],
            "environment.hardware.total_memory_bytes",
            minimum=1,
        )
    elif require_resources:
        raise ReportError("final total memory must be observed")

    configuration = _exact_fields(
        root["configuration"],
        {
            "warmup_samples",
            "measured_samples",
            "fixture",
            "fixture_response_delay_ms",
            "runtime_concurrency",
            "active_verifications_per_authority",
            "latency_source",
        },
        "configuration",
    )
    warmups = _integer(configuration["warmup_samples"], "configuration.warmup_samples")
    samples = _integer(configuration["measured_samples"], "configuration.measured_samples")
    if not MIN_WARMUPS <= warmups <= MAX_WARMUPS:
        raise ReportError("warmup sample count is outside the compiled 1..=3 range")
    if not MIN_SAMPLES <= samples <= MAX_SAMPLES:
        raise ReportError("measured sample count is outside the compiled 3..=10 range")
    if configuration["fixture"] != "hard-coded-127.0.0.1-http1":
        raise ReportError("fixture identity is not the hard-coded loopback fixture")
    if configuration["fixture_response_delay_ms"] != 1:
        raise ReportError("fixture response delay must remain the fixed one millisecond")
    if configuration["runtime_concurrency"] != 1:
        raise ReportError("runtime concurrency must preserve the sequential assessment authority")
    if configuration["active_verifications_per_authority"] != 1:
        raise ReportError("each authority must retain exactly one matched active verification")
    if configuration["latency_source"] != "broker-dispatch-receipt-elapsed-ms":
        raise ReportError("latency source must be broker dispatch receipts")

    resources = _exact_fields(
        root["process_resources"],
        {
            "user_cpu_seconds",
            "system_cpu_seconds",
            "total_cpu_seconds",
            "cpu_percent",
            "peak_rss_kib",
        },
        "process_resources",
    )
    for field in ("user_cpu_seconds", "system_cpu_seconds", "total_cpu_seconds", "cpu_percent"):
        if resources[field] is not None:
            _number(resources[field], f"process_resources.{field}")
        elif require_resources:
            raise ReportError(f"final process_resources.{field} must be observed")
    if resources["peak_rss_kib"] is not None:
        _integer(resources["peak_rss_kib"], "process_resources.peak_rss_kib", minimum=1)
    elif require_resources:
        raise ReportError("final process_resources.peak_rss_kib must be observed")
    if require_resources:
        expected_cpu = float(resources["user_cpu_seconds"]) + float(
            resources["system_cpu_seconds"]
        )
        if not math.isclose(
            float(resources["total_cpu_seconds"]), expected_cpu, rel_tol=1e-9, abs_tol=1e-9
        ):
            raise ReportError("total CPU seconds do not reconcile")

    workloads = root["workloads"]
    if not isinstance(workloads, list) or not workloads:
        raise ReportError("workloads must be a non-empty array")
    seen: set[str] = set()
    for workload_index, workload in enumerate(workloads):
        _validate_workload(workload, workload_index, samples)
        identifier = workload["id"]
        if identifier in seen:
            raise ReportError(f"duplicate workload: {identifier}")
        seen.add(identifier)


def _validate_workload(workload: Any, index: int, measured_samples: int) -> None:
    at = f"workloads[{index}]"
    workload = _exact_fields(
        workload,
        {
            "id",
            "endpoint_count",
            "total_requests",
            "authority_count",
            "requests_per_authority",
            "authority_model",
            "profile",
            "samples",
            "summary",
        },
        at,
    )
    identifier = _string(workload["id"], f"{at}.id")
    expected = WORKLOADS.get(identifier)
    if expected is None:
        raise ReportError(f"unknown production workload: {identifier}")
    for field in ("endpoint_count", "total_requests", "authority_count"):
        if workload[field] != expected[field]:
            raise ReportError(f"{at}.{field} does not match the fixed workload")
    if workload["requests_per_authority"] != expected["requests_per_authority"]:
        raise ReportError(f"{at}.requests_per_authority does not reconcile")
    if workload["authority_model"] != expected["authority_model"]:
        raise ReportError(f"{at}.authority_model does not match the authority partition")
    if workload["profile"] != "web-review":
        raise ReportError(f"{at}.profile must be web-review")
    samples = workload["samples"]
    if not isinstance(samples, list) or len(samples) != measured_samples:
        raise ReportError(f"{at}.samples must contain every configured sample")
    for sample_index, sample in enumerate(samples, start=1):
        sample_at = f"{at}.samples[{sample_index - 1}]"
        sample = _exact_fields(
            sample,
            {
                "sample_index",
                "wall_time_ms",
                "requests_per_second",
                "p50_latency_ms",
                "p95_latency_ms",
                "p99_latency_ms",
                "total_requests",
                "response_bytes",
            },
            sample_at,
        )
        if sample["sample_index"] != sample_index:
            raise ReportError(f"{sample_at}.sample_index is not contiguous")
        wall_time_ms = _number(
            sample["wall_time_ms"], f"{sample_at}.wall_time_ms", positive=True
        )
        requests_per_second = _number(
            sample["requests_per_second"],
            f"{sample_at}.requests_per_second",
            positive=True,
        )
        p50 = _integer(sample["p50_latency_ms"], f"{sample_at}.p50_latency_ms")
        p95 = _integer(sample["p95_latency_ms"], f"{sample_at}.p95_latency_ms")
        p99 = _integer(sample["p99_latency_ms"], f"{sample_at}.p99_latency_ms")
        if not p50 <= p95 <= p99:
            raise ReportError(f"{sample_at} latency percentiles are not monotonic")
        if sample["total_requests"] != expected["total_requests"]:
            raise ReportError(f"{sample_at}.total_requests does not reconcile")
        expected_requests_per_second = (
            float(sample["total_requests"]) * 1_000.0 / wall_time_ms
        )
        if not math.isclose(
            requests_per_second,
            expected_requests_per_second,
            rel_tol=1e-9,
            abs_tol=1e-7,
        ):
            raise ReportError(
                f"{sample_at}.requests_per_second does not reconcile with wall time"
            )
        _integer(sample["response_bytes"], f"{sample_at}.response_bytes", minimum=1)
    _validate_summary(workload["summary"], samples, at)


def _validate_summary(summary: Any, samples: list[dict[str, Any]], at: str) -> None:
    summary = _exact_fields(summary, METRICS, f"{at}.summary")
    for metric in METRICS:
        metric_summary = _exact_fields(
            summary[metric], SUMMARY_FIELDS, f"{at}.summary.{metric}"
        )
        values = [float(sample[metric]) for sample in samples]
        expected = _summarize(values)
        for field, expected_value in expected.items():
            observed = _number(
                metric_summary[field], f"{at}.summary.{metric}.{field}"
            )
            tolerance = max(1e-7, abs(expected_value) * 1e-9)
            if not math.isclose(observed, expected_value, rel_tol=0.0, abs_tol=tolerance):
                raise ReportError(f"{at}.summary.{metric}.{field} does not reconcile")


def _summarize(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    mean = statistics.fmean(ordered)
    deviation = statistics.pstdev(ordered)
    return {
        "minimum": ordered[0],
        "median": statistics.median(ordered),
        "maximum": ordered[-1],
        "mean": mean,
        "standard_deviation": deviation,
        "coefficient_of_variation_percent": 0.0 if mean == 0.0 else deviation / mean * 100.0,
    }

def parse_gnu_time(path: Path) -> dict[str, float | int]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ReportError(f"could not read GNU time evidence: {error}") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise ReportError("GNU time evidence is malformed or duplicated")
        values[key] = value
    expected = {"user_seconds", "system_seconds", "cpu_percent", "peak_rss_kib"}
    if set(values) != expected:
        raise ReportError("GNU time evidence fields are incomplete or unknown")
    try:
        user = float(values["user_seconds"])
        system = float(values["system_seconds"])
        cpu = float(values["cpu_percent"].removesuffix("%"))
        peak = int(values["peak_rss_kib"])
    except ValueError as error:
        raise ReportError("GNU time evidence contains a non-numeric value") from error
    _number(user, "GNU time user_seconds")
    _number(system, "GNU time system_seconds")
    _number(cpu, "GNU time cpu_percent")
    _integer(peak, "GNU time peak_rss_kib", minimum=1)
    return {
        "user_cpu_seconds": user,
        "system_cpu_seconds": system,
        "total_cpu_seconds": user + system,
        "cpu_percent": cpu,
        "peak_rss_kib": peak,
    }


def enrich_resources(report: dict[str, Any], evidence: dict[str, float | int]) -> None:
    resources = report["process_resources"]
    if any(value is not None for value in resources.values()):
        raise ReportError("raw benchmark process resources must be null before GNU time enrichment")
    resources.update(evidence)


def render_markdown(report: dict[str, Any]) -> str:
    environment = report["environment"]
    hardware = environment["hardware"]
    configuration = report["configuration"]
    resources = report["process_resources"]
    lines = [
        "# Termivar endpoint performance evidence",
        "",
        f"Schema: `{SCHEMA}`",
        "",
        "This record contains measurements, not accepted speed thresholds. "
        "`thresholds` is deliberately `null`; no workload receives a speed pass/fail result.",
        "",
        "## Environment",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Commit | `{_markdown(environment['commit_sha'])}` |",
        f"| Rust | `{_markdown(environment['rust_version'])}` |",
        f"| OS | {_markdown(environment['os'])} |",
        f"| Architecture | `{_markdown(environment['architecture'])}` |",
        f"| Build profile | `{_markdown(environment['build_profile'])}` |",
        f"| CPU | {_markdown(hardware['cpu_model'])} |",
        f"| Logical CPUs | {hardware['logical_cpus']} |",
        f"| Total memory | {hardware['total_memory_bytes']} bytes |",
        "",
        "## Process resources",
        "",
        "GNU `time` measures the already-built benchmark process across the selected workloads, "
        "warmups, and measured samples.",
        "",
        "| User CPU | System CPU | Total CPU | CPU utilization | Peak RSS |",
        "| ---: | ---: | ---: | ---: | ---: |",
        (
            f"| {resources['user_cpu_seconds']:.3f} s | "
            f"{resources['system_cpu_seconds']:.3f} s | "
            f"{resources['total_cpu_seconds']:.3f} s | "
            f"{resources['cpu_percent']:.1f}% | {resources['peak_rss_kib']} KiB |"
        ),
        "",
        "## Configuration",
        "",
        f"- Fixture: `{configuration['fixture']}` (harness-owned loopback only)",
        f"- Fixture response delay: {configuration['fixture_response_delay_ms']} ms",
        f"- Profile: `web-review`",
        f"- Runtime concurrency: {configuration['runtime_concurrency']}",
        f"- Active verifications per authority: {configuration['active_verifications_per_authority']}",
        f"- Warmups: {configuration['warmup_samples']}",
        f"- Measured samples: {configuration['measured_samples']}",
        f"- Latency source: `{configuration['latency_source']}`",
        "",
        "The 10,000-request workload is ten independent 998-subject origin assessments. "
        "Each assessment owns one 1,000-request broker/budget authority; the batch is not represented "
        "as one global authority.",
        "",
        "## Workload summaries",
        "",
        "| Workload | Endpoints | Requests | Authorities | Wall median | Wall CV | RPS median | p50 | p95 | p99 | Response bytes median |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for workload in report["workloads"]:
        summary = workload["summary"]
        lines.append(
            f"| `{workload['id']}` | {workload['endpoint_count']} | "
            f"{workload['total_requests']} | {workload['authority_count']} | "
            f"{summary['wall_time_ms']['median']:.3f} ms | "
            f"{summary['wall_time_ms']['coefficient_of_variation_percent']:.2f}% | "
            f"{summary['requests_per_second']['median']:.2f} | "
            f"{summary['p50_latency_ms']['median']:.2f} ms | "
            f"{summary['p95_latency_ms']['median']:.2f} ms | "
            f"{summary['p99_latency_ms']['median']:.2f} ms | "
            f"{summary['response_bytes']['median']:.0f} |"
        )
    lines.extend(["", "## Samples", ""])
    for workload in report["workloads"]:
        lines.extend(
            [
                f"### `{workload['id']}`",
                "",
                f"Authority request counts: `{workload['requests_per_authority']}`",
                "",
                "| Sample | Wall | Requests/s | p50 | p95 | p99 | Response bytes |",
                "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for sample in workload["samples"]:
            lines.append(
                f"| {sample['sample_index']} | {sample['wall_time_ms']:.3f} ms | "
                f"{sample['requests_per_second']:.2f} | {sample['p50_latency_ms']} ms | "
                f"{sample['p95_latency_ms']} ms | {sample['p99_latency_ms']} ms | "
                f"{sample['response_bytes']} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _markdown(value: Any) -> str:
    escaped = html.escape(str(value), quote=False)
    return escaped.replace("\n", " ").replace("\r", " ").replace("|", "\\|").replace("`", "'")


def write_text_atomically(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, text=True
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--gnu-time", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.json_output.resolve() == arguments.markdown_output.resolve():
        raise ReportError("JSON and Markdown outputs must be distinct paths")
    report = load_report(arguments.input)
    validate_report(report, require_resources=False)
    enrich_resources(report, parse_gnu_time(arguments.gnu_time))
    validate_report(report, require_resources=True)
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    markdown = render_markdown(report)
    write_text_atomically(arguments.json_output, encoded)
    write_text_atomically(arguments.markdown_output, markdown)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReportError as error:
        raise SystemExit(f"endpoint performance report rejected: {error}") from error
