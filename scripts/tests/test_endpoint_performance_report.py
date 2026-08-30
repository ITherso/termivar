"""Regression tests for the endpoint-performance evidence contract."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "endpoint_performance_report.py"
SPEC = importlib.util.spec_from_file_location("endpoint_performance_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)


def metric(values: list[float]) -> dict[str, float]:
    return reporter._summarize(values)


def valid_report() -> dict:
    samples = [
        {
            "sample_index": index,
            "wall_time_ms": wall,
            "requests_per_second": rps,
            "p50_latency_ms": 1,
            "p95_latency_ms": 2,
            "p99_latency_ms": 3,
            "total_requests": 102,
            "response_bytes": 4_096,
        }
        for index, wall, rps in [
            (1, 10.0, 102_000.0 / 10.0),
            (2, 11.0, 102_000.0 / 11.0),
            (3, 9.0, 102_000.0 / 9.0),
        ]
    ]
    return {
        "schema": reporter.SCHEMA,
        "environment": {
            "commit_sha": "a" * 40,
            "rust_version": "rustc 1.88.0 (fixture)",
            "os": "Linux fixture",
            "architecture": "x86_64",
            "build_profile": "bench",
            "package_version": "0.10.0-alpha.1",
            "hardware": {
                "cpu_model": "Fixture CPU",
                "logical_cpus": 4,
                "total_memory_bytes": 8 * 1024**3,
            },
        },
        "configuration": {
            "warmup_samples": 1,
            "measured_samples": 3,
            "fixture": "hard-coded-127.0.0.1-http1",
            "fixture_response_delay_ms": 1,
            "runtime_concurrency": 1,
            "active_verifications_per_authority": 1,
            "latency_source": "broker-dispatch-receipt-elapsed-ms",
        },
        "process_resources": {
            "user_cpu_seconds": 1.0,
            "system_cpu_seconds": 0.25,
            "total_cpu_seconds": 1.25,
            "cpu_percent": 98.0,
            "peak_rss_kib": 64_000,
        },
        "workloads": [
            {
                "id": "endpoints-100",
                "endpoint_count": 100,
                "total_requests": 102,
                "authority_count": 1,
                "requests_per_authority": [102],
                "authority_model": "one-shared-authority",
                "profile": "web-review",
                "samples": samples,
                "summary": {
                    "wall_time_ms": metric([10.0, 11.0, 9.0]),
                    "requests_per_second": metric(
                        [102_000.0 / 10.0, 102_000.0 / 11.0, 102_000.0 / 9.0]
                    ),
                    "p50_latency_ms": metric([1.0, 1.0, 1.0]),
                    "p95_latency_ms": metric([2.0, 2.0, 2.0]),
                    "p99_latency_ms": metric([3.0, 3.0, 3.0]),
                    "response_bytes": metric([4_096.0, 4_096.0, 4_096.0]),
                },
            }
        ],
        "thresholds": None,
    }


class ValidationTests(unittest.TestCase):
    def test_even_sample_summary_uses_the_statistical_median(self) -> None:
        self.assertEqual(reporter._summarize([4.0, 1.0, 3.0, 2.0])["median"], 2.5)

    def test_valid_complete_record_and_markdown_preserve_no_threshold_claim(self) -> None:
        document = valid_report()
        document["environment"]["hardware"]["cpu_model"] = "CPU | <unsafe> `model`"
        reporter.validate_report(document, require_resources=True)
        markdown = reporter.render_markdown(document)
        self.assertIn("thresholds` is deliberately `null", markdown)
        self.assertIn("one 1,000-request broker/budget authority", markdown)
        self.assertIn("| `endpoints-100` | 100 | 102 | 1 |", markdown)
        self.assertIn("CPU \\| &lt;unsafe&gt; 'model'", markdown)
        self.assertNotIn("<unsafe>", markdown)

    def test_unknown_duplicate_and_non_null_threshold_fields_fail_closed(self) -> None:
        unknown = valid_report()
        unknown["surprise"] = True
        with self.assertRaises(reporter.ReportError):
            reporter.validate_report(unknown, require_resources=True)

        threshold = valid_report()
        threshold["thresholds"] = {"requests_per_second": 1}
        with self.assertRaises(reporter.ReportError):
            reporter.validate_report(threshold, require_resources=True)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaises(reporter.ReportError):
                reporter.load_report(path)

        multibyte = valid_report()
        multibyte["environment"]["hardware"]["cpu_model"] = "😀" * 129
        with self.assertRaises(reporter.ReportError):
            reporter.validate_report(multibyte, require_resources=True)

    def test_accounting_authority_latency_and_summary_mismatches_are_rejected(self) -> None:
        cases = []
        requests = valid_report()
        requests["workloads"][0]["total_requests"] = 101
        cases.append(requests)
        authorities = valid_report()
        authorities["workloads"][0]["requests_per_authority"] = [51, 51]
        cases.append(authorities)
        latency = valid_report()
        latency["workloads"][0]["samples"][0]["p95_latency_ms"] = 0
        cases.append(latency)
        summary = valid_report()
        summary["workloads"][0]["summary"]["wall_time_ms"]["median"] = 99.0
        cases.append(summary)
        throughput = valid_report()
        throughput["workloads"][0]["samples"][0]["requests_per_second"] = 1.0
        throughput["workloads"][0]["summary"]["requests_per_second"] = metric(
            [1.0, 102_000.0 / 11.0, 102_000.0 / 9.0]
        )
        cases.append(throughput)
        for document in cases:
            with self.subTest(document=document):
                with self.assertRaises(reporter.ReportError):
                    reporter.validate_report(document, require_resources=True)

    def test_raw_resources_are_enriched_once_from_strict_gnu_time_evidence(self) -> None:
        document = valid_report()
        for key in document["process_resources"]:
            document["process_resources"][key] = None
        reporter.validate_report(document, require_resources=False)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "time.txt"
            evidence.write_text(
                "user_seconds=1.50\nsystem_seconds=0.25\ncpu_percent=87%\npeak_rss_kib=12345\n",
                encoding="utf-8",
            )
            parsed = reporter.parse_gnu_time(evidence)
        reporter.enrich_resources(document, parsed)
        reporter.validate_report(document, require_resources=True)
        self.assertEqual(document["process_resources"]["total_cpu_seconds"], 1.75)
        with self.assertRaises(reporter.ReportError):
            reporter.enrich_resources(document, parsed)

    def test_atomic_writer_leaves_one_complete_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "nested" / "report.json"
            reporter.write_text_atomically(output, json.dumps(valid_report()) + "\n")
            decoded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(decoded["schema"], reporter.SCHEMA)
            self.assertEqual(list(output.parent.iterdir()), [output])


if __name__ == "__main__":
    unittest.main()
