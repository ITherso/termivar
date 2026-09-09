"""Independent regressions for bounded WordPress resource evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "wordpress_resource_acceptance.py"
SPEC = importlib.util.spec_from_file_location("wordpress_resource_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acceptance
SPEC.loader.exec_module(acceptance)


LITERAL_CASE_ORACLE = [
    ("baseline", "baseline", 0, "baseline", None, None, None),
    ("sparse-small", "sparse", 32, "completed", None, 1, 1),
    ("sparse-4096", "sparse", 4_096, "completed", None, 1, 1),
    ("sparse-16384", "sparse", 16_384, "completed", None, 1, 1),
    ("sparse-32768", "sparse", 32_768, "completed", None, 1, 1),
    ("sparse-65536", "sparse", 65_536, "completed", None, 1, 1),
    ("sparse-81920", "sparse", 81_920, "rejected", "retained_data_too_large", None, None),
    ("dense-4096", "dense", 4_096, "completed", None, 4_096, 4_096),
    ("dense-4097", "dense", 4_097, "rejected", "result_limit_exceeded", None, None),
    ("record-between-limits", "record-between-limits", 1, "completed", None, 0, 0),
    ("record-over-limit", "record-limit", 1, "rejected", "record_too_large", None, None),
    ("title-field-limit-plus-one", "field-limit", 1, "rejected", "unsupported_value", None, None),
    ("input-limit-plus-one", "input-limit", 0, "rejected", "input_too_large", None, None),
    ("late-malformed", "late-malformed", 4_096, "rejected", "malformed_json", None, None),
    ("duplicate-id", "duplicate-id", 2, "rejected", "duplicate_key", None, None),
]

LITERAL_RESOURCE_POLICY_ORACLE = {
    "baseline": None,
    "sparse-small": "termivar.wordfence-v3-bounded-capacity/v1",
    "sparse-4096": "termivar.wordfence-v3-bounded-capacity/v1",
    "sparse-16384": "termivar.wordfence-v3-bounded-capacity/v1",
    "sparse-32768": "termivar.wordfence-v3-bounded-capacity/v2",
    "sparse-65536": "termivar.wordfence-v3-bounded-capacity/v3",
    "sparse-81920": None,
    "dense-4096": "termivar.wordfence-v3-bounded-capacity/v1",
    "dense-4097": "termivar.wordfence-v3-bounded-capacity/v1",
    "record-between-limits": "termivar.wordfence-v3-bounded-capacity/v2",
    "record-over-limit": None,
    "title-field-limit-plus-one": None,
    "input-limit-plus-one": None,
    "late-malformed": None,
    "duplicate-id": None,
}


def resource_record() -> dict:
    return {
        "provider": "gnu-time",
        "process_scope": "one-fresh-child",
        "elapsed_seconds": 1.25,
        "user_seconds": 1.0,
        "system_seconds": 0.2,
        "cpu_percent": 96.0,
        "peak_rss_kib": 12_345,
    }


def probe_for(case, input_evidence):
    values = {field: None for field in acceptance.PROBE_NUMERIC_FIELDS}
    values["input_bytes"] = None if input_evidence is None else input_evidence["bytes"]
    if case.expected_status != "baseline":
        values["parse_elapsed_ns"] = 10
    if case.expected_status == "completed":
        expected_associations = 20 if case.identifier == "record-between-limits" else case.records
        expected_ranges = 2_560 if case.identifier == "record-between-limits" else case.records
        if case.identifier == "sparse-32768":
            retained_bytes = acceptance.RESOURCE_POLICY_V1_RETAINED_LIMIT + 1
        elif case.identifier == "sparse-65536":
            retained_bytes = acceptance.RESOURCE_POLICY_V2_RETAINED_LIMIT + 1
        else:
            retained_bytes = max(1, case.records * 100)
        values.update({
            "evaluation_elapsed_ns": 20,
            "parsed_records": case.records,
            "software_associations": expected_associations,
            "affected_ranges": expected_ranges,
            "retained_bytes": retained_bytes,
            "selected_associations": case.expected_selected,
            "evaluable_associations": case.expected_selected,
            "within_associations": case.expected_within,
            "outside_associations": 0,
            "indeterminate_associations": 0,
            "excluded_associations": expected_associations - case.expected_selected,
            "selected_ranges": case.expected_selected,
            "evaluated_ranges": case.expected_selected,
        })
    elif case.identifier == "dense-4097":
        values.update({
            "evaluation_elapsed_ns": 20,
            "parsed_records": 4_097,
            "software_associations": 4_097,
            "affected_ranges": 4_097,
            "retained_bytes": 500_000,
        })
    return {
        "schema": acceptance.PROBE_SCHEMA,
        "case": case.identifier,
        "status": case.expected_status,
        "error_code": case.expected_error_code,
        "resource_policy": LITERAL_RESOURCE_POLICY_ORACLE[case.identifier],
        **values,
    }


def input_for(case) -> dict | None:
    if case.mode == "baseline":
        return None
    if case.mode == "record-between-limits":
        byte_length = 512 * 1024 + 1
        distribution = "record-between-512-and-768-kib"
    elif case.mode == "record-limit":
        byte_length = 768 * 1024 + 1
        distribution = "record-over-limit"
    elif case.mode == "field-limit":
        byte_length = 1_025
        distribution = "title-field-limit-plus-one"
    elif case.mode == "input-limit":
        byte_length = acceptance.MAX_INPUT_BYTES + 1
        distribution = "streamed-padding-limit-plus-one"
    elif case.mode == "dense":
        byte_length = 100
        distribution = "all-relevant"
    else:
        byte_length = 100
        distribution = "one-relevant-last"
    return {
        "bytes": byte_length,
        "sha256": "1" * 64,
        "generated_records": case.records,
        "distribution": distribution,
    }


def case_entry(case) -> dict:
    input_evidence = input_for(case)
    return {
        "id": case.identifier,
        "purpose": case.purpose,
        "synthetic": True,
        "input": input_evidence,
        "expected": {
            "status": case.expected_status,
            "error_code": case.expected_error_code,
            "generated_records": case.records,
            "resource_policy": LITERAL_RESOURCE_POLICY_ORACLE[case.identifier],
            "selected_associations": case.expected_selected,
            "within_associations": case.expected_within,
        },
        "observed": probe_for(case, input_evidence),
        "resources": resource_record(),
    }


def valid_cli_acceptance() -> dict:
    return {
        "status": "passed",
        "synthetic": True,
        "profile": "numeric-dotted/v1",
        "binary_version_output": "termivar 0.10.0-alpha.3",
        "scan_invocations": 1,
        "loopback_request_counts": {
            "example": 0,
            "invalid": 0,
            "root": 5,
            "unknown": 0,
            "unsupported": 0,
        },
        "request_trace": [
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "HEAD /wp-content/plugins/selected-plugin/style.css HTTP/1.1",
            "HEAD /wp-content/themes/unselected-theme/style.css HTTP/1.1",
        ],
        "wordpress_counts": {
            "parsed_records": 1,
            "software_associations": 1,
            "selected_associations": 1,
            "evaluable_associations": 1,
            "within_associations": 1,
            "outside_associations": 0,
            "indeterminate_associations": 0,
        },
        "offline_request_delta": 0,
        "verify_status": "integrity_match",
        "self_compare": {
            "only_in_before": 0,
            "only_in_after": 0,
            "changed": 0,
            "unchanged": 1,
            "wordpress_paired_unchanged": 1,
        },
        "inputs": {
            "advisory": {
                "bytes": 500,
                "sha256": "2" * 64,
                "generated_records": 1,
                "distribution": "all-relevant",
            },
            "inventory": {"bytes": 64, "sha256": "3" * 64},
            "preserved": True,
        },
        "bundle_files": [
            {"name": name, "bytes": index, "sha256": str(index) * 64}
            for index, name in enumerate(
                ("assessment.html", "assessment.json", "manifest.json"), start=4
            )
        ],
        "assessment_json_bytes": 5,
        "resources": resource_record(),
    }


class CaseInventoryTests(unittest.TestCase):
    def test_case_inventory_and_outcomes_are_literal_and_closed(self) -> None:
        observed = [
            (
                case.identifier,
                case.mode,
                case.records,
                case.expected_status,
                case.expected_error_code,
                case.expected_selected,
                case.expected_within,
            )
            for case in acceptance.CASE_SPECS
        ]
        self.assertEqual(observed, LITERAL_CASE_ORACLE)
        self.assertEqual(len({row[0] for row in observed}), len(observed))
        self.assertEqual(
            acceptance.EXPECTED_RESOURCE_POLICY_BY_CASE,
            LITERAL_RESOURCE_POLICY_ORACLE,
        )
        self.assertEqual(acceptance.RESOURCE_POLICY_V1_RETAINED_LIMIT, 64 * 1024 * 1024)
        self.assertEqual(acceptance.RESOURCE_POLICY_V2_RETAINED_LIMIT, 128 * 1024 * 1024)
        self.assertEqual(acceptance.MAX_RETAINED_BYTES, 160 * 1024 * 1024)
        self.assertLessEqual(max(case.records for case in acceptance.CASE_SPECS),
                             acceptance.MAX_SOURCE_RECORDS)
        self.assertEqual(
            observed[4],
            ("sparse-32768", "sparse", 32_768, "completed", None, 1, 1),
        )
        self.assertEqual(
            observed[6],
            (
                "sparse-81920",
                "sparse",
                81_920,
                "rejected",
                "retained_data_too_large",
                None,
                None,
            ),
        )

    def test_small_sparse_feed_is_distinct_and_relevant_only_at_the_tail(self) -> None:
        case = acceptance.CASE_BY_ID["sparse-small"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed.json"
            evidence = acceptance.generate_case_input(case, path)
            self.assertIsNotNone(evidence)
            raw = path.read_bytes()
            self.assertEqual(len(raw), evidence["bytes"])
            self.assertEqual(acceptance.digest_file(path), evidence["sha256"])
            pairs = json.loads(raw, object_pairs_hook=list)
        self.assertEqual(len(pairs), 32)
        self.assertEqual(len({key for key, _ in pairs}), 32)
        decoded = json.loads(raw)
        records = list(decoded.values())
        self.assertTrue(all(row["software"][0]["slug"].startswith("irrelevant-") for row in records[:-1]))
        self.assertEqual(records[-1]["software"][0]["slug"], "selected-plugin")
        self.assertEqual(records[-1]["software"][0]["affected_versions"]["[1.0,2.0]"]["to_version"], "2.0")

    def test_dense_feed_has_every_distinct_record_bound_to_one_selected_component(self) -> None:
        case = acceptance.CASE_BY_ID["dense-4096"]
        # Exercise a small equivalent shape here; the native probe measures 4,096.
        small = acceptance.CaseSpec(
            "dense-test", "dense", 5, "completed", None, 5, 5, "test"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dense.json"
            evidence = acceptance.generate_case_input(small, path)
            decoded = json.loads(path.read_bytes())
        self.assertEqual(evidence["distribution"], "all-relevant")
        self.assertEqual(len(decoded), 5)
        self.assertEqual(len({value["id"] for value in decoded.values()}), 5)
        self.assertTrue(all(value["software"][0]["slug"] == "selected-plugin"
                            for value in decoded.values()))
        self.assertEqual(case.expected_selected, 4_096)

    def test_limit_malformed_and_duplicate_generators_have_independent_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            limit_case = acceptance.CASE_BY_ID["input-limit-plus-one"]
            limit_path = root / "limit.json"
            evidence = acceptance.generate_case_input(limit_case, limit_path, input_limit=1_023)
            self.assertEqual(evidence["bytes"], 1_024)
            self.assertEqual(limit_path.stat().st_size, 1_024)
            self.assertTrue(limit_path.read_bytes().startswith(b"{}"))

            malformed = acceptance.CaseSpec(
                "late-test", "late-malformed", 3, "rejected", "malformed_json", None, None, "test"
            )
            malformed_path = root / "malformed.json"
            acceptance.generate_case_input(malformed, malformed_path)
            with self.assertRaises(json.JSONDecodeError):
                json.loads(malformed_path.read_bytes())
            self.assertTrue(malformed_path.read_bytes().endswith(b"}x"))

            duplicate = acceptance.CaseSpec(
                "duplicate-test", "duplicate-id", 2, "rejected", "duplicate_key", None, None, "test"
            )
            duplicate_path = root / "duplicate.json"
            acceptance.generate_case_input(duplicate, duplicate_path)
            raw_pairs = json.loads(duplicate_path.read_bytes(), object_pairs_hook=list)
            self.assertEqual(raw_pairs[0][0], raw_pairs[1][0])
            with self.assertRaises(acceptance.AcceptanceError):
                json.loads(duplicate_path.read_bytes(), object_pairs_hook=acceptance._object_without_duplicates)

            record_limit = acceptance.CASE_BY_ID["record-over-limit"]
            record_path = root / "record-limit.json"
            record_evidence = acceptance.generate_case_input(record_limit, record_path)
            self.assertEqual(record_evidence["distribution"], "record-over-limit")
            raw_record_document = record_path.read_bytes()
            record = next(iter(json.loads(raw_record_document).values()))
            encoded_record = json.dumps(
                record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            self.assertEqual(len(record["description"]), 768 * 1024)
            self.assertGreater(len(encoded_record), 768 * 1024)
            self.assertEqual(record_evidence["bytes"], len(raw_record_document))

            accepted_record = acceptance.CASE_BY_ID["record-between-limits"]
            accepted_path = root / "record-between-limits.json"
            accepted_evidence = acceptance.generate_case_input(accepted_record, accepted_path)
            accepted_document = accepted_path.read_bytes()
            accepted_value = next(iter(json.loads(accepted_document).values()))
            accepted_record_bytes = json.dumps(
                accepted_value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            self.assertEqual(
                accepted_evidence["distribution"], "record-between-512-and-768-kib"
            )
            self.assertGreater(len(accepted_record_bytes), 512 * 1024)
            self.assertLessEqual(len(accepted_record_bytes), 768 * 1024)
            self.assertEqual(len(accepted_value["software"]), 20)
            self.assertTrue(
                all(len(software["affected_versions"]) == 128
                    for software in accepted_value["software"])
            )

            field_limit = acceptance.CASE_BY_ID["title-field-limit-plus-one"]
            field_path = root / "field-limit.json"
            field_evidence = acceptance.generate_case_input(field_limit, field_path)
            self.assertEqual(field_evidence["distribution"], "title-field-limit-plus-one")
            field_document = json.loads(field_path.read_bytes())
            self.assertEqual(len(next(iter(field_document.values()))["title"]), 1_025)


class ProbeValidationTests(unittest.TestCase):
    def test_completed_baseline_and_typed_rejections_pass(self) -> None:
        for case in acceptance.CASE_SPECS:
            with self.subTest(identifier=case.identifier):
                evidence = input_for(case)
                acceptance.validate_probe(probe_for(case, evidence), case, evidence)

    def test_wrong_status_error_counts_and_partial_parse_claims_fail_closed(self) -> None:
        case = acceptance.CASE_BY_ID["sparse-small"]
        evidence = input_for(case)
        original = probe_for(case, evidence)
        mutations = []
        wrong_schema = copy.deepcopy(original)
        wrong_schema["schema"] = "unknown/v1"
        mutations.append(wrong_schema)
        wrong_status = copy.deepcopy(original)
        wrong_status["status"] = "rejected"
        mutations.append(wrong_status)
        wrong_count = copy.deepcopy(original)
        wrong_count["within_associations"] = 0
        mutations.append(wrong_count)
        wrong_excluded = copy.deepcopy(original)
        wrong_excluded["excluded_associations"] = 0
        mutations.append(wrong_excluded)
        wrong_policy = copy.deepcopy(original)
        wrong_policy["resource_policy"] = "termivar.wordfence-v3-bounded-capacity/v2"
        mutations.append(wrong_policy)
        extra = copy.deepcopy(original)
        extra["path"] = "/private/feed"
        mutations.append(extra)
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.validate_probe(mutation, case, evidence)

        parse_failure = acceptance.CASE_BY_ID["late-malformed"]
        parse_input = input_for(parse_failure)
        leaked = probe_for(parse_failure, parse_input)
        leaked["parsed_records"] = 4_096
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(leaked, parse_failure, parse_input)
        leaked_policy = probe_for(parse_failure, parse_input)
        leaked_policy["resource_policy"] = "termivar.wordfence-v3-bounded-capacity/v1"
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(leaked_policy, parse_failure, parse_input)

        crossed_v1 = copy.deepcopy(original)
        crossed_v1["retained_bytes"] = acceptance.RESOURCE_POLICY_V1_RETAINED_LIMIT + 1
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(crossed_v1, case, evidence)

        retained_v2_case = acceptance.CASE_BY_ID["sparse-32768"]
        retained_v2_input = input_for(retained_v2_case)
        did_not_cross_v1 = probe_for(retained_v2_case, retained_v2_input)
        did_not_cross_v1["retained_bytes"] = acceptance.RESOURCE_POLICY_V1_RETAINED_LIMIT
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(did_not_cross_v1, retained_v2_case, retained_v2_input)

        crossed_v2 = probe_for(retained_v2_case, retained_v2_input)
        crossed_v2["retained_bytes"] = acceptance.RESOURCE_POLICY_V2_RETAINED_LIMIT + 1
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(crossed_v2, retained_v2_case, retained_v2_input)

        retained_v3_case = acceptance.CASE_BY_ID["sparse-65536"]
        retained_v3_input = input_for(retained_v3_case)
        did_not_cross_v2 = probe_for(retained_v3_case, retained_v3_input)
        did_not_cross_v2["retained_bytes"] = acceptance.RESOURCE_POLICY_V2_RETAINED_LIMIT
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(did_not_cross_v2, retained_v3_case, retained_v3_input)

        crossed_v3 = probe_for(retained_v3_case, retained_v3_input)
        crossed_v3["retained_bytes"] = acceptance.MAX_RETAINED_BYTES + 1
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(crossed_v3, retained_v3_case, retained_v3_input)

        dense_failure = acceptance.CASE_BY_ID["dense-4097"]
        dense_input = input_for(dense_failure)
        zero_retained = probe_for(dense_failure, dense_input)
        zero_retained["retained_bytes"] = 0
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_probe(zero_retained, dense_failure, dense_input)

    def test_same_length_wrong_case_does_not_satisfy_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            probe = root / "probe"
            binary.write_bytes(b"binary")
            probe.write_bytes(b"probe")
            report = acceptance.new_report("a" * 40, "0.10.0-alpha.3", binary, probe)
        report["cases"] = [case_entry(acceptance.CASE_SPECS[0])]
        acceptance.validate_report(report, complete=False)
        renamed = copy.deepcopy(report)
        renamed["cases"][0]["id"] = "baselinx"
        renamed["cases"][0]["observed"]["case"] = "baselinx"
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_report(renamed, complete=False)


class ResourceAndProjectionTests(unittest.TestCase):
    def test_gnu_time_parser_requires_every_unique_typed_metric(self) -> None:
        valid = (
            "elapsed_seconds=1.25\nuser_seconds=1.00\nsystem_seconds=0.20\n"
            "cpu_percent=96%\npeak_rss_kib=12345\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "time.txt"
            path.write_text(valid, encoding="ascii")
            parsed = acceptance.parse_gnu_time(path)
            self.assertEqual(parsed["peak_rss_kib"], 12_345)
            self.assertEqual(parsed["process_scope"], "one-fresh-child")
            path.write_text(valid.replace("elapsed_seconds=1.25", "elapsed_seconds=0.00"), encoding="ascii")
            self.assertEqual(acceptance.parse_gnu_time(path)["elapsed_seconds"], 0.0)

            for malformed in (
                valid.replace("peak_rss_kib=12345\n", ""),
                valid + "peak_rss_kib=9\n",
                valid.replace("cpu_percent=96%", "cpu_percent=unknown"),
                valid.replace("elapsed_seconds=1.25", "elapsed_seconds=nan"),
                valid.replace("peak_rss_kib=12345", "peak_rss_kib=0"),
            ):
                path.write_text(malformed, encoding="ascii")
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.parse_gnu_time(path)

    def test_report_projection_is_bounded_path_free_and_no_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            probe = root / "probe"
            binary.write_bytes(b"binary")
            probe.write_bytes(b"probe")
            report = acceptance.new_report("a" * 40, "0.10.0-alpha.3", binary, probe)
            report["cases"] = [case_entry(acceptance.CASE_SPECS[0])]
            acceptance.validate_report(report, complete=False)
            markdown = acceptance.render_markdown(report)
            encoded = json.dumps(report, sort_keys=True)
            self.assertNotIn(str(root), markdown)
            self.assertNotIn(str(root), encoded)
            self.assertIn("not_run_no_input", markdown)
            self.assertIn("not a Wordfence export", markdown)

            json_path = root / "result.json"
            markdown_path = root / "result.md"
            acceptance.write_evidence_pair(report, json_path, markdown_path)
            first = json_path.read_bytes()
            self.assertLessEqual(len(first), acceptance.RESULT_LIMIT)
            self.assertLessEqual(markdown_path.stat().st_size, acceptance.RESULT_LIMIT)
            with self.assertRaises(FileExistsError):
                acceptance.write_evidence_pair(report, json_path, markdown_path)
            self.assertEqual(json_path.read_bytes(), first)

    def test_complete_report_requires_exact_five_request_loopback_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            probe = root / "probe"
            binary.write_bytes(b"binary")
            probe.write_bytes(b"probe")
            report = acceptance.new_report("a" * 40, "0.10.0-alpha.3", binary, probe)
        report["cases"] = [case_entry(case) for case in acceptance.CASE_SPECS]
        report["cli_acceptance"] = valid_cli_acceptance()
        report["status"] = "passed"
        acceptance.validate_report(report, complete=True)

        for field, value in (("root", 4), ("unknown", 1)):
            mutated = copy.deepcopy(report)
            mutated["cli_acceptance"]["loopback_request_counts"][field] = value
            with self.subTest(field=field):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.validate_report(mutated, complete=True)

        reordered = copy.deepcopy(report)
        reordered["cli_acceptance"]["request_trace"][3] = (
            "GET /wp-content/plugins/selected-plugin/style.css HTTP/1.1"
        )
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_report(reordered, complete=True)

    def test_report_rejects_mutated_trust_limits_and_resource_claims(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            probe = root / "probe"
            binary.write_bytes(b"binary")
            probe.write_bytes(b"probe")
            report = acceptance.new_report("a" * 40, "0.10.0-alpha.3", binary, probe)
        report["cases"] = [case_entry(case) for case in acceptance.CASE_SPECS]
        report["cli_acceptance"] = valid_cli_acceptance()
        report["status"] = "passed"
        acceptance.validate_report(report, complete=True)

        mutations = []
        identity = copy.deepcopy(report)
        identity["source"]["identity_limit"] = "authenticated source"
        mutations.append(identity)
        metric = copy.deepcopy(report)
        metric["environment"]["peak_memory_metric"] = "heap only"
        mutations.append(metric)
        scope = copy.deepcopy(report)
        scope["environment"]["process_scope"] = "machine wide"
        mutations.append(scope)
        limit = copy.deepcopy(report)
        limit["limits"]["retained_index_bytes"] += 1
        mutations.append(limit)
        limitations = copy.deepcopy(report)
        limitations["limitations"] = ["production ready"]
        mutations.append(limitations)
        cli_metric = copy.deepcopy(report)
        cli_metric["cli_acceptance"]["resources"]["elapsed_seconds"] = -1.0
        mutations.append(cli_metric)
        cli_peak = copy.deepcopy(report)
        cli_peak["cli_acceptance"]["resources"]["peak_rss_kib"] = True
        mutations.append(cli_peak)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.validate_report(mutation, complete=True)

    def test_output_limit_and_unsafe_failure_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            probe = root / "probe"
            binary.write_bytes(b"binary")
            probe.write_bytes(b"probe")
            report = acceptance.new_report("a" * 40, "0.10.0-alpha.3", binary, probe)
        report["failure"] = {"case": "case", "code": "C:\\private\\feed"}
        report["status"] = "failed"
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.validate_report(report, complete=False)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "too-large.txt"
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance._write_complete_new(path, b"x" * (acceptance.RESULT_LIMIT + 1))
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
