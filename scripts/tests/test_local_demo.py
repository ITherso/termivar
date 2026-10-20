"""Synthetic process doubles for the local demo; not native/CMS execution evidence."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("local_demo", SCRIPTS / "local_demo.py")
assert SPEC is not None and SPEC.loader is not None
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)

# Handwritten synthetic rows follow the reviewed rendered-assessment and
# ComparisonItem wire shapes. Expected identities/counts are independent of
# the consumer under test and of the production comparison implementation.
FINGERPRINT_ONE = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
FINGERPRINT_TWO = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
SOURCE = {
    "schema": "venom-rendered-assessment/v1",
    "source_schema": "venom-assessment-run/v1", "run_schema": "venom-run/v1",
    "profile_schema": "venom.scan-profile/v1", "profile": "web-review",
    "status": "complete", "subject_count": 1, "item_count": 2,
    "items": [
        {
            "schema": "venom-assessment-item/v1", "capability_id": "web.passive.csp.missing@1",
            "subject_reference": "subject-0000", "title": "Synthetic content policy observation",
            "disposition": "informational", "claim_basis": "observation", "severity": None,
            "confidence_ppm": 1000000, "fingerprint": FINGERPRINT_ONE, "evidence_count": 1,
            "redacted_summary": "Original synthetic fixture; no target finding.",
            "category": "content-policy", "cwe": None,
            "remediation": {"id": "web.remediation.csp@1", "summary": "Review the content policy."},
            "evidence_references": ["evidence-0000"], "control_evidence_references": [],
            "candidate_evidence_references": [], "case_reference": None,
            "outcome_reference": None, "verification_stage": None,
        },
        {
            "schema": "venom-assessment-item/v1", "capability_id": "web.passive.referrer-policy.missing@1",
            "subject_reference": "subject-0000", "title": "Synthetic referrer policy observation",
            "disposition": "informational", "claim_basis": "observation", "severity": None,
            "confidence_ppm": 1000000, "fingerprint": FINGERPRINT_TWO, "evidence_count": 1,
            "redacted_summary": "Original synthetic fixture; no target finding.",
            "category": "browser-defense", "cwe": None,
            "remediation": {"id": "web.remediation.referrer-policy@1", "summary": "Review the referrer policy."},
            "evidence_references": ["evidence-0000"], "control_evidence_references": [],
            "candidate_evidence_references": [], "case_reference": None,
            "outcome_reference": None, "verification_stage": None,
        },
    ],
}
PROJECTION_ONE = {
    "title": "Synthetic content policy observation", "category": "content-policy",
    "disposition": "informational", "claim_basis": "observation", "severity": None,
    "cwe": None, "confidence_ppm": 1000000,
    "redacted_summary": "Original synthetic fixture; no target finding.",
    "remediation": {"id": "web.remediation.csp@1", "summary": "Review the content policy."},
    "evidence": {"evidence_count": 1, "evidence_reference_count": 1,
                 "control_reference_count": 0, "candidate_reference_count": 0,
                 "case_present": False, "outcome_present": False, "verification_stage": None},
}
PROJECTION_TWO = {
    "title": "Synthetic referrer policy observation", "category": "browser-defense",
    "disposition": "informational", "claim_basis": "observation", "severity": None,
    "cwe": None, "confidence_ppm": 1000000,
    "redacted_summary": "Original synthetic fixture; no target finding.",
    "remediation": {"id": "web.remediation.referrer-policy@1", "summary": "Review the referrer policy."},
    "evidence": {"evidence_count": 1, "evidence_reference_count": 1,
                 "control_reference_count": 0, "candidate_reference_count": 0,
                 "case_present": False, "outcome_present": False, "verification_stage": None},
}


def encoded(document):
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_bundle(path, source=None):
    source = copy.deepcopy(SOURCE if source is None else source)
    path.mkdir(mode=0o700)
    payloads = {
        "assessment.html": b"<!doctype html><html><head><title>Termivar assessment report</title></head><body><p>informational synthetic fixture</p></body></html>",
        "assessment.json": encoded(source),
    }
    for name, data in payloads.items():
        (path / name).write_bytes(data)
    manifest = {
        "schema": "termivar-report-bundle/v1",
        "producer": {"product": "Termivar", "version": "4.5.6-demo.1"},
        "assessment": {"profile": "web-review", "status": "complete",
                       "subject_count": 1, "item_count": source["item_count"]},
        "files": [
            {"name": "assessment.html", "format": "html", "media_type": "text/html; charset=utf-8",
             "byte_length": len(payloads["assessment.html"]), "sha256": digest(payloads["assessment.html"])},
            {"name": "assessment.json", "format": "json", "media_type": "application/json",
             "byte_length": len(payloads["assessment.json"]), "sha256": digest(payloads["assessment.json"])},
        ],
    }
    (path / "manifest.json").write_bytes(encoded(manifest))
    return payloads


def comparison(source_bytes):
    metadata = {"sha256": digest(source_bytes), "schema": "venom-rendered-assessment/v1",
                "profile": "web-review", "status": "complete", "subject_count": 1,
                "item_count": 2, "optional_audits": {}}
    return {
        "schema": "termivar-report-comparison/v1", "scope_assurance": "operator-declared",
        "coverage_equivalence": "not-established", "source_authenticity": "not-established-by-parsing",
        "interpretation_limits": [
            "Imported dispositions and claim bases are untrusted source labels, not endorsed findings.",
            "Only in before does not mean fixed or resolved.",
            "Only in after does not establish when an observation first appeared.",
            "Unchanged means equal compared item projections, not equivalent coverage or security.",
        ],
        "before": copy.deepcopy(metadata), "after": copy.deepcopy(metadata),
        "only_in_after": [], "only_in_before": [], "changed": [],
        "unchanged": [
            {"fingerprint": FINGERPRINT_ONE, "capability_id": "web.passive.csp.missing@1",
             "before": copy.deepcopy(PROJECTION_ONE), "after": copy.deepcopy(PROJECTION_ONE), "changed_fields": []},
            {"fingerprint": FINGERPRINT_TWO, "capability_id": "web.passive.referrer-policy.missing@1",
             "before": copy.deepcopy(PROJECTION_TWO), "after": copy.deepcopy(PROJECTION_TWO), "changed_fields": []},
        ],
    }


def verification(payloads, manifest_bytes):
    return {
        "schema": "termivar-report-verification/v1", "status": "integrity_match", "reason_codes": [],
        "manifest": {"schema": "termivar-report-bundle/v1", "sha256": digest(manifest_bytes),
                     "producer_product": "Termivar", "producer_version": "4.5.6-demo.1",
                     "profile": "web-review", "assessment_status": "complete",
                     "subject_count": 1, "item_count": 2},
        "checks": {
            "layout": "checked_matched", "manifest": "checked_matched",
            "assessment_document": "checked_matched", "assessment_summary": "checked_matched",
            **{name.removesuffix(".html").removesuffix(".json") + ("_html" if name.endswith(".html") else "_json"):
               {"name": name, "state": "checked_matched", "expected_byte_length": len(data),
                "observed_byte_length": len(data), "expected_sha256": digest(data),
                "observed_sha256": digest(data), **({"utf8": "checked_matched"} if name.endswith(".html") else {})}
               for name, data in payloads.items()},
        },
        "trust": {"producer_source_authenticity": "not_established",
                  "html_content_equivalence_or_executable_safety": "not_established",
                  "original_scan_scope_findings_and_remediation": "not_evaluated",
                  "filesystem_snapshot_after_this_invocation": "not_established"},
    }


class FakeFixture:
    last = None

    def __init__(self):
        self.origin = "http://127.0.0.1:48123/"
        self.counts = {"root": 1, "example": 0, "unknown": 0, "unsupported": 0, "invalid": 0}
        self.closed = False
        self.server = mock.Mock()
        self.server.snapshot.side_effect = lambda: self.counts.copy()
        self.server.socket.fileno.side_effect = lambda: -1 if self.closed else 9
        self.thread = mock.Mock()
        self.thread.is_alive.side_effect = lambda: not self.closed
        FakeFixture.last = self

    def __enter__(self):
        return self

    def close(self):
        self.closed = True


class FakeRunner:
    """A bounded process interface double; output is explicitly synthetic."""

    def __init__(self, case, mutation=None, source_mutation=None):
        self.case = case
        self.mutation = mutation
        self.source_mutation = source_mutation
        self.calls = []
        self.payloads = None

    def __call__(self, argv, directory, record, *, timeout, capture_limit):
        self.case.assertEqual(timeout, 60.0)
        self.case.assertEqual(capture_limit, 256 * 1024)
        name = record["invocation_id"]
        self.calls.append(name)
        record.update(argv=argv, exit_code=0, elapsed_ms=1)
        if name == "version":
            stdout, stderr = b"termivar 4.5.6-demo.1\n", b""
        elif name == "scan-bundle":
            self.case.assertFalse(FakeFixture.last.closed)
            self.case.assertEqual(argv[1:4], ["scan", FakeFixture.last.origin, "--profile"])
            self.case.assertEqual(argv[4:], ["web-review", "--report-dir", str(directory / "bundle")])
            source = copy.deepcopy(SOURCE)
            if self.source_mutation:
                self.source_mutation(source)
            self.payloads = write_bundle(directory / "bundle", source)
            FakeFixture.last.counts["root"] += 3
            stdout, stderr = b"", b""
        elif name == "no-overwrite":
            self.case.assertFalse(FakeFixture.last.closed)
            self.case.assertEqual(argv[1], "scan")
            record["exit_code"] = 1
            stdout, stderr = b"", b"report bundle destination already exists\n"
        elif name == "verify-bundle":
            self.case.assertTrue(FakeFixture.last.closed, "Verify must run after real cleanup seam")
            self.case.assertEqual(argv[1:], ["report", "verify", "--dir", str(directory / "bundle"), "--format", "json"])
            stdout, stderr = encoded(verification(
                self.payloads, (directory / "bundle" / "manifest.json").read_bytes())), b""
        else:
            self.case.assertEqual(name, "compare-self")
            self.case.assertTrue(FakeFixture.last.closed, "Compare must run after cleanup seam")
            self.case.assertEqual(argv[1:], ["report", "compare", "--before", str(directory / "bundle" / "assessment.json"),
                                           "--after", str(directory / "bundle" / "assessment.json"), "--same-scope", "--format", "json"])
            stdout, stderr = encoded(comparison(self.payloads["assessment.json"])), b""
        if self.mutation:
            stdout, stderr = self.mutation(name, stdout, stderr, record, directory)
        self.case.assertLessEqual(len(stdout), capture_limit)
        self.case.assertLessEqual(len(stderr), capture_limit)
        for stream, data in (("stdout", stdout), ("stderr", stderr)):
            relative = "captures/" + name + "." + stream + ".txt"
            (directory / relative).write_bytes(data)
            record[stream] = {"path": relative, "bytes": len(data), "sha256": digest(data)}
        return stdout, stderr


class LocalDemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="termivar-demo-test-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.binary = self.root / "synthetic-termivar"
        self.binary.write_bytes(b"test process double, never executable")
        self.output = self.root / "output"
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def execute(self, runner, source_ref=None):
        with mock.patch.object(demo.first_use, "Fixture", FakeFixture), \
                mock.patch.object(demo.first_use, "run_command", side_effect=runner):
            return demo.run_demo(self.binary, self.output, source_ref)

    def test_entire_one_command_demo_and_literal_wire_contracts(self):
        runner = FakeRunner(self)
        result = self.execute(runner, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(result["status"], "passed")
        self.assertEqual(runner.calls, ["version", "scan-bundle", "no-overwrite", "verify-bundle", "compare-self"])
        self.assertEqual(result["bundle"]["assessment"]["item_count"], 2)
        self.assertEqual(result["self_comparison"], {"schema": "termivar-report-comparison/v1",
                         "only_in_after": 0, "only_in_before": 0, "changed": 0, "unchanged": 2})
        self.assertEqual(result["fixture"]["scan_requests_beyond_readiness"],
                         {"root": 3, "example": 0, "unknown": 0, "unsupported": 0, "invalid": 0})
        self.assertTrue(result["fixture"]["stopped_before_offline"])
        self.assertEqual(result["fixture"]["cleanup"], "stopped")
        self.assertEqual(result["binary"]["observed_version_output"], "termivar 4.5.6-demo.1")
        self.assertEqual(result["binary"]["source_identity"], "operator_declared")
        self.assertFalse(result["claims"]["source_ref_is_observed_or_attested"])
        self.assertFalse(result["claims"]["s16_integrated_program_acceptance"])
        recorded = json.loads((self.output / "demo-evidence.json").read_text())
        self.assertEqual(recorded, result)
        self.assertLessEqual((self.output / "demo-evidence.json").stat().st_size, 64 * 1024)
        self.assertEqual(len(list((self.output / "captures").iterdir())), 10)

    def test_source_is_not_inferred_when_declaration_absent(self):
        result = self.execute(FakeRunner(self))
        self.assertEqual(result["status"], "passed")
        self.assertIsNone(result["binary"]["declared_source_ref"])
        self.assertEqual(result["binary"]["source_identity"], "not_supplied")

    def test_invalid_native_exit_keeps_failure_evidence_and_stops_fixture(self):
        def mutation(name, stdout, stderr, record, directory):
            if name == "scan-bundle":
                record["exit_code"] = 7
            return stdout, stderr
        runner = FakeRunner(self, mutation)
        result = self.execute(runner)
        self.assertEqual(result["status"], "failed")
        self.assertIn("scan-bundle native exit", result["failure"])
        self.assertEqual(runner.calls, ["version", "scan-bundle"])
        self.assertTrue(FakeFixture.last.closed)
        self.assertEqual(json.loads((self.output / "demo-evidence.json").read_text())["status"], "failed")

    def test_wrong_request_accounting_fails_before_offline_work(self):
        def mutation(name, stdout, stderr, record, directory):
            if name == "scan-bundle":
                FakeFixture.last.counts["unknown"] += 1
            return stdout, stderr
        runner = FakeRunner(self, mutation)
        result = self.execute(runner)
        self.assertEqual(result["status"], "failed")
        self.assertIn("request trace", result["failure"])
        self.assertEqual(runner.calls, ["version", "scan-bundle"])

    def test_no_overwrite_refusal_and_offline_commands_cannot_mutate_bundle(self):
        for phase in ("no-overwrite", "verify-bundle", "compare-self"):
            with self.subTest(phase=phase):
                output = self.root / phase
                def mutation(name, stdout, stderr, record, directory):
                    if name == phase:
                        with (directory / "bundle" / "assessment.html").open("ab") as stream:
                            stream.write(b" ")
                    return stdout, stderr
                with mock.patch.object(demo.first_use, "Fixture", FakeFixture), \
                        mock.patch.object(demo.first_use, "run_command", side_effect=FakeRunner(self, mutation)):
                    result = demo.run_demo(self.binary, output)
                self.assertEqual(result["status"], "failed")
                self.assertTrue(FakeFixture.last.closed)

    def test_compare_groups_are_required_arrays_and_counts_cannot_override_them(self):
        for group in ("only_in_after", "only_in_before", "changed", "unchanged"):
            for value in (None, "missing", {}, 0, False):
                with self.subTest(group=group, value=value):
                    document = comparison(encoded(SOURCE))
                    if value == "missing":
                        del document[group]
                    else:
                        document[group] = value
                    document["counts"] = {"only_in_after": 0, "only_in_before": 0, "changed": 0, "unchanged": 2}
                    with self.assertRaises(demo.first_use.AcceptanceError):
                        demo.validate_comparison(encoded(document),
                            {"assessment_json_sha256": digest(encoded(SOURCE))},
                            {FINGERPRINT_ONE: "web.passive.csp.missing@1", FINGERPRINT_TWO: "web.passive.referrer-policy.missing@1"})

    def test_actual_orchestration_rejects_equal_count_identity_substitution(self):
        def mutation(name, stdout, stderr, record, directory):
            if name == "compare-self":
                doc = json.loads(stdout)
                doc["unchanged"][1] = copy.deepcopy(doc["unchanged"][0])
                stdout = encoded(doc)
            return stdout, stderr
        runner = FakeRunner(self, mutation)
        result = self.execute(runner)
        self.assertEqual(result["status"], "failed")
        self.assertIn("duplicated", result["failure"])
        self.assertEqual(runner.calls[-1], "compare-self")

    def test_bool_source_count_duplicate_source_and_changed_self_result_fail(self):
        for variant in ("bool-count", "duplicate-source", "changed-result", "bool-metadata"):
            with self.subTest(variant=variant):
                def source_mutation(source):
                    if variant == "bool-count":
                        source["item_count"] = True
                    if variant == "duplicate-source":
                        source["items"][1]["fingerprint"] = FINGERPRINT_ONE
                def mutation(name, stdout, stderr, record, directory):
                    if name == "compare-self" and variant == "changed-result":
                        doc = json.loads(stdout)
                        doc["changed"].append(doc["unchanged"].pop())
                        stdout = encoded(doc)
                    if name == "compare-self" and variant == "bool-metadata":
                        doc = json.loads(stdout)
                        doc["before"]["item_count"] = True
                        stdout = encoded(doc)
                    return stdout, stderr
                output = self.root / variant
                with mock.patch.object(demo.first_use, "Fixture", FakeFixture), \
                        mock.patch.object(demo.first_use, "run_command", side_effect=FakeRunner(self, mutation, source_mutation)):
                    result = demo.run_demo(self.binary, output)
                self.assertEqual(result["status"], "failed")

    def test_verification_result_requires_all_integrity_checks(self):
        for variant in ("missing-check", "wrong-digest", "bool-count"):
            with self.subTest(variant=variant):
                def mutation(name, stdout, stderr, record, directory):
                    if name == "verify-bundle":
                        doc = json.loads(stdout)
                        if variant == "missing-check":
                            del doc["checks"]["assessment_summary"]
                        elif variant == "wrong-digest":
                            doc["checks"]["assessment_json"]["observed_sha256"] = "0" * 64
                        else:
                            doc["manifest"]["item_count"] = True
                        stdout = encoded(doc)
                    return stdout, stderr
                self.output = self.root / variant
                runner = FakeRunner(self, mutation)
                result = self.execute(runner)
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("compare-self", runner.calls)

    def test_failure_evidence_write_does_not_conceal_original_native_failure(self):
        original_open = Path.open
        def fail_evidence(path, *args, **kwargs):
            if path.name == "demo-evidence.json":
                raise OSError("synthetic local write failure")
            return original_open(path, *args, **kwargs)
        def mutation(name, stdout, stderr, record, directory):
            if name == "scan-bundle":
                record["exit_code"] = 7
            return stdout, stderr
        with mock.patch.object(Path, "open", fail_evidence):
            result = self.execute(FakeRunner(self, mutation))
        self.assertEqual(result["status"], "failed")
        self.assertIn("scan-bundle native exit", result["failure"])
        self.assertEqual(result["evidence_write_error"], "OSError")
        self.assertTrue(FakeFixture.last.closed)

    def test_cancellation_and_binary_changes_never_publish_passed_evidence(self):
        for case in ("cancelled", "binary-changed"):
            with self.subTest(case=case):
                def mutation(name, stdout, stderr, record, directory):
                    if name == "scan-bundle" and case == "cancelled":
                        raise KeyboardInterrupt
                    if name == "compare-self" and case == "binary-changed":
                        self.binary.write_bytes(b"changed synthetic binary")
                    return stdout, stderr
                output = self.root / case
                with mock.patch.object(demo.first_use, "Fixture", FakeFixture), \
                        mock.patch.object(demo.first_use, "run_command", side_effect=FakeRunner(self, mutation)):
                    result = demo.run_demo(self.binary, output)
                self.assertEqual(result["status"], "cancelled" if case == "cancelled" else "failed")
                self.assertTrue(FakeFixture.last.closed)
                self.assertEqual(json.loads((output / "demo-evidence.json").read_text())["status"], result["status"])

    def test_proxy_existing_output_and_invalid_source_ref_fail_before_process_or_fixture(self):
        for case in ("proxy", "existing", "source"):
            with self.subTest(case=case), mock.patch.object(demo.first_use, "Fixture") as fixture, \
                    mock.patch.object(demo.first_use, "run_command") as process:
                output = self.root / case
                if case == "existing":
                    output.mkdir()
                    (output / "foreign.txt").write_bytes(b"preserve")
                with mock.patch.dict(os.environ, {"HTTPS_PROXY": "configured"} if case == "proxy" else {}, clear=True):
                    with self.assertRaises(demo.first_use.AcceptanceError):
                        demo.run_demo(self.binary, output, "not-a-source-ref" if case == "source" else None)
                fixture.assert_not_called()
                process.assert_not_called()
                if case == "existing":
                    self.assertEqual((output / "foreign.txt").read_bytes(), b"preserve")
                else:
                    self.assertFalse(output.exists())

    def test_no_target_option_and_no_hardcoded_version_requirement(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
            demo.main(["--binary", str(self.binary), "--output", str(self.output), "--target", "https://example.invalid/"])
        self.assertEqual(error.exception.code, 2)
        with mock.patch.object(demo.first_use, "Fixture", FakeFixture), \
                mock.patch.object(demo.first_use, "run_command", side_effect=FakeRunner(self)), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(demo.main(["--binary", str(self.binary), "--output", str(self.output)]), 0)
        self.assertIn("Verify: integrity_match", stdout.getvalue())
        self.assertIn("2 unchanged", stdout.getvalue())
        self.assertNotIn(str(self.root), stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
