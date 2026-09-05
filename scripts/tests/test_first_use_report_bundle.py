"""Local-only tests for the fixed report-bundle example helper."""

from __future__ import annotations

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
SCRIPT = SCRIPTS / "report_bundle_example.py"
SPEC = importlib.util.spec_from_file_location("report_bundle_example", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bundle(directory: Path, item_count: int = 1) -> bytes:
    directory.mkdir()
    html = b"<!doctype html><html><body>bounded fixture</body></html>"
    assessment = {
        "schema": runner.ASSESSMENT_SCHEMA,
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": item_count,
        "items": [{"fixture": index} for index in range(item_count)],
    }
    assessment_bytes = json.dumps(assessment, separators=(",", ":")).encode()
    manifest = {
        "schema": runner.BUNDLE_SCHEMA,
        "producer": {"product": "Termivar", "version": "0.10.0-alpha.2"},
        "assessment": {
            "profile": "web-review", "status": "complete",
            "subject_count": 1, "item_count": item_count,
        },
        "files": [
            {"name": "assessment.html", "format": "html",
             "media_type": "text/html; charset=utf-8",
             "byte_length": len(html), "sha256": digest(html)},
            {"name": "assessment.json", "format": "json",
             "media_type": "application/json",
             "byte_length": len(assessment_bytes), "sha256": digest(assessment_bytes)},
        ],
    }
    (directory / "assessment.html").write_bytes(html)
    (directory / "assessment.json").write_bytes(assessment_bytes)
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return assessment_bytes


class FakeServer:
    def __init__(self):
        self.counts = {
            "root": 1, "example": 0, "unknown": 0,
            "unsupported": 0, "invalid": 0,
        }

    def snapshot(self):
        return self.counts.copy()


class FakeFixture:
    last = None

    def __init__(self):
        self.server = FakeServer()
        self.origin = "http://127.0.0.1:48123/"
        FakeFixture.last = self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


class BundleValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def test_manifest_hashes_lengths_counts_and_fixed_file_set(self):
        directory = self.root / "bundle"
        assessment = write_bundle(directory, item_count=2)
        result = runner.validate_bundle(directory)
        self.assertEqual(result["assessment"]["item_count"], 2)
        self.assertEqual(result["assessment_json_sha256"], digest(assessment))
        self.assertEqual([entry["name"] for entry in result["files"]],
                         list(runner.FIXED_FILES))
        for entry in result["files"]:
            data = (directory / entry["name"]).read_bytes()
            self.assertEqual(entry["bytes"], len(data))
            self.assertEqual(entry["sha256"], digest(data))

    def test_extra_file_and_incorrect_digest_fail_closed(self):
        directory = self.root / "extra"
        write_bundle(directory)
        (directory / "foreign.txt").write_text("foreign")
        with self.assertRaisesRegex(runner.first_use.AcceptanceError, "exactly"):
            runner.validate_bundle(directory)

        directory = self.root / "digest"
        write_bundle(directory)
        manifest = json.loads((directory / "manifest.json").read_text())
        manifest["files"][0]["sha256"] = "0" * 64
        (directory / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(runner.first_use.AcceptanceError, "digest"):
            runner.validate_bundle(directory)

    def test_duplicate_keys_and_self_compare_contract_fail_closed(self):
        with self.assertRaisesRegex(runner.first_use.AcceptanceError, "duplicate"):
            runner.parse_json(b'{"schema":"a","schema":"b"}', "fixture")
        invalid = json.dumps({
            "schema": runner.COMPARISON_SCHEMA,
            "scope_assurance": "operator-declared",
            "before": {"sha256": "a" * 64}, "after": {"sha256": "a" * 64},
            "only_in_after": [], "only_in_before": [], "changed": [], "unchanged": [],
        }).encode()
        with self.assertRaisesRegex(runner.first_use.AcceptanceError, "unchanged"):
            runner.validate_self_comparison(invalid, 1, "a" * 64)


class EndToEndOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.output = self.root / "bundle"
        self.binary = Path(sys.executable)
        self.addCleanup(self.temp.cleanup)
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_one_fixed_scan_then_offline_self_compare(self):
        invocations = []

        def command(argv, directory, record):
            invocations.append(argv[1:])
            record["exit_code"] = 0
            if argv[1] == "scan":
                self.assertEqual(argv[1:4], ["scan", FakeFixture.last.origin, "--profile"])
                self.assertEqual(argv[4:], ["web-review", "--report-dir", str(self.output)])
                FakeFixture.last.server.counts["root"] += 3
                assessment = write_bundle(self.output, item_count=2)
                self.assessment_digest = digest(assessment)
                return b"", b"report bundle written\n"
            self.assertEqual(argv[1:3], ["report", "compare"])
            comparison = {
                "schema": runner.COMPARISON_SCHEMA,
                "scope_assurance": "operator-declared",
                "before": {"sha256": self.assessment_digest},
                "after": {"sha256": self.assessment_digest},
                "only_in_after": [], "only_in_before": [], "changed": [],
                "unchanged": [{}, {}],
            }
            return json.dumps(comparison).encode(), b""

        with mock.patch.object(runner.first_use, "Fixture", FakeFixture), \
                mock.patch.object(runner.first_use, "run_command", side_effect=command):
            result = runner.run_example(self.binary, self.output)
        self.assertEqual([call[0] for call in invocations], ["scan", "report"])
        self.assertEqual(result["invocations"], {"scan": 1, "report_compare": 1})
        self.assertEqual(result["fixture"]["scan_request_total"], 3)
        self.assertEqual(sum(result["fixture"]["compare_requests"].values()), 0)
        self.assertEqual(result["comparison"]["unchanged"], 2)
        self.assertTrue(result["claims"]["one_assessment_supplied_both_formats"])
        self.assertLessEqual(len(runner.encode_summary(result)), runner.SUMMARY_LIMIT)

    def test_proxy_and_existing_output_refuse_before_fixture(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "configured"}, clear=True), \
                mock.patch.object(runner.first_use, "Fixture") as fixture:
            with self.assertRaisesRegex(runner.first_use.AcceptanceError, "proxy"):
                runner.run_example(self.binary, self.output)
        fixture.assert_not_called()
        self.assertFalse(self.output.exists())

        self.output.mkdir()
        marker = self.output / "foreign.txt"
        marker.write_text("preserve")
        with mock.patch.object(runner.first_use, "Fixture") as fixture:
            with self.assertRaisesRegex(runner.first_use.AcceptanceError, "fresh"):
                runner.run_example(self.binary, self.output)
        fixture.assert_not_called()
        self.assertEqual(marker.read_text(), "preserve")

    def test_no_arbitrary_target_option_exists(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(SystemExit) as error:
                runner.main([
                    "--binary", str(self.binary), "--output", str(self.output),
                    "--target", "https://example.invalid/",
                ])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("unrecognized arguments: --target", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
