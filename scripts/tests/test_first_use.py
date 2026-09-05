"""Local-only regression checks for the first-use runner; no scanner capabilities.

The subprocess doubles below are tiny Python children, never substituted for
real binary/report evidence. Native CLI acceptance is a separate explicit run.
"""

from __future__ import annotations

import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "first_use.py"
SPEC = importlib.util.spec_from_file_location("first_use", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FixtureTests(unittest.TestCase):
    def request(self, fixture, method, path):
        connection = http.client.HTTPConnection("127.0.0.1", fixture.server.server_address[1], timeout=2)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read(runner.HEADER_LIMIT)
        finally:
            connection.close()

    def assert_closed(self, fixture):
        self.assertFalse(fixture.thread.is_alive())
        with self.assertRaises(OSError):
            socket.create_connection(fixture.server.server_address, timeout=0.2)

    def test_fixed_contract_hash_has_only_the_two_static_documents(self):
        description = runner.fixture_description()
        encoded = json.dumps(description["contract"], sort_keys=True, separators=(",", ":")).encode("ascii")
        self.assertEqual(description["sha256"], runner.digest_bytes(encoded))
        self.assertEqual(set(description["contract"]["routes"]), {"/", "/example"})
        self.assertEqual(description["contract"]["bind"], "127.0.0.1:0")
        self.assertEqual(description["contract"]["methods"], ["GET", "HEAD"])
        for document in runner.FIXTURE_RESPONSES.values():
            self.assertNotIn(b"href=", document)
            self.assertNotIn(b"src=", document)
            self.assertNotIn(b"<form", document)
            self.assertIn(b"not a vulnerable application", document)

    def test_get_head_unknown_and_unsupported_are_bounded_and_non_reflective(self):
        with runner.Fixture() as fixture:
            self.assertEqual(fixture.server.server_address[0], "127.0.0.1")
            self.assertGreater(fixture.server.server_address[1], 0)
            for path in ("/", "/example"):
                status, headers, body = self.request(fixture, "GET", path)
                self.assertEqual(status, 200)
                self.assertEqual(body, runner.DOCUMENT)
                self.assertEqual(int(headers["Content-Length"]), len(body))
                self.assertEqual(headers["Connection"], "close")
                status, headers, body = self.request(fixture, "HEAD", path)
                self.assertEqual(status, 200)
                self.assertEqual(body, b"")
                self.assertEqual(int(headers["Content-Length"]), len(runner.DOCUMENT))
            status, _, body = self.request(fixture, "GET", "/unlisted-document")
            self.assertEqual(status, 404)
            self.assertEqual(body, runner.NOT_FOUND)
            self.assertNotIn(b"unlisted-document", body)
            status, _, body = self.request(fixture, "POST", "/")
            self.assertEqual(status, 405)
            self.assertEqual(body, runner.METHOD_REFUSED)
        self.assert_closed(fixture)

    def test_fixture_never_reads_files_to_serve_a_request(self):
        with runner.Fixture() as fixture:
            with mock.patch("builtins.open", side_effect=AssertionError("fixture must not open a file")):
                self.assertEqual(self.request(fixture, "GET", "/")[2], runner.DOCUMENT)
                self.assertEqual(self.request(fixture, "GET", "/missing")[2], runner.NOT_FOUND)

    def test_fixture_is_closed_on_failure_and_cancellation(self):
        for failure in (ValueError, KeyboardInterrupt):
            fixture = runner.Fixture()
            with self.assertRaises(failure):
                with fixture:
                    raise failure()
            self.assert_closed(fixture)

    def test_readiness_failure_closes_the_bound_listener(self):
        fixture = runner.Fixture()
        with mock.patch.object(http.client.HTTPConnection, "getresponse", side_effect=TimeoutError):
            with self.assertRaises(TimeoutError):
                with fixture:
                    self.fail("readiness must fail")
        self.assert_closed(fixture)

    def test_incomplete_header_is_bounded_and_does_not_prevent_cleanup(self):
        with runner.Fixture() as fixture:
            with socket.create_connection(fixture.server.server_address, timeout=2) as client:
                client.settimeout(2)
                # One finite invalid request in an isolated fixture, not load.
                client.sendall(b"G" * runner.HEADER_LIMIT)
                self.assertEqual(client.recv(1), b"")
            self.assertEqual(fixture.server.snapshot()["invalid"], 1)
        self.assert_closed(fixture)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        (self.directory / "captures").mkdir()
        self.addCleanup(self.temp.cleanup)

    def command(self, code, record, **limits):
        return runner.run_command([sys.executable, "-c", code], self.directory, record, **limits)

    def test_real_small_child_captures_status_argv_and_exact_hashes(self):
        record = {"invocation_id": "child"}
        stdout, stderr = self.command("import sys; print('bounded child'); sys.stderr.write('diagnostic'); sys.exit(7)", record)
        self.assertEqual(record["exit_code"], 7)
        self.assertEqual(stdout.strip(), b"bounded child")
        self.assertEqual(stderr, b"diagnostic")
        self.assertEqual(record["argv"][0], sys.executable)
        for stream, data in (("stdout", stdout), ("stderr", stderr)):
            self.assertEqual(record[stream]["sha256"], runner.digest_bytes(data))
            self.assertEqual((self.directory / record[stream]["path"]).read_bytes(), data)

    def test_timeout_reaps_the_owned_child_and_retains_evidence(self):
        children = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        record = {"invocation_id": "timeout"}
        with mock.patch.object(runner.subprocess, "Popen", side_effect=start):
            with self.assertRaisesRegex(runner.AcceptanceError, "wall-time"):
                self.command("import time; time.sleep(30)", record, timeout=0.15)
        self.assertIsNotNone(children[0].poll())
        self.assertIsNotNone(record["exit_code"])
        self.assertTrue((self.directory / record["stderr"]["path"]).is_file())

    def test_capture_overflow_is_bounded_and_child_is_reaped(self):
        record = {"invocation_id": "overflow"}
        with self.assertRaisesRegex(runner.AcceptanceError, "capture exceeded"):
            self.command("import sys; sys.stdout.write('x' * 4096)", record, capture_limit=64)
        self.assertTrue(record["capture_limit_exceeded"])
        self.assertEqual(record["stdout"]["bytes"], 64)
        self.assertIsNotNone(record["exit_code"])

    def test_cancellation_reaps_child_and_preserves_original_interrupt(self):
        children = []
        real_popen = subprocess.Popen

        def start(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            real_wait = child.wait
            calls = 0

            def interrupted_wait(*wait_args, **wait_kwargs):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise KeyboardInterrupt
                return real_wait(*wait_args, **wait_kwargs)

            child.wait = interrupted_wait
            return child

        record = {"invocation_id": "cancelled"}
        with mock.patch.object(runner.subprocess, "Popen", side_effect=start):
            with self.assertRaises(KeyboardInterrupt):
                self.command("import time; time.sleep(30)", record)
        self.assertIsNotNone(children[0].poll())
        self.assertIsNotNone(record["exit_code"])

    def test_blocked_child_is_recorded_without_retry_or_workaround(self):
        record = {"invocation_id": "blocked"}
        with mock.patch.object(runner.subprocess, "Popen", side_effect=PermissionError(13, "blocked")) as launch:
            with self.assertRaisesRegex(runner.AcceptanceError, "host protections were not changed"):
                self.command("pass", record)
        self.assertEqual(launch.call_count, 1)
        self.assertIsNone(record["exit_code"])
        self.assertEqual(record["start_or_io_error"]["errno"], 13)

    def test_pipe_read_error_cannot_be_reported_as_a_complete_capture(self):
        child = mock.Mock()
        child.poll.return_value = 0
        child.returncode = 0
        child.stdout.read1.side_effect = OSError("synthetic pipe failure")
        child.stderr = io.BytesIO(b"")
        record = {"invocation_id": "pipe-error"}
        with mock.patch.object(runner.subprocess, "Popen", return_value=child):
            with self.assertRaisesRegex(runner.AcceptanceError, "before normal EOF"):
                self.command("pass", record)
        self.assertEqual(record["capture_read_errors"], ["OSError"])
        self.assertEqual(record["exit_code"], 0)
        self.assertEqual(record["stdout"]["bytes"], 0)

    def test_process_exit_race_does_not_replace_original_failure(self):
        child = mock.Mock()
        child.poll.side_effect = [None, 0]
        child.terminate.side_effect = ProcessLookupError()
        with mock.patch.object(runner.os, "name", "nt"):
            runner.stop_process(child)
        child.wait.assert_called_once_with(timeout=2)


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.binary = Path(sys.executable)
        self.addCleanup(self.temp.cleanup)
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def run_harness(self, output, **kwargs):
        return runner.run_acceptance(self.binary, output, "57e5ddad7732b0b2c3d5988898aa2e4af5015195", "default", "0.10.0-alpha.2", **kwargs)

    def test_existing_output_is_not_changed_or_removed(self):
        output = self.directory / "existing"
        output.mkdir()
        original = output / "keep.txt"
        original.write_bytes(b"existing user material")
        with self.assertRaisesRegex(runner.AcceptanceError, "fresh"):
            self.run_harness(output)
        self.assertEqual(original.read_bytes(), b"existing user material")

    def test_no_target_option_or_implicit_acquisition_is_available(self):
        with mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(SystemExit) as exit_code:
                runner.main(["--binary", str(self.binary), "--output", str(self.directory / "unused"),
                             "--source-ref", "v0.10.0-alpha.1", "--build-features", "release-bundle",
                             "--expect-version", "0.10.0-alpha.1", "--target", "http://127.0.0.1/"])
        self.assertIn("unrecognized arguments: --target", stderr.getvalue())
        self.assertEqual(exit_code.exception.code, 2)

    def test_wrong_binary_version_fails_before_fixture_start(self):
        def wrong_version(argv, directory, record):
            record["exit_code"] = 0
            return b"termivar 0.0.0\n", b""

        with mock.patch.object(runner, "run_command", side_effect=wrong_version):
            with mock.patch.object(runner, "Fixture") as fixture:
                result = self.run_harness(self.directory / "wrong-version")
        fixture.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["binary"]["actual_version_output"], "termivar 0.0.0")
        self.assertEqual(result["failure"], "binary version did not match expectation")

    def test_floating_source_ref_is_not_accepted_as_pinned_provenance(self):
        with self.assertRaisesRegex(runner.AcceptanceError, "full commit SHA"):
            runner.run_acceptance(self.binary, self.directory / "floating", "main", "default", "0.10.0-alpha.2")

    def test_proxy_is_refused_without_changing_environment_but_no_proxy_alone_is_allowed(self):
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "configured", "NO_PROXY": "127.0.0.1"}):
            with self.assertRaisesRegex(runner.AcceptanceError, "proxy configuration"):
                self.run_harness(self.directory / "proxy-output")
            self.assertEqual(os.environ["HTTP_PROXY"], "configured")
        with mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1"}):
            with mock.patch.object(runner, "exercise"):
                self.assertEqual(self.run_harness(self.directory / "no-proxy-output")["status"], "passed")

    def test_failure_and_cancellation_write_truthful_provenance(self):
        for name, failure, expected in (("failure", runner.AcceptanceError("checked failure"), "failed"),
                                        ("cancel", KeyboardInterrupt(), "cancelled")):
            output = self.directory / name
            with mock.patch.object(runner, "exercise", side_effect=failure):
                result = self.run_harness(output)
            self.assertEqual(result["status"], expected)
            self.assertEqual(json.loads((output / "provenance.json").read_text())["status"], expected)
            self.assertFalse((output / "assessment.json").exists())
            self.assertEqual(result["binary"]["sha256"], runner.digest_file(self.binary))
            self.assertNotIn("actual_version_output", result["binary"])

    def test_public_provenance_changes_only_the_two_path_fields_and_discloses_them(self):
        raw = {"binary": {"path": "/private/binary", "sha256": "measured-test-digest"},
               "invocations": [{"argv": ["/private/binary", "scan", "http://127.0.0.1:1234/"],
                                "exit_code": 1, "fixture_requests": {"example": 1}, "started_at": "fixture-time"}],
               "status": "failed", "failure": "checked failure", "normalization": []}
        original = json.loads(json.dumps(raw))
        public = runner.public_provenance(raw)
        self.assertEqual(raw, original)
        self.assertEqual(public["binary"]["path"], "<LOCAL_BINARY>")
        self.assertEqual(public["invocations"][0]["argv"][0], "<LOCAL_BINARY>")
        self.assertEqual(public["normalization"][0]["fields"], ["binary.path", "invocations[*].argv[0]"])
        public["binary"]["path"] = raw["binary"]["path"]
        public["invocations"][0]["argv"][0] = raw["invocations"][0]["argv"][0]
        public["normalization"] = []
        self.assertEqual(public, raw)

    def test_sample_checks_reject_private_paths_and_external_or_active_html(self):
        for data in (b"https://example.invalid/", str(self.binary).encode(), b"C:\\Users\\private"):
            with self.assertRaises(runner.AcceptanceError):
                runner.validate_sample(data, self.binary)
        for element in ("<script></script>", '<img src="//example.invalid/image">',
                        '<div onclick="action()">', "<form></form>"):
            with self.assertRaises(runner.AcceptanceError):
                runner.ReportHTML().feed(element)
        with self.assertRaises(runner.AcceptanceError):
            runner.validate_sample(b"<html><body>truncated", self.binary, html=True)

    def test_invalid_json_and_report_size_fail_closed(self):
        for data in (b"not JSON", b"{}{}", b"[]"):
            with self.assertRaises(runner.AcceptanceError):
                runner.parse_document(data)
        path = self.directory / "report.json"
        path.write_bytes(b"123456789")
        with mock.patch.object(runner, "REPORT_LIMIT", 8):
            with self.assertRaises(runner.AcceptanceError):
                runner.bounded_report(path)


if __name__ == "__main__":
    unittest.main()
