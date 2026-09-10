import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY_ROOT / "scripts" / "wordpress_discovery_lab_acceptance.py"
SPEC = importlib.util.spec_from_file_location("wordpress_discovery_lab_acceptance", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)


BASE_FINGERPRINT = "sha256:" + "1" * 64
DISCOVERY_FINGERPRINT = "sha256:" + "2" * 64
BASE_CAPABILITY = "web.passive.synthetic@1"
DISCOVERY_CAPABILITY = "technology.wordpress-metadata-source-response-observed@1"


def synthetic_assessment_item(fingerprint, capability_id, title):
    return {
        "schema": "venom-assessment-item/v1",
        "capability_id": capability_id,
        "subject_reference": "subject-0000",
        "title": title,
        "disposition": "informational",
        "claim_basis": "observation",
        "severity": None,
        "confidence_ppm": 550_000,
        "fingerprint": fingerprint,
        "evidence_count": 1,
        "redacted_summary": "Synthetic acceptance observation.",
        "category": "synthetic-acceptance",
        "cwe": None,
        "remediation": {
            "id": "synthetic.remediation@1",
            "summary": "Review the synthetic acceptance observation.",
        },
        "evidence_references": ["evidence-0000"],
        "control_evidence_references": [],
        "candidate_evidence_references": [],
        "case_reference": None,
        "outcome_reference": None,
        "verification_stage": None,
    }


def synthetic_assessment(items, *, item_count=None):
    return {
        "schema": "venom-rendered-assessment/v1",
        "source_schema": "venom-assessment-run/v1",
        "run_schema": "venom-run/v1",
        "profile_schema": "venom.scan-profile/v1",
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": len(items) if item_count is None else item_count,
        "items": items,
    }


def synthetic_projection(title):
    return {
        "title": title,
        "category": "synthetic-acceptance",
        "disposition": "informational",
        "claim_basis": "observation",
        "severity": None,
        "cwe": None,
        "confidence_ppm": 550_000,
        "redacted_summary": "Synthetic acceptance observation.",
        "remediation": {
            "id": "synthetic.remediation@1",
            "summary": "Review the synthetic acceptance observation.",
        },
        "evidence": {
            "evidence_count": 1,
            "evidence_reference_count": 1,
            "control_reference_count": 0,
            "candidate_reference_count": 0,
            "case_present": False,
            "outcome_present": False,
            "verification_stage": None,
        },
    }


def comparison_item(
    fingerprint,
    capability_id,
    *,
    before,
    after,
    changed_fields,
):
    return {
        "fingerprint": fingerprint,
        "capability_id": capability_id,
        "before": before,
        "after": after,
        "changed_fields": changed_fields,
    }


def source_metadata(raw, item_count):
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema": "venom-rendered-assessment/v1",
        "source_schema": "venom-assessment-run/v1",
        "run_schema": "venom-run/v1",
        "profile_schema": "venom.scan-profile/v1",
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": item_count,
        "optional_audits": {},
    }


def wordpress_comparison(*, methodology="changed", coverage="changed"):
    def facet(status):
        return {
            "status": status,
            "changed_fields": [],
            "before": {},
            "after": {},
            "note": "Synthetic acceptance facet.",
        }

    empty_entities = {
        "paired_unchanged_count": 0,
        "paired_changed": [],
        "only_in_before": [],
        "only_in_after": [],
    }
    return {
        "schema": "termivar-wordpress-review-comparison/v2",
        "status": "compared",
        "scope_assurance": "operator-declared",
        "coverage": facet(coverage),
        "methodology": facet(methodology),
        "provenance": facet("unchanged"),
        "discovery_source_content": facet("not_comparable"),
        "components": copy.deepcopy(empty_entities),
        "advisories": copy.deepcopy(empty_entities),
        "interpretation_limits": [],
    }


def comparison_document(before_raw, before_count, after_raw, after_count, *, groups):
    return {
        "schema": "termivar-report-comparison/v1",
        "scope_assurance": "operator-declared",
        "coverage_equivalence": "not-established",
        "source_authenticity": "not-established-by-parsing",
        "interpretation_limits": [],
        "before": source_metadata(before_raw, before_count),
        "after": source_metadata(after_raw, after_count),
        **groups,
    }


class OfflineProcessRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, arguments, *, label, **_kwargs):
        argv = [str(argument) for argument in arguments]
        self.calls.append((label, argv))
        if label not in self.responses:
            raise AssertionError(f"unexpected synthetic command: {label}: {argv!r}")
        if "verification" in label:
            assert argv[1:4] == ["report", "verify", "--dir"]
        else:
            assert argv[1:4] == ["report", "compare", "--before"]
            assert "--after" in argv and "--same-scope" in argv
        assert argv[-2:] == ["--format", "json"]
        return runner.CommandResult(
            json.dumps(self.responses[label], separators=(",", ":")).encode("utf-8"),
            b"",
            0,
        )


def write_synthetic_bundle(root, name, items, *, item_count=None):
    bundle = root / name
    bundle.mkdir()
    raw = json.dumps(
        synthetic_assessment(items, item_count=item_count),
        separators=(",", ":"),
    ).encode("utf-8")
    (bundle / "assessment.json").write_bytes(raw)
    return bundle, raw


def self_comparison(raw, items):
    unchanged = []
    for item in items:
        projection = synthetic_projection(item["title"])
        unchanged.append(comparison_item(
            item["fingerprint"],
            item["capability_id"],
            before=projection,
            after=copy.deepcopy(projection),
            changed_fields=[],
        ))
    return comparison_document(
        raw,
        len(items),
        raw,
        len(items),
        groups={
            "only_in_after": [],
            "only_in_before": [],
            "changed": [],
            "unchanged": unchanged,
        },
    )


def offline_fixture(root, *, discovery_capability=DISCOVERY_CAPABILITY):
    base_item = synthetic_assessment_item(
        BASE_FINGERPRINT, BASE_CAPABILITY, "Synthetic baseline observation"
    )
    discovery_item = synthetic_assessment_item(
        DISCOVERY_FINGERPRINT,
        discovery_capability,
        "Synthetic discovery observation",
    )
    before_bundle, before_raw = write_synthetic_bundle(
        root, "pretty-review-only", [base_item]
    )
    after_bundle, after_raw = write_synthetic_bundle(
        root, "pretty-discovery", [base_item, discovery_item]
    )
    controlled = comparison_document(
        before_raw,
        1,
        after_raw,
        2,
        groups={
            "only_in_after": [comparison_item(
                DISCOVERY_FINGERPRINT,
                discovery_capability,
                before=None,
                after=synthetic_projection("Synthetic discovery observation"),
                changed_fields=[],
            )],
            "only_in_before": [],
            "changed": [comparison_item(
                BASE_FINGERPRINT,
                BASE_CAPABILITY,
                before=synthetic_projection("Synthetic baseline observation"),
                after=synthetic_projection("Synthetic baseline observation with discovery"),
                changed_fields=["title"],
            )],
            "unchanged": [],
        },
    )
    controlled["wordpress_review_comparison"] = wordpress_comparison()
    responses = {
        "offline verification pretty-review-only": {
            "schema": "termivar-report-verification/v1",
            "status": "integrity_match",
        },
        "offline self comparison pretty-review-only": self_comparison(
            before_raw, [base_item]
        ),
        "offline verification pretty-discovery": {
            "schema": "termivar-report-verification/v1",
            "status": "integrity_match",
        },
        "offline self comparison pretty-discovery": self_comparison(
            after_raw, [base_item, discovery_item]
        ),
        "offline collection-policy comparison": controlled,
    }
    scenarios = {
        "pretty-review-only": {"_bundle": str(before_bundle)},
        "pretty-discovery": {"_bundle": str(after_bundle)},
    }
    return scenarios, responses, (before_raw, after_raw)


class WordPressDiscoveryLabAcceptanceTests(unittest.TestCase):
    def test_real_lab_rejects_non_linux_host_before_docker_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            with mock.patch.object(runner.platform, "system", return_value="Windows"):
                with mock.patch.object(runner.shutil, "which") as which:
                    with self.assertRaisesRegex(
                        runner.AcceptanceError, "native Linux Docker engine"
                    ):
                        lab.start()
                    which.assert_not_called()

    def test_fixture_inventory_and_digest_pins_are_closed(self):
        result = runner.validate_fixture()
        self.assertEqual(result["file_count"], 12)
        self.assertRegex(result["fixture_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["ground_truth_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(result["image_references"]), set(runner.IMAGE_REFERENCES))
        for reference in result["image_references"]:
            self.assertRegex(reference, r"^[a-z]+@sha256:[0-9a-f]{64}$")

    def test_validate_only_executes_without_docker(self):
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--validate-only"],
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        document = json.loads(completed.stdout)
        self.assertEqual(document["schema"], runner.TASK_SCHEMA)
        self.assertEqual(document["status"], "validated")

    def test_process_runner_reports_fresh_command_elapsed_and_honest_peak_metric(self):
        result = runner.ProcessRunner().run(
            [sys.executable, "-c", "pass"],
            label="process metric self-test",
            measure_peak_memory=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertGreaterEqual(result.elapsed_seconds, 0.0)
        if runner.platform.system() == "Linux" and Path("/usr/bin/time").is_file():
            self.assertEqual(result.peak_memory["status"], "measured")
            self.assertEqual(result.peak_memory["unit"], "KiB")
            self.assertGreater(result.peak_memory["value"], 0)
        else:
            self.assertEqual(result.peak_memory["status"], "not_measured")

    def test_source_contains_no_broad_or_privileged_docker_operation(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "--privileged",
            "--network=host",
            "/var/run/docker.sock",
            "docker system prune",
            "docker image prune",
            "docker volume prune",
            "docker network prune",
            "remove_dir_all",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('"--internal"', source)
        self.assertNotIn('"--publish"', source)
        self.assertIn('super().__init__(("127.0.0.1", 0)', source)
        self.assertIn('"build", "--network=none", "--pull=false"', source)
        self.assertIn('"--env-file", str(self.wordpress_env)', source)
        self.assertEqual(source.count('"run", "--pull=never"'), 3)
        self.assertNotIn('"--user", "0:0"', source)
        dockerfile = (runner.FIXTURE_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("Listen 8080", dockerfile)
        self.assertIn("<VirtualHost *:8080>", dockerfile)
        self.assertTrue(dockerfile.rstrip().endswith("USER www-data"))
        for forbidden_import in (
            "import urllib",
            "from urllib",
            "import requests",
            "from requests",
        ):
            self.assertNotIn(forbidden_import, source)
        for forbidden_executable in ('"curl"', '"wget"'):
            self.assertNotIn(forbidden_executable, source)

    def test_loopback_relay_forwards_only_to_its_fixed_upstream(self):
        class ResponseHandler(socketserver.BaseRequestHandler):
            def handle(self):
                request = self.request.recv(4096)
                self.server.requests.append(request)
                self.request.sendall(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )

        upstream = socketserver.TCPServer(("127.0.0.1", 0), ResponseHandler)
        upstream.requests = []
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        relay = runner.LoopbackTcpRelay("127.0.0.1", upstream.server_address[1])
        relay_port = relay.start()
        try:
            with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
                client.sendall(b"GET /fixed HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                response = bytearray()
                while payload := client.recv(4096):
                    response.extend(payload)
            self.assertIn(b"200 OK", response)
            self.assertIn(b"GET /fixed HTTP/1.0", upstream.requests[0])
        finally:
            relay.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())

    def test_loopback_relay_stop_closes_an_active_handler(self):
        connected = threading.Event()
        release = threading.Event()

        class HoldingHandler(socketserver.BaseRequestHandler):
            def handle(self):
                connected.set()
                self.request.recv(1)
                release.wait(timeout=2)

        class ThreadedUpstream(socketserver.ThreadingTCPServer):
            daemon_threads = True

        upstream = ThreadedUpstream(("127.0.0.1", 0), HoldingHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        relay = runner.LoopbackTcpRelay("127.0.0.1", upstream.server_address[1])
        relay_port = relay.start()
        client = socket.create_connection(("127.0.0.1", relay_port), timeout=2)
        client.sendall(b"x")
        self.assertTrue(connected.wait(timeout=2))
        started = runner.time.monotonic()
        relay.stop()
        self.assertLess(runner.time.monotonic() - started, 2)
        client.close()
        release.set()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())

    def test_loopback_relay_can_close_before_start(self):
        relay = runner.LoopbackTcpRelay("127.0.0.1", 1)
        relay.stop()

    def test_loopback_relay_reports_post_startup_upstream_failure(self):
        relay = runner.LoopbackTcpRelay("127.0.0.1", 0)
        relay_port = relay.start()
        relay.acknowledge_startup()
        with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
            self.assertEqual(client.recv(1), b"")
        deadline = runner.time.monotonic() + 2
        while (relay._server.transport_failures() == 0
               and runner.time.monotonic() < deadline):
            runner.time.sleep(0.01)
        with self.assertRaisesRegex(runner.AcceptanceError, "transport failure"):
            relay.assert_healthy()
        relay.stop()

    def test_loopback_relay_reports_byte_limit_plus_one_and_still_stops(self):
        received = threading.Event()

        class DrainHandler(socketserver.BaseRequestHandler):
            def handle(self):
                received.set()
                while self.request.recv(4096):
                    pass

        upstream = socketserver.TCPServer(("127.0.0.1", 0), DrainHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        old_limit = runner.MAX_RELAY_CONNECTION_BYTES
        runner.MAX_RELAY_CONNECTION_BYTES = 8
        relay = runner.LoopbackTcpRelay("127.0.0.1", upstream.server_address[1])
        relay_port = relay.start()
        relay.acknowledge_startup()
        try:
            with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
                client.sendall(b"123456789")
                client.shutdown(socket.SHUT_WR)
                while client.recv(4096):
                    pass
            self.assertTrue(received.wait(timeout=2))
            deadline = runner.time.monotonic() + 2
            while (relay._server.limit_failures() == 0
                   and runner.time.monotonic() < deadline):
                runner.time.sleep(0.01)
            with self.assertRaisesRegex(runner.AcceptanceError, "connection or byte bound"):
                relay.assert_healthy()
        finally:
            relay.stop()
            runner.MAX_RELAY_CONNECTION_BYTES = old_limit
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())

    def test_html_execution_boundary_is_exact_and_bounded(self):
        html = (
            "<h3>Execution boundary</h3>"
            "<dl class=\"meta\">"
            "<dt>Exploit execution</dt><dd><code>not_performed</code></dd>"
            "<dt>Impact validation</dt><dd><code>not_performed</code></dd>"
            "</dl>"
        ).encode()
        runner._validate_wordpress_execution_boundary(html)

        duplicated = html.replace(
            b"</dl>",
            b"<dt>Exploit execution</dt><dd><code>not_performed</code></dd></dl>",
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "omits or duplicates"):
            runner._validate_wordpress_execution_boundary(duplicated)
        with self.assertRaisesRegex(runner.AcceptanceError, "report bound"):
            runner._validate_wordpress_execution_boundary(b"")

    def test_internal_container_address_rejects_network_or_address_drift(self):
        network_name = "termivar-wp-net-0123456789ab"
        network_id = "a" * 64
        network = {
            "Name": network_name,
            "Id": network_id,
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "172.30.0.0/16"}]},
        }
        attachments = {
            network_name: {"NetworkID": network_id, "IPAddress": "172.30.0.7"}
        }
        self.assertEqual(
            runner._internal_container_address(network_name, network, attachments),
            "172.30.0.7",
        )
        mutations = []
        not_internal = copy.deepcopy(network)
        not_internal["Internal"] = False
        mutations.append((not_internal, attachments))
        public_subnet = copy.deepcopy(network)
        public_subnet["IPAM"]["Config"][0]["Subnet"] = "8.8.8.0/24"
        mutations.append((public_subnet, attachments))
        wrong_identity = copy.deepcopy(attachments)
        wrong_identity[network_name]["NetworkID"] = "b" * 64
        mutations.append((network, wrong_identity))
        public_address = copy.deepcopy(attachments)
        public_address[network_name]["IPAddress"] = "8.8.8.8"
        mutations.append((network, public_address))
        extra_network = copy.deepcopy(attachments)
        extra_network["foreign"] = {"NetworkID": "c" * 64, "IPAddress": "172.31.0.2"}
        mutations.append((network, extra_network))
        for network_case, attachment_case in mutations:
            with self.subTest(network=network_case, attachments=attachment_case):
                with self.assertRaises(runner.AcceptanceError):
                    runner._internal_container_address(
                        network_name, network_case, attachment_case
                    )

    def test_plain_permalink_oracle_tracks_current_core_index_form(self):
        self.assertEqual(
            runner.EXPECTED_DISCOVERY_PATHS["plain"][0],
            "/index.php?rest_route=/",
        )
        self.assertNotIn("/?rest_route=/", runner.EXPECTED_DISCOVERY_PATHS["plain"])
        self.assertEqual(runner.EXPECTED_DISCOVERY_PATHS["pretty"][0], "/wp-json/")

    def test_exact_four_request_delta_preserves_base_and_extra_order(self):
        review = [("GET", "/", 200, ()), ("HEAD", "/", 200, ())]
        expected = [
            ("GET", path, 200, ()) for path in runner.EXPECTED_DISCOVERY_PATHS["pretty"]
        ]
        runner._assert_request_delta(
            review,
            [review[0], expected[0], expected[1], review[1], expected[2], expected[3]],
            "pretty",
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "reordered"):
            runner._assert_request_delta(review, [*reversed(review), *expected], "pretty")
        with self.assertRaisesRegex(runner.AcceptanceError, "ordered four-request oracle"):
            runner._assert_request_delta(review, [*review, *reversed(expected)], "pretty")
        with self.assertRaisesRegex(runner.AcceptanceError, "ordered four-request oracle"):
            runner._assert_request_delta(
                review,
                [*review, *expected, ("GET", "/wp-json/wp/v2/users", 200, ())],
                "pretty",
            )
        forbidden = list(expected)
        forbidden[0] = (*forbidden[0][:3], ("authorization",))
        with self.assertRaisesRegex(runner.AcceptanceError, "ordered four-request oracle"):
            runner._assert_request_delta(review, [*review, *forbidden], "pretty")

    def test_apache_request_parser_ignores_non_access_log_output(self):
        line = (
            '172.19.0.1 - - [10/Sep/2026:00:00:00 +0000] '
            '"GET /wp-json/ HTTP/1.1" 200 123 '
            'tmv_auth=- tmv_cookie=- tmv_proxy_auth=-'
        )
        match = runner.REQUEST_RE.search(line)
        self.assertIsNotNone(match)
        self.assertEqual((match["method"], match["target"], match["status"]),
                         ("GET", "/wp-json/", "200"))
        self.assertEqual(
            (match["authorization"], match["cookie"], match["proxy_authorization"]),
            ("-", "-", "-"),
        )
        self.assertIsNone(runner.REQUEST_RE.search("Apache configured -- resuming normal operations"))

    @staticmethod
    def discovery_document():
        return {
            "item_count": 1,
            "items": [{
                "capability_id": "technology.wordpress-metadata-source-response-observed@1",
                "title": "WordPress metadata-source response outcome observed",
                "category": "wordpress-metadata-source-response",
                "disposition": "informational",
                "claim_basis": "observation",
                "severity": None,
                "cwe": None,
                "confidence_ppm": 550_000,
                "evidence_count": 4,
                "evidence_references": [
                    "evidence-0001", "evidence-0002", "evidence-0003", "evidence-0004",
                ],
                "control_evidence_references": [],
                "candidate_evidence_references": [],
                "case_reference": None,
                "outcome_reference": None,
                "verification_stage": None,
                "redacted_summary": "Bounded response evidence from selected public WordPress metadata sources was collected; usable metadata, installation authenticity, vulnerable-code reachability, and advisory impact were not established.",
                "remediation": {
                    "id": "wordpress-metadata-review",
                    "summary": "Confirm the installation inventory and source-qualified metadata before making a security or remediation decision.",
                },
            }],
            "wordpress_review": {
                "schema": "security.wordpress-review-audit/v7",
                "review_basis_schema": "security.wordpress-review-audit/v1",
                "additional_request_count": 4,
                "components": [
                    {
                        "identity": {"kind": "core", "slug": "wordpress"},
                        "identity_sources": [
                            "generator_metadata", "same_origin_asset_path"
                        ],
                        "versions": [
                            {
                                "value": "7.1",
                                "source": "generator_metadata",
                                "confidence": "public_declaration",
                            }
                        ],
                    },
                    {
                        "identity": {"kind": "theme", "slug": "termivar-child"},
                        "identity_sources": [
                            "same_origin_asset_path", "theme_stylesheet_declaration"
                        ],
                        "versions": [{
                            "value": "1.4.0",
                            "source": "theme_stylesheet_declaration",
                            "confidence": "public_declaration",
                        }],
                    },
                    {
                        "identity": {"kind": "theme", "slug": "termivar-parent"},
                        "identity_sources": ["theme_stylesheet_declaration"],
                        "versions": [{
                            "value": "3.2.1",
                            "source": "theme_stylesheet_declaration",
                            "confidence": "public_declaration",
                        }],
                    },
                    {
                        "identity": {"kind": "plugin", "slug": "termivar-metadata-lab"},
                        "identity_sources": ["same_origin_asset_path"],
                        "versions": [],
                    },
                ],
            },
            "wordpress_discovery": {
                "schema": "security.wordpress-discovery-audit/v1",
                "capability_id": "technology.wordpress-metadata-discovery@1",
                "policy_id": "termivar.wordpress-metadata-discovery/v1",
                "selected": True,
                "method": "get",
                "credential_mode": "anonymous",
                "seed_count": 3,
                "candidate_count": 4,
                "candidate_limit_reached": False,
                "omitted_candidate_count": 0,
                "attempted_request_count": 4,
                "completed_response_count": 4,
                "committed_response_count": 4,
                "response_bytes": 1024,
                "source_count": 4,
                "sources": [
                    {
                        "kind": "rest_index",
                        "parent_depth": 0,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0001"],
                        "namespaces": ["wp/v2", "termivar-lab/v1"],
                    },
                    {
                        "kind": "theme_stylesheet",
                        "component": {"kind": "theme", "slug": "termivar-child"},
                        "parent_depth": 0,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0002"],
                        "theme": {
                            "name": "Termivar Metadata Child",
                            "version": "1.4.0",
                            "template": "termivar-parent",
                        },
                    },
                    {
                        "kind": "theme_stylesheet",
                        "component": {"kind": "theme", "slug": "termivar-parent"},
                        "parent_depth": 1,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0003"],
                        "theme": {
                            "name": "Termivar Metadata Parent",
                            "version": "3.2.1",
                        },
                    },
                    {
                        "kind": "plugin_readme",
                        "component": {"kind": "plugin", "slug": "termivar-metadata-lab"},
                        "parent_depth": 0,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0004"],
                        "plugin": {
                            "name": "Termivar Metadata Lab",
                            "stable_tag": "9.9.9",
                        },
                    },
                ],
            },
        }

    def test_comparison_groups_require_the_actual_four_array_schema(self):
        document = {
            "schema": "termivar-report-comparison/v1",
            "only_in_after": [],
            "only_in_before": [],
            "changed": [],
            "unchanged": [{"synthetic": True}],
        }
        groups = runner._comparison_group_arrays(document, "synthetic comparison")
        self.assertEqual(
            {name: len(items) for name, items in groups.items()},
            {
                "only_in_after": 0,
                "only_in_before": 0,
                "changed": 0,
                "unchanged": 1,
            },
        )
        self.assertNotIn("counts", document)

        for invalid in ([], None, "comparison", 1, True):
            with self.subTest(root=invalid):
                with self.assertRaisesRegex(runner.AcceptanceError, "root is not an object"):
                    runner._comparison_group_arrays(invalid, "synthetic comparison")
        wrong_schema = copy.deepcopy(document)
        wrong_schema["schema"] = "termivar-report-comparison/v2"
        with self.assertRaisesRegex(runner.AcceptanceError, "unsupported comparison schema"):
            runner._comparison_group_arrays(wrong_schema, "synthetic comparison")

        for missing in runner.COMPARISON_GROUPS:
            malformed = copy.deepcopy(document)
            del malformed[missing]
            malformed["counts"] = {name: 0 for name in runner.COMPARISON_GROUPS}
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(runner.AcceptanceError, f"omits comparison group {missing}"):
                    runner._comparison_group_arrays(malformed, "synthetic comparison")

        for group in runner.COMPARISON_GROUPS:
            for invalid in (None, "items", {}, 1, True):
                malformed = copy.deepcopy(document)
                malformed[group] = invalid
                malformed["counts"] = {name: 999 for name in runner.COMPARISON_GROUPS}
                with self.subTest(group=group, value=invalid):
                    with self.assertRaisesRegex(runner.AcceptanceError, "is not an array"):
                        runner._comparison_group_arrays(malformed, "synthetic comparison")

        contradictory_counts = copy.deepcopy(document)
        contradictory_counts["counts"] = {
            "only_in_after": 99,
            "only_in_before": 99,
            "changed": 99,
            "unchanged": 0,
        }
        groups = runner._comparison_group_arrays(
            contradictory_counts, "synthetic comparison"
        )
        self.assertEqual([len(groups[name]) for name in runner.COMPARISON_GROUPS], [0, 0, 0, 1])

    def test_offline_acceptance_uses_derived_counts_in_both_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, original_bytes = offline_fixture(Path(temporary))
            fake = OfflineProcessRunner(responses)
            result = runner._run_offline_acceptance(
                fake, Path("synthetic-termivar"), scenarios
            )

            self.assertEqual(result["bundles"]["pretty-review-only"], {
                "verification_status": "integrity_match",
                "self_compare_counts": {
                    "only_in_after": 0,
                    "only_in_before": 0,
                    "changed": 0,
                    "unchanged": 1,
                },
            })
            self.assertEqual(result["bundles"]["pretty-discovery"], {
                "verification_status": "integrity_match",
                "self_compare_counts": {
                    "only_in_after": 0,
                    "only_in_before": 0,
                    "changed": 0,
                    "unchanged": 2,
                },
            })
            self.assertEqual(result["review_only_to_discovery"], {
                "status": "compared",
                "methodology": "changed",
                "coverage": "changed",
                "item_counts": {
                    "only_in_after": 1,
                    "only_in_before": 0,
                    "changed": 1,
                    "unchanged": 0,
                },
            })
            self.assertEqual(
                [label for label, _ in fake.calls],
                [
                    "offline verification pretty-review-only",
                    "offline self comparison pretty-review-only",
                    "offline verification pretty-discovery",
                    "offline self comparison pretty-discovery",
                    "offline collection-policy comparison",
                ],
            )
            self.assertEqual(
                (Path(scenarios["pretty-review-only"]["_bundle"])
                 / "assessment.json").read_bytes(),
                original_bytes[0],
            )
            self.assertEqual(
                (Path(scenarios["pretty-discovery"]["_bundle"])
                 / "assessment.json").read_bytes(),
                original_bytes[1],
            )

    def test_offline_acceptance_rejects_self_partition_mutations(self):
        def empty_self(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"] = []

        def changed_self(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"] = []
            comparison["changed"] = [comparison_item(
                BASE_FINGERPRINT,
                BASE_CAPABILITY,
                before=synthetic_projection("before"),
                after=synthetic_projection("after"),
                changed_fields=["title"],
            )]

        def one_sided_self(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            item = comparison["unchanged"].pop()
            item["before"] = None
            comparison["only_in_after"] = [item]

        def duplicate_identity(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"].append(copy.deepcopy(comparison["unchanged"][0]))

        def substituted_identity(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"][0]["fingerprint"] = "sha256:" + "3" * 64

        mutations = (
            (empty_self, "paired identities"),
            (changed_self, "offline self comparison changed"),
            (one_sided_self, "only_in_after identities"),
            (duplicate_identity, "repeats a fingerprint"),
            (substituted_identity, "paired identities"),
        )
        for mutate, message in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    mutate(responses)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            OfflineProcessRunner(responses),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_offline_acceptance_rejects_invalid_source_inventory_counts(self):
        for invalid_count, message in ((True, "invalid item_count"), (2, "does not match")):
            with self.subTest(item_count=invalid_count):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    bundle = Path(scenarios["pretty-review-only"]["_bundle"])
                    document = json.loads((bundle / "assessment.json").read_bytes())
                    document["item_count"] = invalid_count
                    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
                    (bundle / "assessment.json").write_bytes(raw)
                    comparison = responses["offline self comparison pretty-review-only"]
                    comparison["before"] = source_metadata(raw, invalid_count)
                    comparison["after"] = source_metadata(raw, invalid_count)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            OfflineProcessRunner(responses),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_offline_acceptance_rejects_controlled_partition_and_wordpress_drift(self):
        def missing_wordpress(responses):
            del responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]

        def unchanged_methodology(responses):
            responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]["methodology"]["status"] = "unchanged"

        def unchanged_coverage(responses):
            responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]["coverage"]["status"] = "unchanged"

        def missing_discovery_identity(responses):
            comparison = responses["offline collection-policy comparison"]
            comparison["only_in_after"][0]["capability_id"] = "synthetic.other@1"

        def duplicate_controlled_identity(responses):
            comparison = responses["offline collection-policy comparison"]
            comparison["unchanged"] = [copy.deepcopy(comparison["changed"][0])]
            comparison["unchanged"][0]["changed_fields"] = []
            comparison["unchanged"][0]["after"] = copy.deepcopy(
                comparison["unchanged"][0]["before"]
            )

        mutations = (
            (missing_wordpress, "omitted WordPress"),
            (unchanged_methodology, "methodology and coverage"),
            (unchanged_coverage, "methodology and coverage"),
            (missing_discovery_identity, "only_in_after identities"),
            (duplicate_controlled_identity, "repeats a fingerprint"),
        )
        for mutate, message in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    mutate(responses)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            OfflineProcessRunner(responses),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = offline_fixture(
                Path(temporary), discovery_capability="synthetic.other@1"
            )
            with self.assertRaisesRegex(runner.AcceptanceError, "one-sided discovery"):
                runner._run_offline_acceptance(
                    OfflineProcessRunner(responses),
                    Path("synthetic-termivar"),
                    scenarios,
                )

    def test_offline_acceptance_rejects_failed_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = offline_fixture(Path(temporary))
            responses["offline verification pretty-review-only"]["status"] = "not_verified"
            with self.assertRaisesRegex(runner.AcceptanceError, "verification rejected"):
                runner._run_offline_acceptance(
                    OfflineProcessRunner(responses),
                    Path("synthetic-termivar"),
                    scenarios,
                )

    def test_audit_oracle_keeps_stable_tag_out_of_installed_versions(self):
        document = self.discovery_document()
        self.assertEqual(
            runner._validate_discovery_document(document, generator_visible=True),
            "security.wordpress-discovery-audit/v1",
        )
        promoted = copy.deepcopy(document)
        promoted["wordpress_review"]["components"][3]["versions"] = [{"value": "9.9.9"}]
        with self.assertRaisesRegex(runner.AcceptanceError, "promoted"):
            runner._validate_discovery_document(promoted, generator_visible=True)

        missing_theme_version = copy.deepcopy(document)
        missing_theme_version["wordpress_review"]["components"][1]["versions"] = []
        with self.assertRaisesRegex(runner.AcceptanceError, "source-qualified"):
            runner._validate_discovery_document(missing_theme_version, generator_visible=True)

        mismatched = copy.deepcopy(document)
        mismatched["wordpress_review"]["additional_request_count"] = 3
        with self.assertRaisesRegex(runner.AcceptanceError, "request accounting"):
            runner._validate_discovery_document(mismatched, generator_visible=True)

    def test_suppressed_generator_must_not_supply_core_version(self):
        document = self.discovery_document()
        document["wordpress_review"]["components"][0]["versions"] = []
        document["wordpress_review"]["components"][0]["identity_sources"] = [
            "same_origin_asset_path"
        ]
        runner._validate_discovery_document(document, generator_visible=False)
        quality = runner._discovery_quality_metrics(document, generator_visible=False)
        self.assertEqual(quality["observable_identity_recall"], {
            "matched": 4,
            "denominator": 4,
            "missed": 0,
        })
        self.assertEqual(quality["expected_abstentions"]["correct"], 3)
        self.assertEqual(quality["expected_abstentions"]["denominator"], 3)
        with self.assertRaisesRegex(runner.AcceptanceError, "suppressed generator"):
            runner._validate_discovery_document(self.discovery_document(), generator_visible=False)

    def test_quality_oracle_has_independent_denominators_and_rejects_false_matches(self):
        document = self.discovery_document()
        quality = runner._discovery_quality_metrics(document, generator_visible=True)
        self.assertEqual(quality["observable_identity_recall"], {
            "matched": 4,
            "denominator": 4,
            "missed": 0,
        })
        self.assertEqual(quality["false_identity_matches"], {
            "count": 0,
            "observed_denominator": 4,
        })
        self.assertEqual(
            quality["version_accuracy_by_source_class"]["generator_metadata"],
            {"correct": 1, "denominator": 1, "not_observable": 0},
        )
        self.assertEqual(
            quality["version_accuracy_by_source_class"]["theme_stylesheet_declaration"],
            {"correct": 2, "denominator": 2},
        )
        self.assertEqual(quality["expected_abstentions"]["correct"], 2)
        self.assertEqual(quality["expected_abstentions"]["denominator"], 2)

        extra = copy.deepcopy(document)
        extra["wordpress_review"]["components"].append({
            "identity": {"kind": "plugin", "slug": "unexpected-plugin"},
            "identity_sources": ["same_origin_asset_path"],
            "versions": [],
        })
        with self.assertRaisesRegex(runner.AcceptanceError, "identity oracle"):
            runner._discovery_quality_metrics(extra, generator_visible=True)

        wrong_source = copy.deepcopy(document)
        wrong_source["wordpress_review"]["components"][0]["versions"][0]["source"] = (
            "same_origin_asset_path"
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "version/source oracle"):
            runner._discovery_quality_metrics(wrong_source, generator_visible=True)

    def test_duplicate_ground_truth_key_is_rejected(self):
        with self.assertRaisesRegex(runner.AcceptanceError, "duplicate object key"):
            runner.parse_json(b'{"schema":"one","schema":"two"}', "fixture")

    def test_evidence_output_is_bounded_and_no_overwrite(self):
        evidence = {
            "schema": runner.TASK_SCHEMA,
            "status": "failed",
            "source_ref": "0" * 40,
            "failure": "synthetic test failure",
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            runner.write_evidence(destination, evidence)
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    "wordpress-discovery-lab-acceptance.json",
                    "wordpress-discovery-lab-acceptance.md",
                },
            )
            with self.assertRaises(FileExistsError):
                runner.write_evidence(destination, evidence)

    def test_cleanup_failure_retains_exact_task_owned_resume_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(runner.ProcessRunner(), Path(temporary))
            abandoned = runner._safe_name("wp-cli", "a" * 12)
            lab._wp_cli_containers.add(abandoned)
            lab._created.add("network")

            def failed_cleanup(*_args, **_kwargs):
                return runner.CommandResult(b"", b"bounded failure", 1)

            lab.docker = failed_cleanup
            with self.assertRaisesRegex(
                runner.AcceptanceError,
                f"{abandoned}.*{lab.network}",
            ):
                lab.shutdown()
            self.assertEqual(lab._wp_cli_containers, {abandoned})
            self.assertEqual(lab._created, {"network"})

    def test_wp_cleanup_does_not_forget_a_container_that_still_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(runner.ProcessRunner(), Path(temporary))
            observed_name = None

            def persistent_container(*arguments, **_kwargs):
                nonlocal observed_name
                if arguments[0] == "run":
                    observed_name = arguments[arguments.index("--name") + 1]
                    return runner.CommandResult(b"ok", b"", 0)
                if arguments[:2] == ("rm", "--force"):
                    return runner.CommandResult(b"", b"bounded failure", 1)
                if arguments[:3] == ("container", "ls", "--all"):
                    return runner.CommandResult(f"{observed_name}\n".encode(), b"", 0)
                self.fail(f"unexpected Docker command: {arguments!r}")

            lab.docker = persistent_container
            with self.assertRaisesRegex(
                runner.AcceptanceError,
                "WP-CLI cleanup remains unconfirmed",
            ):
                lab.wp("core", "version", label="synthetic WP-CLI command")
            self.assertEqual(lab._wp_cli_containers, {observed_name})


if __name__ == "__main__":
    unittest.main()
