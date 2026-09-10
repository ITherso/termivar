import copy
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
                "execution": {
                    "exploit_execution": "not_performed",
                    "impact_validation": "not_performed",
                },
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
