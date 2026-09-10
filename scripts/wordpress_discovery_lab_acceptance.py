#!/usr/bin/env python3
"""Run Termivar WordPress discovery against a disposable real WordPress lab.

The controller pulls three digest-pinned upstream images, then performs all
lab traffic on a Docker internal bridge. WordPress is exposed only on a random
127.0.0.1 port. Termivar receives no lab credentials or inventory. Full report
documents stay in a private temporary directory; the output is bounded summary
evidence without local paths, credentials, or report text.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import shutil
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from typing import Any, Iterable, Sequence


TASK_SCHEMA = "termivar-test.wordpress-discovery-lab-acceptance/v1"
WORDPRESS_IMAGE = (
    "wordpress@sha256:49801e46d08eb27ea68ed62e205bb35b1bb2dc962251bf2292a7d374f9637cee"
)
WORDPRESS_CLI_IMAGE = (
    "wordpress@sha256:51ff6b7643d9b4c29d74d83b2c3fe12e706812e7add075f189535f498dd5201d"
)
MARIADB_IMAGE = (
    "mariadb@sha256:a75328dabed542a3b704efe54086071cb3f99e6a640cc8a18d7273bc4de2e5e7"
)
IMAGE_PIN_RECORDS = {
    "wordpress": {
        "tag": "wordpress:7.1-php8.3-apache",
        "index_digest": "sha256:5a93c470ae8220fddf71f6ebe3bc94e615ddc2ae4d9810f795b830fb11c41a17",
        "reference": WORDPRESS_IMAGE,
    },
    "wordpress_cli": {
        "tag": "wordpress:cli-2.12.0-php8.3",
        "index_digest": "sha256:2b5e9d4d3e51909dca1aaa4732e9f5e5bf0377c2114dbd8ff39f060bff202586",
        "reference": WORDPRESS_CLI_IMAGE,
    },
    "mariadb": {
        "tag": "mariadb:11.8.9",
        "index_digest": "sha256:2d2f4095530294735a857cfe22bb101e19b0849b416911c796ec4aa81b164a62",
        "reference": MARIADB_IMAGE,
    },
}
IMAGE_REFERENCES = tuple(record["reference"] for record in IMAGE_PIN_RECORDS.values())
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "wordpress-discovery-lab"
GROUND_TRUTH_PATH = (
    Path(__file__).resolve().parents[1]
    / "docs" / "examples" / "wordpress-review" / "discovery-lab" / "ground-truth.json"
)
MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
MAX_EVIDENCE_OUTPUT = 256 * 1024
MAX_REPORT_PAYLOAD_BYTES = 16 * 1024 * 1024
PRIVATE_DIRECTORY_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
WORDPRESS_CONTAINER_PORT = 8080
MAX_RELAY_CONNECTION_BYTES = 64 * 1024 * 1024
MAX_RELAY_CONCURRENT_CONNECTIONS = 16
MAX_RELAY_TOTAL_CONNECTIONS = 256
MAX_RELAY_TOTAL_BYTES = 256 * 1024 * 1024
RELAY_IDLE_TIMEOUT_SECONDS = 30
RELAY_STOP_POLL_SECONDS = 0.25
COMMAND_TIMEOUT_SECONDS = 180
STARTUP_TIMEOUT_SECONDS = 120
REQUEST_RE = re.compile(
    r'"(?P<method>[A-Z]+) (?P<target>\S+) HTTP/[0-9.]+" '
    r'(?P<status>[0-9]{3}) \S+ '
    r'tmv_auth=(?P<authorization>[-1]) '
    r'tmv_cookie=(?P<cookie>[-1]) '
    r'tmv_proxy_auth=(?P<proxy_authorization>[-1])(?:\s|$)'
)
SOURCE_REF_RE = re.compile(r"[0-9a-f]{40}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?\Z")

EXPECTED_COMPONENTS = {
    ("core", "wordpress"): ("7.1", "installed"),
    ("theme", "termivar-child"): ("1.4.0", "active"),
    ("theme", "termivar-parent"): ("3.2.1", "parent"),
    ("plugin", "termivar-metadata-lab"): ("2.3.4", "active"),
    ("plugin", "termivar-hidden-lab"): ("4.5.6", "inactive"),
}
EXPECTED_DISCOVERY_PATHS = {
    "pretty": (
        "/wp-json/",
        "/wp-content/themes/termivar-child/style.css",
        "/wp-content/themes/termivar-parent/style.css",
        "/wp-content/plugins/termivar-metadata-lab/readme.txt",
    ),
    "plain": (
        "/index.php?rest_route=/",
        "/wp-content/themes/termivar-child/style.css",
        "/wp-content/themes/termivar-parent/style.css",
        "/wp-content/plugins/termivar-metadata-lab/readme.txt",
    ),
}


class AcceptanceError(RuntimeError):
    """A bounded acceptance assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceError("JSON contains a duplicate object key")
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> Any:
    require(len(raw) <= 16 * 1024 * 1024, f"{label} exceeds the acceptance bound")
    try:
        text = raw.decode("utf-8", "strict")
        return json.loads(text, object_pairs_hook=_json_object_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError(f"{label} is not strict UTF-8 JSON") from error


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file())
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def validate_fixture(root: Path = FIXTURE_ROOT) -> dict[str, Any]:
    require(root.is_dir() and not root.is_symlink(), "lab fixture directory is unavailable")
    expected = {
        "Dockerfile",
        "themes/termivar-parent/style.css",
        "themes/termivar-parent/index.php",
        "themes/termivar-child/style.css",
        "themes/termivar-child/functions.php",
        "themes/termivar-child/index.php",
        "plugins/termivar-metadata-lab/termivar-metadata-lab.php",
        "plugins/termivar-metadata-lab/readme.txt",
        "plugins/termivar-metadata-lab/assets/lab.css",
        "plugins/termivar-hidden-lab/termivar-hidden-lab.php",
        "plugins/termivar-hidden-lab/readme.txt",
        "plugins/termivar-generator-control/termivar-generator-control.php",
    }
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    }
    require(actual == expected, "lab fixture file inventory differs from its closed contract")
    for path in root.rglob("*"):
        require(not path.is_symlink(), "lab fixture must not contain links")
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    require(f"FROM {WORDPRESS_IMAGE}" in dockerfile, "WordPress base image is not pinned")
    require(dockerfile.rstrip().endswith("USER www-data"),
            "lab runtime must select the non-root www-data identity")
    require("Listen 8080" in dockerfile and "<VirtualHost *:8080>" in dockerfile,
            "lab runtime must use its unprivileged container port")
    require("http://" not in dockerfile and "https://" not in dockerfile,
            "lab build must not fetch network content")
    require("ADD " not in dockerfile, "lab build must use only checked-in COPY sources")
    child_template = (root / "themes/termivar-child/index.php").read_text(encoding="utf-8")
    require(
        '<img src="/wp-includes/images/blank.gif"' in child_template,
        "lab root must retain its deterministic identity-only core asset reference",
    )
    require(GROUND_TRUTH_PATH.is_file() and not GROUND_TRUTH_PATH.is_symlink(),
            "lab ground-truth declaration is unavailable")
    truth = parse_json(GROUND_TRUTH_PATH.read_bytes(), "lab ground truth")
    require(truth.get("schema") == "termivar-test.wordpress-discovery-ground-truth/v1",
            "lab ground-truth schema changed")
    pin_records = {
        name: {
            "tag": item["tag"],
            "index_digest": item["index_digest"],
            "reference": item["reference"],
        }
        for name, item in truth["images"].items()
    }
    require(pin_records == IMAGE_PIN_RECORDS, "lab image tag/index/platform pins disagree")
    components = {
        (item["kind"], item["slug"]): (item["version"], item["state"])
        for item in truth["components"]
    }
    require(components == EXPECTED_COMPONENTS, "lab component oracle changed")
    require(truth["rest"]["pretty_root_path"] == EXPECTED_DISCOVERY_PATHS["pretty"][0],
            "pretty REST path oracle changed")
    require(truth["rest"]["plain_root_path"] == EXPECTED_DISCOVERY_PATHS["plain"][0],
            "plain REST path oracle changed")
    return {
        "fixture_sha256": tree_sha256(root),
        "ground_truth_sha256": sha256_file(GROUND_TRUTH_PATH),
        "file_count": len(actual),
        "image_references": list(IMAGE_REFERENCES),
    }


@dataclasses.dataclass(frozen=True)
class CommandResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    elapsed_seconds: float = 0.0
    peak_memory: dict[str, Any] | None = None


class ProcessRunner:
    def run(
        self,
        arguments: Sequence[str | os.PathLike[str]],
        *,
        input_bytes: bytes | None = None,
        expected: int | Iterable[int] = 0,
        timeout: int = COMMAND_TIMEOUT_SECONDS,
        label: str,
        measure_peak_memory: bool = False,
    ) -> CommandResult:
        argv = [os.fspath(argument) for argument in arguments]
        peak_memory: dict[str, Any] = {
            "status": "not_measured",
            "reason": "measurement_not_requested",
        }
        started = time.monotonic()
        if measure_peak_memory and platform.system() == "Linux" and Path("/usr/bin/time").is_file():
            with tempfile.TemporaryDirectory(prefix="termivar-process-metric-") as metric_dir:
                metric_path = Path(metric_dir) / "gnu-time.txt"
                completed = subprocess.run(
                    [
                        "/usr/bin/time",
                        "-f",
                        "maximum_resident_set_kib=%M",
                        "-o",
                        str(metric_path),
                        "--",
                        *argv,
                    ],
                    input=input_bytes,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )
                raw_metric = metric_path.read_bytes() if metric_path.is_file() else b""
                require(len(raw_metric) <= 4096, f"{label} memory metric is oversized")
                match = re.fullmatch(
                    rb"maximum_resident_set_kib=([1-9][0-9]*)\s*", raw_metric
                )
                require(match is not None, f"{label} GNU time memory metric is malformed")
                peak_memory = {
                    "status": "measured",
                    "metric": "maximum_resident_set_size",
                    "value": int(match.group(1)),
                    "unit": "KiB",
                    "scope": "command_process_high_water_mark_reported_by_gnu_time",
                    "mechanism": "GNU time %M",
                }
        else:
            completed = subprocess.run(
                argv,
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if measure_peak_memory:
                peak_memory = {
                    "status": "not_measured",
                    "reason": "gnu_time_unavailable_on_this_platform",
                }
        elapsed_seconds = time.monotonic() - started
        require(len(completed.stdout) <= MAX_COMMAND_OUTPUT, f"{label} stdout is oversized")
        require(len(completed.stderr) <= MAX_COMMAND_OUTPUT, f"{label} stderr is oversized")
        statuses = {expected} if isinstance(expected, int) else set(expected)
        if completed.returncode not in statuses:
            stderr = completed.stderr.decode("utf-8", "replace")[-4000:]
            raise AcceptanceError(
                f"{label} exited {completed.returncode}; bounded diagnostic: {stderr}"
            )
        return CommandResult(
            completed.stdout,
            completed.stderr,
            completed.returncode,
            elapsed_seconds,
            peak_memory,
        )


def _safe_name(prefix: str, run_id: str) -> str:
    value = f"termivar-{prefix}-{run_id}"
    require(re.fullmatch(r"[a-z0-9-]{1,63}", value) is not None, "unsafe Docker name")
    return value


def _internal_container_address(
    network_name: str,
    network_document: Any,
    container_networks: Any,
) -> str:
    require(isinstance(network_document, dict), "internal network identity is malformed")
    network_id = network_document.get("Id")
    require(network_document.get("Name") == network_name
            and network_document.get("Internal") is True
            and isinstance(network_id, str)
            and re.fullmatch(r"[0-9a-f]{64}", network_id) is not None,
            "lab network is not the exact internal network")
    ipam = network_document.get("IPAM")
    require(isinstance(ipam, dict), "internal network address plan is malformed")
    configurations = ipam.get("Config")
    require(isinstance(configurations, list) and 1 <= len(configurations) <= 4,
            "internal network address plan is unavailable")
    subnets: list[ipaddress.IPv4Network] = []
    for configuration in configurations:
        require(isinstance(configuration, dict), "internal network subnet is malformed")
        raw_subnet = configuration.get("Subnet")
        if not isinstance(raw_subnet, str):
            continue
        try:
            subnet = ipaddress.ip_network(raw_subnet, strict=True)
        except ValueError as error:
            raise AcceptanceError("internal network subnet is malformed") from error
        if isinstance(subnet, ipaddress.IPv4Network):
            require(subnet.is_private and not subnet.is_loopback and not subnet.is_link_local,
                    "internal network subnet is outside the private lab boundary")
            subnets.append(subnet)
    require(subnets, "internal network has no supported private IPv4 subnet")

    require(isinstance(container_networks, dict)
            and set(container_networks) == {network_name},
            "WordPress fixture must remain attached only to its internal network")
    attachment = container_networks[network_name]
    require(isinstance(attachment, dict)
            and attachment.get("NetworkID") == network_id,
            "WordPress internal network attachment is malformed")
    raw_address = attachment.get("IPAddress")
    require(isinstance(raw_address, str), "WordPress internal address is unavailable")
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError as error:
        raise AcceptanceError("WordPress internal address is malformed") from error
    require(isinstance(address, ipaddress.IPv4Address)
            and address.is_private and not address.is_reserved
            and not address.is_unspecified and not address.is_multicast
            and not address.is_loopback and not address.is_link_local
            and any(address in subnet for subnet in subnets),
            "WordPress internal address is outside the private lab boundary")
    return str(address)


class _LoopbackRelayHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        relay = self.server
        transferred = 0
        self.request.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
        try:
            upstream = socket.create_connection(
                relay.upstream_address, timeout=RELAY_IDLE_TIMEOUT_SECONDS
            )
        except OSError:
            relay.record_transport_failure()
            return
        with upstream:
            upstream.settimeout(RELAY_IDLE_TIMEOUT_SECONDS)
            destinations = {self.request: upstream, upstream: self.request}
            last_activity = time.monotonic()
            while destinations:
                if relay.stop_event.is_set():
                    return
                try:
                    readable, _, _ = select.select(
                        tuple(destinations), (), (), RELAY_STOP_POLL_SECONDS
                    )
                except (OSError, ValueError):
                    return
                if not readable:
                    if time.monotonic() - last_activity >= RELAY_IDLE_TIMEOUT_SECONDS:
                        return
                    continue
                for source in readable:
                    destination = destinations[source]
                    try:
                        payload = source.recv(64 * 1024)
                    except OSError:
                        return
                    if not payload:
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        del destinations[source]
                        continue
                    last_activity = time.monotonic()
                    transferred += len(payload)
                    if (transferred > MAX_RELAY_CONNECTION_BYTES
                            or not relay.record_transfer(len(payload))):
                        relay.record_limit_failure()
                        return
                    try:
                        destination.sendall(payload)
                    except OSError:
                        return


class _LoopbackRelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True
    request_queue_size = MAX_RELAY_CONCURRENT_CONNECTIONS

    def __init__(self, upstream_address: tuple[str, int]):
        self.upstream_address = upstream_address
        self._limit_failures = 0
        self._transport_failures = 0
        self._total_connections = 0
        self._total_bytes = 0
        self._failure_lock = threading.Lock()
        self._connection_slots = threading.BoundedSemaphore(MAX_RELAY_CONCURRENT_CONNECTIONS)
        self.stop_event = threading.Event()
        super().__init__(("127.0.0.1", 0), _LoopbackRelayHandler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self.record_limit_failure()
            request.close()
            return
        with self._failure_lock:
            if self._total_connections >= MAX_RELAY_TOTAL_CONNECTIONS:
                self._limit_failures += 1
                self._connection_slots.release()
                request.close()
                return
            self._total_connections += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()

    def record_limit_failure(self) -> None:
        with self._failure_lock:
            self._limit_failures += 1

    def record_transport_failure(self) -> None:
        with self._failure_lock:
            self._transport_failures += 1

    def record_transfer(self, byte_length: int) -> bool:
        with self._failure_lock:
            if self._total_bytes + byte_length > MAX_RELAY_TOTAL_BYTES:
                return False
            self._total_bytes += byte_length
            return True

    def limit_failures(self) -> int:
        with self._failure_lock:
            return self._limit_failures

    def transport_failures(self) -> int:
        with self._failure_lock:
            return self._transport_failures

    def acknowledge_startup(self) -> None:
        with self._failure_lock:
            self._transport_failures = 0

    def handle_error(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        self.record_transport_failure()
        request.close()


class LoopbackTcpRelay:
    def __init__(self, upstream_host: str, upstream_port: int):
        self._server = _LoopbackRelayServer((upstream_host, upstream_port))
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="termivar-wordpress-loopback-relay",
            daemon=True,
        )
        self._started = False
        self._stopped = False

    def start(self) -> int:
        require(not self._started and not self._stopped, "loopback relay cannot be restarted")
        self._thread.start()
        self._started = True
        return int(self._server.server_address[1])

    def acknowledge_startup(self) -> None:
        require(self._started and not self._stopped,
                "loopback relay startup cannot be acknowledged in this state")
        self._server.acknowledge_startup()

    def assert_healthy(self) -> None:
        require(self._server.limit_failures() == 0,
                "loopback relay exceeded a connection or byte bound")
        require(self._server.transport_failures() == 0,
                "loopback relay encountered an upstream transport failure")

    def stop(self) -> None:
        if not self._stopped:
            self._server.stop_event.set()
            if self._started:
                self._server.shutdown()
            self._server.server_close()
            if self._started:
                self._thread.join(timeout=RELAY_IDLE_TIMEOUT_SECONDS)
            self._stopped = True
        require(not self._thread.is_alive(), "loopback relay did not stop within its bound")


class DockerWordPressLab:
    def __init__(self, runner: ProcessRunner, work: Path):
        self.runner = runner
        self.work = work
        self.run_id = uuid.uuid4().hex[:12]
        self.label = f"termivar-wordpress-discovery-{self.run_id}"
        self.network = _safe_name("wp-net", self.run_id)
        self.database_volume = _safe_name("wp-db", self.run_id)
        self.wordpress_volume = _safe_name("wp-data", self.run_id)
        self.database = _safe_name("wp-db", self.run_id)
        self.wordpress = _safe_name("wp-web", self.run_id)
        self.derived_image = _safe_name("wp-fixture", self.run_id)
        self.database_password = secrets.token_urlsafe(32)
        self.admin_password = secrets.token_urlsafe(32)
        self.wordpress_env = self.work / "wordpress.env"
        self.origin: str | None = None
        self.loopback_relay: LoopbackTcpRelay | None = None
        self._created: set[str] = set()
        self._wp_cli_containers: set[str] = set()
        self.image_ids: dict[str, str] = {}

    def docker(self, *arguments: str, label: str, **kwargs: Any) -> CommandResult:
        return self.runner.run(["docker", *arguments], label=label, **kwargs)

    def start(self) -> None:
        require(
            platform.system() == "Linux",
            "the internal-bridge WordPress lab requires a native Linux Docker engine",
        )
        require(shutil.which("docker") is not None, "Docker CLI is unavailable")
        info = self.docker("info", "--format", "{{.Architecture}}", label="Docker readiness")
        require(info.stdout.decode("utf-8", "strict").strip() == "x86_64",
                "the pinned lab manifests require an x86_64 Docker engine")

        # This is the only public-network-dependent phase of the lab itself.
        for index, reference in enumerate(IMAGE_REFERENCES):
            self.docker("pull", reference, label=f"pinned image pull {index + 1}", timeout=300)
            inspected = self.docker(
                "image", "inspect", "--format", "{{.Id}}", reference,
                label=f"pinned image inspection {index + 1}",
            )
            image_id = inspected.stdout.decode("utf-8", "strict").strip()
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is not None,
                    "Docker returned an invalid image identity")
            self.image_ids[reference] = image_id

        self.docker(
            "build", "--network=none", "--pull=false", "--tag", self.derived_image,
            str(FIXTURE_ROOT), label="offline lab image build", timeout=300,
        )
        self._created.add("image")
        common_label = f"org.termivar.acceptance={self.label}"
        self.docker(
            "network", "create", "--driver", "bridge", "--internal",
            "--label", common_label, self.network, label="internal lab network creation",
        )
        self._created.add("network")
        for marker, volume in (("database_volume", self.database_volume),
                               ("wordpress_volume", self.wordpress_volume)):
            self.docker("volume", "create", "--label", common_label, volume,
                        label=f"{marker} creation")
            self._created.add(marker)

        database_env = self.work / "database.env"
        wordpress_env = self.wordpress_env
        database_env.write_text(
            "MARIADB_DATABASE=wordpress\n"
            "MARIADB_USER=termivar\n"
            f"MARIADB_PASSWORD={self.database_password}\n"
            "MARIADB_RANDOM_ROOT_PASSWORD=1\n",
            encoding="utf-8",
        )
        wordpress_env.write_text(
            "WORDPRESS_DB_HOST=database:3306\n"
            "WORDPRESS_DB_USER=termivar\n"
            f"WORDPRESS_DB_PASSWORD={self.database_password}\n"
            "WORDPRESS_DB_NAME=wordpress\n"
            "WORDPRESS_CONFIG_EXTRA=define( 'DISABLE_WP_CRON', true ); define( 'AUTOMATIC_UPDATER_DISABLED', true ); define( 'WP_AUTO_UPDATE_CORE', false ); define( 'WP_HTTP_BLOCK_EXTERNAL', true );\n",
            encoding="utf-8",
        )
        os.chmod(database_env, 0o600)
        os.chmod(wordpress_env, 0o600)

        self.docker(
            "run", "--pull=never", "--detach", "--name", self.database,
            "--label", common_label, "--network", self.network,
            "--network-alias", "database", "--env-file", str(database_env),
            "--mount", f"type=volume,source={self.database_volume},target=/var/lib/mysql",
            "--health-cmd", "healthcheck.sh --connect --innodb_initialized",
            "--health-interval", "2s", "--health-timeout", "2s", "--health-retries", "60",
            MARIADB_IMAGE, label="database container start",
        )
        self._created.add("database")
        self._wait_for_database()

        self.docker(
            "run", "--pull=never", "--detach", "--name", self.wordpress,
            "--label", common_label, "--network", self.network,
            "--env-file", str(wordpress_env),
            "--mount", f"type=volume,source={self.wordpress_volume},target=/var/www/html",
            self.derived_image, label="WordPress container start",
        )
        self._created.add("wordpress")
        runtime_uid = self.docker(
            "exec", self.wordpress, "id", "-u", label="WordPress runtime user inspection"
        ).stdout.decode("utf-8", "strict").strip()
        runtime_gid = self.docker(
            "exec", self.wordpress, "id", "-g", label="WordPress runtime group inspection"
        ).stdout.decode("utf-8", "strict").strip()
        require((runtime_uid, runtime_gid) == ("33", "33"),
                "WordPress fixture did not run as the bounded www-data identity")
        self._wait_for_wordpress_process()
        network_document = parse_json(
            self.docker(
                "network", "inspect", "--format", "{{json .}}", self.network,
                label="internal lab network inspection",
            ).stdout,
            "internal lab network identity",
        )
        container_networks = parse_json(
            self.docker(
                "inspect", "--format", "{{json .NetworkSettings.Networks}}",
                self.wordpress, label="WordPress internal address inspection",
            ).stdout,
            "WordPress internal network identity",
        )
        address = _internal_container_address(
            self.network, network_document, container_networks
        )
        self.loopback_relay = LoopbackTcpRelay(address, WORDPRESS_CONTAINER_PORT)
        port = self.loopback_relay.start()
        require(1 <= port <= 65535, "loopback relay supplied an invalid port")
        self.origin = f"http://127.0.0.1:{port}/"
        self._wait_for_loopback_relay(port)
        self.loopback_relay.acknowledge_startup()
        self._install_wordpress()
        database_env.unlink()

    def _wait_for_database(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            result = self.docker(
                "inspect", "--format", "{{.State.Health.Status}}", self.database,
                label="database health inspection", expected=(0, 1),
            )
            if result.returncode == 0 and result.stdout.strip() == b"healthy":
                return
            time.sleep(1)
        raise AcceptanceError("database did not become healthy within the bounded startup time")

    def _wait_for_wordpress_process(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            files = self.docker(
                "exec", self.wordpress, "sh", "-c",
                "test -f /var/www/html/wp-config.php && test -f /var/www/html/wp-load.php",
                label="WordPress file readiness", expected=(0, 1),
            )
            if files.returncode == 0:
                response = self.docker(
                    "exec", self.wordpress, "php", "-r",
                    f"$s=@fsockopen('127.0.0.1',{WORDPRESS_CONTAINER_PORT},$e,$m,1);"
                    "if(!$s){exit(1);}fwrite($s,\"GET / HTTP/1.0\\r\\n"
                    "Host: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n\");"
                    "$line=fgets($s);fclose($s);"
                    "exit(is_string($line)&&strncmp($line,'HTTP/',5)===0?0:1);",
                    label="WordPress internal HTTP readiness", expected=(0, 1),
                )
                if response.returncode == 0:
                    return
            time.sleep(1)
        raise AcceptanceError("WordPress did not become ready within the bounded startup time")

    @staticmethod
    def _wait_for_loopback_relay(port: int) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1) as probe:
                    probe.sendall(
                        b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                    )
                    response = probe.recv(16)
                    if response.startswith(b"HTTP/"):
                        return
            except OSError:
                pass
            time.sleep(0.1)
        raise AcceptanceError("loopback relay did not become ready within its bound")

    def assert_relay_healthy(self) -> None:
        require(self.loopback_relay is not None, "loopback relay is unavailable")
        self.loopback_relay.assert_healthy()

    def wp(self, *arguments: str, label: str, input_bytes: bytes | None = None) -> CommandResult:
        name = _safe_name("wp-cli", uuid.uuid4().hex[:12])
        self._wp_cli_containers.add(name)
        command_failed = False
        try:
            return self.docker(
                "run", "--pull=never", "--rm", "--name", name,
                "--label", f"org.termivar.acceptance={self.label}",
                "--network", self.network, "--volumes-from", self.wordpress,
                "--env-file", str(self.wordpress_env),
                "--user", "33:33", "--env", "HOME=/tmp",
                "--env", "WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1",
                "--workdir", "/var/www/html", WORDPRESS_CLI_IMAGE, "wp", *arguments,
                label=label, input_bytes=input_bytes,
            )
        except BaseException:
            command_failed = True
            raise
        finally:
            # --rm handles the normal case. The explicit exact-name cleanup also
            # covers a timeout that outlives the local Docker CLI subprocess.
            cleanup = self.docker(
                "rm", "--force", name, label="WP-CLI container cleanup", expected=(0, 1)
            )
            absent = cleanup.returncode == 0
            if not absent:
                # `docker run --rm` normally removes the container first and a
                # subsequent exact-name `rm` returns 1. Confirm absence through
                # a successful bounded listing; a generic return code 1 alone
                # must not erase the ownership marker for a surviving container.
                remaining = self.docker(
                    "container", "ls", "--all", "--filter", f"name=^/{name}$",
                    "--format", "{{.Names}}", label="WP-CLI cleanup confirmation",
                )
                names = {
                    line.strip()
                    for line in remaining.stdout.decode("utf-8", "strict").splitlines()
                    if line.strip()
                }
                absent = name not in names
            if absent:
                self._wp_cli_containers.discard(name)
            elif not command_failed:
                raise AcceptanceError(
                    f"task-owned WP-CLI cleanup remains unconfirmed for {name}"
                )

    def _install_wordpress(self) -> None:
        require(self.origin is not None, "WordPress origin is unavailable")
        self.wp(
            "core", "install", f"--url={self.origin}",
            "--title=Termivar metadata discovery lab",
            "--admin_user=termivar-lab-admin", "--admin_email=lab@example.invalid",
            "--skip-email", "--prompt=admin_password", label="WordPress installation",
            input_bytes=(self.admin_password + "\n").encode("utf-8"),
        )
        self.wp("theme", "activate", "termivar-child", label="child theme activation")
        self.wp("plugin", "activate", "termivar-metadata-lab",
                label="metadata plugin activation")
        self.wp("option", "update", "permalink_structure", "/%postname%/",
                label="pretty permalink selection")
        self.wp("rewrite", "flush", "--hard", label="pretty permalink flush")

    def configure(self, *, permalink: str, generator_visible: bool) -> None:
        require(permalink in {"pretty", "plain"}, "unknown permalink scenario")
        plugin_command = "deactivate" if generator_visible else "activate"
        self.wp("plugin", plugin_command, "termivar-generator-control",
                label="generator visibility configuration")
        structure = "/%postname%/" if permalink == "pretty" else ""
        self.wp("option", "update", "permalink_structure", structure,
                label=f"{permalink} permalink selection")
        self.wp("rewrite", "flush", "--hard", label=f"{permalink} permalink flush")

    def ground_truth(self) -> dict[str, Any]:
        core = self.wp("core", "version", label="core ground truth").stdout.decode().strip()
        stylesheet = self.wp("option", "get", "stylesheet",
                             label="stylesheet ground truth").stdout.decode().strip()
        template = self.wp("option", "get", "template",
                           label="template ground truth").stdout.decode().strip()
        themes = parse_json(
            self.wp("theme", "list", "--format=json", "--fields=name,status,version",
                    label="theme ground truth").stdout,
            "WP-CLI theme ground truth",
        )
        plugins = parse_json(
            self.wp("plugin", "list", "--format=json", "--fields=name,status,version",
                    label="plugin ground truth").stdout,
            "WP-CLI plugin ground truth",
        )
        require(core == "7.1", "WP-CLI core ground truth differs from the pinned release")
        require(stylesheet == "termivar-child" and template == "termivar-parent",
                "active child/parent ground truth differs")
        theme_map = {row["name"]: (row["version"], row["status"]) for row in themes}
        plugin_map = {row["name"]: (row["version"], row["status"]) for row in plugins}
        require(theme_map.get("termivar-child") == ("1.4.0", "active"),
                "child theme WP-CLI ground truth differs")
        require(theme_map.get("termivar-parent") == ("3.2.1", "parent"),
                "parent theme WP-CLI ground truth differs")
        require(plugin_map.get("termivar-metadata-lab") == ("2.3.4", "active"),
                "metadata plugin WP-CLI ground truth differs")
        require(plugin_map.get("termivar-hidden-lab") == ("4.5.6", "inactive"),
                "hidden plugin WP-CLI ground truth differs")
        return {
            "core_version": core,
            "active_stylesheet": stylesheet,
            "parent_template": template,
            "task_themes": {
                name: {"version": theme_map[name][0], "status": theme_map[name][1]}
                for name in ("termivar-child", "termivar-parent")
            },
            "task_plugins": {
                name: {"version": plugin_map[name][0], "status": plugin_map[name][1]}
                for name in ("termivar-metadata-lab", "termivar-hidden-lab")
            },
            "plugin_readme_stable_tag": "9.9.9",
        }

    def request_log(self) -> list[tuple[str, str, int, tuple[str, ...]]]:
        result = self.docker("logs", self.wordpress, label="WordPress request log")
        requests: list[tuple[str, str, int, tuple[str, ...]]] = []
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            match = REQUEST_RE.search(line)
            if match:
                forbidden_headers = tuple(
                    name
                    for name, group in (
                        ("authorization", "authorization"),
                        ("cookie", "cookie"),
                        ("proxy-authorization", "proxy_authorization"),
                    )
                    if match.group(group) == "1"
                )
                requests.append(
                    (
                        match.group("method"),
                        match.group("target"),
                        int(match.group("status")),
                        forbidden_headers,
                    )
                )
        return requests

    def trace(
        self,
        before: list[tuple[str, str, int, tuple[str, ...]]],
    ) -> list[tuple[str, str, int, tuple[str, ...]]]:
        after = self.request_log()
        require(after[: len(before)] == before, "Apache request log changed non-append-only")
        return after[len(before):]

    def shutdown(self) -> None:
        failures: list[str] = []
        if self.loopback_relay is not None:
            try:
                self.loopback_relay.stop()
            except (AcceptanceError, OSError):
                failures.append("loopback_relay")
            else:
                self.loopback_relay = None
        for name in sorted(self._wp_cli_containers):
            result = self.docker("rm", "--force", name,
                                 label="abandoned WP-CLI cleanup", expected=(0, 1))
            if result.returncode != 0:
                failures.append("wp_cli_container")
            else:
                self._wp_cli_containers.discard(name)
        if "wordpress" in self._created:
            result = self.docker("rm", "--force", self.wordpress,
                                 label="WordPress cleanup", expected=(0, 1))
            if result.returncode != 0:
                failures.append("wordpress_container")
            else:
                self._created.discard("wordpress")
        if "database" in self._created:
            result = self.docker("rm", "--force", self.database,
                                 label="database cleanup", expected=(0, 1))
            if result.returncode != 0:
                failures.append("database_container")
            else:
                self._created.discard("database")
        for marker, volume in (("wordpress_volume", self.wordpress_volume),
                               ("database_volume", self.database_volume)):
            if marker in self._created:
                result = self.docker("volume", "rm", volume,
                                     label=f"{marker} cleanup", expected=(0, 1))
                if result.returncode != 0:
                    failures.append(marker)
                else:
                    self._created.discard(marker)
        if "network" in self._created:
            result = self.docker("network", "rm", self.network,
                                 label="network cleanup", expected=(0, 1))
            if result.returncode != 0:
                failures.append("network")
            else:
                self._created.discard("network")
        if "image" in self._created:
            result = self.docker("image", "rm", self.derived_image,
                                 label="derived image cleanup", expected=(0, 1))
            if result.returncode != 0:
                failures.append("derived_image")
            else:
                self._created.discard("image")
        try:
            self.wordpress_env.unlink(missing_ok=True)
        except OSError:
            failures.append("wordpress_environment_file")
        if failures:
            residual_names = sorted(self._wp_cli_containers)
            owned_names = {
                "wordpress": self.wordpress,
                "database": self.database,
                "wordpress_volume": self.wordpress_volume,
                "database_volume": self.database_volume,
                "network": self.network,
                "image": self.derived_image,
            }
            residual_names.extend(
                owned_names[marker]
                for marker in sorted(self._created)
                if marker in owned_names
            )
            if self.wordpress_env.exists():
                residual_names.append("private_wordpress_environment_file")
            if self.loopback_relay is not None:
                residual_names.append("loopback_relay")
            raise AcceptanceError(
                "task-owned Docker cleanup failed for "
                + ", ".join(sorted(set(failures)))
                + "; cleanup remains unconfirmed for: "
                + ", ".join(residual_names)
            )


def _all_strings(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, str):
        values.append(value)
    elif isinstance(value, list):
        for item in value:
            values.extend(_all_strings(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            values.append(str(key))
            values.extend(_all_strings(item))
    return values


def _report_identity(bundle: Path) -> dict[str, Any]:
    expected = {"assessment.html", "assessment.json", "manifest.json"}
    actual = {path.name for path in bundle.iterdir()}
    require(actual == expected, "report bundle does not contain exactly three committed files")
    identity: dict[str, Any] = {}
    for name in sorted(expected):
        path = bundle / name
        require(path.is_file() and not path.is_symlink(), "bundle payload is not regular")
        identity[name] = {"byte_length": path.stat().st_size, "sha256": sha256_file(path)}
    return identity


def _validate_wordpress_execution_boundary(html_bytes: bytes) -> None:
    require(
        0 < len(html_bytes) <= MAX_REPORT_PAYLOAD_BYTES,
        "assessment HTML is empty or exceeds its report bound",
    )
    try:
        html = html_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise AcceptanceError("assessment HTML is not valid UTF-8") from error
    for marker in (
        "<dt>Exploit execution</dt><dd><code>not_performed</code></dd>",
        "<dt>Impact validation</dt><dd><code>not_performed</code></dd>",
    ):
        require(
            html.count(marker) == 1,
            "assessment HTML omits or duplicates its fixed WordPress execution boundary",
        )


def _validate_discovery_document(document: dict[str, Any], *, generator_visible: bool) -> str:
    audit = document.get("wordpress_review")
    discovery = document.get("wordpress_discovery")
    require(isinstance(audit, dict), "discovery report omits the WordPress review audit")
    require(isinstance(discovery, dict), "discovery report omits the separate wire audit")
    require(audit.get("schema") == "security.wordpress-review-audit/v7"
            and audit.get("review_basis_schema") == "security.wordpress-review-audit/v1"
            and audit.get("additional_request_count")
            == discovery.get("attempted_request_count"),
            "discovery-influenced review schema or request accounting changed")
    schema = discovery.get("schema")
    require(schema == "security.wordpress-discovery-audit/v1",
            "discovery report has an unexpected wire-audit identity")
    require(discovery.get("policy_id") == "termivar.wordpress-metadata-discovery/v1"
            and discovery.get("selected") is True
            and discovery.get("method") == "get"
            and discovery.get("credential_mode") == "anonymous",
            "discovery report changed its closed authority policy")
    require(discovery.get("seed_count") == 3
            and discovery.get("candidate_count") == 4
            and discovery.get("candidate_limit_reached") is False
            and discovery.get("omitted_candidate_count") == 0
            and discovery.get("attempted_request_count") == 4
            and discovery.get("completed_response_count") == 4
            and discovery.get("committed_response_count") == 4
            and discovery.get("source_count") == 4,
            "real-CMS discovery did not reconcile its four expected sources")
    sources = discovery.get("sources")
    require(isinstance(sources, list), "discovery audit omits its source rows")
    discovery_items = [
        item for item in document.get("items", [])
        if isinstance(item, dict)
        and item.get("capability_id")
        == "technology.wordpress-metadata-source-response-observed@1"
    ]
    require(len(discovery_items) == 1,
            "discovery report omits or duplicates its metadata observation item")
    item = discovery_items[0]
    require(item.get("title") == "WordPress metadata-source response outcome observed"
            and item.get("category") == "wordpress-metadata-source-response"
            and item.get("disposition") == "informational"
            and item.get("claim_basis") == "observation"
            and item.get("severity") is None and item.get("cwe") is None
            and item.get("confidence_ppm") == 550_000
            and item.get("evidence_count") == discovery["committed_response_count"]
            and len(item.get("evidence_references", []))
            == discovery["committed_response_count"]
            and item.get("control_evidence_references") == []
            and item.get("candidate_evidence_references") == []
            and item.get("case_reference") is None
            and item.get("outcome_reference") is None
            and item.get("verification_stage") is None,
            "discovery metadata observation item changed its fixed claim or evidence shape")
    source_keys = [
        (source.get("kind"), source.get("component"), source.get("parent_depth"))
        for source in sources
        if isinstance(source, dict)
    ]
    require(source_keys == [
        ("rest_index", None, 0),
        ("theme_stylesheet", {"kind": "theme", "slug": "termivar-child"}, 0),
        ("theme_stylesheet", {"kind": "theme", "slug": "termivar-parent"}, 1),
        ("plugin_readme", {"kind": "plugin", "slug": "termivar-metadata-lab"}, 0),
    ], "discovery source order or identity differs from the closed oracle")
    require(all(source.get("outcome") == "observed"
                and source.get("request_attempted") is True
                and source.get("evidence_reference_count") == 1
                and isinstance(source.get("evidence_references"), list)
                and len(source["evidence_references"]) == 1
                and isinstance(source.get("response_bytes"), int)
                and source["response_bytes"] > 0
                for source in sources),
            "discovery source outcome, evidence, or byte accounting differs")
    require(sum(source.get("request_attempted") is True for source in sources
                if isinstance(source, dict)) == discovery["attempted_request_count"],
            "discovery source request-attempt accounting differs")
    source_references = [reference for source in sources
                         for reference in source["evidence_references"]]
    require(source_references == item.get("evidence_references")
            and len(set(source_references)) == len(source_references),
            "discovery source-to-evidence linkage differs")
    strings = set(_all_strings({"review": audit, "discovery": discovery}))
    for expected in (
        "termivar-child", "1.4.0", "termivar-parent", "3.2.1",
        "termivar-metadata-lab", "9.9.9", "wp/v2", "termivar-lab/v1",
    ):
        require(expected in strings, f"discovery audit omits expected typed value {expected}")
    # The inactive fixture has no public reference and must remain absent rather
    # than being guessed from the filesystem or WP-CLI ground truth.
    require("termivar-hidden-lab" not in strings,
            "discovery guessed an inactive plugin with no public reference")
    components = audit.get("components")
    require(isinstance(components, list), "discovery audit omits typed components")
    for slug, version in (
        ("termivar-child", "1.4.0"),
        ("termivar-parent", "3.2.1"),
    ):
        theme_rows = [
            row for row in components
            if isinstance(row, dict)
            and row.get("identity") == {"kind": "theme", "slug": slug}
        ]
        require(len(theme_rows) == 1,
                f"discovered theme {slug} is missing or duplicated in review evidence")
        row = theme_rows[0]
        require("theme_stylesheet_declaration" in row.get("identity_sources", [])
                and row.get("versions") == [{
                    "value": version,
                    "source": "theme_stylesheet_declaration",
                    "confidence": "public_declaration",
                }],
                f"discovered theme {slug} did not feed exact source-qualified version evidence")
    plugin_rows = [
        row for row in components
        if isinstance(row, dict)
        and row.get("identity") == {"kind": "plugin", "slug": "termivar-metadata-lab"}
    ]
    require(len(plugin_rows) == 1, "metadata plugin identity is missing or duplicated")
    plugin_versions = {
        item.get("value") for item in plugin_rows[0].get("versions", [])
        if isinstance(item, dict)
    }
    require("9.9.9" not in plugin_versions,
            "plugin Stable tag was promoted to an installed version")
    discovery_plugin_rows = [
        row for row in sources
        if isinstance(row, dict)
        and row.get("component") == {"kind": "plugin", "slug": "termivar-metadata-lab"}
    ]
    require(len(discovery_plugin_rows) == 1
            and discovery_plugin_rows[0].get("plugin", {}).get("stable_tag") == "9.9.9",
            "plugin Stable tag was not retained as separate discovery metadata")
    core_rows = [
        row for row in components
        if isinstance(row, dict)
        and row.get("identity") == {"kind": "core", "slug": "wordpress"}
    ]
    if generator_visible:
        require(any(
            item.get("value") == "7.1"
            for row in core_rows for item in row.get("versions", [])
            if isinstance(item, dict)
        ), "visible generator did not produce source-qualified core version evidence")
    else:
        require(not any(row.get("versions") for row in core_rows),
                "suppressed generator unexpectedly produced core version evidence")
    return schema


def _discovery_quality_metrics(
    document: dict[str, Any], *, generator_visible: bool
) -> dict[str, Any]:
    """Compare the report with a literal oracle independent of Termivar helpers."""
    audit = document.get("wordpress_review")
    require(isinstance(audit, dict), "quality oracle requires a WordPress review audit")
    rows = audit.get("components")
    require(isinstance(rows, list), "quality oracle requires component rows")
    components: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        require(isinstance(row, dict), "quality oracle found a malformed component row")
        identity = row.get("identity")
        require(isinstance(identity, dict), "quality oracle found a missing component identity")
        key = (identity.get("kind"), identity.get("slug"))
        require(all(isinstance(value, str) for value in key),
                "quality oracle found a malformed component identity")
        require(key not in components, "quality oracle found a duplicate component identity")
        components[key] = row

    expected_identities = {
        ("core", "wordpress"),
        ("theme", "termivar-child"),
        ("theme", "termivar-parent"),
        ("plugin", "termivar-metadata-lab"),
    }
    observed_identities = set(components)
    matched_identities = observed_identities & expected_identities
    false_identity_matches = observed_identities - expected_identities
    missed_identities = expected_identities - observed_identities
    require(not false_identity_matches and not missed_identities,
            "real-CMS observable component identity oracle disagrees")

    expected_sources = {
        ("core", "wordpress"): {
            "same_origin_asset_path",
            *({"generator_metadata"} if generator_visible else set()),
        },
        ("theme", "termivar-child"): {
            "same_origin_asset_path",
            "theme_stylesheet_declaration",
        },
        ("theme", "termivar-parent"): {"theme_stylesheet_declaration"},
        ("plugin", "termivar-metadata-lab"): {"same_origin_asset_path"},
    }
    for identity, sources in expected_sources.items():
        actual = components[identity].get("identity_sources")
        require(isinstance(actual, list) and set(actual) == sources,
                f"source-class oracle disagrees for {identity[0]}:{identity[1]}")

    expected_versions: dict[tuple[str, str], list[dict[str, str]]] = {
        ("core", "wordpress"): ([{
            "value": "7.1",
            "source": "generator_metadata",
            "confidence": "public_declaration",
        }] if generator_visible else []),
        ("theme", "termivar-child"): [{
            "value": "1.4.0",
            "source": "theme_stylesheet_declaration",
            "confidence": "public_declaration",
        }],
        ("theme", "termivar-parent"): [{
            "value": "3.2.1",
            "source": "theme_stylesheet_declaration",
            "confidence": "public_declaration",
        }],
        ("plugin", "termivar-metadata-lab"): [],
    }
    for identity, expected in expected_versions.items():
        require(components[identity].get("versions") == expected,
                f"version/source oracle disagrees for {identity[0]}:{identity[1]}")

    strings = set(_all_strings({"review": audit, "discovery": document.get("wordpress_discovery")}))
    abstentions = {
        "hidden_plugin_identity_not_guessed": "termivar-hidden-lab" not in strings,
        "readme_stable_tag_not_installed_version": not any(
            version.get("value") == "9.9.9"
            for version in components[("plugin", "termivar-metadata-lab")]["versions"]
            if isinstance(version, dict)
        ),
    }
    if not generator_visible:
        abstentions["suppressed_generator_version_not_inferred"] = not components[
            ("core", "wordpress")
        ]["versions"]
    require(all(abstentions.values()), "expected discovery abstention oracle disagrees")

    generator_total = int(generator_visible)
    return {
        "observable_identity_recall": {
            "matched": len(matched_identities),
            "denominator": len(expected_identities),
            "missed": len(missed_identities),
        },
        "false_identity_matches": {
            "count": len(false_identity_matches),
            "observed_denominator": len(observed_identities),
        },
        "version_accuracy_by_source_class": {
            "generator_metadata": {
                "correct": generator_total,
                "denominator": generator_total,
                "not_observable": int(not generator_visible),
            },
            "theme_stylesheet_declaration": {"correct": 2, "denominator": 2},
            "same_origin_asset_path": {
                "correct": 0,
                "denominator": 0,
                "meaning": "identity_only_not_version_evidence",
            },
            "plugin_readme_stable_tag": {
                "correct": 0,
                "denominator": 0,
                "meaning": "distribution_hint_not_installed_version",
            },
        },
        "expected_abstentions": {
            "correct": sum(abstentions.values()),
            "denominator": len(abstentions),
            "cases": sorted(abstentions),
        },
        "deliberately_unobservable_not_in_recall_denominator": [
            "plugin:termivar-hidden-lab"
        ],
    }


def _assert_request_delta(
    review_trace: list[tuple[str, str, int, tuple[str, ...]]],
    discovery_trace: list[tuple[str, str, int, tuple[str, ...]]],
    permalink: str,
) -> None:
    matched_review = 0
    extra: list[tuple[str, str, int, tuple[str, ...]]] = []
    for request in discovery_trace:
        if matched_review < len(review_trace) and request == review_trace[matched_review]:
            matched_review += 1
        else:
            extra.append(request)
    require(matched_review == len(review_trace),
            "discovery changed, removed, or reordered an existing request")
    expected = [("GET", path, 200, ()) for path in EXPECTED_DISCOVERY_PATHS[permalink]]
    require(extra == expected,
            f"{permalink} discovery request delta differs from the ordered four-request oracle")


def _run_scan(
    runner: ProcessRunner,
    binary: Path,
    origin: str,
    bundle: Path,
    *,
    wordpress_review: bool,
    discovery: bool,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, dict[str, Any]]:
    arguments: list[str | os.PathLike[str]] = [
        binary, "scan", origin, "--profile", "web-review", "--progress", "--report-dir", bundle,
    ]
    if wordpress_review:
        arguments.append("--wordpress-review")
    if discovery:
        arguments.append("--wordpress-discovery")
    result = runner.run(
        arguments,
        label=label,
        timeout=300,
        measure_peak_memory=True,
    )
    require(result.stdout == b"", f"{label} wrote a report document to stdout")
    require(b"Authorization" not in result.stderr and b"Cookie" not in result.stderr,
            f"{label} diagnostic exposed a forbidden credential-header name")
    identity = _report_identity(bundle)
    document = parse_json((bundle / "assessment.json").read_bytes(), f"{label} assessment")
    require(document.get("schema") == "venom-rendered-assessment/v1",
            f"{label} assessment schema changed")
    require(document.get("status") == "complete", f"{label} assessment is incomplete")
    return (
        document,
        identity,
        result.stdout,
        result.stderr,
        {
            "elapsed_milliseconds": round(result.elapsed_seconds * 1000, 3),
            "peak_memory": result.peak_memory,
        },
    )


def _run_offline_acceptance(
    runner: ProcessRunner, binary: Path, scenarios: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    results: dict[str, Any] = {"fixture_was_stopped_first": True, "bundles": {}}
    for name, scenario in scenarios.items():
        bundle = Path(scenario["_bundle"])
        verify = runner.run(
            [binary, "report", "verify", "--dir", bundle, "--format", "json"],
            label=f"offline verification {name}",
        )
        verified = parse_json(verify.stdout, f"offline verification {name}")
        require(verified.get("status") == "integrity_match",
                f"offline verification rejected {name}")
        compare = runner.run(
            [
                binary, "report", "compare", "--before", bundle / "assessment.json",
                "--after", bundle / "assessment.json", "--same-scope", "--format", "json",
            ],
            label=f"offline self comparison {name}",
        )
        compared = parse_json(compare.stdout, f"offline self comparison {name}")
        counts = compared.get("counts")
        require(isinstance(counts, dict), "offline comparison omits counts")
        source = parse_json(
            (bundle / "assessment.json").read_bytes(),
            f"offline self comparison source {name}",
        )
        item_count = source.get("item_count")
        require(isinstance(item_count, int) and not isinstance(item_count, bool)
                and item_count > 0,
                f"offline self comparison source has invalid item count for {name}")
        require(counts.get("only_in_after") == 0 and counts.get("only_in_before") == 0
                and counts.get("changed") == 0
                and counts.get("unchanged") == item_count
                and sum(counts.get(key, -1) for key in (
                    "only_in_after", "only_in_before", "changed", "unchanged"
                )) == item_count,
                f"offline self comparison changed {name}")
        results["bundles"][name] = {
            "verification_status": verified["status"],
            "self_compare_counts": counts,
        }

    before = Path(scenarios["pretty-review-only"]["_bundle"])
    after = Path(scenarios["pretty-discovery"]["_bundle"])
    controlled = runner.run(
        [
            binary, "report", "compare", "--before", before / "assessment.json",
            "--after", after / "assessment.json", "--same-scope", "--format", "json",
        ],
        label="offline collection-policy comparison",
    )
    comparison = parse_json(controlled.stdout, "offline collection-policy comparison")
    wordpress = comparison.get("wordpress_review_comparison")
    require(isinstance(wordpress, dict),
            "offline comparison omitted WordPress collection-policy change")
    require(wordpress.get("status") == "compared"
            and wordpress.get("methodology", {}).get("status") == "changed"
            and wordpress.get("coverage", {}).get("status") == "changed",
            "offline comparison did not separate discovery methodology and coverage changes")
    counts = comparison.get("counts")
    before_document = parse_json(
        (before / "assessment.json").read_bytes(),
        "offline collection-policy before assessment",
    )
    after_document = parse_json(
        (after / "assessment.json").read_bytes(),
        "offline collection-policy after assessment",
    )
    require(isinstance(counts, dict)
            and counts.get("only_in_before") == 0
            and counts.get("only_in_after")
            == after_document.get("item_count") - before_document.get("item_count")
            and sum(counts.get(key, -1) for key in (
                "only_in_after", "only_in_before", "changed", "unchanged"
            )) == after_document.get("item_count"),
            "offline collection-policy comparison lost or duplicated observations")
    only_after = comparison.get("only_in_after")
    require(isinstance(only_after, list)
            and any(item.get("capability_id")
                    == "technology.wordpress-metadata-source-response-observed@1"
                    for item in only_after if isinstance(item, dict)),
            "offline comparison omitted the one-sided discovery observation")
    results["review_only_to_discovery"] = {
        "status": wordpress["status"],
        "methodology": wordpress["methodology"]["status"],
        "coverage": wordpress["coverage"]["status"],
        "item_counts": counts,
    }
    return results


def _trace_json(
    trace: list[tuple[str, str, int, tuple[str, ...]]],
) -> list[dict[str, Any]]:
    return [
        {
            "sequence": index + 1,
            "method": method,
            "target": target,
            "status": status,
            "forbidden_credential_headers": list(forbidden_headers),
        }
        for index, (method, target, status, forbidden_headers) in enumerate(trace)
    ]


def execute_acceptance(binary: Path, source_ref: str, expected_version: str) -> dict[str, Any]:
    require(binary.is_file() and not binary.is_symlink(), "binary must be a regular non-link file")
    fixture_before = tree_sha256(FIXTURE_ROOT)
    ground_truth_before = sha256_file(GROUND_TRUTH_PATH)
    runner = ProcessRunner()
    version = runner.run([binary, "--version"], label="binary version").stdout.decode().strip()
    require(version == f"termivar {expected_version}", "binary version differs from expectation")
    scan_help = runner.run([binary, "scan", "--help"], label="scan help").stdout.decode()
    require("--wordpress-review" in scan_help and "--wordpress-discovery" in scan_help,
            "feature-enabled scan help omits WordPress discovery")
    capabilities = parse_json(
        runner.run([binary, "capabilities", "--format", "json"],
                   label="capabilities").stdout,
        "capabilities",
    )
    surfaces = capabilities.get("surfaces", [])
    discovery_surfaces = [row for row in surfaces if row.get("key") == "option.wordpress-discovery"]
    require(len(discovery_surfaces) == 1
            and discovery_surfaces[0].get("build_state") == "compiled",
            "capabilities do not report compiled WordPress discovery")

    result: dict[str, Any] = {
        "schema": TASK_SCHEMA,
        "status": "running",
        "source_ref": source_ref,
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "binary": {
            "version": version,
            "byte_length": binary.stat().st_size,
            "sha256": sha256_file(binary),
        },
        "fixture": validate_fixture(),
        "images": {},
        "ground_truth": {},
        "scenarios": {},
        "offline": {},
        "claim_limits": {
            "metadata_authenticity": "not_established",
            "plugin_stable_tag": "distribution_hint_not_installed_version",
            "generator_absence": "unknown_not_negative",
            "rest_namespace": "protocol_support_not_component_version",
            "exploit_execution": "not_performed",
            "impact_validation": "not_performed",
        },
    }

    with tempfile.TemporaryDirectory(prefix="termivar-wordpress-discovery-") as temporary:
        work = Path(temporary)
        lab = DockerWordPressLab(runner, work)
        shutdown = False
        try:
            lab.start()
            result["images"] = {
                reference: {"docker_image_id": image_id, "reference": reference}
                for reference, image_id in sorted(lab.image_ids.items())
            }
            result["ground_truth"] = lab.ground_truth()
            require(lab.origin is not None, "lab origin is unavailable")

            bundles = work / "bundles"
            bundles.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            scenarios: dict[str, dict[str, Any]] = {}

            def run_case(
                name: str,
                *,
                review: bool,
                discovery: bool,
            ) -> list[tuple[str, str, int, tuple[str, ...]]]:
                before = lab.request_log()
                bundle = bundles / name
                try:
                    document, identity, _, _, process_metrics = _run_scan(
                        runner, binary, lab.origin or "", bundle,
                        wordpress_review=review, discovery=discovery, label=name,
                    )
                except Exception:
                    lab.assert_relay_healthy()
                    raise
                lab.assert_relay_healthy()
                trace = lab.trace(before)
                schema = None
                quality = None
                discovery_response_bytes = 0
                if discovery:
                    _validate_wordpress_execution_boundary(
                        (bundle / "assessment.html").read_bytes()
                    )
                    schema = _validate_discovery_document(
                        document, generator_visible=not name.startswith("suppressed-")
                    )
                    quality = _discovery_quality_metrics(
                        document, generator_visible=not name.startswith("suppressed-")
                    )
                    discovery_response_bytes = document["wordpress_discovery"]["response_bytes"]
                scenarios[name] = {
                    "wordpress_review": review,
                    "wordpress_discovery": discovery,
                    "request_count": len(trace),
                    "request_trace": _trace_json(trace),
                    "wordpress_audit_schema": schema,
                    "quality": quality,
                    "discovery_response_bytes": discovery_response_bytes,
                    "process_metrics": process_metrics,
                    "bundle": identity,
                    "_bundle": str(bundle),
                }
                return trace

            lab.configure(permalink="pretty", generator_visible=True)
            baseline_trace = run_case("ordinary-web-review", review=False, discovery=False)
            pretty_review = run_case("pretty-review-only", review=True, discovery=False)
            pretty_discovery = run_case("pretty-discovery", review=True, discovery=True)
            require(baseline_trace == pretty_review,
                    "review-only changed or reordered the ordinary web-review request trace")
            _assert_request_delta(pretty_review, pretty_discovery, "pretty")
            scenarios["pretty-discovery"]["additional_requests_vs_review_only"] = (
                len(pretty_discovery) - len(pretty_review)
            )

            lab.configure(permalink="pretty", generator_visible=False)
            suppressed_review = run_case("suppressed-review-only", review=True, discovery=False)
            suppressed_discovery = run_case("suppressed-discovery", review=True, discovery=True)
            _assert_request_delta(suppressed_review, suppressed_discovery, "pretty")
            scenarios["suppressed-discovery"]["additional_requests_vs_review_only"] = (
                len(suppressed_discovery) - len(suppressed_review)
            )

            lab.configure(permalink="plain", generator_visible=True)
            plain_review = run_case("plain-review-only", review=True, discovery=False)
            plain_discovery = run_case("plain-discovery", review=True, discovery=True)
            _assert_request_delta(plain_review, plain_discovery, "plain")
            scenarios["plain-discovery"]["additional_requests_vs_review_only"] = (
                len(plain_discovery) - len(plain_review)
            )

            measured = [
                scenario["process_metrics"]["peak_memory"].get("status") == "measured"
                for scenario in scenarios.values()
            ]
            if platform.system() == "Linux":
                require(all(measured), "Linux lab did not record every Termivar process peak")
            result["resource_measurement"] = {
                "status": "measured" if all(measured) else "not_measured",
                "scenario_count": len(scenarios),
                "measured_scenarios": sum(measured),
                "scope": "fresh_Termivar_process_per_scenario",
                "network_elapsed_is_not_parser_benchmark": True,
            }

            lab.assert_relay_healthy()
            lab.shutdown()
            shutdown = True
            result["scenarios"] = scenarios
            result["offline"] = _run_offline_acceptance(runner, binary, scenarios)
        finally:
            if not shutdown:
                lab.shutdown()

    for scenario in result["scenarios"].values():
        scenario.pop("_bundle", None)
    require(tree_sha256(FIXTURE_ROOT) == fixture_before,
            "acceptance modified the checked-in fixture inputs")
    require(sha256_file(GROUND_TRUTH_PATH) == ground_truth_before,
            "acceptance modified the checked-in ground truth")
    result["fixture"]["unchanged_after_execution"] = True
    result["status"] = "passed"
    result["claims"] = {
        "real_wordpress_executed": True,
        "wordpress_cli_used_only_as_test_ground_truth": True,
        "termivar_received_credentials": False,
        "termivar_sent_forbidden_credential_headers": False,
        "termivar_received_inventory": False,
        "lab_network_internal": True,
        "target_origin_loopback_only": True,
        "public_network_after_image_pull": False,
        "offline_commands_ran_after_fixture_shutdown": True,
        "process_memory_is_os_high_water_not_rust_heap": True,
    }
    return result


def render_markdown(evidence: dict[str, Any]) -> str:
    lines = [
        "# Termivar WordPress discovery lab acceptance",
        "",
        f"Status: **{evidence.get('status', 'failed')}**",
        "",
        f"Source: `{evidence.get('source_ref', 'unavailable')}`",
        "",
    ]
    if evidence.get("status") == "passed":
        lines.extend([
            "| Scenario | Requests | Discovery bytes | Elapsed ms | Peak memory | WordPress audit |",
            "| --- | ---: | ---: | ---: | --- | --- |",
        ])
        for name, scenario in evidence["scenarios"].items():
            peak = scenario["process_metrics"]["peak_memory"]
            peak_text = (
                f"{peak['value']} {peak['unit']}"
                if peak.get("status") == "measured"
                else "not measured"
            )
            lines.append(
                f"| `{name}` | {scenario['request_count']} | "
                f"{scenario['discovery_response_bytes']} | "
                f"{scenario['process_metrics']['elapsed_milliseconds']} | {peak_text} | "
                f"`{scenario['wordpress_audit_schema'] or 'not_applicable'}` |"
            )
        lines.extend([
            "",
            "The old review-only trace matched ordinary web-review. Each enabled discovery "
            "case added exactly one REST index, one child stylesheet, one bounded parent "
            "stylesheet, and one plugin readme GET. All were same-origin and loopback.",
            "",
            "WP-CLI was used only inside the disposable lab for independent ground truth. "
            "Termivar received no credentials or inventory. The Stable tag remained a "
            "distribution hint, not an installed plugin version. No exploit or impact "
            "validation was performed.",
            "",
            "Every discovery scenario independently matched 4/4 observable component "
            "identities with zero false identity matches. Theme stylesheet versions "
            "matched 2/2; generator-version denominators are scenario-specific. The "
            "hidden inactive plugin and Stable-tag-as-installed-version cases are "
            "reported as expected abstentions, not successful discoveries.",
            "",
            "Elapsed time includes controlled loopback network work and is not a parser "
            "benchmark. GNU time peak values are per fresh Termivar process high-water "
            "marks, not Rust heap measurements or an exact discovery-only allocation.",
            "",
        ])
    else:
        lines.extend([f"Failure stage: `{evidence.get('failure', 'unknown')}`", ""])
    return "\n".join(lines)


def write_evidence(output_dir: Path, evidence: dict[str, Any]) -> None:
    parent = output_dir.parent
    require(parent.is_dir() and not parent.is_symlink(), "output parent must be an existing directory")
    require(output_dir.name not in {"", ".", ".."}, "output directory has an invalid final name")
    output_dir.mkdir(mode=PRIVATE_DIRECTORY_MODE, exist_ok=False)
    json_bytes = (json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    markdown_bytes = render_markdown(evidence).encode("utf-8")
    require(len(json_bytes) <= MAX_EVIDENCE_OUTPUT, "JSON evidence exceeds its bound")
    require(len(markdown_bytes) <= MAX_EVIDENCE_OUTPUT, "Markdown evidence exceeds its bound")
    (output_dir / "wordpress-discovery-lab-acceptance.json").write_bytes(json_bytes)
    (output_dir / "wordpress-discovery-lab-acceptance.md").write_bytes(markdown_bytes)
    os.chmod(output_dir / "wordpress-discovery-lab-acceptance.json", 0o600)
    os.chmod(output_dir / "wordpress-discovery-lab-acceptance.md", 0o600)


def parse_arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--source-ref")
    parser.add_argument("--expect-version")
    parser.add_argument(
        "--validate-only", action="store_true",
        help="validate pinned fixtures and the non-Docker plan without running a lab",
    )
    args = parser.parse_args(argv)
    if not args.validate_only:
        missing = [
            name for name in ("binary", "output_dir", "source_ref", "expect_version")
            if getattr(args, name) is None
        ]
        if missing:
            parser.error("live acceptance requires --binary, --output-dir, --source-ref and --expect-version")
        if SOURCE_REF_RE.fullmatch(args.source_ref) is None:
            parser.error("--source-ref must be a lowercase full Git SHA")
        if VERSION_RE.fullmatch(args.expect_version) is None:
            parser.error("--expect-version is invalid")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(sys.argv[1:] if argv is None else argv)
    fixture = validate_fixture()
    if args.validate_only:
        print(json.dumps({"schema": TASK_SCHEMA, "status": "validated", "fixture": fixture},
                         indent=2, sort_keys=True))
        return 0
    evidence: dict[str, Any]
    try:
        evidence = execute_acceptance(
            args.binary.resolve(strict=True), args.source_ref, args.expect_version
        )
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        evidence = {
            "schema": TASK_SCHEMA,
            "status": "failed",
            "source_ref": args.source_ref,
            "failure": str(error)[-4000:],
            "fixture": fixture,
        }
    write_evidence(args.output_dir, evidence)
    return 0 if evidence["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
