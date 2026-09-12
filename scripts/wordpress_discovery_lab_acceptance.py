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
FINGERPRINT_CATALOGUE_PATH = (
    Path(__file__).resolve().parents[1]
    / "docs" / "examples" / "wordpress-review" / "asset-fingerprints"
    / "catalogue.synthetic.json"
)
FINGERPRINT_COMPONENT = ("plugin", "termivar-fingerprint-lab")
FINGERPRINT_REFERENCE_ORACLE = {
    "release-a": {
        "assets/common.css": (32, "e4b20a225f36b6cecb22bd9c1e89b256f33ed39ad9e34bf2044462bba21bf17f"),
        "assets/fingerprint.css": (37, "9ae3210e7954adbb2ed976b34b4605495de9a8406634bedd92bc14a3d317fdae"),
        "assets/fingerprint.js": (49, "0a0760b281d010ed4d70610e4f2f460a33846088b373ec10fd47d0d5ccb4bf26"),
    },
    "release-b": {
        "assets/common.css": (32, "e4b20a225f36b6cecb22bd9c1e89b256f33ed39ad9e34bf2044462bba21bf17f"),
        "assets/fingerprint.css": (37, "c8b61302a47ea3208b743c287349570d3580756b3fafc73ac14a5eada9557b90"),
        "assets/fingerprint.js": (49, "0a0760b281d010ed4d70610e4f2f460a33846088b373ec10fd47d0d5ccb4bf26"),
    },
    "release-c": {
        "assets/common.css": (32, "e4b20a225f36b6cecb22bd9c1e89b256f33ed39ad9e34bf2044462bba21bf17f"),
        "assets/fingerprint.css": (37, "c8b61302a47ea3208b743c287349570d3580756b3fafc73ac14a5eada9557b90"),
        "assets/fingerprint.js": (50, "4f770e9b2646e3b0d0b0ac777c7f76ad3893f1477d1a9e00c3cfbfb443b5f4a2"),
    },
}
MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
MAX_EVIDENCE_OUTPUT = 256 * 1024
MAX_REPORT_PAYLOAD_BYTES = 16 * 1024 * 1024
PRIVATE_DIRECTORY_MODE = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
WORDPRESS_CONTAINER_PORT = 8080
WP_CLI_CONFIG_PATH = "/var/www/html/.termivar-wp-cli.yml"
WP_CLI_REWRITE_CONFIG = b"apache_modules:\n  - mod_rewrite\n"
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
ITEM_FINGERPRINT_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
CAPABILITY_ID_RE = re.compile(r"[!-~]{1,256}\Z")
COMPARISON_GROUPS = (
    "only_in_after",
    "only_in_before",
    "changed",
    "unchanged",
)
ITEM_PROJECTION_FIELDS = (
    "title",
    "category",
    "disposition",
    "claim_basis",
    "severity",
    "cwe",
    "confidence_ppm",
    "redacted_summary",
    "remediation",
    "evidence",
)
OPTIONAL_AUDIT_FIELDS = (
    "authorization_review",
    "openapi_review",
    "rest_review",
    "wordpress_review",
    "wordpress_discovery",
    "wordpress_asset_fingerprints",
)

EXPECTED_COMPONENTS = {
    ("core", "wordpress"): ("7.1", "installed"),
    ("theme", "termivar-child"): ("1.4.0", "active"),
    ("theme", "termivar-parent"): ("3.2.1", "parent"),
    ("plugin", "termivar-metadata-lab"): ("2.3.4", "active"),
    ("plugin", "termivar-fingerprint-lab"): ("4.0.0", "active"),
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
    "blog-pretty": (
        "/blog/wp-json/",
        "/blog/wp-content/themes/termivar-child/style.css",
        "/blog/wp-content/themes/termivar-parent/style.css",
        "/blog/wp-content/plugins/termivar-metadata-lab/readme.txt",
    ),
    "blog-plain": (
        "/blog/index.php?rest_route=/",
        "/blog/wp-content/themes/termivar-child/style.css",
        "/blog/wp-content/themes/termivar-parent/style.css",
        "/blog/wp-content/plugins/termivar-metadata-lab/readme.txt",
    ),
    "cms": (
        "/wp-json/",
        "/cms/wp-content/themes/termivar-child/style.css",
        "/cms/wp-content/themes/termivar-parent/style.css",
        "/cms/wp-content/plugins/termivar-metadata-lab/readme.txt",
    ),
    "custom": (
        "/wp-json/",
        "/site-content/themes/termivar-child/style.css",
        "/site-content/themes/termivar-parent/style.css",
        "/modules/termivar-metadata-lab/readme.txt",
    ),
    "custom-no-layout": ("/wp-json/",),
}
LAYOUT_ROLES = ("core", "themes", "plugins", "rest_index")
OPAQUE_REFERENCE_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclasses.dataclass(frozen=True)
class DiscoveryOracle:
    application_url: str
    request_paths: tuple[str, ...]
    core_base_url: str
    themes_base_url: str | None
    plugins_base_url: str | None
    rest_base_url: str
    declaration_bytes: bytes | None = None
    skipped_sibling_application_count: int = 0

    @property
    def full_component_set(self) -> bool:
        return self.themes_base_url is not None and self.plugins_base_url is not None

    @property
    def attempted_request_count(self) -> int:
        return len(self.request_paths)


def _framed_reference(domain: str, value: str) -> str:
    """Independent literal oracle for the documented opaque URL framing."""
    digest = hashlib.sha256()
    for part in (domain.encode("ascii"), value.encode("ascii")):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


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
        "plugins/termivar-fingerprint-lab/termivar-fingerprint-lab.php",
        "plugins/termivar-fingerprint-lab/readme.txt",
        "plugins/termivar-fingerprint-lab/assets/common.css",
        "plugins/termivar-fingerprint-lab/assets/fingerprint.css",
        "plugins/termivar-fingerprint-lab/assets/fingerprint.js",
        "plugins/termivar-fingerprint-lab/reference/release-a/assets/common.css",
        "plugins/termivar-fingerprint-lab/reference/release-a/assets/fingerprint.css",
        "plugins/termivar-fingerprint-lab/reference/release-a/assets/fingerprint.js",
        "plugins/termivar-fingerprint-lab/reference/release-b/assets/common.css",
        "plugins/termivar-fingerprint-lab/reference/release-b/assets/fingerprint.css",
        "plugins/termivar-fingerprint-lab/reference/release-b/assets/fingerprint.js",
        "plugins/termivar-fingerprint-lab/reference/release-c/assets/common.css",
        "plugins/termivar-fingerprint-lab/reference/release-c/assets/fingerprint.css",
        "plugins/termivar-fingerprint-lab/reference/release-c/assets/fingerprint.js",
        "plugins/termivar-hidden-lab/termivar-hidden-lab.php",
        "plugins/termivar-hidden-lab/readme.txt",
        "plugins/termivar-generator-control/termivar-generator-control.php",
        "sibling-shop/wp-content/themes/termivar-child/assets/decoy.css",
        "sibling-shop/wp-content/themes/termivar-child/style.css",
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
        "includes_url( 'images/blank.gif' )" in child_template,
        "lab theme must retain its deployment-aware identity-only core asset reference",
    )
    require(
        'href="/shop/wp-content/themes/termivar-child/assets/decoy.css"'
        in child_template,
        "lab child theme must retain its selected-/blog sibling decoy",
    )
    require(
        "home_url( '/contact/' )" in child_template
        and "home_url( '/gallery/' )" in child_template,
        "lab theme must retain its two ordinary page links",
    )
    fingerprint_plugin = (
        root / "plugins" / "termivar-fingerprint-lab" / "termivar-fingerprint-lab.php"
    ).read_text(encoding="utf-8")
    require(
        "Version: 4.0.0" in fingerprint_plugin
        and "is_page( array( 'contact', 'gallery' ) )" in fingerprint_plugin
        and "'cache-42'" in fingerprint_plugin,
        "fingerprint plugin identity or page-conditional asset policy changed",
    )
    for release_id, files in FINGERPRINT_REFERENCE_ORACLE.items():
        for relative_path, (byte_length, sha256) in files.items():
            reference = (
                root / "plugins" / "termivar-fingerprint-lab" / "reference"
                / release_id / Path(relative_path)
            )
            require(
                reference.stat().st_size == byte_length
                and sha256_file(reference) == sha256,
                f"fingerprint reference oracle changed for {release_id}/{relative_path}",
            )
    require(
        FINGERPRINT_CATALOGUE_PATH.is_file()
        and not FINGERPRINT_CATALOGUE_PATH.is_symlink()
        and FINGERPRINT_CATALOGUE_PATH.stat().st_size == 4601
        and sha256_file(FINGERPRINT_CATALOGUE_PATH)
        == "49d914864f0bf7f342a69b2fc10a5656fa021342209bcb328b409dba1ca76140",
        "checked-in fingerprint catalogue oracle changed",
    )
    sibling_style = (
        root / "sibling-shop/wp-content/themes/termivar-child/style.css"
    ).read_text(encoding="utf-8")
    require("Version: 88.8.8" in sibling_style,
            "lab sibling theme version oracle changed")
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
    layouts = truth.get("layouts")
    require(isinstance(layouts, dict), "lab layout ground truth is unavailable")
    require(layouts == {
        "selected_blog": {
            "application_path": "/blog/",
            "core_base_path": "/blog/",
            "themes_base_path": "/blog/wp-content/themes/",
            "plugins_base_path": "/blog/wp-content/plugins/",
            "pretty_rest_path": "/blog/wp-json/",
            "plain_rest_path": "/blog/index.php?rest_route=/",
            "sibling_decoy_path": (
                "/shop/wp-content/themes/termivar-child/assets/decoy.css"
            ),
            "sibling_style_version": "88.8.8",
        },
        "root_home_cms_core": {
            "application_path": "/",
            "core_base_path": "/cms/",
            "themes_base_path": "/cms/wp-content/themes/",
            "plugins_base_path": "/cms/wp-content/plugins/",
            "rest_path": "/wp-json/",
        },
        "declared_custom_content": {
            "application_path": "/",
            "core_base_path": "/cms/",
            "themes_base_path": "/site-content/themes/",
            "plugins_base_path": "/modules/",
            "rest_path": "/wp-json/",
        },
    }, "lab layout ground truth changed")
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


@dataclasses.dataclass(frozen=True)
class AssessmentInventory:
    schema: str
    item_count: int
    identities: dict[str, str]
    projections: dict[str, dict[str, Any]]
    optional_audits: dict[str, Any]
    sha256: str


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
                        "--quiet",
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
        self._install_wp_cli_rewrite_config()
        self._install_wordpress()
        database_env.unlink()

    def _install_wp_cli_rewrite_config(self) -> None:
        """Install the task-owned config needed for real hard rewrite flushes."""
        self.docker(
            "exec", "--interactive", self.wordpress, "sh", "-eu", "-c",
            f"umask 077; cat > {WP_CLI_CONFIG_PATH}; "
            f"test -f {WP_CLI_CONFIG_PATH}; "
            f"! test -L {WP_CLI_CONFIG_PATH}; "
            f"test \"$(wc -l < {WP_CLI_CONFIG_PATH})\" -eq 2; "
            f"test \"$(sed -n '1p' {WP_CLI_CONFIG_PATH})\" = 'apache_modules:'; "
            f"test \"$(sed -n '2p' {WP_CLI_CONFIG_PATH})\" = '  - mod_rewrite'",
            label="WP-CLI rewrite configuration",
            input_bytes=WP_CLI_REWRITE_CONFIG,
        )

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
                "--env", f"WP_CLI_CONFIG_PATH={WP_CLI_CONFIG_PATH}",
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
        self.wp("plugin", "activate", "termivar-fingerprint-lab",
                label="fingerprint plugin activation")
        for slug, title in (("contact", "Contact"), ("gallery", "Gallery")):
            post_id = self.wp(
                "post", "create", "--post_type=page", "--post_status=publish",
                f"--post_name={slug}", f"--post_title={title}", "--porcelain",
                label=f"{slug} page creation",
            ).stdout.decode("utf-8", "strict").strip()
            require(post_id.isdigit() and int(post_id) > 0,
                    f"{slug} page ground truth is unavailable")
        self.wp("option", "update", "permalink_structure", "/%postname%/",
                label="pretty permalink selection")
        self.wp("rewrite", "flush", "--hard", label="pretty permalink flush")

    def configure_fingerprint_assets(
        self,
        *,
        variant: str,
        mode: str,
        path: str = "/var/www/html",
        plugin_directory: str | None = None,
    ) -> dict[str, Any]:
        """Select immutable task-owned bytes without exposing a version to Termivar."""
        require(variant in {"release-a", "release-b", "release-c", "mixed"},
                "unknown fingerprint fixture variant")
        require(mode in {"two", "one", "common"},
                "unknown fingerprint fixture mode")
        plugin = (
            f"{plugin_directory}/termivar-fingerprint-lab"
            if plugin_directory is not None
            else f"{path}/wp-content/plugins/termivar-fingerprint-lab"
        )
        js_release = "release-c" if variant == "mixed" else variant
        css_release = "release-a" if variant == "mixed" else variant
        self.docker(
            "exec", self.wordpress, "sh", "-eu", "-c",
            f"cp {plugin}/reference/{js_release}/assets/fingerprint.js "
            f"{plugin}/assets/fingerprint.js; "
            f"cp {plugin}/reference/{css_release}/assets/fingerprint.css "
            f"{plugin}/assets/fingerprint.css; "
            f"cp {plugin}/reference/release-a/assets/common.css "
            f"{plugin}/assets/common.css",
            label=f"fingerprint {variant} asset selection",
        )
        self.wp(
            f"--path={path}", "option", "update", "termivar_fingerprint_lab_mode", mode,
            label=f"fingerprint {mode} presentation selection",
        )
        expected_paths = (
            ["assets/common.css"] if mode == "common"
            else ["assets/fingerprint.js"] if mode == "one"
            else ["assets/fingerprint.css", "assets/fingerprint.js"]
        )
        expected = {}
        for relative_path in expected_paths:
            release = (
                "release-a" if relative_path == "assets/common.css"
                else js_release if relative_path.endswith(".js") else css_release
            )
            byte_length, sha256 = FINGERPRINT_REFERENCE_ORACLE[release][relative_path]
            expected[relative_path] = {
                "byte_length": byte_length,
                "sha256": sha256,
            }
        return {
            "installed_plugin_version": "4.0.0",
            "variant": variant,
            "mode": mode,
            "observed_assets": expected,
            "url_version_hint": "cache-42",
            "readme_stable_tag": "9.9.9",
        }

    def configure(self, *, permalink: str, generator_visible: bool) -> None:
        self.configure_at(
            "/var/www/html", permalink=permalink, generator_visible=generator_visible
        )

    def configure_at(
        self, path: str, *, permalink: str, generator_visible: bool
    ) -> None:
        require(permalink in {"pretty", "plain"}, "unknown permalink scenario")
        plugin_command = "deactivate" if generator_visible else "activate"
        self.wp(f"--path={path}", "plugin", plugin_command, "termivar-generator-control",
                label="generator visibility configuration")
        structure = "/%postname%/" if permalink == "pretty" else ""
        self.wp(f"--path={path}", "option", "update", "permalink_structure", structure,
                label=f"{permalink} permalink selection")
        self.wp(f"--path={path}", "rewrite", "flush", "--hard",
                label=f"{permalink} permalink flush")
        if permalink == "pretty":
            self._assert_pretty_rewrite_file(path)

    def _assert_pretty_rewrite_file(self, wordpress_path: str) -> None:
        expected = {
            "/var/www/html": (
                "/var/www/html/.htaccess", "RewriteBase /",
                "RewriteRule . /index.php [L]",
            ),
            "/var/www/html/blog": (
                "/var/www/html/blog/.htaccess", "RewriteBase /blog/",
                "RewriteRule . /blog/index.php [L]",
            ),
            "/var/www/html/cms": (
                "/var/www/html/.htaccess", "RewriteBase /",
                "RewriteRule . /index.php [L]",
            ),
        }
        require(wordpress_path in expected, "unknown pretty-permalink fixture path")
        rewrite_path, rewrite_base, final_rule = expected[wordpress_path]
        self.docker(
            "exec", self.wordpress, "sh", "-eu", "-c",
            f"test -f {rewrite_path}; ! test -L {rewrite_path}; "
            f"test -s {rewrite_path}; "
            f"test \"$(wc -c < {rewrite_path})\" -le 16384; "
            f"grep -Fxq '# BEGIN WordPress' {rewrite_path}; "
            f"grep -Fxq '{rewrite_base}' {rewrite_path}; "
            f"grep -Fxq '{final_rule}' {rewrite_path}; "
            f"grep -Fxq '# END WordPress' {rewrite_path}",
            label=f"{wordpress_path} pretty rewrite ground truth",
        )

    def _application_url(self, path: str) -> str:
        require(self.origin is not None and self.origin.endswith("/"),
                "WordPress origin is unavailable")
        require(path.startswith("/") and path.endswith("/"),
                "application path must be an absolute directory")
        return self.origin.rstrip("/") + path

    def prepare_blog_application(self) -> str:
        """Copy the installed CMS below /blog and add one static sibling decoy."""
        self.docker(
            "exec", self.wordpress, "sh", "-eu", "-c",
            "mkdir /var/www/html/blog; "
            "find /var/www/html -mindepth 1 -maxdepth 1 ! -name blog "
            f"! -name {Path(WP_CLI_CONFIG_PATH).name} "
            "-exec cp -a '{}' /var/www/html/blog/ ';'; "
            "cp -a /usr/src/termivar-sibling/shop /var/www/html/shop; "
            "rm -f /var/www/html/.htaccess",
            label="selected blog application preparation",
        )
        application = self._application_url("/blog/")
        self.wp("--path=/var/www/html/blog", "option", "update", "siteurl",
                application.rstrip("/"), label="blog site URL selection")
        self.wp("--path=/var/www/html/blog", "option", "update", "home",
                application.rstrip("/"), label="blog home URL selection")
        self.configure_at(
            "/var/www/html/blog", permalink="pretty", generator_visible=True
        )
        return application

    def prepare_root_home_with_cms_core(self) -> str:
        """Serve the site at / while executing the installed core below /cms/."""
        self.docker(
            "exec", self.wordpress, "sh", "-eu", "-c",
            "mkdir /var/www/html/cms; "
            "find /var/www/html/blog -mindepth 1 -maxdepth 1 "
            "-exec cp -a '{}' /var/www/html/cms/ ';'; "
            "printf '%s\\n' '<?php' \"define( 'WP_USE_THEMES', true );\" "
            "\"require __DIR__ . '/cms/wp-blog-header.php';\" "
            "> /var/www/html/index.php",
            label="root-home CMS core preparation",
        )
        application = self._application_url("/")
        site = self._application_url("/cms/").rstrip("/")
        self.wp("--path=/var/www/html/cms", "option", "update", "siteurl", site,
                label="CMS core site URL selection")
        self.wp("--path=/var/www/html/cms", "option", "update", "home",
                application.rstrip("/"), label="root home URL selection")
        self.configure_at(
            "/var/www/html/cms", permalink="pretty", generator_visible=True
        )
        return application

    def prepare_custom_content_roots(self) -> bytes:
        """Move themes and plugins to declared same-origin role directories."""
        require(self.origin is not None, "WordPress origin is unavailable")
        content_url = self._application_url("/site-content/").rstrip("/")
        plugin_url = self._application_url("/modules/").rstrip("/")
        for name, value in (
            ("WP_CONTENT_DIR", "/var/www/html/site-content"),
            ("WP_CONTENT_URL", content_url),
            ("WP_PLUGIN_DIR", "/var/www/html/modules"),
            ("WP_PLUGIN_URL", plugin_url),
        ):
            self.wp(
                "--path=/var/www/html/cms", "config", "set", name, value,
                "--type=constant", label=f"custom {name} selection",
            )
        self.docker(
            "exec", self.wordpress, "sh", "-eu", "-c",
            "mv /var/www/html/cms/wp-content /var/www/html/site-content; "
            "mv /var/www/html/site-content/plugins /var/www/html/modules",
            label="custom content directory move",
        )
        self.configure_at(
            "/var/www/html/cms", permalink="pretty", generator_visible=True
        )
        declaration = {
            "schema": "security.wordpress-layout/v1",
            "application_url": self._application_url("/"),
            "core_base_url": self._application_url("/cms/"),
            "themes_base_url": self._application_url("/site-content/themes/"),
            "plugins_base_url": self._application_url("/modules/"),
        }
        return (json.dumps(declaration, separators=(",", ":"), sort_keys=True) + "\n").encode(
            "utf-8"
        )

    def ground_truth(self, path: str = "/var/www/html") -> dict[str, Any]:
        path_argument = f"--path={path}"
        core = self.wp(path_argument, "core", "version",
                       label="core ground truth").stdout.decode().strip()
        stylesheet = self.wp(path_argument, "option", "get", "stylesheet",
                             label="stylesheet ground truth").stdout.decode().strip()
        template = self.wp(path_argument, "option", "get", "template",
                           label="template ground truth").stdout.decode().strip()
        themes = parse_json(
            self.wp(path_argument, "theme", "list", "--format=json",
                    "--fields=name,status,version",
                    label="theme ground truth").stdout,
            "WP-CLI theme ground truth",
        )
        plugins = parse_json(
            self.wp(path_argument, "plugin", "list", "--format=json",
                    "--fields=name,status,version",
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
        require(plugin_map.get("termivar-fingerprint-lab") == ("4.0.0", "active"),
                "fingerprint plugin WP-CLI ground truth differs")
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
                for name in (
                    "termivar-metadata-lab",
                    "termivar-hidden-lab",
                    "termivar-fingerprint-lab",
                )
            },
            "plugin_readme_stable_tag": "9.9.9",
            "fingerprint_plugin": {
                "installed_version": "4.0.0",
                "catalogue_contains_installed_version": False,
                "conditional_pages": ["contact", "gallery"],
                "url_version_hint": "cache-42",
                "readme_stable_tag": "9.9.9",
            },
        }

    def deployment_ground_truth(
        self, path: str, *, expected_home: str, expected_site: str
    ) -> dict[str, str]:
        path_argument = f"--path={path}"
        home = self.wp(
            path_argument, "option", "get", "home", label="home URL ground truth"
        ).stdout.decode("utf-8", "strict").strip()
        site = self.wp(
            path_argument, "option", "get", "siteurl", label="site URL ground truth"
        ).stdout.decode("utf-8", "strict").strip()
        require(home == expected_home.rstrip("/")
                and site == expected_site.rstrip("/"),
                "deployment ground truth differs from the configured application/core URLs")
        return {"home": home, "siteurl": site}

    def custom_root_ground_truth(self) -> dict[str, str]:
        values: dict[str, str] = {}
        for name in ("WP_CONTENT_DIR", "WP_CONTENT_URL", "WP_PLUGIN_DIR", "WP_PLUGIN_URL"):
            values[name] = self.wp(
                "--path=/var/www/html/cms", "config", "get", name, "--type=constant",
                label=f"custom {name} ground truth",
            ).stdout.decode("utf-8", "strict").strip()
        require(values["WP_CONTENT_DIR"] == "/var/www/html/site-content"
                and values["WP_PLUGIN_DIR"] == "/var/www/html/modules"
                and values["WP_CONTENT_URL"]
                == self._application_url("/site-content/").rstrip("/")
                and values["WP_PLUGIN_URL"]
                == self._application_url("/modules/").rstrip("/"),
                "custom directory ground truth differs from the declared layout")
        return values

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


def _validate_discovery_source_shape(source: dict[str, Any]) -> None:
    """Validate the closed v2 source-row keys without requiring omitted metadata."""
    kind = source.get("kind")
    metadata_key = {
        "rest_index": "namespaces",
        "theme_stylesheet": "theme",
        "plugin_readme": "plugin",
    }.get(kind)
    required_keys = {
        "kind", "association", "resource_reference", "parent_depth", "outcome",
        "request_attempted", "response_bytes", "evidence_reference_count",
        "evidence_references",
    }
    if kind != "rest_index":
        required_keys.add("component")
    allowed_keys = required_keys | {"role_reference"}
    if metadata_key is not None:
        allowed_keys.add(metadata_key)
    metadata_present = metadata_key in source if metadata_key is not None else False
    metadata = source.get(metadata_key) if metadata_present else None
    metadata_shape_valid = False
    if metadata_key is not None and metadata_present == (source.get("outcome") == "observed"):
        if not metadata_present:
            metadata_shape_valid = True
        elif kind == "rest_index":
            metadata_shape_valid = (
                isinstance(metadata, list)
                and bool(metadata)
                and all(isinstance(value, str) and value for value in metadata)
            )
        else:
            metadata_fields = {
                "theme_stylesheet": {
                    "name", "version", "template", "requires_wordpress",
                    "requires_php", "tested_up_to",
                },
                "plugin_readme": {
                    "name", "stable_tag", "requires_wordpress", "requires_php",
                    "tested_up_to",
                },
            }[kind]
            metadata_shape_valid = (
                isinstance(metadata, dict)
                and set(metadata).issubset(metadata_fields)
                and isinstance(metadata.get("name"), str)
                and bool(metadata["name"])
            )
    component = source.get("component")
    expected_component_kind = {
        "theme_stylesheet": "theme",
        "plugin_readme": "plugin",
    }.get(kind)
    component_shape_valid = (
        "component" not in source
        if kind == "rest_index"
        else isinstance(component, dict)
        and set(component) == {"kind", "slug"}
        and component.get("kind") == expected_component_kind
        and isinstance(component.get("slug"), str)
        and bool(component["slug"])
    )
    association = source.get("association")
    role_reference_present = "role_reference" in source
    role_reference = source.get("role_reference")
    ordinary_associations = {
        "structured_advertisement", "operator_qualified_advertisement",
        "observed_conventional", "explicit_operator", "same_theme_base_parent",
    }
    role_shape_valid = (
        association == "invalid_advertisement"
        and kind == "rest_index"
        and source.get("outcome") == "invalid_advertisement"
        and not role_reference_present
    ) or (
        association in ordinary_associations
        and role_reference_present
        and isinstance(role_reference, str)
        and OPAQUE_REFERENCE_RE.fullmatch(role_reference) is not None
    )
    require(
        metadata_key is not None
        and required_keys.issubset(source)
        and set(source).issubset(allowed_keys)
        and metadata_shape_valid
        and component_shape_valid
        and role_shape_valid,
        "discovery source row has an unexpected shape",
    )


def _bounded_discovery_source_outcomes(document: dict[str, Any]) -> str:
    """Return only closed source kind/outcome tokens for private-safe diagnostics."""
    discovery = document.get("wordpress_discovery")
    if not isinstance(discovery, dict):
        return "unavailable"
    sources = discovery.get("sources")
    if not isinstance(sources, list):
        return "unavailable"
    valid_kinds = {"rest_index", "theme_stylesheet", "plugin_readme"}
    valid_outcomes = {
        "observed", "no_metadata", "not_found", "unauthorized", "rate_limited",
        "redirect_observed", "unsupported_content", "invalid_advertisement",
        "malformed", "truncated", "request_failed", "budget_exhausted",
        "cancelled", "deadline_exceeded", "not_selected_by_limit",
        "not_attempted_after_throttle",
    }
    entries = []
    for source in sources[:12]:
        if not isinstance(source, dict):
            entries.append("invalid:invalid")
            continue
        kind = source.get("kind")
        outcome = source.get("outcome")
        safe_kind = kind if isinstance(kind, str) and kind in valid_kinds else "invalid"
        safe_outcome = (
            outcome
            if isinstance(outcome, str) and outcome in valid_outcomes
            else "invalid"
        )
        entries.append(f"{safe_kind}:{safe_outcome}")
    if len(sources) > 12:
        entries.append("truncated")
    return ",".join(entries) if entries else "empty"


def _same_unique_reference_members(
    source_references: Any,
    item_references: Any,
) -> bool:
    """Compare opaque evidence membership without inventing an order contract."""
    if not isinstance(source_references, list) or not isinstance(item_references, list):
        return False
    if not all(isinstance(reference, str) for reference in source_references):
        return False
    if not all(isinstance(reference, str) for reference in item_references):
        return False
    source_members = set(source_references)
    item_members = set(item_references)
    return (
        len(source_members) == len(source_references)
        and len(item_members) == len(item_references)
        and source_members == item_members
    )


def _validate_discovery_document(
    document: dict[str, Any],
    *,
    generator_visible: bool,
    oracle: DiscoveryOracle | None = None,
) -> str:
    audit = document.get("wordpress_review")
    discovery = document.get("wordpress_discovery")
    require(isinstance(audit, dict), "discovery report omits the WordPress review audit")
    require(isinstance(discovery, dict), "discovery report omits the separate wire audit")
    require(set(discovery) == {
                "schema", "capability_id", "policy_id", "selected", "method",
                "credential_mode", "seed_count", "candidate_count",
                "candidate_limit_reached", "omitted_candidate_count",
                "attempted_request_count", "completed_response_count",
                "committed_response_count", "response_bytes", "source_count",
                "layout", "sources",
            }, "discovery report has an unexpected top-level shape")
    require(audit.get("schema") == "security.wordpress-review-audit/v7"
            and audit.get("review_basis_schema") == "security.wordpress-review-audit/v1"
            and audit.get("additional_request_count")
            == discovery.get("attempted_request_count"),
            "discovery-influenced review schema or request accounting changed")
    schema = discovery.get("schema")
    require(schema == "security.wordpress-discovery-audit/v2",
            "discovery report has an unexpected wire-audit identity")
    require(discovery.get("policy_id")
            == "termivar.wordpress-deployment-aware-metadata-discovery/v1"
            and discovery.get("selected") is True
            and discovery.get("method") == "get"
            and discovery.get("credential_mode") == "anonymous",
            "discovery report changed its closed authority policy")
    expected_count = oracle.attempted_request_count if oracle is not None else 4
    expected_seed_count = 3 if expected_count == 4 else expected_count
    require(discovery.get("seed_count") == expected_seed_count
            and discovery.get("candidate_count") == expected_count
            and discovery.get("candidate_limit_reached") is False
            and discovery.get("omitted_candidate_count") == 0
            and discovery.get("attempted_request_count") == expected_count
            and discovery.get("completed_response_count") == expected_count
            and discovery.get("committed_response_count") == expected_count
            and discovery.get("source_count") == expected_count,
            "real-CMS discovery did not reconcile its expected sources")
    sources = discovery.get("sources")
    require(isinstance(sources, list) and len(sources) == expected_count,
            "discovery audit omits its source rows")
    for source in sources:
        require(isinstance(source, dict), "discovery source row is not an object")
        _validate_discovery_source_shape(source)
    layout = discovery.get("layout")
    expected_layout_keys = {
        "application_reference", "roles", "skipped_foreign_origin_count",
        "skipped_sibling_application_count", "conflicting_association_count",
    }
    if isinstance(layout, dict) and "declaration" in layout:
        expected_layout_keys.add("declaration")
    require(isinstance(layout, dict) and set(layout) == expected_layout_keys,
            "discovery layout has an unexpected shape")
    application_reference = layout.get("application_reference")
    require(isinstance(application_reference, str)
            and OPAQUE_REFERENCE_RE.fullmatch(application_reference) is not None,
            "discovery layout has an invalid application reference")
    roles = layout.get("roles")
    require(isinstance(roles, list) and len(roles) == len(LAYOUT_ROLES)
            and [role.get("role") for role in roles if isinstance(role, dict)]
            == list(LAYOUT_ROLES),
            "discovery layout roles changed order or shape")
    role_map = {role["role"]: role for role in roles}
    for role_name, role in role_map.items():
        require(set(role) in (
                    {"role", "status", "basis", "candidate_count"},
                    {"role", "status", "basis", "reference", "candidate_count"},
                )
                and role.get("status") in {"exact", "ambiguous", "unresolved"}
                and role.get("basis") in {
                    "conventional_asset", "structured_advertisement",
                    "operator_declaration", "none",
                }
                and isinstance(role.get("candidate_count"), int)
                and not isinstance(role.get("candidate_count"), bool),
                f"discovery layout role {role_name} is malformed")
        reference = role.get("reference")
        require(reference is None or (
                    isinstance(reference, str)
                    and OPAQUE_REFERENCE_RE.fullmatch(reference) is not None
                ), f"discovery layout role {role_name} has an invalid reference")

    if oracle is not None:
        require(application_reference == _framed_reference(
                    "wordpress-selected-application", oracle.application_url
                ), "discovery layout application reference differs from the selected entry")
        declared = oracle.declaration_bytes is not None
        declaration = layout.get("declaration")
        if declared:
            require(declaration == {
                        "schema": "security.wordpress-layout/v1",
                        "byte_length": len(oracle.declaration_bytes or b""),
                        "sha256": hashlib.sha256(oracle.declaration_bytes or b"").hexdigest(),
                    }, "discovery layout declaration identity differs from exact input bytes")
        else:
            require(declaration is None, "conventional discovery unexpectedly reports a declaration")
        expected_role_urls = {
            "core": oracle.core_base_url,
            "themes": oracle.themes_base_url,
            "plugins": oracle.plugins_base_url,
            "rest_index": oracle.rest_base_url,
        }
        for role_name, base_url in expected_role_urls.items():
            role = role_map[role_name]
            if base_url is None:
                require(role == {
                            "role": role_name, "status": "unresolved", "basis": "none",
                            "candidate_count": 0,
                        }, f"discovery unexpectedly resolved undeclared {role_name} layout")
                continue
            basis = (
                "structured_advertisement" if role_name == "rest_index"
                else "operator_declaration" if declared
                else "conventional_asset"
            )
            require(role == {
                        "role": role_name,
                        "status": "exact",
                        "basis": basis,
                        "reference": _framed_reference(
                            "wordpress-discovery-role", base_url
                        ),
                        "candidate_count": 1,
                    }, f"discovery {role_name} layout differs from the literal oracle")
        require(layout.get("skipped_foreign_origin_count") == 0
                and layout.get("skipped_sibling_application_count")
                == oracle.skipped_sibling_application_count
                and layout.get("conflicting_association_count") == 0,
                "discovery layout exclusion accounting differs from the oracle")
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
    expected_source_keys = [("rest_index", None, 0)]
    if expected_count == 4:
        expected_source_keys.extend([
            ("theme_stylesheet", {"kind": "theme", "slug": "termivar-child"}, 0),
            ("theme_stylesheet", {"kind": "theme", "slug": "termivar-parent"}, 1),
            ("plugin_readme", {"kind": "plugin", "slug": "termivar-metadata-lab"}, 0),
        ])
    require(source_keys == expected_source_keys,
            "discovery source order or identity differs from the closed oracle")
    require(all(source.get("outcome") == "observed"
                and source.get("association") in {
                    "structured_advertisement", "operator_qualified_advertisement",
                    "observed_conventional", "explicit_operator",
                    "same_theme_base_parent",
                }
                and isinstance(source.get("resource_reference"), str)
                and OPAQUE_REFERENCE_RE.fullmatch(source["resource_reference"]) is not None
                and isinstance(source.get("role_reference"), str)
                and OPAQUE_REFERENCE_RE.fullmatch(source["role_reference"]) is not None
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
    require(_same_unique_reference_members(
                source_references, item.get("evidence_references")
            ),
            "discovery source-to-evidence linkage differs")
    if oracle is not None:
        origin = oracle.application_url.split("/", 3)[:3]
        origin = "/".join(origin)
        source_roles = ["rest_index"] + (["themes", "themes", "plugins"]
                                          if expected_count == 4 else [])
        source_associations = ["structured_advertisement"] + (
            [
                "explicit_operator" if oracle.declaration_bytes is not None
                else "observed_conventional",
                "same_theme_base_parent",
                "explicit_operator" if oracle.declaration_bytes is not None
                else "observed_conventional",
            ] if expected_count == 4 else []
        )
        for source, path, role_name, association in zip(
            sources, oracle.request_paths, source_roles, source_associations, strict=True
        ):
            base_url = {
                "rest_index": oracle.rest_base_url,
                "themes": oracle.themes_base_url,
                "plugins": oracle.plugins_base_url,
            }[role_name]
            require(base_url is not None, "source oracle omitted its role base")
            require(source.get("association") == association
                    and source.get("resource_reference") == _framed_reference(
                        "wordpress-discovery-resource", origin + path
                    )
                    and source.get("role_reference") == _framed_reference(
                        "wordpress-discovery-role", base_url
                    ), "discovery source association or opaque reference differs")
    strings = set(_all_strings({"review": audit, "discovery": discovery}))
    expected_strings = ["wp/v2", "termivar-lab/v1"]
    if expected_count == 4:
        expected_strings.extend([
            "termivar-child", "1.4.0", "termivar-parent", "3.2.1",
            "termivar-metadata-lab", "9.9.9",
        ])
    for expected in expected_strings:
        require(expected in strings, f"discovery audit omits expected typed value {expected}")
    # The inactive fixture has no public reference and must remain absent rather
    # than being guessed from the filesystem or WP-CLI ground truth.
    require("termivar-hidden-lab" not in strings,
            "discovery guessed an inactive plugin with no public reference")
    require("88.8.8" not in strings,
            "discovery imported the selected-/blog sibling theme declaration")
    components = audit.get("components")
    require(isinstance(components, list), "discovery audit omits typed components")
    for slug, version in (() if expected_count != 4 else (
        ("termivar-child", "1.4.0"),
        ("termivar-parent", "3.2.1"),
    )):
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
    require(len(plugin_rows) == (1 if expected_count == 4 else 0),
            "metadata plugin identity coverage differs from the layout oracle")
    plugin_versions = {
        item.get("value") for row in plugin_rows for item in row.get("versions", [])
        if isinstance(item, dict)
    }
    require("9.9.9" not in plugin_versions,
            "plugin Stable tag was promoted to an installed version")
    discovery_plugin_rows = [
        row for row in sources
        if isinstance(row, dict)
        and row.get("component") == {"kind": "plugin", "slug": "termivar-metadata-lab"}
    ]
    require((expected_count != 4 and not discovery_plugin_rows)
            or (len(discovery_plugin_rows) == 1
                and discovery_plugin_rows[0].get("plugin", {}).get("stable_tag") == "9.9.9"),
            "plugin Stable tag coverage differs from the layout oracle")
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
    oracle_name: str,
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
    expected = [("GET", path, 200, ()) for path in EXPECTED_DISCOVERY_PATHS[oracle_name]]
    require(extra == expected,
            f"{oracle_name} discovery request delta differs from the ordered four-request oracle")


def _assert_fingerprint_request_delta(
    baseline_trace: list[tuple[str, str, int, tuple[str, ...]]],
    fingerprint_trace: list[tuple[str, str, int, tuple[str, ...]]],
    *,
    plugin_base_path: str,
    relative_paths: Sequence[str],
    page_paths: Sequence[str] = ("/contact/", "/gallery/"),
) -> None:
    matched_baseline = 0
    extra: list[tuple[str, str, int, tuple[str, ...]]] = []
    for request in fingerprint_trace:
        if (
            matched_baseline < len(baseline_trace)
            and request == baseline_trace[matched_baseline]
        ):
            matched_baseline += 1
        else:
            extra.append(request)
    require(
        matched_baseline == len(baseline_trace),
        "fingerprint selection changed, removed, or reordered existing scan requests",
    )
    expected = [
        ("GET", f"{plugin_base_path}{path}?ver=cache-42", 200, ())
        for path in sorted(relative_paths)
    ]
    require(
        extra == expected,
        "fingerprint request delta differs from the exact observed-resource oracle",
    )
    for page in page_paths:
        require(
            sum(1 for method, target, status, _ in fingerprint_trace
                if (method, target, status) == ("GET", page, 200)) == 1,
            f"observed page {page} was not reused from exactly one ordinary GET",
        )
    readme = f"{plugin_base_path}readme.txt"
    require(
        sum(1 for method, target, status, _ in fingerprint_trace
            if (method, target, status) == ("GET", readme, 200)) == 1,
        "page-repeated fingerprint plugin metadata was not deduplicated",
    )
    require(
        not any("/reference/" in target for _, target, _, _ in fingerprint_trace),
        "catalogue-only reference paths unexpectedly created request authority",
    )


def _assert_fingerprint_option_off_trace(
    trace: list[tuple[str, str, int, tuple[str, ...]]],
    *,
    plugin_base_path: str,
    relative_paths: Sequence[str],
) -> None:
    expected = [
        ("HEAD", f"{plugin_base_path}{path}", 200, ())
        for path in sorted(relative_paths)
        if path.endswith(".css")
    ]
    asset_prefix = f"{plugin_base_path}assets/"
    actual = [
        request
        for request in trace
        if request[1].startswith(asset_prefix)
    ]
    require(
        actual == expected,
        "option-off observed discovery must preserve the ordinary stylesheet HEAD "
        "without acquiring fingerprint asset bodies",
    )


def _run_scan(
    runner: ProcessRunner,
    binary: Path,
    origin: str,
    bundle: Path,
    *,
    wordpress_review: bool,
    discovery: bool,
    layout_path: Path | None = None,
    page_scope: str | None = None,
    fingerprints_path: Path | None = None,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, dict[str, Any]]:
    arguments: list[str | os.PathLike[str]] = [
        binary, "scan", origin, "--profile", "web-review", "--progress", "--report-dir", bundle,
    ]
    if wordpress_review:
        arguments.append("--wordpress-review")
    if discovery:
        arguments.append("--wordpress-discovery")
    if layout_path is not None:
        arguments.extend(["--wordpress-layout", layout_path])
    if page_scope is not None:
        require(page_scope == "observed", "lab does not support linked page acquisition")
        arguments.extend(["--wordpress-page-scope", page_scope])
    if fingerprints_path is not None:
        arguments.extend(["--wordpress-fingerprints", fingerprints_path])
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
    assessment_bytes = (bundle / "assessment.json").read_bytes()
    for private_input in (layout_path, fingerprints_path):
        if private_input is None:
            continue
        private_path = os.fsencode(private_input)
        require(private_path not in result.stdout and private_path not in result.stderr
                and all(private_path not in (bundle / name).read_bytes()
                        for name in ("assessment.html", "assessment.json", "manifest.json")),
                f"{label} exposed a private local input path")
    document = parse_json(assessment_bytes, f"{label} assessment")
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


def _run_nonroot_trace_baseline(
    runner: ProcessRunner,
    binary: Path,
    origin: str,
    *,
    label: str,
) -> dict[str, Any]:
    result = runner.run(
        [
            binary,
            "scan",
            origin,
            "--profile",
            "web-review",
            "--format",
            "json",
            "--progress",
        ],
        expected=1,
        label=label,
        timeout=300,
        measure_peak_memory=True,
    )
    require(result.returncode == 1, f"{label} did not retain typed incompleteness")
    diagnostic = parse_json(result.stdout, f"{label} incomplete diagnostic")
    require(isinstance(diagnostic, dict), f"{label} diagnostic root is not an object")
    require(
        diagnostic.get("schema_version") == "web-assessment/v2"
        and diagnostic.get("disposition") == "incomplete",
        f"{label} returned the wrong diagnostic contract",
    )
    reasons = diagnostic.get("incomplete_reasons")
    require(
        isinstance(reasons, list) and bool(reasons),
        f"{label} incomplete diagnostic has no reasons",
    )
    assessment = diagnostic.get("assessment")
    report = assessment.get("report") if isinstance(assessment, dict) else None
    projection = (
        report.get("assessment_items") if isinstance(report, dict) else None
    )
    require(
        isinstance(projection, dict)
        and projection.get("projection_status") == "unavailable"
        and "items" not in projection,
        f"{label} published a partial assessment-item projection",
    )
    require(
        b"Authorization" not in result.stderr and b"Cookie" not in result.stderr,
        f"{label} diagnostic exposed a forbidden credential-header name",
    )
    return {
        "exit_code": result.returncode,
        "typed_incomplete": True,
        "diagnostic_schema": diagnostic["schema_version"],
        "incomplete_reason_count": len(reasons),
        "elapsed_milliseconds": round(result.elapsed_seconds * 1000, 3),
        "peak_memory": result.peak_memory,
    }


def _read_assessment_inventory(path: Path, label: str) -> AssessmentInventory:
    require(path.is_file() and not path.is_symlink(), f"{label} is not a regular report file")
    with path.open("rb") as source:
        raw = source.read(MAX_REPORT_PAYLOAD_BYTES + 1)
    require(0 < len(raw) <= MAX_REPORT_PAYLOAD_BYTES,
            f"{label} is empty or exceeds the report bound")
    document = parse_json(raw, label)
    require(isinstance(document, dict), f"{label} root is not an object")
    schema = document.get("schema")
    require(schema == "venom-rendered-assessment/v1",
            f"{label} has an unsupported assessment schema")
    require(document.get("status") == "complete", f"{label} is not complete")
    item_count = document.get("item_count")
    require(isinstance(item_count, int) and not isinstance(item_count, bool)
            and item_count >= 0,
            f"{label} has an invalid item_count")
    items = document.get("items")
    require(isinstance(items, list) and len(items) == item_count,
            f"{label} item_count does not match its item array")

    identities: dict[str, str] = {}
    projections: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(items):
        require(isinstance(item, dict), f"{label} item {index} is not an object")
        require(item.get("schema") == "venom-assessment-item/v1",
                f"{label} item {index} has an unsupported schema")
        fingerprint = item.get("fingerprint")
        capability_id = item.get("capability_id")
        require(isinstance(fingerprint, str)
                and ITEM_FINGERPRINT_RE.fullmatch(fingerprint) is not None,
                f"{label} item {index} has an invalid fingerprint")
        require(isinstance(capability_id, str)
                and CAPABILITY_ID_RE.fullmatch(capability_id) is not None,
                f"{label} item {index} has an invalid capability identity")
        require(fingerprint not in identities,
                f"{label} contains a duplicate item fingerprint")
        identities[fingerprint] = capability_id
        remediation = item.get("remediation")
        evidence_references = item.get("evidence_references")
        control_references = item.get("control_evidence_references")
        candidate_references = item.get("candidate_evidence_references")
        require(isinstance(remediation, dict)
                and isinstance(evidence_references, list)
                and isinstance(control_references, list)
                and isinstance(candidate_references, list),
                f"{label} item {index} has an invalid comparison projection")
        projections[fingerprint] = {
            "title": item.get("title"),
            "category": item.get("category"),
            "disposition": item.get("disposition"),
            "claim_basis": item.get("claim_basis"),
            "severity": item.get("severity"),
            "cwe": item.get("cwe"),
            "confidence_ppm": item.get("confidence_ppm"),
            "redacted_summary": item.get("redacted_summary"),
            "remediation": remediation,
            "evidence": {
                "evidence_count": item.get("evidence_count"),
                "evidence_reference_count": len(evidence_references),
                "control_reference_count": len(control_references),
                "candidate_reference_count": len(candidate_references),
                "case_present": item.get("case_reference") is not None,
                "outcome_present": item.get("outcome_reference") is not None,
                "verification_stage": item.get("verification_stage"),
            },
        }
    optional_audits = {
        field: document[field]
        for field in OPTIONAL_AUDIT_FIELDS
        if field in document
    }
    return AssessmentInventory(
        schema=schema,
        item_count=item_count,
        identities=identities,
        projections=projections,
        optional_audits=optional_audits,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _comparison_group_arrays(document: Any, label: str) -> dict[str, list[Any]]:
    require(isinstance(document, dict), f"{label} root is not an object")
    require(document.get("schema") == "termivar-report-comparison/v1",
            f"{label} has an unsupported comparison schema")
    groups: dict[str, list[Any]] = {}
    for group in COMPARISON_GROUPS:
        require(group in document, f"{label} omits comparison group {group}")
        value = document[group]
        require(isinstance(value, list), f"{label} comparison group {group} is not an array")
        groups[group] = value
    return groups


def _validate_comparison_partition(
    document: Any,
    before: AssessmentInventory,
    after: AssessmentInventory,
    label: str,
) -> tuple[dict[str, int], dict[str, dict[str, str]]]:
    groups = _comparison_group_arrays(document, label)
    for side, source in (("before", before), ("after", after)):
        metadata = document.get(side)
        require(isinstance(metadata, dict), f"{label} omits {side} source metadata")
        metadata_count = metadata.get("item_count")
        require(isinstance(metadata_count, int) and not isinstance(metadata_count, bool)
                and metadata_count == source.item_count,
                f"{label} {side} metadata item_count does not match its source")
        require(metadata.get("schema") == source.schema,
                f"{label} {side} metadata schema does not match its source")
        require(metadata.get("sha256") == source.sha256,
                f"{label} {side} metadata digest does not match its source bytes")
        require(metadata.get("optional_audits") == source.optional_audits,
                f"{label} {side} optional audit metadata does not match its source")

    shared = before.identities.keys() & after.identities.keys()
    for fingerprint in shared:
        require(before.identities[fingerprint] == after.identities[fingerprint],
                f"{label} source capability identities conflict for one fingerprint")

    identities: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for group, items in groups.items():
        group_identities: dict[str, str] = {}
        for index, item in enumerate(items):
            require(isinstance(item, dict),
                    f"{label} {group} item {index} is not an object")
            fingerprint = item.get("fingerprint")
            capability_id = item.get("capability_id")
            changed_fields = item.get("changed_fields")
            require(isinstance(fingerprint, str)
                    and ITEM_FINGERPRINT_RE.fullmatch(fingerprint) is not None,
                    f"{label} {group} item {index} has an invalid fingerprint")
            require(isinstance(capability_id, str)
                    and CAPABILITY_ID_RE.fullmatch(capability_id) is not None,
                    f"{label} {group} item {index} has an invalid capability identity")
            require(fingerprint not in seen,
                    f"{label} repeats a fingerprint across comparison groups")
            require(isinstance(changed_fields, list)
                    and all(isinstance(field, str) for field in changed_fields),
                    f"{label} {group} item {index} has invalid changed_fields")

            before_projection = item.get("before")
            after_projection = item.get("after")
            expected_before = before.projections.get(fingerprint)
            expected_after = after.projections.get(fingerprint)
            if isinstance(before_projection, dict):
                require(set(before_projection) == set(ITEM_PROJECTION_FIELDS),
                        f"{label} {group} item {index} has an invalid before projection")
            if isinstance(after_projection, dict):
                require(set(after_projection) == set(ITEM_PROJECTION_FIELDS),
                        f"{label} {group} item {index} has an invalid after projection")
            if group == "only_in_before":
                valid_shape = (before_projection == expected_before
                               and after_projection is None and not changed_fields)
            elif group == "only_in_after":
                valid_shape = (before_projection is None
                               and after_projection == expected_after and not changed_fields)
            elif group == "changed":
                expected_changed_fields = [
                    field for field in ITEM_PROJECTION_FIELDS
                    if (isinstance(before_projection, dict)
                        and isinstance(after_projection, dict)
                        and before_projection[field] != after_projection[field])
                ]
                valid_shape = (before_projection == expected_before
                               and after_projection == expected_after
                               and changed_fields == expected_changed_fields
                               and bool(expected_changed_fields))
            else:
                valid_shape = (before_projection == expected_before
                               and after_projection == expected_after
                               and before_projection == after_projection
                               and not changed_fields)
            require(valid_shape, f"{label} {group} item {index} has an invalid group shape")
            group_identities[fingerprint] = capability_id
            seen.add(fingerprint)
        identities[group] = group_identities

    expected_only_before = {
        fingerprint: before.identities[fingerprint]
        for fingerprint in before.identities.keys() - after.identities.keys()
    }
    expected_only_after = {
        fingerprint: after.identities[fingerprint]
        for fingerprint in after.identities.keys() - before.identities.keys()
    }
    expected_shared = {
        fingerprint: before.identities[fingerprint]
        for fingerprint in shared
    }
    actual_shared = {**identities["changed"], **identities["unchanged"]}
    require(identities["only_in_before"] == expected_only_before,
            f"{label} only_in_before identities do not match the before source")
    require(identities["only_in_after"] == expected_only_after,
            f"{label} only_in_after identities do not match the after source")
    require(actual_shared == expected_shared,
            f"{label} paired identities do not match the source intersection")

    counts = {group: len(items) for group, items in groups.items()}
    require(counts["only_in_before"] + counts["changed"] + counts["unchanged"]
            == before.item_count,
            f"{label} does not conserve the before source item count")
    require(counts["only_in_after"] + counts["changed"] + counts["unchanged"]
            == after.item_count,
            f"{label} does not conserve the after source item count")
    return counts, identities


def _require_changed_wordpress_facet(document: dict[str, Any], name: str) -> None:
    facet = document.get(name)
    require(isinstance(facet, dict) and facet.get("status") == "changed",
            f"offline WordPress comparison {name} is not changed")
    before = facet.get("before")
    after = facet.get("after")
    changed_fields = facet.get("changed_fields")
    require(isinstance(before, dict) and isinstance(after, dict),
            f"offline WordPress comparison {name} omits compared projections")
    expected_fields = sorted(
        key for key in before.keys() | after.keys()
        if before.get(key) != after.get(key)
    )
    require(isinstance(changed_fields, list)
            and changed_fields == expected_fields
            and bool(expected_fields),
            f"offline WordPress comparison {name} has inconsistent changed fields")


def _require_empty_wordpress_entities(document: dict[str, Any], label: str) -> None:
    for name in ("components", "advisories"):
        entities = document.get(name)
        require(isinstance(entities, dict)
                and entities.get("paired_unchanged_count") == 0
                and entities.get("paired_changed") == []
                and entities.get("only_in_before") == []
                and entities.get("only_in_after") == [],
                f"{label} unexpectedly paired WordPress {name}")


def _run_offline_acceptance(
    runner: ProcessRunner, binary: Path, scenarios: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    def require_bundle_unchanged(name: str, scenario: dict[str, Any]) -> None:
        expected_identity = scenario.get("bundle")
        require(isinstance(expected_identity, dict),
                f"offline source bundle identity is missing for {name}")
        require(_report_identity(Path(scenario["_bundle"])) == expected_identity,
                f"offline commands modified report bundle {name}")

    results: dict[str, Any] = {"fixture_was_stopped_first": True, "bundles": {}}
    for name, scenario in scenarios.items():
        bundle = Path(scenario["_bundle"])
        require_bundle_unchanged(name, scenario)
        verify = runner.run(
            [binary, "report", "verify", "--dir", bundle, "--format", "json"],
            label=f"offline verification {name}",
        )
        verified = parse_json(verify.stdout, f"offline verification {name}")
        require(isinstance(verified, dict)
                and verified.get("schema") == "termivar-report-verification/v1",
                f"offline verification returned an unsupported schema for {name}")
        require(verified.get("status") == "integrity_match",
                f"offline verification rejected {name}")
        require_bundle_unchanged(name, scenario)
        compare = runner.run(
            [
                binary, "report", "compare", "--before", bundle / "assessment.json",
                "--after", bundle / "assessment.json", "--same-scope", "--format", "json",
            ],
            label=f"offline self comparison {name}",
        )
        compared = parse_json(compare.stdout, f"offline self comparison {name}")
        source = _read_assessment_inventory(
            bundle / "assessment.json", f"offline self comparison source {name}"
        )
        require(source.item_count > 0,
                f"offline self comparison source has invalid item count for {name}")
        counts, _ = _validate_comparison_partition(
            compared, source, source, f"offline self comparison {name}"
        )
        require(counts["only_in_after"] == 0 and counts["only_in_before"] == 0
                and counts["changed"] == 0
                and counts["unchanged"] == source.item_count,
                f"offline self comparison changed {name}")
        if scenario.get("fingerprints") is not None:
            wordpress = compared.get("wordpress_review_comparison")
            fingerprints = (
                wordpress.get("asset_fingerprints")
                if isinstance(wordpress, dict) else None
            )
            require(
                isinstance(wordpress, dict)
                and wordpress.get("schema")
                == "termivar-wordpress-review-comparison/v3"
                and wordpress.get("status") == "compared"
                and isinstance(fingerprints, dict)
                and fingerprints.get("status") == "compared"
                and all(
                    fingerprints.get(facet, {}).get("status") == "unchanged"
                    for facet in ("methodology", "catalogue", "coverage")
                )
                and fingerprints.get("resources", {}).get("paired_unchanged_count")
                == scenario["fingerprints"]["resource_count"]
                and fingerprints.get("components", {}).get("paired_unchanged_count") == 1
                and all(
                    not fingerprints.get(entity, {}).get(group)
                    for entity in ("resources", "components")
                    for group in ("paired_changed", "only_in_before", "only_in_after")
                ),
                f"offline fingerprint self comparison changed {name}",
            )
        require_bundle_unchanged(name, scenario)
        results["bundles"][name] = {
            "bundle_unchanged": True,
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
    before_document = _read_assessment_inventory(
        before / "assessment.json",
        "offline collection-policy before assessment",
    )
    after_document = _read_assessment_inventory(
        after / "assessment.json",
        "offline collection-policy after assessment",
    )
    require(before_document.item_count > 0 and after_document.item_count > 0,
            "offline collection-policy comparison source has invalid item count")
    counts, identities = _validate_comparison_partition(
        comparison,
        before_document,
        after_document,
        "offline collection-policy comparison",
    )
    wordpress = comparison.get("wordpress_review_comparison")
    require(isinstance(wordpress, dict),
            "offline comparison omitted WordPress collection-policy change")
    require(wordpress.get("schema") == "termivar-wordpress-review-comparison/v2"
            and wordpress.get("status") == "not_compared"
            and wordpress.get("reason") == "application_scope_unknown",
            "offline comparison treated omitted legacy application scope as comparable")
    _require_empty_wordpress_entities(wordpress, "offline collection-policy comparison")
    _require_changed_wordpress_facet(wordpress, "methodology")
    _require_changed_wordpress_facet(wordpress, "coverage")
    require(counts["only_in_before"] == 0
            and counts["only_in_after"]
            == after_document.item_count - before_document.item_count,
            "offline collection-policy comparison lost or duplicated observations")
    require(len(identities["only_in_after"]) == 1
            and next(iter(identities["only_in_after"].values()), None)
            == "technology.wordpress-metadata-source-response-observed@1",
            "offline comparison omitted the one-sided discovery observation")
    results["review_only_to_discovery"] = {
        "status": wordpress["status"],
        "reason": wordpress["reason"],
        "methodology": wordpress["methodology"]["status"],
        "coverage": wordpress["coverage"]["status"],
        "item_counts": counts,
    }

    custom_names = {"custom-no-layout-discovery", "custom-layout-discovery"}
    if custom_names <= scenarios.keys():
        before = Path(scenarios["custom-no-layout-discovery"]["_bundle"])
        after = Path(scenarios["custom-layout-discovery"]["_bundle"])
        compared = runner.run(
            [
                binary, "report", "compare", "--before", before / "assessment.json",
                "--after", after / "assessment.json", "--same-scope", "--format", "json",
            ],
            label="offline custom layout comparison",
        )
        comparison = parse_json(compared.stdout, "offline custom layout comparison")
        before_document = _read_assessment_inventory(
            before / "assessment.json", "offline custom layout before assessment"
        )
        after_document = _read_assessment_inventory(
            after / "assessment.json", "offline custom layout after assessment"
        )
        counts, _ = _validate_comparison_partition(
            comparison, before_document, after_document,
            "offline custom layout comparison",
        )
        wordpress = comparison.get("wordpress_review_comparison")
        require(isinstance(wordpress, dict)
                and wordpress.get("schema") == "termivar-wordpress-review-comparison/v2"
                and wordpress.get("status") == "compared"
                and wordpress.get("reason") is None,
                "offline custom layout comparison did not retain one application scope")
        _require_changed_wordpress_facet(wordpress, "methodology")
        _require_changed_wordpress_facet(wordpress, "coverage")
        require(
            scenarios["custom-no-layout-discovery"].get("layout_application_reference")
            == scenarios["custom-layout-discovery"].get("layout_application_reference")
            and isinstance(
                scenarios["custom-layout-discovery"].get("layout_application_reference"), str
            ),
            "custom layout scenarios did not retain one application identity",
        )
        results["custom_no_layout_to_declared_layout"] = {
            "status": wordpress["status"],
            "methodology": wordpress["methodology"]["status"],
            "coverage": wordpress["coverage"]["status"],
            "item_counts": counts,
        }

    mismatch_names = {"blog-pretty-discovery", "custom-layout-discovery"}
    if mismatch_names <= scenarios.keys():
        before = Path(scenarios["blog-pretty-discovery"]["_bundle"])
        after = Path(scenarios["custom-layout-discovery"]["_bundle"])
        compared = runner.run(
            [
                binary, "report", "compare", "--before", before / "assessment.json",
                "--after", after / "assessment.json", "--same-scope", "--format", "json",
            ],
            label="offline application-scope mismatch comparison",
        )
        comparison = parse_json(
            compared.stdout, "offline application-scope mismatch comparison"
        )
        before_document = _read_assessment_inventory(
            before / "assessment.json", "offline application-scope mismatch before"
        )
        after_document = _read_assessment_inventory(
            after / "assessment.json", "offline application-scope mismatch after"
        )
        counts, _ = _validate_comparison_partition(
            comparison, before_document, after_document,
            "offline application-scope mismatch comparison",
        )
        wordpress = comparison.get("wordpress_review_comparison")
        require(isinstance(wordpress, dict)
                and wordpress.get("status") == "not_compared"
                and wordpress.get("reason") == "application_scope_mismatch",
                "offline comparison paired known different WordPress applications")
        _require_empty_wordpress_entities(
            wordpress, "offline application-scope mismatch comparison"
        )
        require(
            scenarios["blog-pretty-discovery"].get("layout_application_reference")
            != scenarios["custom-layout-discovery"].get("layout_application_reference"),
            "different applications unexpectedly share one opaque identity",
        )
        results["application_scope_mismatch"] = {
            "status": wordpress["status"],
            "reason": wordpress["reason"],
            "item_counts": counts,
        }

    fingerprint_names = {
        "fingerprint-release-b",
        "fingerprint-mixed-artifacts",
        "fingerprint-missing-reference",
    }
    if fingerprint_names <= scenarios.keys():
        def compare_fingerprints(
            before_name: str,
            after_name: str,
            *,
            catalogue_status: str,
            changed_resource_count: int,
            unchanged_resource_count: int,
            required_component_dimensions: set[str],
            label: str,
        ) -> dict[str, Any]:
            before_path = Path(scenarios[before_name]["_bundle"]) / "assessment.json"
            after_path = Path(scenarios[after_name]["_bundle"]) / "assessment.json"
            command = runner.run(
                [
                    binary, "report", "compare", "--before", before_path,
                    "--after", after_path, "--same-scope", "--format", "json",
                ],
                label=label,
            )
            comparison = parse_json(command.stdout, label)
            before_document = _read_assessment_inventory(before_path, f"{label} before")
            after_document = _read_assessment_inventory(after_path, f"{label} after")
            require(before_document.item_count == after_document.item_count,
                    f"{label} unexpectedly changed item cardinality")
            counts, _ = _validate_comparison_partition(
                comparison, before_document, after_document, label
            )
            require(
                counts == {
                    "only_in_after": 0,
                    "only_in_before": 0,
                    "changed": 0,
                    "unchanged": before_document.item_count,
                },
                f"{label} confused fingerprint audit changes with assessment items",
            )
            wordpress = comparison.get("wordpress_review_comparison")
            fingerprints = (
                wordpress.get("asset_fingerprints")
                if isinstance(wordpress, dict) else None
            )
            resources = (
                fingerprints.get("resources") if isinstance(fingerprints, dict) else None
            )
            components = (
                fingerprints.get("components") if isinstance(fingerprints, dict) else None
            )
            resource_changes = (
                resources.get("paired_changed") if isinstance(resources, dict) else None
            )
            component_changes = (
                components.get("paired_changed") if isinstance(components, dict) else None
            )
            require(
                isinstance(wordpress, dict)
                and wordpress.get("schema") == "termivar-wordpress-review-comparison/v3"
                and wordpress.get("status") == "compared"
                and isinstance(fingerprints, dict)
                and fingerprints.get("status") == "compared"
                and fingerprints.get("methodology", {}).get("status") == "unchanged"
                and fingerprints.get("catalogue", {}).get("status") == catalogue_status
                and fingerprints.get("coverage", {}).get("status") == "unchanged"
                and isinstance(resources, dict)
                and resources.get("paired_unchanged_count") == unchanged_resource_count
                and isinstance(resource_changes, list)
                and len(resource_changes) == changed_resource_count
                and isinstance(components, dict)
                and isinstance(component_changes, list)
                and len(component_changes) == 1
                and required_component_dimensions
                <= set(component_changes[0].get("changed_dimensions", [])),
                f"{label} did not separate bytes, catalogue, coverage, and candidates",
            )
            if changed_resource_count:
                require(
                    all(
                        set(change.get("changed_dimensions", [])) == {"resource_bytes"}
                        for change in resource_changes
                    ),
                    f"{label} attributed a byte-only change to another resource dimension",
                )
            return {
                "item_counts": counts,
                "catalogue": catalogue_status,
                "changed_resources": changed_resource_count,
                "unchanged_resources": unchanged_resource_count,
                "component_changed_dimensions": component_changes[0][
                    "changed_dimensions"
                ],
            }

        results["fingerprint_bytes_changed"] = compare_fingerprints(
            "fingerprint-release-b",
            "fingerprint-mixed-artifacts",
            catalogue_status="unchanged",
            changed_resource_count=2,
            unchanged_resource_count=0,
            required_component_dimensions={"candidate_set", "reference_matrix"},
            label="offline fingerprint byte comparison",
        )
        results["fingerprint_catalogue_changed"] = compare_fingerprints(
            "fingerprint-release-b",
            "fingerprint-missing-reference",
            catalogue_status="changed",
            changed_resource_count=0,
            unchanged_resource_count=2,
            required_component_dimensions={
                "candidate_set", "reference_matrix", "resource_coverage"
            },
            label="offline fingerprint catalogue comparison",
        )
    for name, scenario in scenarios.items():
        require_bundle_unchanged(name, scenario)
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


def _validate_observed_page_baseline(document: dict[str, Any]) -> str:
    require(
        document.get("wordpress_asset_fingerprints") is None,
        "option-off observed run unexpectedly emitted a fingerprint audit",
    )
    review = document.get("wordpress_review")
    discovery = document.get("wordpress_discovery")
    pages = discovery.get("page_collection") if isinstance(discovery, dict) else None
    require(
        isinstance(review, dict)
        and review.get("schema") == "security.wordpress-review-audit/v7"
        and isinstance(discovery, dict)
        and discovery.get("schema") == "security.wordpress-discovery-audit/v3"
        and discovery.get("attempted_request_count") == 5
        and discovery.get("committed_response_count") == 5
        and review.get("additional_request_count") == 5
        and isinstance(pages, dict)
        and pages.get("mode") == "observed"
        and pages.get("candidate_count") == 2
        and pages.get("selected_count") == 2
        and pages.get("reused_response_count") == 2
        and pages.get("fetched_response_count") == 0
        and pages.get("attempted_request_count") == 0
        and pages.get("committed_response_count") == 2,
        "option-off observed-page baseline changed its reuse or request accounting",
    )
    fingerprint_readmes = [
        source for source in discovery.get("sources", [])
        if isinstance(source, dict)
        and source.get("kind") == "plugin_readme"
        and source.get("component")
        == {"kind": FINGERPRINT_COMPONENT[0], "slug": FINGERPRINT_COMPONENT[1]}
    ]
    require(
        len(fingerprint_readmes) == 1
        and fingerprint_readmes[0].get("plugin", {}).get("stable_tag") == "9.9.9"
        and len(fingerprint_readmes[0].get("source_page_references", [])) == 2,
        "observed-page baseline did not deduplicate its conditional plugin metadata",
    )
    return discovery["schema"]


def _write_missing_reference_catalogue(source: Path, target: Path) -> dict[str, Any]:
    """Create one labelled synthetic coverage mutation without production helpers."""
    document = parse_json(source.read_bytes(), "fingerprint source catalogue")
    require(isinstance(document, dict), "fingerprint source catalogue is not an object")
    components = document.get("components")
    require(isinstance(components, list) and len(components) == 1,
            "fingerprint source catalogue component matrix changed")
    releases = components[0].get("releases") if isinstance(components[0], dict) else None
    require(isinstance(releases, list) and len(releases) == 3,
            "fingerprint source catalogue release matrix changed")
    removed = 0
    for release in releases:
        if not isinstance(release, dict) or release.get("release_id") != "release-a":
            continue
        files = release.get("files")
        require(isinstance(files, list), "release-a fingerprint rows are unavailable")
        kept = []
        for row in files:
            if isinstance(row, dict) and row.get("path") == "assets/fingerprint.css":
                removed += 1
            else:
                kept.append(row)
        release["files"] = kept
    require(removed == 1, "missing-reference mutation did not remove exactly one row")
    encoded = (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )
    target.write_bytes(encoded)
    os.chmod(target, 0o600)
    return {
        "byte_length": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "mutation": "release-a/assets/fingerprint.css reference removed",
    }


def _validate_fingerprint_document(
    document: dict[str, Any],
    *,
    catalogue_path: Path,
    asset_oracle: dict[str, dict[str, Any]],
    expected_state: str,
    compatible: Sequence[str],
    undetermined: Sequence[str],
    inconsistent: Sequence[str],
) -> dict[str, Any]:
    """Validate the literal fingerprint wire contract without rerunning its matcher."""
    audit = document.get("wordpress_asset_fingerprints")
    require(isinstance(audit, dict), "fingerprint audit is unavailable")
    require(
        audit.get("schema") == "security.wordpress-asset-fingerprint-audit/v1"
        and audit.get("capability_id")
        == "technology.wordpress-asset-fingerprint-candidate@1"
        and audit.get("policy_id")
        == "termivar.wordpress-observed-asset-fingerprint/v1"
        and audit.get("selected") is True
        and audit.get("representation_profile") == "identity-content-bytes/v1"
        and audit.get("finite_reference_scope") == "listed_releases_only"
        and audit.get("same_release_assumption")
        == "considered_paths_share_one_listed_release_artifact_set"
        and audit.get("installed_version_assurance")
        == "not_established_by_asset_fingerprints"
        and audit.get("source_authenticity") == "not_established",
        "fingerprint audit changed its bounded conditional claim contract",
    )
    catalogue = audit.get("catalogue")
    require(isinstance(catalogue, dict), "fingerprint catalogue provenance is unavailable")
    require(
        catalogue.get("schema") == "security.wordpress-asset-fingerprint-catalog/v1"
        and catalogue.get("byte_length") == catalogue_path.stat().st_size
        and catalogue.get("sha256") == sha256_file(catalogue_path)
        and isinstance(catalogue.get("semantic_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", catalogue["semantic_sha256"]) is not None
        and catalogue.get("component_count") == 1
        and catalogue.get("release_count") == 3,
        "fingerprint catalogue identity or finite scope differs",
    )
    resources = audit.get("resources")
    require(isinstance(resources, list), "fingerprint resource rows are unavailable")
    require(
        audit.get("candidate_count") == len(asset_oracle)
        and audit.get("selected_resource_count") == len(asset_oracle)
        and audit.get("omitted_resource_count") == 0
        and audit.get("attempted_request_count") == len(asset_oracle)
        and audit.get("reused_response_count") == 0
        and audit.get("fetched_response_count") == len(asset_oracle)
        and audit.get("stop") == "complete"
        and audit.get("resource_count") == len(asset_oracle)
        and len(resources) == len(asset_oracle),
        "fingerprint acquisition accounting differs from the literal oracle",
    )
    actual_resources: dict[str, dict[str, Any]] = {}
    transferred_bytes = 0
    for resource in resources:
        require(isinstance(resource, dict), "fingerprint resource row is malformed")
        path = resource.get("relative_path")
        require(isinstance(path, str) and path not in actual_resources,
                "fingerprint resource identity is missing or duplicated")
        require(
            resource.get("component")
            == {"kind": FINGERPRINT_COMPONENT[0], "slug": FINGERPRINT_COMPONENT[1]}
            and resource.get("acquisition") == "fetched"
            and resource.get("outcome") == "observed"
            and resource.get("request_attempted") is True
            and resource.get("observed_variant_count") == 1
            and "url" not in resource
            and "query" not in resource,
            f"fingerprint resource policy differs for {path!r}",
        )
        source_pages = resource.get("source_page_references")
        require(
            isinstance(source_pages, list)
            and len(source_pages) == 2
            and len(set(source_pages)) == 2
            and all(isinstance(value, str) and OPAQUE_REFERENCE_RE.fullmatch(value)
                    for value in source_pages),
            f"fingerprint page provenance differs for {path!r}",
        )
        evidence = resource.get("evidence_references")
        require(
            resource.get("evidence_reference_count") == 1
            and isinstance(evidence, list)
            and len(evidence) == 1
            and isinstance(evidence[0], str),
            f"fingerprint evidence accounting differs for {path!r}",
        )
        expected = asset_oracle.get(path)
        observation = resource.get("observation")
        require(
            expected is not None
            and isinstance(observation, dict)
            and observation.get("byte_length") == expected["byte_length"]
            and observation.get("sha256") == expected["sha256"]
            and resource.get("interpreted_response_bytes") == expected["byte_length"]
            and resource.get("response_bytes") == expected["byte_length"],
            f"fingerprint bytes differ from the independent oracle for {path!r}",
        )
        transferred_bytes += expected["byte_length"]
        actual_resources[path] = observation
    require(set(actual_resources) == set(asset_oracle),
            "fingerprint resource set differs from the independent oracle")
    require(
        audit.get("response_bytes") == transferred_bytes,
        "fingerprint transferred-byte accounting differs from complete asset bytes",
    )

    components = audit.get("components")
    require(
        audit.get("component_count") == 1
        and isinstance(components, list)
        and len(components) == 1,
        "fingerprint component accounting differs",
    )
    component = components[0]
    expected_release_states = {
        release_id: "compatible" for release_id in compatible
    }
    expected_release_states.update(
        {release_id: "undetermined" for release_id in undetermined}
    )
    expected_release_states.update(
        {release_id: "inconsistent" for release_id in inconsistent}
    )
    release_rows = component.get("releases") if isinstance(component, dict) else None
    require(isinstance(release_rows, list), "fingerprint release rows are unavailable")
    actual_release_states = {
        release.get("release_id"): release.get("state")
        for release in release_rows
        if isinstance(release, dict)
    }
    require(
        component.get("identity")
        == {"kind": FINGERPRINT_COMPONENT[0], "slug": FINGERPRINT_COMPONENT[1]}
        and component.get("catalogue_component_listed") is True
        and component.get("state") == expected_state
        and component.get("candidate_resource_count") == len(asset_oracle)
        and component.get("selected_resource_count") == len(asset_oracle)
        and component.get("completely_interpreted_resource_count") == len(asset_oracle)
        and component.get("omitted_resource_count") == 0
        and component.get("compatible_release_ids") == list(compatible)
        and component.get("undetermined_release_ids") == list(undetermined)
        and component.get("inconsistent_release_ids") == list(inconsistent)
        and component.get("resource_count") == len(asset_oracle)
        and component.get("release_count") == 3
        and len(release_rows) == 3
        and actual_release_states == expected_release_states,
        "fingerprint candidate aggregation differs from the independent oracle",
    )
    review = document.get("wordpress_review")
    require(
        isinstance(review, dict)
        and review.get("schema") == "security.wordpress-review-audit/v8",
        "fingerprint run did not use the coordinated WordPress v8 wrapper",
    )
    discovery = document.get("wordpress_discovery")
    page_collection = (
        discovery.get("page_collection") if isinstance(discovery, dict) else None
    )
    require(
        isinstance(discovery, dict)
        and discovery.get("schema") == "security.wordpress-discovery-audit/v3"
        and discovery.get("attempted_request_count") == 5
        and discovery.get("committed_response_count") == 5
        and isinstance(page_collection, dict)
        and page_collection.get("mode") == "observed"
        and page_collection.get("candidate_count") == 2
        and page_collection.get("selected_count") == 2
        and page_collection.get("omitted_candidate_count") == 0
        and page_collection.get("reused_response_count") == 2
        and page_collection.get("fetched_response_count") == 0
        and page_collection.get("not_observed_count") == 0
        and page_collection.get("rejected_response_count") == 0
        and page_collection.get("accepted_association_count") == 2
        and page_collection.get("rejected_association_count") == 0
        and page_collection.get("attempted_request_count") == 0
        and page_collection.get("completed_response_count") == 2
        and page_collection.get("committed_response_count") == 2
        and isinstance(page_collection.get("pages"), list)
        and len(page_collection["pages"]) == 2
        and review.get("additional_request_count") == 5 + len(asset_oracle),
        "fingerprint run did not preserve observed-page reuse and shared accounting",
    )
    page_references = {
        page.get("page_reference")
        for page in page_collection["pages"]
        if isinstance(page, dict)
    }
    require(
        len(page_references) == 2
        and all(isinstance(value, str) and OPAQUE_REFERENCE_RE.fullmatch(value)
                for value in page_references)
        and all(set(resource["source_page_references"]) == page_references
                for resource in resources),
        "fingerprint resource-to-page provenance does not reconcile",
    )
    fingerprint_readmes = [
        source for source in discovery.get("sources", [])
        if isinstance(source, dict)
        and source.get("kind") == "plugin_readme"
        and source.get("component")
        == {"kind": FINGERPRINT_COMPONENT[0], "slug": FINGERPRINT_COMPONENT[1]}
    ]
    require(
        len(fingerprint_readmes) == 1
        and fingerprint_readmes[0].get("outcome") == "observed"
        and set(fingerprint_readmes[0].get("source_page_references", []))
        == page_references
        and fingerprint_readmes[0].get("plugin", {}).get("stable_tag") == "9.9.9",
        "fingerprint plugin metadata was not deduplicated across observed pages",
    )
    review_rows = review.get("components")
    require(isinstance(review_rows, list), "fingerprint review component rows are unavailable")
    require(
        len(review_rows) == 5
        and all(
            isinstance(row, dict) and isinstance(row.get("identity"), dict)
            for row in review_rows
        ),
        "fingerprint run changed the bounded WordPress component-row cardinality",
    )
    review_identities = {
        (row.get("identity", {}).get("kind"), row.get("identity", {}).get("slug"))
        for row in review_rows
        if isinstance(row, dict) and isinstance(row.get("identity"), dict)
    }
    require(
        review_identities
        == {
            ("core", "wordpress"),
            ("theme", "termivar-child"),
            ("theme", "termivar-parent"),
            ("plugin", "termivar-metadata-lab"),
            FINGERPRINT_COMPONENT,
        },
        "fingerprint run lost, substituted, or invented a WordPress component identity",
    )
    fingerprint_rows = [
        row for row in review_rows
        if isinstance(row, dict)
        and row.get("identity")
        == {"kind": FINGERPRINT_COMPONENT[0], "slug": FINGERPRINT_COMPONENT[1]}
    ]
    require(len(fingerprint_rows) == 1, "fingerprint component identity was lost or duplicated")
    require(
        fingerprint_rows[0].get("identity_sources") == ["same_origin_asset_path"]
        and fingerprint_rows[0].get("versions") == [],
        "fingerprint, Stable tag, or URL ver was promoted to installed-version evidence",
    )
    return {
        "state": expected_state,
        "compatible_release_ids": list(compatible),
        "undetermined_release_ids": list(undetermined),
        "inconsistent_release_ids": list(inconsistent),
        "resource_count": len(resources),
        "attempted_request_count": audit["attempted_request_count"],
        "reused_response_count": audit["reused_response_count"],
        "fetched_response_count": audit["fetched_response_count"],
        "response_bytes": audit["response_bytes"],
        "informative_resource_count": component.get("informative_resource_count"),
        "listed_matrix_complete": component.get("listed_matrix_complete"),
        "catalogue_sha256": catalogue["sha256"],
        "catalogue_semantic_sha256": catalogue["semantic_sha256"],
    }


def _validate_discovery_capability(document: Any) -> None:
    require(isinstance(document, dict), "capabilities must be a JSON object")
    require(
        document.get("schema") == "termivar-cli-capabilities/v1",
        "capabilities schema is unsupported",
    )
    surfaces = document.get("surfaces")
    require(isinstance(surfaces, list), "capabilities surfaces must be an array")
    discovery_surfaces = [
        row
        for row in surfaces
        if isinstance(row, dict) and row.get("key") == "option.wordpress-discovery"
    ]
    require(
        len(discovery_surfaces) == 1,
        "capabilities do not report exactly one WordPress discovery surface",
    )
    discovery = discovery_surfaces[0]
    prerequisites = discovery.get("prerequisites")
    expected_prerequisites = [
        "--profile web-review",
        "--wordpress-review",
        "--wordpress-discovery",
        "optional --wordpress-page-scope observed",
        "optional --wordpress-layout FILE",
        "optional --wordpress-fingerprints FILE",
    ]
    require(
        discovery.get("build_state") == "compiled"
        and discovery.get("compile_feature") == "wordpress-review"
        and discovery.get("implementation_status") == "implemented"
        and prerequisites == expected_prerequisites,
        "capabilities do not report compiled WordPress discovery",
    )


def execute_acceptance(binary: Path, source_ref: str, expected_version: str) -> dict[str, Any]:
    require(binary.is_file() and not binary.is_symlink(), "binary must be a regular non-link file")
    fixture_before = tree_sha256(FIXTURE_ROOT)
    ground_truth_before = sha256_file(GROUND_TRUTH_PATH)
    fingerprint_catalogue_before = sha256_file(FINGERPRINT_CATALOGUE_PATH)
    runner = ProcessRunner()
    version = runner.run([binary, "--version"], label="binary version").stdout.decode().strip()
    require(version == f"termivar {expected_version}", "binary version differs from expectation")
    scan_help = runner.run([binary, "scan", "--help"], label="scan help").stdout.decode()
    require("--wordpress-review" in scan_help
            and "--wordpress-discovery" in scan_help
            and "--wordpress-page-scope" in scan_help
            and "--wordpress-layout" in scan_help
            and "--wordpress-fingerprints" in scan_help,
            "feature-enabled scan help omits WordPress discovery")
    capabilities = parse_json(
        runner.run([binary, "capabilities", "--format", "json"],
                   label="capabilities").stdout,
        "capabilities",
    )
    _validate_discovery_capability(capabilities)

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
        "trace_only_baselines": {},
        "offline": {},
        "claim_limits": {
            "metadata_authenticity": "not_established",
            "plugin_stable_tag": "distribution_hint_not_installed_version",
            "asset_fingerprint_candidate": (
                "finite_catalogue_compatibility_not_installed_version"
            ),
            "url_ver": "cache_hint_not_release_selector",
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

            def absolute(path: str) -> str:
                return (lab.origin or "").rstrip("/") + path

            def oracle(
                application_path: str,
                path_key: str,
                *,
                core_path: str,
                themes_path: str | None,
                plugins_path: str | None,
                rest_path: str,
                declaration_bytes: bytes | None = None,
                skipped_sibling: int = 0,
            ) -> DiscoveryOracle:
                return DiscoveryOracle(
                    application_url=absolute(application_path),
                    request_paths=EXPECTED_DISCOVERY_PATHS[path_key],
                    core_base_url=absolute(core_path),
                    themes_base_url=(absolute(themes_path) if themes_path else None),
                    plugins_base_url=(absolute(plugins_path) if plugins_path else None),
                    rest_base_url=absolute(rest_path),
                    declaration_bytes=declaration_bytes,
                    skipped_sibling_application_count=skipped_sibling,
                )

            def run_case(
                name: str,
                *,
                review: bool,
                discovery: bool,
                target: str | None = None,
                discovery_oracle: DiscoveryOracle | None = None,
                layout_path: Path | None = None,
                page_scope: str | None = None,
                fingerprints_path: Path | None = None,
                fingerprint_expectation: dict[str, Any] | None = None,
            ) -> list[tuple[str, str, int, tuple[str, ...]]]:
                before = lab.request_log()
                bundle = bundles / name
                try:
                    document, identity, _, _, process_metrics = _run_scan(
                        runner, binary, target or lab.origin or "", bundle,
                        wordpress_review=review, discovery=discovery,
                        layout_path=layout_path, page_scope=page_scope,
                        fingerprints_path=fingerprints_path, label=name,
                    )
                except Exception:
                    lab.assert_relay_healthy()
                    raise
                lab.assert_relay_healthy()
                trace = lab.trace(before)
                schema = None
                quality = None
                discovery_response_bytes = 0
                fingerprint_summary = None
                if discovery:
                    _validate_wordpress_execution_boundary(
                        (bundle / "assessment.html").read_bytes()
                    )
                    try:
                        if fingerprint_expectation is not None:
                            require(fingerprints_path is not None,
                                    "fingerprint expectation has no catalogue input")
                            schema = document.get("wordpress_discovery", {}).get("schema")
                            fingerprint_summary = _validate_fingerprint_document(
                                document,
                                catalogue_path=fingerprints_path,
                                **fingerprint_expectation,
                            )
                        elif page_scope == "observed":
                            schema = _validate_observed_page_baseline(document)
                        else:
                            schema = _validate_discovery_document(
                                document,
                                generator_visible=not name.startswith("suppressed-"),
                                oracle=discovery_oracle,
                            )
                            if discovery_oracle is None or discovery_oracle.full_component_set:
                                quality = _discovery_quality_metrics(
                                    document,
                                    generator_visible=not name.startswith("suppressed-"),
                                )
                    except AcceptanceError as error:
                        outcomes = _bounded_discovery_source_outcomes(document)
                        raise AcceptanceError(
                            f"{name}: {error}; source_outcomes={outcomes}"
                        ) from error
                    discovery_response_bytes = document["wordpress_discovery"]["response_bytes"]
                scenarios[name] = {
                    "wordpress_review": review,
                    "wordpress_discovery": discovery,
                    "request_count": len(trace),
                    "request_trace": _trace_json(trace),
                    "wordpress_audit_schema": schema,
                    "layout_application_reference": (
                        document.get("wordpress_discovery", {})
                        .get("layout", {})
                        .get("application_reference")
                    ),
                    "layout": (
                        document.get("wordpress_discovery", {}).get("layout")
                        if discovery else None
                    ),
                    "source_associations": ([
                        {
                            "kind": source.get("kind"),
                            "component": source.get("component"),
                            "parent_depth": source.get("parent_depth"),
                            "association": source.get("association"),
                            "resource_reference": source.get("resource_reference"),
                            "role_reference": source.get("role_reference"),
                        }
                        for source in document.get("wordpress_discovery", {}).get(
                            "sources", []
                        )
                        if isinstance(source, dict)
                    ] if discovery else []),
                    "expected_metadata_paths": (
                        list(discovery_oracle.request_paths)
                        if discovery_oracle is not None else []
                    ),
                    "quality": quality,
                    "fingerprints": fingerprint_summary,
                    "discovery_response_bytes": discovery_response_bytes,
                    "process_metrics": process_metrics,
                    "bundle": identity,
                    "_bundle": str(bundle),
                }
                return trace

            def run_nonroot_trace_baseline(
                name: str, target: str
            ) -> list[tuple[str, str, int, tuple[str, ...]]]:
                before = lab.request_log()
                process_metrics = _run_nonroot_trace_baseline(
                    runner,
                    binary,
                    target,
                    label=name,
                )
                lab.assert_relay_healthy()
                trace = lab.trace(before)
                result["trace_only_baselines"][name] = {
                    "wordpress_review": False,
                    "wordpress_discovery": False,
                    "request_count": len(trace),
                    "request_trace": _trace_json(trace),
                    "process_metrics": process_metrics,
                    "no_completed_bundle_expected": True,
                }
                return trace

            lab.configure(permalink="pretty", generator_visible=True)
            root_pretty_oracle = oracle(
                "/", "pretty", core_path="/", themes_path="/wp-content/themes/",
                plugins_path="/wp-content/plugins/", rest_path="/",
            )
            baseline_trace = run_case("ordinary-web-review", review=False, discovery=False)
            pretty_review = run_case("pretty-review-only", review=True, discovery=False)
            pretty_discovery = run_case(
                "pretty-discovery", review=True, discovery=True,
                discovery_oracle=root_pretty_oracle,
            )
            require(baseline_trace == pretty_review,
                    "review-only changed or reordered the ordinary web-review request trace")
            _assert_request_delta(pretty_review, pretty_discovery, "pretty")
            scenarios["pretty-discovery"]["additional_requests_vs_review_only"] = (
                len(pretty_discovery) - len(pretty_review)
            )

            lab.configure(permalink="pretty", generator_visible=False)
            suppressed_review = run_case("suppressed-review-only", review=True, discovery=False)
            suppressed_discovery = run_case(
                "suppressed-discovery", review=True, discovery=True,
                discovery_oracle=root_pretty_oracle,
            )
            _assert_request_delta(suppressed_review, suppressed_discovery, "pretty")
            scenarios["suppressed-discovery"]["additional_requests_vs_review_only"] = (
                len(suppressed_discovery) - len(suppressed_review)
            )

            lab.configure(permalink="plain", generator_visible=True)
            plain_review = run_case("plain-review-only", review=True, discovery=False)
            root_plain_oracle = dataclasses.replace(
                root_pretty_oracle, request_paths=EXPECTED_DISCOVERY_PATHS["plain"]
            )
            plain_discovery = run_case(
                "plain-discovery", review=True, discovery=True,
                discovery_oracle=root_plain_oracle,
            )
            _assert_request_delta(plain_review, plain_discovery, "plain")
            scenarios["plain-discovery"]["additional_requests_vs_review_only"] = (
                len(plain_discovery) - len(plain_review)
            )

            # The finite catalogue is checked independently above. These cases
            # vary only task-owned served bytes and presentation, never a version
            # declaration supplied to Termivar.
            lab.configure(permalink="pretty", generator_visible=True)
            missing_catalogue_path = work / "fingerprint-catalogue-missing-a-css.json"
            missing_catalogue_identity = _write_missing_reference_catalogue(
                FINGERPRINT_CATALOGUE_PATH, missing_catalogue_path
            )
            result["ground_truth"]["fingerprint_catalogues"] = {
                "complete": {
                    "byte_length": FINGERPRINT_CATALOGUE_PATH.stat().st_size,
                    "sha256": sha256_file(FINGERPRINT_CATALOGUE_PATH),
                    "release_ids": ["release-a", "release-b", "release-c"],
                },
                "missing_reference_mutation": missing_catalogue_identity,
            }

            observed_baseline_truth = lab.configure_fingerprint_assets(
                variant="release-b", mode="two"
            )
            observed_baseline = run_case(
                "fingerprint-observed-option-off",
                review=True,
                discovery=True,
                page_scope="observed",
            )
            _assert_fingerprint_option_off_trace(
                observed_baseline,
                plugin_base_path="/wp-content/plugins/termivar-fingerprint-lab/",
                relative_paths=tuple(observed_baseline_truth["observed_assets"]),
            )

            def run_fingerprint_case(
                name: str,
                *,
                variant: str,
                mode: str,
                catalogue_path: Path = FINGERPRINT_CATALOGUE_PATH,
                state: str,
                compatible: Sequence[str],
                undetermined: Sequence[str],
                inconsistent: Sequence[str],
            ) -> list[tuple[str, str, int, tuple[str, ...]]]:
                ground_truth = lab.configure_fingerprint_assets(
                    variant=variant, mode=mode
                )
                trace = run_case(
                    name,
                    review=True,
                    discovery=True,
                    page_scope="observed",
                    fingerprints_path=catalogue_path,
                    fingerprint_expectation={
                        "asset_oracle": ground_truth["observed_assets"],
                        "expected_state": state,
                        "compatible": compatible,
                        "undetermined": undetermined,
                        "inconsistent": inconsistent,
                    },
                )
                _assert_fingerprint_request_delta(
                    observed_baseline,
                    trace,
                    plugin_base_path="/wp-content/plugins/termivar-fingerprint-lab/",
                    relative_paths=tuple(ground_truth["observed_assets"]),
                )
                scenarios[name]["ground_truth"] = ground_truth
                scenarios[name]["additional_asset_requests_vs_option_off"] = (
                    len(trace) - len(observed_baseline)
                )
                return trace

            run_fingerprint_case(
                "fingerprint-release-b",
                variant="release-b",
                mode="two",
                state="single_catalogue_candidate",
                compatible=["release-b"],
                undetermined=[],
                inconsistent=["release-a", "release-c"],
            )
            run_fingerprint_case(
                "fingerprint-release-a",
                variant="release-a",
                mode="two",
                state="single_catalogue_candidate",
                compatible=["release-a"],
                undetermined=[],
                inconsistent=["release-b", "release-c"],
            )
            run_fingerprint_case(
                "fingerprint-one-file",
                variant="release-b",
                mode="one",
                state="provisional_candidates",
                compatible=["release-a", "release-b"],
                undetermined=[],
                inconsistent=["release-c"],
            )
            run_fingerprint_case(
                "fingerprint-common-file",
                variant="release-b",
                mode="common",
                state="provisional_candidates",
                compatible=["release-a", "release-b", "release-c"],
                undetermined=[],
                inconsistent=[],
            )
            run_fingerprint_case(
                "fingerprint-mixed-artifacts",
                variant="mixed",
                mode="two",
                state="no_consistent_catalogue_release",
                compatible=[],
                undetermined=[],
                inconsistent=["release-a", "release-b", "release-c"],
            )
            run_fingerprint_case(
                "fingerprint-missing-reference",
                variant="release-b",
                mode="two",
                catalogue_path=missing_catalogue_path,
                state="provisional_candidates",
                compatible=["release-b"],
                undetermined=["release-a"],
                inconsistent=["release-c"],
            )

            blog_target = lab.prepare_blog_application()
            result["ground_truth"]["blog"] = {
                "inventory": lab.ground_truth("/var/www/html/blog"),
                "deployment": lab.deployment_ground_truth(
                    "/var/www/html/blog", expected_home=blog_target,
                    expected_site=blog_target,
                ),
            }
            blog_pretty_oracle = oracle(
                "/blog/", "blog-pretty", core_path="/blog/",
                themes_path="/blog/wp-content/themes/",
                plugins_path="/blog/wp-content/plugins/", rest_path="/blog/",
                skipped_sibling=1,
            )
            blog_pretty_baseline = run_nonroot_trace_baseline(
                "blog-pretty-ordinary-web-review", blog_target,
            )
            blog_pretty_discovery = run_case(
                "blog-pretty-discovery", review=True, discovery=True,
                target=blog_target, discovery_oracle=blog_pretty_oracle,
            )
            _assert_request_delta(
                blog_pretty_baseline, blog_pretty_discovery, "blog-pretty"
            )
            require(not any(
                        target.endswith("/shop/wp-content/themes/termivar-child/style.css")
                        for _, target, _, _ in blog_pretty_discovery
                    ), "selected /blog discovery requested the sibling theme stylesheet")
            scenarios["blog-pretty-discovery"][
                "additional_requests_vs_ordinary_web_review"
            ] = (
                len(blog_pretty_discovery) - len(blog_pretty_baseline)
            )

            lab.configure_fingerprint_assets(
                variant="release-c", mode="two", path="/var/www/html/blog"
            )
            blog_fingerprint_baseline = run_case(
                "blog-fingerprint-observed-option-off",
                review=True,
                discovery=True,
                target=blog_target,
                page_scope="observed",
            )
            blog_fingerprint_truth = lab.configure_fingerprint_assets(
                variant="release-c", mode="two", path="/var/www/html/blog"
            )
            blog_fingerprint = run_case(
                "blog-fingerprint-release-c",
                review=True,
                discovery=True,
                target=blog_target,
                page_scope="observed",
                fingerprints_path=FINGERPRINT_CATALOGUE_PATH,
                fingerprint_expectation={
                    "asset_oracle": blog_fingerprint_truth["observed_assets"],
                    "expected_state": "single_catalogue_candidate",
                    "compatible": ["release-c"],
                    "undetermined": [],
                    "inconsistent": ["release-a", "release-b"],
                },
            )
            _assert_fingerprint_request_delta(
                blog_fingerprint_baseline,
                blog_fingerprint,
                plugin_base_path=(
                    "/blog/wp-content/plugins/termivar-fingerprint-lab/"
                ),
                relative_paths=tuple(blog_fingerprint_truth["observed_assets"]),
                page_paths=("/blog/contact/", "/blog/gallery/"),
            )
            scenarios["blog-fingerprint-release-c"]["ground_truth"] = (
                blog_fingerprint_truth
            )
            scenarios["blog-fingerprint-release-c"][
                "additional_asset_requests_vs_option_off"
            ] = len(blog_fingerprint) - len(blog_fingerprint_baseline)

            lab.configure_at(
                "/var/www/html/blog", permalink="plain", generator_visible=True
            )
            blog_plain_oracle = dataclasses.replace(
                blog_pretty_oracle, request_paths=EXPECTED_DISCOVERY_PATHS["blog-plain"]
            )
            blog_plain_baseline = run_nonroot_trace_baseline(
                "blog-plain-ordinary-web-review", blog_target,
            )
            blog_plain_discovery = run_case(
                "blog-plain-discovery", review=True, discovery=True,
                target=blog_target, discovery_oracle=blog_plain_oracle,
            )
            _assert_request_delta(blog_plain_baseline, blog_plain_discovery, "blog-plain")
            scenarios["blog-plain-discovery"][
                "additional_requests_vs_ordinary_web_review"
            ] = (
                len(blog_plain_discovery) - len(blog_plain_baseline)
            )

            cms_target = lab.prepare_root_home_with_cms_core()
            result["ground_truth"]["cms"] = {
                "inventory": lab.ground_truth("/var/www/html/cms"),
                "deployment": lab.deployment_ground_truth(
                    "/var/www/html/cms", expected_home=cms_target,
                    expected_site=absolute("/cms/"),
                ),
            }
            cms_oracle = oracle(
                "/", "cms", core_path="/cms/",
                themes_path="/cms/wp-content/themes/",
                plugins_path="/cms/wp-content/plugins/", rest_path="/",
            )
            cms_review = run_case(
                "cms-review-only", review=True, discovery=False, target=cms_target
            )
            cms_discovery = run_case(
                "cms-discovery", review=True, discovery=True, target=cms_target,
                discovery_oracle=cms_oracle,
            )
            _assert_request_delta(cms_review, cms_discovery, "cms")
            scenarios["cms-discovery"]["additional_requests_vs_review_only"] = (
                len(cms_discovery) - len(cms_review)
            )

            declaration_bytes = lab.prepare_custom_content_roots()
            layout_path = work / "wordpress-layout.json"
            layout_path.write_bytes(declaration_bytes)
            os.chmod(layout_path, 0o600)
            layout_input_identity = {
                "byte_length": len(declaration_bytes),
                "sha256": hashlib.sha256(declaration_bytes).hexdigest(),
            }
            result["ground_truth"]["custom"] = {
                "inventory": lab.ground_truth("/var/www/html/cms"),
                "deployment": lab.deployment_ground_truth(
                    "/var/www/html/cms", expected_home=cms_target,
                    expected_site=absolute("/cms/"),
                ),
                "declared_roots": lab.custom_root_ground_truth(),
            }
            custom_review = run_case(
                "custom-review-only", review=True, discovery=False, target=cms_target
            )
            custom_no_layout_oracle = oracle(
                "/", "custom-no-layout", core_path="/cms/", themes_path=None,
                plugins_path=None, rest_path="/",
            )
            custom_no_layout = run_case(
                "custom-no-layout-discovery", review=True, discovery=True,
                target=cms_target, discovery_oracle=custom_no_layout_oracle,
            )
            _assert_request_delta(custom_review, custom_no_layout, "custom-no-layout")
            custom_layout_oracle = oracle(
                "/", "custom", core_path="/cms/",
                themes_path="/site-content/themes/", plugins_path="/modules/",
                rest_path="/", declaration_bytes=declaration_bytes,
            )
            custom_layout = run_case(
                "custom-layout-discovery", review=True, discovery=True,
                target=cms_target, discovery_oracle=custom_layout_oracle,
                layout_path=layout_path,
            )
            _assert_request_delta(custom_review, custom_layout, "custom")
            scenarios["custom-no-layout-discovery"][
                "additional_requests_vs_review_only"
            ] = len(custom_no_layout) - len(custom_review)
            scenarios["custom-layout-discovery"]["additional_requests_vs_review_only"] = (
                len(custom_layout) - len(custom_review)
            )
            require(
                layout_path.read_bytes() == declaration_bytes,
                "Termivar modified the operator layout declaration",
            )
            scenarios["custom-layout-discovery"]["layout_input"] = {
                **layout_input_identity,
                "unchanged_after_scan": True,
            }

            lab.configure_fingerprint_assets(
                variant="release-b",
                mode="two",
                path="/var/www/html/cms",
                plugin_directory="/var/www/html/modules",
            )
            custom_fingerprint_baseline = run_case(
                "custom-fingerprint-observed-option-off",
                review=True,
                discovery=True,
                target=cms_target,
                layout_path=layout_path,
                page_scope="observed",
            )
            custom_fingerprint_truth = lab.configure_fingerprint_assets(
                variant="release-b",
                mode="two",
                path="/var/www/html/cms",
                plugin_directory="/var/www/html/modules",
            )
            custom_fingerprint = run_case(
                "custom-fingerprint-release-b",
                review=True,
                discovery=True,
                target=cms_target,
                layout_path=layout_path,
                page_scope="observed",
                fingerprints_path=FINGERPRINT_CATALOGUE_PATH,
                fingerprint_expectation={
                    "asset_oracle": custom_fingerprint_truth["observed_assets"],
                    "expected_state": "single_catalogue_candidate",
                    "compatible": ["release-b"],
                    "undetermined": [],
                    "inconsistent": ["release-a", "release-c"],
                },
            )
            _assert_fingerprint_request_delta(
                custom_fingerprint_baseline,
                custom_fingerprint,
                plugin_base_path="/modules/termivar-fingerprint-lab/",
                relative_paths=tuple(custom_fingerprint_truth["observed_assets"]),
            )
            scenarios["custom-fingerprint-release-b"]["ground_truth"] = (
                custom_fingerprint_truth
            )
            scenarios["custom-fingerprint-release-b"][
                "additional_asset_requests_vs_option_off"
            ] = len(custom_fingerprint) - len(custom_fingerprint_baseline)
            require(
                layout_path.read_bytes() == declaration_bytes,
                "fingerprint run modified the operator layout declaration",
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
    require(sha256_file(FINGERPRINT_CATALOGUE_PATH) == fingerprint_catalogue_before,
            "acceptance modified the checked-in fingerprint catalogue")
    result["fixture"]["unchanged_after_execution"] = True
    result["status"] = "passed"
    result["claims"] = {
        "real_wordpress_executed": True,
        "wordpress_cli_used_only_as_test_ground_truth": True,
        "termivar_received_credentials": False,
        "termivar_sent_forbidden_credential_headers": False,
        "termivar_received_inventory": False,
        "termivar_received_custom_component_wordlist": False,
        "custom_layout_input_contained_role_roots_only": True,
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
            "The original review-only trace matched ordinary web-review. Legacy entry-only "
            "discovery cases added exactly one REST index, one child stylesheet, one bounded "
            "parent stylesheet, and one plugin readme GET at their selected layout. Observed-"
            "page cases reused the two ordinary contact/gallery responses and added one "
            "deduplicated readme GET for the page-only fingerprint plugin. Fingerprint-enabled "
            "cases then fetched only the one or two exact observed CSS/JS representations "
            "listed by their scenario; no catalogue-only reference path was requested. The "
            "undeclared custom-root case added only its advertised REST GET. All WordPress-"
            "owned metadata and asset requests were same-origin and loopback.",
            "",
            "WP-CLI was used only inside the disposable lab for independent ground truth. "
            "Termivar received no credentials or inventory. The Stable tag remained a "
            "distribution hint, not an installed plugin version. No exploit or impact "
            "validation was performed.",
            "",
            "Every fully resolved discovery scenario independently matched 4/4 observable component "
            "identities with zero false identity matches. Theme stylesheet versions "
            "matched 2/2; generator-version denominators are scenario-specific. The "
            "hidden inactive plugin and Stable-tag-as-installed-version cases are "
            "reported as expected abstentions, not successful discoveries.",
            "",
            "The task-owned fingerprint plugin was independently installed as version 4.0.0, "
            "which is absent from the finite three-release catalogue. Two complementary "
            "observed assets produced the expected listed-release intersections; one shared "
            "asset remained provisional, mixed assets produced no consistent listed release, "
            "and a deliberately removed reference row remained undetermined. These are "
            "finite-catalogue compatibility results, not installed-version evidence.",
            "",
            "The selected `/blog/` application did not derive its sibling `/shop/` "
            "stylesheet. Declaring the moved theme/plugin roots changed methodology and "
            "coverage for the same root application; comparing `/blog/` with `/` kept "
            "WordPress entities unpaired because their application references differ.",
            "",
            "The two non-root ordinary web-review baselines retained their documented "
            "typed-incomplete result and were used only to compare request traces; they "
            "did not produce completed bundles. Non-root completed WordPress reports "
            "required explicit metadata discovery and its scoped application reference.",
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
