#!/usr/bin/env python3
"""Accept one native Termivar release-candidate archive and its packaged CLI.

Python 3.12.4+, standard library only. The caller supplies one locally built
archive and closed workflow identity declarations. This helper neither builds
nor downloads software, and its hashes identify candidate bytes without
authenticating source, tag, or release provenance.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
from typing import Callable

import first_use
import report_bundle_example
import verify_release_archive


SCHEMA = "termivar-release-candidate-acceptance/v1"
CAPABILITIES_SCHEMA = "termivar-cli-capabilities/v1"
VERIFICATION_SCHEMA = "termivar-report-verification/v1"
COMPARISON_SCHEMA = "termivar-report-comparison/v1"
EVIDENCE_NAME = "acceptance.json"
EVIDENCE_LIMIT = 256 * 1024
MAX_PARENT_ENTRIES = 64
TARGETS = {
    "x86_64-unknown-linux-gnu": {
        "system": "Linux", "machines": {"x86_64", "amd64"},
        "suffix": ".tar.gz", "member": "termivar",
    },
    "x86_64-pc-windows-msvc": {
        "system": "Windows", "machines": {"amd64", "x86_64"},
        "suffix": ".zip", "member": "termivar.exe",
    },
    "x86_64-apple-darwin": {
        "system": "Darwin", "machines": {"x86_64", "amd64"},
        "suffix": ".tar.gz", "member": "termivar",
    },
    "aarch64-apple-darwin": {
        "system": "Darwin", "machines": {"arm64", "aarch64"},
        "suffix": ".tar.gz", "member": "termivar",
    },
}
RELEASE_MEMBERS = (
    "artifact-adapter",
    "normalization-resilience",
    "graphql-review",
    "openapi-review",
    "rest-review",
    "authorization-review",
    "wordpress-review",
)
EXCLUDED_FEATURES = (
    "api-adapter",
    "legacy-scanner",
    "proxy-adapter",
    "ssrf-oast-review",
)
ALL_FEATURES = tuple(sorted(("release-bundle", *RELEASE_MEMBERS, *EXCLUDED_FEATURES)))
WORDPRESS_OPTIONS = (
    "--wordpress-review",
    "--wordpress-discovery",
    "--wordpress-context",
    "--wordpress-advisories",
    "--wordpress-plugins-json",
    "--wordpress-themes-json",
    "--wordpress-core-version-file",
    "--wordpress-advisories-format",
    "--wordpress-external-version-profile",
)
WORDPRESS_PREREQUISITES = (
    "--profile web-review",
    "--wordpress-review",
    "optional --wordpress-context FILE",
    "optional --wordpress-advisories FILE",
    "optional --wordpress-advisories-format termivar|wordfence-v3-production",
    ("optional --wordpress-external-version-profile "
     "numeric-dotted/v1|php-release-subset/v1 (Wordfence Production only)"),
    "optional --wordpress-plugins-json FILE",
    "optional --wordpress-themes-json FILE",
    "optional --wordpress-core-version-file FILE",
)
WORDPRESS_DISCOVERY_PREREQUISITES = (
    "--profile web-review",
    "--wordpress-review",
    "--wordpress-discovery",
)
GROUPS = ("only_in_after", "only_in_before", "changed", "unchanged")
PROGRESS_PREFIX = b"[progress]"
PROGRESS_LINE_LIMIT = 512
PROGRESS_TOTAL_LIMIT = 64 * 1024
PROGRESS_LINE = re.compile(
    rb"^\[progress\] state=(assessment_running|composing_report|rendering_report|"
    rb"writing_stdout|publishing_report|completed|incomplete|failed) "
    rb"elapsed_ms=(?:0|[1-9][0-9]*) "
    rb"accounted_requests=(?:unknown|0|[1-9][0-9]*) "
    rb"accounted_active_verifications=(?:unknown|0|[1-9][0-9]*) "
    rb"subjects_started=(?:unknown|0|[1-9][0-9]*) "
    rb"subjects_processed=(?:unknown|0|[1-9][0-9]*) "
    rb"counts=last_observed(?: bundle_commit=(?:not_committed|committed))?\r?\n$",
    re.ASCII,
)
SYNTHETIC_COUNTS = {
    "only_in_after": 1,
    "only_in_before": 1,
    "changed": 1,
    "unchanged": 1,
}
HEX_SHA = re.compile(r"[0-9a-f]{40}", re.ASCII)
POSITIVE_INTEGER = re.compile(r"[1-9][0-9]*", re.ASCII)
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][A-Za-z0-9-]*))*)?"
    r"(?:\+[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)?",
    re.ASCII,
)


class AcceptanceError(ValueError):
    """A bounded candidate-acceptance condition was not met."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def _regular_non_link(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AcceptanceError(f"{label} is unavailable") from error
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
            f"{label} must be a regular non-link file")


def _fresh_child(path: Path, label: str) -> Path:
    require(path.name not in {"", ".", ".."}, f"{label} must name a fresh child directory")
    absolute = Path(os.path.abspath(path))
    require(not os.path.lexists(absolute), f"{label} must be fresh and nonexistent")
    try:
        parent = absolute.parent.lstat()
    except OSError as error:
        raise AcceptanceError(f"{label} parent is unavailable") from error
    require(stat.S_ISDIR(parent.st_mode) and not absolute.parent.is_symlink(),
            f"{label} parent must be an existing non-link directory")
    return absolute


def _bounded_directory_entries(directory: Path, limit: int, label: str) -> list[Path]:
    entries = []
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(entries) == limit:
                    raise AcceptanceError(f"{label} exceeds its bounded entry count")
                entries.append(Path(entry.path))
    except OSError as error:
        raise AcceptanceError(f"{label} is unavailable") from error
    return entries


def _candidate_identity(archive: Path, target: str, archive_ref: str,
                        expected_version: str) -> tuple[str, str]:
    require(target in TARGETS, "target is not one of the four native release targets")
    require(len(expected_version) <= 128 and VERSION.fullmatch(expected_version) is not None,
            "expected version is not a valid package version")
    require(archive_ref == "main" or archive_ref == f"v{expected_version}",
            "archive ref must be main or the exact candidate tag")
    target_contract = TARGETS[target]
    expected_archive = f"termivar-{archive_ref}-{target}{target_contract['suffix']}"
    require(archive.name == expected_archive,
            "archive basename does not match ref and native target")
    return expected_archive, str(target_contract["member"])


def _assert_single_candidate_archive(archive: Path) -> None:
    entries = _bounded_directory_entries(
        archive.parent, MAX_PARENT_ENTRIES, "candidate archive parent")
    candidates = []
    for entry in entries:
        if (entry.name.startswith("termivar-")
                and (entry.name.endswith(".tar.gz") or entry.name.endswith(".zip"))):
            candidates.append(entry)
    require(len(candidates) == 1 and candidates[0].name == archive.name,
            "candidate directory must contain exactly one Termivar archive")


def _assert_native_target(target: str) -> dict:
    contract = TARGETS[target]
    system = platform.system()
    machine = platform.machine().lower()
    require(system == contract["system"] and machine in contract["machines"],
            "candidate target does not match the native execution host")
    return {"system": system, "architecture": machine, "python": platform.python_version()}


def _parse_json(data: bytes, label: str) -> dict:
    try:
        value = json.loads(data)
    except (UnicodeError, ValueError) as error:
        raise AcceptanceError(f"{label} is not one complete JSON document") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _group_counts(document: dict, expected: dict[str, int]) -> dict[str, int]:
    require(document.get("schema") == COMPARISON_SCHEMA,
            "Report Compare schema is unsupported")
    counts = {}
    for group in GROUPS:
        items = document.get(group)
        require(isinstance(items, list), f"Report Compare {group} group is invalid")
        counts[group] = len(items)
    require(counts == expected, "Report Compare group counts changed")
    return counts


def _snapshot_files(directory: Path) -> dict[str, dict[str, int | str]]:
    entries = sorted(
        _bounded_directory_entries(directory, 8, "owned bundle copy"),
        key=lambda entry: entry.name,
    )
    result = {}
    for entry in entries:
        _regular_non_link(entry, "bundle entry")
        data = report_bundle_example.read_regular_file(
            entry,
            (report_bundle_example.MANIFEST_LIMIT if entry.name == "manifest.json"
             else report_bundle_example.REPORT_LIMIT),
            "bundle entry",
        )
        result[entry.name] = {"bytes": len(data), "sha256": first_use.digest_bytes(data)}
    return result


def _safe_command_record(identifier: str, raw: dict, request_delta: dict | None) -> dict:
    result = {
        "id": identifier,
        "exit_code": raw.get("exit_code"),
        "stdout": {key: raw.get("stdout", {}).get(key) for key in ("bytes", "sha256")},
        "stderr": {key: raw.get("stderr", {}).get(key) for key in ("bytes", "sha256")},
    }
    if request_delta is not None:
        result["fixture_requests"] = request_delta
    return result


def _remove_capture(record: dict, work: Path) -> None:
    for stream in ("stdout", "stderr"):
        relative = record.get(stream, {}).get("path")
        if isinstance(relative, str):
            candidate = work / relative
            try:
                candidate.unlink()
            except OSError as error:
                raise AcceptanceError("temporary command capture cleanup failed") from error


class CandidateRunner:
    def __init__(self, binary: Path, work: Path, fixture=None) -> None:
        self.binary = binary
        self.work = work
        self.fixture = fixture
        self.records: list[dict] = []
        self.counter = 0

    def run(self, identifier: str, arguments: list[str], expected_exit: int = 0,
            expected_stderr_empty: bool | None = None) -> tuple[bytes, bytes]:
        self.counter += 1
        raw = {"invocation_id": f"{self.counter:02}-{identifier}"}
        before = self.fixture.server.snapshot() if self.fixture else None
        stdout = stderr = b""
        try:
            stdout, stderr = first_use.run_command(
                [str(self.binary), *arguments], self.work, raw)
        finally:
            after = self.fixture.server.snapshot() if self.fixture else None
            delta = (report_bundle_example.request_delta(before, after)
                     if before is not None and after is not None else None)
            self.records.append(_safe_command_record(identifier, raw, delta))
            _remove_capture(raw, self.work)
        require(raw.get("exit_code") == expected_exit,
                f"{identifier} returned an unexpected process exit")
        if expected_stderr_empty is True:
            require(stderr == b"", f"{identifier} emitted an unexpected diagnostic")
        if expected_stderr_empty is False:
            require(stderr != b"", f"{identifier} did not emit its expected diagnostic")
        return stdout, stderr


def _validate_help(runner: CandidateRunner, expected_version: str) -> dict:
    version, _ = runner.run("version", ["--version"], expected_stderr_empty=True)
    require(version.decode("utf-8").strip() == f"termivar {expected_version}",
            "packaged binary version does not match the caller's expected version")
    top, _ = runner.run("top-help", ["--help"], expected_stderr_empty=True)
    scan, _ = runner.run("scan-help", ["scan", "--help"], expected_stderr_empty=True)
    report, _ = runner.run("report-help", ["report", "--help"], expected_stderr_empty=True)
    top_text = top.decode("utf-8")
    scan_text = scan.decode("utf-8")
    report_text = report.decode("utf-8")
    for command in ("scan", "artifact", "report", "capabilities"):
        require(re.search(rf"(?m)^\s+{re.escape(command)}(?:\s|$)", top_text) is not None,
                f"top-level help omits {command}")
    for command in ("api", "proxy", "legacy-scan"):
        require(re.search(rf"(?m)^\s+{re.escape(command)}(?:\s|$)", top_text) is None,
                f"top-level help unexpectedly exposes {command}")
    require("--report-dir" in scan_text, "scan help omits --report-dir")
    require("--progress" in scan_text, "scan help omits --progress")
    for option in ("--normalization-resilience", "--graphql-review", "--openapi-review",
                   "--rest-review", "--authorization-review-policy"):
        require(option in scan_text, f"scan help omits release-bundle option {option}")
    require("--ssrf-oast-review" not in scan_text,
            "scan help unexpectedly exposes ssrf-oast-review")
    for option in WORDPRESS_OPTIONS:
        require(re.search(rf"(?m)^\s*{re.escape(option)}(?:\s|$)", scan_text) is not None,
                f"scan help omits bundled WordPress option {option}")
    for command in ("compare", "verify"):
        require(re.search(rf"(?m)^\s+{command}(?:\s|$)", report_text) is not None,
                f"report help omits {command}")
    return {"version": f"termivar {expected_version}", "help_surfaces": "matched"}


def _validate_capabilities(runner: CandidateRunner, expected_version: str) -> dict:
    text, _ = runner.run("capabilities-text", ["capabilities"], expected_stderr_empty=True)
    encoded, _ = runner.run(
        "capabilities-json", ["capabilities", "--format", "json"],
        expected_stderr_empty=True)
    document = _parse_json(encoded, "capabilities output")
    require(document.get("schema") == CAPABILITIES_SCHEMA
            and document.get("product") == "Termivar"
            and document.get("package_version") == expected_version
            and document.get("runtime_execution") == "not_performed",
            "capabilities identity or offline state changed")
    features = document.get("cli_package_features")
    require(isinstance(features, list) and len(features) == len(ALL_FEATURES),
            "capabilities feature inventory is incomplete")
    states = {}
    for feature in features:
        require(isinstance(feature, dict)
                and isinstance(feature.get("name"), str)
                and feature.get("build_state") in {"compiled", "not_compiled"}
                and feature["name"] not in states,
                "capabilities feature row is invalid or duplicated")
        states[feature["name"]] = feature["build_state"]
    require(tuple(sorted(states)) == ALL_FEATURES,
            "capabilities feature names changed")
    compiled = tuple(sorted(name for name, state in states.items() if state == "compiled"))
    require(compiled == tuple(sorted(("release-bundle", *RELEASE_MEMBERS))),
            "packaged feature composition does not match release-bundle")
    require(all(states[name] == "not_compiled" for name in EXCLUDED_FEATURES),
            "excluded package feature is compiled")
    limitation = document.get("build_origin_authenticity")
    require(isinstance(limitation, str)
            and "do not establish source authenticity" in limitation,
            "capabilities output overstates build provenance")
    text_value = text.decode("utf-8")
    require(text_value.startswith("Termivar CLI capabilities\n")
            and "runtime_execution: not_performed" in text_value,
            "capabilities text identity changed")
    surfaces = document.get("surfaces")
    require(isinstance(surfaces, list), "capabilities surfaces are unavailable")
    for surface in surfaces:
        require(isinstance(surface, dict), "capabilities surface row is invalid")
        label = surface.get("label")
        state = surface.get("build_state")
        require(isinstance(label, str) and state in {"compiled", "not_compiled"},
                "capabilities surface state is invalid")
        require(f"[{state}] {label}" in text_value,
                "capabilities text and JSON views disagree")
    wordpress_surfaces = [
        surface for surface in surfaces
        if surface.get("key") == "option.wordpress-review"
    ]
    require(len(wordpress_surfaces) == 1,
            "packaged WordPress surface identity changed")
    wordpress = wordpress_surfaces[0]
    require(wordpress.get("compile_feature") == "wordpress-review"
            and wordpress.get("build_state") == "compiled"
            and wordpress.get("maturity") == "preview"
            and wordpress.get("implementation_status") == "implemented"
            and wordpress.get("group") == "optional"
            and wordpress.get("kind") == "scan_option"
            and wordpress.get("alias") is None,
            "packaged WordPress surface metadata changed")
    require(tuple(wordpress.get("prerequisites", ())) == WORDPRESS_PREREQUISITES,
            "packaged WordPress explicit opt-in contract changed")
    limitation = wordpress.get("limitation")
    require(isinstance(limitation, str)
            and "adds no target requests" in limitation
            and "explicitly select" in limitation
            and "stays indeterminate" in limitation,
            "packaged WordPress limitation no longer preserves explicit opt-in semantics")
    discovery_surfaces = [
        surface for surface in surfaces
        if surface.get("key") == "option.wordpress-discovery"
    ]
    require(len(discovery_surfaces) == 1,
            "packaged WordPress discovery surface identity changed")
    discovery = discovery_surfaces[0]
    require(discovery.get("compile_feature") == "wordpress-review"
            and discovery.get("build_state") == "compiled"
            and discovery.get("maturity") == "preview"
            and discovery.get("implementation_status") == "implemented"
            and discovery.get("group") == "optional"
            and discovery.get("kind") == "scan_option"
            and discovery.get("alias") is None,
            "packaged WordPress discovery surface metadata changed")
    require(tuple(discovery.get("prerequisites", ()))
            == WORDPRESS_DISCOVERY_PREREQUISITES,
            "packaged WordPress discovery opt-in contract changed")
    discovery_limitation = discovery.get("limitation")
    require(isinstance(discovery_limitation, str)
            and "at most 12" in discovery_limitation
            and "anonymous same-origin metadata GET requests" in discovery_limitation
            and "never enabled by --wordpress-review alone" in discovery_limitation
            and "Stable tag is not treated as an installed version" in discovery_limitation
            and "no exploit or impact validation" in discovery_limitation,
            "packaged WordPress discovery limitation is incomplete")
    return {
        "schema": document["schema"],
        "runtime_execution": document["runtime_execution"],
        "composition_marker": "release-bundle",
        "compiled_members": list(RELEASE_MEMBERS),
        "excluded_features": list(EXCLUDED_FEATURES),
        "wordpress_preview": {
            "build_state": "compiled",
            "maturity": "preview",
            "implementation_status": "implemented",
            "runtime_activation": "explicit_opt_in",
            "discovery": {
                "build_state": "compiled",
                "runtime_activation": "separate_explicit_opt_in",
                "source_authenticity": "not_established",
            },
        },
        "source_authenticity": "not_established",
    }


def _validate_verification(document: dict, status: str) -> None:
    require(document.get("schema") == VERIFICATION_SCHEMA
            and document.get("status") == status,
            "Report Verify result does not match its expected status")


def _validate_progress(stderr: bytes, forbidden_values: tuple[bytes, ...]) -> dict:
    lines = [
        line for line in stderr.splitlines(keepends=True)
        if line.startswith(PROGRESS_PREFIX)
    ]
    require(lines, "bundle scan emitted no opted-in progress records")
    require(sum(len(line) for line in lines) <= PROGRESS_TOTAL_LIMIT,
            "bundle scan progress exceeded its documented total bound")
    require(all(len(line) <= PROGRESS_LINE_LIMIT and line.isascii()
                and PROGRESS_LINE.fullmatch(line) is not None for line in lines),
            "bundle scan progress record shape or bound changed")
    progress = b"".join(lines)
    require(all(value not in progress for value in forbidden_values),
            "bundle scan progress exposed a private target or output path")
    lowered = progress.lower()
    require(all(token not in lowered for token in
                (b"eta=", b"finding", b"verdict", b"vulnerability")),
            "bundle scan progress introduced an ETA or finding claim")
    states = [
        PROGRESS_LINE.fullmatch(line).group(1).decode("ascii")
        for line in lines
    ]
    lifecycle = (
        "assessment_running", "composing_report", "rendering_report",
        "publishing_report", "completed",
    )
    running_count = 0
    for state in states:
        if state != "assessment_running":
            break
        running_count += 1
    require(running_count > 0
            and states[running_count:] == list(lifecycle[1:])
            and "writing_stdout" not in states,
            "bundle scan progress lifecycle changed")
    return {
        "channel": "stderr",
        "line_count": len(lines),
        "bytes": sum(len(line) for line in lines),
        "states": states,
        "counts_semantics": "last_observed",
        "eta_or_finding_claims": "absent",
    }


WORDPRESS_DOCUMENT = (
    b'<!doctype html><html><head><meta name="generator" content="WordPress 2.4.0-beta1">'
    b'<link rel="stylesheet" href="/wp-content/plugins/synthetic-policy-within/style.css">'
    b'<link rel="stylesheet" href="/wp-content/themes/synthetic-policy-outside/style.css">'
    b'</head><body>bounded synthetic packaged WordPress Preview fixture</body></html>'
)
WORDPRESS_TRACE = (
    "GET / HTTP/1.1",
    "GET / HTTP/1.1",
    "GET / HTTP/1.1",
    "HEAD /wp-content/plugins/synthetic-policy-within/style.css HTTP/1.1",
    "HEAD /wp-content/themes/synthetic-policy-outside/style.css HTTP/1.1",
)
WORDPRESS_DISCOVERY_DOCUMENT = (
    b'<!doctype html><html><head><meta name="generator" content="WordPress 6.9.4">'
    b'<link rel="https://api.w.org/" href="/wp-json/">'
    b'<link rel="stylesheet" href="/wp-content/plugins/synthetic-discovery-plugin/style.css">'
    b'<link rel="stylesheet" href="/wp-content/themes/synthetic-discovery-theme/style.css">'
    b'</head><body>bounded synthetic packaged WordPress discovery fixture</body></html>'
)
WORDPRESS_DISCOVERY_REST_INDEX = b'{"namespaces":["wp/v2","oembed/1.0"]}'
WORDPRESS_DISCOVERY_THEME = (
    b'/*\nTheme Name: Synthetic Discovery Theme\nVersion: 1.5\n'
    b'Requires at least: 6.0\nTested up to: 6.9\n*/\n'
)
WORDPRESS_DISCOVERY_PLUGIN = (
    b'=== Synthetic Discovery Plugin ===\nStable tag: 9.9.9\n'
    b'Requires at least: 6.0\nTested up to: 6.9\n'
)
WORDPRESS_DISCOVERY_SOURCE_BYTES = {
    "rest_index": len(WORDPRESS_DISCOVERY_REST_INDEX),
    "theme_stylesheet": len(WORDPRESS_DISCOVERY_THEME),
    "plugin_readme": len(WORDPRESS_DISCOVERY_PLUGIN),
}
WORDPRESS_DISCOVERY_RESPONSE_BYTES = sum(WORDPRESS_DISCOVERY_SOURCE_BYTES.values())
WORDPRESS_DISCOVERY_TRACE = (
    "GET / HTTP/1.1",
    "GET / HTTP/1.1",
    "GET / HTTP/1.1",
    "GET /wp-json/ HTTP/1.1",
    "GET /wp-content/themes/synthetic-discovery-theme/style.css HTTP/1.1",
    "GET /wp-content/plugins/synthetic-discovery-plugin/readme.txt HTTP/1.1",
    "HEAD /wp-content/plugins/synthetic-discovery-plugin/style.css HTTP/1.1",
    "HEAD /wp-content/themes/synthetic-discovery-theme/style.css HTTP/1.1",
    "HEAD /wp-json/ HTTP/1.1",
)
WORDPRESS_DISCOVERY_POLICY = "termivar.wordpress-metadata-discovery/v1"
WORDPRESS_RESOURCE_POLICY = "termivar.wordfence-v3-bounded-capacity/v1"
WORDPRESS_MAPPING_REVISION = "termivar-wordfence-v3-production/v2"
WORDPRESS_EXPLICIT_POLICY = "termivar.wordfence-v3-explicit-interpretation/v1"
WORDPRESS_IDENTITY_POLICY = (
    "termivar.wordfence-v3-exact-plus-ascii-lowercase-candidate/v1"
)
WORDPRESS_NOTICE = {
    "id": ("wordfence-notice-sha256:"
           "826c6b2cc3601beebdd82831cb757c64e721434a7e6ea7d5f1511ca041858379"),
    "message": "Original synthetic fixture notice; not a provider notice.",
    "party": "termivar_fixture_author",
    "notice": "Synthetic data created for Termivar package acceptance.",
    "license": "This fictional fixture may be copied with its label intact.",
    "license_url": "https://example.invalid/termivar/package-acceptance/terms",
}
WORDPRESS_SEMANTIC_SHA256 = (
    "4694cd26b7f147fc69b9ff9772c71052a5ebb2717b0f2ac8ae592df4dc3a8363"
)
WORDPRESS_ACCOUNTED_RETAINED_BYTES = 9_708


@contextmanager
def _wordpress_fixture():
    """Reuse the repository loopback fixture with fixed WordPress-shaped bytes."""
    expected_paths = {
        b"/",
        b"/wp-content/plugins/synthetic-policy-within/style.css",
        b"/wp-content/themes/synthetic-policy-outside/style.css",
    }

    class WordPressHandler(first_use.StaticHandler):
        def handle(self) -> None:
            self.request.settimeout(1.0)
            request = bytearray()
            try:
                while (b"\r\n\r\n" not in request
                       and len(request) < first_use.HEADER_LIMIT):
                    chunk = self.request.recv(
                        min(1024, first_use.HEADER_LIMIT - len(request)))
                    if not chunk:
                        return
                    request.extend(chunk)
                if b"\r\n\r\n" not in request:
                    self.server.note("invalid")
                    return
                first_line = bytes(request).split(b"\r\n", 1)[0]
                words = first_line.split(b" ")
                if len(words) != 3 or words[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                    self.server.note("invalid")
                    return
                method, path = words[:2]
                with self.server.count_lock:
                    self.server.request_lines.append(
                        first_line.decode("ascii", errors="replace"))
                if method not in (b"GET", b"HEAD"):
                    code, reason, body, category = (
                        405, "Method Not Allowed", first_use.METHOD_REFUSED, "unsupported")
                elif path not in expected_paths:
                    code, reason, body, category = (
                        404, "Not Found", first_use.NOT_FOUND, "unknown")
                else:
                    code, reason, body, category = (
                        200, "OK", WORDPRESS_DOCUMENT, "root")
                self.server.note(category)
                headers = (
                    f"HTTP/1.1 {code} {reason}\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                self.request.sendall(headers + (b"" if method == b"HEAD" else body))
            except (OSError, TimeoutError):
                return

    previous_document = first_use.DOCUMENT
    first_use.DOCUMENT = WORDPRESS_DOCUMENT
    fixture = first_use.Fixture()
    fixture.server.RequestHandlerClass = WordPressHandler
    fixture.server.request_lines = []
    try:
        with fixture:
            yield fixture
    finally:
        first_use.DOCUMENT = previous_document


@contextmanager
def _wordpress_discovery_fixture():
    """Serve distinct, bounded WordPress metadata representations."""
    routes = {
        b"/": ("text/html; charset=utf-8", WORDPRESS_DISCOVERY_DOCUMENT),
        b"/wp-json/": (
            "application/json; charset=utf-8", WORDPRESS_DISCOVERY_REST_INDEX),
        b"/wp-content/themes/synthetic-discovery-theme/style.css": (
            "text/css; charset=utf-8", WORDPRESS_DISCOVERY_THEME),
        b"/wp-content/plugins/synthetic-discovery-plugin/style.css": (
            "text/css; charset=utf-8", b"/* synthetic plugin asset */"),
        b"/wp-content/plugins/synthetic-discovery-plugin/readme.txt": (
            "text/plain; charset=utf-8", WORDPRESS_DISCOVERY_PLUGIN),
    }

    class WordPressDiscoveryHandler(first_use.StaticHandler):
        def handle(self) -> None:
            self.request.settimeout(1.0)
            request = bytearray()
            try:
                while (b"\r\n\r\n" not in request
                       and len(request) < first_use.HEADER_LIMIT):
                    chunk = self.request.recv(
                        min(1024, first_use.HEADER_LIMIT - len(request)))
                    if not chunk:
                        return
                    request.extend(chunk)
                if b"\r\n\r\n" not in request:
                    self.server.note("invalid")
                    return
                first_line = bytes(request).split(b"\r\n", 1)[0]
                words = first_line.split(b" ")
                if len(words) != 3 or words[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                    self.server.note("invalid")
                    return
                method, path = words[:2]
                header_names = {
                    line.split(b":", 1)[0].strip().lower()
                    for line in bytes(request).split(b"\r\n")[1:]
                    if b":" in line
                }
                forbidden_headers = tuple(sorted(
                    name.decode("ascii")
                    for name in header_names
                    if name in {
                        b"authorization", b"cookie", b"proxy-authorization",
                    }
                ))
                with self.server.count_lock:
                    self.server.request_lines.append(
                        first_line.decode("ascii", errors="replace"))
                    if forbidden_headers:
                        self.server.discovery_forbidden_headers.append((
                            first_line.decode("ascii", errors="replace"),
                            forbidden_headers,
                        ))
                if method not in (b"GET", b"HEAD"):
                    code, reason, media_type, body, category = (
                        405, "Method Not Allowed", "text/plain; charset=utf-8",
                        first_use.METHOD_REFUSED, "unsupported")
                elif path not in routes:
                    code, reason, media_type, body, category = (
                        404, "Not Found", "text/plain; charset=utf-8",
                        first_use.NOT_FOUND, "unknown")
                else:
                    media_type, body = routes[path]
                    code, reason, category = 200, "OK", "root"
                self.server.note(category)
                headers = (
                    f"HTTP/1.1 {code} {reason}\r\n"
                    f"Content-Type: {media_type}\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                self.request.sendall(headers + (b"" if method == b"HEAD" else body))
            except (OSError, TimeoutError):
                return

    previous_document = first_use.DOCUMENT
    first_use.DOCUMENT = WORDPRESS_DISCOVERY_DOCUMENT
    fixture = first_use.Fixture()
    fixture.server.RequestHandlerClass = WordPressDiscoveryHandler
    fixture.server.request_lines = []
    fixture.server.discovery_forbidden_headers = []
    try:
        with fixture:
            yield fixture
    finally:
        first_use.DOCUMENT = previous_document


def _write_new_input(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        require(output.write(data) == len(data), "synthetic WordPress input write was incomplete")


def _prepare_wordpress_inputs(work: Path, origin: str) -> dict:
    directory = work / "wordpress-inputs"
    directory.mkdir(mode=0o700)
    plugins = [
        {"name": "synthetic-policy-within", "status": "active", "version": "1.5"},
        {"name": "synthetic-policy-candidate", "status": "active", "version": "1.5"},
        {"name": "synthetic-prerelease-plugin", "status": "active",
         "version": "2.4.0-beta1"},
        {"name": "synthetic-trailing-zero-plugin", "status": "active", "version": "1.0"},
        {"name": "synthetic-vendor-label-plugin", "status": "active",
         "version": "1.0-vendor1"},
    ]
    themes = [
        {"name": "synthetic-policy-outside", "status": "active", "version": "2.1"},
    ]
    context = {
        "schema": "security.wordpress-context/v1",
        "root": origin,
        "hosting_os": "linux",
        "multisite": "disabled",
        "components": [],
    }

    def software(kind: str, slug: str, lower: str, upper: str,
                 *, upper_inclusive: bool = True) -> dict:
        return {
            "type": kind,
            "name": f"[SYNTHETIC] {slug}",
            "slug": slug,
            "affected_versions": {
                f"[{lower}, {upper}{']' if upper_inclusive else ')'}": {
                    "from_version": lower,
                    "from_inclusive": True,
                    "to_version": upper,
                    "to_inclusive": upper_inclusive,
                },
            },
            "patched": False,
            "patched_versions": [],
            "remediation": "Synthetic package-acceptance data; no installed fix is asserted.",
        }

    source_id = "00000000-0000-4000-8000-0000000000b6"
    feed = {
        source_id: {
            "id": source_id,
            "title": "[SYNTHETIC] Packaged WordPress Preview acceptance",
            "software": [
                software("plugin", "synthetic-policy-within", "1.0", "2.0"),
                software("theme", "synthetic-policy-outside", "1.0", "2.0"),
                software("plugin", "synthetic-vendor-label-plugin", "1.0", "2.0"),
                software("core", "wordpress", "2.4.0-beta0", "2.4.0",
                         upper_inclusive=False),
                software("plugin", "SYNTHETIC-POLICY-CANDIDATE", "1.0", "2.0"),
                software("plugin", "https://example.invalid/plugins/opaque_name",
                         "1.0", "2.0"),
            ],
            "informational": False,
            "description": "Original fictional data for bounded packaged acceptance.",
            "references": ["https://example.invalid/termivar/package-acceptance/b6"],
            "cwe": None,
            "cvss": None,
            "cve": None,
            "cve_link": None,
            "researchers": [],
            "published": None,
            "updated": None,
            "copyrights": {
                "message": "Original synthetic fixture notice; not a provider notice.",
                "termivar_fixture_author": {
                    "notice": "Synthetic data created for Termivar package acceptance.",
                    "license": "This fictional fixture may be copied with its label intact.",
                    "license_url": "https://example.invalid/termivar/package-acceptance/terms",
                },
            },
        },
    }
    discovery_catalog = {
        "schema": "security.wordpress-advisory-catalog/v1",
        "catalog": {
            "id": "termivar-synthetic-wordpress-discovery-acceptance",
            "revision": "synthetic-discovery-v1",
            "retrieved_on": "2026-09-10",
        },
        "records": [{
            "id": "SYNTHETIC-DISCOVERED-THEME-0001",
            "component": {"kind": "theme", "slug": "synthetic-discovery-theme"},
            "source": {
                "reference": "https://example.invalid/termivar/discovery/theme-0001",
                "revision": "synthetic-discovery-v1",
                "retrieved_on": "2026-09-10",
                "usage_basis": (
                    "Fictional discovery acceptance data; not a real advisory."
                ),
            },
            "summary": (
                "Synthetic interval used only to prove discovered theme-version evaluation."
            ),
            "affected_ranges": [{
                "lower": {"version": "1.0", "inclusive": True},
                "upper": {"version": "2.0", "inclusive": False},
            }],
            "fixed_versions": ["2.0"],
            "prerequisites": [],
        }],
    }
    values = {
        "plugins": json.dumps(plugins, separators=(",", ":")).encode("ascii") + b"\n",
        "themes": json.dumps(themes, separators=(",", ":")).encode("ascii") + b"\n",
        "core": b"2.4.0-beta1\n",
        "context": json.dumps(context, separators=(",", ":")).encode("ascii") + b"\n",
        "wordfence": json.dumps(feed, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n",
        "discovery_catalog": json.dumps(
            discovery_catalog, separators=(",", ":"), sort_keys=True
        ).encode("ascii") + b"\n",
        "malformed": b'{"synthetic-late-record":',
    }
    paths = {}
    snapshots = {}
    for name, data in values.items():
        suffix = ".txt" if name == "core" else ".json"
        path = directory / f"{name}{suffix}"
        _write_new_input(path, data)
        paths[name] = path
        snapshots[name] = {"bytes": len(data), "sha256": first_use.digest_bytes(data)}
    native_catalog = (Path(__file__).resolve().parents[1]
                      / "docs/examples/wordpress-review/advisories.profiles.synthetic.json")
    _regular_non_link(native_catalog, "native WordPress catalogue fixture")
    paths["native_catalog"] = native_catalog
    snapshots["native_catalog"] = {
        "bytes": native_catalog.stat().st_size,
        "sha256": first_use.digest_file(native_catalog),
    }
    return {"paths": paths, "snapshots": snapshots}


def _read_assessment(bundle_path: Path) -> tuple[dict, dict, str]:
    bundle = report_bundle_example.validate_bundle(bundle_path)
    encoded = report_bundle_example.read_regular_file(
        bundle_path / "assessment.json", report_bundle_example.REPORT_LIMIT,
        "packaged WordPress assessment")
    html = report_bundle_example.read_regular_file(
        bundle_path / "assessment.html", report_bundle_example.REPORT_LIMIT,
        "packaged WordPress HTML")
    try:
        html_text = html.decode("utf-8")
    except UnicodeError as error:
        raise AcceptanceError("packaged WordPress HTML is not UTF-8") from error
    return _parse_json(encoded, "packaged WordPress assessment"), bundle, html_text


def _wordpress_surface_items(assessment: dict) -> int:
    items = assessment.get("items")
    require(isinstance(items, list), "assessment items are unavailable")
    return sum(item.get("category") == "wordpress-surface"
               for item in items if isinstance(item, dict))


def _validate_wordpress_surface_item(assessment: dict) -> None:
    items = assessment.get("items")
    require(isinstance(items, list), "assessment items are unavailable")
    surfaces = [item for item in items if isinstance(item, dict)
                and item.get("category") == "wordpress-surface"]
    require(len(surfaces) == 1, "WordPress surface item cardinality changed")
    item = surfaces[0]
    require(item.get("capability_id") == "technology.wordpress-surface-observed@1"
            and item.get("disposition") == "informational"
            and item.get("claim_basis") == "observation"
            and item.get("case_reference") is None
            and item.get("outcome_reference") is None
            and item.get("verification_stage") is None
            and item.get("control_evidence_references") == []
            and item.get("candidate_evidence_references") == [],
            "WordPress surface item claim or verification boundary changed")


def _validate_native_wordpress(assessment: dict) -> dict:
    audit = assessment.get("wordpress_review")
    require(isinstance(audit, dict)
            and audit.get("schema") == "security.wordpress-review-audit/v3"
            and audit.get("catalog_schema") == "security.wordpress-advisory-catalog/v2"
            and audit.get("catalog_status") == "evaluated"
            and audit.get("additional_request_count") == 0
            and audit.get("item_projected") is True
            and _wordpress_surface_items(assessment) == 1,
            "native WordPress packaged assessment contract changed")
    _validate_wordpress_surface_item(assessment)
    advisories = audit.get("advisories")
    require(isinstance(advisories, list), "native WordPress advisories are unavailable")
    by_id = {row.get("id"): row for row in advisories if isinstance(row, dict)}
    require(len(by_id) == len(advisories) == 5,
            "native WordPress advisory cardinality changed")
    expected = {
        "SYNTHETIC-BETA-NUMERIC-0001": (
            "numeric-dotted/v1", "unsupported", "indeterminate_unsupported"),
        "SYNTHETIC-BETA-PHP-SUBSET-0001": (
            "php-release-subset/v1", "within_declared_range",
            "candidate_match_on_declared_facts"),
        "SYNTHETIC-TRAILING-ZERO-NUMERIC-0001": (
            "numeric-dotted/v1", "within_declared_range",
            "candidate_match_on_declared_facts"),
        "SYNTHETIC-TRAILING-ZERO-PHP-SUBSET-0001": (
            "php-release-subset/v1", "outside_declared_ranges",
            "contradicted_by_declared_facts"),
        "SYNTHETIC-VENDOR-LABEL-UNSUPPORTED-0001": (
            "php-release-subset/v1", "unsupported", "indeterminate_unsupported"),
    }
    for identifier, (profile, relation, applicability) in expected.items():
        row = by_id.get(identifier)
        require(isinstance(row, dict)
                and row.get("comparison_profile") == profile
                and row.get("version_relation") == relation
                and row.get("applicability") == applicability
                and row.get("exploit_execution") == "not_performed"
                and row.get("impact_validation") == "not_performed",
                f"native WordPress result changed for {identifier}")
    return {
        "audit_schema": audit["schema"],
        "surface_items": 1,
        "advisory_count": len(advisories),
        "expected_results": {
            "within": 2, "outside": 1, "indeterminate": 2,
        },
    }


def _external_evaluation(external: dict, slug: str) -> dict:
    rows = external.get("evaluations")
    require(isinstance(rows, list), "external WordPress evaluations are unavailable")
    matches = [row for row in rows if isinstance(row, dict)
               and row.get("key", {}).get("source_component", {}).get("slug") == slug]
    require(len(matches) == 1, f"external WordPress evaluation identity changed for {slug}")
    return matches[0]


def _validate_external_wordpress(assessment: dict, html: str,
                                 input_snapshot: dict, profile: str | None) -> dict:
    audit = assessment.get("wordpress_review")
    require(isinstance(audit, dict)
            and audit.get("schema") == "security.wordpress-review-audit/v6"
            and audit.get("additional_request_count") == 0
            and audit.get("item_projected") is True
            and _wordpress_surface_items(assessment) == 1,
            "external WordPress packaged assessment contract changed")
    _validate_wordpress_surface_item(assessment)
    external = audit.get("external_review")
    require(isinstance(external, dict)
            and external.get("source_namespace") == "wordfence-intelligence"
            and external.get("source_format") == "wordfence-v3-production"
            and external.get("mapping_revision") == WORDPRESS_MAPPING_REVISION
            and external.get("identity_mapping_policy") == WORDPRESS_IDENTITY_POLICY
            and external.get("identity_source_assurance") == "not_established"
            and external.get("resource_policy") == WORDPRESS_RESOURCE_POLICY,
            "external WordPress v6 identity or capacity contract changed")
    source_input = external.get("input")
    require(isinstance(source_input, dict)
            and source_input.get("byte_length") == input_snapshot["bytes"]
            and source_input.get("sha256") == input_snapshot["sha256"]
            and source_input.get("semantic_sha256") == WORDPRESS_SEMANTIC_SHA256
            and source_input.get("accounted_retained_bytes")
            == WORDPRESS_ACCOUNTED_RETAINED_BYTES,
            "external WordPress input provenance changed")
    notices = external.get("notices")
    require(notices == [WORDPRESS_NOTICE],
            "external WordPress synthetic notice was not retained exactly once")
    require(all(WORDPRESS_NOTICE[name] in html for name in (
                "message", "party", "notice", "license", "license_url"))
            and '<script' not in html.casefold()
            and (f'rel="noreferrer noopener" href="{WORDPRESS_NOTICE["license_url"]}"'
                 in html),
            "external WordPress notice was not safely retained in assessment HTML")
    limitations = external.get("identity_limitations")
    require(isinstance(limitations, list) and len(limitations) == 1,
            "external WordPress identity limitation cardinality changed")
    limitation = limitations[0]
    require(isinstance(limitation, dict)
            and limitation.get("key", {}).get("source_component") == {
                "kind": "plugin",
                "slug": "https://example.invalid/plugins/opaque_name",
            }
            and limitation.get("identity_resolution") == "canonical_identity_unavailable"
            and limitation.get("version_relation") == "not_evaluated"
            and limitation.get("version_relation_reason")
            == "canonical_identity_unavailable"
            and limitation.get("applicability") == "indeterminate"
            and limitation.get("execution") == {
                "exploit_execution": "not_performed",
                "impact_validation": "not_performed",
            }, "external WordPress unresolved identity limitation changed")
    counts = external.get("counts")
    require(isinstance(counts, dict), "external WordPress counts are unavailable")
    common_counts = {
        "parsed_records": 1,
        "software_associations": 6,
        "exact_identity_associations": 4,
        "candidate_identity_associations": 1,
        "ambiguous_identity_associations": 0,
        "unresolved_identity_associations": 1,
        "projected_identity_limitations": 1,
        "unprojected_identity_limitations": 0,
        "selected_associations": 5,
        "excluded_associations": 1,
        "mapped_unselected_associations": 0,
    }
    if profile is None:
        expected_counts = {
            **common_counts,
            "evaluable_associations": 0,
            "unsupported_associations": 5,
        }
        require(counts == expected_counts,
                "unresolved external WordPress compact v6 accounting changed")
        require(external.get("comparison_policy")
                == "wordfence-v3/source-semantics-unresolved/v1"
                and "comparison_profile" not in external
                and "policy_selection" not in external
                and "source_semantics_assurance" not in external
                and counts.get("evaluable_associations") == 0
                and counts.get("unsupported_associations") == 5
                and all(row.get("version_relation")
                        == "source_comparison_semantics_unresolved"
                        for row in external.get("evaluations", [])),
                "absent external comparator no longer preserves unresolved results")
        partition = {"within": 0, "outside": 0, "indeterminate": 5}
    else:
        require(profile == "numeric-dotted/v1"
                and external.get("comparison_policy") == WORDPRESS_EXPLICIT_POLICY
                and external.get("comparison_profile") == profile
                and external.get("policy_selection") == "explicit_operator"
                and external.get("source_semantics_assurance") == "not_established",
                "explicit external WordPress policy metadata changed")
        expected_counts = {
            **common_counts,
            "evaluable_associations": 2,
            "unsupported_associations": 3,
            "within_associations": 1,
            "outside_associations": 1,
            "indeterminate_associations": 3,
            "selected_ranges": 5,
            "evaluated_ranges": 2,
            "containing_ranges": 1,
            "noncontaining_ranges": 1,
            "unsupported_ranges": 1,
            "invalid_ranges": 0,
            "not_evaluated_ranges": 2,
            "partial_range_coverage_associations": 0,
        }
        require(counts == expected_counts,
                "explicit external WordPress result partition changed")
        expected_rows = {
            "synthetic-policy-within": (
                "within_supported_range_under_selected_policy",
                "version_match_under_selected_policy"),
            "synthetic-policy-outside": (
                "outside_declared_ranges_under_selected_policy",
                "no_version_match_under_selected_policy"),
            "synthetic-vendor-label-plugin": ("indeterminate", "indeterminate"),
            "wordpress": ("indeterminate", "indeterminate"),
            "SYNTHETIC-POLICY-CANDIDATE": (
                "indeterminate", "indeterminate"),
        }
        for slug, (relation, applicability) in expected_rows.items():
            row = _external_evaluation(external, slug)
            require(row.get("version_relation") == relation
                    and row.get("applicability") == applicability
                    and row.get("execution") == {
                        "exploit_execution": "not_performed",
                        "impact_validation": "not_performed",
                    }, f"explicit external WordPress result changed for {slug}")
            if slug == "SYNTHETIC-POLICY-CANDIDATE":
                require(row.get("identity_mapping") == "ascii_case_fold_candidate"
                        and row.get("version_relation_reason")
                        == "identity_mapping_candidate",
                        "candidate identity was incorrectly promoted to a range conclusion")
        partition = {"within": 1, "outside": 1, "indeterminate": 3}
    return {
        "audit_schema": audit["schema"],
        "surface_items": 1,
        "mapping_revision": external["mapping_revision"],
        "resource_policy": external["resource_policy"],
        "identity_partition": {
            name: counts[name] for name in (
                "exact_identity_associations", "candidate_identity_associations",
                "ambiguous_identity_associations", "unresolved_identity_associations")
        },
        "selected_associations": counts["selected_associations"],
        "result_partition": partition,
        "comparison_policy": external["comparison_policy"],
        "comparison_profile": external.get("comparison_profile"),
        "source_semantics_assurance": external.get("source_semantics_assurance",
                                                    "not_established_by_source"),
        "notice_count": len(notices),
    }


def _wordpress_scan_arguments(fixture, bundle: Path, paths: dict,
                              source: str) -> list[str]:
    arguments = [
        "scan", fixture.origin, "--profile", "web-review", "--wordpress-review",
        "--wordpress-plugins-json", str(paths["plugins"]),
        "--wordpress-themes-json", str(paths["themes"]),
        "--wordpress-core-version-file", str(paths["core"]),
        "--wordpress-advisories",
        str(paths["native_catalog"] if source == "native" else paths["wordfence"]),
    ]
    if source != "native":
        arguments.extend(["--wordpress-advisories-format", "wordfence-v3-production"])
    if source == "numeric":
        arguments.extend([
            "--wordpress-external-version-profile", "numeric-dotted/v1",
        ])
    arguments.extend(["--report-dir", str(bundle)])
    return arguments


def _run_wordpress_scan(runner: CandidateRunner, work: Path, fixture, identifier: str,
                        arguments: list[str], expected_version: str) -> dict:
    before_trace = len(fixture.server.request_lines)
    stdout, _ = runner.run(identifier, arguments, expected_stderr_empty=False)
    require(stdout == b"", f"{identifier} wrote a report document to stdout")
    trace = tuple(fixture.server.request_lines[before_trace:])
    require(trace == WORDPRESS_TRACE,
            f"{identifier} changed the bounded WordPress fixture request trace")
    bundle_path = Path(arguments[arguments.index("--report-dir") + 1])
    assessment, bundle, html = _read_assessment(bundle_path)
    require(bundle.get("producer") == {"product": "Termivar", "version": expected_version},
            f"{identifier} bundle producer identity changed")
    return {
        "bundle": bundle_path,
        "assessment": assessment,
        "html": html,
        "snapshot": _snapshot_files(bundle_path),
        "request_trace": trace,
    }


def _run_wordpress_fixture_acceptance(runner: CandidateRunner, work: Path,
                                      expected_version: str) -> dict:
    fixture = runner.fixture
    require(fixture is not None, "WordPress fixture runner is unavailable")
    require(fixture.server.snapshot() == {
        "root": 1, "example": 0, "unknown": 0,
        "unsupported": 0, "invalid": 0,
    }, "WordPress fixture readiness accounting changed")
    prepared = _prepare_wordpress_inputs(work, fixture.origin)
    paths = prepared["paths"]
    input_snapshots = prepared["snapshots"]

    malformed_bundle = work / "wordpress-malformed-must-not-exist"
    runner.run("wordpress-malformed-preflight", [
        "scan", fixture.origin, "--profile", "web-review", "--wordpress-review",
        "--wordpress-plugins-json", str(paths["plugins"]),
        "--wordpress-advisories", str(paths["malformed"]),
        "--wordpress-advisories-format", "wordfence-v3-production",
        "--wordpress-external-version-profile", "numeric-dotted/v1",
        "--report-dir", str(malformed_bundle),
    ], expected_exit=1, expected_stderr_empty=False)
    require(not malformed_bundle.exists(),
            "malformed WordPress preflight created a report bundle")

    conflict_bundle = work / "wordpress-conflict-must-not-exist"
    runner.run("wordpress-input-conflict", [
        "scan", fixture.origin, "--profile", "web-review", "--wordpress-review",
        "--wordpress-context", str(paths["context"]),
        "--wordpress-plugins-json", str(paths["plugins"]),
        "--report-dir", str(conflict_bundle),
    ], expected_exit=2, expected_stderr_empty=False)
    require(not conflict_bundle.exists(),
            "conflicting WordPress inputs created a report bundle")

    inactive_bundle = work / "wordpress-inactive"
    inactive = _run_wordpress_scan(
        runner, work, fixture, "wordpress-inactive", [
            "scan", fixture.origin, "--profile", "web-review",
            "--report-dir", str(inactive_bundle),
        ], expected_version)
    require("wordpress_review" not in inactive["assessment"]
            and _wordpress_surface_items(inactive["assessment"]) == 0,
            "compiled WordPress Preview activated without runtime opt-in")

    native_bundle = work / "wordpress-native"
    native = _run_wordpress_scan(
        runner, work, fixture, "wordpress-native",
        _wordpress_scan_arguments(fixture, native_bundle, paths, "native"),
        expected_version)
    native_result = _validate_native_wordpress(native["assessment"])

    unresolved_bundle = work / "wordpress-external-unresolved"
    unresolved = _run_wordpress_scan(
        runner, work, fixture, "wordpress-external-unresolved",
        _wordpress_scan_arguments(fixture, unresolved_bundle, paths, "unresolved"),
        expected_version)
    unresolved_result = _validate_external_wordpress(
        unresolved["assessment"], unresolved["html"],
        input_snapshots["wordfence"], None)

    numeric_bundle = work / "wordpress-external-numeric"
    numeric = _run_wordpress_scan(
        runner, work, fixture, "wordpress-external-numeric",
        _wordpress_scan_arguments(fixture, numeric_bundle, paths, "numeric"),
        expected_version)
    numeric_result = _validate_external_wordpress(
        numeric["assessment"], numeric["html"],
        input_snapshots["wordfence"], "numeric-dotted/v1")

    by_id = {record["id"]: record for record in runner.records}
    for identifier in ("wordpress-malformed-preflight", "wordpress-input-conflict"):
        require(sum(by_id[identifier]["fixture_requests"].values()) == 0,
                f"{identifier} contacted the target fixture")
    for identifier in (
            "wordpress-inactive", "wordpress-native",
            "wordpress-external-unresolved", "wordpress-external-numeric"):
        require(by_id[identifier]["fixture_requests"] == {
            "example": 0, "invalid": 0, "root": 5,
            "unknown": 0, "unsupported": 0,
        }, f"{identifier} request accounting changed")

    for name, snapshot in input_snapshots.items():
        path = paths[name]
        require(path.stat().st_size == snapshot["bytes"]
                and first_use.digest_file(path) == snapshot["sha256"],
                f"synthetic WordPress input changed: {name}")

    return {
        "bundles": {
            "inactive": inactive["bundle"],
            "native": native["bundle"],
            "unresolved": unresolved["bundle"],
            "numeric": numeric["bundle"],
        },
        "bundle_snapshots": {
            "inactive": inactive["snapshot"],
            "native": native["snapshot"],
            "unresolved": unresolved["snapshot"],
            "numeric": numeric["snapshot"],
        },
        "item_counts": {
            name: value["assessment"]["item_count"] for name, value in {
                "inactive": inactive, "native": native,
                "unresolved": unresolved, "numeric": numeric,
            }.items()
        },
        "inputs": {"paths": paths, "snapshots": input_snapshots},
        "public": {
            "fixture_kind": "original_synthetic_wordpress_shaped_loopback",
            "request_trace_per_completed_scan": list(WORDPRESS_TRACE),
            "preflight": {
                "malformed": "refused_before_request_without_bundle",
                "conflicting_inputs": "refused_before_request_without_bundle",
            },
            "inactive": {
                "wordpress_audit_present": False,
                "wordpress_surface_items": 0,
                "runtime_activation": "not_selected",
            },
            "native_catalogue": native_result,
            "external_absent_profile": unresolved_result,
            "external_explicit_numeric": numeric_result,
            "source_authenticity": "not_established",
            "security_effectiveness_or_remediation": "not_established",
        },
    }


def _validate_wordpress_discovery(assessment: dict) -> dict:
    discovery = assessment.get("wordpress_discovery")
    require(isinstance(discovery, dict)
            and discovery.get("schema") == "security.wordpress-discovery-audit/v1"
            and discovery.get("capability_id")
            == "technology.wordpress-metadata-discovery@1"
            and discovery.get("policy_id") == WORDPRESS_DISCOVERY_POLICY
            and discovery.get("selected") is True
            and discovery.get("method") == "get"
            and discovery.get("credential_mode") == "anonymous"
            and discovery.get("seed_count") == 3
            and discovery.get("candidate_count") == 3
            and discovery.get("candidate_limit_reached") is False
            and discovery.get("omitted_candidate_count") == 0
            and discovery.get("attempted_request_count") == 3
            and discovery.get("completed_response_count") == 3
            and discovery.get("committed_response_count") == 3
            and discovery.get("response_bytes") == WORDPRESS_DISCOVERY_RESPONSE_BYTES
            and discovery.get("source_count") == 3,
            "packaged WordPress discovery audit identity or accounting changed")
    sources = discovery.get("sources")
    require(isinstance(sources, list) and len(sources) == 3,
            "packaged WordPress discovery source cardinality changed")
    discovery_items = [
        item for item in assessment.get("items", [])
        if isinstance(item, dict)
        and item.get("capability_id")
        == "technology.wordpress-metadata-source-response-observed@1"
    ]
    require(len(discovery_items) == 1,
            "packaged WordPress discovery observation item is missing or duplicated")
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
            and item.get("verification_stage") is None
            and item.get("redacted_summary")
            == "Bounded response evidence from selected public WordPress metadata sources was collected; usable metadata, installation authenticity, vulnerable-code reachability, and advisory impact were not established."
            and item.get("remediation") == {
                "id": "wordpress-metadata-review",
                "summary": "Confirm the installation inventory and source-qualified metadata before making a security or remediation decision.",
            }, "packaged WordPress discovery observation projection changed")
    require(sum(source.get("response_bytes", -1) for source in sources
                if isinstance(source, dict)) == discovery["response_bytes"]
            and all(source.get("evidence_reference_count") == 1
                    and source.get("request_attempted") is True
                    and isinstance(source.get("evidence_references"), list)
                    and len(source["evidence_references"]) == 1
                    for source in sources if isinstance(source, dict))
            and sum(source.get("request_attempted") is True for source in sources
                    if isinstance(source, dict))
            == discovery["attempted_request_count"],
            "packaged WordPress discovery response/evidence accounting changed")
    source_references = [reference for source in sources
                         for reference in source["evidence_references"]]
    require(source_references == item.get("evidence_references")
            and len(set(source_references)) == len(source_references),
            "packaged WordPress discovery source-to-evidence linkage changed")
    by_kind = {source.get("kind"): source for source in sources
               if isinstance(source, dict)}
    require(tuple(sorted(by_kind))
            == ("plugin_readme", "rest_index", "theme_stylesheet"),
            "packaged WordPress discovery source identities changed")
    require(all(by_kind[kind].get("response_bytes") == expected
                for kind, expected in WORDPRESS_DISCOVERY_SOURCE_BYTES.items()),
            "packaged WordPress discovery per-source response accounting changed")
    rest = by_kind["rest_index"]
    theme = by_kind["theme_stylesheet"]
    plugin = by_kind["plugin_readme"]
    require(rest.get("outcome") == "observed"
            and sorted(rest.get("namespaces", [])) == ["oembed/1.0", "wp/v2"],
            "packaged WordPress REST namespace discovery changed")
    require(theme.get("outcome") == "observed"
            and theme.get("component") == {
                "kind": "theme", "slug": "synthetic-discovery-theme",
            }
            and theme.get("theme", {}).get("version") == "1.5",
            "packaged WordPress theme metadata discovery changed")
    require(plugin.get("outcome") == "observed"
            and plugin.get("component") == {
                "kind": "plugin", "slug": "synthetic-discovery-plugin",
            }
            and plugin.get("plugin", {}).get("stable_tag") == "9.9.9",
            "packaged WordPress plugin metadata discovery changed")
    require("version" not in plugin.get("plugin", {}),
            "plugin Stable tag was promoted to an installed version")
    review = assessment.get("wordpress_review")
    require(isinstance(review, dict)
            and review.get("schema") == "security.wordpress-review-audit/v7"
            and review.get("review_basis_schema")
            == "security.wordpress-review-audit/v1"
            and review.get("additional_request_count")
            == discovery["attempted_request_count"],
            "discovery-influenced review schema or request accounting changed")
    theme_components = [
        component for component in review.get("components", [])
        if isinstance(component, dict)
        and component.get("identity") == {
            "kind": "theme", "slug": "synthetic-discovery-theme",
        }
    ]
    require(len(theme_components) == 1
            and "theme_stylesheet_declaration"
            in theme_components[0].get("identity_sources", [])
            and theme_components[0].get("versions") == [{
                "value": "1.5",
                "source": "theme_stylesheet_declaration",
                "confidence": "public_declaration",
            }],
            "discovered theme did not retain the exact source-qualified theme version")
    advisories = review.get("advisories")
    require(isinstance(advisories, list) and len(advisories) == 1,
            "discovered theme advisory projection changed")
    row = advisories[0]
    require(row.get("id") == "SYNTHETIC-DISCOVERED-THEME-0001"
            and row.get("version_relation") == "within_declared_range"
            and row.get("exploit_execution") == "not_performed"
            and row.get("impact_validation") == "not_performed",
            "discovered theme version did not feed the existing evaluator")
    encoded = json.dumps(plugin, sort_keys=True)
    require("9.9.9" in encoded,
            "plugin Stable tag was not retained as a distribution hint")
    return {
        "schema": discovery["schema"],
        "policy_id": discovery["policy_id"],
        "attempted_requests": discovery["attempted_request_count"],
        "committed_responses": discovery["committed_response_count"],
        "response_bytes": discovery["response_bytes"],
        "observed_sources": sorted(by_kind),
        "theme_version_relation": row["version_relation"],
        "plugin_stable_tag_is_installed_version": False,
    }


def _run_wordpress_discovery_acceptance(runner: CandidateRunner, work: Path,
                                        expected_version: str,
                                        state: dict) -> dict:
    fixture = runner.fixture
    require(fixture is not None, "WordPress discovery fixture runner is unavailable")
    require(fixture.server.snapshot() == {
        "root": 1, "example": 0, "unknown": 0,
        "unsupported": 0, "invalid": 0,
    }, "WordPress discovery fixture readiness accounting changed")

    paths = state["inputs"]["paths"]
    missing_review = work / "wordpress-discovery-missing-review-must-not-exist"
    runner.run("wordpress-discovery-missing-review", [
        "scan", fixture.origin, "--profile", "web-review",
        "--wordpress-discovery", "--report-dir", str(missing_review),
    ], expected_exit=2, expected_stderr_empty=False)
    require(not missing_review.exists(),
            "discovery without review reserved an output directory")

    wrong_profile = work / "wordpress-discovery-baseline-must-not-exist"
    runner.run("wordpress-discovery-wrong-profile", [
        "scan", fixture.origin, "--profile", "baseline", "--wordpress-review",
        "--wordpress-discovery", "--report-dir", str(wrong_profile),
    ], expected_exit=2, expected_stderr_empty=False)
    require(not wrong_profile.exists(),
            "baseline discovery selection reserved an output directory")

    bundle_path = work / "wordpress-discovery"
    before_trace = len(fixture.server.request_lines)
    before_forbidden_headers = len(fixture.server.discovery_forbidden_headers)
    stdout, _ = runner.run("wordpress-discovery", [
        "scan", fixture.origin, "--profile", "web-review", "--wordpress-review",
        "--wordpress-discovery", "--wordpress-advisories",
        str(paths["discovery_catalog"]), "--report-dir", str(bundle_path),
    ], expected_stderr_empty=False)
    require(stdout == b"", "WordPress discovery wrote a report document to stdout")
    trace = tuple(fixture.server.request_lines[before_trace:])
    require(trace == WORDPRESS_DISCOVERY_TRACE,
            "WordPress discovery request method/order/count changed")
    require(
        fixture.server.discovery_forbidden_headers[before_forbidden_headers:] == [],
        "WordPress discovery sent a forbidden credential header",
    )
    assessment, bundle, _ = _read_assessment(bundle_path)
    require(bundle.get("producer") == {"product": "Termivar", "version": expected_version},
            "WordPress discovery bundle producer identity changed")
    discovery_result = _validate_wordpress_discovery(assessment)

    by_id = {record["id"]: record for record in runner.records}
    for identifier in (
            "wordpress-discovery-missing-review", "wordpress-discovery-wrong-profile"):
        require(sum(by_id[identifier]["fixture_requests"].values()) == 0,
                f"{identifier} contacted the target fixture")
    require(by_id["wordpress-discovery"]["fixture_requests"] == {
        "example": 0, "invalid": 0, "root": len(WORDPRESS_DISCOVERY_TRACE),
        "unknown": 0, "unsupported": 0,
    }, "WordPress discovery fixture accounting changed")

    state["bundles"]["discovery"] = bundle_path
    state["bundle_snapshots"]["discovery"] = _snapshot_files(bundle_path)
    state["item_counts"]["discovery"] = assessment["item_count"]
    state["public"]["discovery"] = {
        **discovery_result,
        "request_trace": list(trace),
        "forbidden_credential_headers_observed": False,
        "ordinary_review_auto_enabled_discovery": False,
        "source_authenticity": "not_established",
        "security_effectiveness_or_remediation": "not_established",
    }
    return state


def _run_wordpress_offline_acceptance(runner: CandidateRunner, state: dict) -> dict:
    bundles = state["bundles"]
    verifications = {}
    for name, bundle_path in bundles.items():
        stdout, _ = runner.run(f"wordpress-verify-{name}", [
            "report", "verify", "--dir", str(bundle_path), "--format", "json",
        ], expected_stderr_empty=True)
        document = _parse_json(stdout, "packaged WordPress Report Verify output")
        _validate_verification(document, "integrity_match")
        require(_snapshot_files(bundle_path) == state["bundle_snapshots"][name],
                f"Report Verify changed the {name} WordPress bundle")
        verifications[name] = "integrity_match"

    numeric = bundles["numeric"] / "assessment.json"
    stdout, _ = runner.run("wordpress-self-compare", [
        "report", "compare", "--before", str(numeric), "--after", str(numeric),
        "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    self_compare = _parse_json(stdout, "packaged WordPress self comparison")
    self_counts = _group_counts(self_compare, {
        "only_in_after": 0, "only_in_before": 0, "changed": 0,
        "unchanged": state["item_counts"]["numeric"],
    })
    wordpress_self = self_compare.get("wordpress_review_comparison")
    require(isinstance(wordpress_self, dict)
            and wordpress_self.get("status") == "compared"
            and wordpress_self.get("methodology", {}).get("status") == "unchanged"
            and not wordpress_self.get("advisories", {}).get("paired_changed")
            and not wordpress_self.get("advisories", {}).get("only_in_before")
            and not wordpress_self.get("advisories", {}).get("only_in_after"),
            "WordPress self comparison changed")

    discovery = bundles["discovery"] / "assessment.json"
    stdout, _ = runner.run("wordpress-discovery-self-compare", [
        "report", "compare", "--before", str(discovery), "--after", str(discovery),
        "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    discovery_self = _parse_json(stdout, "packaged WordPress discovery self comparison")
    discovery_self_counts = _group_counts(discovery_self, {
        "only_in_after": 0, "only_in_before": 0, "changed": 0,
        "unchanged": state["item_counts"]["discovery"],
    })

    unresolved = bundles["unresolved"] / "assessment.json"
    stdout, _ = runner.run("wordpress-methodology-compare", [
        "report", "compare", "--before", str(unresolved), "--after", str(numeric),
        "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    controlled = _parse_json(stdout, "packaged WordPress methodology comparison")
    controlled_counts = _group_counts(controlled, {
        "only_in_after": 0, "only_in_before": 0, "changed": 0,
        "unchanged": state["item_counts"]["numeric"],
    })
    wordpress_controlled = controlled.get("wordpress_review_comparison")
    methodology = (wordpress_controlled.get("methodology", {})
                   if isinstance(wordpress_controlled, dict) else {})
    changed_fields = methodology.get("changed_fields")
    advisories = (wordpress_controlled.get("advisories", {})
                  if isinstance(wordpress_controlled, dict) else {})
    require(isinstance(wordpress_controlled, dict)
            and wordpress_controlled.get("status") == "compared"
            and methodology.get("status") == "changed"
            and isinstance(changed_fields, list)
            and "comparison_policy" in changed_fields
            and "comparison_profile" in changed_fields
            and len(advisories.get("paired_changed", [])) == 5
            and not advisories.get("only_in_before")
            and not advisories.get("only_in_after"),
            "controlled WordPress methodology comparison changed")

    for name, bundle_path in bundles.items():
        require(_snapshot_files(bundle_path) == state["bundle_snapshots"][name],
                f"offline comparison changed the {name} WordPress bundle")
    paths = state["inputs"]["paths"]
    snapshots = state["inputs"]["snapshots"]
    for name, snapshot in snapshots.items():
        path = paths[name]
        require(path.stat().st_size == snapshot["bytes"]
                and first_use.digest_file(path) == snapshot["sha256"],
                f"offline commands changed synthetic WordPress input: {name}")

    public = state["public"]
    public["bundle_verification"] = verifications
    public["self_comparison"] = {
        "groups": self_counts,
        "methodology": "unchanged",
        "advisory_differences": 0,
    }
    public["discovery_self_comparison"] = {
        "groups": discovery_self_counts,
        "input_mutation": False,
    }
    public["controlled_comparison"] = {
        "groups": controlled_counts,
        "methodology": "changed",
        "changed_fields_include": ["comparison_policy", "comparison_profile"],
        "paired_advisory_differences": 5,
    }
    public["offline_commands_after_fixture_shutdown"] = True
    public["inputs_preserved"] = True
    return public


def _run_fixture_acceptance(
        runner: CandidateRunner, work: Path, expected_version: str) -> dict:
    fixture = runner.fixture
    require(fixture is not None, "fixture runner is unavailable")
    readiness = fixture.server.snapshot()
    require(readiness == {
        "root": 1, "example": 0, "unknown": 0,
        "unsupported": 0, "invalid": 0,
    }, "fixture readiness accounting changed")

    existing = work / "existing-bundle"
    existing.mkdir(mode=0o700)
    marker = existing / "foreign-marker"
    marker.write_bytes(b"preserve")
    runner.run("existing-destination", [
        "scan", fixture.origin, "--profile", "web-review", "--report-dir", str(existing),
    ], expected_exit=1, expected_stderr_empty=False)
    require(marker.read_bytes() == b"preserve" and len(list(existing.iterdir())) == 1,
            "existing-destination refusal changed foreign bytes")

    preflight = work / "preflight-must-not-exist"
    runner.run("preflight-conflict", [
        "scan", fixture.origin, "--profile", "baseline", "--report-dir", str(preflight),
    ], expected_exit=2, expected_stderr_empty=False)
    require(not preflight.exists(), "preflight refusal created a bundle directory")

    bundle_path = work / "assessment-bundle"
    stdout, progress_stderr = runner.run("bundle-scan", [
        "scan", fixture.origin, "--profile", "web-review", "--progress",
        "--report-dir", str(bundle_path),
    ], expected_stderr_empty=False)
    require(stdout == b"", "successful bundle scan wrote a report to stdout")
    progress = _validate_progress(
        progress_stderr,
        (fixture.origin.encode("utf-8"), str(bundle_path).encode("utf-8")),
    )
    bundle = report_bundle_example.validate_bundle(bundle_path)
    require(bundle["producer"] == {"product": "Termivar", "version": expected_version},
            "bundle producer identity changed")
    bundle_snapshot = _snapshot_files(bundle_path)

    runner.run("bundle-no-overwrite", [
        "scan", fixture.origin, "--profile", "web-review", "--report-dir", str(bundle_path),
    ], expected_exit=1, expected_stderr_empty=False)
    require(_snapshot_files(bundle_path) == bundle_snapshot,
            "no-overwrite refusal changed completed bundle bytes")

    verify_stdout, _ = runner.run("bundle-verify", [
        "report", "verify", "--dir", str(bundle_path), "--format", "json",
    ], expected_stderr_empty=True)
    verification = _parse_json(verify_stdout, "Report Verify output")
    _validate_verification(verification, "integrity_match")
    require(_snapshot_files(bundle_path) == bundle_snapshot,
            "Report Verify changed completed bundle bytes")

    comparison_stdout, _ = runner.run("bundle-self-compare", [
        "report", "compare", "--before", str(bundle_path / "assessment.json"),
        "--after", str(bundle_path / "assessment.json"), "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    self_comparison = report_bundle_example.validate_self_comparison(
        comparison_stdout, bundle["assessment"]["item_count"],
        bundle["assessment_json_sha256"])
    require(_snapshot_files(bundle_path) == bundle_snapshot,
            "Report Compare changed completed bundle bytes")

    before_fixture = Path(__file__).resolve().parents[1] / "docs/examples/report-compare/before.json"
    after_fixture = Path(__file__).resolve().parents[1] / "docs/examples/report-compare/after.json"
    _regular_non_link(before_fixture, "synthetic before fixture")
    _regular_non_link(after_fixture, "synthetic after fixture")
    synthetic_before_hash = first_use.digest_file(before_fixture)
    synthetic_after_hash = first_use.digest_file(after_fixture)
    synthetic_stdout, _ = runner.run("synthetic-compare", [
        "report", "compare", "--before", str(before_fixture), "--after", str(after_fixture),
        "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    synthetic = _parse_json(synthetic_stdout, "synthetic Report Compare output")
    synthetic_counts = _group_counts(synthetic, SYNTHETIC_COUNTS)
    require(synthetic["changed"][0].get("changed_fields") == ["redacted_summary"],
            "synthetic comparison changed-field contract changed")
    require(first_use.digest_file(before_fixture) == synthetic_before_hash
            and first_use.digest_file(after_fixture) == synthetic_after_hash,
            "synthetic Report Compare changed an input")

    modified = work / "modified-bundle"
    shutil.copytree(bundle_path, modified)
    modified_html = modified / "assessment.html"
    html = modified_html.read_bytes()
    require(len(html) > 1, "generated HTML is unexpectedly empty")
    changed = bytearray(html)
    changed[1] = ord("?") if changed[1] != ord("?") else ord("!")
    modified_html.write_bytes(changed)
    modified_snapshot = _snapshot_files(modified)
    mismatch_stdout, _ = runner.run("modified-bundle-verify", [
        "report", "verify", "--dir", str(modified), "--format", "json",
    ], expected_exit=1, expected_stderr_empty=True)
    mismatch = _parse_json(mismatch_stdout, "mismatched Report Verify output")
    _validate_verification(mismatch, "not_verified")
    reasons = mismatch.get("reason_codes")
    require(isinstance(reasons, list) and "payload_digest_mismatch" in reasons
            and "payload_length_mismatch" not in reasons,
            "same-length payload mutation was not classified as a digest mismatch")
    require(_snapshot_files(modified) == modified_snapshot,
            "Report Verify changed the mismatched bundle")

    incomplete = work / "incomplete-must-not-exist"
    incomplete_stdout, _ = runner.run("begun-incomplete", [
        "scan", f"{fixture.origin}example", "--profile", "web-review", "--format", "json",
        "--report-dir", str(incomplete),
    ], expected_exit=1)
    incomplete_document = _parse_json(incomplete_stdout, "incomplete scan diagnostic")
    require(incomplete_document.get("schema_version") == "web-assessment/v2"
            and incomplete_document.get("disposition") == "incomplete",
            "begun assessment did not retain the incomplete diagnostic contract")
    require(not incomplete.exists(), "incomplete assessment left a completed bundle directory")

    by_id = {record["id"]: record for record in runner.records}
    zero_request_commands = (
        "capabilities-text", "capabilities-json",
        "existing-destination", "preflight-conflict", "bundle-no-overwrite",
        "bundle-verify", "bundle-self-compare", "synthetic-compare",
        "modified-bundle-verify",
    )
    require(all(sum(by_id[name]["fixture_requests"].values()) == 0
                for name in zero_request_commands),
            "offline or preflight acceptance command contacted the fixture")
    require(by_id["bundle-scan"]["fixture_requests"] == {
        "example": 0, "invalid": 0, "root": 3,
        "unknown": 0, "unsupported": 0,
    }, "bundle scan request trace changed")
    require(by_id["begun-incomplete"]["fixture_requests"] == {
        "example": 3, "invalid": 0, "root": 0,
        "unknown": 0, "unsupported": 0,
    },
            "begun-incomplete scan request trace changed")

    return {
        "readiness_requests": readiness,
        "bundle_scan_requests": by_id["bundle-scan"]["fixture_requests"],
        "begun_incomplete_requests": by_id["begun-incomplete"]["fixture_requests"],
        "offline_and_preflight_requests": {
            name: by_id[name]["fixture_requests"] for name in zero_request_commands
        },
        "bundle": {
            "assessment": bundle["assessment"],
            "files": bundle["files"],
        },
        "live_progress": progress,
        "verification": {
            "status": verification["status"],
            "mismatch_status": mismatch["status"],
            "mismatch_reason": "payload_digest_mismatch",
        },
        "self_comparison": self_comparison,
        "synthetic_comparison": {
            "fixture_kind": "synthetic_document_processing_not_assessment_evidence",
            "counts": synthetic_counts,
            "changed_fields": ["redacted_summary"],
            "before_sha256": synthetic_before_hash,
            "after_sha256": synthetic_after_hash,
        },
        "no_overwrite": "preserved",
        "preflight": "refused_before_request",
        "incomplete": "began_then_withheld_bundle",
    }


def _encode_evidence(result: dict) -> bytes:
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    require(len(encoded) <= EVIDENCE_LIMIT, "candidate acceptance evidence exceeds its byte limit")
    return encoded


def _write_evidence(directory: Path, result: dict) -> None:
    encoded = _encode_evidence(result)
    destination = directory / EVIDENCE_NAME
    with destination.open("xb") as output:
        require(output.write(encoded) == len(encoded), "candidate evidence write was incomplete")
        output.flush()
        os.fsync(output.fileno())


def _remove_owned_work(work: Path) -> None:
    try:
        captures = work / "captures"
        if captures.exists():
            captures.rmdir()
        for child in sorted(work.iterdir(), key=lambda path: len(path.parts), reverse=True):
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        work.rmdir()
    except OSError as error:
        raise AcceptanceError("temporary acceptance workspace cleanup failed") from error


def run_acceptance(archive: Path, target: str, archive_ref: str, source_sha: str,
                   run_id: str, run_attempt: str, extract_to: Path,
                   evidence_dir: Path, expected_version: str,
                   inspect: Callable[..., dict] = verify_release_archive.inspect_archive) -> dict:
    require(sys.version_info >= (3, 12, 4), "Python 3.12.4 or newer is required")
    require(not any(value for name, value in os.environ.items()
                    if name.lower() in {"http_proxy", "https_proxy", "all_proxy"}),
            "proxy configuration is present; acceptance will not change proxy policy")
    require(HEX_SHA.fullmatch(source_sha) is not None,
            "source SHA must be one lowercase full commit identity")
    require(POSITIVE_INTEGER.fullmatch(run_id) is not None
            and POSITIVE_INTEGER.fullmatch(run_attempt) is not None,
            "workflow run identity must contain positive decimal integers")
    archive = Path(os.path.abspath(archive))
    _regular_non_link(archive, "candidate archive")
    expected_archive, expected_member = _candidate_identity(
        archive, target, archive_ref, expected_version)
    _assert_single_candidate_archive(archive)
    native_host = _assert_native_target(target)
    extract_to = _fresh_child(extract_to, "extraction directory")
    evidence_dir = _fresh_child(evidence_dir, "evidence directory")
    require(extract_to != evidence_dir
            and extract_to not in evidence_dir.parents
            and evidence_dir not in extract_to.parents,
            "extraction and evidence destinations must not overlap")

    evidence_dir.mkdir(mode=0o700)
    work = evidence_dir / "work"
    work.mkdir(mode=0o700)
    (work / "captures").mkdir(mode=0o700)
    result = {
        "schema": SCHEMA,
        "status": "running",
        "candidate": {
            "target": target,
            "archive_ref": archive_ref,
            "source_sha": source_sha,
            "source_identity_basis": "workflow_context_declaration",
            "workflow_run": {"id": run_id, "attempt": run_attempt},
        },
        "host": native_host,
        "limits": {
            "archive_bytes": verify_release_archive.MAX_ARCHIVE_BYTES,
            "binary_bytes": verify_release_archive.MAX_BINARY_BYTES,
            "command_seconds": first_use.COMMAND_TIMEOUT,
            "capture_bytes_per_stream": first_use.CAPTURE_LIMIT,
            "evidence_bytes": EVIDENCE_LIMIT,
        },
        "claims": {
            "native_packaged_binary_executed": False,
            "native_packaged_binary_execution_attempted": False,
            "candidate_hashes_are_published_checksums": False,
            "candidate_hashes_or_capabilities_authenticate_source": False,
            "tag_bound_attestation_performed": False,
            "release_published": False,
            "fixture_is_a_security_effectiveness_test": False,
        },
        "commands": [],
    }
    failure: str | None = None
    interrupted = False
    try:
        archive_result = inspect(
            archive, expected_archive, expected_member, extract_to=extract_to)
        binary = extract_to / expected_member
        _regular_non_link(binary, "extracted packaged binary")
        require(first_use.digest_file(binary) == archive_result["member_sha256"],
                "extracted binary digest does not match inspected archive member")
        runner = CandidateRunner(binary, work)
        result["commands"] = runner.records
        result["claims"]["native_packaged_binary_execution_attempted"] = True
        result["interfaces"] = _validate_help(runner, expected_version)
        with first_use.Fixture() as fixture:
            runner.fixture = fixture
            result["capabilities"] = _validate_capabilities(runner, expected_version)
            result["application"] = _run_fixture_acceptance(
                runner, work, expected_version)
        with _wordpress_fixture() as fixture:
            runner.fixture = fixture
            wordpress_state = _run_wordpress_fixture_acceptance(
                runner, work, expected_version)
        with _wordpress_discovery_fixture() as fixture:
            runner.fixture = fixture
            wordpress_state = _run_wordpress_discovery_acceptance(
                runner, work, expected_version, wordpress_state)
        runner.fixture = None
        result["application"]["wordpress_preview"] = (
            _run_wordpress_offline_acceptance(runner, wordpress_state))
        require(first_use.digest_file(binary) == archive_result["member_sha256"],
                "packaged binary changed during candidate acceptance")
        require(first_use.digest_file(archive) == archive_result["archive_sha256"],
                "candidate archive changed during candidate acceptance")
        result["archive"] = archive_result
        result["claims"]["native_packaged_binary_executed"] = True
        result["status"] = "passed"
    except KeyboardInterrupt:
        interrupted = True
        failure = "candidate acceptance was interrupted"
        result["status"] = "cancelled"
    except (AcceptanceError, first_use.AcceptanceError,
            verify_release_archive.VerificationError) as error:
        failure = str(error)
        result["status"] = "failed"
    except (OSError, UnicodeError, KeyError, TypeError, ValueError):
        failure = "local candidate execution or bounded validation failed"
        result["status"] = "failed"
    try:
        _remove_owned_work(work)
    except AcceptanceError:
        result["status"] = "failed"
        failure = "temporary acceptance workspace cleanup failed"
    if failure is not None:
        result["failure"] = failure
    _write_evidence(evidence_dir, result)
    require(not interrupted or result["status"] == "cancelled",
            "interrupted acceptance status changed")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=tuple(TARGETS))
    parser.add_argument("--archive-ref", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--extract-to", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--expect-version", required=True)
    args = parser.parse_args(argv)
    try:
        result = run_acceptance(
            args.archive, args.target, args.archive_ref, args.source_sha,
            args.run_id, args.run_attempt, args.extract_to,
            args.evidence_dir, args.expect_version,
        )
        encoded = _encode_evidence(result)
        require(sys.stdout.buffer.write(encoded) == len(encoded),
                "candidate acceptance result could not be written completely")
        sys.stdout.buffer.flush()
    except (AcceptanceError, first_use.AcceptanceError,
            verify_release_archive.VerificationError) as error:
        print(f"release-candidate acceptance refused: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("release-candidate acceptance failed: local input or output unavailable",
              file=sys.stderr)
        return 1
    return 0 if result["status"] == "passed" else 130 if result["status"] == "cancelled" else 1


if __name__ == "__main__":
    raise SystemExit(main())
