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
import hashlib
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
    "--wordpress-page-scope",
    "--wordpress-layout",
    "--wordpress-context",
    "--wordpress-advisories",
    "--wordpress-plugins-json",
    "--wordpress-themes-json",
    "--wordpress-core-version-file",
    "--wordpress-advisories-format",
    "--wordpress-external-version-profile",
    "--wordpress-fingerprints",
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
    "optional --wordpress-page-scope observed",
    "optional --wordpress-layout FILE",
    "optional --wordpress-fingerprints FILE",
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


def _require_exact_keys(document: object, required: tuple[str, ...],
                        optional: tuple[str, ...], label: str) -> dict:
    require(isinstance(document, dict), f"{label} is not an object")
    observed = set(document)
    required_set = set(required)
    optional_set = set(optional)
    require(required_set <= observed and observed <= required_set | optional_set,
            f"{label} fields changed")
    return document


def _is_opaque_wordpress_reference(value: object) -> bool:
    return (isinstance(value, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value, re.ASCII) is not None)


def _same_unique_string_members(left: object, right: object) -> bool:
    """Compare exact string membership without imposing serialization order."""
    if not isinstance(left, list) or not isinstance(right, list):
        return False
    if not all(isinstance(value, str) for value in left + right):
        return False
    left_members = set(left)
    right_members = set(right)
    return (
        len(left_members) == len(left)
        and len(right_members) == len(right)
        and left_members == right_members
    )


def _framed_wordpress_reference(domain: str, value: str) -> str:
    """Independent literal oracle for the documented opaque URL framing."""
    digest = hashlib.sha256()
    for part in (domain.encode("ascii"), value.encode("ascii")):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return "sha256:" + digest.hexdigest()


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
            and "Without --wordpress-page-scope it remains entry-only" in discovery_limitation
            and "observed reuses eligible committed page responses without retrieving pages"
                in discovery_limitation
            and "same 12-request WordPress-owned limit" in discovery_limitation
            and "Stable tag is not treated as an installed version" in discovery_limitation
            and "exact complete bytes" in discovery_limitation
            and "finite listed release set" in discovery_limitation
            and "cannot nominate unseen resources" in discovery_limitation
            and "URL ver remain hints" in discovery_limitation
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
WORDPRESS_BLOG_DOCUMENT = (
    b'<!doctype html><html><head><meta name="generator" content="WordPress 6.9.4">'
    b'<link rel="https://api.w.org/" href="/blog/wp-json/">'
    b'<link rel="stylesheet" href="/blog/wp-content/themes/'
    b'synthetic-discovery-theme/assets/site.css">'
    b'<script src="/blog/wp-content/plugins/synthetic-discovery-plugin/'
    b'assets/app.js"></script>'
    b'<img src="/blog/wp-includes/images/blank.gif">'
    b'<script src="/shop/wp-content/plugins/sibling-decoy/assets/app.js"></script>'
    b'</head><body>bounded conventional blog layout fixture</body></html>'
)
WORDPRESS_CUSTOM_DOCUMENT = (
    b'<!doctype html><html><head><meta name="generator" content="WordPress 6.9.4">'
    b'<link rel="https://api.w.org/" href="/cms/wp-json/">'
    b'<link rel="stylesheet" href="/site-content/themes/'
    b'synthetic-discovery-theme/assets/site.css">'
    b'<script src="/modules/synthetic-discovery-plugin/assets/app.js"></script>'
    b'<img src="/cms/wp-includes/images/blank.gif">'
    b'<script src="/shop/wp-content/plugins/sibling-decoy/assets/app.js"></script>'
    b'</head><body>bounded declared custom layout fixture</body></html>'
)
WORDPRESS_LAYOUT_THEME = (
    b'/*\nTheme Name: Synthetic Discovery Theme\nVersion: 1.5\n'
    b'Template: synthetic-discovery-parent\nRequires at least: 6.0\n'
    b'Tested up to: 6.9\n*/\n'
)
WORDPRESS_LAYOUT_PARENT_THEME = (
    b'/*\nTheme Name: Synthetic Discovery Parent\nVersion: 2.0\n*/\n'
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
WORDPRESS_BLOG_TRACE = (
    "GET /blog/ HTTP/1.1",
    "GET /blog/ HTTP/1.1",
    "GET /blog/ HTTP/1.1",
    "GET /blog/wp-json/ HTTP/1.1",
    "GET /blog/wp-content/themes/synthetic-discovery-theme/style.css HTTP/1.1",
    "GET /blog/wp-content/themes/synthetic-discovery-parent/style.css HTTP/1.1",
    "GET /blog/wp-content/plugins/synthetic-discovery-plugin/readme.txt HTTP/1.1",
    "HEAD /blog/wp-content/themes/synthetic-discovery-theme/assets/site.css HTTP/1.1",
    "HEAD /blog/wp-json/ HTTP/1.1",
)
WORDPRESS_CUSTOM_TRACE = (
    "GET /blog/ HTTP/1.1",
    "GET /blog/ HTTP/1.1",
    "GET /blog/ HTTP/1.1",
    "GET /cms/wp-json/ HTTP/1.1",
    "GET /site-content/themes/synthetic-discovery-theme/style.css HTTP/1.1",
    "GET /site-content/themes/synthetic-discovery-parent/style.css HTTP/1.1",
    "GET /modules/synthetic-discovery-plugin/readme.txt HTTP/1.1",
    "HEAD /cms/wp-json/ HTTP/1.1",
    "HEAD /site-content/themes/synthetic-discovery-theme/assets/site.css HTTP/1.1",
)
WORDPRESS_LAYOUT_SOURCE_BYTES = {
    "rest_index": len(WORDPRESS_DISCOVERY_REST_INDEX),
    "theme_stylesheet": len(WORDPRESS_LAYOUT_THEME),
    "parent_theme_stylesheet": len(WORDPRESS_LAYOUT_PARENT_THEME),
    "plugin_readme": len(WORDPRESS_DISCOVERY_PLUGIN),
}
WORDPRESS_LAYOUT_RESPONSE_BYTES = sum(WORDPRESS_LAYOUT_SOURCE_BYTES.values())
WORDPRESS_DISCOVERY_POLICY = "termivar.wordpress-deployment-aware-metadata-discovery/v1"
WORDPRESS_DISCOVERY_AUDIT_SCHEMA = "security.wordpress-discovery-audit/v2"
WORDPRESS_LAYOUT_SCHEMA = "security.wordpress-layout/v1"
WORDPRESS_NONROOT_DISCOVERY_DIAGNOSTIC = (
    b"a non-root WordPress application target requires explicit `--wordpress-discovery`"
)
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
WORDPRESS_FINGERPRINT_CATALOG_SCHEMA = (
    "security.wordpress-asset-fingerprint-catalog/v1"
)
WORDPRESS_FINGERPRINT_AUDIT_SCHEMA = (
    "security.wordpress-asset-fingerprint-audit/v1"
)
WORDPRESS_FINGERPRINT_POLICY = "termivar.wordpress-observed-asset-fingerprint/v1"
WORDPRESS_FINGERPRINT_REPRESENTATION = "identity-content-bytes/v1"
WORDPRESS_FINGERPRINT_COMPONENT = "termivar-fingerprint-lab"
# Literal, original package-acceptance bytes.  The catalogue below is built by
# this helper with hashlib, independently of the packaged matcher.
WORDPRESS_FINGERPRINT_JS_AB = b'window.termivarFingerprintLab={channel:"amber"};\n'
WORDPRESS_FINGERPRINT_JS_C = b'window.termivarFingerprintLab={channel:"cobalt"};\n'
WORDPRESS_FINGERPRINT_CSS_A = b".termivar-fingerprint{color:#13579b}\n"
WORDPRESS_FINGERPRINT_CSS_BC = b".termivar-fingerprint{color:#2468ac}\n"
WORDPRESS_FINGERPRINT_COMMON = b".termivar-common{display:block}\n"
WORDPRESS_FINGERPRINT_ROOT = (
    b"<!doctype html><html><head>"
    b'<link rel="stylesheet" href="/wp-content/themes/fingerprint-base/assets/site.css">'
    b"</head><body>"
    b'<a href="/contact/">contact</a><a href="/gallery/">gallery</a>'
    b"</body></html>"
)
WORDPRESS_FINGERPRINT_PAGE = (
    b"<!doctype html><html><head>"
    b'<script src="/wp-content/plugins/termivar-fingerprint-lab/assets/'
    b'fingerprint.js?ver=release-c"></script>'
    b'<link rel="stylesheet" href="/wp-content/plugins/termivar-fingerprint-lab/'
    b'assets/fingerprint.css?ver=release-a">'
    b"</head><body>bounded packaged secondary page</body></html>"
)
WORDPRESS_FINGERPRINT_CUSTOM_ROOT = (
    b'<!doctype html><html><head><meta name="generator" content="WordPress 6.9.4">'
    b'<link rel="https://api.w.org/" href="/cms/wp-json/">'
    b'<script src="/modules/synthetic-discovery-plugin/assets/app.js"></script>'
    b'</head><body><a href="/blog/contact/">contact</a>'
    b'<a href="/blog/gallery/">gallery</a></body></html>'
)
WORDPRESS_FINGERPRINT_CUSTOM_PAGE = (
    b"<!doctype html><html><head>"
    b'<link rel="stylesheet" href="/site-content/themes/'
    b'synthetic-discovery-theme/assets/site.css">'
    b'<script src="/modules/termivar-fingerprint-lab/assets/'
    b'fingerprint.js?ver=release-c"></script>'
    b'<link rel="stylesheet" href="/modules/termivar-fingerprint-lab/'
    b'assets/fingerprint.css?ver=release-a">'
    b"</head><body>bounded packaged custom-layout secondary page</body></html>"
)
WORDPRESS_FINGERPRINT_PLUGIN = (
    b"=== Termivar Fingerprint Lab ===\nStable tag: 9.9.9\n"
)
WORDPRESS_FINGERPRINT_ASSET_PATHS = (
    "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.js?ver=release-c",
    "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.css?ver=release-a",
)
WORDPRESS_FINGERPRINT_CUSTOM_ASSET_PATHS = (
    "/modules/termivar-fingerprint-lab/assets/fingerprint.js?ver=release-c",
    "/modules/termivar-fingerprint-lab/assets/fingerprint.css?ver=release-a",
)


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
        b"/blog/wp-json/": (
            "application/json; charset=utf-8", WORDPRESS_DISCOVERY_REST_INDEX),
        b"/blog/wp-content/themes/synthetic-discovery-theme/assets/site.css": (
            "text/css; charset=utf-8", b"/* conventional theme asset */"),
        b"/blog/wp-content/themes/synthetic-discovery-theme/style.css": (
            "text/css; charset=utf-8", WORDPRESS_LAYOUT_THEME),
        b"/blog/wp-content/themes/synthetic-discovery-parent/style.css": (
            "text/css; charset=utf-8", WORDPRESS_LAYOUT_PARENT_THEME),
        b"/blog/wp-content/plugins/synthetic-discovery-plugin/assets/app.js": (
            "application/javascript", b"/* conventional plugin asset */"),
        b"/blog/wp-content/plugins/synthetic-discovery-plugin/readme.txt": (
            "text/plain; charset=utf-8", WORDPRESS_DISCOVERY_PLUGIN),
        b"/blog/wp-includes/images/blank.gif": (
            "image/gif", b"GIF89a"),
        b"/cms/wp-json/": (
            "application/json; charset=utf-8", WORDPRESS_DISCOVERY_REST_INDEX),
        b"/cms/wp-includes/images/blank.gif": ("image/gif", b"GIF89a"),
        b"/site-content/themes/synthetic-discovery-theme/assets/site.css": (
            "text/css; charset=utf-8", b"/* declared theme asset */"),
        b"/site-content/themes/synthetic-discovery-theme/style.css": (
            "text/css; charset=utf-8", WORDPRESS_LAYOUT_THEME),
        b"/site-content/themes/synthetic-discovery-parent/style.css": (
            "text/css; charset=utf-8", WORDPRESS_LAYOUT_PARENT_THEME),
        b"/modules/synthetic-discovery-plugin/assets/app.js": (
            "application/javascript", b"/* declared plugin asset */"),
        b"/modules/synthetic-discovery-plugin/readme.txt": (
            "text/plain; charset=utf-8", WORDPRESS_DISCOVERY_PLUGIN),
        b"/shop/wp-content/plugins/sibling-decoy/assets/app.js": (
            "application/javascript", b"/* sibling decoy */"),
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
                elif path == b"/blog/":
                    media_type, body = (
                        "text/html; charset=utf-8",
                        self.server.wordpress_layout_document,
                    )
                    code, reason, category = 200, "OK", "root"
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
    fixture.server.wordpress_layout_document = WORDPRESS_BLOG_DOCUMENT
    try:
        with fixture:
            yield fixture
    finally:
        first_use.DOCUMENT = previous_document


@contextmanager
def _wordpress_fingerprint_fixture():
    """Serve two page-only JS/CSS representations through ordinary page GETs."""
    routes = {
        b"/": ("text/html; charset=utf-8", WORDPRESS_FINGERPRINT_ROOT),
        b"/contact/": ("text/html; charset=utf-8", WORDPRESS_FINGERPRINT_PAGE),
        b"/gallery/": ("text/html; charset=utf-8", WORDPRESS_FINGERPRINT_PAGE),
        b"/blog/": ("text/html; charset=utf-8", WORDPRESS_FINGERPRINT_CUSTOM_ROOT),
        b"/blog/contact/": (
            "text/html; charset=utf-8", WORDPRESS_FINGERPRINT_CUSTOM_PAGE,
        ),
        b"/blog/gallery/": (
            "text/html; charset=utf-8", WORDPRESS_FINGERPRINT_CUSTOM_PAGE,
        ),
        b"/wp-content/themes/fingerprint-base/assets/site.css": (
            "text/css", b"body{color:#111}\n",
        ),
        b"/wp-content/themes/fingerprint-base/style.css": (
            "text/css", b"/* Theme Name: Fingerprint Base\nVersion: 1.0 */\n",
        ),
        WORDPRESS_FINGERPRINT_ASSET_PATHS[0].encode("ascii"): (
            "application/javascript", WORDPRESS_FINGERPRINT_JS_AB,
        ),
        WORDPRESS_FINGERPRINT_ASSET_PATHS[1].encode("ascii"): (
            "text/css", WORDPRESS_FINGERPRINT_CSS_BC,
        ),
        b"/wp-content/plugins/termivar-fingerprint-lab/readme.txt": (
            "text/plain; charset=utf-8", WORDPRESS_FINGERPRINT_PLUGIN,
        ),
        b"/cms/wp-json/": (
            "application/json; charset=utf-8", WORDPRESS_DISCOVERY_REST_INDEX,
        ),
        b"/site-content/themes/synthetic-discovery-theme/assets/site.css": (
            "text/css", b"body{color:#111}\n",
        ),
        b"/site-content/themes/synthetic-discovery-theme/style.css": (
            "text/css; charset=utf-8", WORDPRESS_LAYOUT_THEME,
        ),
        b"/site-content/themes/synthetic-discovery-parent/style.css": (
            "text/css; charset=utf-8", WORDPRESS_LAYOUT_PARENT_THEME,
        ),
        b"/modules/synthetic-discovery-plugin/assets/app.js": (
            "application/javascript", b"/* declared plugin asset */",
        ),
        b"/modules/synthetic-discovery-plugin/readme.txt": (
            "text/plain; charset=utf-8", WORDPRESS_DISCOVERY_PLUGIN,
        ),
        WORDPRESS_FINGERPRINT_CUSTOM_ASSET_PATHS[0].encode("ascii"): (
            "application/javascript", WORDPRESS_FINGERPRINT_JS_AB,
        ),
        WORDPRESS_FINGERPRINT_CUSTOM_ASSET_PATHS[1].encode("ascii"): (
            "text/css", WORDPRESS_FINGERPRINT_CSS_BC,
        ),
        b"/modules/termivar-fingerprint-lab/readme.txt": (
            "text/plain; charset=utf-8", WORDPRESS_FINGERPRINT_PLUGIN,
        ),
    }

    class WordPressFingerprintHandler(first_use.StaticHandler):
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
                lines = bytes(request).split(b"\r\n")
                words = lines[0].split(b" ")
                if len(words) != 3 or words[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                    self.server.note("invalid")
                    return
                method, path = words[:2]
                headers = {}
                for line in lines[1:]:
                    if b":" in line:
                        name, value = line.split(b":", 1)
                        headers.setdefault(name.strip().lower(), []).append(value.strip())
                forbidden = tuple(sorted(
                    name.decode("ascii") for name in headers
                    if name in {b"authorization", b"cookie", b"proxy-authorization"}
                ))
                first_line = lines[0].decode("ascii", errors="replace")
                with self.server.count_lock:
                    self.server.request_lines.append(first_line)
                    if forbidden:
                        self.server.fingerprint_forbidden_headers.append(
                            (first_line, forbidden))
                    if (method == b"GET"
                            and path.decode("ascii", errors="replace")
                            in (*WORDPRESS_FINGERPRINT_ASSET_PATHS,
                                *WORDPRESS_FINGERPRINT_CUSTOM_ASSET_PATHS)):
                        self.server.fingerprint_accept_encodings.append((
                            first_line,
                            tuple(value.decode("ascii", errors="replace")
                                  for value in headers.get(b"accept-encoding", ())),
                        ))
                if method not in (b"GET", b"HEAD"):
                    code, reason, media_type, body, category = (
                        405, "Method Not Allowed", "text/plain; charset=utf-8",
                        first_use.METHOD_REFUSED, "unsupported",
                    )
                elif path not in routes:
                    code, reason, media_type, body, category = (
                        404, "Not Found", "text/plain; charset=utf-8",
                        first_use.NOT_FOUND, "unknown",
                    )
                else:
                    media_type, body = routes[path]
                    code, reason, category = 200, "OK", "root"
                self.server.note(category)
                response_headers = (
                    f"HTTP/1.1 {code} {reason}\r\n"
                    f"Content-Type: {media_type}\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                self.request.sendall(
                    response_headers + (b"" if method == b"HEAD" else body))
            except (OSError, TimeoutError):
                return

    previous_document = first_use.DOCUMENT
    first_use.DOCUMENT = WORDPRESS_FINGERPRINT_ROOT
    fixture = first_use.Fixture()
    fixture.server.RequestHandlerClass = WordPressFingerprintHandler
    fixture.server.request_lines = []
    fixture.server.fingerprint_forbidden_headers = []
    fixture.server.fingerprint_accept_encodings = []
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


def _prepare_wordpress_layout_inputs(work: Path, origin: str) -> dict:
    directory = work / "wordpress-inputs"

    def encoded(application: str) -> bytes:
        return json.dumps({
            "schema": WORDPRESS_LAYOUT_SCHEMA,
            "application_url": application,
            "core_base_url": f"{origin}cms/",
            "themes_base_url": f"{origin}site-content/themes/",
            "plugins_base_url": f"{origin}modules/",
        }, separators=(",", ":")).encode("ascii") + b"\n"

    values = {
        "layout": encoded(f"{origin}blog/"),
        "layout_mismatch": encoded(f"{origin}sibling/"),
        "layout_malformed": b'{"schema":"security.wordpress-layout/v1",',
    }
    paths = {}
    snapshots = {}
    for name, data in values.items():
        path = directory / f"{name}.json"
        _write_new_input(path, data)
        paths[name] = path
        snapshots[name] = {"bytes": len(data), "sha256": first_use.digest_bytes(data)}
    return {"paths": paths, "snapshots": snapshots}


def _prepare_wordpress_fingerprint_inputs(work: Path, origin: str) -> dict:
    """Write independent finite-release matrices for packaged execution."""
    directory = work / "wordpress-inputs"

    def file(path: str, content: bytes) -> dict:
        return {
            "path": path,
            "byte_length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "representation_profile": WORDPRESS_FINGERPRINT_REPRESENTATION,
        }

    files = {
        "js_ab": file("assets/fingerprint.js", WORDPRESS_FINGERPRINT_JS_AB),
        "js_c": file("assets/fingerprint.js", WORDPRESS_FINGERPRINT_JS_C),
        "css_a": file("assets/fingerprint.css", WORDPRESS_FINGERPRINT_CSS_A),
        "css_bc": file("assets/fingerprint.css", WORDPRESS_FINGERPRINT_CSS_BC),
        "common": file("assets/common.css", WORDPRESS_FINGERPRINT_COMMON),
    }

    def release(identifier: str, version: str, rows: list[dict]) -> dict:
        return {
            "release_id": identifier,
            "version": version,
            "source": {
                "reference": f"https://example.invalid/termivar/{identifier}",
                "revision": f"{identifier}/v1",
                "notice_ids": ["termivar-packaged-fingerprint-notice"],
            },
            "files": rows,
        }

    def catalogue(identifier: str, partial: bool) -> bytes:
        release_a_files = [files["common"], files["js_ab"]]
        if not partial:
            release_a_files.append(files["css_a"])
        document = {
            "schema": WORDPRESS_FINGERPRINT_CATALOG_SCHEMA,
            "catalog": {
                "id": identifier,
                "revision": "v1",
                "source_namespace": "termivar.synthetic.packaged-fingerprints",
                "provenance": {
                    "reference": "https://example.invalid/termivar/fingerprint-matrix",
                    "revision": "packaged-matrix/v1",
                    "notices": [{
                        "id": "termivar-packaged-fingerprint-notice",
                        "party": "Termivar synthetic fixture authors",
                        "notice": "Original harmless package-acceptance bytes.",
                        "license": "Synthetic test data permission.",
                        "license_reference": (
                            "https://example.invalid/termivar/fingerprint-matrix/license"
                        ),
                    }],
                },
            },
            "components": [{
                "kind": "plugin",
                "slug": WORDPRESS_FINGERPRINT_COMPONENT,
                "releases": [
                    release("release-a", "1.0.0", release_a_files),
                    release("release-b", "2.0.0", [
                        files["common"], files["js_ab"], files["css_bc"],
                    ]),
                    release("release-c", "3.0.0", [
                        files["common"], files["js_c"], files["css_bc"],
                    ]),
                ],
            }],
        }
        return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"

    values = {
        "fingerprint_full": catalogue("termivar-packaged-fingerprint-full", False),
        "fingerprint_partial": catalogue("termivar-packaged-fingerprint-partial", True),
    }
    paths = {}
    snapshots = {}
    for name, encoded in values.items():
        path = directory / f"{name}.json"
        _write_new_input(path, encoded)
        paths[name] = path
        snapshots[name] = {
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    custom_layout_bytes = json.dumps({
        "schema": WORDPRESS_LAYOUT_SCHEMA,
        "application_url": f"{origin}blog/",
        "core_base_url": f"{origin}cms/",
        "themes_base_url": f"{origin}site-content/themes/",
        "plugins_base_url": f"{origin}modules/",
    }, separators=(",", ":")).encode("ascii") + b"\n"
    custom_layout_path = directory / "fingerprint_custom_layout.json"
    _write_new_input(custom_layout_path, custom_layout_bytes)
    return {
        "paths": paths,
        "snapshots": snapshots,
        "custom_layout": {
            "path": custom_layout_path,
            "snapshot": {
                "bytes": len(custom_layout_bytes),
                "sha256": hashlib.sha256(custom_layout_bytes).hexdigest(),
            },
        },
        "oracle": {
            "js_ab": files["js_ab"],
            "css_bc": files["css_bc"],
            "unseen_common": files["common"],
        },
    }


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


def _validate_wordpress_discovery(assessment: dict, case: str, origin: str,
                                  declaration_snapshot: dict | None = None) -> dict:
    require(case in {"root", "blog", "custom"},
            "packaged WordPress discovery acceptance case is unsupported")
    rest = {
        "kind": "rest_index",
        "slug": None,
        "parent_depth": 0,
        "response_bytes": len(WORDPRESS_DISCOVERY_REST_INDEX),
        "metadata": {"namespaces": ["oembed/1.0", "wp/v2"]},
    }
    plugin = {
        "kind": "plugin_readme",
        "slug": "synthetic-discovery-plugin",
        "parent_depth": 0,
        "response_bytes": len(WORDPRESS_DISCOVERY_PLUGIN),
        "metadata": {"plugin": {
            "name": "Synthetic Discovery Plugin",
            "stable_tag": "9.9.9",
            "requires_wordpress": "6.0",
            "tested_up_to": "6.9",
        }},
    }
    if case == "root":
        application_url = origin
        role_urls = {
            "themes": f"{origin}wp-content/themes/",
            "plugins": f"{origin}wp-content/plugins/",
            "rest_index": origin,
        }
        resource_urls = (
            f"{origin}wp-json/",
            f"{origin}wp-content/themes/synthetic-discovery-theme/style.css",
            f"{origin}wp-content/plugins/synthetic-discovery-plugin/readme.txt",
        )
        theme = {
            "kind": "theme_stylesheet",
            "slug": "synthetic-discovery-theme",
            "parent_depth": 0,
            "response_bytes": len(WORDPRESS_DISCOVERY_THEME),
            "metadata": {"theme": {
                "name": "Synthetic Discovery Theme",
                "version": "1.5",
                "requires_wordpress": "6.0",
                "tested_up_to": "6.9",
            }},
        }
        sources_expected = [
            {**rest, "association": "structured_advertisement"},
            {**theme, "association": "observed_conventional"},
            {**plugin, "association": "observed_conventional"},
        ]
        roles_expected = [
            ("core", "unresolved", "none", 0),
            ("themes", "exact", "conventional_asset", 1),
            ("plugins", "exact", "conventional_asset", 1),
            ("rest_index", "exact", "structured_advertisement", 1),
        ]
        response_bytes = WORDPRESS_DISCOVERY_RESPONSE_BYTES
        layout_counts = (0, 0, 0)
    else:
        application_url = f"{origin}blog/"
        if case == "blog":
            role_urls = {
                "core": application_url,
                "themes": f"{origin}blog/wp-content/themes/",
                "plugins": f"{origin}blog/wp-content/plugins/",
                "rest_index": application_url,
            }
            resource_urls = (
                f"{origin}blog/wp-json/",
                f"{origin}blog/wp-content/themes/synthetic-discovery-theme/style.css",
                f"{origin}blog/wp-content/themes/synthetic-discovery-parent/style.css",
                f"{origin}blog/wp-content/plugins/synthetic-discovery-plugin/readme.txt",
            )
        else:
            role_urls = {
                "core": f"{origin}cms/",
                "themes": f"{origin}site-content/themes/",
                "plugins": f"{origin}modules/",
                "rest_index": f"{origin}cms/",
            }
            resource_urls = (
                f"{origin}cms/wp-json/",
                f"{origin}site-content/themes/synthetic-discovery-theme/style.css",
                f"{origin}site-content/themes/synthetic-discovery-parent/style.css",
                f"{origin}modules/synthetic-discovery-plugin/readme.txt",
            )
        theme = {
            "kind": "theme_stylesheet",
            "slug": "synthetic-discovery-theme",
            "parent_depth": 0,
            "response_bytes": len(WORDPRESS_LAYOUT_THEME),
            "metadata": {"theme": {
                "name": "Synthetic Discovery Theme",
                "version": "1.5",
                "template": "synthetic-discovery-parent",
                "requires_wordpress": "6.0",
                "tested_up_to": "6.9",
            }},
        }
        parent = {
            "kind": "theme_stylesheet",
            "slug": "synthetic-discovery-parent",
            "parent_depth": 1,
            "association": "same_theme_base_parent",
            "response_bytes": len(WORDPRESS_LAYOUT_PARENT_THEME),
            "metadata": {"theme": {
                "name": "Synthetic Discovery Parent",
                "version": "2.0",
            }},
        }
        ordinary = "observed_conventional" if case == "blog" else "explicit_operator"
        rest_association = ("structured_advertisement" if case == "blog"
                            else "operator_qualified_advertisement")
        sources_expected = [
            {**rest, "association": rest_association},
            {**theme, "association": ordinary},
            parent,
            {**plugin, "association": ordinary},
        ]
        basis = "conventional_asset" if case == "blog" else "operator_declaration"
        roles_expected = [
            ("core", "exact", basis, 1),
            ("themes", "exact", basis, 1),
            ("plugins", "exact", basis, 1),
            ("rest_index", "exact",
             "structured_advertisement" if case == "blog" else basis, 1),
        ]
        response_bytes = WORDPRESS_LAYOUT_RESPONSE_BYTES
        layout_counts = (0, 1, 0) if case == "blog" else (0, 0, 1)

    discovery = _require_exact_keys(
        assessment.get("wordpress_discovery"),
        (
            "schema", "capability_id", "policy_id", "selected", "method",
            "credential_mode", "seed_count", "candidate_count",
            "candidate_limit_reached", "omitted_candidate_count",
            "attempted_request_count", "completed_response_count",
            "committed_response_count", "response_bytes", "source_count",
            "layout", "sources",
        ), (), "packaged WordPress discovery audit",
    )
    expected_count = len(sources_expected)
    require(discovery.get("schema") == WORDPRESS_DISCOVERY_AUDIT_SCHEMA
            and discovery.get("capability_id")
            == "technology.wordpress-metadata-discovery@1"
            and discovery.get("policy_id") == WORDPRESS_DISCOVERY_POLICY
            and discovery.get("selected") is True
            and discovery.get("method") == "get"
            and discovery.get("credential_mode") == "anonymous"
            and discovery.get("seed_count") == 3
            and discovery.get("candidate_count") == expected_count
            and discovery.get("candidate_limit_reached") is False
            and discovery.get("omitted_candidate_count") == 0
            and discovery.get("attempted_request_count") == expected_count
            and discovery.get("completed_response_count") == expected_count
            and discovery.get("committed_response_count") == expected_count
            and discovery.get("response_bytes") == response_bytes
            and discovery.get("source_count") == expected_count,
            "packaged WordPress discovery audit identity or accounting changed")

    layout = _require_exact_keys(
        discovery.get("layout"),
        (
            "application_reference", "roles", "skipped_foreign_origin_count",
            "skipped_sibling_application_count", "conflicting_association_count",
        ), ("declaration",), "packaged WordPress discovery layout",
    )
    require(layout.get("application_reference") == _framed_wordpress_reference(
                "wordpress-selected-application", application_url)
            and _is_opaque_wordpress_reference(layout.get("application_reference")),
            "packaged WordPress discovery application reference changed")
    require(tuple(layout.get(name) for name in (
                "skipped_foreign_origin_count",
                "skipped_sibling_application_count",
                "conflicting_association_count",
            )) == layout_counts,
            "packaged WordPress discovery layout coverage accounting changed")
    if case == "custom":
        require(declaration_snapshot is not None,
                "declared WordPress layout input snapshot is unavailable")
        declaration = _require_exact_keys(
            layout.get("declaration"), ("schema", "byte_length", "sha256"), (),
            "packaged WordPress layout declaration provenance",
        )
        require(declaration == {
            "schema": WORDPRESS_LAYOUT_SCHEMA,
            "byte_length": declaration_snapshot["bytes"],
            "sha256": declaration_snapshot["sha256"],
        }, "packaged WordPress layout declaration provenance changed")
    else:
        require("declaration" not in layout,
                "undeclared WordPress discovery unexpectedly reported a layout input")

    roles = layout.get("roles")
    require(isinstance(roles, list) and len(roles) == len(roles_expected),
            "packaged WordPress discovery layout role cardinality changed")
    role_references = {}
    for role, expected in zip(roles, roles_expected):
        role = _require_exact_keys(
            role, ("role", "status", "basis", "candidate_count"), ("reference",),
            "packaged WordPress discovery layout role",
        )
        name, status, basis, candidate_count = expected
        require((role.get("role"), role.get("status"), role.get("basis"),
                 role.get("candidate_count")) == expected,
                f"packaged WordPress discovery {name} role changed")
        if status == "exact":
            require(role.get("reference") == _framed_wordpress_reference(
                        "wordpress-discovery-role", role_urls[name])
                    and _is_opaque_wordpress_reference(role.get("reference")),
                    f"packaged WordPress discovery {name} role reference changed")
            role_references[name] = role["reference"]
        else:
            require("reference" not in role,
                    f"packaged WordPress discovery {name} role was falsely resolved")

    sources = discovery.get("sources")
    require(isinstance(sources, list) and len(sources) == expected_count,
            "packaged WordPress discovery source cardinality changed")
    source_references = []
    evidence_references = []
    source_identities = []
    for source, expected, resource_url in zip(
            sources, sources_expected, resource_urls, strict=True):
        metadata_key = {
            "rest_index": "namespaces",
            "theme_stylesheet": "theme",
            "plugin_readme": "plugin",
        }[expected["kind"]]
        required = (
            "kind", "association", "resource_reference", "role_reference",
            "component", "parent_depth", "outcome", "request_attempted",
            "response_bytes", "evidence_reference_count", "evidence_references",
            metadata_key,
        )
        if expected["kind"] == "rest_index":
            required = tuple(name for name in required if name != "component")
        source = _require_exact_keys(
            source, required, (), "packaged WordPress discovery source",
        )
        identity = (source.get("kind"),
                    source.get("component", {}).get("slug"),
                    source.get("parent_depth"))
        expected_identity = (expected["kind"], expected["slug"],
                             expected["parent_depth"])
        source_identities.append(identity)
        require(identity == expected_identity
                and source.get("association") == expected["association"]
                and source.get("outcome") == "observed"
                and source.get("request_attempted") is True
                and source.get("evidence_reference_count") == 1,
                "packaged WordPress discovery source identity or outcome changed")
        require(source.get("response_bytes") == expected["response_bytes"],
                "packaged WordPress discovery per-source response accounting changed")
        if expected["slug"] is not None:
            kind = "theme" if expected["kind"] == "theme_stylesheet" else "plugin"
            require(source.get("component") == {
                "kind": kind, "slug": expected["slug"],
            }, "packaged WordPress discovery component identity changed")
        if metadata_key == "plugin":
            require("version" not in source.get("plugin", {}),
                    "plugin Stable tag was promoted to an installed version")
        require(source.get(metadata_key) == expected["metadata"][metadata_key],
                "packaged WordPress discovery typed metadata changed")
        role_name = {
            "rest_index": "rest_index",
            "theme_stylesheet": "themes",
            "plugin_readme": "plugins",
        }[expected["kind"]]
        require(source.get("role_reference") == role_references.get(role_name),
                "packaged WordPress discovery source-to-role binding changed")
        require(source.get("resource_reference") == _framed_wordpress_reference(
                    "wordpress-discovery-resource", resource_url)
                and _is_opaque_wordpress_reference(source.get("resource_reference")),
                "packaged WordPress discovery resource reference changed")
        source_references.append(source["resource_reference"])
        references = source.get("evidence_references")
        require(isinstance(references, list) and len(references) == 1
                and isinstance(references[0], str),
                "packaged WordPress discovery evidence reference shape changed")
        evidence_references.extend(references)
    require(len(set(source_identities)) == expected_count
            and len(set(source_references)) == expected_count
            and len(set(evidence_references)) == expected_count,
            "packaged WordPress discovery source identity was duplicated")
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
            and item.get("evidence_count") == expected_count
            and len(item.get("evidence_references", []))
            == expected_count
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
    require(sum(source["response_bytes"] for source in sources) == response_bytes,
            "packaged WordPress discovery response/evidence accounting changed")
    require(_same_unique_string_members(
                evidence_references, item.get("evidence_references")
            ),
            "packaged WordPress discovery source-to-evidence linkage changed")
    by_kind = {source.get("kind"): source for source in sources
               if isinstance(source, dict)}
    require(tuple(sorted(by_kind))
            == ("plugin_readme", "rest_index", "theme_stylesheet"),
            "packaged WordPress discovery source identities changed")
    expected_kind_totals = {}
    for expected in sources_expected:
        expected_kind_totals[expected["kind"]] = (
            expected_kind_totals.get(expected["kind"], 0) + expected["response_bytes"])
    require(all(sum(source["response_bytes"] for source in sources
                    if source["kind"] == kind) == expected
                for kind, expected in expected_kind_totals.items()),
            "packaged WordPress discovery per-source response accounting changed")
    rest = by_kind["rest_index"]
    child_theme_sources = [
        source for source in sources
        if source.get("component", {}).get("slug")
        == "synthetic-discovery-theme"
    ]
    require(len(child_theme_sources) == 1,
            "packaged WordPress child-theme source is missing or duplicated")
    theme = child_theme_sources[0]
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
            == expected_count,
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
    parent_components = [
        component for component in review.get("components", [])
        if isinstance(component, dict)
        and component.get("identity") == {
            "kind": "theme", "slug": "synthetic-discovery-parent",
        }
    ]
    if case == "root":
        require(not parent_components,
                "root discovery unexpectedly projected a parent theme")
    else:
        require(len(parent_components) == 1
                and "theme_stylesheet_declaration"
                in parent_components[0].get("identity_sources", [])
                and parent_components[0].get("versions") == [{
                    "value": "2.0",
                    "source": "theme_stylesheet_declaration",
                    "confidence": "public_declaration",
                }],
                "same-base parent theme did not retain its source-qualified version")
    require("sibling-decoy" not in json.dumps({
                "review": review, "discovery": discovery,
            }, sort_keys=True),
            "selected /blog discovery projected the sibling decoy")
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
        "case": case,
        "attempted_requests": expected_count,
        "committed_responses": expected_count,
        "response_bytes": discovery["response_bytes"],
        "observed_sources": sorted(by_kind),
        "source_associations": [source["association"] for source in sources],
        "layout": {
            "declaration_supplied": case == "custom",
            "role_statuses": {role["role"]: role["status"] for role in roles},
            "role_bases": {role["role"]: role["basis"] for role in roles},
            "skipped_foreign_origin_count": layout_counts[0],
            "skipped_sibling_application_count": layout_counts[1],
            "conflicting_association_count": layout_counts[2],
        },
        "same_base_parent_sources": sum(
            source["association"] == "same_theme_base_parent" for source in sources),
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

    prepared = _prepare_wordpress_layout_inputs(work, fixture.origin)
    paths = state["inputs"]["paths"]
    paths.update(prepared["paths"])
    state["inputs"]["snapshots"].update(prepared["snapshots"])
    blog_target = f"{fixture.origin}blog/"
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

    nonroot_review = work / "wordpress-nonroot-review-must-not-exist"
    nonroot_stdout, nonroot_stderr = runner.run(
        "wordpress-nonroot-review-missing-discovery", [
        "scan", blog_target, "--profile", "web-review", "--wordpress-review",
        "--report-dir", str(nonroot_review),
    ], expected_exit=1, expected_stderr_empty=False)
    require(
        nonroot_stdout == b""
        and WORDPRESS_NONROOT_DISCOVERY_DIAGNOSTIC in nonroot_stderr,
        "non-root review returned the wrong discovery preflight diagnostic",
    )
    require(not nonroot_review.exists(),
            "non-root review without discovery reserved an output directory")

    layout_preflights = (
        (
            "wordpress-layout-missing-discovery",
            paths["layout"],
            work / "wordpress-layout-missing-discovery-must-not-exist",
            2,
            False,
        ),
        (
            "wordpress-layout-malformed",
            paths["layout_malformed"],
            work / "wordpress-layout-malformed-must-not-exist",
            1,
            True,
        ),
        (
            "wordpress-layout-target-mismatch",
            paths["layout_mismatch"],
            work / "wordpress-layout-target-mismatch-must-not-exist",
            1,
            True,
        ),
    )
    for identifier, layout, destination, expected_exit, discovery_enabled in layout_preflights:
        arguments = [
            "scan", blog_target, "--profile", "web-review", "--wordpress-review",
        ]
        if discovery_enabled:
            arguments.append("--wordpress-discovery")
        arguments.extend([
            "--wordpress-layout", str(layout), "--report-dir", str(destination),
        ])
        runner.run(identifier, arguments, expected_exit=expected_exit,
                   expected_stderr_empty=False)
        require(not destination.exists(),
                f"{identifier} reserved an output directory")

    def run_case(identifier: str, target: str, trace_expected: tuple[str, ...],
                 case: str, layout_input: Path | None = None) -> dict:
        bundle_path = work / identifier
        before_trace = len(fixture.server.request_lines)
        before_forbidden_headers = len(fixture.server.discovery_forbidden_headers)
        arguments = [
            "scan", target, "--profile", "web-review", "--wordpress-review",
            "--wordpress-discovery", "--wordpress-advisories",
            str(paths["discovery_catalog"]),
        ]
        if layout_input is not None:
            arguments.extend(["--wordpress-layout", str(layout_input)])
        arguments.extend(["--report-dir", str(bundle_path)])
        stdout, _ = runner.run(identifier, arguments, expected_stderr_empty=False)
        require(stdout == b"", f"{identifier} wrote a report document to stdout")
        trace = tuple(fixture.server.request_lines[before_trace:])
        require(trace == trace_expected,
                f"{identifier} request method/order/count changed")
        require(
            fixture.server.discovery_forbidden_headers[before_forbidden_headers:] == [],
            f"{identifier} sent a forbidden credential header",
        )
        assessment, bundle, _ = _read_assessment(bundle_path)
        require(bundle.get("producer") == {
            "product": "Termivar", "version": expected_version,
        }, f"{identifier} bundle producer identity changed")
        result = _validate_wordpress_discovery(
            assessment,
            case,
            fixture.origin,
            (prepared["snapshots"]["layout"] if layout_input is not None else None),
        )
        return {
            "path": bundle_path,
            "assessment": assessment,
            "result": result,
            "trace": trace,
        }

    root = run_case(
        "wordpress-discovery", fixture.origin, WORDPRESS_DISCOVERY_TRACE, "root")
    fixture.server.wordpress_layout_document = WORDPRESS_BLOG_DOCUMENT
    blog = run_case(
        "wordpress-discovery-blog", blog_target, WORDPRESS_BLOG_TRACE, "blog")
    fixture.server.wordpress_layout_document = WORDPRESS_CUSTOM_DOCUMENT
    custom = run_case(
        "wordpress-discovery-custom", blog_target, WORDPRESS_CUSTOM_TRACE, "custom",
        paths["layout"])
    require(
        blog["assessment"]["wordpress_discovery"]["layout"]["application_reference"]
        == custom["assessment"]["wordpress_discovery"]["layout"]["application_reference"],
        "conventional and declared layout scans did not retain one application identity",
    )

    by_id = {record["id"]: record for record in runner.records}
    preflight_identifiers = (
        "wordpress-discovery-missing-review", "wordpress-discovery-wrong-profile",
        "wordpress-nonroot-review-missing-discovery",
        *(case[0] for case in layout_preflights),
    )
    for identifier in preflight_identifiers:
        require(sum(by_id[identifier]["fixture_requests"].values()) == 0,
                f"{identifier} contacted the target fixture")
    cases = {"discovery": root, "discovery_blog": blog, "discovery_custom": custom}
    for name, value in cases.items():
        require(by_id[value["path"].name]["fixture_requests"] == {
            "example": 0, "invalid": 0, "root": len(value["trace"]),
            "unknown": 0, "unsupported": 0,
        }, f"{value['path'].name} fixture accounting changed")
        state["bundles"][name] = value["path"]
        state["bundle_snapshots"][name] = _snapshot_files(value["path"])
        state["item_counts"][name] = value["assessment"]["item_count"]
    for name, snapshot in prepared["snapshots"].items():
        path = prepared["paths"][name]
        require(path.stat().st_size == snapshot["bytes"]
                and first_use.digest_file(path) == snapshot["sha256"],
                f"packaged scan changed synthetic WordPress layout input: {name}")
    state["public"]["discovery"] = {
        **root["result"],
        "request_trace": list(root["trace"]),
        "forbidden_credential_headers_observed": False,
        "ordinary_review_auto_enabled_discovery": False,
        "source_authenticity": "not_established",
        "security_effectiveness_or_remediation": "not_established",
    }
    state["public"]["layout_preflight"] = {
        "nonroot_review_missing_discovery": "refused_before_request_without_bundle",
        "missing_discovery": "refused_before_request_without_bundle",
        "malformed": "refused_before_request_without_bundle",
        "application_mismatch": "refused_before_request_without_bundle",
    }
    state["public"]["layout_cases"] = {
        "conventional_blog": {
            **blog["result"], "request_trace": list(blog["trace"]),
        },
        "declared_custom_roots": {
            **custom["result"], "request_trace": list(custom["trace"]),
        },
        "same_application_identity": True,
        "sibling_decoy_metadata_requests": 0,
    }
    return state


def _validate_wordpress_fingerprints(
        assessment: dict, snapshot: dict, *, partial: bool,
        custom_layout_snapshot: dict | None = None,
        origin: str | None = None) -> dict:
    custom_layout = custom_layout_snapshot is not None
    require(not custom_layout or isinstance(origin, str),
            "custom fingerprint layout origin is unavailable")
    audit = _require_exact_keys(
        assessment.get("wordpress_asset_fingerprints"),
        (
            "schema", "capability_id", "policy_id", "selected",
            "representation_profile", "finite_reference_scope",
            "same_release_assumption", "installed_version_assurance",
            "source_authenticity", "catalogue", "candidate_count",
            "selected_resource_count", "omitted_resource_count",
            "attempted_request_count", "reused_response_count",
            "fetched_response_count", "response_bytes", "stop",
            "resource_count", "resources", "component_count", "components",
        ), (), "packaged WordPress asset fingerprint audit",
    )
    require(
        audit.get("schema") == WORDPRESS_FINGERPRINT_AUDIT_SCHEMA
        and audit.get("capability_id")
        == "technology.wordpress-asset-fingerprint-candidate@1"
        and audit.get("policy_id") == WORDPRESS_FINGERPRINT_POLICY
        and audit.get("selected") is True
        and audit.get("representation_profile") == WORDPRESS_FINGERPRINT_REPRESENTATION
        and audit.get("finite_reference_scope") == "listed_releases_only"
        and audit.get("same_release_assumption")
        == "considered_paths_share_one_listed_release_artifact_set"
        and audit.get("installed_version_assurance")
        == "not_established_by_asset_fingerprints"
        and audit.get("source_authenticity") == "not_established"
        and audit.get("candidate_count") == 2
        and audit.get("selected_resource_count") == 2
        and audit.get("omitted_resource_count") == 0
        and audit.get("attempted_request_count") == 2
        and audit.get("reused_response_count") == 0
        and audit.get("fetched_response_count") == 2
        and audit.get("response_bytes")
        == len(WORDPRESS_FINGERPRINT_JS_AB) + len(WORDPRESS_FINGERPRINT_CSS_BC)
        and audit.get("stop") == "complete"
        and audit.get("resource_count") == 2
        and audit.get("component_count") == 1,
        "packaged WordPress asset fingerprint policy or accounting changed",
    )
    catalogue = _require_exact_keys(
        audit.get("catalogue"),
        (
            "schema", "id", "revision", "source_namespace", "byte_length",
            "sha256", "semantic_sha256", "retained_bytes", "component_count",
            "release_count", "file_count", "provenance",
        ), (), "packaged WordPress fingerprint catalogue provenance",
    )
    require(
        catalogue.get("schema") == WORDPRESS_FINGERPRINT_CATALOG_SCHEMA
        and catalogue.get("id") == (
            "termivar-packaged-fingerprint-partial" if partial
            else "termivar-packaged-fingerprint-full"
        )
        and catalogue.get("revision") == "v1"
        and catalogue.get("source_namespace")
        == "termivar.synthetic.packaged-fingerprints"
        and catalogue.get("byte_length") == snapshot["bytes"]
        and catalogue.get("sha256") == snapshot["sha256"]
        and isinstance(catalogue.get("semantic_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", catalogue["semantic_sha256"], re.ASCII)
        and isinstance(catalogue.get("retained_bytes"), int)
        and not isinstance(catalogue.get("retained_bytes"), bool)
        and catalogue["retained_bytes"] > 0
        and catalogue.get("component_count") == 1
        and catalogue.get("release_count") == 3
        and catalogue.get("file_count") == (8 if partial else 9),
        "packaged WordPress fingerprint catalogue identity changed",
    )
    resources = audit.get("resources")
    require(isinstance(resources, list) and len(resources) == 2,
            "packaged WordPress fingerprint resource cardinality changed")
    discovery = assessment.get("wordpress_discovery")
    require(
        isinstance(discovery, dict)
        and discovery.get("schema") == "security.wordpress-discovery-audit/v3"
        and discovery.get("policy_id")
        == "termivar.wordpress-page-scoped-metadata-discovery/v1",
        "packaged fingerprint scan did not use observed-page discovery",
    )
    page_collection = discovery.get("page_collection")
    require(
        isinstance(page_collection, dict)
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
        and len(page_collection["pages"]) == 2,
        "packaged fingerprint observed-page accounting changed",
    )
    page_references = set()
    for page in page_collection["pages"]:
        page = _require_exact_keys(
            page,
            (
                "page_reference", "acquisition", "association", "outcome",
                "request_attempted", "interpreted_response_bytes", "response_bytes",
                "evidence_reference_count", "evidence_references",
            ),
            (), "packaged fingerprint observed-page row",
        )
        require(
            page.get("acquisition") == "reused"
            and page.get("association") == "accepted"
            and page.get("outcome") == "accepted"
            and page.get("request_attempted") is False
            and isinstance(page.get("interpreted_response_bytes"), int)
            and not isinstance(page.get("interpreted_response_bytes"), bool)
            and page["interpreted_response_bytes"] > 0
            and page.get("response_bytes") == 0
            and page.get("evidence_reference_count") == 1
            and isinstance(page.get("evidence_references"), list)
            and len(page["evidence_references"]) == 1,
            "packaged fingerprint observed-page assurance changed",
        )
        page_references.add(page.get("page_reference"))
    require(
        len(page_references) == 2
        and all(_is_opaque_wordpress_reference(value) for value in page_references)
        and _is_opaque_wordpress_reference(page_collection.get("entry_page_reference"))
        and page_collection.get("entry_page_reference") not in page_references,
        "packaged fingerprint accepted-page provenance changed",
    )
    if custom_layout:
        layout = discovery.get("layout")
        require(isinstance(layout, dict),
                "packaged custom fingerprint layout is unavailable")
        declaration = layout.get("declaration")
        roles = layout.get("roles")
        role_by_name = {
            role.get("role"): role for role in roles
            if isinstance(role, dict)
        } if isinstance(roles, list) else {}
        require(
            declaration == {
                "schema": WORDPRESS_LAYOUT_SCHEMA,
                "byte_length": custom_layout_snapshot["bytes"],
                "sha256": custom_layout_snapshot["sha256"],
            }
            and layout.get("application_reference")
            == _framed_wordpress_reference(
                "wordpress-selected-application", f"{origin}blog/")
            and role_by_name.get("plugins", {}).get("basis")
            == "operator_declaration"
            and role_by_name.get("plugins", {}).get("reference")
            == _framed_wordpress_reference(
                "wordpress-discovery-role", f"{origin}modules/")
            and role_by_name.get("themes", {}).get("basis")
            == "operator_declaration"
            and role_by_name.get("themes", {}).get("reference")
            == _framed_wordpress_reference(
                "wordpress-discovery-role", f"{origin}site-content/themes/")
            and discovery.get("seed_count") == 4
            and discovery.get("candidate_count") == 5
            and discovery.get("attempted_request_count") == 5
            and discovery.get("completed_response_count") == 5
            and discovery.get("committed_response_count") == 5
            and discovery.get("source_count") == 5,
            "packaged custom fingerprint frozen-layout accounting changed",
        )

        sources = discovery.get("sources")
        require(isinstance(sources, list) and len(sources) == 5,
                "packaged custom fingerprint metadata source count changed")
        expected_sources = (
            ("rest_index", None, "operator_qualified_advertisement"),
            ("theme_stylesheet", ("theme", "synthetic-discovery-theme"),
             "explicit_operator"),
            ("theme_stylesheet", ("theme", "synthetic-discovery-parent"),
             "same_theme_base_parent"),
            ("plugin_readme", ("plugin", "synthetic-discovery-plugin"),
             "explicit_operator"),
            ("plugin_readme", ("plugin", WORDPRESS_FINGERPRINT_COMPONENT),
             "explicit_operator"),
        )
        entry_reference = page_collection.get("entry_page_reference")
        require(_is_opaque_wordpress_reference(entry_reference),
                "packaged custom fingerprint entry provenance changed")
        for index, (source, expected) in enumerate(
                zip(sources, expected_sources, strict=True)):
            kind, component, association = expected
            actual_component = source.get("component") if isinstance(source, dict) else None
            expected_component = (
                None if component is None
                else {"kind": component[0], "slug": component[1]}
            )
            expected_pages = (
                page_references if index in {1, 2, len(expected_sources) - 1}
                else {entry_reference}
            )
            require(
                isinstance(source, dict)
                and source.get("kind") == kind
                and actual_component == expected_component
                and source.get("association") == association
                and isinstance(source.get("source_page_references"), list)
                and len(source["source_page_references"]) == len(expected_pages)
                and set(source["source_page_references"]) == expected_pages,
                "packaged custom fingerprint source binding changed",
            )
        require(
            discovery.get("response_bytes")
            == sum(source.get("response_bytes", -1) for source in sources),
            "packaged custom fingerprint metadata byte accounting changed",
        )
    by_path = {}
    for resource in resources:
        resource = _require_exact_keys(
            resource,
            (
                "component", "relative_path", "resource_reference",
                "source_page_references", "observed_variant_count", "acquisition",
                "outcome", "request_attempted", "interpreted_response_bytes",
                "response_bytes", "evidence_reference_count",
                "evidence_references", "observation",
            ), (), "packaged WordPress fingerprint resource",
        )
        path = resource.get("relative_path")
        require(path in {"assets/fingerprint.js", "assets/fingerprint.css"}
                and path not in by_path,
                "packaged WordPress fingerprint resource identity changed")
        expected = (
            WORDPRESS_FINGERPRINT_JS_AB
            if path.endswith(".js") else WORDPRESS_FINGERPRINT_CSS_BC
        )
        observation = _require_exact_keys(
            resource.get("observation"), ("byte_length", "sha256"), (),
            "packaged WordPress fingerprint byte observation",
        )
        require(
            resource.get("component") == {
                "kind": "plugin", "slug": WORDPRESS_FINGERPRINT_COMPONENT,
            }
            and _is_opaque_wordpress_reference(resource.get("resource_reference"))
            and isinstance(resource.get("source_page_references"), list)
            and all(
                isinstance(reference, str)
                and _is_opaque_wordpress_reference(reference)
                for reference in resource["source_page_references"]
            )
            and set(resource["source_page_references"]) == page_references
            and len(resource["source_page_references"]) == 2
            and resource.get("observed_variant_count") == 1
            and resource.get("acquisition") == "fetched"
            and resource.get("outcome") == "observed"
            and resource.get("request_attempted") is True
            and resource.get("interpreted_response_bytes") == len(expected)
            and resource.get("response_bytes") == len(expected)
            and resource.get("evidence_reference_count") == 1
            and isinstance(resource.get("evidence_references"), list)
            and len(resource["evidence_references"]) == 1
            and observation == {
                "byte_length": len(expected),
                "sha256": hashlib.sha256(expected).hexdigest(),
            }
            and "url" not in resource,
            "packaged WordPress fingerprint resource assurance changed",
        )
        by_path[path] = resource

    components = audit.get("components")
    require(isinstance(components, list) and len(components) == 1,
            "packaged WordPress fingerprint component cardinality changed")
    component = components[0]
    expected_state = "provisional_candidates" if partial else "single_catalogue_candidate"
    expected_undetermined = ["release-a"] if partial else []
    require(
        component.get("identity") == {
            "kind": "plugin", "slug": WORDPRESS_FINGERPRINT_COMPONENT,
        }
        and component.get("catalogue_component_listed") is True
        and component.get("state") == expected_state
        and component.get("candidate_resource_count") == 2
        and component.get("selected_resource_count") == 2
        and component.get("completely_interpreted_resource_count") == 2
        and component.get("omitted_resource_count") == 0
        and component.get("informative_resource_count") == (1 if partial else 2)
        and component.get("listed_matrix_complete") is (not partial)
        and component.get("compatible_release_ids") == ["release-b"]
        and component.get("undetermined_release_ids") == expected_undetermined
        and component.get("inconsistent_release_ids")
        == (["release-c"] if partial else ["release-a", "release-c"])
        and component.get("resource_count") == 2
        and component.get("release_count") == 3,
        "packaged WordPress fingerprint candidate intersection changed",
    )
    release_rows = component.get("releases")
    require(isinstance(release_rows, list)
            and [row.get("release_id") for row in release_rows]
            == ["release-a", "release-b", "release-c"]
            and release_rows[1].get("version") == "2.0.0"
            and release_rows[1].get("state") == "compatible",
            "packaged WordPress fingerprint listed-release identity changed")
    matrix = component.get("resources")
    require(isinstance(matrix, list) and len(matrix) == 2,
            "packaged WordPress fingerprint comparison matrix changed")

    review = assessment.get("wordpress_review")
    require(isinstance(review, dict)
            and review.get("schema") == "security.wordpress-review-audit/v8",
            "fingerprint-influenced WordPress review schema changed")
    plugin_components = [
        row for row in review.get("components", [])
        if isinstance(row, dict) and row.get("identity") == {
            "kind": "plugin", "slug": WORDPRESS_FINGERPRINT_COMPONENT,
        }
    ]
    require(len(plugin_components) == 1 and plugin_components[0].get("versions") == [],
            "fingerprint candidate or URL ver became installed-version evidence")
    sources = discovery.get("sources", []) if isinstance(discovery, dict) else []
    readmes = [source for source in sources if isinstance(source, dict)
               and source.get("kind") == "plugin_readme"
               and source.get("component") == {
                   "kind": "plugin", "slug": WORDPRESS_FINGERPRINT_COMPONENT,
               }]
    require(len(readmes) == 1
            and readmes[0].get("association")
            == ("explicit_operator" if custom_layout else "observed_conventional")
            and readmes[0].get("plugin", {}).get("stable_tag") == "9.9.9"
            and "version" not in readmes[0].get("plugin", {}),
            "plugin Stable tag became installed-version evidence")
    if custom_layout:
        require(review.get("additional_request_count") == 7,
                "packaged custom fingerprint shared request accounting changed")
    return {
        "audit_schema": audit["schema"],
        "catalogue_schema": catalogue["schema"],
        "catalogue_sha256": catalogue["sha256"],
        "state": component["state"],
        "compatible_release_ids": component["compatible_release_ids"],
        "undetermined_release_ids": component["undetermined_release_ids"],
        "inconsistent_release_ids": component["inconsistent_release_ids"],
        "observed_resources": sorted(by_path),
        "page_collection": {
            "selected": page_collection["selected_count"],
            "reused": page_collection["reused_response_count"],
            "committed": page_collection["committed_response_count"],
            "wordpress_owned_page_requests": page_collection["attempted_request_count"],
        },
        "installed_version_assurance": audit["installed_version_assurance"],
        "url_ver_selected_release": False,
        "plugin_stable_tag_is_installed_version": False,
        "custom_layout": custom_layout,
        "metadata_source_count": discovery.get("source_count"),
        "conditional_readme_association": readmes[0].get("association"),
        "source_page_reference_count": len(page_references),
        "fingerprint_request_count": audit.get("attempted_request_count"),
        "fingerprint_fetched_response_count": audit.get("fetched_response_count"),
    }


def _run_wordpress_fingerprint_acceptance(runner: CandidateRunner, work: Path,
                                          expected_version: str,
                                          state: dict) -> dict:
    fixture = runner.fixture
    require(fixture is not None, "WordPress fingerprint fixture runner is unavailable")
    require(fixture.server.snapshot() == {
        "root": 1, "example": 0, "unknown": 0,
        "unsupported": 0, "invalid": 0,
    }, "WordPress fingerprint fixture readiness accounting changed")
    prepared = _prepare_wordpress_fingerprint_inputs(work, fixture.origin)
    state["inputs"]["paths"].update(prepared["paths"])
    state["inputs"]["snapshots"].update(prepared["snapshots"])
    state["inputs"]["paths"]["fingerprint_custom_layout"] = (
        prepared["custom_layout"]["path"])
    state["inputs"]["snapshots"]["fingerprint_custom_layout"] = (
        prepared["custom_layout"]["snapshot"])

    preflight = work / "wordpress-fingerprint-missing-discovery-must-not-exist"
    runner.run("wordpress-fingerprint-missing-discovery", [
        "scan", fixture.origin, "--profile", "web-review", "--wordpress-review",
        "--wordpress-fingerprints", str(prepared["paths"]["fingerprint_full"]),
        "--report-dir", str(preflight),
    ], expected_exit=2, expected_stderr_empty=False)
    require(not preflight.exists(),
            "fingerprints without discovery reserved an output directory")

    cases = {}
    for name, partial, custom_layout in (
            ("fingerprint_full", False, False),
            ("fingerprint_partial", True, False),
            ("fingerprint_custom", False, True)):
        bundle = work / f"wordpress-{name.replace('_', '-')}"
        before_trace = len(fixture.server.request_lines)
        before_encodings = len(fixture.server.fingerprint_accept_encodings)
        target = f"{fixture.origin}blog/" if custom_layout else fixture.origin
        arguments = [
            "scan", target, "--profile", "web-review", "--wordpress-review",
            "--wordpress-discovery", "--wordpress-page-scope", "observed",
            "--wordpress-fingerprints", str(prepared["paths"][
                "fingerprint_full" if custom_layout else name]),
        ]
        if custom_layout:
            arguments.extend([
                "--wordpress-layout", str(prepared["custom_layout"]["path"]),
            ])
        arguments.extend(["--report-dir", str(bundle)])
        stdout, _ = runner.run(
            f"wordpress-{name.replace('_', '-')}", arguments,
            expected_stderr_empty=False,
        )
        require(stdout == b"", f"{name} wrote a report document to stdout")
        trace = tuple(fixture.server.request_lines[before_trace:])
        page_paths = (("/blog/contact/", "/blog/gallery/") if custom_layout
                      else ("/contact/", "/gallery/"))
        asset_paths = (WORDPRESS_FINGERPRINT_CUSTOM_ASSET_PATHS if custom_layout
                       else WORDPRESS_FINGERPRINT_ASSET_PATHS)
        for path in page_paths:
            require(trace.count(f"GET {path} HTTP/1.1") == 1,
                    f"{name} did not reuse each ordinary secondary page exactly once")
        for path in asset_paths:
            require(trace.count(f"GET {path} HTTP/1.1") == 1,
                    f"{name} did not fetch each admitted asset exactly once")
        if custom_layout:
            metadata_paths = (
                "/cms/wp-json/",
                "/site-content/themes/synthetic-discovery-theme/style.css",
                "/site-content/themes/synthetic-discovery-parent/style.css",
                "/modules/synthetic-discovery-plugin/readme.txt",
                "/modules/termivar-fingerprint-lab/readme.txt",
            )
            require(all(trace.count(f"GET {path} HTTP/1.1") == 1
                        for path in metadata_paths),
                    "custom fingerprint metadata sources were not fetched exactly once")
        require(not any("assets/common.css" in request for request in trace),
                f"{name} fetched an unseen catalogue path")
        require(not fixture.server.fingerprint_forbidden_headers,
                f"{name} sent a forbidden credential header")
        encodings = fixture.server.fingerprint_accept_encodings[before_encodings:]
        require(len(encodings) == 2
                and all(values == ("identity",) for _, values in encodings),
                f"{name} did not request identity content bytes")
        assessment, manifest, _ = _read_assessment(bundle)
        require(manifest.get("producer") == {
            "product": "Termivar", "version": expected_version,
        }, f"{name} bundle producer identity changed")
        result = _validate_wordpress_fingerprints(
            assessment,
            prepared["snapshots"]["fingerprint_full" if custom_layout else name],
            partial=partial,
            custom_layout_snapshot=(prepared["custom_layout"]["snapshot"]
                                    if custom_layout else None),
            origin=(fixture.origin if custom_layout else None),
        )
        cases[name] = {
            "path": bundle,
            "assessment": assessment,
            "snapshot": _snapshot_files(bundle),
            "result": result,
            "trace": trace,
        }

    by_id = {record["id"]: record for record in runner.records}
    require(sum(by_id["wordpress-fingerprint-missing-discovery"]
                ["fixture_requests"].values()) == 0,
            "fingerprint preflight contacted the target fixture")
    for name, value in cases.items():
        state["bundles"][name] = value["path"]
        state["bundle_snapshots"][name] = value["snapshot"]
        state["item_counts"][name] = value["assessment"]["item_count"]
    for name, snapshot in prepared["snapshots"].items():
        path = prepared["paths"][name]
        require(path.stat().st_size == snapshot["bytes"]
                and first_use.digest_file(path) == snapshot["sha256"],
                f"packaged scan changed synthetic fingerprint catalogue: {name}")
    custom_layout = prepared["custom_layout"]
    require(
        custom_layout["path"].stat().st_size == custom_layout["snapshot"]["bytes"]
        and first_use.digest_file(custom_layout["path"])
        == custom_layout["snapshot"]["sha256"],
        "packaged scan changed the synthetic fingerprint layout declaration",
    )
    state["public"]["asset_fingerprints"] = {
        "fixture_kind": "original_synthetic_secondary_page_observed_js_css_loopback",
        "reference_oracle": prepared["oracle"],
        "two_file_intersection": cases["fingerprint_full"]["result"],
        "missing_reference_provisional": cases["fingerprint_partial"]["result"],
        "custom_secondary": cases["fingerprint_custom"]["result"],
        "request_traces": {
            name: list(value["trace"]) for name, value in cases.items()
        },
        "identity_content_encoding_requested": True,
        "unseen_catalogue_paths_requested": 0,
        "source_authenticity": "not_established",
        "listed_release_scope_is_exhaustive": False,
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

    discovery_self_counts = {}
    for name in ("discovery", "discovery_blog", "discovery_custom"):
        assessment = bundles[name] / "assessment.json"
        identifier = "wordpress-" + name.replace("_", "-") + "-self-compare"
        stdout, _ = runner.run(identifier, [
            "report", "compare", "--before", str(assessment),
            "--after", str(assessment), "--same-scope", "--format", "json",
        ], expected_stderr_empty=True)
        document = _parse_json(stdout, f"packaged WordPress {name} self comparison")
        discovery_self_counts[name] = _group_counts(document, {
            "only_in_after": 0, "only_in_before": 0, "changed": 0,
            "unchanged": state["item_counts"][name],
        })
        wordpress = document.get("wordpress_review_comparison")
        facets = ({key: wordpress.get(key, {}) for key in (
            "methodology", "coverage", "provenance", "discovery_source_content",
        )} if isinstance(wordpress, dict) else {})
        entities = ({key: wordpress.get(key, {}) for key in (
            "components", "advisories",
        )} if isinstance(wordpress, dict) else {})
        require(isinstance(wordpress, dict)
                and wordpress.get("schema") == "termivar-wordpress-review-comparison/v2"
                and wordpress.get("status") == "compared"
                and wordpress.get("reason") is None
                and wordpress.get("scope_assurance") == "operator-declared"
                and facets["methodology"].get("status") == "unchanged"
                and facets["coverage"].get("status") == "not_established"
                and facets["provenance"].get("status") == "unchanged"
                and facets["discovery_source_content"].get("status") == "unchanged"
                and all(facet.get("changed_fields") == []
                        for facet in facets.values())
                and all(isinstance(entity, dict)
                        and entity.get("paired_changed") == []
                        and entity.get("only_in_before") == []
                        and entity.get("only_in_after") == []
                        and isinstance(entity.get("paired_unchanged_count"), int)
                        for entity in entities.values()),
                f"packaged WordPress {name} semantic self comparison changed")

    conventional = bundles["discovery_blog"] / "assessment.json"
    declared = bundles["discovery_custom"] / "assessment.json"
    stdout, _ = runner.run("wordpress-layout-methodology-coverage-compare", [
        "report", "compare", "--before", str(conventional),
        "--after", str(declared), "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    layout_comparison = _parse_json(
        stdout, "packaged WordPress layout methodology and coverage comparison")
    require(state["item_counts"]["discovery_blog"]
            == state["item_counts"]["discovery_custom"],
            "controlled WordPress layout cases changed item cardinality")
    layout_comparison_counts = _group_counts(layout_comparison, {
        "only_in_after": 0, "only_in_before": 0, "changed": 0,
        "unchanged": state["item_counts"]["discovery_blog"],
    })
    wordpress_layout = layout_comparison.get("wordpress_review_comparison")
    methodology = (wordpress_layout.get("methodology", {})
                   if isinstance(wordpress_layout, dict) else {})
    coverage = (wordpress_layout.get("coverage", {})
                if isinstance(wordpress_layout, dict) else {})
    provenance = (wordpress_layout.get("provenance", {})
                  if isinstance(wordpress_layout, dict) else {})
    source_content = (wordpress_layout.get("discovery_source_content", {})
                      if isinstance(wordpress_layout, dict) else {})
    require(isinstance(wordpress_layout, dict)
             and wordpress_layout.get("schema")
             == "termivar-wordpress-review-comparison/v2"
             and wordpress_layout.get("status") == "compared"
             and wordpress_layout.get("reason") is None
             and wordpress_layout.get("scope_assurance") == "operator-declared"
            and methodology.get("status") == "changed"
            and methodology.get("changed_fields") == ["wordpress_discovery"]
             and coverage.get("status") == "changed"
             and coverage.get("changed_fields") == ["wordpress_discovery"]
             and provenance.get("status") == "changed"
             and provenance.get("changed_fields") == ["wordpress_layout"]
             and source_content.get("status") == "changed"
             and source_content.get("changed_fields") == ["rest_indexes"],
             "controlled WordPress layout methodology/coverage comparison changed")

    fingerprint_self_counts = {}
    for name in ("fingerprint_full", "fingerprint_partial", "fingerprint_custom"):
        assessment = bundles[name] / "assessment.json"
        stdout, _ = runner.run(f"wordpress-{name.replace('_', '-')}-self-compare", [
            "report", "compare", "--before", str(assessment),
            "--after", str(assessment), "--same-scope", "--format", "json",
        ], expected_stderr_empty=True)
        document = _parse_json(
            stdout, f"packaged WordPress {name} fingerprint self comparison")
        fingerprint_self_counts[name] = _group_counts(document, {
            "only_in_after": 0, "only_in_before": 0, "changed": 0,
            "unchanged": state["item_counts"][name],
        })
        wordpress = document.get("wordpress_review_comparison")
        fingerprints = (wordpress.get("asset_fingerprints", {})
                        if isinstance(wordpress, dict) else {})
        require(isinstance(wordpress, dict)
                and wordpress.get("schema") == "termivar-wordpress-review-comparison/v3"
                and wordpress.get("status") == "compared"
                and fingerprints.get("status") == "compared"
                and all(fingerprints.get(facet, {}).get("status") == "unchanged"
                        for facet in ("methodology", "catalogue", "coverage"))
                and fingerprints.get("resources", {}).get("paired_unchanged_count") == 2
                and fingerprints.get("components", {}).get("paired_unchanged_count") == 1
                and all(not fingerprints.get(entity, {}).get(group)
                        for entity in ("resources", "components")
                        for group in ("paired_changed", "only_in_before", "only_in_after")),
                f"packaged WordPress {name} fingerprint self comparison changed")

    full = bundles["fingerprint_full"] / "assessment.json"
    partial = bundles["fingerprint_partial"] / "assessment.json"
    stdout, _ = runner.run("wordpress-fingerprint-catalogue-compare", [
        "report", "compare", "--before", str(full), "--after", str(partial),
        "--same-scope", "--format", "json",
    ], expected_stderr_empty=True)
    fingerprint_comparison = _parse_json(
        stdout, "packaged WordPress fingerprint catalogue comparison")
    require(state["item_counts"]["fingerprint_full"]
            == state["item_counts"]["fingerprint_partial"],
            "controlled fingerprint cases changed item cardinality")
    fingerprint_comparison_counts = _group_counts(fingerprint_comparison, {
        "only_in_after": 0, "only_in_before": 0, "changed": 0,
        "unchanged": state["item_counts"]["fingerprint_full"],
    })
    wordpress_fingerprint = fingerprint_comparison.get("wordpress_review_comparison")
    fingerprints = (wordpress_fingerprint.get("asset_fingerprints", {})
                    if isinstance(wordpress_fingerprint, dict) else {})
    component_changes = fingerprints.get("components", {}).get("paired_changed", [])
    require(isinstance(wordpress_fingerprint, dict)
            and wordpress_fingerprint.get("schema")
            == "termivar-wordpress-review-comparison/v3"
            and wordpress_fingerprint.get("status") == "compared"
            and fingerprints.get("status") == "compared"
            and fingerprints.get("methodology", {}).get("status") == "unchanged"
            and fingerprints.get("catalogue", {}).get("status") == "changed"
            and fingerprints.get("coverage", {}).get("status") == "unchanged"
            and fingerprints.get("resources", {}).get("paired_unchanged_count") == 2
            and isinstance(component_changes, list) and len(component_changes) == 1
            and {"candidate_set", "reference_matrix", "resource_coverage"}
            <= set(component_changes[0].get("changed_dimensions", [])),
            "controlled fingerprint catalogue/candidate comparison changed")

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
        "groups_by_case": discovery_self_counts,
        "input_mutation": False,
    }
    public["layout_comparison"] = {
        "groups": layout_comparison_counts,
        "methodology": "changed",
        "coverage": "changed",
        "provenance": provenance["status"],
        "discovery_source_content": source_content["status"],
        "input_or_bundle_mutation": False,
    }
    public["asset_fingerprints"]["self_comparison"] = {
        "groups_by_case": fingerprint_self_counts,
        "input_mutation": False,
    }
    public["asset_fingerprints"]["catalogue_comparison"] = {
        "groups": fingerprint_comparison_counts,
        "methodology": "unchanged",
        "catalogue": "changed",
        "coverage": "component_resource_coverage_changed",
        "resource_bytes": "unchanged",
        "candidate_set": "changed",
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
        with _wordpress_fingerprint_fixture() as fixture:
            runner.fixture = fixture
            wordpress_state = _run_wordpress_fingerprint_acceptance(
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
