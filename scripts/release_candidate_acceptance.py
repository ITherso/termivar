#!/usr/bin/env python3
"""Accept one native Termivar release-candidate archive and its packaged CLI.

Python 3.12.4+, standard library only. The caller supplies one locally built
archive and closed workflow identity declarations. This helper neither builds
nor downloads software, and its hashes identify candidate bytes without
authenticating source, tag, or release provenance.
"""

from __future__ import annotations

import argparse
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
)
EXCLUDED_FEATURES = (
    "api-adapter",
    "legacy-scanner",
    "proxy-adapter",
    "ssrf-oast-review",
)
ALL_FEATURES = tuple(sorted(("release-bundle", *RELEASE_MEMBERS, *EXCLUDED_FEATURES)))
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
    return {
        "schema": document["schema"],
        "runtime_execution": document["runtime_execution"],
        "composition_marker": "release-bundle",
        "compiled_members": list(RELEASE_MEMBERS),
        "excluded_features": list(EXCLUDED_FEATURES),
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
