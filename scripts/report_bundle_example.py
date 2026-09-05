#!/usr/bin/env python3
"""Exercise one local Termivar report bundle against the fixed loopback fixture.

This helper accepts only an already-built local binary and a fresh local bundle
directory. It does not build or download software, accept an arbitrary target,
load credentials, or contact a public network. The emitted JSON is a bounded
recording aid, not source attestation.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

import first_use


SUMMARY_SCHEMA = "termivar-report-bundle-example-run/v1"
BUNDLE_SCHEMA = "termivar-report-bundle/v1"
COMPARISON_SCHEMA = "termivar-report-comparison/v1"
ASSESSMENT_SCHEMA = "venom-rendered-assessment/v1"
FIXED_FILES = ("assessment.html", "assessment.json", "manifest.json")
PAYLOAD_FILES = ("assessment.html", "assessment.json")
REPORT_LIMIT = 16 * 1024 * 1024
MANIFEST_LIMIT = 64 * 1024
SUMMARY_LIMIT = 64 * 1024
SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?")
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise first_use.AcceptanceError(message)


def checked_integer(value: object, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
            f"{label} must be a non-negative integer")
    return value


def parse_json(data: bytes, label: str) -> dict:
    def object_without_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise first_use.AcceptanceError(f"{label} contains a duplicate object key")
            result[key] = value
        return result

    try:
        value = json.loads(data, object_pairs_hook=object_without_duplicates)
    except first_use.AcceptanceError:
        raise
    except (UnicodeError, ValueError) as error:
        raise first_use.AcceptanceError(f"{label} is not one complete JSON document") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def read_regular_file(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise first_use.AcceptanceError(f"{label} is unavailable") from error
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(),
            f"{label} must be a regular non-link file")
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError as error:
        raise first_use.AcceptanceError(f"{label} could not be read") from error
    require(0 < len(data) <= limit, f"{label} is empty or exceeds its byte limit")
    return data


def validate_output_destination(path: Path) -> Path:
    require(path.name not in {"", ".", ".."},
            "output must name a fresh child directory")
    absolute = Path(os.path.abspath(path))
    require(not os.path.lexists(absolute), "output directory must be fresh and nonexistent")
    parent = absolute.parent
    try:
        metadata = parent.lstat()
    except OSError as error:
        raise first_use.AcceptanceError("output parent is unavailable") from error
    require(stat.S_ISDIR(metadata.st_mode) and not parent.is_symlink(),
            "output parent must be an existing non-link directory")
    return absolute


def validate_binary(path: Path) -> Path:
    try:
        supplied = path.expanduser()
        metadata = supplied.lstat()
        binary = supplied.resolve(strict=True)
    except OSError as error:
        raise first_use.AcceptanceError("explicit local binary is unavailable") from error
    require(stat.S_ISREG(metadata.st_mode) and not supplied.is_symlink(),
            "explicit local binary must be a regular non-link file")
    return binary


def request_delta(before: dict, after: dict) -> dict:
    require(before.keys() == after.keys(), "fixture request taxonomy changed")
    delta = {name: after[name] - before[name] for name in sorted(before)}
    require(all(isinstance(value, int) and value >= 0 for value in delta.values()),
            "fixture request accounting moved backwards")
    return delta


def validate_bundle(directory: Path) -> dict:
    require(directory.is_dir() and not directory.is_symlink(),
            "CLI did not publish a regular bundle directory")
    entries = sorted(directory.iterdir(), key=lambda entry: entry.name)
    require(tuple(entry.name for entry in entries) == tuple(sorted(FIXED_FILES)),
            "bundle must contain exactly the three fixed files")
    require(all(entry.is_file() and not entry.is_symlink() for entry in entries),
            "bundle entries must be regular non-link files")

    html = read_regular_file(directory / "assessment.html", REPORT_LIMIT, "assessment HTML")
    assessment_bytes = read_regular_file(
        directory / "assessment.json", REPORT_LIMIT, "assessment JSON")
    manifest_bytes = read_regular_file(
        directory / "manifest.json", MANIFEST_LIMIT, "bundle manifest")
    assessment = parse_json(assessment_bytes, "assessment JSON")
    manifest = parse_json(manifest_bytes, "bundle manifest")

    require(assessment.get("schema") == ASSESSMENT_SCHEMA,
            "bundle assessment schema is unsupported")
    require(assessment.get("profile") == "web-review"
            and assessment.get("status") == "complete",
            "bundle assessment is not a complete web-review document")
    assessment_subjects = checked_integer(
        assessment.get("subject_count"), "assessment subject count")
    assessment_items = checked_integer(assessment.get("item_count"), "assessment item count")
    items = assessment.get("items")
    require(isinstance(items, list) and len(items) == assessment_items,
            "assessment item count is inconsistent")

    require(manifest.get("schema") == BUNDLE_SCHEMA,
            "bundle manifest schema is unsupported")
    producer = manifest.get("producer")
    require(isinstance(producer, dict) and producer.get("product") == "Termivar"
            and isinstance(producer.get("version"), str)
            and SEMVER.fullmatch(producer["version"]) is not None,
            "bundle producer identity is invalid")
    manifest_assessment = manifest.get("assessment")
    require(isinstance(manifest_assessment, dict)
            and manifest_assessment.get("profile") == "web-review"
            and manifest_assessment.get("status") == "complete",
            "manifest assessment identity is invalid")
    require(checked_integer(manifest_assessment.get("subject_count"),
                            "manifest subject count") == assessment_subjects,
            "manifest subject count does not match assessment JSON")
    require(checked_integer(manifest_assessment.get("item_count"),
                            "manifest item count") == assessment_items,
            "manifest item count does not match assessment JSON")

    files = manifest.get("files")
    require(isinstance(files, list) and len(files) == 2,
            "manifest must describe exactly two payload files")
    require([entry.get("name") if isinstance(entry, dict) else None for entry in files]
            == list(PAYLOAD_FILES), "manifest payload ordering or names changed")
    expectations = {
        "assessment.html": ("html", "text/html; charset=utf-8", html),
        "assessment.json": ("json", "application/json", assessment_bytes),
    }
    summary_files = []
    for entry in files:
        require(isinstance(entry, dict), "manifest file entry must be an object")
        name = entry.get("name")
        require(name in expectations, "manifest contains an unexpected payload name")
        expected_format, expected_media, data = expectations[name]
        digest = first_use.digest_bytes(data)
        length = len(data)
        require(entry.get("format") == expected_format
                and entry.get("media_type") == expected_media,
                "manifest payload format metadata is invalid")
        require(checked_integer(entry.get("byte_length"), "manifest payload byte length")
                == length, "manifest payload byte length does not match exact bytes")
        require(isinstance(entry.get("sha256"), str)
                and LOWER_SHA256.fullmatch(entry["sha256"]) is not None
                and entry["sha256"] == digest,
                "manifest payload digest does not match exact bytes")
        summary_files.append({"name": name, "bytes": length, "sha256": digest})
    require(all(entry["name"] != "manifest.json" for entry in files),
            "manifest must not hash itself")
    summary_files.append({
        "name": "manifest.json",
        "bytes": len(manifest_bytes),
        "sha256": first_use.digest_bytes(manifest_bytes),
    })
    return {
        "producer": {"product": producer["product"], "version": producer["version"]},
        "assessment": {
            "schema": assessment["schema"],
            "profile": assessment["profile"],
            "status": assessment["status"],
            "subject_count": assessment_subjects,
            "item_count": assessment_items,
        },
        "files": summary_files,
        "assessment_json_sha256": first_use.digest_bytes(assessment_bytes),
    }


def validate_self_comparison(data: bytes, expected_items: int,
                             assessment_sha256: str) -> dict:
    document = parse_json(data, "Report Compare output")
    require(document.get("schema") == COMPARISON_SCHEMA,
            "Report Compare schema is unsupported")
    require(document.get("scope_assurance") == "operator-declared",
            "Report Compare scope assertion is missing")
    counts = {}
    for group in ("only_in_after", "only_in_before", "changed", "unchanged"):
        items = document.get(group)
        require(isinstance(items, list), f"Report Compare {group} group is invalid")
        counts[group] = len(items)
    require(counts == {
        "only_in_after": 0,
        "only_in_before": 0,
        "changed": 0,
        "unchanged": expected_items,
    }, "self-comparison did not produce unchanged items only")
    before = document.get("before")
    after = document.get("after")
    require(isinstance(before, dict) and isinstance(after, dict)
            and before.get("sha256") == assessment_sha256
            and after.get("sha256") == assessment_sha256,
            "Report Compare source hashes do not match the bundled assessment")
    return {"schema": document["schema"], **counts}


def run_example(binary_path: Path, output_path: Path) -> dict:
    require(not any(value for name, value in os.environ.items()
                    if name.lower() in {"http_proxy", "https_proxy", "all_proxy"}),
            "proxy configuration is present; helper will not change proxy policy")
    binary = validate_binary(binary_path)
    binary_sha256 = first_use.digest_file(binary)
    output = validate_output_destination(output_path)
    records = []

    with tempfile.TemporaryDirectory(prefix="termivar-report-bundle-example-") as raw_capture:
        capture_directory = Path(raw_capture)
        (capture_directory / "captures").mkdir(mode=0o700)

        def invoke(identifier: str, argv: list[str]) -> tuple[bytes, bytes]:
            record = {"invocation_id": identifier}
            records.append(record)
            stdout, stderr = first_use.run_command(
                [str(binary), *argv], capture_directory, record)
            require(record.get("exit_code") == 0, f"{identifier} command did not succeed")
            return stdout, stderr

        with first_use.Fixture() as fixture:
            readiness = fixture.server.snapshot()
            require(readiness == {
                "root": 1, "example": 0, "unknown": 0,
                "unsupported": 0, "invalid": 0,
            }, "fixture readiness accounting changed")
            scan_before = fixture.server.snapshot()
            stdout, _ = invoke("scan-bundle", [
                "scan", fixture.origin, "--profile", "web-review",
                "--report-dir", str(output),
            ])
            require(stdout == b"", "successful report bundle scan must keep stdout empty")
            scan_after = fixture.server.snapshot()
            scan_requests = request_delta(scan_before, scan_after)
            require(scan_requests == {
                "example": 0, "invalid": 0, "root": 3,
                "unknown": 0, "unsupported": 0,
            }, "bundle scan must make exactly three root requests beyond readiness")
            bundle = validate_bundle(output)

            compare_before = fixture.server.snapshot()
            comparison_stdout, comparison_stderr = invoke("compare-self", [
                "report", "compare",
                "--before", str(output / "assessment.json"),
                "--after", str(output / "assessment.json"),
                "--same-scope", "--format", "json",
            ])
            require(comparison_stderr == b"", "Report Compare emitted an unexpected diagnostic")
            compare_after = fixture.server.snapshot()
            compare_requests = request_delta(compare_before, compare_after)
            require(sum(compare_requests.values()) == 0,
                    "offline Report Compare contacted the fixture")
            comparison = validate_self_comparison(
                comparison_stdout, bundle["assessment"]["item_count"],
                bundle["assessment_json_sha256"])
            bundle_after_compare = validate_bundle(output)
            require(bundle_after_compare == bundle,
                    "offline Report Compare changed the report bundle")

    require(first_use.digest_file(binary) == binary_sha256,
            "explicit local binary changed during the example run")
    invocation_ids = [record["invocation_id"] for record in records]
    require(invocation_ids == ["scan-bundle", "compare-self"],
            "example helper must run exactly one scan followed by one comparison")

    return {
        "schema": SUMMARY_SCHEMA,
        "status": "passed",
        "binary": {
            "name": binary.name,
            "sha256": binary_sha256,
            **bundle["producer"],
        },
        "fixture": {
            "contract_sha256": first_use.fixture_description()["sha256"],
            "readiness_requests": readiness,
            "scan_requests_beyond_readiness": scan_requests,
            "scan_request_total": sum(scan_requests.values()),
            "compare_requests": compare_requests,
        },
        "bundle": {
            "assessment": bundle["assessment"],
            "files": bundle["files"],
        },
        "comparison": comparison,
        "invocations": {
            "scan": invocation_ids.count("scan-bundle"),
            "report_compare": invocation_ids.count("compare-self"),
        },
        "limits": {
            "report_bytes": REPORT_LIMIT,
            "manifest_bytes": MANIFEST_LIMIT,
            "summary_bytes": SUMMARY_LIMIT,
            "command_seconds": first_use.COMMAND_TIMEOUT,
            "capture_bytes_per_stream": first_use.CAPTURE_LIMIT,
        },
        "claims": {
            "one_assessment_supplied_both_formats": True,
            "checksums_are_authentication": False,
            "fixture_is_a_security_effectiveness_test": False,
        },
    }


def encode_summary(summary: dict) -> bytes:
    encoded = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8")
    require(len(encoded) <= SUMMARY_LIMIT, "recording summary exceeds its byte limit")
    return encoded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary", required=True, type=Path,
        help="already-built local Termivar executable; never built or downloaded")
    parser.add_argument(
        "--output", required=True, type=Path,
        help="fresh nonexistent report-bundle directory with an existing parent")
    args = parser.parse_args(argv)
    try:
        summary = run_example(args.binary, args.output)
        encoded = encode_summary(summary)
        require(sys.stdout.buffer.write(encoded) == len(encoded),
                "recording summary could not be written completely")
        sys.stdout.buffer.flush()
    except first_use.AcceptanceError as error:
        print(f"report-bundle-example: {error}", file=sys.stderr)
        return 1
    except (OSError, UnicodeError):
        print("report-bundle-example: local execution or verification failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
