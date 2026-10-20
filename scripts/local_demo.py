#!/usr/bin/env python3
"""Demonstrate an existing Termivar CLI against its fixed benign loopback fixture.

One command creates a report bundle, stops the owned fixture, and runs the real
offline Verify and self-Compare commands. It never builds/downloads software,
accepts an arbitrary target, reads credentials, or opens a browser. Output and
captures are private local evidence, not source attestation or a security test.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import signal
import sys

import first_use
import report_bundle_example as bundle_example


SCHEMA = "termivar-local-demo-evidence/v1"  # Task evidence, not a product schema.
EVIDENCE_LIMIT = 64 * 1024
CAPTURE_LIMIT = 256 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
SOURCE_REF = re.compile(r"(?:[0-9a-fA-F]{40}|v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)")
FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
EXPECTED_SCAN_REQUESTS = {
    "root": 3, "example": 0, "unknown": 0, "unsupported": 0, "invalid": 0,
}
require = bundle_example.require


def parse_json(data: bytes, label: str) -> dict:
    try:
        data.decode("utf-8")
    except UnicodeError as error:
        raise first_use.AcceptanceError(f"{label} is not UTF-8") from error
    try:
        return bundle_example.parse_json(data, label)
    except RecursionError as error:
        raise first_use.AcceptanceError(f"{label} nesting is unsupported") from error


def assessment_identities(directory: Path, expected_count: int) -> dict[str, str]:
    data = bundle_example.read_regular_file(
        directory / "assessment.json", bundle_example.REPORT_LIMIT, "assessment JSON")
    document = parse_json(data, "assessment JSON")
    items = document.get("items")
    require(isinstance(items, list) and len(items) == expected_count and expected_count > 0,
            "fixed demo requires a nonempty, consistent source item array")
    identities = {}
    for row in items:
        require(isinstance(row, dict), "source item must be an object")
        fingerprint, capability = row.get("fingerprint"), row.get("capability_id")
        require(isinstance(fingerprint, str) and FINGERPRINT.fullmatch(fingerprint) is not None
                and isinstance(capability, str) and 0 < len(capability) <= 256,
                "source item identity is invalid")
        require(fingerprint not in identities, "source item identity is duplicated")
        require(row.get("disposition") == "informational"
                and row.get("claim_basis") == "observation",
                "fixed benign fixture must yield observation-only informational items")
        identities[fingerprint] = capability
    return identities


def validate_verification(data: bytes, bundle: dict) -> dict:
    document = parse_json(data, "Report Verify output")
    require(document.get("schema") == "termivar-report-verification/v1"
            and document.get("status") == "integrity_match"
            and document.get("reason_codes") == [],
            "Report Verify did not establish the expected integrity result")
    checks, trust = document.get("checks"), document.get("trust")
    require(isinstance(checks, dict) and isinstance(trust, dict),
            "Report Verify checks or trust record is missing")
    for name in ("layout", "manifest", "assessment_document", "assessment_summary"):
        require(checks.get(name) == "checked_matched", f"Report Verify {name} check failed")
    files = {row["name"]: row for row in bundle["files"]}
    for name, filename in (("assessment_html", "assessment.html"),
                           ("assessment_json", "assessment.json")):
        value, expected = checks.get(name), files[filename]
        require(isinstance(value, dict) and value.get("state") == "checked_matched"
                and value.get("name") == filename,
                f"Report Verify {name} check failed")
        for key in ("expected_byte_length", "observed_byte_length"):
            require(bundle_example.checked_integer(value.get(key), key) == expected["bytes"],
                    "Report Verify payload byte length differs from the bundle")
        require(value.get("expected_sha256") == expected["sha256"]
                and value.get("observed_sha256") == expected["sha256"],
                "Report Verify payload digest differs from the bundle")
    manifest = document.get("manifest")
    require(isinstance(manifest, dict)
            and manifest.get("schema") == "termivar-report-bundle/v1"
            and manifest.get("sha256") == files["manifest.json"]["sha256"]
            and manifest.get("producer_product") == "Termivar"
            and manifest.get("producer_version") == bundle["producer"]["version"]
            and manifest.get("profile") == "web-review"
            and manifest.get("assessment_status") == "complete",
            "Report Verify manifest identity differs from the bundle")
    for key in ("item_count", "subject_count"):
        require(bundle_example.checked_integer(manifest.get(key), key)
                == bundle["assessment"][key], "Report Verify source cardinality differs")
    require(trust.get("producer_source_authenticity") == "not_established",
            "Report Verify source-assurance contract changed")
    return {"schema": document["schema"], "status": document["status"],
            "producer_source_authenticity": "not_established"}


def validate_comparison(data: bytes, bundle: dict, identities: dict[str, str]) -> dict:
    counts = bundle_example.validate_self_comparison(
        data, len(identities), bundle["assessment_json_sha256"])
    document = parse_json(data, "Report Compare output")
    for name in ("before", "after"):
        value = document[name]
        count = bundle_example.checked_integer(value.get("item_count"), f"{name} item count")
        require(count == len(identities), "Report Compare source cardinality changed")
    observed = {}
    for row in document["unchanged"]:
        require(isinstance(row, dict), "self-comparison item must be an object")
        fingerprint, capability = row.get("fingerprint"), row.get("capability_id")
        require(isinstance(fingerprint, str) and fingerprint not in observed
                and fingerprint in identities and identities[fingerprint] == capability,
                "self-comparison substituted or duplicated a source identity")
        require(isinstance(row.get("before"), dict)
                and row.get("before") == row.get("after")
                and row.get("changed_fields") == [],
                "self-comparison unchanged projection is invalid")
        observed[fingerprint] = capability
    require(observed == identities, "self-comparison omitted a source identity")
    return counts


def _fixture_stopped(fixture) -> bool:
    return not fixture.thread.is_alive() and fixture.server.socket.fileno() == -1


def _failure(evidence: dict, error: BaseException) -> None:
    if evidence["status"] not in {"failed", "cancelled"}:
        evidence["status"] = "cancelled" if isinstance(error, KeyboardInterrupt) else "failed"
        evidence["failure"] = (str(error) if isinstance(error, first_use.AcceptanceError)
                               else "interrupted" if isinstance(error, KeyboardInterrupt)
                               else type(error).__name__)


def run_demo(binary_path: Path, output_path: Path, source_ref: str | None = None) -> dict:
    require(sys.version_info >= (3, 12, 4), "Python 3.12.4 or newer is required")
    require(source_ref is None or (len(source_ref) <= 128
                                  and SOURCE_REF.fullmatch(source_ref) is not None),
            "declared source ref must be a full commit SHA or exact version tag")
    require(not any(value for name, value in os.environ.items()
                    if name.lower() in {"http_proxy", "https_proxy", "all_proxy"}),
            "proxy configuration is present; demo will not change proxy policy")
    binary = bundle_example.validate_binary(binary_path)
    require(0 < binary.stat().st_size <= MAX_BINARY_BYTES,
            "explicit local binary is empty or exceeds the demo byte limit")
    binary_digest = first_use.digest_file(binary)
    output = bundle_example.validate_output_destination(output_path)
    output.mkdir(mode=0o700)
    (output / "captures").mkdir(mode=0o700)
    bundle_path = output / "bundle"
    evidence = {
        "schema": SCHEMA, "status": "running", "started_at": first_use.utc_now(),
        "binary": {"path": str(binary), "sha256_before": binary_digest,
                   "declared_source_ref": source_ref,
                   "source_identity": "operator_declared" if source_ref else "not_supplied",
                   "source_authenticity": "not_established"},
        "host": {"system": platform.system(), "machine": platform.machine(),
                 "python": platform.python_version()},
        "fixture": {"contract_sha256": first_use.fixture_description()["sha256"],
                    "stopped_before_offline": False},
        "invocations": [],
        "limits": {"command_seconds": first_use.COMMAND_TIMEOUT,
                   "capture_bytes_per_stream": CAPTURE_LIMIT,
                   "report_bytes": bundle_example.REPORT_LIMIT,
                   "manifest_bytes": bundle_example.MANIFEST_LIMIT,
                   "evidence_bytes": EVIDENCE_LIMIT, "binary_bytes": MAX_BINARY_BYTES},
        "claims": {"fixture_is_a_security_effectiveness_test": False,
                   "source_ref_is_observed_or_attested": False,
                   "s16_integrated_program_acceptance": False},
    }
    fixture = None

    def invoke(name: str, args: list[str], expected_exit: int = 0) -> tuple[bytes, bytes]:
        record = {"invocation_id": name}
        evidence["invocations"].append(record)
        stdout, stderr = first_use.run_command(
            [str(binary), *args], output, record,
            timeout=first_use.COMMAND_TIMEOUT, capture_limit=CAPTURE_LIMIT)
        require(len(stdout) <= CAPTURE_LIMIT and len(stderr) <= CAPTURE_LIMIT,
                f"{name} output exceeded its capture limit")
        require(record.get("exit_code") == expected_exit, f"{name} native exit did not match")
        return stdout, stderr

    try:
        stdout, stderr = invoke("version", ["--version"])
        version = stdout.decode("utf-8").strip()
        require(not stderr and len(version) <= 128 and version.startswith("termivar ")
                and bundle_example.SEMVER.fullmatch(version.removeprefix("termivar ")) is not None,
                "local executable did not identify a supported Termivar version")
        evidence["binary"]["observed_version_output"] = version
        fixture = first_use.Fixture()
        fixture.__enter__()
        readiness = fixture.server.snapshot()
        require(readiness == {**EXPECTED_SCAN_REQUESTS, "root": 1},
                "fixed fixture readiness accounting changed")
        stdout, _ = invoke("scan-bundle", [
            "scan", fixture.origin, "--profile", "web-review", "--report-dir", str(bundle_path)])
        require(not stdout, "bundle scan wrote unexpected stdout")
        scan_end = fixture.server.snapshot()
        scan_requests = bundle_example.request_delta(readiness, scan_end)
        require(scan_requests == EXPECTED_SCAN_REQUESTS,
                "fixed demo scan request trace differs from the reviewed fixture contract")
        bundle = bundle_example.validate_bundle(bundle_path)
        parse_json(bundle_example.read_regular_file(
            bundle_path / "manifest.json", bundle_example.MANIFEST_LIMIT, "bundle manifest"),
            "bundle manifest")
        require(bundle["producer"]["version"] == version.removeprefix("termivar "),
                "bundle producer version differs from the executed binary")
        for name in ("assessment.html", "assessment.json"):
            first_use.validate_sample(bundle_example.read_regular_file(
                bundle_path / name, bundle_example.REPORT_LIMIT, name), binary,
                html=name.endswith(".html"))
        identities = assessment_identities(bundle_path, bundle["assessment"]["item_count"])
        evidence["bundle"] = bundle
        evidence["fixture"].update(readiness_requests=readiness,
                                   scan_requests_beyond_readiness=scan_requests)
        stdout, stderr = invoke("no-overwrite", [
            "scan", fixture.origin, "--profile", "web-review", "--report-dir", str(bundle_path)], 1)
        require(not stdout and b"report bundle destination already exists" in stderr,
                "existing bundle refusal did not retain the expected contract")
        require(fixture.server.snapshot() == scan_end,
                "no-overwrite refusal contacted the fixture")
        require(bundle_example.validate_bundle(bundle_path) == bundle,
                "no-overwrite refusal changed report bytes")
        fixture.close()
        require(_fixture_stopped(fixture), "fixed fixture did not stop before offline commands")
        evidence["fixture"]["stopped_before_offline"] = True
        offline_before = fixture.server.snapshot()
        stdout, stderr = invoke("verify-bundle", [
            "report", "verify", "--dir", str(bundle_path), "--format", "json"])
        require(not stderr, "Report Verify wrote an unexpected diagnostic")
        evidence["verification"] = validate_verification(stdout, bundle)
        require(bundle_example.validate_bundle(bundle_path) == bundle,
                "Report Verify changed report bytes")
        stdout, stderr = invoke("compare-self", [
            "report", "compare", "--before", str(bundle_path / "assessment.json"),
            "--after", str(bundle_path / "assessment.json"), "--same-scope", "--format", "json"])
        require(not stderr, "Report Compare wrote an unexpected diagnostic")
        evidence["self_comparison"] = validate_comparison(stdout, bundle, identities)
        require(bundle_example.validate_bundle(bundle_path) == bundle,
                "Report Compare changed report bytes")
        require(fixture.server.snapshot() == offline_before,
                "offline commands changed fixture request accounting")
        evidence["status"] = "passed"
    except (first_use.AcceptanceError, OSError, UnicodeError, RecursionError, KeyboardInterrupt) as error:
        _failure(evidence, error)
    finally:
        if fixture is not None:
            try:
                fixture.close()
                require(_fixture_stopped(fixture), "owned fixture cleanup did not complete")
                evidence["fixture"]["cleanup"] = "stopped"
            except (first_use.AcceptanceError, OSError) as error:
                evidence["fixture"]["cleanup"] = type(error).__name__
                _failure(evidence, error)
        try:
            final_binary = bundle_example.validate_binary(binary)
            require(final_binary.stat().st_size <= MAX_BINARY_BYTES,
                    "explicit local binary grew beyond its byte limit")
            evidence["binary"]["sha256_after"] = first_use.digest_file(final_binary)
            require(evidence["binary"]["sha256_after"] == binary_digest,
                    "explicit local binary changed during the demo")
        except (first_use.AcceptanceError, OSError) as error:
            _failure(evidence, error)
        evidence["finished_at"] = first_use.utc_now()
        try:
            encoded = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
            require(len(encoded) <= EVIDENCE_LIMIT, "private demo evidence exceeds its byte limit")
            with (output / "demo-evidence.json").open("xb") as stream:
                require(stream.write(encoded) == len(encoded),
                        "private demo evidence could not be written completely")
        except (first_use.AcceptanceError, OSError) as error:
            evidence["evidence_write_error"] = type(error).__name__
            _failure(evidence, error)
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path,
                        help="existing local executable; never built or downloaded")
    parser.add_argument("--output", required=True, type=Path,
                        help="fresh private evidence directory with an existing trusted parent")
    parser.add_argument("--source-ref", help="optional operator-declared full source SHA or version tag")
    args = parser.parse_args(argv)
    try:
        result = run_demo(args.binary, args.output, args.source_ref)
    except (first_use.AcceptanceError, OSError, UnicodeError) as error:
        print(f"local-demo: {error}" if isinstance(error, first_use.AcceptanceError)
              else "local-demo: local input or output preparation failed", file=sys.stderr)
        return 1
    if result["status"] != "passed":
        print("local-demo: " + result["status"] + "; inspect private demo-evidence.json and captures", file=sys.stderr)
        return 130 if result["status"] == "cancelled" else 1
    comparison = result["self_comparison"]
    print("local-demo: passed; fixed benign loopback demonstration")
    print(f"assessment: complete; {result['bundle']['assessment']['item_count']} informational items")
    print("fixture: stopped before offline commands; no-overwrite refusal preserved bytes")
    print("Verify: integrity_match")
    print(f"self-Compare: {comparison['unchanged']} unchanged; 0 changed; 0 one-sided")
    print("report: bundle/assessment.html; private evidence: demo-evidence.json (inside --output)")
    print("This demonstrates CLI/report behavior, not security effectiveness or S16 completion.")
    return 0


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
