#!/usr/bin/env python3
"""Measure bounded Wordfence import/evaluation cases and one real CLI path.

Python 3.11+, standard library only. Inputs are original synthetic records
streamed before each measured child starts. GNU time observes a fresh process
for every case. The emitted evidence is bounded and path-free; it is not a heap
profile, vendor-feed validation, source authentication, or a performance SLA.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import html
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterable


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))
import first_use as first_use_support  # noqa: E402


SCHEMA = "termivar-wordpress-resource-acceptance/v1"
PROBE_SCHEMA = "termivar-wordpress-resource-probe/v1"
RESULT_LIMIT = 64 * 1024
PROBE_RESULT_LIMIT = 64 * 1024
CAPTURE_LIMIT = 512 * 1024
REPORT_LIMIT = 16 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 300.0
MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_RETAINED_BYTES = 64 * 1024 * 1024
MAX_SOURCE_RECORDS = 100_000
MAX_SELECTED_ASSOCIATIONS = 4_096
EXPECTED_PROFILE = "numeric-dotted/v1"
EXPECTED_LOOPBACK_REQUESTS = 5
IDENTITY_LIMIT = (
    "source ref and hashes identify supplied bytes; they are not signatures or attestations"
)
MEASUREMENT_PROVIDER = "GNU time"
PEAK_MEMORY_METRIC = "maximum resident set size"
PEAK_MEMORY_UNIT = "KiB"
PROCESS_SCOPE = "one fresh child per case; parent generation excluded"
EVIDENCE_LIMITATIONS = (
    "All workload inputs are original synthetic records, not a Wordfence export.",
    "Peak RSS is an OS-observed whole-process high-water mark, not Rust heap attribution.",
    "The retained-index charge is policy accounting, not a process-memory ceiling.",
    "Independent process peaks cannot be subtracted as exact component allocation.",
    "Passing inputs establish bounded supported-domain behavior, not full-feed completeness.",
    "Explicit interpretation is operator-selected Termivar policy, not vendor-endorsed semantics.",
)
EXPECTED_VERSION_RE = re.compile(
    r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?"
)
SHA_RE = re.compile(r"[0-9a-f]{64}")
SOURCE_RE = re.compile(r"[0-9a-f]{40}")
SAFE_TEXT_RE = re.compile(r"[A-Za-z0-9_. ()/+,:=-]{1,160}")

PROBE_NUMERIC_FIELDS = (
    "input_bytes",
    "parse_elapsed_ns",
    "evaluation_elapsed_ns",
    "parsed_records",
    "software_associations",
    "affected_ranges",
    "retained_bytes",
    "selected_associations",
    "evaluable_associations",
    "within_associations",
    "outside_associations",
    "indeterminate_associations",
    "excluded_associations",
    "selected_ranges",
    "evaluated_ranges",
)


class AcceptanceError(ValueError):
    """The evidence or observed child behavior violated the closed contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


@dataclass(frozen=True)
class CaseSpec:
    identifier: str
    mode: str
    records: int
    expected_status: str
    expected_error_code: str | None
    expected_selected: int | None
    expected_within: int | None
    purpose: str


# This literal expectation table is deliberately independent of probe output.
# sparse-65536 and sparse-81920 are pinned outcomes, not dynamically accepted.
CASE_SPECS = (
    CaseSpec("baseline", "baseline", 0, "baseline", None, None, None,
             "fresh test-process overhead without a feed"),
    CaseSpec("sparse-small", "sparse", 32, "completed", None, 1, 1,
             "small accepted import with the relevant row last"),
    CaseSpec("sparse-4096", "sparse", 4_096, "completed", None, 1, 1,
             "former native-catalogue record scale"),
    CaseSpec("sparse-16384", "sparse", 16_384, "completed", None, 1, 1,
             "larger distinct sparse snapshot"),
    CaseSpec("sparse-32768", "sparse", 32_768, "completed", None, 1, 1,
             "accepted sparse snapshot near the first effective retained bound"),
    CaseSpec("sparse-65536", "sparse", 65_536, "rejected", "retained_data_too_large", None, None,
             "larger distinct snapshot rejected by retained-index accounting"),
    CaseSpec("sparse-81920", "sparse", 81_920, "rejected", "retained_data_too_large", None, None,
             "explicit retained-index rejection without truncation"),
    CaseSpec("dense-4096", "dense", 4_096, "completed", None, 4_096, 4_096,
             "maximum accepted relevant association count"),
    CaseSpec("dense-4097", "dense", 4_097, "rejected", "result_limit_exceeded", None, None,
             "typed result-limit rejection instead of first-N selection"),
    CaseSpec("record-over-limit", "record-limit", 1, "rejected", "record_too_large", None, None,
             "one record exceeds the literal 512 KiB record ceiling"),
    CaseSpec("title-field-limit-plus-one", "field-limit", 1, "rejected", "unsupported_value", None, None,
             "one title exceeds the literal 1,024-byte semantic field ceiling"),
    CaseSpec("input-limit-plus-one", "input-limit", 0, "rejected", "input_too_large", None, None,
             "streamed raw-byte limit plus one"),
    CaseSpec("late-malformed", "late-malformed", 4_096, "rejected", "malformed_json", None, None,
             "malformed suffix after a relevant final record"),
    CaseSpec("duplicate-id", "duplicate-id", 2, "rejected", "duplicate_key", None, None,
             "duplicate root identity rejected"),
)
CASE_BY_ID = {case.identifier: case for case in CASE_SPECS}


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AcceptanceError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _exact_fields(value: Any, fields: Iterable[str], at: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{at} must be an object")
    expected = set(fields)
    actual = set(value)
    require(actual == expected, f"{at} fields differ from the closed schema")
    return value


def _integer_or_none(value: Any, at: str, *, minimum: int = 0) -> int | None:
    if value is None:
        return None
    require(not isinstance(value, bool) and isinstance(value, int) and value >= minimum,
            f"{at} must be null or an integer >= {minimum}")
    return value


def _finite_number(value: Any, at: str) -> float:
    require(not isinstance(value, bool) and isinstance(value, (int, float)),
            f"{at} must be numeric")
    rendered = float(value)
    require(math.isfinite(rendered) and rendered >= 0.0,
            f"{at} must be finite and non-negative")
    return rendered


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _uuid(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012x}"


def _record(index: int, slug: str) -> dict[str, Any]:
    identifier = _uuid(index)
    return {
        "id": identifier,
        "title": f"[SYNTHETIC] Resource record {index}",
        "software": [{
            "type": "plugin",
            "name": "[SYNTHETIC] Resource component",
            "slug": slug,
            "affected_versions": {
                "[1.0,2.0]": {
                    "from_version": "1.0",
                    "from_inclusive": True,
                    "to_version": "2.0",
                    "to_inclusive": True,
                }
            },
            "patched": False,
            "patched_versions": [],
            "remediation": "",
        }],
        "informational": False,
        "description": "",
        "references": [],
        "cwe": None,
        "cvss": None,
        "cve": None,
        "cve_link": None,
        "researchers": [],
        "published": None,
        "updated": None,
        "copyrights": None,
    }


class _DigestingWriter:
    def __init__(self, handle) -> None:
        self.handle = handle
        self.digest = hashlib.sha256()
        self.length = 0

    def write(self, data: bytes) -> None:
        self.handle.write(data)
        self.digest.update(data)
        self.length += len(data)


def _open_new_private(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb")


def _stream_feed(path: Path, records: int, *, dense: bool = False,
                 trailing: bytes = b"", duplicate_root_key: bool = False) -> dict[str, Any]:
    require(records > 0, "streamed feed must contain a record")
    with _open_new_private(path) as raw:
        output = _DigestingWriter(raw)
        output.write(b"{")
        for position in range(records):
            if position:
                output.write(b",")
            index = 0 if duplicate_root_key else position
            identifier = _uuid(index)
            selected = dense or position == records - 1
            slug = "selected-plugin" if selected else f"irrelevant-{position:05d}"
            key = json.dumps(identifier, ensure_ascii=True).encode("ascii")
            value = json.dumps(
                _record(index, slug),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            output.write(key)
            output.write(b":")
            output.write(value)
        output.write(b"}")
        output.write(trailing)
        raw.flush()
        os.fsync(raw.fileno())
    return {
        "bytes": output.length,
        "sha256": output.digest.hexdigest(),
        "generated_records": records,
        "distribution": "all-relevant" if dense else "one-relevant-last",
    }


def _stream_input_limit(path: Path, limit: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    total = limit + 1
    prefix = b"{}"
    require(total >= len(prefix), "test input limit is too small")
    remaining = total - len(prefix)
    chunk = b" " * min(1024 * 1024, max(1, remaining))
    with _open_new_private(path) as raw:
        output = _DigestingWriter(raw)
        output.write(prefix)
        while remaining:
            part = chunk[:min(len(chunk), remaining)]
            output.write(part)
            remaining -= len(part)
        raw.flush()
        os.fsync(raw.fileno())
    return {
        "bytes": output.length,
        "sha256": output.digest.hexdigest(),
        "generated_records": 0,
        "distribution": "streamed-padding-limit-plus-one",
    }


def _stream_single_limit_record(path: Path, mode: str) -> dict[str, Any]:
    record = _record(0, "selected-plugin")
    if mode == "record-limit":
        record["description"] = "x" * (512 * 1024)
        distribution = "record-over-limit"
    elif mode == "field-limit":
        record["title"] = "x" * 1_025
        distribution = "title-field-limit-plus-one"
    else:
        raise AcceptanceError("unknown single-record limit mode")
    identifier = _uuid(0)
    data = json.dumps(
        {identifier: record}, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return {
        **_write_private(path, data),
        "generated_records": 1,
        "distribution": distribution,
    }


def generate_case_input(case: CaseSpec, path: Path, *, input_limit: int = MAX_INPUT_BYTES) -> dict[str, Any] | None:
    if case.mode == "baseline":
        return None
    if case.mode == "sparse":
        return _stream_feed(path, case.records)
    if case.mode == "dense":
        return _stream_feed(path, case.records, dense=True)
    if case.mode in {"record-limit", "field-limit"}:
        return _stream_single_limit_record(path, case.mode)
    if case.mode == "input-limit":
        return _stream_input_limit(path, input_limit)
    if case.mode == "late-malformed":
        return _stream_feed(path, case.records, trailing=b"x")
    if case.mode == "duplicate-id":
        return _stream_feed(path, case.records, duplicate_root_key=True)
    raise AcceptanceError("unknown compiled resource case")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=2)


def run_bounded(argv: list[str], *, directory: Path, environment: dict[str, str],
                timeout: float = COMMAND_TIMEOUT_SECONDS) -> tuple[int, bytes, bytes]:
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    read_errors: list[str] = []
    readers: list[threading.Thread] = []
    try:
        process = subprocess.Popen(
            argv,
            cwd=directory,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        raise AcceptanceError("measured child could not execute") from error

    def collect(pipe, buffer: bytearray) -> None:
        try:
            while chunk := pipe.read(8192):
                available = max(0, CAPTURE_LIMIT - len(buffer))
                buffer.extend(chunk[:available])
                if len(chunk) > available:
                    overflow.set()
        except OSError:
            read_errors.append("read_failed")
        finally:
            pipe.close()

    try:
        assert process.stdout is not None and process.stderr is not None
        for pipe, buffer in zip((process.stdout, process.stderr), buffers):
            thread = threading.Thread(target=collect, args=(pipe, buffer), daemon=True)
            thread.start()
            readers.append(thread)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if overflow.is_set():
                raise AcceptanceError("measured child capture exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AcceptanceError("measured child exceeded its deadline")
            try:
                process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                pass
    finally:
        _stop_process(process)
        for thread in readers:
            thread.join(timeout=3)
    require(not any(thread.is_alive() for thread in readers), "measured child pipes did not close")
    require(not overflow.is_set(), "measured child capture exceeded its bound")
    require(not read_errors, "measured child capture failed")
    return process.returncode, bytes(buffers[0]), bytes(buffers[1])


def parse_gnu_time(path: Path) -> dict[str, float | int | str]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise AcceptanceError("GNU time evidence could not be read") from error
    require(0 < len(data) <= 4_096, "GNU time evidence size is invalid")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeError as error:
        raise AcceptanceError("GNU time evidence is not ASCII") from error
    values: dict[str, str] = {}
    for line in lines:
        if not line:
            continue
        key, separator, value = line.partition("=")
        require(bool(separator) and key not in values, "GNU time evidence is malformed or duplicated")
        values[key] = value
    expected = {"elapsed_seconds", "user_seconds", "system_seconds", "cpu_percent", "peak_rss_kib"}
    require(set(values) == expected, "GNU time evidence has missing or unknown fields")
    try:
        elapsed = float(values["elapsed_seconds"])
        user = float(values["user_seconds"])
        system = float(values["system_seconds"])
        cpu = float(values["cpu_percent"].removesuffix("%"))
        peak = int(values["peak_rss_kib"])
    except ValueError as error:
        raise AcceptanceError("GNU time evidence contains a non-numeric value") from error
    _finite_number(elapsed, "resources.elapsed_seconds")
    _finite_number(user, "resources.user_seconds")
    _finite_number(system, "resources.system_seconds")
    _finite_number(cpu, "resources.cpu_percent")
    require(peak > 0, "resources.peak_rss_kib must be positive")
    return {
        "provider": "gnu-time",
        "process_scope": "one-fresh-child",
        "elapsed_seconds": elapsed,
        "user_seconds": user,
        "system_seconds": system,
        "cpu_percent": cpu,
        "peak_rss_kib": peak,
    }


def load_bounded_json(path: Path, maximum: int) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            data = source.read(maximum + 1)
    except OSError as error:
        raise AcceptanceError("bounded result could not be read") from error
    require(0 < len(data) <= maximum, "bounded result size is invalid")
    try:
        value = json.loads(data, object_pairs_hook=_object_without_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("bounded result is not one strict JSON document") from error
    require(isinstance(value, dict), "bounded result root must be an object")
    return value


def validate_probe(probe: dict[str, Any], case: CaseSpec, input_evidence: dict[str, Any] | None) -> None:
    fields = {"schema", "case", "status", "error_code", *PROBE_NUMERIC_FIELDS}
    _exact_fields(probe, fields, "probe")
    require(probe["schema"] == PROBE_SCHEMA, "probe schema differs")
    require(probe["case"] == case.identifier, "probe case differs")
    require(probe["status"] == case.expected_status, "probe status differs from the literal oracle")
    require(probe["error_code"] == case.expected_error_code, "probe error differs from the literal oracle")
    for field in PROBE_NUMERIC_FIELDS:
        _integer_or_none(probe[field], f"probe.{field}")

    expected_bytes = None if input_evidence is None else input_evidence["bytes"]
    require(probe["input_bytes"] == expected_bytes, "probe input length differs from generated bytes")
    if case.expected_status == "baseline":
        require(all(probe[field] is None for field in PROBE_NUMERIC_FIELDS if field != "input_bytes"),
                "baseline must not claim parser/evaluator measurements")
        return

    require(probe["parse_elapsed_ns"] is not None, "input case lacks parse timing")
    if case.expected_status == "completed":
        require(probe["evaluation_elapsed_ns"] is not None, "completed case lacks evaluation timing")
        require(probe["parsed_records"] == case.records, "completed case record count differs")
        require(probe["software_associations"] == case.records, "completed association count differs")
        require(probe["affected_ranges"] == case.records, "completed range count differs")
        require(0 < probe["retained_bytes"] <= MAX_RETAINED_BYTES,
                "completed retained accounting is outside the configured bound")
        require(probe["selected_associations"] == case.expected_selected,
                "completed selected association count differs")
        require(probe["evaluable_associations"] == case.expected_selected,
                "completed evaluable association count differs")
        require(probe["within_associations"] == case.expected_within,
                "completed within count differs")
        require(probe["outside_associations"] == 0, "synthetic accepted cases must not be outside")
        require(probe["indeterminate_associations"] == 0,
                "synthetic accepted cases must not be indeterminate")
        require(probe["excluded_associations"] == case.records - case.expected_selected,
                "completed excluded association count does not reconcile")
        require(probe["selected_ranges"] == case.expected_selected,
                "completed selected range count differs")
        require(probe["evaluated_ranges"] == case.expected_selected,
                "completed evaluated range count differs")
    elif case.identifier == "dense-4097":
        require(probe["parsed_records"] == 4_097, "dense limit input was not fully parsed")
        require(probe["software_associations"] == 4_097, "dense limit association count differs")
        require(probe["affected_ranges"] == 4_097, "dense limit range count differs")
        require(probe["evaluation_elapsed_ns"] is not None, "dense result rejection was not evaluated")
        require(all(probe[field] is None for field in (
            "selected_associations", "evaluable_associations", "within_associations",
            "outside_associations", "indeterminate_associations", "excluded_associations",
            "selected_ranges", "evaluated_ranges",
        )), "failed evaluation must not publish partial result counters")
    else:
        require(probe["evaluation_elapsed_ns"] is None,
                "parse rejection must not claim evaluation timing")
        require(all(probe[field] is None for field in (
            "parsed_records", "software_associations", "affected_ranges", "retained_bytes",
            "selected_associations", "evaluable_associations", "within_associations",
            "outside_associations", "indeterminate_associations", "excluded_associations",
            "selected_ranges", "evaluated_ranges",
        )), "parse rejection must not publish partial decoded counters")


def _time_argv(executable_argv: list[str], time_path: Path) -> list[str]:
    return [
        "/usr/bin/time",
        "--quiet",
        "--format",
        "elapsed_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\ncpu_percent=%P\npeak_rss_kib=%M",
        "--output",
        str(time_path),
        *executable_argv,
    ]


def run_probe_case(case: CaseSpec, probe: Path, directory: Path,
                   base_environment: dict[str, str]) -> dict[str, Any]:
    input_path = directory / f"{case.identifier}.input.json"
    result_path = directory / f"{case.identifier}.result.json"
    time_path = directory / f"{case.identifier}.time.txt"
    input_evidence = generate_case_input(case, input_path)
    environment = base_environment.copy()
    environment["TERMIVAR_WORDPRESS_RESOURCE_CASE"] = case.identifier
    environment["TERMIVAR_WORDPRESS_RESOURCE_OUTPUT"] = str(result_path.resolve())
    if input_evidence is None:
        environment.pop("TERMIVAR_WORDPRESS_RESOURCE_INPUT", None)
    else:
        environment["TERMIVAR_WORDPRESS_RESOURCE_INPUT"] = str(input_path.resolve())
    argv = _time_argv([
        str(probe),
        "--ignored",
        "--exact",
        "resource_measurement_case",
        "--nocapture",
        "--test-threads=1",
    ], time_path)
    exit_code, _stdout, _stderr = run_bounded(
        argv,
        directory=directory,
        environment=environment,
    )
    require(exit_code == 0, f"probe case {case.identifier} failed")
    probe_result = load_bounded_json(result_path, PROBE_RESULT_LIMIT)
    validate_probe(probe_result, case, input_evidence)
    resources = parse_gnu_time(time_path)
    if input_evidence is not None:
        require(digest_file(input_path) == input_evidence["sha256"],
                "generated input changed during probe execution")
    for path in (input_path, result_path, time_path):
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise AcceptanceError("owned probe temporary cleanup failed") from error
    return {
        "id": case.identifier,
        "purpose": case.purpose,
        "synthetic": True,
        "input": input_evidence,
        "expected": {
            "status": case.expected_status,
            "error_code": case.expected_error_code,
            "generated_records": case.records,
            "selected_associations": case.expected_selected,
            "within_associations": case.expected_within,
        },
        "observed": probe_result,
        "resources": resources,
    }


def _write_private(path: Path, data: bytes) -> dict[str, Any]:
    with _open_new_private(path) as destination:
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _read_report(path: Path) -> tuple[bytes, dict[str, Any]]:
    try:
        with path.open("rb") as source:
            data = source.read(REPORT_LIMIT + 1)
    except OSError as error:
        raise AcceptanceError("CLI report could not be read") from error
    require(0 < len(data) <= REPORT_LIMIT, "CLI report exceeds its existing bound")
    try:
        document = json.loads(data, object_pairs_hook=_object_without_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("CLI report is not strict JSON") from error
    require(isinstance(document, dict), "CLI report root is not an object")
    return data, document


def _run_simple_cli(binary: Path, arguments: list[str], directory: Path,
                    environment: dict[str, str]) -> tuple[int, bytes, bytes]:
    return run_bounded([str(binary), *arguments], directory=directory, environment=environment, timeout=90.0)


@contextmanager
def _wordpress_loopback_fixture():
    """Reuse the first-use server with a fixed WordPress-shaped root document."""
    document = (
        b'<!doctype html><html><head><meta name="generator" content="WordPress 1.5">'
        b'<link rel="stylesheet" href="/wp-content/plugins/selected-plugin/style.css">'
        b'<link rel="stylesheet" href="/wp-content/themes/unselected-theme/style.css">'
        b'</head><body>bounded synthetic resource acceptance</body></html>'
    )
    expected_paths = {
        b"/",
        b"/wp-content/plugins/selected-plugin/style.css",
        b"/wp-content/themes/unselected-theme/style.css",
    }

    class ResourceHandler(first_use_support.StaticHandler):
        def handle(self) -> None:
            self.request.settimeout(1.0)
            request = bytearray()
            try:
                while b"\r\n\r\n" not in request and len(request) < first_use_support.HEADER_LIMIT:
                    chunk = self.request.recv(
                        min(1024, first_use_support.HEADER_LIMIT - len(request))
                    )
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
                    self.server.request_lines.append(first_line.decode("ascii", errors="replace"))
                if method not in (b"GET", b"HEAD"):
                    code, reason, body, category = (
                        405,
                        "Method Not Allowed",
                        first_use_support.METHOD_REFUSED,
                        "unsupported",
                    )
                elif path not in expected_paths:
                    code, reason, body, category = (
                        404,
                        "Not Found",
                        first_use_support.NOT_FOUND,
                        "unknown",
                    )
                else:
                    code, reason, body, category = 200, "OK", document, "root"
                self.server.note(category)
                headers = (
                    f"HTTP/1.1 {code} {reason}\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii")
                self.request.sendall(headers + (b"" if method == b"HEAD" else body))
            except (OSError, TimeoutError):
                return

    previous_document = first_use_support.DOCUMENT
    first_use_support.DOCUMENT = document
    fixture = first_use_support.Fixture()
    fixture.server.RequestHandlerClass = ResourceHandler
    fixture.server.request_lines = []
    try:
        with fixture:
            yield fixture
    finally:
        first_use_support.DOCUMENT = previous_document


def run_cli_acceptance(binary: Path, directory: Path, base_environment: dict[str, str],
                       expected_version: str) -> dict[str, Any]:
    feed_path = directory / "cli.synthetic-wordfence.json"
    plugins_path = directory / "cli.synthetic-plugins.json"
    bundle_path = directory / "cli-bundle"
    time_path = directory / "cli.time.txt"
    feed = _stream_feed(feed_path, 1, dense=True)
    inventory_bytes = b'[{"name":"selected-plugin","status":"active","version":"1.5"}]\n'
    inventory = _write_private(plugins_path, inventory_bytes)
    environment = base_environment.copy()
    for name in list(environment):
        if name.lower() in {"http_proxy", "https_proxy", "all_proxy"}:
            environment.pop(name)
    environment["NO_PROXY"] = "127.0.0.1,localhost"
    environment["no_proxy"] = "127.0.0.1,localhost"

    version_exit, version_stdout, _ = _run_simple_cli(binary, ["--version"], directory, environment)
    require(version_exit == 0, "feature-enabled CLI version command failed")
    try:
        version_output = version_stdout.decode("utf-8").strip()
    except UnicodeError as error:
        raise AcceptanceError("feature-enabled CLI version output is not UTF-8") from error
    require(version_output == f"termivar {expected_version}", "feature-enabled CLI version differs")

    with _wordpress_loopback_fixture() as fixture:
        before_scan = fixture.server.snapshot()
        before_trace = len(fixture.server.request_lines)
        scan_arguments = [
            "scan",
            "--profile", "web-review",
            "--format", "json",
            "--wordpress-review",
            "--wordpress-plugins-json", str(plugins_path),
            "--wordpress-advisories", str(feed_path),
            "--wordpress-advisories-format", "wordfence-v3-production",
            "--wordpress-external-version-profile", EXPECTED_PROFILE,
            "--report-dir", str(bundle_path),
            fixture.origin,
        ]
        scan_exit, scan_stdout, _scan_stderr = run_bounded(
            _time_argv([str(binary), *scan_arguments], time_path),
            directory=directory,
            environment=environment,
            timeout=120.0,
        )
        after_scan = fixture.server.snapshot()
        raw_request_counts = {
            key: after_scan[key] - before_scan[key] for key in sorted(before_scan)
        }
        require(raw_request_counts == {
            "example": 0,
            "invalid": 0,
            "root": 5,
            "unknown": 0,
            "unsupported": 0,
        }, "feature-enabled CLI request trace differs from the five-request oracle")
        scan_request_counts = raw_request_counts
        request_trace = fixture.server.request_lines[before_trace:]
        require(request_trace == [
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "HEAD /wp-content/plugins/selected-plugin/style.css HTTP/1.1",
            "HEAD /wp-content/themes/unselected-theme/style.css HTTP/1.1",
        ], "feature-enabled CLI request methods/order differ from the literal oracle")
        require(scan_exit == 0 and not scan_stdout, "feature-enabled CLI scan did not publish cleanly")
        require(scan_request_counts["root"] == EXPECTED_LOOPBACK_REQUESTS
                and all(scan_request_counts[name] == 0 for name in (
                    "example", "invalid", "unknown", "unsupported"
                )), "feature-enabled CLI did not preserve the exact request oracle")
        require(bundle_path.is_dir() and not bundle_path.is_symlink(), "CLI bundle was not created")
        require(sorted(path.name for path in bundle_path.iterdir()) == [
            "assessment.html", "assessment.json", "manifest.json"
        ], "CLI bundle layout differs")
        assessment_bytes, assessment = _read_report(bundle_path / "assessment.json")
        require(assessment.get("schema") == "venom-rendered-assessment/v1",
                "CLI assessment outer schema differs")
        wordpress = assessment.get("wordpress_review")
        require(isinstance(wordpress, dict) and wordpress.get("schema") == "security.wordpress-review-audit/v5",
                "CLI assessment did not contain the explicit-policy v5 audit")
        external = wordpress.get("external_review")
        require(isinstance(external, dict), "CLI assessment lacks external review")
        counts = external.get("counts")
        require(isinstance(counts, dict), "CLI assessment lacks external counts")
        for field, expected in {
            "parsed_records": 1,
            "software_associations": 1,
            "selected_associations": 1,
            "evaluable_associations": 1,
            "within_associations": 1,
            "outside_associations": 0,
            "indeterminate_associations": 0,
        }.items():
            require(counts.get(field) == expected, f"CLI assessment count differs for {field}")
        require(external.get("comparison_profile") == EXPECTED_PROFILE,
                "CLI assessment comparison profile differs")
        evaluations = external.get("evaluations")
        require(isinstance(evaluations, list) and len(evaluations) == 1,
                "CLI assessment evaluation count differs")
        require(evaluations[0].get("version_relation") == "within_supported_range_under_selected_policy",
                "CLI assessment did not produce the literal within-range result")

        offline_before = fixture.server.snapshot()
        verify_exit, verify_stdout, _ = _run_simple_cli(
            binary,
            ["report", "verify", "--dir", str(bundle_path), "--format", "json"],
            directory,
            environment,
        )
        require(verify_exit == 0, "CLI bundle verification failed")
        try:
            verify = json.loads(verify_stdout, object_pairs_hook=_object_without_duplicates)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AcceptanceError("CLI verification output is not strict JSON") from error
        require(isinstance(verify, dict) and verify.get("status") == "integrity_match",
                "CLI verification did not report integrity_match")

        compare_exit, compare_stdout, _ = _run_simple_cli(
            binary,
            [
                "report", "compare",
                "--before", str(bundle_path / "assessment.json"),
                "--after", str(bundle_path / "assessment.json"),
                "--same-scope", "--format", "json",
            ],
            directory,
            environment,
        )
        require(compare_exit == 0, "CLI self-comparison failed")
        try:
            comparison = json.loads(compare_stdout, object_pairs_hook=_object_without_duplicates)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise AcceptanceError("CLI comparison output is not strict JSON") from error
        require(isinstance(comparison, dict), "CLI comparison output root differs")
        for group in ("only_in_before", "only_in_after", "changed"):
            require(comparison.get(group) == [], f"CLI self-comparison populated {group}")
        unchanged = comparison.get("unchanged")
        require(isinstance(unchanged, list) and unchanged,
                "CLI self-comparison did not retain unchanged observations")
        wordpress_comparison = comparison.get("wordpress_review_comparison")
        require(isinstance(wordpress_comparison, dict), "CLI self-comparison lacks WordPress details")
        require(wordpress_comparison.get("methodology", {}).get("status") == "unchanged",
                "CLI self-comparison changed the methodology")
        require(wordpress_comparison.get("advisories", {}).get("paired_unchanged_count") == 1,
                "CLI self-comparison did not pair the external association")
        offline_after = fixture.server.snapshot()
        require(offline_after == offline_before,
                "offline Verify/Compare unexpectedly contacted the loopback fixture")

    require(digest_file(feed_path) == feed["sha256"], "CLI advisory input changed")
    require(digest_file(plugins_path) == inventory["sha256"], "CLI inventory input changed")
    resources = parse_gnu_time(time_path)
    bundle_files = []
    for name in ("assessment.html", "assessment.json", "manifest.json"):
        path = bundle_path / name
        bundle_files.append({"name": name, "bytes": path.stat().st_size, "sha256": digest_file(path)})
    for path in (feed_path, plugins_path, time_path):
        path.unlink(missing_ok=True)
    # Keep no generated bundle/feed bytes in uploaded evidence; only identities.
    for path in bundle_path.iterdir():
        path.unlink()
    bundle_path.rmdir()
    return {
        "status": "passed",
        "synthetic": True,
        "profile": EXPECTED_PROFILE,
        "binary_version_output": version_output,
        "scan_invocations": 1,
        "loopback_request_counts": scan_request_counts,
        "request_trace": request_trace,
        "wordpress_counts": {key: counts[key] for key in (
            "parsed_records", "software_associations", "selected_associations",
            "evaluable_associations", "within_associations", "outside_associations",
            "indeterminate_associations",
        )},
        "offline_request_delta": 0,
        "verify_status": "integrity_match",
        "self_compare": {
            "only_in_before": 0,
            "only_in_after": 0,
            "changed": 0,
            "unchanged": len(unchanged),
            "wordpress_paired_unchanged": 1,
        },
        "inputs": {
            "advisory": feed,
            "inventory": inventory,
            "preserved": True,
        },
        "bundle_files": bundle_files,
        "assessment_json_bytes": len(assessment_bytes),
        "resources": resources,
    }


def _safe_host_text(value: str, at: str) -> str:
    require(SAFE_TEXT_RE.fullmatch(value) is not None, f"{at} contains unsupported characters")
    return value


def new_report(source_ref: str, expected_version: str, binary: Path, probe: Path) -> dict[str, Any]:
    require(SOURCE_RE.fullmatch(source_ref) is not None, "source ref must be a lowercase full Git SHA")
    require(EXPECTED_VERSION_RE.fullmatch(expected_version) is not None, "expected version is invalid")
    return {
        "schema": SCHEMA,
        "status": "running",
        "source": {
            "source_ref": source_ref,
            "expected_version": expected_version,
            "binary_sha256": digest_file(binary),
            "probe_sha256": digest_file(probe),
            "identity_limit": IDENTITY_LIMIT,
        },
        "environment": {
            "os": _safe_host_text(platform.system() or "unknown", "environment.os"),
            "architecture": _safe_host_text(platform.machine() or "unknown", "environment.architecture"),
            "python_version": _safe_host_text(platform.python_version(), "environment.python_version"),
            "measurement_provider": MEASUREMENT_PROVIDER,
            "peak_memory_metric": PEAK_MEMORY_METRIC,
            "peak_memory_unit": PEAK_MEMORY_UNIT,
            "process_scope": PROCESS_SCOPE,
        },
        "limits": {
            "raw_input_bytes": MAX_INPUT_BYTES,
            "source_records": MAX_SOURCE_RECORDS,
            "retained_index_bytes": MAX_RETAINED_BYTES,
            "selected_associations": MAX_SELECTED_ASSOCIATIONS,
            "command_seconds_per_child": COMMAND_TIMEOUT_SECONDS,
            "capture_bytes_per_stream": CAPTURE_LIMIT,
            "evidence_document_bytes": RESULT_LIMIT,
        },
        "cases": [],
        "cli_acceptance": {"status": "not_run"},
        "real_export_acceptance": {
            "status": "not_run_no_input",
            "reason": "No authorized vendor export was supplied to this mission.",
        },
        "limitations": list(EVIDENCE_LIMITATIONS),
        "failure": None,
    }


def validate_report(report: dict[str, Any], *, complete: bool) -> None:
    _exact_fields(report, {
        "schema", "status", "source", "environment", "limits", "cases",
        "cli_acceptance", "real_export_acceptance", "limitations", "failure",
    }, "report")
    require(report["schema"] == SCHEMA, "acceptance report schema differs")
    require(report["status"] in {"running", "passed", "failed"}, "acceptance status is invalid")
    source = _exact_fields(report["source"], {
        "source_ref", "expected_version", "binary_sha256", "probe_sha256", "identity_limit",
    }, "source")
    require(SOURCE_RE.fullmatch(source["source_ref"]) is not None, "source ref is invalid")
    require(EXPECTED_VERSION_RE.fullmatch(source["expected_version"]) is not None,
            "source expected version is invalid")
    require(SHA_RE.fullmatch(source["binary_sha256"]) is not None, "binary digest is invalid")
    require(SHA_RE.fullmatch(source["probe_sha256"]) is not None, "probe digest is invalid")
    require(source["identity_limit"] == IDENTITY_LIMIT, "source identity limitation differs")
    environment = _exact_fields(report["environment"], {
        "os", "architecture", "python_version", "measurement_provider",
        "peak_memory_metric", "peak_memory_unit", "process_scope",
    }, "environment")
    for field in ("os", "architecture", "python_version"):
        _safe_host_text(environment[field], f"environment.{field}")
    require(environment == {
        "os": environment["os"],
        "architecture": environment["architecture"],
        "python_version": environment["python_version"],
        "measurement_provider": MEASUREMENT_PROVIDER,
        "peak_memory_metric": PEAK_MEMORY_METRIC,
        "peak_memory_unit": PEAK_MEMORY_UNIT,
        "process_scope": PROCESS_SCOPE,
    }, "measurement trust declarations differ")
    limits = _exact_fields(report["limits"], {
        "raw_input_bytes", "source_records", "retained_index_bytes",
        "selected_associations", "command_seconds_per_child",
        "capture_bytes_per_stream", "evidence_document_bytes",
    }, "limits")
    require(limits == {
        "raw_input_bytes": MAX_INPUT_BYTES,
        "source_records": MAX_SOURCE_RECORDS,
        "retained_index_bytes": MAX_RETAINED_BYTES,
        "selected_associations": MAX_SELECTED_ASSOCIATIONS,
        "command_seconds_per_child": COMMAND_TIMEOUT_SECONDS,
        "capture_bytes_per_stream": CAPTURE_LIMIT,
        "evidence_document_bytes": RESULT_LIMIT,
    }, "reported resource limits differ from the reviewed constants")
    require(isinstance(report["cases"], list) and len(report["cases"]) <= len(CASE_SPECS),
            "acceptance cases exceed the closed inventory")
    observed_ids = [entry.get("id") for entry in report["cases"] if isinstance(entry, dict)]
    require(observed_ids == [case.identifier for case in CASE_SPECS[:len(observed_ids)]],
            "acceptance cases are not a deterministic inventory prefix")
    for entry, case in zip(report["cases"], CASE_SPECS):
        _exact_fields(entry, {"id", "purpose", "synthetic", "input", "expected", "observed", "resources"},
                      f"case.{case.identifier}")
        require(entry["id"] == case.identifier and entry["synthetic"] is True,
                "case identity or synthetic label differs")
        require(entry["purpose"] == case.purpose, "case purpose differs")
        expected = _exact_fields(entry["expected"], {
            "status", "error_code", "generated_records", "selected_associations",
            "within_associations",
        }, f"case.{case.identifier}.expected")
        require(expected == {
            "status": case.expected_status,
            "error_code": case.expected_error_code,
            "generated_records": case.records,
            "selected_associations": case.expected_selected,
            "within_associations": case.expected_within,
        }, "case expected result differs from the literal oracle")
        if case.mode == "baseline":
            require(entry["input"] is None, "baseline must not claim an input")
        else:
            input_evidence = _exact_fields(entry["input"], {
                "bytes", "sha256", "generated_records", "distribution",
            }, f"case.{case.identifier}.input")
            require(isinstance(input_evidence["bytes"], int) and input_evidence["bytes"] > 0,
                    "case input byte length is invalid")
            require(SHA_RE.fullmatch(input_evidence["sha256"]) is not None,
                    "case input digest is invalid")
            require(input_evidence["generated_records"] == case.records,
                    "case generated record count differs")
            require(input_evidence["distribution"] in {
                "one-relevant-last", "all-relevant", "record-over-limit",
                "title-field-limit-plus-one", "streamed-padding-limit-plus-one",
            }, "case input distribution is invalid")
        validate_probe(entry["observed"], case, entry["input"])
        resources = entry["resources"]
        _exact_fields(resources, {
            "provider", "process_scope", "elapsed_seconds", "user_seconds",
            "system_seconds", "cpu_percent", "peak_rss_kib",
        }, f"case.{case.identifier}.resources")
        require(resources["provider"] == "gnu-time" and resources["process_scope"] == "one-fresh-child",
                "case resource scope differs")
        _finite_number(resources["elapsed_seconds"], "elapsed")
        _finite_number(resources["user_seconds"], "user")
        _finite_number(resources["system_seconds"], "system")
        _finite_number(resources["cpu_percent"], "cpu")
        require(isinstance(resources["peak_rss_kib"], int) and resources["peak_rss_kib"] > 0,
                "case peak RSS is invalid")
    real = _exact_fields(report["real_export_acceptance"], {"status", "reason"},
                         "real_export_acceptance")
    require(real["status"] == "not_run_no_input", "real export status overclaims supplied evidence")
    require(real["reason"] == "No authorized vendor export was supplied to this mission.",
            "real export reason differs from the scoped evidence")
    cli = report["cli_acceptance"]
    require(isinstance(cli, dict), "CLI acceptance must be an object")
    if cli.get("status") == "not_run":
        _exact_fields(cli, {"status"}, "cli_acceptance")
    elif cli.get("status") == "passed":
        _exact_fields(cli, {
            "status", "synthetic", "profile", "binary_version_output", "scan_invocations",
            "loopback_request_counts", "request_trace", "wordpress_counts", "offline_request_delta",
            "verify_status", "self_compare", "inputs", "bundle_files",
            "assessment_json_bytes", "resources",
        }, "cli_acceptance")
        require(cli["synthetic"] is True and cli["profile"] == EXPECTED_PROFILE,
                "CLI acceptance identity differs")
        require(cli["binary_version_output"] == f"termivar {source['expected_version']}",
                "CLI accepted version differs")
        require(cli["scan_invocations"] == 1 and cli["offline_request_delta"] == 0,
                "CLI invocation/request accounting differs")
        require(cli["verify_status"] == "integrity_match", "CLI Verify status differs")
        request_counts = _exact_fields(cli["loopback_request_counts"], {
            "example", "invalid", "root", "unknown", "unsupported",
        }, "cli_acceptance.loopback_request_counts")
        require(request_counts["root"] == EXPECTED_LOOPBACK_REQUESTS
                and all(request_counts[name] == 0 for name in (
                    "example", "invalid", "unknown", "unsupported"
                )), "CLI loopback request accounting differs from the five-request oracle")
        require(cli["request_trace"] == [
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "GET / HTTP/1.1",
            "HEAD /wp-content/plugins/selected-plugin/style.css HTTP/1.1",
            "HEAD /wp-content/themes/unselected-theme/style.css HTTP/1.1",
        ], "CLI request methods/order differ from the five-request oracle")
        counts = _exact_fields(cli["wordpress_counts"], {
            "parsed_records", "software_associations", "selected_associations",
            "evaluable_associations", "within_associations", "outside_associations",
            "indeterminate_associations",
        }, "cli_acceptance.wordpress_counts")
        require(counts == {
            "parsed_records": 1,
            "software_associations": 1,
            "selected_associations": 1,
            "evaluable_associations": 1,
            "within_associations": 1,
            "outside_associations": 0,
            "indeterminate_associations": 0,
        }, "CLI WordPress counts differ from the independent small-case oracle")
        self_compare = _exact_fields(cli["self_compare"], {
            "only_in_before", "only_in_after", "changed", "unchanged",
            "wordpress_paired_unchanged",
        }, "cli_acceptance.self_compare")
        require(self_compare["only_in_before"] == self_compare["only_in_after"] == self_compare["changed"] == 0,
                "CLI self-compare has a changed/one-sided group")
        require(self_compare["unchanged"] > 0 and self_compare["wordpress_paired_unchanged"] == 1,
                "CLI self-compare lacks unchanged observations")
        inputs = _exact_fields(cli["inputs"], {"advisory", "inventory", "preserved"},
                               "cli_acceptance.inputs")
        require(inputs["preserved"] is True, "CLI inputs were not preserved")
        for name in ("advisory", "inventory"):
            item = inputs[name]
            require(isinstance(item, dict) and isinstance(item.get("bytes"), int)
                    and item["bytes"] > 0 and SHA_RE.fullmatch(item.get("sha256", "")) is not None,
                    f"CLI {name} identity is invalid")
        files = cli["bundle_files"]
        require(isinstance(files, list) and [item.get("name") for item in files] == [
            "assessment.html", "assessment.json", "manifest.json"
        ], "CLI bundle file inventory differs")
        for item in files:
            _exact_fields(item, {"name", "bytes", "sha256"}, "cli_acceptance.bundle_file")
            require(isinstance(item["bytes"], int) and item["bytes"] > 0
                    and SHA_RE.fullmatch(item["sha256"]) is not None,
                    "CLI bundle file identity is invalid")
        require(isinstance(cli["assessment_json_bytes"], int) and cli["assessment_json_bytes"] > 0,
                "CLI assessment byte length is invalid")
        cli_resources = cli["resources"]
        _exact_fields(cli_resources, {
            "provider", "process_scope", "elapsed_seconds", "user_seconds",
            "system_seconds", "cpu_percent", "peak_rss_kib",
        }, "cli_acceptance.resources")
        require(cli_resources["provider"] == "gnu-time"
                and cli_resources["process_scope"] == "one-fresh-child",
                "CLI resource scope differs")
        _finite_number(cli_resources["elapsed_seconds"], "cli.elapsed")
        _finite_number(cli_resources["user_seconds"], "cli.user")
        _finite_number(cli_resources["system_seconds"], "cli.system")
        _finite_number(cli_resources["cpu_percent"], "cli.cpu")
        require(isinstance(cli_resources["peak_rss_kib"], int)
                and not isinstance(cli_resources["peak_rss_kib"], bool)
                and cli_resources["peak_rss_kib"] > 0,
                "CLI peak RSS is invalid")
    else:
        raise AcceptanceError("CLI acceptance status is invalid")
    require(report["limitations"] == list(EVIDENCE_LIMITATIONS),
            "evidence limitations differ from the reviewed trust boundary")
    require(all(isinstance(item, str) and 0 < len(item.encode("utf-8")) <= 256
                for item in report["limitations"]), "limitation text exceeds its bound")
    if report["failure"] is not None:
        failure = _exact_fields(report["failure"], {"case", "code"}, "failure")
        require(isinstance(failure["case"], str) and SAFE_TEXT_RE.fullmatch(failure["case"]),
                "failure case is unsafe")
        require(isinstance(failure["code"], str) and SAFE_TEXT_RE.fullmatch(failure["code"]),
                "failure code is unsafe")
    if complete:
        require(report["status"] == "passed", "complete evidence must be passed")
        require(len(report["cases"]) == len(CASE_SPECS), "complete evidence lacks a case")
        require(report["cli_acceptance"].get("status") == "passed", "complete evidence lacks CLI acceptance")
        require(report["failure"] is None, "complete evidence retains failure state")


def render_markdown(report: dict[str, Any]) -> str:
    source = report["source"]
    lines = [
        "# Termivar WordPress resource acceptance",
        "",
        f"Status: **{html.escape(report['status'])}**",
        "",
        f"Schema: `{SCHEMA}`",
        "",
        "These are OS-observed fresh-process measurements over synthetic inputs. "
        "They are not vendor-export acceptance, heap attribution, or a performance SLA.",
        "",
        "## Source",
        "",
        f"- Source ref: `{source['source_ref']}`",
        f"- Expected CLI version: `{source['expected_version']}`",
        f"- Binary SHA-256: `{source['binary_sha256']}`",
        f"- Probe SHA-256: `{source['probe_sha256']}`",
        "",
        "## Fresh-child measurements",
        "",
        "| Case | Expected / observed | Input bytes | Records | Selected | Retained bytes | Parse | Evaluate | Wall | User | System | CPU | Peak RSS |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in report["cases"]:
        observed = entry["observed"]
        resources = entry["resources"]
        input_bytes = 0 if entry["input"] is None else entry["input"]["bytes"]
        relation = observed["status"]
        if observed["error_code"] is not None:
            relation += f" ({observed['error_code']})"
        def shown(value: Any) -> str:
            return "not reached" if value is None else str(value)
        parse = observed["parse_elapsed_ns"]
        evaluate = observed["evaluation_elapsed_ns"]
        parse_text = "not reached" if parse is None else f"{parse / 1_000_000:.2f} ms"
        evaluate_text = "not reached" if evaluate is None else f"{evaluate / 1_000_000:.2f} ms"
        lines.append(
            f"| `{entry['id']}` | {html.escape(relation)} | {input_bytes} | "
            f"{shown(observed['parsed_records'])} | {shown(observed['selected_associations'])} | "
            f"{shown(observed['retained_bytes'])} | {parse_text} | {evaluate_text} | "
            f"{resources['elapsed_seconds']:.2f} s | "
            f"{resources['user_seconds']:.2f} s | {resources['system_seconds']:.2f} s | "
            f"{resources['cpu_percent']:.1f}% | {resources['peak_rss_kib']} KiB |"
        )
    cli = report["cli_acceptance"]
    lines.extend(["", "## Real feature-enabled CLI acceptance", ""])
    if cli.get("status") == "passed":
        counts = cli["wordpress_counts"]
        lines.extend([
            f"- One scan invocation produced a v5 explicit-policy result: "
            f"{counts['within_associations']} within, {counts['outside_associations']} outside, "
            f"{counts['indeterminate_associations']} indeterminate.",
            f"- Loopback requests during scan: {sum(cli['loopback_request_counts'].values())}; "
            "Verify/Compare request delta: 0.",
            "- Request trace: `" + "`, `".join(cli["request_trace"]) + "`.",
            f"- Bundle Verify: `{cli['verify_status']}`; self-compare unchanged observations: "
            f"{cli['self_compare']['unchanged']}.",
            f"- CLI peak RSS: {cli['resources']['peak_rss_kib']} KiB "
            f"({cli['resources']['elapsed_seconds']:.2f} s wall).",
        ])
    else:
        lines.append("The CLI acceptance path did not complete.")
    real = report["real_export_acceptance"]
    lines.extend([
        "",
        "## Real export acceptance",
        "",
        f"`{real['status']}` — {html.escape(real['reason'])}",
        "",
        "## Limits of this evidence",
        "",
        *[f"- {html.escape(item)}" for item in report["limitations"]],
    ])
    if report["failure"] is not None:
        lines.extend(["", "## Failure checkpoint", "", f"`{html.escape(str(report['failure']))}`"])
    return "\n".join(lines).rstrip() + "\n"


def _write_complete_new(path: Path, data: bytes) -> None:
    require(0 < len(data) <= RESULT_LIMIT, "evidence output exceeds its bound")
    with _open_new_private(path) as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def write_evidence_pair(report: dict[str, Any], json_output: Path, markdown_output: Path) -> None:
    require(json_output != markdown_output, "evidence outputs must be distinct")
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    markdown = render_markdown(report).encode("utf-8")
    require(len(encoded) <= RESULT_LIMIT and len(markdown) <= RESULT_LIMIT,
            "rendered evidence exceeds its bound")
    _write_complete_new(json_output, encoded)
    _write_complete_new(markdown_output, markdown)


def run_acceptance(probe: Path, binary: Path, working_directory: Path,
                   source_ref: str, expected_version: str) -> dict[str, Any]:
    require(sys.version_info >= (3, 11), "Python 3.11 or newer is required")
    require(Path("/usr/bin/time").is_file() and os.access("/usr/bin/time", os.X_OK),
            "GNU /usr/bin/time is required")
    probe = probe.resolve(strict=True)
    binary = binary.resolve(strict=True)
    require(probe.is_file() and os.access(probe, os.X_OK), "probe must be an executable regular file")
    require(binary.is_file() and os.access(binary, os.X_OK), "binary must be an executable regular file")
    base_environment = os.environ.copy()
    report = new_report(source_ref, expected_version, binary, probe)
    active_case = "setup"
    try:
        for case in CASE_SPECS:
            active_case = case.identifier
            report["cases"].append(run_probe_case(case, probe, working_directory, base_environment))
        active_case = "feature-enabled-cli"
        report["cli_acceptance"] = run_cli_acceptance(
            binary, working_directory, base_environment, expected_version
        )
        require(digest_file(binary) == report["source"]["binary_sha256"],
                "feature-enabled binary changed during acceptance")
        require(digest_file(probe) == report["source"]["probe_sha256"],
                "resource probe changed during acceptance")
        report["status"] = "passed"
    except KeyboardInterrupt:
        report["status"] = "failed"
        report["failure"] = {"case": active_case, "code": "interrupted"}
    except (AcceptanceError, first_use_support.AcceptanceError, OSError) as error:
        report["status"] = "failed"
        report["failure"] = {
            "case": active_case,
            "code": (
                "acceptance_contract_mismatch"
                if isinstance(error, AcceptanceError)
                else "loopback_fixture_failed"
                if isinstance(error, first_use_support.AcceptanceError)
                else "filesystem_io_error"
            ),
        }
    validate_report(report, complete=report["status"] == "passed")
    return report


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path,
                        help="already-built wordpress_acceptance_corpus test executable")
    parser.add_argument("--binary", required=True, type=Path,
                        help="already-built feature-enabled termivar executable")
    parser.add_argument("--work-dir", required=True, type=Path,
                        help="fresh private temporary directory owned by the wrapper")
    parser.add_argument("--source-ref", required=True,
                        help="exact lowercase source commit declaration")
    parser.add_argument("--expect-version", required=True,
                        help="exact package version expected from the CLI")
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        require(arguments.work_dir.is_dir() and not arguments.work_dir.is_symlink(),
                "work directory must be an existing regular directory")
        require(not arguments.json_output.exists() and not arguments.markdown_output.exists(),
                "evidence destinations must be new")
        require(arguments.json_output.parent == arguments.markdown_output.parent,
                "evidence destinations must share one owned directory")
        report = run_acceptance(
            arguments.probe,
            arguments.binary,
            arguments.work_dir.resolve(),
            arguments.source_ref,
            arguments.expect_version,
        )
        write_evidence_pair(report, arguments.json_output, arguments.markdown_output)
    except (AcceptanceError, OSError) as error:
        print(f"wordpress resource acceptance rejected: {error}", file=sys.stderr)
        return 1
    print("WordPress resource acceptance evidence written (synthetic; real export not run).")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
