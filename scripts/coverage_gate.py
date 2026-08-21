#!/usr/bin/env python3
"""Measure and enforce Venom's repository-owned Rust source coverage.

The checker deliberately uses only the Python standard library.  It consumes
Tarpaulin's Cobertura XML, measures the fixed repository scope, and compares
ratios with integer cross multiplication.  The temporary ``--calibrate`` mode
is valid only while neither the checked-out commit nor the event base commit
contains an accepted baseline pointer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterable

# One read is bounded to 256 MiB + 1 byte; strict UTF-8 and DTD/ENTITY checks
# happen before the same byte snapshot feeds parsing and the evidence hash.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml


SCHEMA = "venom.coverage.v1"
RUST_TOOLCHAIN = "1.88.0"
INSTALLER_RUST_TOOLCHAIN = "1.91.0"
TARPAULIN_VERSION = "0.37.2"
RUNNER_TARGET = "x86_64-unknown-linux-gnu"
TARPAULIN_COMMAND = (
    "cargo +1.88.0 tarpaulin --locked --workspace --all-features --ignore-tests "
    "--ignore-config --out Xml --timeout 300"
)
TIMEOUT_SECONDS = 300
SCOPE_INCLUDES = ["crates/*/src/**", "xtask/src/**"]
SCOPE_EXCLUDES = [
    "test functions (--ignore-tests) and Rust paths outside the fixed include scope"
]
DEFAULT_BASELINE_POINTER = "docs/reports/coverage/accepted-baseline.txt"
DEFAULT_ARTIFACT_NAME = "coverage-evidence"
CANONICAL_REPOSITORY = "ITherso/venom"
EXPECTED_CARGO_CONFIG = b'[alias]\nxtask = "run --locked -p xtask --"\n'
MAX_COBERTURA_BYTES = 256 * 1024 * 1024
_TESTS_WORKFLOW = ".github/workflows/tests.yml"
_CALIBRATION_STEP_NAME = b"      - name: Calibrate repository coverage policy"
_ENFORCEMENT_STEP_NAME = b"      - name: Enforce repository coverage policy"
_CALIBRATION_ARGUMENTS = b" --calibrate --require-base"
_ENFORCEMENT_ARGUMENTS = b" --require-base"

_FULL_SHA = re.compile(r"[0-9a-f]{40}")
_BASELINE_NAME = re.compile(r"[0-9a-f]{7,40}\.json")
_PORTABLE_PATH = re.compile(r"[A-Za-z0-9._/-]+")
_HUNK = re.compile(
    r"^@@ -[0-9]+(?:,[0-9]+)? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?$"
)
_TARPAULIN_CFG_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:r#)?tarpaulin(?:_[A-Za-z0-9_]+)?(?![A-Za-z0-9_])"
)
_COVERAGE_OFF_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:r#)?coverage\s*\(\s*(?:r#)?off\s*\)"
)
_NO_COVERAGE_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:r#)?no_coverage(?![A-Za-z0-9_])"
)
_ATTRIBUTE_OPEN = re.compile(r"#\s*!?\s*\[")
_FORBIDDEN_XML_DECLARATION = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


class GateError(RuntimeError):
    """A fail-closed coverage input or policy error."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_safe_relative_path(value: str) -> bool:
    if not value or "\\" in value or "\x00" in value:
        return False
    if any(ord(character) < 32 for character in value):
        return False
    path = PurePosixPath(value)
    return (
        _PORTABLE_PATH.fullmatch(value) is not None
        and not path.is_absolute()
        and "." not in path.parts
        and ".." not in path.parts
        and path.as_posix() == value
    )


def in_scope(path: str) -> bool:
    """Return whether a safe repository-relative path is measured source."""

    if not _is_safe_relative_path(path) or not path.endswith(".rs"):
        return False
    parts = path.split("/")
    if len(parts) >= 3 and parts[0:2] == ["xtask", "src"]:
        return True
    return len(parts) >= 4 and parts[0] == "crates" and parts[2] == "src"


def _workspace_path(root: Path, value: str, purpose: str) -> Path:
    if not _is_safe_relative_path(value):
        raise GateError(f"{purpose} must be a safe repository-relative POSIX path: {value!r}")
    resolved_root = root.resolve()
    resolved = (resolved_root / Path(*PurePosixPath(value).parts)).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise GateError(f"{purpose} escapes the workspace: {value!r}") from error
    return resolved


def _normalise_report_path(root: Path, raw: str) -> str:
    if not raw or "\x00" in raw or any(ord(character) < 32 for character in raw):
        raise GateError(f"Cobertura contains an unsafe empty or control-character path: {raw!r}")
    raw = raw.replace("\\", "/")
    candidate = PurePosixPath(raw)
    resolved_root = root.resolve()
    if candidate.is_absolute():
        resolved = Path(str(candidate)).resolve()
        try:
            relative = resolved.relative_to(resolved_root)
        except ValueError as error:
            raise GateError(f"Cobertura path escapes the workspace: {raw!r}") from error
        value = relative.as_posix()
    else:
        if "." in candidate.parts or ".." in candidate.parts:
            raise GateError(f"Cobertura path is not canonical: {raw!r}")
        value = candidate.as_posix()
        _workspace_path(root, value, "Cobertura path")
    if not _is_safe_relative_path(value):
        raise GateError(f"Cobertura path is unsafe after normalisation: {raw!r}")
    return value


def _read_cobertura(path: Path) -> bytes:
    """Read at most one byte beyond the accepted Cobertura size."""

    try:
        with path.open("rb") as report:
            xml_bytes = report.read(MAX_COBERTURA_BYTES + 1)
    except OSError as error:
        raise GateError(f"cannot read Cobertura report {path}: {error}") from error
    if len(xml_bytes) > MAX_COBERTURA_BYTES:
        raise GateError("Cobertura report exceeds the 256 MiB parser limit")
    return xml_bytes


def parse_cobertura(
    xml_bytes: bytes, workspace_root: Path
) -> dict[str, dict[int, int]]:
    """Parse in-scope line hits from bounded Cobertura bytes, failing closed."""

    if len(xml_bytes) > MAX_COBERTURA_BYTES:
        raise GateError("Cobertura report exceeds the 256 MiB parser limit")
    try:
        xml_text = xml_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise GateError("Cobertura report must be strict UTF-8") from error
    if "\x00" in xml_text:
        raise GateError("Cobertura report must be strict UTF-8 XML without NUL bytes")
    declaration = re.match(r"\A\ufeff?<\?xml\s+([^?]*)\?>", xml_text, re.IGNORECASE)
    if declaration is not None:
        encoding = re.search(
            r"(?:^|\s)encoding\s*=\s*(['\"])([^'\"]+)\1",
            declaration.group(1),
            re.IGNORECASE,
        )
        if encoding is not None and encoding.group(2).casefold() != "utf-8":
            raise GateError("Cobertura XML declaration must specify UTF-8")
    if _FORBIDDEN_XML_DECLARATION.search(xml_text) is not None:
        raise GateError("Cobertura DTD and entity declarations are forbidden")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise GateError(f"invalid Cobertura XML: {error}") from error

    files: dict[str, dict[int, int]] = {}
    seen_files: set[str] = set()
    for class_element in root.iter():
        if class_element.tag.rsplit("}", 1)[-1] != "class":
            continue
        raw_filename = class_element.get("filename")
        if raw_filename is None:
            raise GateError("Cobertura class is missing its filename")
        filename = _normalise_report_path(workspace_root, raw_filename)
        if not in_scope(filename):
            continue
        if filename in seen_files:
            raise GateError(f"Cobertura repeats an in-scope class path: {filename}")
        seen_files.add(filename)
        lines: dict[int, int] = {}
        line_containers = [
            child
            for child in class_element
            if child.tag.rsplit("}", 1)[-1] == "lines"
        ]
        if len(line_containers) > 1:
            raise GateError(f"Cobertura repeats the class-level lines container for {filename}")
        for element in line_containers[0] if line_containers else []:
            if element.tag.rsplit("}", 1)[-1] != "line":
                continue
            raw_number = element.get("number")
            raw_hits = element.get("hits")
            if raw_number is None or not raw_number.isascii() or not raw_number.isdigit():
                raise GateError(f"Cobertura has an invalid line number in {filename}: {raw_number!r}")
            if raw_hits is None or not raw_hits.isascii() or not raw_hits.isdigit():
                raise GateError(f"Cobertura has invalid hits for {filename}:{raw_number}: {raw_hits!r}")
            if len(raw_number) > 20 or len(raw_hits) > 20:
                raise GateError(f"Cobertura numeric field is unreasonably large in {filename}")
            number = int(raw_number)
            hits = int(raw_hits)
            if number <= 0:
                raise GateError(f"Cobertura line numbers must be positive in {filename}")
            if number in lines:
                raise GateError(f"Cobertura repeats {filename}:{number}")
            lines[number] = hits
        if lines:
            files[filename] = lines

    if not files:
        raise GateError("Cobertura contains no in-scope Rust source files")
    return dict(sorted(files.items()))


def parse_unified_diff(text: str) -> dict[str, set[int]]:
    """Return new-side line numbers from a zero-context Git unified diff."""

    changed, _ = _parse_unified_diff_details(text)
    return changed


def _parse_unified_diff_details(text: str) -> tuple[dict[str, set[int]], set[str]]:
    """Return changed lines plus files for which Git emitted at least one hunk."""

    changed: dict[str, set[int]] = {}
    hunk_files: set[str] = set()
    current: str | None = None
    state = "metadata"
    for line_number, line in enumerate(text.splitlines(), 1):
        if line.startswith("diff --git "):
            current = None
            state = "metadata"
            continue
        if state == "metadata" and line.startswith("--- "):
            raw = line[4:]
            if raw != "/dev/null":
                if not raw.startswith("a/") or not _is_safe_relative_path(raw[2:]):
                    raise GateError(
                        f"diff line {line_number} contains an unsafe old-file header"
                    )
            state = "new-header"
            continue
        if state == "new-header":
            if not line.startswith("+++ "):
                raise GateError(f"diff line {line_number} is missing its new-file header")
            raw = line[4:]
            if raw == "/dev/null":
                current = None
                state = "hunks"
                continue
            if not raw.startswith("b/"):
                raise GateError(f"diff line {line_number} has an unexpected new-file prefix")
            current = raw[2:]
            if not _is_safe_relative_path(current):
                raise GateError(f"diff line {line_number} contains an unsafe path: {current!r}")
            if in_scope(current):
                changed.setdefault(current, set())
            else:
                current = None
            state = "hunks"
            continue
        if not line.startswith("@@"):
            continue
        if state != "hunks":
            raise GateError(f"diff line {line_number} has a hunk outside a file header")
        if current is None:
            continue
        match = _HUNK.fullmatch(line)
        if match is None:
            raise GateError(f"diff line {line_number} has a malformed hunk header")
        if len(match.group(1)) > 20 or (
            match.group(2) is not None and len(match.group(2)) > 20
        ):
            raise GateError(f"diff line {line_number} has an unreasonably large range")
        start = int(match.group(1))
        count = int(match.group(2)) if match.group(2) is not None else 1
        if count > 10_000_000:
            raise GateError(f"diff line {line_number} exceeds the changed-line safety limit")
        if count < 0 or (count > 0 and start <= 0):
            raise GateError(f"diff line {line_number} has an invalid new-side range")
        hunk_files.add(current)
        changed[current].update(range(start, start + count))
    if state == "new-header":
        raise GateError("diff ended before the new-file header")
    return changed, hunk_files


def ratio_at_least(
    covered: int, coverable: int, floor_covered: int, floor_coverable: int
) -> bool:
    """Compare two coverage ratios without floating-point rounding."""

    if min(covered, floor_covered) < 0 or coverable <= 0 or floor_coverable <= 0:
        raise GateError("coverage ratios require nonnegative numerators and positive denominators")
    if covered > coverable or floor_covered > floor_coverable:
        raise GateError("covered lines cannot exceed coverable lines")
    return covered * floor_coverable >= floor_covered * coverable


def _format_ratio(covered: int, coverable: int) -> str:
    if coverable == 0:
        return "N/A"
    hundredths = (covered * 10_000 + coverable // 2) // coverable
    return f"{hundredths // 100}.{hundredths % 100:02d}% ({covered}/{coverable})"


def _git(root: Path, arguments: Iterable[str], *, binary: bool = False) -> bytes | str:
    command = ["git", *arguments]
    completed = subprocess.run(
        command,
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise GateError(f"{' '.join(command)} failed: {stderr}")
    if binary:
        return completed.stdout
    try:
        return completed.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"{' '.join(command)} returned non-UTF-8 output") from error


def _resolve_commit(root: Path, value: str | None, purpose: str) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip()
    if value == "0" * 40:
        raise GateError(f"{purpose} cannot be Git's all-zero null commit")
    if value != "HEAD" and _FULL_SHA.fullmatch(value.lower()) is None:
        raise GateError(f"{purpose} must be HEAD or a full 40-character commit SHA")
    output = _git(root, ["rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}"])
    commit = str(output).strip().lower()
    if _FULL_SHA.fullmatch(commit) is None:
        raise GateError(f"{purpose} did not resolve to a full commit SHA")
    return commit


def _tracked_sources_at(root: Path, commit: str) -> list[str]:
    output = _git(
        root,
        ["ls-tree", "-r", "-z", "--name-only", commit, "--", "crates", "xtask"],
        binary=True,
    )
    assert isinstance(output, bytes)
    paths = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GateError("Git returned a non-UTF-8 tracked source path") from error
        if not _is_safe_relative_path(value):
            raise GateError(f"Git returned an unsafe tracked path: {value!r}")
        if in_scope(value):
            paths.append(value)
    return sorted(paths)


def _raw_string_end(source: str, start: int) -> int | None:
    """Return the end of a Rust raw string starting at ``start``, if any."""

    prefix_length = 0
    for prefix in ("br", "cr", "r"):
        if source.startswith(prefix, start):
            prefix_length = len(prefix)
            break
    if prefix_length == 0:
        return None
    marker = start + prefix_length
    hashes = 0
    while marker + hashes < len(source) and source[marker + hashes] == "#":
        hashes += 1
    quote = marker + hashes
    if quote >= len(source) or source[quote] != '"':
        return None
    terminator = '"' + ("#" * hashes)
    closing = source.find(terminator, quote + 1)
    if closing < 0:
        raise GateError("unterminated Rust raw string while checking coverage exclusions")
    return closing + len(terminator)


def _char_literal_end(source: str, start: int) -> int | None:
    """Return the end of a Rust character literal without confusing lifetimes."""

    value = start + 1
    if value >= len(source) or source[value] in "'\r\n":
        return None
    if source[value] != "\\":
        closing = value + 1
    elif value + 1 >= len(source):
        return None
    elif source[value + 1] == "x":
        closing = value + 4
    elif (
        source[value + 1] == "u"
        and value + 2 < len(source)
        and source[value + 2] == "{"
    ):
        brace = source.find("}", value + 3)
        if brace < 0:
            return None
        closing = brace + 1
    else:
        closing = value + 2
    if closing < len(source) and source[closing] == "'":
        return closing + 1
    return None


def _rust_code_only(source: str) -> str:
    """Mask Rust comments and literals while preserving offsets and line numbers."""

    masked = list(source)

    def mask(start: int, end: int) -> None:
        for offset in range(start, end):
            if masked[offset] not in "\r\n":
                masked[offset] = " "

    offset = 0
    while offset < len(source):
        if source.startswith("//", offset):
            end = source.find("\n", offset + 2)
            if end < 0:
                end = len(source)
            mask(offset, end)
            offset = end
            continue
        if source.startswith("/*", offset):
            depth = 1
            end = offset + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise GateError("unterminated Rust block comment while checking coverage exclusions")
            mask(offset, end)
            offset = end
            continue
        raw_end = _raw_string_end(source, offset)
        if raw_end is not None:
            mask(offset, raw_end)
            offset = raw_end
            continue
        if source[offset] == '"':
            end = offset + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == '"':
                    end += 1
                    break
                end += 1
            else:
                raise GateError("unterminated Rust string while checking coverage exclusions")
            mask(offset, end)
            offset = end
            continue
        if source[offset] == "'":
            char_end = _char_literal_end(source, offset)
            if char_end is not None:
                mask(offset, char_end)
                offset = char_end
                continue
        offset += 1
    return "".join(masked)


def _instrumentation_exclusions(source: str) -> list[tuple[int, str]]:
    """Locate coverage-suppressing Rust tokens outside comments and literals."""

    code = _rust_code_only(source)
    findings = []
    for match in _TARPAULIN_CFG_TOKEN.finditer(code):
        findings.append(
            (code.count("\n", 0, match.start()) + 1, "reserved `tarpaulin` cfg token")
        )

    search_from = 0
    while attribute := _ATTRIBUTE_OPEN.search(code, search_from):
        depth = 1
        end = attribute.end()
        while end < len(code) and depth:
            if code[end] == "[":
                depth += 1
            elif code[end] == "]":
                depth -= 1
            end += 1
        if depth:
            raise GateError("unterminated Rust attribute while checking coverage exclusions")
        body_start = attribute.end()
        body = code[body_start : end - 1]
        for pattern, description in (
            (_COVERAGE_OFF_TOKEN, "`coverage(off)` instrumentation exclusion"),
            (_NO_COVERAGE_TOKEN, "`no_coverage` instrumentation exclusion"),
        ):
            for match in pattern.finditer(body):
                absolute = body_start + match.start()
                findings.append((code.count("\n", 0, absolute) + 1, description))
        search_from = end
    return sorted(findings)


def _reject_instrumentation_exclusions(
    root: Path, commit: str, tracked_sources: Iterable[str]
) -> None:
    """Reject instrumentation exclusions in every tracked, in-scope HEAD blob."""

    violations = []
    for path in sorted(tracked_sources):
        if not in_scope(path):
            raise GateError(f"coverage exclusion scan received an out-of-scope path: {path}")
        blob = _git_blob(root, commit, path)
        if blob is None:
            raise GateError(f"tracked in-scope source is absent from the head commit: {path}")
        try:
            source = blob.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GateError(f"tracked Rust source is not UTF-8: {path}") from error
        violations.extend(
            f"{path}:{line} ({description})"
            for line, description in _instrumentation_exclusions(source)
        )
    if violations:
        raise GateError(
            "in-scope Rust source may not suppress coverage instrumentation: "
            + "; ".join(violations)
        )


def _changed_sources(root: Path, base: str, head: str) -> tuple[list[str], dict[str, set[int]]]:
    range_spec = f"{base}...{head}"
    raw_names = _git(
        root,
        [
            "-c",
            "core.quotePath=false",
            "diff",
            "--name-only",
            "-z",
            "--diff-filter=ACMR",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            "--text",
            range_spec,
            "--",
            "crates",
            "xtask",
        ],
        binary=True,
    )
    assert isinstance(raw_names, bytes)
    names: list[str] = []
    for raw in raw_names.split(b"\0"):
        if not raw:
            continue
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GateError("Git returned a non-UTF-8 changed path") from error
        if not _is_safe_relative_path(value):
            raise GateError(f"Git returned an unsafe changed path: {value!r}")
        if in_scope(value):
            names.append(value)

    diff = _git(
        root,
        [
            "-c",
            "core.quotePath=false",
            "diff",
            "--unified=0",
            "--no-ext-diff",
            "--no-color",
            "--no-renames",
            "--no-textconv",
            "--text",
            range_spec,
            "--",
            "crates",
            "xtask",
        ],
    )
    assert isinstance(diff, str)
    line_map, hunk_files = _parse_unified_diff_details(diff)
    name_set = set(names)
    unexpected = sorted(set(line_map) - name_set)
    if unexpected:
        raise GateError(f"diff hunks were not present in the changed-file list: {unexpected}")
    for name in names:
        head_blob = _git_blob(root, head, name)
        if head_blob is None:
            raise GateError(f"changed in-scope source is absent from the head commit: {name}")
        if _git_blob(root, base, name) != head_blob and name not in hunk_files:
            raise GateError(
                f"Git reported a content change for {name} without a forced-text diff hunk"
            )
        line_map.setdefault(name, set())
    return sorted(name_set), dict(sorted(line_map.items()))


def _git_blob(root: Path, commit: str, path: str) -> bytes | None:
    if not _is_safe_relative_path(path):
        raise GateError(f"baseline blob path is unsafe: {path!r}")
    spec = f"{commit}:{path}"
    exists = subprocess.run(
        ["git", "cat-file", "-e", spec],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if exists.returncode == 1 or exists.returncode == 128:
        return None
    if exists.returncode != 0:
        stderr = exists.stderr.decode("utf-8", errors="replace").strip()
        raise GateError(f"cannot inspect {spec}: {stderr}")
    output = _git(root, ["show", spec], binary=True)
    assert isinstance(output, bytes)
    return output


def _verify_coverage_cargo_config(root: Path, commit: str) -> None:
    if _git_blob(root, commit, ".cargo/config.toml") != EXPECTED_CARGO_CONFIG:
        raise GateError(
            "measured head must contain the exact reviewed .cargo/config.toml alias-only bytes"
        )
    if _git_blob(root, commit, ".cargo/config") is not None:
        raise GateError("legacy workspace-local .cargo/config is forbidden")


def _changed_paths_between(root: Path, base: str, head: str) -> list[str]:
    output = _git(
        root,
        [
            "-c",
            "core.quotePath=false",
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
            base,
            head,
            "--",
        ],
        binary=True,
    )
    assert isinstance(output, bytes)
    paths = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        try:
            path = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise GateError("Git returned a non-UTF-8 candidate-acceptance path") from error
        if not _is_safe_relative_path(path):
            raise GateError(f"Git returned an unsafe candidate-acceptance path: {path!r}")
        paths.append(path)
    return sorted(set(paths))


def _required_mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(f"accepted baseline field {name} must be an object")
    return value


def _require_exact_keys(mapping: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(mapping)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise GateError(
            f"accepted baseline field {name} has an invalid key set; "
            f"missing={missing}, unexpected={unexpected}"
        )


def _required_string(mapping: dict[str, Any], key: str, name: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise GateError(f"accepted baseline field {name}.{key} must be a nonempty string")
    return value


def _required_count(mapping: dict[str, Any], key: str, name: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GateError(f"accepted baseline field {name}.{key} must be a nonnegative integer")
    return value


def validate_baseline(record: Any, target: str) -> dict[str, Any]:
    """Validate the committed evidence schema used as a numeric floor."""

    root = _required_mapping(record, "root")
    _require_exact_keys(
        root,
        {
            "schema",
            "source",
            "tooling",
            "scope",
            "coverage",
            "cobertura",
            "provenance",
            "patch",
            "evaluation",
        },
        "root",
    )
    if root.get("schema") != SCHEMA:
        raise GateError(f"accepted baseline {target} has an unsupported schema")

    source = _required_mapping(root.get("source"), "source")
    _require_exact_keys(source, {"commit", "cargo_lock_sha256"}, "source")
    source_commit = _required_string(source, "commit", "source")
    if _FULL_SHA.fullmatch(source_commit) is None:
        raise GateError("accepted baseline source.commit must be a lowercase full SHA")
    lock_digest = _required_string(source, "cargo_lock_sha256", "source")
    if re.fullmatch(r"[0-9a-f]{64}", lock_digest) is None:
        raise GateError("accepted baseline source.cargo_lock_sha256 must be a SHA-256 digest")

    tooling = _required_mapping(root.get("tooling"), "tooling")
    _require_exact_keys(
        tooling,
        {
            "rust",
            "installer_rust",
            "tarpaulin",
            "runner_target",
            "command",
            "timeout_seconds",
        },
        "tooling",
    )
    expected_tooling = {
        "rust": RUST_TOOLCHAIN,
        "installer_rust": INSTALLER_RUST_TOOLCHAIN,
        "tarpaulin": TARPAULIN_VERSION,
        "runner_target": RUNNER_TARGET,
        "command": TARPAULIN_COMMAND,
        "timeout_seconds": TIMEOUT_SECONDS,
    }
    for key, expected in expected_tooling.items():
        if tooling.get(key) != expected:
            raise GateError(f"accepted baseline tooling.{key} must equal {expected!r}")

    scope = _required_mapping(root.get("scope"), "scope")
    _require_exact_keys(scope, {"includes", "excludes"}, "scope")
    if scope.get("includes") != SCOPE_INCLUDES or scope.get("excludes") != SCOPE_EXCLUDES:
        raise GateError("accepted baseline uses a different source-coverage scope")

    coverage = _required_mapping(root.get("coverage"), "coverage")
    _require_exact_keys(
        coverage,
        {"covered_lines", "coverable_lines", "files", "omitted_in_scope_files"},
        "coverage",
    )
    covered = _required_count(coverage, "covered_lines", "coverage")
    coverable = _required_count(coverage, "coverable_lines", "coverage")
    if coverable == 0 or covered > coverable:
        raise GateError("accepted baseline requires 0 <= covered_lines <= coverable_lines and a nonzero denominator")
    files = coverage.get("files")
    omitted = coverage.get("omitted_in_scope_files")
    if not isinstance(files, list) or not isinstance(omitted, list):
        raise GateError("accepted baseline coverage files and omissions must be arrays")
    paths: list[str] = []
    file_covered = 0
    file_coverable = 0
    for index, entry in enumerate(files):
        item = _required_mapping(entry, f"coverage.files[{index}]")
        _require_exact_keys(
            item,
            {"path", "covered_lines", "coverable_lines"},
            f"coverage.files[{index}]",
        )
        path = _required_string(item, "path", f"coverage.files[{index}]")
        if not in_scope(path):
            raise GateError(f"accepted baseline contains an unsafe or out-of-scope file: {path!r}")
        item_covered = _required_count(item, "covered_lines", f"coverage.files[{index}]")
        item_coverable = _required_count(item, "coverable_lines", f"coverage.files[{index}]")
        if item_coverable == 0 or item_covered > item_coverable:
            raise GateError(
                f"accepted baseline requires a positive per-file denominator and covered <= coverable for {path}"
            )
        paths.append(path)
        file_covered += item_covered
        file_coverable += item_coverable
    if paths != sorted(set(paths)):
        raise GateError("accepted baseline coverage files must be unique and path-sorted")
    if (file_covered, file_coverable) != (covered, coverable):
        raise GateError("accepted baseline aggregate counts do not equal its per-file counts")
    if any(not isinstance(path, str) or not in_scope(path) for path in omitted):
        raise GateError("accepted baseline omissions contain an unsafe or out-of-scope path")
    if omitted != sorted(set(omitted)) or set(paths).intersection(omitted):
        raise GateError("accepted baseline omissions must be unique, sorted, and disjoint from measured files")

    cobertura = _required_mapping(root.get("cobertura"), "cobertura")
    _require_exact_keys(cobertura, {"path", "sha256"}, "cobertura")
    digest = _required_string(cobertura, "sha256", "cobertura")
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise GateError("accepted baseline cobertura.sha256 must be a SHA-256 digest")
    if _required_string(cobertura, "path", "cobertura") != "cobertura.xml":
        raise GateError("accepted baseline cobertura.path must equal 'cobertura.xml'")

    provenance = _required_mapping(root.get("provenance"), "provenance")
    _require_exact_keys(
        provenance,
        {
            "repository",
            "run_id",
            "run_attempt",
            "artifact_name",
            "artifact_url",
        },
        "provenance",
    )
    repository = _required_string(provenance, "repository", "provenance")
    run_id = _required_string(provenance, "run_id", "provenance")
    run_attempt = _required_string(provenance, "run_attempt", "provenance")
    artifact_name = _required_string(provenance, "artifact_name", "provenance")
    artifact_url = _required_string(provenance, "artifact_url", "provenance")
    if repository != CANONICAL_REPOSITORY:
        raise GateError(
            f"accepted baseline provenance.repository must equal {CANONICAL_REPOSITORY!r}"
        )
    if (
        not run_id.isascii()
        or not run_id.isdigit()
        or int(run_id) == 0
        or not run_attempt.isascii()
        or not run_attempt.isdigit()
        or int(run_attempt) == 0
    ):
        raise GateError(
            "accepted baseline provenance must contain positive ASCII run_id and run_attempt"
        )
    if artifact_name != DEFAULT_ARTIFACT_NAME:
        raise GateError(f"accepted baseline artifact_name must be {DEFAULT_ARTIFACT_NAME!r}")
    expected_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    if artifact_url != expected_url:
        raise GateError(f"accepted baseline artifact_url must equal {expected_url!r}")

    patch = root.get("patch")
    if patch is not None:
        patch = _required_mapping(patch, "patch")
        _require_exact_keys(
            patch,
            {
                "covered_lines",
                "coverable_lines",
                "changed_in_scope_files",
                "files",
            },
            "patch",
        )
        patch_covered = _required_count(patch, "covered_lines", "patch")
        patch_coverable = _required_count(patch, "coverable_lines", "patch")
        if patch_covered > patch_coverable:
            raise GateError("accepted baseline patch covered count exceeds its coverable count")
        if not isinstance(patch.get("files"), list) or not isinstance(
            patch.get("changed_in_scope_files"), list
        ):
            raise GateError("accepted baseline patch file inventories must be arrays")
        changed_files = patch["changed_in_scope_files"]
        if any(not isinstance(path, str) or not in_scope(path) for path in changed_files):
            raise GateError("accepted baseline patch changed-file inventory is invalid")
        if changed_files != sorted(set(changed_files)):
            raise GateError("accepted baseline patch changed-file inventory must be unique and sorted")
        patch_paths: list[str] = []
        file_patch_covered = 0
        file_patch_coverable = 0
        for index, entry in enumerate(patch["files"]):
            item = _required_mapping(entry, f"patch.files[{index}]")
            _require_exact_keys(
                item,
                {"path", "covered_lines", "coverable_lines", "changed_lines"},
                f"patch.files[{index}]",
            )
            path = _required_string(item, "path", f"patch.files[{index}]")
            if path not in changed_files:
                raise GateError(f"accepted baseline patch file is not in its changed inventory: {path}")
            item_covered = _required_count(item, "covered_lines", f"patch.files[{index}]")
            item_coverable = _required_count(item, "coverable_lines", f"patch.files[{index}]")
            item_changed = _required_count(item, "changed_lines", f"patch.files[{index}]")
            if item_covered > item_coverable:
                raise GateError(f"accepted baseline patch covered count exceeds coverable count for {path}")
            if item_coverable > item_changed:
                raise GateError(
                    f"accepted baseline patch coverable count exceeds changed count for {path}"
                )
            patch_paths.append(path)
            file_patch_covered += item_covered
            file_patch_coverable += item_coverable
        if patch_paths != sorted(set(patch_paths)):
            raise GateError("accepted baseline patch files must be unique and path-sorted")
        if patch_paths != changed_files:
            raise GateError(
                "accepted baseline patch files must exactly equal its changed-file inventory"
            )
        if (file_patch_covered, file_patch_coverable) != (
            patch_covered,
            patch_coverable,
        ):
            raise GateError("accepted baseline aggregate patch counts do not equal its per-file counts")

    evaluation = _required_mapping(root.get("evaluation"), "evaluation")
    _require_exact_keys(
        evaluation,
        {"mode", "status", "baseline_record", "total", "patch"},
        "evaluation",
    )
    mode = evaluation.get("mode")
    if mode not in {"calibration", "enforcement"}:
        raise GateError("accepted baseline evaluation.mode is invalid")
    if evaluation.get("status") != "passed":
        raise GateError("accepted baseline evaluation.status must equal 'passed'")
    baseline_record = evaluation.get("baseline_record")
    if baseline_record is not None and (
        not isinstance(baseline_record, str) or not _is_safe_relative_path(baseline_record)
    ):
        raise GateError("accepted baseline evaluation.baseline_record is invalid")
    total_status = _required_string(evaluation, "total", "evaluation")
    patch_status = _required_string(evaluation, "patch", "evaluation")
    if mode == "calibration":
        expected_patch = (
            "not applicable" if patch is None else "measured; no accepted numeric floor"
        )
        if baseline_record is not None or total_status != "measured; no accepted numeric floor":
            raise GateError("accepted calibration evidence has incoherent baseline or total status")
        if patch_status != expected_patch:
            raise GateError("accepted calibration evidence has incoherent patch status")
    else:
        if baseline_record is None or total_status != "passed":
            raise GateError("accepted enforcement evidence has incoherent baseline or total status")
        if patch is None:
            expected_patch = "not applicable"
        elif patch["coverable_lines"] == 0:
            expected_patch = "not applicable (zero coverable changed lines)"
        else:
            expected_patch = "passed"
        if patch_status != expected_patch:
            raise GateError("accepted enforcement evidence has incoherent patch status")
    return root


def _is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    raise GateError(f"cannot compare baseline ancestry: {stderr}")


def load_baseline(root: Path, commit: str, pointer_path: str) -> tuple[str, dict[str, Any]] | None:
    pointer_blob = _git_blob(root, commit, pointer_path)
    if pointer_blob is None:
        return None
    try:
        pointer_text = pointer_blob.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"{pointer_path} is not UTF-8") from error
    lines = pointer_text.splitlines()
    if len(lines) != 1 or lines[0] != lines[0].strip():
        raise GateError(f"{pointer_path} must contain exactly one canonical baseline path")
    target = lines[0]
    if not _is_safe_relative_path(target):
        raise GateError(f"{pointer_path} contains an unsafe baseline path")
    target_path = PurePosixPath(target)
    if target_path.parent.as_posix() != "docs/reports/coverage" or _BASELINE_NAME.fullmatch(target_path.name) is None:
        raise GateError(f"{pointer_path} must point to docs/reports/coverage/<7-40 lowercase hex>.json")
    record_blob = _git_blob(root, commit, target)
    markdown_path = str(target_path.with_suffix(".md"))
    markdown_blob = _git_blob(root, commit, markdown_path)
    if record_blob is None or markdown_blob is None:
        raise GateError(f"accepted baseline pointer requires both {target} and {markdown_path}")
    try:
        record_text = record_blob.decode("utf-8")
        record = json.loads(record_text)
        markdown = markdown_blob.decode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError(f"accepted baseline evidence is invalid: {error}") from error
    record = validate_baseline(record, target)
    if record_text != json.dumps(record, indent=2, sort_keys=True) + "\n":
        raise GateError("accepted baseline JSON is not the deterministic canonical rendering")
    source_commit = record["source"]["commit"]
    if not source_commit.startswith(target_path.stem):
        raise GateError("accepted baseline filename must be a prefix of source.commit")
    if not _is_ancestor(root, source_commit, commit):
        raise GateError("accepted baseline source.commit is not an ancestor of the commit using it")
    lock_blob = _git_blob(root, source_commit, "Cargo.lock")
    if lock_blob is None or _sha256(lock_blob) != record["source"]["cargo_lock_sha256"]:
        raise GateError("accepted baseline Cargo.lock digest does not match source.commit")
    inventory = {
        entry["path"] for entry in record["coverage"]["files"]
    }.union(record["coverage"]["omitted_in_scope_files"])
    if inventory != set(_tracked_sources_at(root, source_commit)):
        raise GateError(
            "accepted baseline measured-file and omission inventory does not match source.commit"
        )
    if markdown != render_markdown(record):
        raise GateError("accepted baseline Markdown does not match its deterministic JSON rendering")
    return target, record


def _candidate_baseline_changed(
    head_baseline: tuple[str, dict[str, Any]] | None,
    base_baseline: tuple[str, dict[str, Any]] | None,
) -> bool:
    return head_baseline is not None and (
        base_baseline is None
        or head_baseline[0] != base_baseline[0]
        or head_baseline[1] != base_baseline[1]
    )


def _candidate_provenance_violations(
    root: Path,
    head: str,
    head_baseline: tuple[str, dict[str, Any]] | None,
    base_baseline: tuple[str, dict[str, Any]] | None,
) -> list[str]:
    """Bind first/replacement evidence to a dedicated acceptance transition."""

    if not _candidate_baseline_changed(head_baseline, base_baseline):
        return []
    assert head_baseline is not None
    source_commit = head_baseline[1]["source"]["commit"]
    changed_paths = _changed_paths_between(root, source_commit, head)
    allowed_truth_paths = {"README.md", "FEATURES.md", "mkdocs.yml"}
    unexpected = [
        path
        for path in changed_paths
        if path != _TESTS_WORKFLOW
        and path not in allowed_truth_paths
        and not path.startswith("docs/")
    ]
    violations = []
    if unexpected:
        violations.append(
            "candidate accepted baseline changed paths outside the dedicated acceptance "
            "allowlist: "
            + ", ".join(unexpected)
        )

    source_workflow = _git_blob(root, source_commit, _TESTS_WORKFLOW)
    head_workflow = _git_blob(root, head, _TESTS_WORKFLOW)
    if source_workflow is None or head_workflow is None:
        violations.append("candidate acceptance requires the tracked Tests workflow at both commits")
        return violations
    if base_baseline is None:
        if (
            source_workflow.count(_CALIBRATION_STEP_NAME) != 1
            or source_workflow.count(_CALIBRATION_ARGUMENTS) != 1
        ):
            violations.append(
                "first baseline source workflow does not contain one exact calibration invocation"
            )
        else:
            expected_workflow = source_workflow.replace(
                _CALIBRATION_STEP_NAME, _ENFORCEMENT_STEP_NAME, 1
            ).replace(_CALIBRATION_ARGUMENTS, _ENFORCEMENT_ARGUMENTS, 1)
            if head_workflow != expected_workflow:
                violations.append(
                    "first baseline acceptance must make only the exact calibration-to-enforcement workflow flip"
                )
    elif head_workflow != source_workflow:
        violations.append(
            "replacement baseline acceptance must leave the enforcement workflow byte-identical"
        )
    return violations


def _coverage_measurement(
    line_hits: dict[str, dict[int, int]], tracked_sources: list[str]
) -> tuple[dict[str, Any], list[str]]:
    tracked = set(tracked_sources)
    unexpected = sorted(set(line_hits) - tracked)
    if unexpected:
        raise GateError(f"Cobertura contains untracked in-scope source files: {unexpected}")
    files = []
    total_covered = 0
    total_coverable = 0
    for path, lines in sorted(line_hits.items()):
        coverable = len(lines)
        covered = sum(1 for hits in lines.values() if hits > 0)
        files.append(
            {
                "path": path,
                "covered_lines": covered,
                "coverable_lines": coverable,
            }
        )
        total_covered += covered
        total_coverable += coverable
    if total_coverable == 0:
        raise GateError("coverage measurement has a zero coverable-line denominator")
    omitted = sorted(tracked - set(line_hits))
    return (
        {
            "covered_lines": total_covered,
            "coverable_lines": total_coverable,
            "files": files,
            "omitted_in_scope_files": omitted,
        },
        omitted,
    )


def _patch_measurement(
    line_hits: dict[str, dict[int, int]],
    changed_files: list[str],
    changed_lines: dict[str, set[int]],
) -> tuple[dict[str, Any], list[str]]:
    missing = sorted(set(changed_files) - set(line_hits))
    files = []
    total_covered = 0
    total_coverable = 0
    for path in changed_files:
        if path not in line_hits:
            continue
        coverable_lines = sorted(set(line_hits[path]).intersection(changed_lines.get(path, set())))
        covered = sum(1 for line in coverable_lines if line_hits[path][line] > 0)
        files.append(
            {
                "path": path,
                "covered_lines": covered,
                "coverable_lines": len(coverable_lines),
                "changed_lines": len(changed_lines.get(path, set())),
            }
        )
        total_covered += covered
        total_coverable += len(coverable_lines)
    return (
        {
            "covered_lines": total_covered,
            "coverable_lines": total_coverable,
            "changed_in_scope_files": changed_files,
            "files": files,
        },
        missing,
    )


def _baseline_counts(record: dict[str, Any]) -> tuple[int, int]:
    coverage = record["coverage"]
    return coverage["covered_lines"], coverage["coverable_lines"]


def _evaluation_violations(
    coverage: dict[str, Any],
    patch: dict[str, Any] | None,
    missing_changed: list[str],
    head_baseline: tuple[str, dict[str, Any]] | None,
    base_baseline: tuple[str, dict[str, Any]] | None,
    calibrate: bool,
    candidate_provenance_violations: Iterable[str] = (),
) -> tuple[list[str], dict[str, Any]]:
    violations = list(candidate_provenance_violations)
    if missing_changed:
        violations.append(
            "Cobertura omitted changed in-scope source files: " + ", ".join(missing_changed)
        )

    if calibrate:
        if head_baseline is not None or base_baseline is not None:
            violations.append("calibration mode is forbidden once a committed accepted baseline exists")
        evaluation = {
            "mode": "calibration",
            "status": "failed" if violations else "passed",
            "baseline_record": None,
            "total": "measured; no accepted numeric floor",
            "patch": "measured; no accepted numeric floor" if patch is not None else "not applicable",
        }
        return violations, evaluation

    if head_baseline is None:
        violations.append("normal mode requires a committed accepted coverage baseline")
        evaluation = {
            "mode": "enforcement",
            "status": "failed",
            "baseline_record": None,
            "total": "not evaluated",
            "patch": "not evaluated" if patch is not None else "not applicable",
        }
        return violations, evaluation

    baseline_path, baseline = head_baseline
    baseline_covered, baseline_coverable = _baseline_counts(baseline)
    candidate_changed = _candidate_baseline_changed(head_baseline, base_baseline)
    if candidate_changed and baseline["coverage"] != coverage:
        violations.append(
            "candidate accepted baseline coverage inventory and counts do not exactly match the current measurement"
        )
    if base_baseline is not None:
        base_covered, base_coverable = _baseline_counts(base_baseline[1])
        if not ratio_at_least(baseline_covered, baseline_coverable, base_covered, base_coverable):
            violations.append("candidate accepted baseline lowers the base commit's coverage ratio")

    if not ratio_at_least(
        coverage["covered_lines"],
        coverage["coverable_lines"],
        baseline_covered,
        baseline_coverable,
    ):
        violations.append("aggregate source coverage is below the accepted baseline ratio")

    omission_floor = base_baseline[1] if base_baseline is not None else baseline
    baseline_files = {
        entry["path"] for entry in omission_floor["coverage"]["files"]
    }
    current_files = {entry["path"] for entry in coverage["files"]}
    current_sources = current_files.union(coverage["omitted_in_scope_files"])
    newly_omitted = sorted(
        set(coverage["omitted_in_scope_files"])
        - set(omission_floor["coverage"]["omitted_in_scope_files"])
    )
    lost_measured = sorted((baseline_files.intersection(current_sources)) - current_files)
    if newly_omitted:
        violations.append("new in-scope files are absent from Cobertura: " + ", ".join(newly_omitted))
    if lost_measured:
        violations.append("previously measured in-scope files disappeared from Cobertura: " + ", ".join(lost_measured))

    patch_status = "not applicable"
    if patch is not None:
        if patch["coverable_lines"] == 0:
            patch_status = "not applicable (zero coverable changed lines)"
        elif ratio_at_least(
            patch["covered_lines"],
            patch["coverable_lines"],
            baseline_covered,
            baseline_coverable,
        ):
            patch_status = "passed"
        else:
            patch_status = "failed"
            violations.append("changed-line patch coverage is below the accepted baseline ratio")

    evaluation = {
        "mode": "enforcement",
        "status": "failed" if violations else "passed",
        "baseline_record": baseline_path,
        "total": "passed" if not any("aggregate source coverage" in item for item in violations) else "failed",
        "patch": patch_status,
    }
    return violations, evaluation


def _record(
    *,
    root: Path,
    head: str,
    cobertura_path: Path,
    cobertura_bytes: bytes,
    coverage: dict[str, Any],
    patch: dict[str, Any] | None,
    evaluation: dict[str, Any],
    repository: str,
    run_id: str,
    run_attempt: str,
    artifact_name: str,
) -> dict[str, Any]:
    committed_lock = _git_blob(root, head, "Cargo.lock")
    if committed_lock is None:
        raise GateError("measured head commit does not contain Cargo.lock")
    lock_status = subprocess.run(
        ["git", "diff", "--quiet", head, "--", "Cargo.lock"],
        cwd=root,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if lock_status.returncode == 1:
        raise GateError("working-tree Cargo.lock differs from the measured head commit")
    if lock_status.returncode != 0:
        stderr = lock_status.stderr.decode("utf-8", errors="replace").strip()
        raise GateError(f"cannot verify working-tree Cargo.lock: {stderr}")
    artifact_url = (
        f"https://github.com/{repository}/actions/runs/{run_id}"
        if repository != "local" and run_id != "local"
        else "local"
    )
    return {
        "schema": SCHEMA,
        "source": {
            "commit": head,
            "cargo_lock_sha256": _sha256(committed_lock),
        },
        "tooling": {
            "rust": RUST_TOOLCHAIN,
            "installer_rust": INSTALLER_RUST_TOOLCHAIN,
            "tarpaulin": TARPAULIN_VERSION,
            "runner_target": RUNNER_TARGET,
            "command": TARPAULIN_COMMAND,
            "timeout_seconds": TIMEOUT_SECONDS,
        },
        "scope": {
            "includes": SCOPE_INCLUDES,
            "excludes": SCOPE_EXCLUDES,
        },
        "coverage": coverage,
        "cobertura": {
            "path": cobertura_path.relative_to(root.resolve()).as_posix(),
            "sha256": _sha256(cobertura_bytes),
        },
        "provenance": {
            "repository": repository,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "artifact_name": artifact_name,
            "artifact_url": artifact_url,
        },
        "patch": patch,
        "evaluation": evaluation,
    }


def render_markdown(record: dict[str, Any]) -> str:
    """Render the canonical human-readable companion for an evidence JSON."""

    coverage = record["coverage"]
    patch = record.get("patch")
    evaluation = record["evaluation"]
    lines = [
        "# Coverage evidence",
        "",
        f"- Source commit: `{record['source']['commit']}`",
        f"- Rust: `{record['tooling']['rust']}`",
        f"- Installer Rust: `{record['tooling']['installer_rust']}`",
        f"- cargo-tarpaulin: `{record['tooling']['tarpaulin']}`",
        f"- Runner target: `{record['tooling']['runner_target']}`",
        f"- Command: `{record['tooling']['command']}`",
        f"- Cargo.lock SHA-256: `{record['source']['cargo_lock_sha256']}`",
        f"- Cobertura SHA-256: `{record['cobertura']['sha256']}`",
        f"- Workflow run: `{record['provenance']['artifact_url']}`",
        f"- Artifact: `{record['provenance']['artifact_name']}`",
        "",
        "## Result",
        "",
        f"- Mode: `{evaluation['mode']}`",
        f"- Status: `{evaluation['status']}`",
        f"- Accepted baseline: `{evaluation['baseline_record'] or 'none'}`",
        f"- Aggregate: {_format_ratio(coverage['covered_lines'], coverage['coverable_lines'])}",
    ]
    if patch is None:
        lines.append("- Changed-line patch: N/A (no base comparison)")
    else:
        lines.append(
            "- Changed-line patch: "
            + _format_ratio(patch["covered_lines"], patch["coverable_lines"])
        )
    lines.extend(
        [
            "",
            "## Scope",
            "",
            "Included:",
            "",
            *[f"- `{item}`" for item in record["scope"]["includes"]],
            "",
            "Excluded from instrumentation:",
            "",
            *[f"- {item}" for item in record["scope"]["excludes"]],
            "",
            "## Per-file counts",
            "",
            "| File | Covered | Coverable | Ratio |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for item in coverage["files"]:
        lines.append(
            f"| `{item['path']}` | {item['covered_lines']} | {item['coverable_lines']} | "
            f"{_format_ratio(item['covered_lines'], item['coverable_lines'])} |"
        )
    lines.extend(["", "## Omitted in-scope files", ""])
    omitted = coverage["omitted_in_scope_files"]
    if omitted:
        lines.extend(f"- `{path}`" for path in omitted)
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def _write_summary(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8", newline="\n")


def _parse_args(arguments: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-root", default=".")
    parser.add_argument("--cobertura", default="cobertura.xml")
    parser.add_argument("--baseline-pointer", default=DEFAULT_BASELINE_POINTER)
    parser.add_argument("--summary-json", default="coverage-summary.json")
    parser.add_argument("--summary-markdown", default="coverage-summary.md")
    parser.add_argument("--base-ref", default=os.environ.get("COVERAGE_BASE_SHA"))
    parser.add_argument("--head-ref", default=os.environ.get("COVERAGE_HEAD_SHA", "HEAD"))
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--require-base", action="store_true")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "local"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "local"))
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", "local"))
    parser.add_argument("--artifact-name", default=DEFAULT_ARTIFACT_NAME)
    return parser.parse_args(arguments)


def run(arguments: list[str] | None = None) -> int:
    args = _parse_args(arguments)
    root = Path(args.workspace_root).resolve()
    if not (root / ".git").exists():
        raise GateError(f"workspace root is not a Git worktree: {root}")
    cobertura_path = _workspace_path(root, args.cobertura, "Cobertura input")
    summary_json_path = _workspace_path(root, args.summary_json, "JSON summary output")
    summary_markdown_path = _workspace_path(
        root, args.summary_markdown, "Markdown summary output"
    )
    if summary_json_path == summary_markdown_path:
        raise GateError("JSON and Markdown summary outputs must be different files")
    pointer = args.baseline_pointer
    _workspace_path(root, pointer, "accepted-baseline pointer")

    if args.require_base and (args.base_ref is None or not args.base_ref.strip()):
        raise GateError("this workflow invocation requires a nonempty base ref")
    head = _resolve_commit(root, args.head_ref, "head ref")
    assert head is not None
    checked_out_head = _resolve_commit(root, "HEAD", "checked-out HEAD")
    if checked_out_head != head:
        raise GateError("COVERAGE_HEAD_SHA does not match the checked-out HEAD commit")
    base = _resolve_commit(root, args.base_ref, "base ref")
    if base == head:
        raise GateError("base and head commits must differ")
    _verify_coverage_cargo_config(root, head)

    cobertura_bytes = _read_cobertura(cobertura_path)
    line_hits = parse_cobertura(cobertura_bytes, root)
    tracked = _tracked_sources_at(root, head)
    _reject_instrumentation_exclusions(root, head, tracked)
    coverage, _ = _coverage_measurement(line_hits, tracked)

    patch: dict[str, Any] | None = None
    missing_changed: list[str] = []
    if base is not None:
        changed_files, changed_lines = _changed_sources(root, base, head)
        patch, missing_changed = _patch_measurement(line_hits, changed_files, changed_lines)

    head_baseline = load_baseline(root, head, pointer)
    base_baseline = load_baseline(root, base, pointer) if base is not None else None
    candidate_provenance_violations = _candidate_provenance_violations(
        root, head, head_baseline, base_baseline
    )
    violations, evaluation = _evaluation_violations(
        coverage,
        patch,
        missing_changed,
        head_baseline,
        base_baseline,
        args.calibrate,
        candidate_provenance_violations,
    )
    record = _record(
        root=root,
        head=head,
        cobertura_path=cobertura_path,
        cobertura_bytes=cobertura_bytes,
        coverage=coverage,
        patch=patch,
        evaluation=evaluation,
        repository=args.repository,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        artifact_name=args.artifact_name,
    )
    _write_summary(summary_json_path, json.dumps(record, indent=2, sort_keys=True) + "\n")
    markdown = render_markdown(record)
    _write_summary(summary_markdown_path, markdown)
    if violations:
        for violation in violations:
            print(f"coverage gate: {violation}", file=sys.stderr)
        return 1
    print(
        "coverage gate: "
        f"{evaluation['mode']} {evaluation['status']}; "
        f"aggregate {_format_ratio(coverage['covered_lines'], coverage['coverable_lines'])}"
    )
    return 0


def main() -> int:
    try:
        return run()
    except GateError as error:
        print(f"coverage gate: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
