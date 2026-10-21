"""Fail closed over the three GitHub Actions native-runtime matrix results.

This is CI orchestration, not a product report reader or runtime authority.
The workflow supplies toJSON(needs); it declares no matrix job outputs.
"""

from __future__ import annotations

import json
import os
import sys


NEEDS_ENV = "TERMIVAR_NATIVE_RUNTIME_NEEDS"
MAX_INPUT_BYTES = 16 * 1024
REQUIRED_JOBS = (
    "platform-runtime-core",
    "platform-runtime-reviews",
    "platform-runtime-protocols",
)


class NativeRuntimeGateError(ValueError):
    """An incomplete or malformed CI dependency result."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise NativeRuntimeGateError("duplicate field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise NativeRuntimeGateError("unsupported JSON constant")


def parse_needs(raw: str | None) -> object:
    if not isinstance(raw, str) or len(raw) > MAX_INPUT_BYTES:
        raise NativeRuntimeGateError("missing or oversized dependency input")
    if len(raw.encode("utf-8", "strict")) > MAX_INPUT_BYTES:
        raise NativeRuntimeGateError("oversized dependency input")
    return json.loads(
        raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant
    )


def validate_needs(document: object) -> None:
    if type(document) is not dict or set(document) != set(REQUIRED_JOBS):
        raise NativeRuntimeGateError("incorrect dependency inventory")
    for job in REQUIRED_JOBS:
        result = document[job]
        if type(result) is not dict or set(result) != {"result", "outputs"}:
            raise NativeRuntimeGateError("incorrect dependency record")
        if type(result["outputs"]) is not dict or result["outputs"]:
            raise NativeRuntimeGateError("matrix outputs are not qualification")
        if type(result["result"]) is not str or result["result"] != "success":
            raise NativeRuntimeGateError("native qualification incomplete")


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise NativeRuntimeGateError("unexpected arguments")
        validate_needs(parse_needs(os.environ.get(NEEDS_ENV)))
    except (ValueError, UnicodeError, RecursionError):
        # Never reflect dependency text or exception details into CI logs.
        print("native runtime gate: incomplete or invalid dependencies", file=sys.stderr)
        return 1
    print("native runtime gate: all three native matrices succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
