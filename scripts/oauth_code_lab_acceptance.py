#!/usr/bin/env python3
"""Owned Keycloak acceptance for imported and client-initiated code sessions.

This controller is not product login automation or an OIDC verifier. It uses
an explicitly admin-prepared SSO fixture for two ephemeral users in one pinned,
isolated provider. It does NOT qualify an interactive username/password flow.
The nine historical cases hand only a bounded transaction file to Termivar.
Five separately registered V7 cases instead consume Termivar's generated private
handoff and submit a genuine form POST to its one-shot loopback listener. The
resource server independently introspects the bearer using a different client.

--validate-only checks original fixture contracts; it does NOT run Keycloak,
Docker, a CLI process, or a CMS. Actual execution requires Linux Docker and an
already built feature-enabled candidate. No public target/account is used.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import html.parser
import http.client
import http.cookiejar
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import uuid


SCHEMA = "termivar-owned-oauth-code-lab-acceptance/v1"
KEYCLOAK_VERSION = "26.8.1"
KEYCLOAK_SOURCE = "24ed1dadf3f246a555adb6d3d4a99e9b3003fb3b"
KEYCLOAK_INDEX = "sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b"
KEYCLOAK_AMD64 = "sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc"
KEYCLOAK_CONFIG = "sha256:b55801be6ce15109868bd056dc18d62d47106bfaad7ffbd1a5d804192ec98257"
KEYCLOAK_MANIFEST_BYTES = 1056
IMAGE = "quay.io/keycloak/keycloak@" + KEYCLOAK_AMD64
REALM = "termivar-owned-code"
PUBLIC_CLIENT = "termivar-owned-public"
RESOURCE_CLIENT = "termivar-owned-resource"
CONTROLLER_CLIENT = "termivar-owned-controller"
USER_IDS = {"canary-a": "00000000-0000-4000-8000-000000000001",
            "canary-b": "00000000-0000-4000-8000-000000000002"}
SCOPE = "canary-read"
REALM_PATH = "/realms/" + REALM
PROTOCOL_PATH = REALM_PATH + "/protocol/openid-connect/"
TOKEN_PATH = PROTOCOL_PATH + "token"
INTROSPECTION_PATH = TOKEN_PATH + "/introspect"
AUTH_PATH = PROTOCOL_PATH + "auth"
HEALTH = "/app/health"
RESOURCES = ("/app/private/one", "/app/private/two")
MAX_HTTP_BODY = 128 * 1024
MAX_TOKEN_BODY = 32 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_EVIDENCE = 256 * 1024
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_ALL_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_TRACE = 256
MAX_COMMAND_SECONDS = 180
SETUP_SECONDS = 180
GROUPS = ("only_in_after", "only_in_before", "changed", "unchanged")
# Literal independent scenario registry. These are not populated from output.
SCENARIOS = (
    "option-off", "valid-a", "replayed-code", "wrong-verifier",
    "wrong-b-health", "valid-b-context",
    "refresh-a", "refresh-b-context", "refresh-health-loss",
)
REFRESH_SCENARIOS = ("refresh-a", "refresh-b-context", "refresh-health-loss")
REFRESH_POSITIVE = ("refresh-a", "refresh-b-context")
# A separate V7 registry; the historical nine cases, path guard and input
# cardinalities below remain unchanged. These are frozen before any CLI run.
AUTHORIZATION_SCENARIOS = (
    "initiated-valid-a", "initiated-wrong-state", "initiated-wrong-issuer",
    "initiated-provider-error", "initiated-challenge-substitution",
)
AUTHORIZATION_CALLBACK_PATH = "/termivar/oauth/callback"
AUTHORIZATION_UNASSIGNED_SCOPE = "owned-unassigned-scope"
AUTHORIZATION_WAIT_MS = 30_000
AUTHORIZATION_EXPECTED = {
    "initiated-valid-a": {"token_posts": 1, "protected_gets": 5, "resources": 2,
                          "callback_commits": 1, "callback_outcome": "callback_committed",
                          "session_outcome": "complete"},
    "initiated-wrong-state": {"token_posts": 0, "protected_gets": 0, "resources": 0,
                              "callback_commits": 0, "callback_outcome": "response_rejected",
                              "session_outcome": "oauth_code_exchange_unavailable"},
    "initiated-wrong-issuer": {"token_posts": 0, "protected_gets": 0, "resources": 0,
                               "callback_commits": 0, "callback_outcome": "response_rejected",
                               "session_outcome": "oauth_code_exchange_unavailable"},
    "initiated-provider-error": {"token_posts": 0, "protected_gets": 0, "resources": 0,
                                 "callback_commits": 0, "callback_outcome": "provider_error",
                                 "session_outcome": "oauth_code_exchange_unavailable"},
    "initiated-challenge-substitution": {"token_posts": 1, "protected_gets": 0, "resources": 0,
                                        "callback_commits": 1, "callback_outcome": "callback_committed",
                                        "session_outcome": "oauth_code_exchange_unavailable"},
}
EXPECTED_SESSION_ROLES = {
    "option-off": (),
    "valid-a": ("health", "resource-one", "health", "resource-two", "health"),
    "replayed-code": (),
    "wrong-verifier": (),
    "wrong-b-health": ("health",),
    "valid-b-context": ("health", "resource-one", "health", "resource-two", "health"),
    "refresh-a": ("health", "resource-one", "health", "health", "resource-two", "health"),
    "refresh-b-context": ("health", "resource-one", "health", "health", "resource-two", "health"),
    "refresh-health-loss": ("health", "resource-one", "health", "health"),
}
EXPECTED_OUTCOMES = {
    "valid-a": "complete", "valid-b-context": "complete",
    "replayed-code": "oauth_code_exchange_unavailable",
    "wrong-verifier": "oauth_code_exchange_unavailable",
    "wrong-b-health": "startup_unhealthy",
    "refresh-a": "complete", "refresh-b-context": "complete", "refresh-health-loss": "session_lost",
}
EXPECTED_RESOURCES = {"option-off": 0, "valid-a": 2, "replayed-code": 0,
                      "wrong-verifier": 0, "wrong-b-health": 0, "valid-b-context": 2,
                      "refresh-a": 2, "refresh-b-context": 2, "refresh-health-loss": 1}
EXPECTED_TOKEN_POSTS = {"option-off": 0, "valid-a": 1, "replayed-code": 1,
                        "wrong-verifier": 1, "wrong-b-health": 1, "valid-b-context": 1,
                        "refresh-a": 2, "refresh-b-context": 2, "refresh-health-loss": 2}
EXPECTED_IDP_SEQUENCE = {
    "option-off": (),
    "valid-a": ("authorization_code",) + ("backend-introspection",) * 5,
    "replayed-code": ("authorization_code",), "wrong-verifier": ("authorization_code",),
    "wrong-b-health": ("authorization_code", "backend-introspection"),
    "valid-b-context": ("authorization_code",) + ("backend-introspection",) * 5,
    "refresh-a": ("authorization_code",) + ("backend-introspection",) * 3
                 + ("refresh_token",) + ("backend-introspection",) * 3,
    "refresh-b-context": ("authorization_code",) + ("backend-introspection",) * 3
                         + ("refresh_token",) + ("backend-introspection",) * 3,
    "refresh-health-loss": ("authorization_code",) + ("backend-introspection",) * 3
                          + ("refresh_token", "backend-introspection"),
}
OFFLINE_CONTROLS = (
    ("a-to-b-context", "valid-a", "valid-b-context", "different-principal"),
    ("refresh-a-to-b-context", "refresh-a", "refresh-b-context", "different-principal"),
    ("code-to-refresh-policy", "valid-a", "refresh-a", "different-policy"),
    ("refresh-health-loss", "refresh-a", "refresh-health-loss", "coverage"),
)
ASSURANCE = {
    "profile": "external-public-code-s256-bearer/v1",
    "transport_profile": "owned-numeric-loopback-http/v1",
    "transaction_context_assurance": "operator_declared_external_transaction",
    "pkce_assurance": "imported_s256_context_not_remote_enforcement",
    "token_interpretation": "opaque_bearer_not_oidc_identity",
    "authorization_initiated": False, "browser_callback_received": False,
    "state_nonce_verified": False, "oidc_identity_validation_performed": False,
    "token_signature_validation_performed": False,
}


class LabError(RuntimeError):
    """Only static, private-safe codes and pre-reduced diagnostics cross here."""

    def __init__(self, code: str, diagnostic: dict | None = None):
        super().__init__(code)
        self.code = code
        self.diagnostic = diagnostic or {}


def require(condition: bool, code: str, diagnostic: dict | None = None) -> None:
    if not condition:
        raise LabError(code, diagnostic)


def integer(value: object) -> bool:
    return type(value) is int and value >= 0


def marker(value: object) -> object:
    """Diagnostics retain absent/type errors instead of coercing them to zero."""
    if value is _MISSING:
        return {"state": "missing"}
    if value is None or type(value) in (int, bool):
        return value
    if isinstance(value, list):
        return {"type": "array", "length": len(value)}
    return {"type": type(value).__name__}


_MISSING = object()


def strict_json(source: bytes, maximum: int = MAX_OUTPUT) -> object:
    require(0 < len(source) <= maximum, "json_size")

    def pairs(rows: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in rows:
            require(key not in result, "json_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(source.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(LabError("json_number")))
    except (ValueError, UnicodeError, RecursionError):
        raise LabError("json_malformed") from None
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        require(nodes <= 32768 and depth <= 32, "json_work_limit")
        if isinstance(item, dict):
            require(all(isinstance(k, str) and len(k) <= 256 for k in item), "json_key_limit")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            require(len(item) <= MAX_HTTP_BODY, "json_string_limit")
    return value


def encoded_form(fields: dict[str, str]) -> bytes:
    return urllib.parse.urlencode(fields).encode("ascii")


def challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def validate_image_inspection(document: object) -> dict:
    """Admit two reviewed engine identity shapes, never an arbitrary image ID.

    Legacy image stores expose the pinned config ID. The containerd store
    exposes its target manifest ID and descriptor instead. Both must bind the
    same exact pulled reference, platform and non-root user. Other inspection
    fields (notably Config.Env) are neither evidence nor diagnostics.
    """
    row = document[0] if type(document) is list and len(document) == 1 and type(document[0]) is dict else {}
    identity = row.get("Id", _MISSING)
    descriptor = row.get("Descriptor", _MISSING)
    config = row.get("Config", _MISSING)
    user = config.get("User", _MISSING) if type(config) is dict else _MISSING
    repos = row.get("RepoDigests", _MISSING)
    profile = ("legacy_config_id" if identity == KEYCLOAK_CONFIG else
               "containerd_manifest_descriptor" if identity == KEYCLOAK_AMD64 else "unrecognized")

    def digest_marker(value: object) -> object:
        return value if type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) else marker(value)

    def literal_marker(value: object, allowed: tuple[str, ...]) -> object:
        return value if type(value) is str and value in allowed else marker(value)

    descriptor_fields = descriptor if type(descriptor) is dict else {}
    size = descriptor_fields.get("size", _MISSING)
    diagnostic = {
        "expected": {"profiles": ["legacy_config_id", "containerd_manifest_descriptor"],
                     "config_digest": KEYCLOAK_CONFIG, "manifest_digest": KEYCLOAK_AMD64,
                     "manifest_bytes": KEYCLOAK_MANIFEST_BYTES, "pinned_reference": IMAGE,
                     "platform": "linux/amd64", "users": ["1000", "1000:0"]},
        "actual": {"root": marker(document), "row": marker(document[0]) if type(document) is list and len(document) == 1 else {"state": "unavailable"},
                   "profile": profile, "id": digest_marker(identity), "descriptor": marker(descriptor),
                   "descriptor_digest": digest_marker(descriptor_fields.get("digest", _MISSING)),
                   "descriptor_media_type": literal_marker(descriptor_fields.get("mediaType", _MISSING), ("application/vnd.oci.image.manifest.v1+json",)),
                   "descriptor_size": size if type(size) is int and 0 <= size <= MAX_HTTP_BODY else marker(size) if type(size) is not int else {"type": "int", "state": "outside_diagnostic_bound"},
                   "repo_digests": marker(repos), "exact_pinned_reference": type(repos) is list and repos == [IMAGE],
                   "os": literal_marker(row.get("Os", _MISSING), ("linux", "windows", "darwin")),
                   "architecture": literal_marker(row.get("Architecture", _MISSING), ("amd64", "arm64", "arm", "386")),
                   "config": marker(config), "user": literal_marker(user, ("1000", "1000:0", "0", "root"))},
    }
    require(type(document) is list and len(document) == 1 and type(document[0]) is dict
            and type(identity) is str and profile != "unrecognized"
            and type(repos) is list and len(repos) == 1 and type(repos[0]) is str and repos == [IMAGE]
            and type(row.get("Architecture")) is str and row["Architecture"] == "amd64"
            and type(row.get("Os")) is str and row["Os"] == "linux",
            "idp_image_config_identity", diagnostic)
    if profile == "legacy_config_id":
        require(descriptor is _MISSING, "idp_image_config_identity", diagnostic)
    else:
        require(type(descriptor) is dict and set(descriptor) == {"mediaType", "digest", "size"}
                and descriptor.get("mediaType") == "application/vnd.oci.image.manifest.v1+json"
                and descriptor.get("digest") == KEYCLOAK_AMD64
                and type(descriptor.get("size")) is int and descriptor["size"] == KEYCLOAK_MANIFEST_BYTES,
                "idp_image_config_identity", diagnostic)
    require(type(config) is dict and type(user) is str and user in ("1000", "1000:0"), "idp_image_user", diagnostic)
    return {"status": "validated", "profile": profile, "id": identity,
            "pinned_reference": IMAGE, "expected_config_digest": KEYCLOAK_CONFIG,
            "platform": "linux/amd64", "user": user,
            "manifest_descriptor": dict(descriptor) if profile == "containerd_manifest_descriptor" else None}


class PrivateValues:
    """Bounded ephemeral canary registry, never serialized or hashed publicly.

    Python/library/OS copies are not claimed to be zeroized. This guard tests
    the selected output sinks, not universal absence of sensitive copies.
    """

    def __init__(self) -> None:
        self._values: list[bytes] = []
        self._owned_input_root: bytes | None = None
        self._owned_input_path_digests: set[bytes] = set()
        self._retained_bytes = 0

    def add(self, value: str | bytes) -> None:
        require(len(value) <= MAX_HTTP_BODY, "private_registry_limit")
        raw = value.encode("utf-8") if isinstance(value, str) else value
        if len(raw) >= 16 and raw not in self._values:
            require(len(self._values) < 96 and len(raw) <= MAX_HTTP_BODY
                    and self._retained_bytes + len(raw) <= 96 * MAX_HTTP_BODY, "private_registry_limit")
            self._values.append(raw)
            self._retained_bytes += len(raw)

    def register_owned_input_path(self, work_root: Path, raw_path: str) -> None:
        """Only the frozen eighteen controller-owned direct child paths.

        The registered root guards every raw child path by containment. Each
        full original child-path hash is still guarded separately; this does
        not remove secret or raw provider-response canaries to save slots.
        """
        require(type(work_root) is type(Path()) and work_root.is_absolute() and type(raw_path) is str,
                "private_input_path_guard")
        root = str(work_root)
        require(16 <= len(root) <= MAX_HTTP_BODY and len(raw_path) <= MAX_HTTP_BODY,
                "private_input_path_guard")
        root_bytes = root.encode("utf-8")
        require(root_bytes in self._values
                and (self._owned_input_root is None or self._owned_input_root == root_bytes),
                "private_input_path_guard")
        # Exact string equality is intentional: Windows Path equality alone
        # would silently accept changed-case aliases. No resolve/read occurs.
        admitted = any(raw_path == str(work_root / (name + suffix))
                       for name in SCENARIOS for suffix in (".toml", ".secret.tsv"))
        require(admitted and str(Path(raw_path).parent) == root, "private_input_path_guard")
        raw = raw_path.encode("utf-8")
        require(len(raw) <= MAX_HTTP_BODY and root_bytes in raw, "private_input_path_guard")
        digest = hashlib.sha256(raw).digest()
        if digest not in self._owned_input_path_digests:
            require(len(self._owned_input_path_digests) < 18
                    and self._retained_bytes + len(digest) <= 96 * MAX_HTTP_BODY,
                    "private_registry_limit")
            self._owned_input_path_digests.add(digest)
            self._retained_bytes += len(digest)
        # Share the already charged immutable root canary, not another copy.
        self._owned_input_root = self._values[self._values.index(root_bytes)]

    def check(self, source: bytes) -> None:
        require(not any(value in source for value in self._values), "secret_in_output")
        # Detect public unkeyed digests without ever exporting the digest.
        require(not any(hashlib.sha256(value).hexdigest().encode() in source
                        for value in self._values), "secret_digest_in_output")
        require(not any(value.hex().encode("ascii") in source
                        for value in self._owned_input_path_digests), "secret_digest_in_output")


class CombinedOutputPrivacy:
    """Both retained registries remain live through every offline operation.

    V7 has its own explicit 96-entry lab guard, not extra slots in the legacy
    guard. The total retained payload ceiling is twice the unchanged per-guard
    ceiling. This is bounded harness storage, not a product budget increase.
    """

    def __init__(self, legacy: PrivateValues, authorization: PrivateValues):
        require(type(legacy) is PrivateValues and type(authorization) is PrivateValues
                and legacy is not authorization, "combined_privacy_guards")
        self.guards = (legacy, authorization)

    def check(self, source: bytes) -> None:
        require(sum(guard._retained_bytes for guard in self.guards) <= 2 * 96 * MAX_HTTP_BODY,
                "combined_privacy_retained_limit")
        for guard in self.guards:
            guard.check(source)


def _record_fixture_failure(owner: object, error: Exception, channel: str) -> None:
    """Keep the original failure and only a closed, value-free cause class."""
    owner.errors.append(channel + "_failure")
    cause = ("private_registry_limit" if isinstance(error, LabError) and error.code == "private_registry_limit"
             else "fixture_contract_failure" if isinstance(error, LabError)
             else "transport_io_failure" if isinstance(error, OSError)
             else "value_failure")
    if cause not in owner.failure_causes and len(owner.failure_causes) < 4:
        owner.failure_causes.append(cause)


def _fixture_runtime_diagnostic(scenario: str, relay: object, target: object) -> dict:
    """No raw exceptions, tokens, source paths, response bodies or URLs."""
    def count(value: object, maximum: int) -> object:
        return len(value) if type(value) in (list, dict) and len(value) <= maximum else marker(value)

    def channel(owner: object) -> dict:
        causes = getattr(owner, "failure_causes", _MISSING)
        allowed = {"private_registry_limit", "fixture_contract_failure", "transport_io_failure", "value_failure"}
        return {"error_count": count(getattr(owner, "errors", _MISSING), MAX_TRACE),
                "cause_classes": (list(causes) if type(causes) is list and len(causes) <= 4
                                  and all(type(value) is str and value in allowed for value in causes)
                                  else marker(causes)),
                "handler_failed": marker(getattr(getattr(owner, "server", None), "handler_failed", _MISSING)),
                "trace_row_count": count(getattr(owner, "trace", _MISSING), MAX_TRACE)}

    captures = getattr(relay, "_refresh_captures", _MISSING)
    selected = captures.get(scenario, _MISSING) if type(captures) is dict else _MISSING
    result = {"scenario": scenario if scenario in SCENARIOS + AUTHORIZATION_SCENARIOS else marker(scenario),
            "relay": channel(relay), "target": channel(target),
            "private_registry": {"entry_count": count(getattr(getattr(relay, "private", None), "_values", _MISSING), 96),
                                 "entry_limit": 96},
            "refresh_capture_count": count(captures, 3),
            "selected_refresh_capture": {
                key: marker(getattr(selected, key, _MISSING))
                for key in ("initial_returned", "refresh_responses", "replacement_returned", "replacement_value_differs")}}
    if scenario in AUTHORIZATION_SCENARIOS:
        result["authorization_private_registry"] = {
            "entry_count": count(getattr(getattr(relay, "authorization_private", None), "_values", _MISSING), 96),
            "entry_limit": 96,
        }
    return result


@dataclasses.dataclass(frozen=True)
class Result:
    stdout: bytes
    stderr: bytes
    returncode: int
    elapsed_seconds: float


class CapturedChild:
    """One bounded subprocess with concurrently drained private output."""

    def __init__(self, args: list[str], input_bytes: bytes | None = None):
        try:
            self.process = subprocess.Popen(args, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            raise LabError("process_start") from None
        self.buffers = [bytearray(), bytearray()]
        self.overflow = threading.Event()
        self.threads = []
        for index, stream in enumerate((self.process.stdout, self.process.stderr)):
            thread = threading.Thread(target=self._drain, args=(index, stream), daemon=True)
            thread.start()
            self.threads.append(thread)
        if input_bytes is not None:
            require(len(input_bytes) <= MAX_HTTP_BODY, "process_input_limit")
            self.input_error = threading.Event()

            def write_input():
                try:
                    self.process.stdin.write(input_bytes)
                    self.process.stdin.close()
                except (OSError, BrokenPipeError):
                    self.input_error.set()

            writer = threading.Thread(target=write_input, daemon=True)
            writer.start()
            self.threads.append(writer)

    def _drain(self, index: int, stream) -> None:
        try:
            while True:
                block = stream.read(8192)
                if not block:
                    return
                if len(self.buffers[index]) + len(block) > MAX_OUTPUT:
                    self.overflow.set()
                    self.process.kill()
                    return
                self.buffers[index].extend(block)
        finally:
            stream.close()

    def finish(self, timeout: float) -> Result:
        started = time.monotonic()
        try:
            status = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.stop()
            raise LabError("process_timeout") from None
        for thread in self.threads:
            thread.join(timeout=2)
        require(not self.overflow.is_set() and all(not t.is_alive() for t in self.threads), "process_output_limit")
        require(not getattr(self, "input_error", threading.Event()).is_set(), "process_input")
        return Result(bytes(self.buffers[0]), bytes(self.buffers[1]), status, time.monotonic() - started)

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)
        for thread in self.threads:
            thread.join(timeout=2)


def last_owned_container_state(inspected: object, owner: object) -> dict:
    """Reduce only an already inspected, owner-bound container's stale state."""
    result = {"observation_scope": "last_inspected_before_client_exit_not_atomic_final_state",
              "ownership": "not_established", "state": "unavailable"}
    if not (type(owner) is str and re.fullmatch(r"termivar-oauth-[0-9a-f]{16}", owner)
            and type(inspected) is list and len(inspected) == 1 and type(inspected[0]) is dict):
        return result
    row = inspected[0]
    config = row.get("Config")
    labels = config.get("Labels") if type(config) is dict else None
    if not (type(labels) is dict and type(labels.get("termivar.oauth.owner")) is str
            and labels["termivar.oauth.owner"] == owner):
        return result
    result["ownership"] = "validated"
    state = row.get("State")
    if type(state) is not dict:
        return result

    def unknown(value: object) -> dict:
        names = {type(None): "null", bool: "boolean", int: "integer", float: "number",
                 str: "string", dict: "object", list: "array"}
        return {"state": "missing"} if value is _MISSING else {"state": "unknown", "type": names.get(type(value), "unsupported")}

    values = {}
    for key in ("Status", "Running", "ExitCode", "OOMKilled"):
        value = state.get(key, _MISSING)
        valid = (type(value) is str and value in ("created", "running", "paused", "restarting", "removing", "exited", "dead")) if key == "Status" else (
            type(value) is int and 0 <= value <= 255 if key == "ExitCode" else type(value) is bool)
        values[key] = {"state": "known", "value": value} if valid else unknown(value)
    error = state.get("Error", _MISSING)
    values["Error"] = {"field_present": error is not _MISSING, "type": "string" if type(error) is str else unknown(error),
                       "nonempty": bool(error) if type(error) is str else None}
    result.update({"state": "available", "fields": values})
    return result


def daemon_start_lexical_signals(stdout: bytes, stderr: bytes, *, capture_complete: bool,
                                 inspected: object, owner: object, private: PrivateValues | None) -> dict:
    """Fixed presence flags, not a masked transcript or an English parser."""
    def refused(reason: str) -> dict:
        return {"state": "not_eligible", "reason": reason}

    if capture_complete is not True or type(stdout) is not bytes or stdout:
        return refused("complete_empty_stdout_required")
    if type(stderr) is not bytes or not 0 < len(stderr) <= MAX_HTTP_BODY:
        return refused("bounded_complete_stderr_required")
    if any(value not in (10, 13) and not 32 <= value <= 126 for value in stderr):
        return refused("printable_ascii_required")
    if last_owned_container_state(inspected, owner)["ownership"] != "validated":
        return refused("validated_task_owner_required")
    normalized = stderr.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        return refused("single_daemon_line_required")
    lines = normalized.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    prefix = b"Error response from daemon: "
    trailer = b"Error: failed to start containers: " + owner.encode("ascii") + b"-idp"
    if not (1 <= len(lines) <= 2 and lines[0].startswith(prefix) and len(lines[0]) > len(prefix)
            and (len(lines) == 1 or lines[1] == trailer)):
        return refused("single_daemon_line_required")
    if type(private) is not PrivateValues:
        return refused("private_registry_required")
    try:
        private.check(stderr)
    except Exception:
        return refused("private_registry_check_failed")
    # Whitespace atoms only: paths, URLs, assignments, quoted values, numbers,
    # hashes and compounds such as secret-tmpfs-value stay opaque. Never split
    # them into apparently safe vocabulary fragments.
    vocabulary = (
        "tmpfs", "uid", "gid", "mode", "size", "mount", "mounts", "log", "logging", "driver", "local",
        "max-size", "max-file", "invalid", "unknown", "unsupported", "support", "reading", "network",
        "port", "address", "allocated", "stdin", "attach", "tty", "user", "runtime", "command", "cgroup",
        "memory", "pids", "permission", "denied", "not", "found", "no", "such", "directory", "read", "file",
        "filesystem", "cpu", "cpus", "nanocpus", "can", "be", "set", "kernel", "does", "cfs", "scheduler",
        "mounted", "range", "of", "from", "to", "there", "are", "only", "available", "as", "your", "the",
        "failed", "start", "container", "containers", "create", "task", "shim", "oci", "process", "exec",
        "for", "argument", "option", "configuration", "error", "bind", "device", "root", "entrypoint",
        "quota", "limit", "unable", "with", "is", "on", "and", "or", "in",
    )
    body = lines[0][len(prefix):].lower()
    atoms = [atom.rstrip(b".,:;").decode("ascii") for atom in body.split()]
    admitted = set(vocabulary)
    present = set(atoms) & admitted
    # Literal Moby v28.5.1 daemon_unix.go templates; values are never emitted.
    cpu_cfs = body == b"nanocpus can not be set, as your kernel does not support cpu cfs scheduler or the cgroup is not mounted"
    cpu_range = re.fullmatch(rb"range of cpus is from 0\.01 to ([1-9][0-9]{0,3})\.00, as there are only \1 cpus available", body) is not None
    return {"state": "eligible", "interpretation": "lexical_signals_not_established_cause",
            "presence": {word: word in present for word in vocabulary},
            "templates": {"cpu_cfs_unavailable": cpu_cfs, "cpu_range_unavailable": cpu_range},
            "unknown_token_count": sum(atom not in admitted for atom in atoms)}


def startup_failure_diagnostic(child: CapturedChild, exit_code: object,
                               private: PrivateValues | None = None, *, last_inspected: object = None,
                               owner: object = None, overflow: object = None) -> dict:
    """Reduce private attached output to closed markers, never lines or hashes.

    Markers are diagnostic signals, not a verified explanation of the exit.
    Only the existing first 128 KiB per stream is inspected; no provider body,
    unknown prose, URL, environment value or reversible fragment is exported.
    """
    status = exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None
    summary = {"phase": "attached_provider_before_readiness", "bootstrap_subphase": "unknown",
               "attached_child_exit_code": status, "finished_child_exit_code": None,
               "overflow_flag": overflow if type(overflow) is bool else None,
               "exit_class": "exit_" + str(status) if status in (126, 127, 137) else "other_exit" if status is not None else "unknown",
               "capture_state": "unavailable", "stdout_captured_bytes": None, "stderr_captured_bytes": None,
               "classification_bytes": 0, "classification_scope": "first_128_kib_per_stream",
               "failure_classes": ["unknown"], "source_layer_markers": ["unknown"],
               "marker_interpretation": "closed_text_signals_not_established_cause", "diagnostic_errors": [],
               "docker_daemon_lexical": {"state": "not_eligible", "reason": "capture_unavailable"}}
    try:
        summary["last_owned_container_inspection"] = last_owned_container_state(last_inspected, owner)
    except Exception:
        summary["last_owned_container_inspection"] = {"observation_scope": "last_inspected_before_client_exit_not_atomic_final_state",
                                                       "ownership": "not_established", "state": "unavailable"}
        summary["diagnostic_errors"].append("last_inspection_unavailable")
    streams = None
    try:
        result = child.finish(2)
        finished = result.returncode
        summary["finished_child_exit_code"] = finished if type(finished) is int and -255 <= finished <= 255 else None
        values = (result.stdout, result.stderr)
        require(all(type(value) is bytes and len(value) <= MAX_OUTPUT for value in values), "diagnostic_output_shape")
        streams = values
        summary["capture_state"] = "complete"
    except Exception:
        summary["diagnostic_errors"].append("finish_or_output_unavailable")
        try:
            buffers = child.buffers
            require(type(buffers) is list and len(buffers) == 2
                    and all(type(value) in (bytes, bytearray) and len(value) <= MAX_OUTPUT for value in buffers),
                    "diagnostic_buffer_shape")
            streams = tuple(bytes(value) for value in buffers)
            summary["capture_state"] = "partial"
        except Exception:
            summary["diagnostic_errors"].append("buffer_read_unavailable")
    if streams is not None:
        summary["stdout_captured_bytes"], summary["stderr_captured_bytes"] = map(len, streams)
        prefixes = tuple(value[:MAX_HTTP_BODY].lower() for value in streams)
        summary["classification_bytes"] = sum(map(len, prefixes))
        signals = (
            ("permission_denied_marker", ((b"permission denied",),)),
            ("temporary_native_mapping_marker", ((b"/tmp/", b"failed to map segment from shared object"),)),
            ("read_only_filesystem_marker", ((b"read-only file system",),)),
            ("java_options_rejected_marker", ((b"unrecognized vm option",), (b"unrecognized option:",))),
            ("unsupported_cli_marker", ((b"unknown option",), (b"unknown command",), (b"unmatched argument",))),
            ("realm_schema_import_marker", ((b"failed to import realm",), (b"unrecognized field", b"realm"), (b"could not parse realm",))),
            ("out_of_memory_marker", ((b"java.lang.outofmemoryerror",), (b"out of memory",))),
            ("storage_exhaustion_marker", ((b"no space left on device",),)),
            ("stdin_attach_template_marker", ((b"the input device is not a tty",), (b"error attaching:",), (b"error waiting for container:",))),
        )
        summary["failure_classes"] = [name for name, alternatives in signals
                                      if any(all(fragment in prefix for fragment in required)
                                             for required in alternatives for prefix in prefixes)] or ["unknown"]
        lines = [line.lstrip() for prefix in prefixes for line in prefix.splitlines()]
        layers = (
            ("docker_daemon_error_prefix", (b"error response from daemon:", b"docker: error response from daemon:")),
            ("docker_attach_error_prefix", (b"error attaching:", b"error waiting for container:")),
            ("oci_runtime_error_prefix", (b"oci runtime create failed:", b"oci runtime exec failed:", b"failed to create shim task:")),
            ("jvm_launcher_error_prefix", (b"error: could not create the java virtual machine.", b"error: could not find or load main class ", b"error occurred during initialization of vm")),
            ("keycloak_startup_error_prefix", (b"error: failed to start server in ", b"error: failed to run 'start-dev' command.")),
            ("keycloak_import_error_prefix", (b"error: failed to run 'import' command.",)),
        )
        summary["source_layer_markers"] = [name for name, starts in layers
                                           if any(line.startswith(starts) for line in lines)]
        if any(re.match(rb"owned-bootstrap: (?:-c: )?line [0-9]{1,4}:", line) for line in lines):
            summary["source_layer_markers"].append("owned_bootstrap_shell_error_prefix")
        summary["source_layer_markers"] = summary["source_layer_markers"] or ["unknown"]
        try:
            summary["docker_daemon_lexical"] = daemon_start_lexical_signals(
                streams[0], streams[1], capture_complete=summary["capture_state"] == "complete",
                inspected=last_inspected, owner=owner, private=private)
        except Exception:
            summary["docker_daemon_lexical"] = {"state": "not_eligible", "reason": "diagnostic_unavailable"}
    if private is not None:
        try:
            private.check(json.dumps(summary, sort_keys=True).encode())
        except Exception:
            # Even a diagnostic/privacy failure cannot replace the original
            # startup exception or leak an exception message/provider body.
            return {"phase": "attached_provider_before_readiness", "bootstrap_subphase": "unknown",
                    "attached_child_exit_code": status, "finished_child_exit_code": summary["finished_child_exit_code"],
                    "overflow_flag": overflow if type(overflow) is bool else None, "failure_classes": ["unknown"],
                    "diagnostic_errors": ["reduced_diagnostic_privacy_check_failed"]}
    return summary


class Runner:
    def __init__(self, private: PrivateValues):
        self.private = private
        self.records: list[dict] = []
        self.output_privacy = private

    def run(self, args: list[str], *, label: str, expected: tuple[int, ...] = (0,),
            input_bytes: bytes | None = None, timeout: float = MAX_COMMAND_SECONDS,
            sensitive_output: bool = False) -> Result:
        started = time.monotonic()
        child = CapturedChild(args, input_bytes)
        result = child.finish(timeout)
        if not sensitive_output:
            self.output_privacy.check(result.stdout)
            self.output_privacy.check(result.stderr)
        self.records.append({"id": label, "exit_code": result.returncode,
                             "elapsed_seconds": round(time.monotonic() - started, 6)})
        require(result.returncode in expected, "process_exit", {"command_id": label, "exit_code": result.returncode})
        return dataclasses.replace(result, elapsed_seconds=time.monotonic() - started)


def _loopback_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port is not None
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and parsed.path in ("", "/"), "owned_origin")
    return f"http://127.0.0.1:{parsed.port}"


def request_bytes(url: str, method: str, body: bytes | None = None,
                  headers: dict[str, str] | None = None, *, maximum: int = MAX_HTTP_BODY) -> tuple[int, list, bytes]:
    """No proxy, redirect, decompression or retry; exact numeric owned origin."""
    parsed = urllib.parse.urlsplit(url)
    _loopback_origin(f"{parsed.scheme}://{parsed.netloc}")
    require(not parsed.fragment and parsed.path.startswith("/"), "owned_request_url")
    conn = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=8)
    try:
        conn.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""), body, headers or {})
        response = conn.getresponse()
        data = response.read(maximum + 1)
        require(len(data) <= maximum, "http_body_limit")
        return response.status, response.getheaders(), data
    except (OSError, http.client.HTTPException):
        raise LabError("owned_http_transport") from None
    finally:
        conn.close()


_IDP_UPSTREAM_SEAL = object()
_AUTHORIZATION_REQUEST_SEAL = object()


def _authorization_callback(value: object) -> str:
    require(type(value) is str and len(value) <= 128, "authorization_callback_binding")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise LabError("authorization_callback_binding") from None
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
            and port is not None and 1024 <= port <= 65535
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment
            and parsed.path == AUTHORIZATION_CALLBACK_PATH
            and value == f"http://127.0.0.1:{port}" + AUTHORIZATION_CALLBACK_PATH,
            "authorization_callback_binding")
    return value


def authorization_callback_bindings() -> dict[str, str]:
    """Freeze five distinct unprivileged callback registrations before import.

    The sockets are controller-owned reservations only during selection and are
    closed before the product starts. A later bind race fails acceptance; the
    controller never changes the registered redirect to make a run connect.
    """
    sockets = []
    result = {}
    try:
        for name in AUTHORIZATION_SCENARIOS:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(listener)
            listener.bind(("127.0.0.1", 0))
            value = f"http://127.0.0.1:{listener.getsockname()[1]}" + AUTHORIZATION_CALLBACK_PATH
            result[name] = _authorization_callback(value)
        require(len(set(result.values())) == 5, "authorization_callback_duplicates")
        return result
    finally:
        for listener in sockets:
            listener.close()


@dataclasses.dataclass(frozen=True, repr=False)
class _InitiatedAuthorizationRequest:
    origin: str
    target: str
    redirect: str
    state: str
    code_challenge: str
    scope: str
    substituted: bool
    _seal: object

    def validate(self, relay_host: str) -> None:
        require(self._seal is _AUTHORIZATION_REQUEST_SEAL
                and _loopback_origin(self.origin) == self.origin
                and urllib.parse.urlsplit(self.origin).netloc == relay_host,
                "authorization_request_binding")
        _authorization_callback(self.redirect)
        require(type(self.target) is str and len(self.target) <= 4096
                and self.target.startswith(AUTH_PATH + "?")
                and type(self.substituted) is bool, "authorization_request_binding")
        try:
            fields = urllib.parse.parse_qsl(self.target.split("?", 1)[1], keep_blank_values=True,
                                            strict_parsing=True, errors="strict", max_num_fields=8)
        except (ValueError, UnicodeError):
            raise LabError("authorization_request_parameters") from None
        values = dict(fields)
        require(len(fields) == len(values) == 8
                and set(values) == {"response_type", "response_mode", "client_id", "redirect_uri",
                                    "scope", "state", "code_challenge", "code_challenge_method"}
                and values == {"response_type": "code", "response_mode": "form_post", "client_id": PUBLIC_CLIENT,
                               "redirect_uri": self.redirect, "scope": self.scope, "state": self.state,
                               "code_challenge": self.code_challenge, "code_challenge_method": "S256"}
                and self.scope in (SCOPE, AUTHORIZATION_UNASSIGNED_SCOPE)
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", self.state) is not None
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", self.code_challenge) is not None,
                "authorization_request_parameters")


def initiated_authorization_request(handoff: bytes, origin: str, redirect: str,
                                    scenario: str, private: PrivateValues) -> _InitiatedAuthorizationRequest:
    require(scenario in AUTHORIZATION_SCENARIOS and type(handoff) is bytes
            and 1 < len(handoff) <= 4097 and handoff.endswith(b"\n")
            and b"\r" not in handoff and b"\n" not in handoff[:-1], "authorization_handoff_shape")
    try:
        uri = handoff[:-1].decode("ascii")
        parsed = urllib.parse.urlsplit(uri)
        require(uri.startswith(_loopback_origin(origin) + AUTH_PATH + "?")
                and not parsed.fragment and not parsed.username and not parsed.password
                and parsed.path == AUTH_PATH, "authorization_handoff_endpoint")
        rows = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True,
                                      errors="strict", max_num_fields=8)
    except (UnicodeError, ValueError):
        raise LabError("authorization_handoff_shape") from None
    values = dict(rows)
    require(len(rows) == len(values) == 8, "authorization_request_parameters")
    scope = AUTHORIZATION_UNASSIGNED_SCOPE if scenario == "initiated-provider-error" else SCOPE
    descriptor = _InitiatedAuthorizationRequest(origin, parsed.path + "?" + parsed.query,
        _authorization_callback(redirect), values.get("state"), values.get("code_challenge"),
        scope, False, _AUTHORIZATION_REQUEST_SEAL)
    descriptor.validate(urllib.parse.urlsplit(origin).netloc)
    private.add(uri)
    private.add(descriptor.state)
    private.add(descriptor.code_challenge)
    if scenario == "initiated-challenge-substitution":
        changed = ("A" if descriptor.code_challenge[0] != "A" else "B") + descriptor.code_challenge[1:]
        values["code_challenge"] = changed
        descriptor = dataclasses.replace(descriptor, target=AUTH_PATH + "?" + urllib.parse.urlencode(values),
                                         code_challenge=changed, substituted=True)
        descriptor.validate(urllib.parse.urlsplit(origin).netloc)
        private.add(origin + descriptor.target)
    return descriptor


def _owned_network_plan(network: object, owner: str, name: str) -> tuple[str, tuple]:
    require(type(network) is dict and type(owner) is str
            and re.fullmatch(r"termivar-oauth-[0-9a-f]{16}", owner) is not None
            and name == owner + "-net", "idp_network_identity")
    labels, ipam = network.get("Labels"), network.get("IPAM")
    require(type(labels) is dict and labels.get("termivar.oauth.owner") == owner
            and network.get("Name") == name and network.get("Internal") is True
            and network.get("Driver") == "bridge" and type(network.get("Id")) is str
            and re.fullmatch(r"[0-9a-f]{64}", network["Id"]) is not None,
            "idp_network_identity")
    rows = ipam.get("Config") if type(ipam) is dict else None
    require(type(rows) is list and 1 <= len(rows) <= 4, "idp_private_subnet")
    ranges = tuple(ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    subnets = []
    for row in rows:
        raw = row.get("Subnet") if type(row) is dict else None
        require(type(raw) is str and len(raw) <= 32, "idp_private_subnet")
        try:
            subnet = ipaddress.IPv4Network(raw, strict=True)
        except ValueError:
            raise LabError("idp_private_subnet") from None
        require(any(subnet.subnet_of(scope) for scope in ranges) and all(not subnet.overlaps(previous) for previous in subnets), "idp_private_subnet")
        subnets.append(subnet)
    return network["Id"], tuple(subnets)


def _provider_route(method: str, target: str) -> str:
    require(type(target) is str and len(target) <= 4096, "relay_route_refused")
    parsed = urllib.parse.urlsplit(target)
    require(target == parsed.path and not parsed.scheme and not parsed.netloc
            and not parsed.query and not parsed.fragment and not target.startswith("//"), "relay_route_refused")
    routes = {("GET", REALM_PATH + "/.well-known/openid-configuration"): "setup-metadata",
              ("POST", TOKEN_PATH): "token-exchange", ("POST", INTROSPECTION_PATH): "backend-introspection",
              ("POST", AUTH_PATH): "controller-authorization"}
    routes.update({("POST", "/admin/realms/" + REALM + "/users/" + value + "/impersonation"): "controller-sso-setup"
                   for value in USER_IDS.values()})
    require(type(method) is str and (method, target) in routes, "relay_route_refused")
    return routes[(method, target)]


@dataclasses.dataclass(frozen=True, repr=False)
class _OwnedIdpUpstream:
    _address: str
    _network_id: str
    _subnet: ipaddress.IPv4Network
    _relay_host: str
    _seal: object

    def __post_init__(self):
        self._validate()

    def _validate(self) -> None:
        require(self._seal is _IDP_UPSTREAM_SEAL and type(self._address) is str and len(self._address) <= 15
                and type(self._network_id) is str and len(self._network_id) == 64
                and re.fullmatch(r"[0-9a-f]{64}", self._network_id) is not None,
                "idp_binding_seal")
        require(type(self._subnet) is ipaddress.IPv4Network and any(self._subnet.subnet_of(ipaddress.IPv4Network(scope))
                for scope in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")), "idp_binding_address")
        try:
            address = ipaddress.IPv4Address(self._address)
        except ValueError:
            raise LabError("idp_binding_address") from None
        require(str(address) == self._address and address in self._subnet
                and address not in (self._subnet.network_address, self._subnet.broadcast_address), "idp_binding_address")
        matched = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", self._relay_host) if type(self._relay_host) is str and len(self._relay_host) <= 32 else None
        require(matched is not None and 1 <= int(matched[1]) <= 65535
                and self._relay_host == "127.0.0.1:" + str(int(matched[1])), "idp_binding_relay_host")

    def request(self, method: str, target: str, body: bytes | None, headers: dict) -> tuple[int, list, bytes]:
        require(self._seal is _IDP_UPSTREAM_SEAL and type(self) is _OwnedIdpUpstream, "idp_binding_seal")
        self._validate()
        _provider_route(method, target)
        return self._request_validated(method, target, body, headers)

    def request_authorization(self, descriptor: _InitiatedAuthorizationRequest, headers: dict) -> tuple[int, list, bytes]:
        require(type(descriptor) is _InitiatedAuthorizationRequest, "authorization_request_binding")
        self._validate()
        descriptor.validate(self._relay_host)
        return self._request_validated("GET", descriptor.target, None, headers)

    def _request_validated(self, method: str, target: str, body: bytes | None, headers: dict) -> tuple[int, list, bytes]:
        require(body is None or type(body) is bytes and len(body) <= MAX_HTTP_BODY, "http_body_limit")
        require(method != "GET" or body is None, "relay_route_refused")
        require(type(headers) is dict and set(headers) <= {"Host", "Accept-Encoding", "Content-Type", "Cookie", "Authorization", "Accept"}
                and headers.get("Host") == self._relay_host and headers.get("Accept-Encoding") == "identity"
                and all(type(value) is str and len(value) <= 16384 and "\r" not in value and "\n" not in value
                        for value in headers.values()), "relay_header_limit")
        conn = http.client.HTTPConnection(self._address, 8080, timeout=8)
        try:
            conn.request(method, target, body, headers)
            response = conn.getresponse()
            data = response.read(MAX_HTTP_BODY + 1)
            require(len(data) <= MAX_HTTP_BODY, "http_body_limit")
            return response.status, response.getheaders(), data
        except (OSError, http.client.HTTPException):
            raise LabError("owned_http_transport") from None
        finally:
            conn.close()


def owned_idp_upstream(container: object, network: object, owner: str, name: str,
                       relay_origin: str) -> _OwnedIdpUpstream | None:
    network_id, subnets = _owned_network_plan(network, owner, name)
    require(type(container) is dict and type(container.get("Config")) is dict
            and type(container["Config"].get("Labels")) is dict
            and type(container.get("HostConfig")) is dict and type(container.get("State")) is dict
            and type(container["HostConfig"].get("SecurityOpt")) is list
            and type(container.get("Mounts")) is list and all(type(row) is dict for row in container["Mounts"])
            and type(container.get("NetworkSettings")) is dict, "idp_container_identity")
    validate_isolation(container, network, owner, name)
    state, settings = container["State"], container["NetworkSettings"]
    require(type(state.get("Running")) is bool and state.get("Status") in ("created", "running")
            and (state["Running"] is True) == (state["Status"] == "running"), "idp_container_state")
    attachments = settings.get("Networks")
    require(type(attachments) is dict and set(attachments) == {name}
            and type(attachments[name]) is dict, "idp_single_network_attachment")
    attachment = attachments[name]
    require(type(attachment.get("NetworkID")) is str
            and attachment["NetworkID"] in ((network_id,) if state["Running"] else ("", network_id)),
            "idp_attachment_network_identity")
    raw = attachment.get("IPAddress")
    require(type(raw) is str and len(raw) <= 15, "idp_binding_address")
    if not raw:
        require(state["Running"] is False, "idp_binding_address")
        return None
    try:
        address = ipaddress.IPv4Address(raw)
    except ValueError:
        raise LabError("idp_binding_address") from None
    matching = [subnet for subnet in subnets if address in subnet and address not in (subnet.network_address, subnet.broadcast_address)]
    require(len(matching) == 1 and str(address) == raw, "idp_binding_address")
    if state["Running"] is False:
        return None
    origin = _loopback_origin(relay_origin)
    return _OwnedIdpUpstream(raw, network_id, matching[0], urllib.parse.urlsplit(origin).netloc, _IDP_UPSTREAM_SEAL)


class FormParser(html.parser.HTMLParser):
    """Small original controller parser; never executes provider HTML/JS."""

    def __init__(self, source: bytes):
        super().__init__(convert_charrefs=True)
        require(len(source) <= MAX_HTTP_BODY, "controller_html_size")
        self.forms: list[dict] = []
        self.active = None
        self.nodes = 0
        try:
            self.feed(source.decode("utf-8"))
            self.close()
        except (UnicodeError, ValueError, RecursionError):
            raise LabError("controller_html") from None
        require(self.active is None, "controller_unclosed_form")

    def handle_starttag(self, tag: str, attrs: list) -> None:
        self.nodes += 1
        require(self.nodes <= 4096 and len(attrs) <= 32, "controller_html_work")
        pairs = {}
        for key, value in attrs:
            require(key not in pairs and isinstance(value, (str, type(None))), "controller_html_attribute")
            require(value is None or len(value) <= 16384, "controller_html_attribute_size")
            pairs[key] = value
        if tag == "form":
            require(self.active is None and len(self.forms) < 8, "controller_form_count")
            self.active = {"action": pairs.get("action"), "method": pairs.get("method", "get").lower(), "inputs": {}}
        elif tag == "input" and self.active is not None:
            name = pairs.get("name")
            if name:
                require(name not in self.active["inputs"] and len(self.active["inputs"]) < 32, "controller_input_duplicate")
                self.active["inputs"][name] = pairs.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            require(self.active is not None, "controller_form_end")
            self.forms.append(self.active)
            self.active = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ControllerCookiePolicy(http.cookiejar.DefaultCookiePolicy):
    """Fixture-only SSO cookies, bound to one owned relay authorization URL.

    Pinned Keycloak regards numeric loopback as a secure context. Python's
    ordinary jar does not: the explicit fixture exception below keeps Secure
    attributes intact and never changes product cookie or TLS policy.
    """

    def __init__(self, origin: str, *, owned_loopback_http: bool = False,
                 authorization_request: _InitiatedAuthorizationRequest | None = None):
        super().__init__()
        require(type(owned_loopback_http) is bool, "controller_cookie_policy")
        try:
            origin = _loopback_origin(origin)
        except (TypeError, ValueError):
            raise LabError("controller_cookie_origin") from None
        if authorization_request is not None:
            require(type(authorization_request) is _InitiatedAuthorizationRequest, "controller_cookie_policy")
            authorization_request.validate(urllib.parse.urlsplit(origin).netloc)
            require(authorization_request.origin == origin, "controller_cookie_origin")
        self.authorization_url = origin + (authorization_request.target if authorization_request is not None else AUTH_PATH)
        self.owned_loopback_http = owned_loopback_http

    def return_ok(self, cookie, request):
        if (request.get_full_url() != self.authorization_url
                or cookie.name not in ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION")):
            return False
        return super().return_ok(cookie, request)

    def return_ok_secure(self, cookie, request):
        return (super().return_ok_secure(cookie, request)
                or (self.owned_loopback_http and cookie.secure
                    and request.get_full_url() == self.authorization_url
                    and cookie.name in ("KEYCLOAK_IDENTITY", "KEYCLOAK_SESSION")))


@dataclasses.dataclass(repr=False)
class Grant:
    code: str
    verifier: str
    code_challenge: str
    issuer: str
    redirect: str
    received: int

    def tsv(self) -> bytes:
        rows = (("authorization_code", self.code), ("code_verifier", self.verifier),
                ("code_challenge", self.code_challenge), ("issuer", self.issuer),
                ("client_id", PUBLIC_CLIENT), ("redirect_uri", self.redirect),
                ("scope", SCOPE), ("received_unix_seconds", str(self.received)))
        require(all("\n" not in value and "\r" not in value and "\t" not in value for _, value in rows), "grant_control")
        data = "".join(key + "\t" + value + "\n" for key, value in rows).encode()
        require(len(data) <= 16 * 1024, "grant_size")
        return data


def obtain_code(origin: str, redirect: str, username: str, controller_secret: str,
                private: PrivateValues) -> Grant:
    """Controller-only admin-prepared SSO, then real public-client code flow.

    The provider's documented impersonation POST establishes its real login
    cookies. No password grant, login-action query, or redirect is dispatched.
    This is NOT qualification of normal interactive login, MFA, or consent.
    """
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    private.add(verifier)
    private.add(state)
    fields = {"client_id": PUBLIC_CLIENT, "redirect_uri": redirect, "response_type": "code",
              "response_mode": "form_post", "scope": SCOPE, "state": state,
              "code_challenge": challenge(verifier), "code_challenge_method": "S256", "prompt": "none"}
    jar = http.cookiejar.CookieJar(policy=ControllerCookiePolicy(origin, owned_loopback_http=True))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPCookieProcessor(jar))

    def post(path: str, values: dict[str, str], extra_headers: dict | None = None) -> bytes:
        require(path.startswith("/") and "?" not in path and "#" not in path, "controller_query_refused")
        request = urllib.request.Request(origin + path, encoded_form(values),
                    {"Content-Type": "application/x-www-form-urlencoded", **(extra_headers or {})}, method="POST")
        try:
            with opener.open(request, timeout=8) as response:
                require(response.status == 200 and not response.headers.get("Content-Encoding"), "controller_response")
                data = response.read(MAX_HTTP_BODY + 1)
                require(len(data) <= MAX_HTTP_BODY, "controller_response_limit")
                return data
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            raise LabError("controller_login_transport") from None

    require(username in USER_IDS, "controller_user")
    admin = strict_json(post(TOKEN_PATH, {"grant_type": "client_credentials", "client_id": CONTROLLER_CLIENT,
                                         "client_secret": controller_secret}), MAX_TOKEN_BODY)
    require(isinstance(admin, dict) and isinstance(admin.get("access_token"), str), "controller_admin_token")
    token = admin["access_token"]
    private.add(token)
    impersonation = strict_json(post("/admin/realms/" + REALM + "/users/" + USER_IDS[username] + "/impersonation", {},
                                    {"Authorization": "Bearer " + token}))
    require(isinstance(impersonation, dict) and type(impersonation.get("sameRealm")) is bool
            and any(cookie.name == "KEYCLOAK_IDENTITY" for cookie in jar), "controller_sso_cookie")
    # The returned account redirect is not followed; the callback is not sent.
    callback = FormParser(post(AUTH_PATH, fields))
    forms = [form for form in callback.forms if "code" in form["inputs"]]
    require(len(forms) == 1 and forms[0]["method"] == "post" and forms[0]["action"] == redirect, "controller_form_post")
    values = forms[0]["inputs"]
    require(values.get("state") == state and "error" not in values, "controller_state")
    code = values["code"]
    require(1 <= len(code) <= 2048 and all(0x21 <= ord(c) <= 0x7e for c in code), "controller_code")
    private.add(code)
    for cookie in jar:
        private.add(cookie.value)
    return Grant(code, verifier, fields["code_challenge"], origin + REALM_PATH, redirect, int(time.time()))


def prepare_initiated_sso(origin: str, controller_secret: str, private: PrivateValues):
    """Prepare only the owned user-agent SSO; it never supplies a product grant.

    The later authorization URL, state and challenge must come from the running
    product's private handoff. Controller credentials/cookies never enter it.
    """
    _loopback_origin(origin)
    jar = http.cookiejar.CookieJar(policy=ControllerCookiePolicy(origin, owned_loopback_http=True))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                         urllib.request.HTTPCookieProcessor(jar))

    def post(path: str, values: dict[str, str], headers: dict | None = None) -> bytes:
        require(path in (TOKEN_PATH, "/admin/realms/" + REALM + "/users/" + USER_IDS["canary-a"] + "/impersonation"),
                "authorization_sso_route")
        request = urllib.request.Request(origin + path, encoded_form(values),
            {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}, method="POST")
        try:
            with opener.open(request, timeout=8) as response:
                require(response.status == 200 and not response.headers.get("Content-Encoding"), "authorization_sso_response")
                body = response.read(MAX_HTTP_BODY + 1)
                require(len(body) <= MAX_HTTP_BODY, "authorization_sso_response_limit")
                return body
        except (OSError, urllib.error.URLError, http.client.HTTPException):
            raise LabError("authorization_sso_transport") from None

    raw = post(TOKEN_PATH, {"grant_type": "client_credentials", "client_id": CONTROLLER_CLIENT,
                            "client_secret": controller_secret})
    admin = strict_json(raw, MAX_TOKEN_BODY)
    require(type(admin) is dict and type(admin.get("access_token")) is str, "authorization_sso_token")
    private.add(raw)
    private.add(admin["access_token"])
    result = strict_json(post("/admin/realms/" + REALM + "/users/" + USER_IDS["canary-a"] + "/impersonation", {},
                              {"Authorization": "Bearer " + admin["access_token"]}))
    require(type(result) is dict and type(result.get("sameRealm")) is bool
            and any(cookie.name == "KEYCLOAK_IDENTITY" for cookie in jar), "authorization_sso_cookie")
    for cookie in jar:
        private.add(cookie.value)
    return opener, jar


def _read_handoff(path: Path, stop: threading.Event) -> bytes:
    deadline = time.monotonic() + AUTHORIZATION_WAIT_MS / 1000
    while time.monotonic() < deadline:
        if path.exists():
            require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4097,
                    "authorization_handoff_shape")
            with path.open("rb") as stream:
                body = stream.read(4098)
            require(len(body) <= 4097, "authorization_handoff_shape")
            if body.endswith(b"\n"):
                return body
        require(not stop.is_set(), "authorization_handoff_not_written")
        stop.wait(0.005)
    raise LabError("authorization_handoff_timeout")


def submit_authorization_callback(redirect: str, origin: str, fields: dict[str, str],
                                   private: PrivateValues) -> dict:
    """A real POST to the product listener, with exact independent wire length."""
    _authorization_callback(redirect)
    origin = _loopback_origin(origin)
    require(type(fields) is dict and 1 <= len(fields) <= 16
            and all(type(key) is str and len(key) <= 128 and type(value) is str
                    and len(value.encode()) <= 2048 for key, value in fields.items()),
            "authorization_callback_fields")
    body = encoded_form(fields)
    require(0 < len(body) <= 8192, "authorization_callback_form_limit")
    parsed = urllib.parse.urlsplit(redirect)
    request = (f"POST {AUTHORIZATION_CALLBACK_PATH} HTTP/1.1\r\nHost: {parsed.netloc}\r\nOrigin: {origin}\r\n"
               "Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    require(len(request) <= 4096 + 8192, "authorization_callback_wire_limit")
    private.add(body)
    try:
        with socket.create_connection(("127.0.0.1", parsed.port), timeout=8) as connection:
            connection.settimeout(8)
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            reply = bytearray()
            while len(reply) <= 512:
                chunk = connection.recv(min(128, 513 - len(reply)))
                if not chunk:
                    break
                reply.extend(chunk)
            require(0 < len(reply) <= 512 and bytes(reply).startswith(b"HTTP/1.1 200 OK\r\n"),
                    "authorization_callback_reply")
            private.check(bytes(reply))
            return {"post_count": 1, "request_bytes": len(request), "reply_bytes": len(reply),
                    "response_status": 200, "credential_headers_sent": False}
    except (OSError, ValueError):
        raise LabError("authorization_callback_transport") from None


def drive_initiated_authorization(relay: "TokenRelay", opener, jar, handoff_path: Path,
                                  redirect: str, name: str, private: PrivateValues,
                                  stop: threading.Event) -> dict:
    """Inert provider HTML parsing, not JavaScript/browser automation.

    The challenge-substitution case changes only the controlled AS request, not
    the handoff file or product verifier. Wrong state/issuer change only the
    returned form. The provider-error case requests an unassigned scope and
    must receive an actual pinned-provider invalid_scope form.
    """
    original = _read_handoff(handoff_path, stop)
    descriptor = initiated_authorization_request(original, relay.origin, redirect, name, private)
    jar.set_policy(ControllerCookiePolicy(relay.origin, owned_loopback_http=True,
                                           authorization_request=descriptor))
    relay.phase = "controller-authorization-" + name
    relay.select_authorization_request(descriptor)
    try:
        request = urllib.request.Request(relay.origin + descriptor.target, method="GET")
        with opener.open(request, timeout=8) as response:
            require(response.status == 200 and not response.headers.get("Content-Encoding"), "authorization_provider_response")
            raw = response.read(MAX_HTTP_BODY + 1)
            require(len(raw) <= MAX_HTTP_BODY, "authorization_provider_response_limit")
            private.add(raw)
        require(relay.authorization_request_used is True, "authorization_request_not_observed")
        forms = FormParser(raw).forms
        require(len(forms) == 1 and forms[0]["method"] == "post" and forms[0]["action"] == redirect,
                "authorization_provider_form")
        values = forms[0]["inputs"]
        require(type(values) is dict and values.get("state") == descriptor.state
                and values.get("iss") == relay.origin + REALM_PATH
                and ("code" in values) != ("error" in values), "authorization_provider_form_binding")
        if name == "initiated-provider-error":
            require(values.get("error") == "invalid_scope" and "code" not in values, "authorization_provider_error_oracle")
        else:
            require("error" not in values and type(values.get("code")) is str
                    and 1 <= len(values["code"]) <= 2048, "authorization_provider_code")
            private.add(values["code"])
        for cookie in jar:
            private.add(cookie.value)
        require(_read_handoff(handoff_path, stop) == original, "authorization_handoff_modified")
        fields = dict(values)
        if name == "initiated-wrong-state":
            fields["state"] = "controlled-wrong-state-value-for-negative"
        elif name == "initiated-wrong-issuer":
            fields["iss"] = "https://unrelated.invalid/owned-issuer"
        relay.phase = name
        submission = submit_authorization_callback(redirect, relay.origin, fields, private)
        return {**submission, "handoff_preserved_before_submission": True,
                "product_generated_request_used": True, "authorization_get_count": 1,
                "controlled_challenge_substitution": descriptor.substituted,
                "provider_error_class": "invalid_scope" if name == "initiated-provider-error" else None,
                "interactive_login_performed": False}
    except (OSError, urllib.error.URLError, http.client.HTTPException):
        raise LabError("authorization_provider_transport") from None
    finally:
        relay.authorization_request = None


def closed_callback_replay_control(redirect: str) -> dict:
    _authorization_callback(redirect)
    port = urllib.parse.urlsplit(redirect).port
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            accepted = True
    except OSError:
        accepted = False
    require(accepted is False, "authorization_listener_reopened")
    return {"execution_class": "controller_after_completed_product_flow", "connection_attempt_count": 1,
            "connection_accepted": False, "form_resubmitted": False,
            "meaning": "closed_single_use_listener_not_provider_code_replay_or_identity_proof"}


def realm_document(resource_secret: str, controller_secret: str, redirect: str,
                   authorization_redirects: tuple[str, ...] = ()) -> dict:
    """Original fixture configuration, not scanner input or expected inventory."""
    require(type(authorization_redirects) is tuple and len(authorization_redirects) in (0, 5)
            and len(set(authorization_redirects)) == len(authorization_redirects), "authorization_callback_registry")
    for callback in authorization_redirects:
        _authorization_callback(callback)
    return {
        "realm": REALM, "enabled": True, "sslRequired": "none",
        "registrationAllowed": False, "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False, "duplicateEmailsAllowed": False,
        "accessTokenLifespan": 180, "accessCodeLifespan": 120,
        # Reviewed pinned RealmRepresentation/TokenManager contract. A separate
        # after-flow controller check observes provider reuse behavior; this
        # configuration never promotes the product's rotation assurance.
        "revokeRefreshToken": True, "refreshTokenMaxReuse": 0,
        "defaultDefaultClientScopes": [], "defaultOptionalClientScopes": [],
        "clientScopes": [{"name": SCOPE, "protocol": "openid-connect",
                          "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
                          "protocolMappers": [{"name": "owned-resource-audience", "protocol": "openid-connect",
                                                "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
                                                "config": {"included.client.audience": RESOURCE_CLIENT,
                                                           "access.token.claim": "true", "id.token.claim": "false",
                                                           "introspection.token.claim": "true"}}]}],
        "clients": [
            {"clientId": PUBLIC_CLIENT, "enabled": True, "protocol": "openid-connect", "publicClient": True,
             "standardFlowEnabled": True, "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
             "serviceAccountsEnabled": False, "consentRequired": False, "redirectUris": [redirect, *authorization_redirects],
             "defaultClientScopes": [], "optionalClientScopes": [SCOPE],
             "attributes": {"pkce.code.challenge.method": "S256"}},
            {"clientId": RESOURCE_CLIENT, "enabled": True, "protocol": "openid-connect", "publicClient": False,
             "secret": resource_secret, "clientAuthenticatorType": "client-secret",
             "standardFlowEnabled": False, "implicitFlowEnabled": False,
             "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
             "defaultClientScopes": [], "optionalClientScopes": []},
            {"clientId": CONTROLLER_CLIENT, "enabled": True, "protocol": "openid-connect", "publicClient": False,
             "secret": controller_secret, "clientAuthenticatorType": "client-secret",
             "standardFlowEnabled": False, "implicitFlowEnabled": False,
             "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
             "fullScopeAllowed": True, "defaultClientScopes": [], "optionalClientScopes": [],
             "protocolMappers": [{"name": "owned-admin-impersonation-role", "protocol": "openid-connect",
                                  "protocolMapper": "oidc-usermodel-client-role-mapper", "consentRequired": False,
                                  "config": {"usermodel.clientRoleMapping.clientId": "realm-management",
                                             "claim.name": "resource_access.realm-management.roles", "multivalued": "true",
                                             "jsonType.label": "String", "access.token.claim": "true"}}]},
        ],
        "users": [{"id": identifier, "username": user, "enabled": True, "emailVerified": True, "requiredActions": [],
                   "firstName": "Owned", "lastName": "Canary", "email": user + "@invalid.example",
                   "credentials": []} for user, identifier in USER_IDS.items()] + [
                       {"username": "service-account-" + CONTROLLER_CLIENT, "enabled": True,
                        "serviceAccountClientId": CONTROLLER_CLIENT,
                        "clientRoles": {"realm-management": ["impersonation"]}}],
    }


class OwnedHTTPServer(http.server.HTTPServer):
    allow_reuse_address = False

    def __init__(self, handler):
        super().__init__(("127.0.0.1", 0), handler)
        self.timeout = 1
        self.handler_failed = False
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def start(self) -> None:
        self.thread.start()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def handle_error(self, request, client_address):
        # BaseServer's default traceback can disclose private response/path
        # context. Preserve a typed failure, not a raw diagnostic transcript.
        self.handler_failed = True

    def stop(self) -> None:
        if self.thread.is_alive():
            self.shutdown()
        self.server_close()
        self.thread.join(timeout=10)
        require(not self.thread.is_alive(), "owned_server_cleanup")


def _read_request(handler: http.server.BaseHTTPRequestHandler, maximum: int) -> bytes:
    require(handler.headers.get("Transfer-Encoding") is None, "fixture_transfer_encoding")
    length = handler.headers.get("Content-Length", "0")
    require(re.fullmatch(r"[0-9]{1,6}", length) is not None and int(length) <= maximum, "fixture_request_size")
    data = handler.rfile.read(int(length))
    require(len(data) == int(length), "fixture_request_incomplete")
    return data


def _send(handler, status: int, body: bytes, content_type: str, headers: list = ()) -> None:
    handler.send_response(status)
    for key, value in headers:
        if key.lower() in {"content-type", "set-cookie", "cache-control", "pragma", "location"}:
            handler.send_header(key, value)
    if not any(key.lower() == "content-type" for key, _ in headers):
        handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.close_connection = True


def public_token_grant(body: bytes, redirect: str | None, initiated_private: PrivateValues | None = None) -> str:
    """Reduce a selected public-client form to a closed class, never its values."""
    require(type(body) is bytes and 0 < len(body) <= 16 * 1024, "public_token_form_size")
    try:
        pairs = urllib.parse.parse_qsl(body.decode("ascii"), keep_blank_values=True,
                                      strict_parsing=True, errors="strict", max_num_fields=5)
    except (UnicodeError, ValueError):
        raise LabError("public_token_form") from None
    fields = dict(pairs)
    require(len(pairs) == len(fields) and fields.get("client_id") == PUBLIC_CLIENT, "public_token_form")
    kind = fields.get("grant_type")
    if kind == "authorization_code":
        require(set(fields) == {"grant_type", "client_id", "redirect_uri", "code", "code_verifier"}
                and type(redirect) is str and fields["redirect_uri"] == redirect
                and 1 <= len(fields["code"]) <= 2048
                and all(0x21 <= ord(c) <= 0x7e for c in fields["code"])
                and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", fields["code_verifier"]) is not None,
                "public_token_form")
    elif kind == "refresh_token":
        require(set(fields) == {"grant_type", "client_id", "refresh_token", "scope"}
                and fields["scope"] == SCOPE and 1 <= len(fields["refresh_token"]) <= 8192
                and all(0x20 <= ord(c) <= 0x7e for c in fields["refresh_token"]), "public_token_form")
    else:
        raise LabError("public_token_grant")
    if initiated_private is not None:
        require(type(initiated_private) is PrivateValues and kind == "authorization_code", "authorization_private_form")
        # Unlike imported grants, these values were generated inside Termivar.
        # Register them at the relay BEFORE any provider dispatch or CLI output
        # check. Whole encoded body and individual values guard different sinks.
        initiated_private.add(fields["code"])
        initiated_private.add(fields["code_verifier"])
        initiated_private.add(body)
    return kind


@dataclasses.dataclass(repr=False)
class _RefreshCapture:
    # At most one initial private RT per each of three closed scenarios. The
    # replacement is compared then discarded here; the leakage registry remains
    # separately bounded. No raw body/token or digest is serialized as evidence.
    initial_refresh: str | None = None
    initial_returned: bool = False
    refresh_responses: int = 0
    replacement_returned: bool | None = None
    replacement_value_differs: bool | None = None


class TokenRelay:
    def __init__(self, private: PrivateValues):
        self.private = private
        self._upstream = None
        self.phase = "setup"
        self.trace: list[dict] = []
        self.errors: list[str] = []
        self.failure_causes: list[str] = []
        self.public_redirect: str | None = None
        self.scanner_scenarios_complete = False
        self._refresh_captures: dict[str, _RefreshCapture] = {}
        self.authorization_private: PrivateValues | None = None
        self.authorization_request: _InitiatedAuthorizationRequest | None = None
        self.authorization_request_used = False
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                try:
                    initiated = owner.authorization_request if self.command == "GET" and owner.authorization_request is not None else None
                    if initiated is not None:
                        require(owner.phase in tuple("controller-authorization-" + name for name in AUTHORIZATION_SCENARIOS)
                                and self.path == initiated.target and owner.authorization_request_used is False,
                                "relay_authorization_request_refused")
                        initiated.validate(urllib.parse.urlsplit(owner.origin).netloc)
                        owner.authorization_request_used = True
                        role = "controller-authorization"
                    else:
                        role = _provider_route(self.command, self.path)
                    require(type(owner._upstream) is _OwnedIdpUpstream and len(owner.trace) < MAX_TRACE, "relay_not_ready_or_limit")
                    body = _read_request(self, MAX_HTTP_BODY)
                    grant_type = None
                    public = owner.phase in SCENARIOS + AUTHORIZATION_SCENARIOS and role == "token-exchange"
                    if public:
                        require(self.command == "POST" and not self.headers.get("Authorization")
                                and not self.headers.get("Cookie")
                                and self.headers.get("Content-Type") == "application/x-www-form-urlencoded"
                                and self.headers.get("Accept-Encoding") == "identity", "public_token_context")
                        grant_type = public_token_grant(body, owner.public_redirect,
                            owner.active_private() if owner.phase in AUTHORIZATION_SCENARIOS else None)
                    headers = {"Host": urllib.parse.urlsplit(owner.origin).netloc, "Accept-Encoding": "identity"}
                    for key in ("Content-Type", "Cookie", "Authorization", "Accept"):
                        if self.headers.get(key) is not None:
                            require(len(self.headers[key]) <= 16384, "relay_header_limit")
                            headers[key] = self.headers[key]
                    if initiated is not None:
                        require(not body and not self.headers.get("Authorization"), "relay_authorization_request_refused")
                        status, response_headers, response_body = owner._upstream.request_authorization(initiated, headers)
                    else:
                        status, response_headers, response_body = owner._upstream.request(self.command, self.path, body or None, headers)
                    require(not any(k.lower() == "content-encoding" for k, _ in response_headers), "relay_coded_response")
                    # Values are only checked for leakage in private memory. The
                    # provider response is forwarded unchanged, never repaired.
                    error_class = None
                    capture_flags = {"refresh_token_present": None, "replacement_value_differs": None}
                    if role == "token-exchange":
                        try:
                            document = strict_json(response_body, MAX_TOKEN_BODY)
                        except LabError:
                            document = None
                        if isinstance(document, dict):
                            # Registry/capture failures must not be swallowed as
                            # malformed JSON and silently disable privacy checks.
                            for name in ("access_token", "refresh_token", "id_token"):
                                if isinstance(document.get(name), str):
                                    owner.active_private().add(document[name])
                            if document.get("error") == "invalid_grant":
                                error_class = "invalid_grant"
                            if public and owner.phase in REFRESH_SCENARIOS:
                                owner.private.add(response_body)
                                capture_flags = owner._capture_refresh(grant_type, status, document)
                            elif public and owner.phase in AUTHORIZATION_SCENARIOS:
                                owner.active_private().add(response_body)
                    owner.trace.append({"phase": owner.phase, "role": role, "method": self.command,
                                        "request_bytes": len(body), "status": status,
                                        "response_bytes": len(response_body), "error_class": error_class,
                                        "grant_type": grant_type,
                                        "credential_header_present": bool(self.headers.get("Authorization")),
                                        "cookie_present": bool(self.headers.get("Cookie")),
                                        "public_form_valid": public,
                                        "identity_requested": self.headers.get("Accept-Encoding") == "identity",
                                        **capture_flags})
                    _send(self, status, response_body, "application/octet-stream", response_headers)
                except (LabError, OSError, ValueError) as error:
                    _record_fixture_failure(owner, error, "relay")
                    _send(self, 502, b'{"error":"owned_relay_failure"}', "application/json")

        self.server = OwnedHTTPServer(Handler)

    def active_private(self) -> PrivateValues:
        selected = (self.phase in AUTHORIZATION_SCENARIOS
                    or self.phase in tuple("controller-authorization-" + name for name in AUTHORIZATION_SCENARIOS))
        if selected:
            require(type(self.authorization_private) is PrivateValues, "authorization_privacy_unavailable")
            return self.authorization_private
        return self.private

    def select_authorization_request(self, descriptor: _InitiatedAuthorizationRequest) -> None:
        require(type(descriptor) is _InitiatedAuthorizationRequest and self.authorization_request is None
                and self.phase in tuple("controller-authorization-" + name for name in AUTHORIZATION_SCENARIOS),
                "relay_authorization_request_refused")
        descriptor.validate(urllib.parse.urlsplit(self.origin).netloc)
        self.authorization_request = descriptor
        self.authorization_request_used = False

    def _capture_refresh(self, grant_type: str, status: int, document: dict) -> dict:
        require(self.phase in REFRESH_SCENARIOS and len(self._refresh_captures) <= 3, "refresh_capture_scope")
        capture = self._refresh_captures.setdefault(self.phase, _RefreshCapture())
        value = document.get("refresh_token")
        usable = (type(value) is str and 1 <= len(value) <= 8192
                  and all(0x20 <= ord(c) <= 0x7e for c in value))
        if grant_type == "authorization_code":
            require(capture.initial_refresh is None and capture.refresh_responses == 0, "refresh_capture_duplicate")
            capture.initial_returned = status == 200 and usable
            capture.initial_refresh = value if capture.initial_returned else None
        else:
            require(grant_type == "refresh_token" and capture.refresh_responses == 0, "refresh_capture_duplicate")
            capture.refresh_responses = 1
            capture.replacement_returned = usable if status == 200 else None
            capture.replacement_value_differs = (not secrets.compare_digest(capture.initial_refresh, value)
                                                if status == 200 and usable and capture.initial_refresh is not None else None)
        return {"refresh_token_present": capture.initial_returned if grant_type == "authorization_code" else capture.replacement_returned,
                "replacement_value_differs": None if grant_type == "authorization_code" else capture.replacement_value_differs}

    def refresh_completed(self, scenario: str) -> bool:
        capture = self._refresh_captures.get(scenario)
        return capture is not None and capture.refresh_responses == 1 and capture.replacement_value_differs is True

    def replay_initial_after_completed_flow(self, scenario: str) -> dict:
        require(self.scanner_scenarios_complete is True and scenario in REFRESH_POSITIVE
                and self.refresh_completed(scenario), "refresh_control_phase")
        capture = self._refresh_captures[scenario]
        require(type(capture.initial_refresh) is str, "refresh_control_missing_value")
        # A surprising token response can contain three sensitive fields. Do
        # not acquire more material if the existing privacy bound cannot hold it.
        require(len(self.private._values) <= 93, "refresh_control_not_run",
                {"scenario": scenario, "status": "not_run", "reason": "private_registry_capacity"})
        previous_phase = self.phase
        self.phase = "controller-old-refresh-" + scenario
        try:
            status, _, data = request_bytes(self.origin + TOKEN_PATH, "POST", encoded_form({
                "grant_type": "refresh_token", "client_id": PUBLIC_CLIENT,
                "refresh_token": capture.initial_refresh, "scope": SCOPE}),
                {"Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "identity"},
                maximum=MAX_TOKEN_BODY)
            document = strict_json(data, MAX_TOKEN_BODY)
            error_class = "invalid_grant" if type(document) is dict and document.get("error") == "invalid_grant" else "other_or_missing"
            require(status == 400 and error_class == "invalid_grant", "refresh_control_provider_result",
                    {"scenario": scenario, "status": status if type(status) is int else marker(status),
                     "error_class": error_class, "operation": "controller_after_completed_flow"})
            return {"execution_class": "independent_controller_after_all_completed_scans",
                    "request_count": 1, "status": status, "error_class": error_class,
                    "product_server_replay_detection_established": False}
        finally:
            capture.initial_refresh = None
            self.phase = previous_phase

    def clear_refresh_values(self) -> None:
        for capture in self._refresh_captures.values():
            capture.initial_refresh = None

    def bind_upstream(self, upstream: _OwnedIdpUpstream) -> None:
        require(type(upstream) is _OwnedIdpUpstream and upstream._seal is _IDP_UPSTREAM_SEAL
                and self._upstream is None, "idp_binding_already_frozen_or_invalid")
        upstream._validate()
        self._upstream = upstream

    @property
    def origin(self) -> str:
        return self.server.origin

    def start(self) -> None:
        self.server.start()

    def stop(self) -> None:
        self.server.stop()


class TargetApplication:
    def __init__(self, relay: TokenRelay, resource_secret: str):
        self.relay = relay
        self.resource_secret = resource_secret
        self.expected_user = "canary-a"
        self.deny_renewed_health = False
        self.phase = "setup"
        self.trace: list[dict] = []
        self.errors: list[str] = []
        self.failure_causes: list[str] = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_HEAD(self):
                self.respond(head=True)

            def do_GET(self):
                self.respond()

            def respond(self, head=False):
                try:
                    require(len(owner.trace) < MAX_TRACE and not self.headers.get("Cookie"), "target_context_or_limit")
                    parsed = urllib.parse.urlsplit(self.path)
                    require(not parsed.query and not parsed.fragment, "target_query")
                    authorization = self.headers.get("Authorization")
                    role = {HEALTH: "health", RESOURCES[0]: "resource-one", RESOURCES[1]: "resource-two"}.get(parsed.path, "ordinary")
                    healthy = False
                    provider_active = application_gate_denied = False
                    canary_a = canary_b = False
                    if authorization:
                        require(self.command == "GET" and role != "ordinary" and authorization.startswith("Bearer "), "target_credential_scope")
                        token = authorization[7:]
                        owner.relay.active_private().add(token)
                        if owner.phase in AUTHORIZATION_SCENARIOS:
                            owner.relay.active_private().add(authorization)
                        basic = base64.b64encode((RESOURCE_CLIENT + ":" + owner.resource_secret).encode()).decode()
                        status, _, data = request_bytes(owner.relay.origin + INTROSPECTION_PATH, "POST",
                            encoded_form({"token": token, "token_type_hint": "access_token"}),
                            {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + basic}, maximum=MAX_TOKEN_BODY)
                        require(status == 200, "target_introspection_status")
                        document = strict_json(data, MAX_TOKEN_BODY)
                        provider_active = type(document) is dict and document.get("active") is True
                        canary_a = introspection_allows(document, "canary-a")
                        canary_b = introspection_allows(document, "canary-b")
                        healthy = canary_a if owner.expected_user == "canary-a" else canary_b
                        application_gate_denied = owner.deny_renewed_health and owner.relay.refresh_completed(owner.phase)
                        if application_gate_denied:
                            # This owned APPLICATION policy refuses its renewed
                            # context despite separately active provider tokens.
                            # No provider expiry/principal/revocation is claimed.
                            canary_a = canary_b = healthy = False
                    if role == "ordinary":
                        require(not authorization and parsed.path == "/", "target_ordinary_scope")
                        body, status, mime = b"<!doctype html><main>owned anonymous application</main>", 200, "text/html; charset=utf-8"
                    elif role == "health":
                        body, status, mime = json.dumps({"canary_a": canary_a, "canary_b": canary_b}).encode(), 200, "application/json"
                    elif healthy:
                        body, status, mime = b'{"record":"harmless-owned-canary"}', 200, "application/json"
                    else:
                        body, status, mime = b'{"denied":true}', 403, "application/json"
                    owner.trace.append({"phase": owner.phase, "role": role, "method": self.command,
                                        "credential_present": bool(authorization), "accepted": healthy,
                                        "entry_path": parsed.path == "/", "response_bytes": 0 if head else len(body),
                                        "provider_active": provider_active,
                                        "application_gate_denied": application_gate_denied})
                    _send(self, status, b"" if head else body, mime)
                except (LabError, OSError, ValueError) as error:
                    _record_fixture_failure(owner, error, "target")
                    _send(self, 500, b'{"error":"owned_target_failure"}', "application/json")

        self.server = OwnedHTTPServer(Handler)

    @property
    def origin(self) -> str:
        return self.server.origin

    def start(self) -> None:
        self.server.start()

    def stop(self) -> None:
        self.server.stop()


def introspection_allows(document: object, expected_user: str) -> bool:
    require(isinstance(document, dict), "introspection_object")
    audience = document.get("aud")
    if isinstance(audience, str):
        audience = [audience]
    return (document.get("active") is True and document.get("username") == expected_user
            and isinstance(audience, list) and all(isinstance(v, str) for v in audience)
            and RESOURCE_CLIENT in audience and document.get("scope") == SCOPE
            and document.get("client_id") == PUBLIC_CLIENT)


# Fixed original shell, not an interpolated command or downloaded script.
# Secrets arrive only on stdin and are written to bounded ephemeral tmpfs.
BOOTSTRAP = r'''set -euo pipefail
umask 077
IFS= read -r realm
printf '%s' "$realm" > /tmp/termivar-owned-realm.json
unset realm
/opt/keycloak/bin/kc.sh import --file /tmp/termivar-owned-realm.json --override false
exec /opt/keycloak/bin/kc.sh start-dev --http-enabled true --hostname "$1" --hostname-strict true --cache local
'''


class KeycloakLab:
    def __init__(self, runner: Runner, relay: TokenRelay, realm: dict):
        self.runner = runner
        self.relay = relay
        self.realm = realm
        self.owner = "termivar-oauth-" + uuid.uuid4().hex[:16]
        self.network = self.owner + "-net"
        self.container = self.owner + "-idp"
        self.network_created = False
        self.container_created = False
        self.attached = None
        self.image_inspection = None
        self._binding = None
        self._last_owned_state = {"observation_scope": "last_inspected_before_client_exit_not_atomic_final_state",
                                  "ownership": "not_established", "state": "unavailable"}
        self.setup_evidence = {"internal_network_plan_validated": False, "isolation_validated": False,
                               "no_host_port_bindings_validated": False, "log_configuration_validated": False,
                               "binding_frozen": False, "binding_count": 0, "last_binding_state": "not_observed",
                               "metadata_attempt_count": 0, "metadata_response_count": 0,
                               "metadata_status_counts": {}, "owned_http_transport_failure_count": 0,
                               "last_metadata": {"state": "not_observed", "json_type": None,
                                                 "issuer_matches": None, "token_endpoint_matches": None}}

    def _setup_diagnostic(self, inspected: object) -> dict:
        try:
            facts = self.setup_evidence
            for key in ("binding_count", "metadata_attempt_count", "metadata_response_count", "owned_http_transport_failure_count"):
                require(integer(facts[key]) and facts[key] <= MAX_TRACE, "readiness_diagnostic_count")
            bins = facts["metadata_status_counts"]
            require(type(bins) is dict and len(bins) <= MAX_TRACE
                    and all(type(key) is str and re.fullmatch(r"[1-5][0-9]{2}", key)
                            and integer(value) and 1 <= value <= MAX_TRACE for key, value in bins.items())
                    and sum(bins.values()) == facts["metadata_response_count"]
                    and facts["metadata_attempt_count"] == facts["metadata_response_count"] + facts["owned_http_transport_failure_count"]
                    and facts["binding_count"] in (0, 1), "readiness_diagnostic_count")
            require(all(type(facts[key]) is bool for key in ("internal_network_plan_validated", "isolation_validated",
                        "no_host_port_bindings_validated", "log_configuration_validated", "binding_frozen"))
                    and facts["binding_frozen"] == (facts["binding_count"] == 1)
                    and facts["last_binding_state"] in ("not_observed", "pending_running_or_private_address", "validated_frozen_private_backend"),
                    "readiness_diagnostic_state")
            metadata = facts["last_metadata"]
            require(type(metadata) is dict and set(metadata) == {"state", "json_type", "issuer_matches", "token_endpoint_matches"}
                    and metadata["state"] in ("not_observed", "response_not_200", "parsed", "transport_unavailable", "json_malformed")
                    and metadata["json_type"] in (None, "object", "array", "string", "boolean", "integer", "number", "null")
                    and all(value is None or type(value) is bool for value in (metadata["issuer_matches"], metadata["token_endpoint_matches"])),
                    "readiness_diagnostic_metadata")
            diagnostic = {"phase": "owned_provider_readiness", **facts,
                          "metadata_status_counts": dict(bins), "last_metadata": dict(facts["last_metadata"]),
                          "last_owned_container_inspection": last_owned_container_state(inspected, self.owner) if inspected is not None else self._last_owned_state}
            self.runner.private.check(json.dumps(diagnostic, sort_keys=True).encode())
            return diagnostic
        except Exception:
            return {"phase": "owned_provider_readiness", "diagnostic_state": "unavailable"}

    def prepare(self) -> None:
        require(sys.platform.startswith("linux"), "linux_docker_required")
        require(not os.environ.get("DOCKER_HOST") or os.environ["DOCKER_HOST"] == "unix:///var/run/docker.sock", "remote_docker_refused")
        context = self.runner.run(["docker", "context", "show"], label="docker-local-context")
        require(context.stdout.strip() == b"default", "nondefault_docker_context_refused")
        self.runner.run(["docker", "pull", "--platform", "linux/amd64", IMAGE], label="prepare-pinned-idp", timeout=300)
        image = strict_json(self.runner.run(["docker", "image", "inspect", IMAGE], label="inspect-idp-image").stdout,
                            MAX_HTTP_BODY)
        self.image_inspection = validate_image_inspection(image)
        self.runner.run(["docker", "network", "create", "--internal", "--driver", "bridge",
                         "--label", "termivar.oauth.owner=" + self.owner, self.network], label="create-owned-network")
        self.network_created = True
        network = strict_json(self.runner.run(["docker", "network", "inspect", self.network], label="inspect-owned-network").stdout,
                              MAX_HTTP_BODY)
        require(type(network) is list and len(network) == 1, "idp_network_identity")
        _owned_network_plan(network[0], self.owner, self.network)
        self.setup_evidence["internal_network_plan_validated"] = True
        args = ["docker", "create", "--pull=never", "--platform", "linux/amd64", "--interactive",
                "--name", self.container, "--label", "termivar.oauth.owner=" + self.owner,
                "--network", self.network,
                "--user", "1000:0", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
                "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
                "--log-opt", "compress=false",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=67108864,uid=1000,gid=0,mode=1700",
                "--tmpfs", "/opt/keycloak/data:rw,nosuid,nodev,noexec,size=201326592,uid=1000,gid=0,mode=1700",
                "--env", "KC_DB=dev-file", "--env", "KC_CACHE=local",
                "--env", "JAVA_OPTS_KC_HEAP=-Xms64m -Xmx512m",
                "--entrypoint", "/bin/bash", IMAGE, "-c", BOOTSTRAP, "owned-bootstrap", self.relay.origin]
        self.runner.run(args, label="create-owned-idp")
        self.container_created = True
        payload = json.dumps(self.realm, separators=(",", ":")).encode() + b"\n"
        self.attached = CapturedChild(["docker", "start", "--attach", "--interactive", self.container], payload)
        deadline = time.monotonic() + SETUP_SECONDS
        inspected = None
        while time.monotonic() < deadline:
            try:
                status = self.attached.process.poll()
                overflow = self.attached.overflow.is_set()
            except Exception:
                raise LabError("idp_startup_failure", {"phase": "attached_provider_before_readiness",
                                                       "failure_classes": ["unknown"],
                                                       "diagnostic_errors": ["attachment_state_unavailable"]}) from None
            if status is not None or overflow:
                try:
                    diagnostic = startup_failure_diagnostic(self.attached, status, getattr(self.runner, "private", None),
                                                            last_inspected=inspected, owner=self.owner, overflow=overflow)
                except Exception:
                    diagnostic = {"phase": "attached_provider_before_readiness", "failure_classes": ["unknown"],
                                  "diagnostic_errors": ["startup_diagnostic_unavailable"]}
                raise LabError("idp_startup_failure", diagnostic)
            inspected = strict_json(self.runner.run(["docker", "inspect", self.container], label="inspect-owned-idp", sensitive_output=True).stdout)
            require(type(inspected) is list and len(inspected) == 1, "idp_container_identity")
            try:
                self._last_owned_state = last_owned_container_state(inspected, self.owner)
            except Exception:
                pass
            candidate = owned_idp_upstream(inspected[0], network[0], self.owner, self.network, self.relay.origin)
            self.setup_evidence.update({"isolation_validated": True, "no_host_port_bindings_validated": True,
                                        "log_configuration_validated": True})
            if candidate is None:
                require(self._binding is None, "idp_binding_lost")
                self.setup_evidence["last_binding_state"] = "pending_running_or_private_address"
            else:
                if self._binding is None:
                    self.relay.bind_upstream(candidate)
                    self._binding = candidate
                    self.setup_evidence.update({"binding_frozen": True, "binding_count": 1})
                else:
                    require(candidate == self._binding, "idp_binding_changed")
                self.setup_evidence["last_binding_state"] = "validated_frozen_private_backend"
                self.setup_evidence["metadata_attempt_count"] += 1
                try:
                    status, _, data = request_bytes(self.relay.origin + REALM_PATH + "/.well-known/openid-configuration", "GET")
                    require(type(status) is int and 100 <= status <= 599, "idp_metadata_status")
                    self.setup_evidence["metadata_response_count"] += 1
                    bins = self.setup_evidence["metadata_status_counts"]
                    bins[str(status)] = bins.get(str(status), 0) + 1
                    self.setup_evidence["last_metadata"] = {"state": "response_not_200", "json_type": None,
                                                            "issuer_matches": None, "token_endpoint_matches": None}
                    if status == 200:
                        document = strict_json(data)
                        kind = {dict: "object", list: "array", str: "string", bool: "boolean", int: "integer", float: "number", type(None): "null"}[type(document)]
                        self.setup_evidence["last_metadata"].update({"state": "parsed", "json_type": kind})
                        require(type(document) is dict, "idp_metadata_object")
                        issuer = document.get("issuer") == self.relay.origin + REALM_PATH
                        token = document.get("token_endpoint") == self.relay.origin + TOKEN_PATH
                        self.setup_evidence["last_metadata"].update({"issuer_matches": issuer, "token_endpoint_matches": token})
                        require(issuer and token, "idp_advertised_origin", self._setup_diagnostic(inspected))
                        break
                except LabError as error:
                    if error.code == "owned_http_transport":
                        self.setup_evidence["owned_http_transport_failure_count"] += 1
                        self.setup_evidence["last_metadata"] = {"state": "transport_unavailable", "json_type": None,
                                                                "issuer_matches": None, "token_endpoint_matches": None}
                    elif error.code == "json_malformed":
                        self.setup_evidence["last_metadata"]["state"] = "json_malformed"
                    if error.code not in ("owned_http_transport", "json_malformed"):
                        raise
            time.sleep(1)
        else:
            raise LabError("idp_readiness_timeout", self._setup_diagnostic(inspected))
        # Readiness connection failures are not scanner acceptance failures.
        self.relay.errors.clear()
        self.relay.failure_causes.clear()
        self.relay.trace.clear()
        self.relay.server.handler_failed = False

    def cleanup(self) -> dict:
        failures = []
        if self.container_created:
            try:
                inspected = strict_json(self.runner.run(["docker", "inspect", self.container], label="cleanup-owned-identity", sensitive_output=True).stdout)
                require(inspected[0].get("Config", {}).get("Labels", {}).get("termivar.oauth.owner") == self.owner, "cleanup_owner")
                self.runner.run(["docker", "stop", "--time", "10", self.container], label="stop-owned-idp", timeout=30)
                self.runner.run(["docker", "rm", self.container], label="remove-owned-idp")
                self.container_created = False
            except LabError:
                failures.append("container_cleanup_failed")
        if self.attached is not None:
            try:
                self.attached.finish(15)
            except LabError:
                self.attached.stop()
                failures.append("attachment_cleanup_failed")
        if self.network_created and not self.container_created:
            try:
                document = strict_json(self.runner.run(["docker", "network", "inspect", self.network], label="cleanup-owned-network-identity").stdout)
                require(isinstance(document, list) and len(document) == 1
                        and document[0].get("Labels", {}).get("termivar.oauth.owner") == self.owner,
                        "cleanup_network_owner")
                self.runner.run(["docker", "network", "rm", self.network], label="remove-owned-network")
                self.network_created = False
            except LabError:
                failures.append("network_cleanup_failed")
        return {"status": "complete" if not failures else "failed", "failures": failures,
                "container_removed": not self.container_created, "network_removed": not self.network_created}


def validate_isolation(container: dict, network: dict, owner: str, name: str) -> None:
    config, host = container.get("Config", {}), container.get("HostConfig", {})
    require(config.get("User") == "1000:0" and config.get("Labels", {}).get("termivar.oauth.owner") == owner,
            "isolation_owner_user")
    require(host.get("Privileged") is False and host.get("CapDrop") == ["ALL"]
            and "no-new-privileges=true" in host.get("SecurityOpt", [])
            and host.get("NetworkMode") == name and not host.get("Binds")
            and host.get("Memory") == 1073741824 and host.get("PidsLimit") == 256, "isolation_host")
    logging = host.get("LogConfig")
    require(type(logging) is dict and set(logging) == {"Type", "Config"}
            and type(logging.get("Type")) is str and logging["Type"] == "local"
            and type(logging.get("Config")) is dict
            and all(type(value) is str for value in logging["Config"].values())
            and logging["Config"] == {"max-size": "1m", "max-file": "1", "compress": "false"},
            "isolation_log_config")
    require(isinstance(host.get("Tmpfs"), dict)
            and set(host["Tmpfs"]) == {"/tmp", "/opt/keycloak/data"}
            and all(isinstance(value, str) and "size=" in value and "uid=1000" in value
                    for value in host["Tmpfs"].values()), "isolation_tmpfs")
    require(all(row.get("Type") == "tmpfs" for row in container.get("Mounts", [])), "isolation_mount")
    require(network.get("Internal") is True and network.get("Driver") == "bridge"
            and network.get("Labels", {}).get("termivar.oauth.owner") == owner, "isolation_network")
    ports = host.get("PortBindings")
    require(ports is None or type(ports) is dict and not ports, "isolation_port")
    settings = container.get("NetworkSettings")
    exposed = settings.get("Ports") if type(settings) is dict else None
    require(exposed is None or type(exposed) is dict and all(value is None for value in exposed.values()), "isolation_port")


def policy_source(issuer: str, redirect: str, principal: str, *, renewable: bool = False) -> bytes:
    require(principal in ("canary-a", "canary-b"), "fixture_principal")
    require(type(renewable) is bool, "fixture_policy_mode")
    source = f'''schema = "security.supplied-session-policy/v{6 if renewable else 5}"
principal_alias = "{principal}"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "{'canary_b' if principal == 'canary-b' else 'canary_a'}"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = {8 if renewable else 6}
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000

[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "{issuer}"
token_endpoint = "{issuer}/protocol/openid-connect/token"
client_id = "{PUBLIC_CLIENT}"
redirect_uri = "{redirect}"
scopes = ["canary-read"]
max_token_response_bytes = 8192
'''
    if renewable:
        source += '''
[oauth_refresh]
profile = "scheduled-public-bearer-refresh/v1"
after_resource_count = 1
max_attempts = 1
'''
    return source.encode()


def authorization_policy_source(issuer: str, redirect: str, name: str) -> bytes:
    require(name in AUTHORIZATION_SCENARIOS, "authorization_scenario")
    _authorization_callback(redirect)
    scope = AUTHORIZATION_UNASSIGNED_SCOPE if name == "initiated-provider-error" else SCOPE
    return f'''schema = "security.supplied-session-policy/v7"
principal_alias = "canary-a"
credential_mechanism = "authorization_header"
credential_acquisition = "client_initiated_oauth_pkce"
health_path = "/app/health"
health_json_field = "canary_a"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 6
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 10000
[oauth_code]
profile = "client-initiated-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "{issuer}"
token_endpoint = "{issuer}/protocol/openid-connect/token"
client_id = "{PUBLIC_CLIENT}"
redirect_uri = "{redirect}"
scopes = ["{scope}"]
max_token_response_bytes = 8192
[oauth_authorization]
profile = "loopback-form-post-state/v1"
authorization_endpoint = "{issuer}/protocol/openid-connect/auth"
max_wait_ms = {AUTHORIZATION_WAIT_MS}
'''.encode()


def validate_authorization_fixture_policy(source: bytes, issuer: str, redirect: str, name: str) -> None:
    try:
        value = tomllib.loads(source.decode())
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise LabError("authorization_fixture_policy") from None
    code, authorization = value.get("oauth_code"), value.get("oauth_authorization")
    require(set(value) == {"schema", "principal_alias", "credential_mechanism", "credential_acquisition",
                           "health_path", "health_json_field", "resources", "max_session_requests",
                           "max_total_response_bytes", "max_response_body_bytes", "max_wall_time_ms",
                           "oauth_code", "oauth_authorization"}
            and value.get("schema") == "security.supplied-session-policy/v7"
            and value.get("principal_alias") == "canary-a"
            and value.get("credential_mechanism") == "authorization_header"
            and value.get("credential_acquisition") == "client_initiated_oauth_pkce"
            and value.get("health_path") == HEALTH and value.get("health_json_field") == "canary_a"
            and value.get("resources") == list(RESOURCES)
            and all(type(value.get(key)) is int and value[key] == expected for key, expected in {
                "max_session_requests": 6, "max_total_response_bytes": 65536,
                "max_response_body_bytes": 8192, "max_wall_time_ms": 10000}.items()),
            "authorization_fixture_policy")
    scope = AUTHORIZATION_UNASSIGNED_SCOPE if name == "initiated-provider-error" else SCOPE
    require(type(code) is dict and code == {
        "profile": "client-initiated-public-code-s256-bearer/v1", "transport_profile": "owned-numeric-loopback-http/v1",
        "issuer": issuer, "token_endpoint": issuer + "/protocol/openid-connect/token", "client_id": PUBLIC_CLIENT,
        "redirect_uri": _authorization_callback(redirect), "scopes": [scope], "max_token_response_bytes": 8192}
        and type(code["max_token_response_bytes"]) is int
        and type(authorization) is dict and authorization == {
            "profile": "loopback-form-post-state/v1", "authorization_endpoint": issuer + "/protocol/openid-connect/auth",
            "max_wait_ms": 30000} and type(authorization["max_wait_ms"]) is int,
        "authorization_fixture_policy")


def validate_fixture_policy(source: bytes) -> None:
    """Narrow independent oracle for THIS owned lab, not a product importer.

    The V5 producer intersects the IdP cap with its common session body cap.
    A valid provider error/empty audit is still expected to publish a bundle.
    """
    try:
        document = tomllib.loads(source.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        raise LabError("fixture_policy_toml") from None
    nested = document.get("oauth_code")
    require(isinstance(nested, dict) and document.get("schema") in (
                "security.supplied-session-policy/v5", "security.supplied-session-policy/v6")
            and type(document.get("max_response_body_bytes")) is int
            and document["max_response_body_bytes"] == 8192
            and type(nested.get("max_token_response_bytes")) is int
            and nested["max_token_response_bytes"] == 8192
            and nested["max_token_response_bytes"] <= document["max_response_body_bytes"], "fixture_policy_body_caps")
    if document["schema"] == "security.supplied-session-policy/v6":
        refresh = document.get("oauth_refresh")
        require(type(refresh) is dict and set(refresh) == {"profile", "after_resource_count", "max_attempts"}
                and refresh["profile"] == "scheduled-public-bearer-refresh/v1"
                and type(refresh["after_resource_count"]) is int and refresh["after_resource_count"] == 1
                and type(refresh["max_attempts"]) is int and refresh["max_attempts"] == 1
                and type(document.get("max_session_requests")) is int and document["max_session_requests"] == 8
                and document.get("resources") == ["/app/private/one", "/app/private/two"], "fixture_refresh_schedule")
    else:
        require("oauth_refresh" not in document, "fixture_refresh_not_selected")


def private_write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def snapshot(directory: Path) -> dict[str, bytes]:
    require(directory.is_dir() and not directory.is_symlink(), "bundle_directory")
    result = {}
    for path in directory.iterdir():
        require(path.is_file() and not path.is_symlink(), "bundle_member")
        require(len(result) < 16 and path.stat().st_size <= MAX_OUTPUT, "bundle_size")
        result[path.name] = path.read_bytes()
        require(sum(len(data) for data in result.values()) <= MAX_BUNDLE_BYTES, "bundle_total_size")
    require({"assessment.json", "assessment.html", "manifest.json"} <= set(result), "bundle_required_members")
    return result


def selected_input_bytes(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 16 * 1024, "selected_input_shape")
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 + 1)
    require(0 < len(data) <= 16 * 1024, "selected_input_size")
    return data


def audit_from_output(result: Result, bundle: Path) -> tuple[dict | None, dict | None]:
    if bundle.is_dir():
        source = strict_json(snapshot(bundle)["assessment.json"])
        require(isinstance(source, dict), "assessment_object")
        return source.get("supplied_session"), source
    document = strict_json(result.stdout)
    require(isinstance(document, dict), "scan_diagnostic_object")
    report = document.get("assessment", {}).get("report", {})
    require(isinstance(report, dict), "scan_diagnostic_report")
    return report.get("supplied_session_audit"), None


def _opaque_reference(value: object, prefix: str) -> bool:
    return type(value) is str and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", value) is not None


def _validate_refresh_case(name: str, audit: object, session: list[dict], exchanges: list[dict],
                           diagnostic: dict) -> dict:
    require(type(audit) is dict and audit.get("schema") == "security.supplied-session-audit/v6"
            and audit.get("credential_acquisition") == "imported_oauth_code_pkce"
            and audit.get("principal_alias") == ("canary-b" if name == "refresh-b-context" else "canary-a")
            and audit.get("outcome") == EXPECTED_OUTCOMES[name], "refresh_session_contract", diagnostic)
    code, refresh = audit.get("oauth_code"), audit.get("oauth_refresh")
    require(type(code) is dict and type(refresh) is dict, "refresh_audit_objects", diagnostic)
    require(all(key in code and type(code[key]) is type(value) and code[key] == value
                for key, value in ASSURANCE.items()), "oauth_claim_boundaries", diagnostic)
    keys = {"profile", "idp_reference", "refresh_policy_reference", "after_resource_count", "max_attempts",
            "token_interpretation", "rotation_assurance", "server_replay_detection_established",
            "initial_epoch", "final_epoch", "request_attempt_count", "request_admitted_count",
            "response_completed_count", "credential_commit_count", "status", "body_state", "response_bytes",
            "configured_token_response_byte_limit", "token_response_validated", "response_scope_matched",
            "declared_token_lifetime_seconds", "replacement_refresh_token_received", "replacement_value_differs",
            "prior_credential_evidence_reference", "boundary_resource_evidence_reference",
            "boundary_health_evidence_reference", "evidence_reference", "health", "outcome"}
    require(set(refresh) == keys, "refresh_closed_fields", diagnostic)
    claims = {"profile": "scheduled-public-bearer-refresh/v1", "after_resource_count": 1,
              "max_attempts": 1, "token_interpretation": "opaque_bearer_not_oidc_identity",
              "rotation_assurance": "replacement_value_observed_not_server_revocation",
              "server_replay_detection_established": False, "initial_epoch": 1, "final_epoch": 2}
    require(all(type(refresh.get(key)) is type(value) and refresh[key] == value for key, value in claims.items()),
            "refresh_claim_boundaries", diagnostic)
    require(_opaque_reference(refresh.get("idp_reference"), "oauth-code-policy-sha256:")
            and refresh["idp_reference"] == code.get("idp_reference")
            and _opaque_reference(refresh.get("refresh_policy_reference"), "oauth-refresh-policy-sha256:"),
            "refresh_policy_binding", diagnostic)
    require(len(exchanges) == 2 and [row.get("grant_type") for row in exchanges] == ["authorization_code", "refresh_token"],
            "refresh_token_post_count", diagnostic)
    require(all(integer(row.get("response_bytes")) for row in session + exchanges), "refresh_trace_byte_types", diagnostic)
    for phase, row in zip((code, refresh), exchanges):
        require(all(integer(phase.get(key)) and phase[key] == 1 for key in (
                    "request_attempt_count", "request_admitted_count", "response_completed_count", "credential_commit_count"))
                and phase.get("status") == row.get("status") == 200
                and phase.get("body_state") == "complete" and phase.get("token_response_validated") is True
                and phase.get("response_scope_matched") is True and phase.get("outcome") == "credential_committed"
                and integer(phase.get("response_bytes")) and phase["response_bytes"] == row.get("response_bytes")
                and phase["response_bytes"] > 0 and type(phase.get("configured_token_response_byte_limit")) is int
                and phase["configured_token_response_byte_limit"] == 8192
                and integer(phase.get("declared_token_lifetime_seconds"))
                and 1 <= phase["declared_token_lifetime_seconds"] <= 3600, "refresh_exchange_accounting", diagnostic)
    require(code.get("verifier_in_admitted_request") is True and code.get("refresh_token_returned") is True
            and refresh.get("replacement_refresh_token_received") is True and refresh.get("replacement_value_differs") is True
            and exchanges[0].get("refresh_token_present") is True
            and exchanges[1].get("refresh_token_present") is True
            and exchanges[1].get("replacement_value_differs") is True, "refresh_independent_value_observation", diagnostic)
    expected_resources = EXPECTED_RESOURCES[name]
    require(all(integer(audit.get(key)) and audit[key] == value for key, value in {
        "selected_resource_count": 2, "dispatched_resource_count": expected_resources,
        "committed_resource_count": expected_resources, "dispatched_request_count": len(session) + 2,
    }.items()), "refresh_session_accounting", diagnostic)
    checkpoints, resources, health = audit.get("checkpoints"), audit.get("resources"), refresh["health"]
    healthy = name in REFRESH_POSITIVE
    require(type(checkpoints) is list and len(checkpoints) == (3 if healthy else 2)
            and all(type(row) is dict for row in checkpoints)
            and type(resources) is list and len(resources) == 2 and all(type(row) is dict for row in resources)
            and type(health) is dict, "refresh_entity_arrays", diagnostic)
    checkpoint_keys = {"sequence", "phase", "after_subject_count", "evidence_reference", "outcome", "status",
                       "body_state", "predicate", "response_bytes", "epoch"}
    require(all(set(row) == checkpoint_keys for row in checkpoints + [health])
            and all(set(row) == {"sequence", "resource_reference", "evidence_reference", "outcome", "status", "response_bytes", "epoch"}
                    for row in resources), "refresh_entity_fields", diagnostic)
    require([row.get("phase") for row in checkpoints] == (["startup", "subject_boundary", "terminal"] if healthy
                                                         else ["startup", "subject_boundary"]), "refresh_checkpoint_phases", diagnostic)
    for index, row in enumerate(checkpoints):
        wire = session[(0, 2, 5)[index]]
        require(integer(row.get("sequence")) and row["sequence"] == index
                and integer(row.get("after_subject_count")) and row["after_subject_count"] == index
                and type(row.get("epoch")) is int and row["epoch"] == (2 if index == 2 else 1)
                and row.get("status") == 200 and row.get("body_state") == "complete"
                and row.get("outcome") == "healthy" and row.get("predicate") == "matched"
                and _opaque_reference(row.get("evidence_reference"), "supplied-session-checkpoint-evidence-sha256:")
                and integer(row.get("response_bytes")) and row["response_bytes"] == wire.get("response_bytes"),
                "refresh_common_checkpoint", diagnostic)
    require(type(health.get("sequence")) is int and health["sequence"] == 2
            and health.get("phase") == "renewal" and type(health.get("after_subject_count")) is int
            and health["after_subject_count"] == 1 and type(health.get("epoch")) is int and health["epoch"] == 2
            and health.get("status") == 200 and health.get("body_state") == "complete"
            and health.get("outcome") == ("healthy" if healthy else "unhealthy")
            and health.get("predicate") == ("matched" if healthy else "not_matched")
            and _opaque_reference(health.get("evidence_reference"), "supplied-session-checkpoint-evidence-sha256:")
            and integer(health.get("response_bytes")) and health["response_bytes"] == session[3].get("response_bytes"),
            "refresh_renewed_health", diagnostic)
    for index, row in enumerate(resources):
        committed = index == 0 or healthy
        require(integer(row.get("sequence")) and row["sequence"] == index
                and type(row.get("epoch")) is int and row["epoch"] == index + 1
                and row.get("outcome") == ("committed" if committed else "not_dispatched")
                and row.get("status") == (200 if committed else None)
                and _opaque_reference(row.get("resource_reference"), "supplied-session-resource-sha256:")
                and (_opaque_reference(row.get("evidence_reference"), "supplied-session-resource-evidence-sha256:")
                     if committed else row.get("evidence_reference") is None)
                and integer(row.get("response_bytes")) and row["response_bytes"] == (session[(1, 4)[index]].get("response_bytes") if committed else 0),
                "refresh_resource_epochs", diagnostic)
    require(len({row["resource_reference"] for row in resources}) == 2, "session_resource_duplicates", diagnostic)
    require(refresh["prior_credential_evidence_reference"] == code.get("evidence_reference")
            and refresh["boundary_resource_evidence_reference"] == resources[0].get("evidence_reference")
            and refresh["boundary_health_evidence_reference"] == checkpoints[1].get("evidence_reference")
            and _opaque_reference(code.get("evidence_reference"), "supplied-session-oauth-code-evidence-sha256:")
            and _opaque_reference(refresh.get("evidence_reference"), "supplied-session-oauth-refresh-evidence-sha256:"),
            "refresh_committed_boundary_binding", diagnostic)
    evidence = [phase["evidence_reference"] for phase in (code, refresh, health)]
    evidence += [row["evidence_reference"] for row in checkpoints + resources if row["evidence_reference"] is not None]
    require(len(set(evidence)) == len(evidence), "refresh_duplicate_evidence", diagnostic)
    wire_bytes = sum(row["response_bytes"] for row in session) + sum(row["response_bytes"] for row in exchanges)
    audit_bytes = code["response_bytes"] + refresh["response_bytes"] + health["response_bytes"] + sum(row["response_bytes"] for row in checkpoints + resources)
    require(integer(audit.get("response_bytes")) and audit["response_bytes"] == wire_bytes == audit_bytes
            and type(audit.get("response_byte_limit")) is int and audit["response_byte_limit"] == 65536
            and audit.get("response_byte_limit_exceeded") is False, "refresh_byte_accounting", diagnostic)
    require(audit.get("coverage") == ("complete" if healthy else "partial")
            and audit.get("refresh_performed") is True and audit.get("anonymous_fallback_performed") is False
            and audit.get("continuous_authentication_established") is False
            and audit.get("exploit_execution") == "not_performed" and audit.get("impact_validation") == "not_performed",
            "refresh_session_claim_boundaries", diagnostic)
    require(all(row.get("provider_active") is True for row in session)
            and all(row.get("accepted") is True and row.get("application_gate_denied") is False for row in session[:3])
            and (all(row.get("accepted") is True and row.get("application_gate_denied") is False for row in session)
                 if healthy else session[-1].get("accepted") is False and session[-1].get("application_gate_denied") is True),
            "refresh_application_oracle", diagnostic)
    return {"status": "passed", "diagnostic": diagnostic, "oauth_outcome": code["outcome"],
            "refresh_outcome": refresh["outcome"], "session_outcome": audit["outcome"],
            "idp_response_bytes": code["response_bytes"] + refresh["response_bytes"],
            "session_response_bytes": audit["response_bytes"], "resource_epochs": [row["epoch"] for row in resources],
            "health_request_count": len(checkpoints) + 1,
            "application_health_refusal_not_provider_expiry": not healthy}


def validate_case(name: str, audit: object, target_rows: list[dict], idp_rows: list[dict],
                  anonymous_baseline: list[dict] | None) -> dict:
    require(name in SCENARIOS, "unknown_scenario")
    require(type(target_rows) is list and type(idp_rows) is list
            and len(target_rows) <= MAX_TRACE and len(idp_rows) <= MAX_TRACE
            and all(type(row) is dict and type(row.get("credential_present")) is bool for row in target_rows)
            and all(type(row) is dict for row in idp_rows), "case_trace_shape",
            {"scenario": name, "target_rows": marker(target_rows), "idp_rows": marker(idp_rows)})
    anonymous = [{"method": row.get("method"), "role": row.get("role"), "entry_path": row.get("entry_path")}
                 for row in target_rows if row.get("credential_present") is False]
    session = [row for row in target_rows if row.get("credential_present") is True]
    exchanges = [row for row in idp_rows if row.get("role") == "token-exchange"]
    diagnostic_oauth = audit.get("oauth_code") if isinstance(audit, dict) else None
    diagnostic = {"scenario": name,
                  "expected": {"session_requests": len(EXPECTED_SESSION_ROLES[name]) + EXPECTED_TOKEN_POSTS[name],
                               "resource_count": EXPECTED_RESOURCES[name], "token_posts": EXPECTED_TOKEN_POSTS[name],
                               "provider_sequence": list(EXPECTED_IDP_SEQUENCE[name])},
                  "actual": {"session_requests": marker(audit.get("dispatched_request_count", _MISSING)) if isinstance(audit, dict) else marker(audit),
                             "resource_count": marker(audit.get("committed_resource_count", _MISSING)) if isinstance(audit, dict) else marker(audit),
                             "token_posts": len(exchanges), "target_session_requests": len(session),
                             "oauth_code": {key: marker(diagnostic_oauth.get(key, _MISSING)) if isinstance(diagnostic_oauth, dict) else marker(diagnostic_oauth)
                                            for key in ("request_attempt_count", "request_admitted_count", "response_completed_count",
                                                        "credential_commit_count", "response_bytes", "token_response_validated")},
                             "checkpoints": marker(audit.get("checkpoints", _MISSING)) if isinstance(audit, dict) else marker(audit),
                             "resources": marker(audit.get("resources", _MISSING)) if isinstance(audit, dict) else marker(audit)}}
    diagnostic_refresh = audit.get("oauth_refresh", _MISSING) if type(audit) is dict else _MISSING
    diagnostic["actual"]["oauth_refresh"] = {key: marker(diagnostic_refresh.get(key, _MISSING)) if type(diagnostic_refresh) is dict else marker(diagnostic_refresh)
        for key in ("request_attempt_count", "request_admitted_count", "response_completed_count", "credential_commit_count",
                    "initial_epoch", "final_epoch", "response_bytes", "token_response_validated", "health")}
    require(anonymous_baseline is None or anonymous == anonymous_baseline, "ordinary_trace_changed", diagnostic)
    require(all(row.get("method") == "GET" and row.get("role") == "ordinary" and row.get("entry_path") is True
                for row in anonymous), "ordinary_trace_scope", diagnostic)
    require(tuple(row.get("role") for row in session) == EXPECTED_SESSION_ROLES[name]
            and all(row.get("method") == "GET" for row in session), "session_trace", diagnostic)
    require(len(exchanges) == EXPECTED_TOKEN_POSTS[name],
            "refresh_token_post_count" if name in REFRESH_SCENARIOS else "token_post_count", diagnostic)
    sequence = tuple(row.get("grant_type") if row.get("role") == "token-exchange" else row.get("role") for row in idp_rows)
    diagnostic["actual"]["provider_sequence"] = [value if type(value) is str and value in {"authorization_code", "refresh_token", "backend-introspection"} else marker(value) for value in sequence]
    require(sequence == EXPECTED_IDP_SEQUENCE[name] and all(row.get("method") == "POST" for row in idp_rows),
            "provider_trace_sequence", diagnostic)
    require(all(row.get("credential_header_present") is False and row.get("cookie_present") is False
                and row.get("public_form_valid") is True and row.get("identity_requested") is True for row in exchanges),
            "public_token_trace_context", diagnostic)
    if name == "option-off":
        require(audit is None and not exchanges and not session and len(anonymous) == 3, "option_off_contract", diagnostic)
        return {"status": "passed", "anonymous_trace": anonymous, "diagnostic": diagnostic}
    if name in REFRESH_SCENARIOS:
        result = _validate_refresh_case(name, audit, session, exchanges, diagnostic)
        result["anonymous_trace"] = anonymous
        return result
    require(isinstance(audit, dict), "session_audit_object", diagnostic)
    require(audit.get("schema") == "security.supplied-session-audit/v5"
            and audit.get("credential_acquisition") == "imported_oauth_code_pkce"
            and audit.get("principal_alias") == ("canary-b" if name == "valid-b-context" else "canary-a")
            and audit.get("outcome") == EXPECTED_OUTCOMES[name], "session_audit_contract", diagnostic)
    nested = audit.get("oauth_code")
    require(isinstance(nested, dict), "oauth_audit_object", diagnostic)
    require(all(key in nested and type(nested[key]) is type(value) and nested[key] == value
                for key, value in ASSURANCE.items()), "oauth_claim_boundaries", diagnostic)
    require(len(exchanges) == 1 and exchanges[0].get("method") == "POST", "token_post_count", diagnostic)
    success = name in ("valid-a", "valid-b-context", "wrong-b-health")
    require(all(integer(nested.get(key)) and nested[key] == value for key, value in {
        "request_attempt_count": 1, "request_admitted_count": 1, "response_completed_count": 1,
        "credential_commit_count": int(success)}.items()), "oauth_accounting", diagnostic)
    require(nested.get("verifier_in_admitted_request") is True
            and nested.get("token_response_validated") is success
            and nested.get("outcome") == ("credential_committed" if success else "response_rejected")
            and nested.get("body_state") == "complete"
            and nested.get("status") == exchanges[0].get("status")
            and nested.get("response_bytes") == exchanges[0].get("response_bytes")
            and integer(nested.get("response_bytes")) and nested["response_bytes"] > 0,
            "oauth_response_contract", diagnostic)
    require(all(integer(audit.get(key)) and audit[key] == value for key, value in {
        "selected_resource_count": 2,
        "dispatched_request_count": len(session) + 1,
        "dispatched_resource_count": 2 if name in ("valid-a", "valid-b-context") else 0,
        "committed_resource_count": 2 if name in ("valid-a", "valid-b-context") else 0,
    }.items()), "session_accounting", diagnostic)
    checkpoints, resources = audit.get("checkpoints"), audit.get("resources")
    phases = ["startup", "subject_boundary", "terminal"] if name in ("valid-a", "valid-b-context") else (["startup"] if name == "wrong-b-health" else [])
    require(isinstance(checkpoints, list) and len(checkpoints) == len(phases)
            and all(isinstance(row, dict) for row in checkpoints)
            and isinstance(resources, list) and len(resources) == 2
            and all(isinstance(row, dict) for row in resources), "session_entity_arrays", diagnostic)
    require([row.get("phase") for row in checkpoints] == phases
            and all(integer(row.get("sequence")) and row["sequence"] == index
                    and integer(row.get("after_subject_count")) and row["after_subject_count"] == index
                    and row.get("status") == 200 and row.get("body_state") == "complete"
                    and row.get("outcome") == ("unhealthy" if name == "wrong-b-health" else "healthy")
                    and isinstance(row.get("evidence_reference"), str)
                    and re.fullmatch(r"supplied-session-checkpoint-evidence-sha256:[0-9a-f]{64}", row["evidence_reference"]) is not None
                    and integer(row.get("response_bytes")) for index, row in enumerate(checkpoints)),
            "session_checkpoints", diagnostic)
    resource_refs = []
    for index, row in enumerate(resources):
        committed = name in ("valid-a", "valid-b-context")
        require(integer(row.get("sequence")) and row["sequence"] == index
                and row.get("outcome") == ("committed" if committed else "not_dispatched")
                and type(row.get("epoch")) is int and row["epoch"] == 1
                and integer(row.get("response_bytes"))
                and (row.get("status") == 200 if committed else row.get("status") is None)
                and isinstance(row.get("resource_reference"), str)
                and re.fullmatch(r"supplied-session-resource-sha256:[0-9a-f]{64}", row["resource_reference"]) is not None
                and ((isinstance(row.get("evidence_reference"), str)
                      and re.fullmatch(r"supplied-session-resource-evidence-sha256:[0-9a-f]{64}", row["evidence_reference"]) is not None)
                     if committed else row.get("evidence_reference") is None),
                "session_resources", diagnostic)
        resource_refs.append(row["resource_reference"])
    require(len(set(resource_refs)) == 2, "session_resource_duplicates", diagnostic)
    expected_bytes = nested["response_bytes"] + sum(row["response_bytes"] for row in checkpoints + resources)
    require(integer(audit.get("response_bytes")) and audit["response_bytes"] == expected_bytes
            and all(integer(row.get("response_bytes")) for row in session)
            and sum(row["response_bytes"] for row in session) + nested["response_bytes"] == expected_bytes
            and type(audit.get("response_byte_limit_exceeded")) is bool
            and audit["response_byte_limit_exceeded"] is False
            and type(nested.get("configured_token_response_byte_limit")) is int
            and nested["configured_token_response_byte_limit"] == 8192, "session_byte_accounting", diagnostic)
    require(audit.get("refresh_performed") is False and audit.get("anonymous_fallback_performed") is False
            and audit.get("continuous_authentication_established") is False
            and audit.get("exploit_execution") == "not_performed"
            and audit.get("impact_validation") == "not_performed", "session_claim_boundaries", diagnostic)
    if success:
        require(exchanges[0]["status"] == 200 and nested.get("response_scope_matched") is True
                and integer(nested.get("declared_token_lifetime_seconds"))
                and 1 <= nested["declared_token_lifetime_seconds"] <= 3600
                and type(nested.get("refresh_token_returned")) is bool
                and re.fullmatch(r"supplied-session-oauth-code-evidence-sha256:[0-9a-f]{64}", nested.get("evidence_reference", "")) is not None,
                "oauth_success_facts", diagnostic)
        require(all(row.get("accepted") is (name != "wrong-b-health") for row in session), "target_independent_oracle", diagnostic)
    else:
        require(exchanges[0]["status"] == 400 and exchanges[0].get("error_class") == "invalid_grant"
                and nested.get("evidence_reference") is None
                and nested.get("response_scope_matched") is None
                and nested.get("declared_token_lifetime_seconds") is None,
                "real_provider_refusal", diagnostic)
    return {"status": "passed", "anonymous_trace": anonymous, "diagnostic": diagnostic,
            "oauth_outcome": nested["outcome"], "session_outcome": audit["outcome"],
            "idp_response_bytes": nested["response_bytes"],
            "session_response_bytes": audit["response_bytes"],
            "provider_declared_lifetime_seconds": nested.get("declared_token_lifetime_seconds")}


def validate_authorization_case(name: str, audit: object, target_rows: list[dict],
                                idp_rows: list[dict], baseline: list[dict], user_agent: object) -> dict:
    require(name in AUTHORIZATION_SCENARIOS, "authorization_scenario")
    expected = AUTHORIZATION_EXPECTED[name]
    nested = audit.get("oauth_authorization", _MISSING) if type(audit) is dict else _MISSING
    token = audit.get("oauth_token_exchange", _MISSING) if type(audit) is dict else _MISSING
    diagnostic = {"scenario": name, "expected": dict(expected), "actual": {
        "audit": marker(audit), "target_rows": marker(target_rows), "idp_rows": marker(idp_rows),
        "authorization": {key: marker(nested.get(key, _MISSING)) if type(nested) is dict else marker(nested)
            for key in ("reservation_count", "accepted_connection_count", "completed_form_count", "callback_commit_count",
                        "state_validated", "issuer_validated", "ingress_bytes", "reply_bytes_written")},
        "token": {key: marker(token.get(key, _MISSING)) if type(token) is dict else marker(token)
            for key in ("request_attempt_count", "request_admitted_count", "response_completed_count",
                        "credential_commit_count", "token_response_validated", "response_bytes")},
        "resources": marker(audit.get("resources", _MISSING)) if type(audit) is dict else marker(audit),
        "user_agent": {key: marker(user_agent.get(key, _MISSING)) if type(user_agent) is dict else marker(user_agent)
            for key in ("post_count", "request_bytes", "reply_bytes", "product_generated_request_used")}}}
    require(type(audit) is dict and type(nested) is dict and type(token) is dict
            and type(target_rows) is list and type(idp_rows) is list
            and len(target_rows) <= MAX_TRACE and len(idp_rows) <= MAX_TRACE
            and all(type(row) is dict for row in target_rows + idp_rows), "authorization_case_shape", diagnostic)
    anonymous = [{"method": row.get("method"), "role": row.get("role"), "entry_path": row.get("entry_path")}
                 for row in target_rows if row.get("credential_present") is False]
    session = [row for row in target_rows if row.get("credential_present") is True]
    exchanges = [row for row in idp_rows if row.get("role") == "token-exchange"]
    require(anonymous == baseline and len(anonymous) == 3
            and all(type(row.get("credential_present")) is bool for row in target_rows)
            and all(row == {"method": "GET", "role": "ordinary", "entry_path": True} for row in anonymous),
            "authorization_ordinary_trace", diagnostic)
    roles = ("health", "resource-one", "health", "resource-two", "health") if expected["protected_gets"] else ()
    require(tuple(row.get("role") for row in session) == roles
            and all(row.get("method") == "GET" and row.get("accepted") is True
                    and row.get("provider_active") is True and row.get("application_gate_denied") is False for row in session),
            "authorization_protected_trace", diagnostic)
    sequence = tuple(row.get("grant_type") if row.get("role") == "token-exchange" else row.get("role") for row in idp_rows)
    expected_sequence = (("authorization_code",) if expected["token_posts"] else ()) + ("backend-introspection",) * expected["protected_gets"]
    require(all(integer(row.get("response_bytes")) for row in session + exchanges),
            "authorization_trace_byte_types", diagnostic)
    require(sequence == expected_sequence and len(exchanges) == expected["token_posts"]
            and all(row.get("method") == "POST" for row in idp_rows)
            and all(row.get("credential_header_present") is False and row.get("cookie_present") is False
                    and row.get("public_form_valid") is True and row.get("identity_requested") is True for row in exchanges),
            "authorization_idp_trace", diagnostic)
    require(type(user_agent) is dict and user_agent.get("post_count") == 1
            and type(user_agent.get("post_count")) is int
            and user_agent.get("authorization_get_count") == 1
            and type(user_agent.get("authorization_get_count")) is int
            and user_agent.get("product_generated_request_used") is True
            and user_agent.get("handoff_preserved_before_submission") is True
            and user_agent.get("credential_headers_sent") is False
            and user_agent.get("interactive_login_performed") is False
            and type(user_agent.get("response_status")) is int and user_agent["response_status"] == 200
            and user_agent.get("controlled_challenge_substitution") is (name == "initiated-challenge-substitution")
            and integer(user_agent.get("request_bytes")) and 0 < user_agent["request_bytes"] <= 12288
            and integer(user_agent.get("reply_bytes")) and 0 < user_agent["reply_bytes"] <= 512,
            "authorization_user_agent_contract", diagnostic)
    require(audit.get("schema") == "security.supplied-session-audit/v7"
            and audit.get("credential_acquisition") == "client_initiated_oauth_pkce"
            and audit.get("principal_assurance") == "operator_declared"
            and _opaque_reference(audit.get("policy_reference"), "supplied-session-policy-sha256:")
            and audit.get("principal_alias") == "canary-a" and audit.get("outcome") == expected["session_outcome"]
            and "oauth_code" not in audit and "oauth_refresh" not in audit
            and audit.get("refresh_performed") is False and audit.get("anonymous_fallback_performed") is False
            and audit.get("continuous_authentication_established") is False
            and audit.get("exploit_execution") == audit.get("impact_validation") == "not_performed",
            "authorization_session_contract", diagnostic)
    require(nested.get("profile") == "loopback-form-post-state/v1"
            and _opaque_reference(nested.get("authorization_policy_reference"), "oauth-authorization-policy-sha256:")
            and type(nested.get("configured_wait_ms")) is int and nested["configured_wait_ms"] == 30000
            and all(integer(nested.get(key)) and nested[key] == count for key, count in {
                "reservation_count": 1, "accepted_connection_count": 1, "completed_form_count": 1,
                "callback_commit_count": expected["callback_commits"]}.items())
            and all(nested.get(key) is True for key in ("listener_bound", "handoff_written", "listener_closed"))
            and nested.get("outcome") == expected["callback_outcome"]
            and all(nested.get(key) is False for key in ("oidc_nonce_validation_performed",
                    "oidc_identity_validation_performed", "token_signature_validation_performed"))
            and nested.get("state_validated") is (name not in ("initiated-wrong-state", "initiated-wrong-issuer"))
            and nested.get("issuer_validated") is (name not in ("initiated-wrong-state", "initiated-wrong-issuer"))
            and integer(nested.get("ingress_bytes")) and nested["ingress_bytes"] == user_agent["request_bytes"]
            and integer(nested.get("reply_bytes_written")) and nested["reply_bytes_written"] == user_agent["reply_bytes"]
            and integer(nested.get("unknown_parameter_count")) and nested["unknown_parameter_count"] <= 16
            and integer(nested.get("elapsed_ms"))
            and (_opaque_reference(nested.get("evidence_reference"), "supplied-session-oauth-authorization-evidence-sha256:")
                 if expected["callback_commits"] else nested.get("evidence_reference") is None)
            and nested.get("provider_error_class") == ("invalid_scope" if name == "initiated-provider-error" else None),
            "authorization_callback_accounting", diagnostic)
    successful = name == "initiated-valid-a"
    require(token.get("profile") == "client-initiated-public-code-s256-bearer/v1"
            and token.get("transport_profile") == "owned-numeric-loopback-http/v1"
            and token.get("pkce_assurance") == "client_generated_s256_not_remote_enforcement"
            and token.get("token_interpretation") == "opaque_bearer_not_oidc_identity"
            and _opaque_reference(token.get("idp_reference"), "oauth-code-policy-sha256:")
            and all(integer(token.get(key)) and token[key] == count for key, count in {
                "request_attempt_count": expected["token_posts"], "request_admitted_count": expected["token_posts"],
                "response_completed_count": expected["token_posts"], "credential_commit_count": int(successful)}.items())
            and token.get("verifier_in_admitted_request") is bool(expected["token_posts"])
            and token.get("token_response_validated") is successful
            and token.get("response_scope_matched") is (True if successful else None)
            and token.get("outcome") == ("credential_committed" if successful else
                "response_rejected" if expected["token_posts"] else "not_started")
            and type(token.get("configured_token_response_byte_limit")) is int
            and token["configured_token_response_byte_limit"] == 8192
            and integer(token.get("response_bytes"))
            and token["response_bytes"] == (exchanges[0].get("response_bytes") if exchanges else 0),
            "authorization_exchange_accounting", diagnostic)
    if exchanges:
        require(exchanges[0].get("status") == (200 if successful else 400)
                and (successful or exchanges[0].get("error_class") == "invalid_grant")
                and token.get("status") == exchanges[0].get("status")
                and token.get("body_state") == "complete" and token["response_bytes"] > 0,
                "authorization_provider_token_oracle", diagnostic)
    else:
        require(token.get("status") is None and token.get("body_state") == "unavailable"
                and token.get("evidence_reference") is None and token.get("declared_token_lifetime_seconds") is None
                and token.get("refresh_token_returned") is None,
                "authorization_unattempted_exchange", diagnostic)
    checkpoints, resources = audit.get("checkpoints"), audit.get("resources")
    require(type(checkpoints) is list and len(checkpoints) == (3 if successful else 0)
            and type(resources) is list and len(resources) == 2
            and all(type(row) is dict for row in checkpoints + resources)
            and all(integer(audit.get(key)) and audit[key] == value for key, value in {
                "selected_resource_count": 2, "dispatched_resource_count": expected["resources"],
                "committed_resource_count": expected["resources"],
                "dispatched_request_count": expected["token_posts"] + expected["protected_gets"]}.items()),
            "authorization_session_accounting", diagnostic)
    references = []
    for index, row in enumerate(resources):
        require(type(row.get("sequence")) is int and row["sequence"] == index
                and type(row.get("epoch")) is int and row["epoch"] == 1
                and _opaque_reference(row.get("resource_reference"), "supplied-session-resource-sha256:")
                and row.get("outcome") == ("committed" if successful else "not_dispatched")
                and row.get("status") == (200 if successful else None)
                and integer(row.get("response_bytes"))
                and row["response_bytes"] == (session[(1, 3)[index]]["response_bytes"] if successful else 0)
                and (_opaque_reference(row.get("evidence_reference"), "supplied-session-resource-evidence-sha256:")
                     if successful else row.get("evidence_reference") is None), "authorization_resource_identity", diagnostic)
        references.append(row["resource_reference"])
    require(len(set(references)) == 2, "authorization_resource_duplicate", diagnostic)
    for index, row in enumerate(checkpoints):
        require(type(row.get("sequence")) is int and row["sequence"] == index
                and row.get("phase") == ("startup", "subject_boundary", "terminal")[index]
                and type(row.get("after_subject_count")) is int and row["after_subject_count"] == index
                and type(row.get("epoch")) is int and row["epoch"] == 1
                and row.get("status") == 200 and row.get("body_state") == "complete"
                and row.get("outcome") == "healthy" and row.get("predicate") == "matched"
                and _opaque_reference(row.get("evidence_reference"), "supplied-session-checkpoint-evidence-sha256:")
                and integer(row.get("response_bytes")) and row["response_bytes"] == session[(0, 2, 4)[index]]["response_bytes"],
                "authorization_health_oracle", diagnostic)
    committed_references = [row["evidence_reference"] for row in resources + checkpoints if row.get("evidence_reference") is not None]
    if successful:
        require(_opaque_reference(token.get("evidence_reference"), "supplied-session-oauth-code-evidence-sha256:"),
                "authorization_token_evidence", diagnostic)
        committed_references.append(token["evidence_reference"])
    if expected["callback_commits"]:
        committed_references.append(nested["evidence_reference"])
    require(len(set(committed_references)) == len(committed_references), "authorization_duplicate_evidence", diagnostic)
    total = sum(row["response_bytes"] for row in session + exchanges)
    require(integer(audit.get("response_bytes")) and audit["response_bytes"] == total
            and total == token["response_bytes"] + sum(row["response_bytes"] for row in checkpoints + resources)
            and type(audit.get("response_byte_limit")) is int and audit["response_byte_limit"] == 65536
            and audit.get("response_byte_limit_exceeded") is False, "authorization_response_bytes", diagnostic)
    return {"status": "passed", "diagnostic": diagnostic, "outgoing_session_requests": expected["token_posts"] + len(session),
            "callback_reception_reservations": 1, "callback_request_bytes": nested["ingress_bytes"],
            "session_response_bytes": total, "ordinary_requests": len(anonymous),
            "reconciled_logical_parent_admissions": len(anonymous) + 1 + expected["token_posts"] + len(session),
            "parent_count_scope": "recomputed_from_independent_outgoing_trace_and_typed_callback_reservation_not_a_saved_parent_snapshot",
            "evaluated_resources": expected["resources"], "callback_outcome": nested["outcome"],
            "token_outcome": token["outcome"], "user_agent": dict(user_agent),
            "pkce_meaning": "controlled_provider_refusal_not_universal_enforcement_proof" if name == "initiated-challenge-substitution" else "client_generated_finite_transaction"}


def item_identities(source: dict) -> set[tuple[str, str]]:
    require(integer(source.get("item_count")) and isinstance(source.get("items"), list)
            and len(source["items"]) == source["item_count"], "source_item_count")
    identities = []
    for item in source["items"]:
        require(isinstance(item, dict) and isinstance(item.get("fingerprint"), str)
                and isinstance(item.get("capability_id"), str), "source_item_identity")
        identities.append((item["fingerprint"], item["capability_id"]))
    require(len(set(identities)) == len(identities), "source_duplicate_identity")
    return set(identities)


def comparison_counts(document: object) -> dict[str, int]:
    require(isinstance(document, dict) and document.get("schema") == "termivar-report-comparison/v1", "comparison_schema")
    require(all(key in document and isinstance(document[key], list) for key in GROUPS), "comparison_groups")
    return {key: len(document[key]) for key in GROUPS}


def _self_compare(document: object, source: dict) -> dict:
    counts = comparison_counts(document)
    expected = item_identities(source)
    require(counts == {"only_in_after": 0, "only_in_before": 0, "changed": 0, "unchanged": len(expected)}, "self_compare_partition")
    actual = item_identities({"item_count": counts["unchanged"], "items": document["unchanged"]})
    require(actual == expected, "self_compare_identity")
    if source.get("supplied_session") is not None:
        nested = document.get("supplied_session_comparison")
        require(isinstance(nested, dict) and nested.get("schema") == "termivar-supplied-session-comparison/v1"
                and nested.get("status") == "compared_within_same_declared_context"
                and nested.get("context", {}).get("status") == "same_declared_context"
                and nested.get("health_and_coverage", {}).get("status") == "unchanged"
                and nested.get("accounting", {}).get("status") == "unchanged", "self_compare_session")
    return counts


def run_offline(runner: Runner, binary: str, bundles: dict[str, tuple[Path, dict]], private: PrivateValues,
                input_snapshots: dict[Path, bytes] | None = None) -> dict:
    results = {}
    require(tuple(bundles) == SCENARIOS, "offline_bundle_registry")
    initial = {name: snapshot(bundle) for name, (bundle, _) in bundles.items()}
    require(sum(len(data) for members in initial.values() for data in members.values()) <= MAX_ALL_BUNDLE_BYTES,
            "offline_retained_bundle_limit")
    for name, (bundle, before) in bundles.items():
        frozen = snapshot(bundle)
        for data in frozen.values():
            private.check(data)
        verify = runner.run([binary, "report", "verify", "--dir", str(bundle), "--format", "json"], label=name + "-verify")
        require(strict_json(verify.stdout).get("status") == "integrity_match", "offline_verify")
        compare = runner.run([binary, "report", "compare", "--before", str(bundle / "assessment.json"),
                              "--after", str(bundle / "assessment.json"), "--same-scope", "--format", "json"], label=name + "-self-compare")
        counts = _self_compare(strict_json(compare.stdout), before)
        require(snapshot(bundle) == frozen, "offline_input_modified")
        results[name] = {"verify": "integrity_match", "self_compare_counts": counts, "input_bytes_preserved": True}
    controls = {}
    for control, before_name, after_name, kind in OFFLINE_CONTROLS:
        require(before_name in bundles and after_name in bundles, "context_compare_sources")
        left, right = bundles[before_name], bundles[after_name]
        compared = runner.run([binary, "report", "compare", "--before", str(left[0] / "assessment.json"),
                               "--after", str(right[0] / "assessment.json"), "--same-scope", "--format", "json"], label=control + "-compare")
        document = strict_json(compared.stdout)
        counts = comparison_counts(document)
        require(len(item_identities(left[1])) == counts["only_in_before"] + counts["changed"] + counts["unchanged"]
                and len(item_identities(right[1])) == counts["only_in_after"] + counts["changed"] + counts["unchanged"], "context_compare_conservation")
        nested = document.get("supplied_session_comparison")
        require(type(nested) is dict, "controlled_session_object")
        left_audit, right_audit = left[1].get("supplied_session"), right[1].get("supplied_session")
        require(type(left_audit) is dict and type(right_audit) is dict, "controlled_session_sources")
        if kind == "coverage":
            require(nested.get("status") == "compared_within_same_declared_context"
                    and nested.get("context", {}).get("status") == "same_declared_context"
                    and nested.get("health_and_coverage", {}).get("status") == "changed"
                    and nested.get("accounting", {}).get("status") == "changed"
                    and left_audit.get("schema") == right_audit.get("schema") == "security.supplied-session-audit/v6"
                    and type(left_audit.get("policy_reference")) is str
                    and left_audit["policy_reference"] == right_audit.get("policy_reference")
                    and left_audit["oauth_refresh"]["final_epoch"] == right_audit["oauth_refresh"]["final_epoch"] == 2,
                    "renewed_health_coverage_compare")
            result_status = "compared_same_context_health_coverage_changed"
        else:
            require(nested.get("status") == "not_compared"
                    and nested.get("context", {}).get("status") == "session_policy_changed"
                    and nested.get("health_and_coverage", {}).get("status") == "not_comparable"
                    and nested.get("accounting", {}).get("status") == "not_comparable", "different_principal_compare")
            require(type(left_audit.get("policy_reference")) is str
                    and type(right_audit.get("policy_reference")) is str
                    and left_audit["policy_reference"] != right_audit["policy_reference"], "controlled_policy_references")
            if kind == "different-principal":
                require(left_audit.get("principal_alias") == "canary-a" and right_audit.get("principal_alias") == "canary-b", "context_compare_principals")
                result_status = "not_compared_different_declared_principal"
            else:
                require(left_audit.get("schema") == "security.supplied-session-audit/v5"
                        and right_audit.get("schema") == "security.supplied-session-audit/v6"
                        and left_audit.get("principal_alias") == right_audit.get("principal_alias") == "canary-a", "context_compare_methodology")
                result_status = "not_compared_different_policy_and_methodology"
        before_rows = document["only_in_before"] + document["changed"] + document["unchanged"]
        after_rows = document["only_in_after"] + document["changed"] + document["unchanged"]
        require(item_identities({"item_count": len(before_rows), "items": before_rows}) == item_identities(left[1])
                and item_identities({"item_count": len(after_rows), "items": after_rows}) == item_identities(right[1]), "context_compare_identities")
        controls[control] = {"item_counts": counts, "status": result_status}
    require(all(snapshot(bundle) == initial[name] for name, (bundle, _) in bundles.items()), "controlled_compare_input_modified")
    if input_snapshots is not None:
        require(len(input_snapshots) == 16 and sum(len(data) for data in input_snapshots.values()) <= MAX_HTTP_BODY
                and all(selected_input_bytes(path) == data
                        for path, data in input_snapshots.items()), "offline_selected_input_modified")
    return {"status": "passed", "bundles": results, "controlled_comparisons": controls,
            "selected_input_bytes_preserved": input_snapshots is not None}


def run_authorization_cases(runner: Runner, binary: str, work: Path, relay: TokenRelay,
                            target: TargetApplication, controller_secret: str,
                            callbacks: dict[str, str], baseline: list[dict], private: PrivateValues,
                            privacy: CombinedOutputPrivacy, summaries: dict) -> tuple[dict, dict]:
    require(tuple(callbacks) == AUTHORIZATION_SCENARIOS and not summaries, "authorization_case_registry")
    bundles, inputs = {}, {}
    for name in AUTHORIZATION_SCENARIOS:
        relay.phase = "controller-authorization-" + name
        target.phase = name
        target.expected_user = "canary-a"
        target.deny_renewed_health = False
        relay.public_redirect = callbacks[name]
        opener, jar = prepare_initiated_sso(relay.origin, controller_secret, private)
        policy, handoff = work / (name + ".toml"), work / (name + ".authorization.txt")
        for path in (policy, handoff):
            private.add(str(path))
        source = authorization_policy_source(relay.origin + REALM_PATH, callbacks[name], name)
        validate_authorization_fixture_policy(source, relay.origin + REALM_PATH, callbacks[name], name)
        private_write(policy, source)
        inputs[policy] = selected_input_bytes(policy)
        require(len(inputs) <= 5 and sum(map(len, inputs.values())) <= MAX_HTTP_BODY, "authorization_input_retained_limit")
        require(not handoff.exists(), "authorization_handoff_preexists")
        bundle = work / (name + "-bundle")
        args = [binary, "scan", target.origin + "/", "--profile", "web-review", "--format", "json",
                "--session-policy", str(policy), "--session-oauth-authorization-output", str(handoff),
                "--report-dir", str(bundle)]
        stop = threading.Event()
        driver_results, driver_errors = [], []

        def drive():
            try:
                driver_results.append(drive_initiated_authorization(relay, opener, jar, handoff,
                    callbacks[name], name, private, stop))
            except LabError as error:
                driver_errors.append(error)
            except Exception:
                driver_errors.append(LabError("authorization_user_agent_failure"))

        target_start, relay_start = len(target.trace), len(relay.trace)
        relay.phase = name
        summaries[name] = {"status": "running", "expected": dict(AUTHORIZATION_EXPECTED[name])}
        worker = threading.Thread(target=drive, daemon=True)
        worker.start()
        original_error = None
        result = None
        try:
            result = runner.run(args, label=name + "-scan", expected=(0,), timeout=60)
        except LabError as error:
            original_error = error
        finally:
            stop.set()
            worker.join(timeout=20)
        if original_error is not None:
            raise original_error
        require(not worker.is_alive(), "authorization_user_agent_cleanup")
        # A driver can register a generated canary after the child capture
        # finishes on an early-exit path. Recheck after the bounded join before
        # interpreting or publishing any successful process evidence.
        require(result is not None, "authorization_scan_result_missing")
        privacy.check(result.stdout)
        privacy.check(result.stderr)
        if driver_errors:
            raise driver_errors[0]
        require(len(driver_results) == 1 and result is not None and result.returncode == 0,
                "authorization_scan_exit", {"scenario": name, "user_agent_result_count": len(driver_results)})
        require(not relay.errors and not target.errors and not relay.server.handler_failed
                and not target.server.handler_failed, "fixture_runtime_failure",
                _fixture_runtime_diagnostic(name, relay, target))
        audit, document = audit_from_output(result, bundle)
        rows = target.trace[target_start:]
        idp = [row for row in relay.trace[relay_start:] if row["phase"] == name]
        summary = validate_authorization_case(name, audit, rows, idp, baseline, driver_results[0])
        require(document is not None, "authorization_expected_bundle", {"scenario": name})
        require(not handoff.exists() and selected_input_bytes(policy) == inputs[policy],
                "authorization_input_or_handoff_cleanup", {"scenario": name})
        summary.update({"exit_code": result.returncode, "elapsed_seconds": result.elapsed_seconds,
                        "bundle_produced": True, "policy_bytes_preserved": True, "private_handoff_removed": True})
        if name == "initiated-valid-a":
            counts = len(target.trace), len(relay.trace)
            summary["closed_listener_replay_control"] = closed_callback_replay_control(callbacks[name])
            require((len(target.trace), len(relay.trace)) == counts, "authorization_replay_added_work")
        summaries[name] = summary
        bundles[name] = bundle, document
        for body in snapshot(bundle).values():
            privacy.check(body)
    require(tuple(summaries) == tuple(bundles) == AUTHORIZATION_SCENARIOS,
            "authorization_scenario_coverage")
    return bundles, inputs


def run_authorization_offline(runner: Runner, binary: str, bundles: dict, legacy_bundles: dict,
                              privacy: CombinedOutputPrivacy, inputs: dict[Path, bytes]) -> dict:
    require(tuple(bundles) == AUTHORIZATION_SCENARIOS and tuple(legacy_bundles) == SCENARIOS,
            "authorization_offline_registry")
    require(len(inputs) == 5 and sum(map(len, inputs.values())) <= MAX_HTTP_BODY,
            "authorization_input_retained_limit")
    initial = {name: snapshot(path) for name, (path, _) in bundles.items()}
    retained = sum(len(body) for members in initial.values() for body in members.values())
    retained += sum(sum(map(len, snapshot(path).values())) for path, _ in legacy_bundles.values())
    require(retained <= MAX_ALL_BUNDLE_BYTES, "offline_retained_bundle_limit")
    results = {}
    for name, (path, source) in bundles.items():
        for body in initial[name].values():
            privacy.check(body)
        result = runner.run([binary, "report", "verify", "--dir", str(path), "--format", "json"], label=name + "-verify")
        verified = strict_json(result.stdout)
        require(type(verified) is dict and verified.get("status") == "integrity_match", "authorization_offline_verify")
        result = runner.run([binary, "report", "compare", "--before", str(path / "assessment.json"),
            "--after", str(path / "assessment.json"), "--same-scope", "--format", "json"], label=name + "-self-compare")
        counts = _self_compare(strict_json(result.stdout), source)
        require(snapshot(path) == initial[name], "authorization_offline_bytes_changed")
        results[name] = {"verify": "integrity_match", "self_compare_counts": counts, "input_bytes_preserved": True}
    before, after = legacy_bundles["valid-a"], bundles["initiated-valid-a"]
    result = runner.run([binary, "report", "compare", "--before", str(before[0] / "assessment.json"),
        "--after", str(after[0] / "assessment.json"), "--same-scope", "--format", "json"], label="external-code-to-initiated-compare")
    document = strict_json(result.stdout)
    counts = comparison_counts(document)
    require(len(item_identities(before[1])) == counts["only_in_before"] + counts["changed"] + counts["unchanged"]
            and len(item_identities(after[1])) == counts["only_in_after"] + counts["changed"] + counts["unchanged"],
            "authorization_control_conservation")
    nested = document.get("supplied_session_comparison")
    require(type(nested) is dict and nested.get("status") == "not_compared"
            and nested.get("context", {}).get("status") == "session_policy_changed"
            and nested.get("health_and_coverage", {}).get("status") == "not_comparable"
            and nested.get("accounting", {}).get("status") == "not_comparable"
            and before[1]["supplied_session"]["schema"] == "security.supplied-session-audit/v5"
            and after[1]["supplied_session"]["schema"] == "security.supplied-session-audit/v7",
            "authorization_control_methodology")
    for rows, source in ((document["only_in_before"] + document["changed"] + document["unchanged"], before[1]),
                         (document["only_in_after"] + document["changed"] + document["unchanged"], after[1])):
        require(item_identities({"item_count": len(rows), "items": rows}) == item_identities(source),
                "authorization_control_identities")
    require(all(snapshot(path) == initial[name] for name, (path, _) in bundles.items())
            and all(selected_input_bytes(path) == source for path, source in inputs.items()),
            "authorization_offline_input_modified")
    return {"status": "passed", "bundles": results, "policy_bytes_preserved": True,
            "controlled_comparisons": {"external-code-to-initiated": {
                "status": "not_compared_different_policy_and_methodology", "item_counts": counts}}}


def validate_fixture() -> dict:
    # RFC7636 Appendix B independent known-answer, not production-generated.
    require(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "rfc7636_oracle")
    require(len(SCENARIOS) == 9 and len(set(SCENARIOS)) == 9
            and set(EXPECTED_SESSION_ROLES) == set(EXPECTED_RESOURCES) == set(EXPECTED_TOKEN_POSTS)
            == set(EXPECTED_IDP_SEQUENCE) == set(SCENARIOS) and len(OFFLINE_CONTROLS) == 4, "scenario_registry")
    document = realm_document("synthetic-resource-secret-not-for-runtime", "synthetic-controller-secret-not-for-runtime",
                              "http://127.0.0.1:12345/callback")
    clients = document["clients"]
    require(clients[0]["publicClient"] is True and clients[0]["attributes"]["pkce.code.challenge.method"] == "S256"
            and all(client["directAccessGrantsEnabled"] is False for client in clients)
            and clients[1]["publicClient"] is False and clients[0]["defaultClientScopes"] == []
            and clients[0]["optionalClientScopes"] == [SCOPE], "realm_contract")
    require(document["revokeRefreshToken"] is True and type(document["refreshTokenMaxReuse"]) is int
            and document["refreshTokenMaxReuse"] == 0, "realm_refresh_configuration")
    validate_fixture_policy(policy_source("http://127.0.0.1:1234/realms/termivar-owned-code",
                                         "http://127.0.0.1:5678/callback", "canary-a"))
    validate_fixture_policy(policy_source("http://127.0.0.1:1234/realms/termivar-owned-code",
                                         "http://127.0.0.1:5678/callback", "canary-a", renewable=True))
    require(len(AUTHORIZATION_SCENARIOS) == len(set(AUTHORIZATION_SCENARIOS)) == 5
            and set(AUTHORIZATION_EXPECTED) == set(AUTHORIZATION_SCENARIOS), "authorization_scenario_registry")
    for index, name in enumerate(AUTHORIZATION_SCENARIOS):
        callback = f"http://127.0.0.1:{18500 + index}" + AUTHORIZATION_CALLBACK_PATH
        source = authorization_policy_source("http://127.0.0.1:1234" + REALM_PATH, callback, name)
        validate_authorization_fixture_policy(source, "http://127.0.0.1:1234" + REALM_PATH, callback, name)
    return {"schema": SCHEMA, "status": "fixture_contracts_valid", "execution_class": "static_only",
            "cms_or_idp_execution": "not_performed", "scenario_registry": list(SCENARIOS),
            "authorization_scenario_registry": list(AUTHORIZATION_SCENARIOS),
            "provider_version": KEYCLOAK_VERSION, "provider_source": KEYCLOAK_SOURCE,
            "image_index": KEYCLOAK_INDEX, "image_linux_amd64": KEYCLOAK_AMD64}


def execute(binary: Path, output: Path, source_ref: str, expect_version: str, runner: Runner | None = None) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", source_ref) is not None, "source_ref")
    require(binary.is_file() and not binary.is_symlink(), "binary_regular_file")
    require(not output.exists(), "output_no_overwrite")
    output.mkdir(mode=0o700, parents=True)
    private = runner.private if runner is not None else PrivateValues()
    runner = runner or Runner(private)
    authorization_private = PrivateValues()
    output_privacy = CombinedOutputPrivacy(private, authorization_private)
    runner.output_privacy = output_privacy
    binary_hash = hashlib.sha256()
    with binary.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            binary_hash.update(block)
    evidence = {**validate_fixture(), "status": "running", "execution_class": "real_owned_keycloak_and_native_cli",
                "source_ref": source_ref, "binary_sha256": binary_hash.hexdigest(),
                "binary_bytes": binary.stat().st_size, "scenarios": {}, "offline": {"status": "not_run"},
                "authorization_scenarios": {}, "authorization_offline": {"status": "not_run"},
                "publication": "not_performed",
                "controller_refresh_replay": {"status": "not_run", "expected": {"http_status": 400,
                    "error_class": "invalid_grant", "submitted_revoke_refresh_token": True,
                    "submitted_refresh_token_max_reuse": 0}, "observations": {},
                    "meaning": "independent_owned_provider_control_not_product_revocation_or_identity_assurance"}}
    relay = TokenRelay(private)
    relay.authorization_private = authorization_private
    resource_secret = secrets.token_urlsafe(32)
    controller_secret = secrets.token_urlsafe(32)
    for value in (resource_secret, controller_secret):
        private.add(value)
    target = TargetApplication(relay, resource_secret)
    redirect = target.origin + "/callback"
    relay.public_redirect = redirect
    callbacks = authorization_callback_bindings()
    lab = KeycloakLab(runner, relay, realm_document(resource_secret, controller_secret, redirect,
                                                   tuple(callbacks.values())))
    primary_error = None
    controller_error = None
    cleanup = {}
    bundles = {}
    input_snapshots = {}
    authorization_bundles, authorization_inputs = {}, {}
    with tempfile.TemporaryDirectory(prefix=".private-owned-oauth-", dir=output, ignore_cleanup_errors=True) as temporary:
        work = Path(temporary)
        private.add(str(work))
        authorization_private.add(str(work))
        try:
            version = runner.run([str(binary), "--version"], label="candidate-version")
            require(re.fullmatch(rb"termivar " + re.escape(expect_version.encode()) + rb"\s*", version.stdout) is not None, "candidate_version")
            relay.start()
            target.start()
            lab.prepare()
            baseline = None
            valid_grant = None
            for name in SCENARIOS:
                target.phase = relay.phase = name
                target.expected_user = "canary-b" if name in ("valid-b-context", "refresh-b-context") else "canary-a"
                target.deny_renewed_health = name == "refresh-health-loss"
                policy = work / (name + ".toml")
                grant_file = work / (name + ".secret.tsv")
                private.register_owned_input_path(work, str(policy))
                private.register_owned_input_path(work, str(grant_file))
                grant = None
                if name != "option-off":
                    if name == "replayed-code":
                        require(valid_grant is not None and 0 <= int(time.time()) - valid_grant.received <= 55, "replay_grant_freshness")
                        grant = valid_grant
                    else:
                        relay.phase = "controller-" + name
                        username = "canary-b" if name in ("wrong-b-health", "valid-b-context", "refresh-b-context") else "canary-a"
                        grant = obtain_code(relay.origin, redirect, username, controller_secret, private)
                        if name == "wrong-verifier":
                            verifier = secrets.token_urlsafe(48)
                            private.add(verifier)
                            grant = dataclasses.replace(grant, verifier=verifier, code_challenge=challenge(verifier))
                        if name == "valid-a":
                            valid_grant = grant
                    policy_bytes = policy_source(relay.origin + REALM_PATH, redirect,
                                                 "canary-b" if name in ("valid-b-context", "refresh-b-context") else "canary-a",
                                                 renewable=name in REFRESH_SCENARIOS)
                    validate_fixture_policy(policy_bytes)
                    private_write(policy, policy_bytes)
                    private_write(grant_file, grant.tsv())
                source_before = selected_input_bytes(grant_file) if grant is not None else None
                policy_before = selected_input_bytes(policy) if grant is not None else None
                if grant is not None:
                    input_snapshots.update({policy: policy_before, grant_file: source_before})
                    require(len(input_snapshots) <= 16 and sum(map(len, input_snapshots.values())) <= MAX_HTTP_BODY,
                            "selected_input_retained_bound")
                target_start, relay_start = len(target.trace), len(relay.trace)
                relay.phase = name
                bundle = work / (name + "-bundle")
                args = [str(binary), "scan", target.origin + "/", "--profile", "web-review", "--format", "json"]
                if grant is not None:
                    args += ["--session-policy", str(policy), "--session-oauth-code-file", str(grant_file)]
                args += ["--report-dir", str(bundle)]
                result = runner.run(args, label=name + "-scan", expected=(0,))
                require(result.returncode == 0, "scan_exit_contract", {"scenario": name, "expected_exit": 0,
                                                                      "actual_exit": result.returncode})
                require(not relay.errors and not target.errors and not relay.server.handler_failed
                        and not target.server.handler_failed, "fixture_runtime_failure",
                        _fixture_runtime_diagnostic(name, relay, target))
                audit, source = audit_from_output(result, bundle)
                rows = target.trace[target_start:]
                idp_rows = [row for row in relay.trace[relay_start:] if row["phase"] == name]
                summary = validate_case(name, audit, rows, idp_rows, baseline)
                if name == "option-off":
                    baseline = summary["anonymous_trace"]
                summary.pop("anonymous_trace")
                summary.update({"exit_code": result.returncode, "bundle_produced": source is not None,
                                "elapsed_seconds": result.elapsed_seconds,
                                "secret_input_bytes_preserved": grant is None or selected_input_bytes(grant_file) == source_before,
                                "policy_input_bytes_preserved": grant is None or selected_input_bytes(policy) == policy_before})
                require(summary["secret_input_bytes_preserved"] and summary["policy_input_bytes_preserved"], "secret_or_policy_input_modified")
                evidence["scenarios"][name] = summary
                if source is not None:
                    bundles[name] = (bundle, source)
                    for data in snapshot(bundle).values():
                        private.check(data)
                require(source is not None, "expected_completed_bundle", {"scenario": name})
            require(tuple(evidence["scenarios"]) == SCENARIOS, "scenario_coverage")
            require(tuple(bundles) == SCENARIOS, "emitted_bundle_coverage")
            authorization_bundles, authorization_inputs = run_authorization_cases(
                runner, str(binary), work, relay, target, controller_secret, callbacks, baseline,
                authorization_private, output_privacy, evidence["authorization_scenarios"])
            # No positive flow can depend on state after a replay/revocation
            # control. All scanner activity finishes before these two controls.
            relay.scanner_scenarios_complete = True
            target_count = len(target.trace)
            scanner_idp_count = sum(row["phase"] in SCENARIOS + AUTHORIZATION_SCENARIOS for row in relay.trace)
            replay_results = evidence["controller_refresh_replay"]
            for name in REFRESH_POSITIVE:
                try:
                    replay_results["observations"][name] = relay.replay_initial_after_completed_flow(name)
                    require(len(target.trace) == target_count
                            and sum(row["phase"] in SCENARIOS + AUTHORIZATION_SCENARIOS for row in relay.trace) == scanner_idp_count,
                            "refresh_control_contaminated_scanner_trace")
                except LabError as error:
                    replay_results["observations"][name] = {"status": "not_run" if error.code == "refresh_control_not_run" else "failed",
                                                          "code": error.code, "diagnostic": error.diagnostic}
                    if controller_error is None:
                        controller_error = error
            replay_results["status"] = "passed" if controller_error is None else "failed_or_not_run"
            replay_results["all_scanner_scenarios_completed_before_controls"] = True
        except LabError as error:
            primary_error = error
        except Exception:
            primary_error = LabError("unexpected_controller_failure")
        finally:
            # Genuine target and IdP shutdown precedes ALL offline commands.
            for name, operation in (("target", target.stop), ("relay", relay.stop)):
                try:
                    operation()
                    cleanup[name + "_stopped"] = True
                except (LabError, RuntimeError):
                    cleanup[name + "_stopped"] = False
            relay.clear_refresh_values()
            cleanup["direct_refresh_capture_references_cleared"] = all(
                capture.initial_refresh is None for capture in relay._refresh_captures.values())
            try:
                cleanup["idp"] = lab.cleanup()
            except Exception:
                # A diagnostic/cleanup exception must not replace the actual
                # acceptance failure or emit a raw provider exception.
                cleanup["idp"] = {"status": "failed", "failures": ["unexpected_owned_cleanup_failure"],
                                  "container_removed": False, "network_removed": False}
        try:
            require(cleanup.get("target_stopped") is True and cleanup.get("relay_stopped") is True
                    and cleanup["idp"]["status"] == "complete", "cleanup_failed")
            if primary_error is None:
                frozen_trace_lengths = (len(target.trace), len(relay.trace))
                evidence["offline"] = run_offline(runner, str(binary), bundles, output_privacy, input_snapshots)
                evidence["authorization_offline"] = run_authorization_offline(
                    runner, str(binary), authorization_bundles, bundles, output_privacy, authorization_inputs)
                require(all(selected_input_bytes(path) == data for path, data in input_snapshots.items()),
                        "offline_selected_input_modified")
                require((len(target.trace), len(relay.trace)) == frozen_trace_lengths, "offline_network_activity")
                evidence["offline"]["fixtures_stopped_before_execution"] = True
                evidence["authorization_offline"]["fixtures_stopped_before_execution"] = True
        except LabError as error:
            if primary_error is None:
                primary_error = controller_error if controller_error is not None else error
                if controller_error is not None:
                    cleanup["secondary_error"] = error.code
            else:
                cleanup["secondary_error"] = error.code
        if primary_error is None and controller_error is not None:
            primary_error = controller_error
    cleanup["private_work_removed"] = not work.exists()
    if not cleanup["private_work_removed"]:
        if primary_error is None:
            primary_error = LabError("private_work_cleanup_failed")
        else:
            cleanup["private_work_secondary_error"] = "private_work_cleanup_failed"
    evidence["cleanup"] = cleanup
    evidence["image_inspection"] = getattr(lab, "image_inspection", None)
    try:
        evidence["provider_setup"] = lab._setup_diagnostic(None) if hasattr(lab, "_setup_diagnostic") else None
    except Exception:
        evidence["provider_setup"] = {"phase": "owned_provider_readiness", "diagnostic_state": "unavailable"}
    evidence["commands"] = runner.records
    evidence["cms_or_idp_execution"] = "performed" if evidence["scenarios"] else "not_established"
    if primary_error is not None:
        evidence["status"] = "failed"
        evidence["failure"] = {"code": primary_error.code, "diagnostic": primary_error.diagnostic}
    else:
        evidence["status"] = "passed"
    evidence["controller_acquisition"] = "admin_prepared_sso_then_real_post_authorization_s256_form_post"
    evidence["controller_cookie_transport"] = "explicit_owned_loopback_http_exact_relay_authorization_only_secure_attribute_retained"
    evidence["authorization_acquisition"] = "product_generated_state_s256_handoff_then_admin_prepared_sso_user_agent_get_and_real_loopback_form_post"
    evidence["interactive_login_qualification"] = "not_performed"
    evidence["privacy"] = {"selected_sinks_checked": True, "raw_tokens_or_provider_logs_exported": False,
                           "independent_retained_guards": 2, "raw_entry_cap_per_guard": 96,
                           "combined_retained_payload_byte_ceiling": 2 * 96 * MAX_HTTP_BODY,
                           "sensitive_python_library_copies_zeroized": "not_claimed"}
    payload = json.dumps(evidence, sort_keys=True, indent=2).encode() + b"\n"
    try:
        require(len(payload) <= MAX_EVIDENCE, "evidence_size")
        output_privacy.check(payload)
        private_write(output / "oauth-code-lab-acceptance.json", payload)
    except (OSError, LabError):
        if primary_error is None:
            raise LabError("evidence_write_failed") from None
        raise primary_error from None
    if primary_error is not None:
        raise primary_error
    return evidence


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--source-ref")
    parser.add_argument("--expect-version")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.validate_only:
            require(not any((args.binary, args.output_dir, args.source_ref, args.expect_version)), "validate_only_arguments")
            print(json.dumps(validate_fixture(), sort_keys=True))
            return 0
        require(all((args.binary, args.output_dir, args.source_ref, args.expect_version)), "execution_arguments")
        result = execute(args.binary.resolve(), args.output_dir.absolute(), args.source_ref, args.expect_version)
        print(json.dumps({"schema": SCHEMA, "status": result["status"], "scenario_count": len(result["scenarios"]),
                          "authorization_scenario_count": len(result["authorization_scenarios"])}))
        return 0
    except LabError as error:
        # Never emit exception causes, target URLs, secret paths or captured output.
        print(json.dumps({"schema": SCHEMA, "status": "failed", "code": error.code}), file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print(json.dumps({"schema": SCHEMA, "status": "failed", "code": "local_execution_unavailable"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
