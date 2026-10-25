#!/usr/bin/env python3
"""Owned Keycloak acceptance for the imported authorization-code session slice.

This controller is not product login automation or an OIDC verifier. It uses
an explicitly admin-prepared SSO fixture for two ephemeral users in one pinned,
isolated provider. It does NOT qualify an interactive username/password flow.
Only the bounded transaction file is handed to Termivar. The resource server
independently introspects the resulting bearer using a different client.

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
import json
import os
from pathlib import Path
import re
import secrets
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
)
EXPECTED_SESSION_ROLES = {
    "option-off": (),
    "valid-a": ("health", "resource-one", "health", "resource-two", "health"),
    "replayed-code": (),
    "wrong-verifier": (),
    "wrong-b-health": ("health",),
    "valid-b-context": ("health", "resource-one", "health", "resource-two", "health"),
}
EXPECTED_OUTCOMES = {
    "valid-a": "complete", "valid-b-context": "complete",
    "replayed-code": "oauth_code_exchange_unavailable",
    "wrong-verifier": "oauth_code_exchange_unavailable",
    "wrong-b-health": "startup_unhealthy",
}
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

    def add(self, value: str | bytes) -> None:
        raw = value.encode("utf-8") if isinstance(value, str) else value
        if len(raw) >= 16 and raw not in self._values:
            require(len(self._values) < 96 and len(raw) <= MAX_HTTP_BODY, "private_registry_limit")
            self._values.append(raw)

    def check(self, source: bytes) -> None:
        require(not any(value in source for value in self._values), "secret_in_output")
        # Detect public unkeyed digests without ever exporting the digest.
        require(not any(hashlib.sha256(value).hexdigest().encode() in source
                        for value in self._values), "secret_digest_in_output")


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


class Runner:
    def __init__(self, private: PrivateValues):
        self.private = private
        self.records: list[dict] = []

    def run(self, args: list[str], *, label: str, expected: tuple[int, ...] = (0,),
            input_bytes: bytes | None = None, timeout: float = MAX_COMMAND_SECONDS,
            sensitive_output: bool = False) -> Result:
        started = time.monotonic()
        child = CapturedChild(args, input_bytes)
        result = child.finish(timeout)
        if not sensitive_output:
            self.private.check(result.stdout)
            self.private.check(result.stderr)
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

    def __init__(self, origin: str, *, owned_loopback_http: bool = False):
        super().__init__()
        require(type(owned_loopback_http) is bool, "controller_cookie_policy")
        try:
            origin = _loopback_origin(origin)
        except (TypeError, ValueError):
            raise LabError("controller_cookie_origin") from None
        self.authorization_url = origin + AUTH_PATH
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


def realm_document(resource_secret: str, controller_secret: str, redirect: str) -> dict:
    """Original fixture configuration, not scanner input or expected inventory."""
    return {
        "realm": REALM, "enabled": True, "sslRequired": "none",
        "registrationAllowed": False, "resetPasswordAllowed": False,
        "loginWithEmailAllowed": False, "duplicateEmailsAllowed": False,
        "accessTokenLifespan": 180, "accessCodeLifespan": 120,
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
             "serviceAccountsEnabled": False, "consentRequired": False, "redirectUris": [redirect],
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


class TokenRelay:
    def __init__(self, private: PrivateValues):
        self.private = private
        self.upstream = None
        self.phase = "setup"
        self.trace: list[dict] = []
        self.errors: list[str] = []
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
                    parsed = urllib.parse.urlsplit(self.path)
                    if self.command == "GET" and parsed.path == REALM_PATH + "/.well-known/openid-configuration" and not parsed.query:
                        role = "setup-metadata"
                    elif self.command == "POST" and parsed.path == TOKEN_PATH and not parsed.query:
                        role = "token-exchange"
                    elif self.command == "POST" and parsed.path == INTROSPECTION_PATH and not parsed.query:
                        role = "backend-introspection"
                    elif self.command == "POST" and parsed.path == AUTH_PATH and not parsed.query:
                        role = "controller-authorization"
                    elif self.command == "POST" and parsed.path in {
                        "/admin/realms/" + REALM + "/users/" + identifier + "/impersonation" for identifier in USER_IDS.values()
                    } and not parsed.query:
                        role = "controller-sso-setup"
                    else:
                        raise LabError("relay_route_refused")
                    require(owner.upstream is not None and len(owner.trace) < MAX_TRACE, "relay_not_ready_or_limit")
                    body = _read_request(self, MAX_HTTP_BODY)
                    require(not parsed.query and not parsed.fragment, "relay_query_refused")
                    headers = {"Host": urllib.parse.urlsplit(owner.origin).netloc, "Accept-Encoding": "identity"}
                    for key in ("Content-Type", "Cookie", "Authorization", "Accept"):
                        if self.headers.get(key) is not None:
                            require(len(self.headers[key]) <= 16384, "relay_header_limit")
                            headers[key] = self.headers[key]
                    status, response_headers, response_body = request_bytes(owner.upstream + self.path, self.command, body or None, headers)
                    require(not any(k.lower() == "content-encoding" for k, _ in response_headers), "relay_coded_response")
                    # Values are only checked for leakage in private memory. The
                    # provider response is forwarded unchanged, never repaired.
                    error_class = None
                    if role == "token-exchange":
                        try:
                            document = strict_json(response_body, MAX_TOKEN_BODY)
                            if isinstance(document, dict):
                                for name in ("access_token", "refresh_token", "id_token"):
                                    if isinstance(document.get(name), str):
                                        owner.private.add(document[name])
                                if document.get("error") == "invalid_grant":
                                    error_class = "invalid_grant"
                        except LabError:
                            pass
                    owner.trace.append({"phase": owner.phase, "role": role, "method": self.command,
                                        "request_bytes": len(body), "status": status,
                                        "response_bytes": len(response_body), "error_class": error_class})
                    _send(self, status, response_body, "application/octet-stream", response_headers)
                except (LabError, OSError, ValueError):
                    owner.errors.append("relay_failure")
                    _send(self, 502, b'{"error":"owned_relay_failure"}', "application/json")

        self.server = OwnedHTTPServer(Handler)

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
        self.phase = "setup"
        self.trace: list[dict] = []
        self.errors: list[str] = []
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
                    canary_a = canary_b = False
                    if authorization:
                        require(self.command == "GET" and role != "ordinary" and authorization.startswith("Bearer "), "target_credential_scope")
                        token = authorization[7:]
                        owner.relay.private.add(token)
                        basic = base64.b64encode((RESOURCE_CLIENT + ":" + owner.resource_secret).encode()).decode()
                        status, _, data = request_bytes(owner.relay.origin + INTROSPECTION_PATH, "POST",
                            encoded_form({"token": token, "token_type_hint": "access_token"}),
                            {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic " + basic}, maximum=MAX_TOKEN_BODY)
                        require(status == 200, "target_introspection_status")
                        document = strict_json(data, MAX_TOKEN_BODY)
                        canary_a = introspection_allows(document, "canary-a")
                        canary_b = introspection_allows(document, "canary-b")
                        healthy = canary_a if owner.expected_user == "canary-a" else canary_b
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
                                        "entry_path": parsed.path == "/", "response_bytes": 0 if head else len(body)})
                    _send(self, status, b"" if head else body, mime)
                except (LabError, OSError, ValueError):
                    owner.errors.append("target_failure")
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
        args = ["docker", "create", "--pull=never", "--platform", "linux/amd64", "--interactive",
                "--name", self.container, "--label", "termivar.oauth.owner=" + self.owner,
                "--network", self.network, "--publish", "127.0.0.1::8080",
                "--user", "1000:0", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
                "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1",
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
            require(self.attached.process.poll() is None and not self.attached.overflow.is_set(), "idp_startup_failure")
            inspected = strict_json(self.runner.run(["docker", "inspect", self.container], label="inspect-owned-idp", sensitive_output=True).stdout)
            row = inspected[0]
            ports = row.get("NetworkSettings", {}).get("Ports", {}).get("8080/tcp")
            if isinstance(ports, list) and len(ports) == 1:
                require(ports[0].get("HostIp") == "127.0.0.1" and re.fullmatch(r"[0-9]{1,5}", ports[0].get("HostPort", "")), "idp_loopback_port")
                self.relay.upstream = "http://127.0.0.1:" + ports[0]["HostPort"]
                try:
                    status, _, data = request_bytes(self.relay.origin + REALM_PATH + "/.well-known/openid-configuration", "GET")
                    if status == 200:
                        document = strict_json(data)
                        require(document.get("issuer") == self.relay.origin + REALM_PATH
                                and document.get("token_endpoint") == self.relay.origin + TOKEN_PATH, "idp_advertised_origin")
                        break
                except LabError as error:
                    if error.code not in ("owned_http_transport", "json_malformed"):
                        raise
            time.sleep(1)
        else:
            raise LabError("idp_readiness_timeout")
        network = strict_json(self.runner.run(["docker", "network", "inspect", self.network], label="inspect-owned-network").stdout)
        validate_isolation(inspected[0], network[0], self.owner, self.network)
        # Readiness connection failures are not scanner acceptance failures.
        self.relay.errors.clear()
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
    require(isinstance(host.get("Tmpfs"), dict)
            and set(host["Tmpfs"]) == {"/tmp", "/opt/keycloak/data"}
            and all(isinstance(value, str) and "size=" in value and "uid=1000" in value
                    for value in host["Tmpfs"].values()), "isolation_tmpfs")
    require(all(row.get("Type") == "tmpfs" for row in container.get("Mounts", [])), "isolation_mount")
    require(network.get("Internal") is True and network.get("Driver") == "bridge"
            and network.get("Labels", {}).get("termivar.oauth.owner") == owner, "isolation_network")
    ports = host.get("PortBindings")
    require(isinstance(ports, dict) and set(ports) == {"8080/tcp"}
            and len(ports["8080/tcp"]) == 1 and ports["8080/tcp"][0].get("HostIp") == "127.0.0.1", "isolation_port")


def policy_source(issuer: str, redirect: str, principal: str) -> bytes:
    require(principal in ("canary-a", "canary-b"), "fixture_principal")
    return f'''schema = "security.supplied-session-policy/v5"
principal_alias = "{principal}"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/app/health"
health_json_field = "{'canary_b' if principal == 'canary-b' else 'canary_a'}"
resources = ["/app/private/one", "/app/private/two"]
max_session_requests = 6
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
'''.encode()


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
    require(isinstance(nested, dict) and document.get("schema") == "security.supplied-session-policy/v5"
            and type(document.get("max_response_body_bytes")) is int
            and document["max_response_body_bytes"] == 8192
            and type(nested.get("max_token_response_bytes")) is int
            and nested["max_token_response_bytes"] == 8192
            and nested["max_token_response_bytes"] <= document["max_response_body_bytes"], "fixture_policy_body_caps")


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


def validate_case(name: str, audit: object, target_rows: list[dict], idp_rows: list[dict],
                  anonymous_baseline: list[dict] | None) -> dict:
    require(name in SCENARIOS, "unknown_scenario")
    anonymous = [{"method": row.get("method"), "role": row.get("role"), "entry_path": row.get("entry_path")}
                 for row in target_rows if row.get("credential_present") is False]
    session = [row for row in target_rows if row.get("credential_present") is True]
    exchanges = [row for row in idp_rows if row.get("role") == "token-exchange"]
    diagnostic_oauth = audit.get("oauth_code") if isinstance(audit, dict) else None
    diagnostic = {"scenario": name,
                  "expected": {"session_requests": len(EXPECTED_SESSION_ROLES[name]) + int(name != "option-off"),
                               "resource_count": 2 if name in ("valid-a", "valid-b-context") else 0,
                               "token_posts": int(name != "option-off")},
                  "actual": {"session_requests": marker(audit.get("dispatched_request_count", _MISSING)) if isinstance(audit, dict) else marker(audit),
                             "resource_count": marker(audit.get("committed_resource_count", _MISSING)) if isinstance(audit, dict) else marker(audit),
                             "token_posts": len(exchanges), "target_session_requests": len(session),
                             "oauth_code": {key: marker(diagnostic_oauth.get(key, _MISSING)) if isinstance(diagnostic_oauth, dict) else marker(diagnostic_oauth)
                                            for key in ("request_attempt_count", "request_admitted_count", "response_completed_count",
                                                        "credential_commit_count", "response_bytes", "token_response_validated")},
                             "checkpoints": marker(audit.get("checkpoints", _MISSING)) if isinstance(audit, dict) else marker(audit),
                             "resources": marker(audit.get("resources", _MISSING)) if isinstance(audit, dict) else marker(audit)}}
    require(anonymous_baseline is None or anonymous == anonymous_baseline, "ordinary_trace_changed", diagnostic)
    require(all(row.get("method") == "GET" and row.get("role") == "ordinary" and row.get("entry_path") is True
                for row in anonymous), "ordinary_trace_scope", diagnostic)
    require(tuple(row.get("role") for row in session) == EXPECTED_SESSION_ROLES[name]
            and all(row.get("method") == "GET" for row in session), "session_trace", diagnostic)
    if name == "option-off":
        require(audit is None and not exchanges and not session and len(anonymous) == 3, "option_off_contract", diagnostic)
        return {"status": "passed", "anonymous_trace": anonymous, "diagnostic": diagnostic}
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


def run_offline(runner: Runner, binary: str, bundles: dict[str, tuple[Path, dict]], private: PrivateValues) -> dict:
    results = {}
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
    require("valid-a" in bundles and "valid-b-context" in bundles, "context_compare_sources")
    left, right = bundles["valid-a"], bundles["valid-b-context"]
    compared = runner.run([binary, "report", "compare", "--before", str(left[0] / "assessment.json"),
                           "--after", str(right[0] / "assessment.json"), "--same-scope", "--format", "json"], label="a-to-b-context-compare")
    document = strict_json(compared.stdout)
    counts = comparison_counts(document)
    require(len(item_identities(left[1])) == counts["only_in_before"] + counts["changed"] + counts["unchanged"]
            and len(item_identities(right[1])) == counts["only_in_after"] + counts["changed"] + counts["unchanged"], "context_compare_conservation")
    nested = document.get("supplied_session_comparison")
    require(isinstance(nested, dict) and nested.get("status") == "not_compared"
            and nested.get("context", {}).get("status") == "session_policy_changed"
            and nested.get("health_and_coverage", {}).get("status") == "not_comparable"
            and nested.get("accounting", {}).get("status") == "not_comparable", "different_principal_compare")
    before_rows = document["only_in_before"] + document["changed"] + document["unchanged"]
    after_rows = document["only_in_after"] + document["changed"] + document["unchanged"]
    require(item_identities({"item_count": len(before_rows), "items": before_rows}) == item_identities(left[1])
            and item_identities({"item_count": len(after_rows), "items": after_rows}) == item_identities(right[1]), "context_compare_identities")
    require(left[1].get("supplied_session", {}).get("principal_alias") == "canary-a"
            and right[1].get("supplied_session", {}).get("principal_alias") == "canary-b", "context_compare_principals")
    require(all(snapshot(bundle) == initial[name] for name, (bundle, _) in bundles.items()), "controlled_compare_input_modified")
    return {"status": "passed", "bundles": results,
            "controlled_comparisons": {"a-to-b-context": {"item_counts": counts, "status": "not_compared_different_declared_principal"}}}


def validate_fixture() -> dict:
    # RFC7636 Appendix B independent known-answer, not production-generated.
    require(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "rfc7636_oracle")
    require(len(SCENARIOS) == 6 and len(set(SCENARIOS)) == 6 and set(EXPECTED_SESSION_ROLES) == set(SCENARIOS), "scenario_registry")
    document = realm_document("synthetic-resource-secret-not-for-runtime", "synthetic-controller-secret-not-for-runtime",
                              "http://127.0.0.1:12345/callback")
    clients = document["clients"]
    require(clients[0]["publicClient"] is True and clients[0]["attributes"]["pkce.code.challenge.method"] == "S256"
            and all(client["directAccessGrantsEnabled"] is False for client in clients)
            and clients[1]["publicClient"] is False and clients[0]["defaultClientScopes"] == []
            and clients[0]["optionalClientScopes"] == [SCOPE], "realm_contract")
    validate_fixture_policy(policy_source("http://127.0.0.1:1234/realms/termivar-owned-code",
                                         "http://127.0.0.1:5678/callback", "canary-a"))
    return {"schema": SCHEMA, "status": "fixture_contracts_valid", "execution_class": "static_only",
            "cms_or_idp_execution": "not_performed", "scenario_registry": list(SCENARIOS),
            "provider_version": KEYCLOAK_VERSION, "provider_source": KEYCLOAK_SOURCE,
            "image_index": KEYCLOAK_INDEX, "image_linux_amd64": KEYCLOAK_AMD64}


def execute(binary: Path, output: Path, source_ref: str, expect_version: str, runner: Runner | None = None) -> dict:
    require(re.fullmatch(r"[0-9a-f]{40}", source_ref) is not None, "source_ref")
    require(binary.is_file() and not binary.is_symlink(), "binary_regular_file")
    require(not output.exists(), "output_no_overwrite")
    output.mkdir(mode=0o700, parents=True)
    private = runner.private if runner is not None else PrivateValues()
    runner = runner or Runner(private)
    binary_hash = hashlib.sha256()
    with binary.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            binary_hash.update(block)
    evidence = {**validate_fixture(), "status": "running", "execution_class": "real_owned_keycloak_and_native_cli",
                "source_ref": source_ref, "binary_sha256": binary_hash.hexdigest(),
                "binary_bytes": binary.stat().st_size, "scenarios": {}, "offline": {"status": "not_run"},
                "publication": "not_performed"}
    relay = TokenRelay(private)
    resource_secret = secrets.token_urlsafe(32)
    controller_secret = secrets.token_urlsafe(32)
    for value in (resource_secret, controller_secret):
        private.add(value)
    target = TargetApplication(relay, resource_secret)
    redirect = target.origin + "/callback"
    lab = KeycloakLab(runner, relay, realm_document(resource_secret, controller_secret, redirect))
    primary_error = None
    cleanup = {}
    bundles = {}
    with tempfile.TemporaryDirectory(prefix=".private-owned-oauth-", dir=output, ignore_cleanup_errors=True) as temporary:
        work = Path(temporary)
        private.add(str(work))
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
                target.expected_user = "canary-b" if name == "valid-b-context" else "canary-a"
                policy = work / (name + ".toml")
                grant_file = work / (name + ".secret.tsv")
                private.add(str(policy))
                private.add(str(grant_file))
                grant = None
                if name != "option-off":
                    if name == "replayed-code":
                        require(valid_grant is not None and 0 <= int(time.time()) - valid_grant.received <= 55, "replay_grant_freshness")
                        grant = valid_grant
                    else:
                        relay.phase = "controller-" + name
                        username = "canary-b" if name in ("wrong-b-health", "valid-b-context") else "canary-a"
                        grant = obtain_code(relay.origin, redirect, username, controller_secret, private)
                        if name == "wrong-verifier":
                            verifier = secrets.token_urlsafe(48)
                            private.add(verifier)
                            grant = dataclasses.replace(grant, verifier=verifier, code_challenge=challenge(verifier))
                        if name == "valid-a":
                            valid_grant = grant
                    policy_bytes = policy_source(relay.origin + REALM_PATH, redirect,
                                                 "canary-b" if name == "valid-b-context" else "canary-a")
                    validate_fixture_policy(policy_bytes)
                    private_write(policy, policy_bytes)
                    private_write(grant_file, grant.tsv())
                source_before = grant_file.read_bytes() if grant is not None else None
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
                        and not target.server.handler_failed, "fixture_runtime_failure")
                audit, source = audit_from_output(result, bundle)
                rows = target.trace[target_start:]
                idp_rows = [row for row in relay.trace[relay_start:] if row["phase"] == name]
                summary = validate_case(name, audit, rows, idp_rows, baseline)
                if name == "option-off":
                    baseline = summary["anonymous_trace"]
                summary.pop("anonymous_trace")
                summary.update({"exit_code": result.returncode, "bundle_produced": source is not None,
                                "elapsed_seconds": result.elapsed_seconds,
                                "secret_input_bytes_preserved": grant is None or grant_file.read_bytes() == source_before})
                require(summary["secret_input_bytes_preserved"], "secret_input_modified")
                evidence["scenarios"][name] = summary
                if source is not None:
                    bundles[name] = (bundle, source)
                    for data in snapshot(bundle).values():
                        private.check(data)
                require(source is not None, "expected_completed_bundle", {"scenario": name})
            require(tuple(evidence["scenarios"]) == SCENARIOS, "scenario_coverage")
            require(tuple(bundles) == SCENARIOS, "emitted_bundle_coverage")
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
                evidence["offline"] = run_offline(runner, str(binary), bundles, private)
                require((len(target.trace), len(relay.trace)) == frozen_trace_lengths, "offline_network_activity")
                evidence["offline"]["fixtures_stopped_before_execution"] = True
        except LabError as error:
            if primary_error is None:
                primary_error = error
            else:
                cleanup["secondary_error"] = error.code
    cleanup["private_work_removed"] = not work.exists()
    if not cleanup["private_work_removed"]:
        if primary_error is None:
            primary_error = LabError("private_work_cleanup_failed")
        else:
            cleanup["private_work_secondary_error"] = "private_work_cleanup_failed"
    evidence["cleanup"] = cleanup
    evidence["image_inspection"] = getattr(lab, "image_inspection", None)
    evidence["commands"] = runner.records
    evidence["cms_or_idp_execution"] = "performed" if evidence["scenarios"] else "not_established"
    if primary_error is not None:
        evidence["status"] = "failed"
        evidence["failure"] = {"code": primary_error.code, "diagnostic": primary_error.diagnostic}
    else:
        evidence["status"] = "passed"
    evidence["controller_acquisition"] = "admin_prepared_sso_then_real_post_authorization_s256_form_post"
    evidence["controller_cookie_transport"] = "explicit_owned_loopback_http_exact_relay_authorization_only_secure_attribute_retained"
    evidence["interactive_login_qualification"] = "not_performed"
    evidence["privacy"] = {"selected_sinks_checked": True, "raw_tokens_or_provider_logs_exported": False,
                           "sensitive_python_library_copies_zeroized": "not_claimed"}
    payload = json.dumps(evidence, sort_keys=True, indent=2).encode() + b"\n"
    try:
        require(len(payload) <= MAX_EVIDENCE, "evidence_size")
        private.check(payload)
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
        print(json.dumps({"schema": SCHEMA, "status": result["status"], "scenario_count": len(result["scenarios"])}))
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
