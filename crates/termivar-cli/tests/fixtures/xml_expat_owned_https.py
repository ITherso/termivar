"""Bounded CPython/Expat oracle for the owned HTTPS XML CLI acceptance.

This is test infrastructure, not a product XML parser.  It deliberately admits
one fixed provider hostname and one fixed loopback resolver.  The public test
root is pinned below; no system roots, proxy settings, redirects, retries, or
caller-selected destinations are used.
"""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import sys
from urllib.parse import urlsplit
from xml.parsers import expat


MAX_XML_BYTES = 96 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 16 * 1024
PROVIDER_HOST = "oast-provider.termivar.test"
PROVIDER_ADDRESS = "::1"
RESULT_SCHEMA = "termivar-test.xml-expat-result/v1"
ROOT_CERTIFICATE_DER_BASE64 = (
    "MIIBjTCCATOgAwIBAgIJAJLYjoWViQgyMAoGCCqGSM49BAMCMCkxJzAlBgNVBAMT"
    "HlRlcm1pdmFyIE93bmVkIEhUVFBTIFRlc3QgUm9vdDAgFw0yNjA4MzAwMDAwMDBa"
    "GA8yMDk5MTIzMTIzNTk1OVowKTEnMCUGA1UEAxMeVGVybWl2YXIgT3duZWQgSFRU"
    "UFMgVGVzdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEIQz45V50Pyx"
    "2eBYt1RA6bImh/m+1+tFfrE3o4dEwLpyfTYF314TD9K/HFknQlmO2//jzCYCXAWJ"
    "JkBnmP5qRqNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD"
    "VR0OBBYEFBd0YfXO+Bxp1hr5F4pYDhecrqA3MAoGCCqGSM49BAMCA0gAMEUCIEYh"
    "m8rw77JIp6N6ZYDJT6Vvh37VamQZZJpzCuSNKLwzAiEAzsZJR6xAfZPCEjF1SSi9"
    "QZHP7IZerxPUSmqzKFPCGsM="
)


class OracleError(Exception):
    """A value-free failure classification for the owned fixture."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--mode", choices=("safe", "external"), required=True)
    parser.add_argument("--provider-port", type=int, required=True)
    result = parser.parse_args()
    if not 1 <= result.provider_port <= 65535:
        raise OracleError("provider_port")
    return result


def _read_xml() -> bytes:
    document = sys.stdin.buffer.read(MAX_XML_BYTES + 1)
    if len(document) > MAX_XML_BYTES:
        raise OracleError("xml_bound")
    if not document:
        raise OracleError("xml_empty")
    return document


def _read_provider_response(stream: ssl.SSLSocket) -> bytes:
    response = bytearray()
    while len(response) <= MAX_PROVIDER_RESPONSE_BYTES:
        chunk = stream.recv(min(4096, MAX_PROVIDER_RESPONSE_BYTES + 1 - len(response)))
        if not chunk:
            break
        response.extend(chunk)
    if len(response) > MAX_PROVIDER_RESPONSE_BYTES:
        raise OracleError("provider_response_bound")
    return bytes(response)


def _fetch_external_entity(system_id: str, provider_port: int) -> bytes:
    parsed = urlsplit(system_id)
    if (
        parsed.scheme != "https"
        or parsed.hostname != PROVIDER_HOST
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or "\r" in parsed.path
        or "\n" in parsed.path
        or len(parsed.path.encode("utf-8")) > 2048
    ):
        raise OracleError("provider_authority")

    root_der = base64.b64decode(ROOT_CERTIFICATE_DER_BASE64, validate=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(root_der))

    raw = socket.create_connection((PROVIDER_ADDRESS, provider_port), timeout=2.0)
    stream: ssl.SSLSocket | None = None
    try:
        stream = context.wrap_socket(raw, server_hostname=PROVIDER_HOST)
        stream.settimeout(2.0)
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {PROVIDER_HOST}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        stream.sendall(request)
        response = _read_provider_response(stream)
        stream.unwrap().close()
    except Exception:
        if stream is not None:
            stream.close()
        else:
            raw.close()
        raise

    head_end = response.find(b"\r\n\r\n")
    if head_end < 0:
        raise OracleError("provider_response_head")
    head = response[:head_end]
    if not head.startswith(b"HTTP/1.1 204 "):
        raise OracleError("provider_response_status")
    return response[head_end + 4 :]


def _parse(document: bytes, mode: str, provider_port: int) -> int:
    parser = expat.ParserCreate(namespace_separator="|")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    resolutions = 0

    if mode == "external":

        def resolve_external_entity(
            context: str,
            base: str | None,
            system_id: str,
            public_id: str | None,
        ) -> int:
            del base, public_id
            nonlocal resolutions
            if resolutions != 0:
                raise OracleError("external_entity_bound")
            # Consume the only permitted resolution before any network work so
            # a nested external entity cannot create a second request.
            resolutions += 1
            payload = _fetch_external_entity(system_id, provider_port)
            external = parser.ExternalEntityParserCreate(context)
            external.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
            external.Parse(payload, True)
            return 1

        parser.ExternalEntityRefHandler = resolve_external_entity

    parser.Parse(document, True)
    return resolutions


def _main() -> int:
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 12):
        raise OracleError("runtime")
    arguments = _arguments()
    document = _read_xml()
    resolutions = _parse(document, arguments.mode, arguments.provider_port)
    result = {
        "external_entity_count": resolutions,
        "mode": arguments.mode,
        "runtime": "cpython-3.12",
        "schema": RESULT_SCHEMA,
    }
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 1024:
        raise OracleError("result_bound")
    sys.stdout.buffer.write(encoded + b"\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except (OracleError, expat.ExpatError, OSError, ssl.SSLError, ValueError) as error:
        code = error.code if isinstance(error, OracleError) else "parser_or_transport"
        sys.stderr.write(f"xml_expat_oracle:{code}\n")
        raise SystemExit(2) from None
