#!/usr/bin/env python3
"""Run an acquired local Termivar binary against a fixed, benign loopback fixture.

Python 3.12.4+, standard library only. No downloads, builds, arbitrary targets,
credentials, optional review flags, or sample normalization. Captures are local
evidence, not automatically safe-to-publish provenance (argv includes local paths).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import http.client
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time


SCHEMA = "termivar-first-use/v1"
CAPTURE_LIMIT = 2 * 1024 * 1024  # Each stdout/stderr capture, not an unbounded pipe.
REPORT_LIMIT = 16 * 1024 * 1024  # Existing renderer ceiling; no runtime limit change.
COMMAND_TIMEOUT = 60.0
HEADER_LIMIT = 8192
DOCUMENT = (
    b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    b"<title>Termivar local demonstration</title></head><body>"
    b"<h1>Termivar local demonstration</h1>"
    b"<p>This fixed static document demonstrates command and report behavior. "
    b"It is not a vulnerable application or a security effectiveness test.</p>"
    b"</body></html>"
)
NOT_FOUND = b"<!doctype html><title>Not found</title><p>No demonstration document.</p>"
METHOD_REFUSED = b"<!doctype html><title>Method not supported</title><p>GET or HEAD only.</p>"
FIXTURE_RESPONSES = {"/": DOCUMENT, "/example": DOCUMENT}


class AcceptanceError(Exception):
    """A checked acceptance condition was not met."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AcceptanceError(message)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fixture_description() -> dict:
    # Hash the complete fixed response contract, not a checkout or user file.
    content = {
        "bind": "127.0.0.1:0",
        "methods": ["GET", "HEAD"],
        "content_type": "text/html; charset=utf-8",
        "routes": {path: body.decode("ascii") for path, body in FIXTURE_RESPONSES.items()},
        "unknown_status": 404,
        "unknown_body": NOT_FOUND.decode("ascii"),
        "unsupported_status": 405,
        "unsupported_body": METHOD_REFUSED.decode("ascii"),
        "header_limit_bytes": HEADER_LIMIT,
    }
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"contract": content, "sha256": digest_bytes(encoded)}


class StaticHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(1.0)
        request = bytearray()
        try:
            while b"\r\n\r\n" not in request and len(request) < HEADER_LIMIT:
                chunk = self.request.recv(min(1024, HEADER_LIMIT - len(request)))
                if not chunk:
                    return
                request.extend(chunk)
            if b"\r\n\r\n" not in request:
                self.server.note("invalid")
                return
            words = bytes(request).split(b"\r\n", 1)[0].split(b" ")
            if len(words) != 3 or words[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
                self.server.note("invalid")
                return
            method, path = words[:2]
            if method not in (b"GET", b"HEAD"):
                code, reason, body, category = 405, "Method Not Allowed", METHOD_REFUSED, "unsupported"
            elif path in (b"/", b"/example"):
                code, reason, body = 200, "OK", FIXTURE_RESPONSES[path.decode("ascii")]
                category = "root" if path == b"/" else "example"
            else:
                code, reason, body, category = 404, "Not Found", NOT_FOUND, "unknown"
            self.server.note(category)
            headers = (
                f"HTTP/1.1 {code} {reason}\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            self.request.sendall(headers + (b"" if method == b"HEAD" else body))
        except (OSError, TimeoutError):
            return


class StaticServer(socketserver.TCPServer):
    allow_reuse_address = False

    def __init__(self) -> None:
        self.counts = {key: 0 for key in ("root", "example", "unknown", "unsupported", "invalid")}
        self.count_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), StaticHandler)

    def note(self, category: str) -> None:
        with self.count_lock:
            self.counts[category] += 1

    def snapshot(self) -> dict:
        with self.count_lock:
            return self.counts.copy()

    def handle_error(self, request, client_address) -> None:
        # Never reflect or log requests, headers, peer addresses, or paths.
        self.note("invalid")


class Fixture:
    def __init__(self) -> None:
        self.server = StaticServer()  # Bind before any readiness report.
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05})
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}/"

    def __enter__(self) -> "Fixture":
        try:
            self.thread.start()
            # Direct numeric connection; http.client does not use a proxy.
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=3)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                require(response.status == 200 and response.read(HEADER_LIMIT) == DOCUMENT,
                        "fixture readiness response did not match")
            finally:
                connection.close()
        except BaseException:
            self.close()
            raise
        return self

    def close(self) -> None:
        if self.thread.is_alive():
            self.server.shutdown()
        self.server.server_close()
        if self.thread.ident is not None:
            self.thread.join(timeout=3)
        require(not self.thread.is_alive(), "fixture did not stop")

    def __exit__(self, *exc) -> None:
        self.close()


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        process.wait(timeout=2)
        return
    except OSError:
        if process.poll() is None:
            raise
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def run_command(argv: list[str], directory: Path, record: dict,
                timeout: float = COMMAND_TIMEOUT, capture_limit: int = CAPTURE_LIMIT) -> tuple[bytes, bytes]:
    """Bound both pipes while running; always reap the one CLI child we start."""
    record.update(argv=argv, started_at=utc_now(), exit_code=None)
    started = time.monotonic()
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    read_errors = []
    readers = []
    process = None

    def collect(pipe, buffer):
        try:
            while chunk := pipe.read1(8192):
                available = max(0, capture_limit - len(buffer))
                buffer.extend(chunk[:available])
                if len(chunk) > available:
                    overflow.set()
        except OSError as error:
            read_errors.append(type(error).__name__)
        finally:
            pipe.close()

    try:
        process = subprocess.Popen(argv, cwd=directory, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=os.name == "posix")
        for pipe, buffer in zip((process.stdout, process.stderr), buffers):
            thread = threading.Thread(target=collect, args=(pipe, buffer))
            thread.start()
            readers.append(thread)
        deadline = started + timeout
        while process.poll() is None:
            require(not overflow.is_set(), "command capture exceeded its byte limit")
            remaining = deadline - time.monotonic()
            require(remaining > 0, "command exceeded its wall-time limit")
            try:
                process.wait(timeout=min(0.05, remaining))
            except subprocess.TimeoutExpired:
                pass
        for thread in readers:
            thread.join(timeout=2)
        require(not any(thread.is_alive() for thread in readers), "command capture did not close")
        require(not read_errors, "command capture failed before normal EOF")
        require(not overflow.is_set(), "command capture exceeded its byte limit")
    except OSError as error:
        record["start_or_io_error"] = {"type": type(error).__name__, "errno": error.errno,
                                       "winerror": getattr(error, "winerror", None)}
        raise AcceptanceError("local binary could not execute; host protections were not changed") from error
    finally:
        if process is not None:
            try:
                stop_process(process)
            except (OSError, subprocess.TimeoutExpired) as error:
                # Keep the primary timeout/cancellation error and record cleanup
                # failure separately, never replace it with a process-exit race.
                record["cleanup_error"] = type(error).__name__
            record["exit_code"] = process.returncode
        for thread in readers:
            thread.join(timeout=3)
        record["finished_at"] = utc_now()
        record["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        record["capture_limit_exceeded"] = overflow.is_set()
        if read_errors:
            record["capture_read_errors"] = list(read_errors)
        for stream, buffer in zip(("stdout", "stderr"), buffers):
            relative = f"captures/{record['invocation_id']}.{stream}.txt"
            with (directory / relative).open("xb") as output:
                output.write(buffer)
            record[stream] = {"path": relative, "bytes": len(buffer), "sha256": digest_bytes(buffer)}
    require("cleanup_error" not in record, "CLI child cleanup failed; inspect provenance")
    return bytes(buffers[0]), bytes(buffers[1])


def bounded_report(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(), "report must be a regular file")
    with path.open("rb") as source:
        data = source.read(REPORT_LIMIT + 1)
    require(0 < len(data) <= REPORT_LIMIT, "report size is outside the renderer bound")
    return data


def parse_document(data: bytes) -> dict:
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as error:
        raise AcceptanceError("CLI output is not one complete JSON document") from error
    require(isinstance(value, dict), "CLI JSON must be an object")
    return value


class ReportHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags = set()

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        require(tag not in {"script", "iframe", "object", "embed", "form", "base"},
                "report contains active or embedded content")
        for name, value in attrs:
            require(not name.startswith("on"), "report contains an event handler")
            if name in {"src", "href", "action", "data", "srcset"}:
                require(value is not None and value.startswith("#"), "report refers to an external resource")


def validate_sample(data: bytes, binary: Path, html: bool = False) -> None:
    text = data.decode("utf-8")
    private_paths = [str(binary), str(Path.cwd())]
    try:
        private_paths.append(str(Path.home()))
    except RuntimeError:
        pass  # Service accounts need not have a home; generic path checks remain.
    for private in private_paths:
        require(private not in text, "report contains a machine-specific private path")
    require(re.search(r"(?i)(?:https?://|file://|/Users/|/home/|[A-Z]:\\)", text) is None,
            "report contains an unexpected URL or private path")
    if html:
        parsed = ReportHTML()
        parsed.feed(text)
        parsed.close()
        require({"html", "head", "title", "body"} <= parsed.tags,
                "report is not a complete HTML document")
        require("<title>Termivar assessment report</title>" in text,
                "HTML does not identify the existing assessment renderer")
        require("</html>" in text.lower() and "informational" in text,
                "HTML report does not contain complete informational output")
        require(re.search(r"(?i)(?:@import|url\s*\()", text) is None,
                "HTML report contains an external style resource")


def exercise(binary: Path, directory: Path, expected_version: str, provenance: dict) -> None:
    records = provenance["invocations"]

    def invoke(name, args, fixture=None):
        record = {"invocation_id": name}
        records.append(record)
        before = fixture.server.snapshot() if fixture else None
        try:
            stdout, stderr = run_command([str(binary), *args], directory, record)
        finally:
            if fixture:
                after = fixture.server.snapshot()
                record["fixture_requests"] = {key: after[key] - before[key] for key in before}
        return record, stdout, stderr

    for name, args in [("01-version", ["--version"]), ("02-help", ["--help"]),
                       ("03-scan-help", ["scan", "--help"])]:
        record, stdout, _ = invoke(name, args)
        require(record["exit_code"] == 0, f"{name} did not succeed")
        text = stdout.decode("utf-8")
        if name == "01-version":
            provenance["binary"]["actual_version_output"] = text.strip()
            require(text.strip() == f"termivar {expected_version}", "binary version did not match expectation")
        elif name == "02-help":
            require("scan" in text and "--version" in text, "top-level help lacks documented syntax")
        else:
            require(all(option in text for option in ("--profile", "--format", "--report-format", "--report-output", "web-review")),
                    "scan help lacks documented report syntax")

    with Fixture() as fixture:
        provenance["fixture"]["actual_origin"] = fixture.origin
        record, stdout, _ = invoke("04-default", ["scan", "--format", "json", fixture.origin], fixture)
        require(record["exit_code"] == 0, "default scan did not succeed")
        default = parse_document(stdout)
        require(default.get("schema_version") == "decision-scan/v1", "default schema changed")
        require("assessment" not in default and "profile_contract" not in default,
                "default operational output became a findings report")
        terminal = default.get("terminal", {})
        require(terminal.get("runtime_limit") is None and (
            terminal.get("command") == "complete" or
            (terminal.get("command") == "halt" and terminal.get("stop_reason") == "no_eligible_action")),
            "default scan did not reach an ordinary completed operational stop")
        require(default.get("usage", {}).get("total_requests", 0) > 0 and record["fixture_requests"]["root"] > 0,
                "default scan did not observe the fixture")
        with (directory / "default.json").open("xb") as output:
            output.write(stdout)

        for number, kind in [(5, "json"), (6, "html")]:
            destination = f"assessment.{kind}"
            record, stdout, _ = invoke(f"{number:02}-assessment-{kind}", [
                "scan", "--profile", "web-review", "--report-format", kind,
                "--report-output", destination, fixture.origin], fixture)
            require(record["exit_code"] == 0 and not stdout, f"{kind} report file run did not succeed cleanly")
            require(record["fixture_requests"]["root"] > 0, "report run did not observe the fixture")
            data = bounded_report(directory / destination)
            validate_sample(data, binary, html=kind == "html")
            if kind == "json":
                report = parse_document(data)
                require(report.get("schema") == "venom-rendered-assessment/v1"
                        and report.get("source_schema") == "venom-assessment-run/v1"
                        and report.get("profile_schema") == "venom.scan-profile/v1"
                        and report.get("profile") == "web-review" and report.get("status") == "complete",
                        "completed assessment report contract changed")
                items = report.get("items")
                require(isinstance(items, list) and len(items) == report.get("item_count") and len(items) > 0,
                        "assessment item count is missing or inconsistent")
                require(all(item.get("disposition") == "informational" and item.get("claim_basis") == "observation"
                            and item.get("subject_reference") == "subject-0000" for item in items),
                        "fixture did not produce only root informational observations")
                require(not any(key in report for key in ("authorization_review", "openapi_review", "rest_review", "ssrf_oast_review")),
                        "an optional review was unexpectedly evaluated")
            record["report"] = {"path": destination, "bytes": len(data), "sha256": digest_bytes(data)}

        original = bounded_report(directory / "assessment.json")
        record, stdout, stderr = invoke("07-existing-output", [
            "scan", "--profile", "web-review", "--report-format", "json",
            "--report-output", "assessment.json", fixture.origin], fixture)
        require(record["exit_code"] != 0 and not stdout and b"report output already exists" in stderr,
                "existing output was not refused")
        require(bounded_report(directory / "assessment.json") == original, "existing report bytes changed")
        record["preserved_report_sha256"] = digest_bytes(original)
        require(sum(record["fixture_requests"].values()) == 0, "existing-output refusal contacted the fixture")

        record, stdout, stderr = invoke("08-preflight-failure", [
            "scan", "--profile", "baseline", "--report-format", "json",
            "--report-output", "preflight-must-not-exist.json", fixture.origin], fixture)
        require(record["exit_code"] != 0 and not stdout and b"--profile" in stderr,
                "preflight conflict did not fail before output")
        require(not (directory / "preflight-must-not-exist.json").exists(), "preflight failure created a report")
        require(sum(record["fixture_requests"].values()) == 0, "preflight failure contacted the fixture")

        # Existing non-origin-root subject-identity seam, not a query/payload or
        # a production limit change. This must begin I/O, then withhold a report.
        record, stdout, _ = invoke("09-begun-incomplete", [
            "scan", "--profile", "web-review", "--format", "json", "--report-format", "json",
            "--report-output", "incomplete-must-not-exist.json", fixture.origin + "example"], fixture)
        require(record["exit_code"] != 0, "non-root assessment unexpectedly completed")
        require(record["fixture_requests"]["example"] > 0, "incomplete case never began fixture I/O")
        require(not (directory / "incomplete-must-not-exist.json").exists(), "incomplete case created a success report")
        incomplete = parse_document(stdout)
        require(incomplete.get("schema_version") == "web-assessment/v2" and incomplete.get("disposition") == "incomplete",
                "begun-incomplete diagnostic contract changed")
        require(incomplete.get("incomplete_reasons"), "incomplete diagnostic has no reasons")
        projection = incomplete.get("assessment", {}).get("report", {}).get("assessment_items", {})
        require(projection.get("projection_status") == "unavailable" and "items" not in projection,
                "incomplete case published a partial item projection")
        provenance["fixture"]["request_counts_including_readiness"] = fixture.server.snapshot()
    provenance["fixture"]["stopped"] = True


def run_acceptance(binary: Path, directory: Path, source_ref: str,
                   build_features: str, expected_version: str) -> dict:
    require(sys.version_info >= (3, 12, 4), "Python 3.12.4 or newer is required for private Windows output directories")
    require(not any(value for name, value in os.environ.items()
                    if name.lower() in {"http_proxy", "https_proxy", "all_proxy"}),
            "proxy configuration is present; runner will not change host proxy policy")
    binary = binary.expanduser().resolve(strict=True)
    require(binary.is_file(), "explicit local binary must be a regular file")
    require(re.fullmatch(r"(?:[a-fA-F0-9]{40}|v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?)", source_ref) is not None,
            "source ref must be a full commit SHA or exact version tag")
    require(0 < len(build_features) <= 128 and all(32 <= ord(c) < 127 for c in build_features),
            "build features must be a short declared label")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", expected_version) is not None,
            "expected version must be explicit")
    require(not directory.exists() and not directory.is_symlink(), "output directory must be fresh and nonexistent")
    directory.mkdir(mode=0o700)  # No recursive directory creation or cleanup of user data.
    directory = directory.resolve()
    (directory / "captures").mkdir(mode=0o700)
    provenance = {
        "schema": SCHEMA, "status": "running", "started_at": utc_now(),
        "binary": {"path": str(binary), "sha256": digest_file(binary),
                   "declared_source_ref": source_ref, "declared_build_features": build_features,
                   "expected_version": expected_version,
                   "declarations_note": "Ref and features are caller declarations, not inferred or attested by --version."},
        "host": {"os": platform.system(), "architecture": platform.machine(), "python": platform.python_version()},
        "fixture": fixture_description(), "invocations": [],
        "normalization": [],
        "limits": {"command_seconds": COMMAND_TIMEOUT, "capture_bytes_per_stream": CAPTURE_LIMIT,
                   "report_bytes": REPORT_LIMIT},
    }
    try:
        exercise(binary, directory, expected_version, provenance)
        require(digest_file(binary) == provenance["binary"]["sha256"], "binary changed during acceptance")
        provenance["status"] = "passed"
    except KeyboardInterrupt:
        provenance["status"] = "cancelled"
        provenance["failure"] = "interrupted; started CLI and fixture cleanup requested"
    except (AcceptanceError, OSError, UnicodeError) as error:
        provenance["status"] = "failed"
        provenance["failure"] = str(error) if isinstance(error, AcceptanceError) else type(error).__name__
    finally:
        provenance["finished_at"] = utc_now()
        with (directory / "provenance.json").open("x", encoding="utf-8", newline="\n") as output:
            json.dump(provenance, output, indent=2, sort_keys=True)
            output.write("\n")
    return provenance


def public_provenance(raw: dict) -> dict:
    """Return a display copy changing only the documented local-binary fields.

    Raw captures stay local/CI. Reports are never rewritten here. Invocation
    labels are harness identities; the renderer need not expose a runtime ID.
    """
    result = json.loads(json.dumps(raw))
    result["binary"]["path"] = "<LOCAL_BINARY>"
    for invocation in result["invocations"]:
        invocation["argv"][0] = "<LOCAL_BINARY>"
    result["normalization"] = [*result.get("normalization", []), {
        "fields": ["binary.path", "invocations[*].argv[0]"],
        "replacement": "<LOCAL_BINARY>",
        "reason": "Remove the local executable path only; all other measured evidence is unchanged.",
    }]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="already acquired LOCAL executable; never built or downloaded")
    parser.add_argument("--output", type=Path, required=True, help="fresh nonexistent output directory with an existing parent")
    parser.add_argument("--source-ref", required=True, help="declared full source commit or exact release tag")
    parser.add_argument("--build-features", required=True, help="declared build feature set, e.g. default or release-bundle")
    parser.add_argument("--expect-version", required=True, help="exact expected version, e.g. 0.10.0-alpha.2")
    args = parser.parse_args(argv)
    try:
        result = run_acceptance(args.binary, args.output, args.source_ref, args.build_features, args.expect_version)
    except (AcceptanceError, OSError) as error:
        print(f"first-use: {error}", file=sys.stderr)
        return 1
    print(f"first-use: {result['status']}; inspect the bounded captures and provenance in the selected output directory")
    return 0 if result["status"] == "passed" else 130 if result["status"] == "cancelled" else 1


if __name__ == "__main__":
    def interrupt(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
