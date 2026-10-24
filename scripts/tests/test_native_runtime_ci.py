"""Literal source-contract and real-process checks for native CI partitioning."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"
BASELINE = ROOT / "scripts" / "tests" / "fixtures" / "native-runtime-baseline.yml"
SCRIPT = ROOT / "scripts" / "ci" / "native_runtime_gate.py"
SPEC = importlib.util.spec_from_file_location("native_runtime_gate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("native gate test module is unavailable")
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

# Independently reviewed identities and payload placement, not read from the gate.
JOBS = ("platform-runtime-core", "platform-runtime-reviews", "platform-runtime-protocols")
HOSTS = ("ubuntu-latest", "windows-latest", "macos-latest", "macos-15-intel")
PAYLOADS = {
    "core": (
        "Build default CLI",
        "Exercise CLI metadata",
        "Exercise compiled CLI capabilities offline",
        "Exercise opt-in live progress CLI",
        "Exercise opt-in WordPress review CLI",
        "Exercise opt-in WordPress discovery CLI",
        "Exercise opt-in supplied-session review CLI",
        "Exercise opt-in resource authorization review CLI",
        "Guard the native Windows all-feature assessment stack",
        "Exercise opt-in passive TLS observation CLI",
        "Exercise trusted passive TLS observation broker path",
        "Reject authenticated session bodies from the anonymous secret-exposure context",
        "Exercise supplied-session WordPress integration CLI",
        "Exercise supplied-session WordPress preflight boundaries",
        "Exercise supplied-session and OAST preflight composition",
        "Exercise delayed native OAST replay polling",
        "Test first-use fixture and checked-in sample contracts",
        "Test release archive verification contracts",
        "Test packaged release candidate acceptance contracts",
        "Accept the actual development CLI against its own loopback fixture",
        "Acquire the exact published Linux prerelease for separate acceptance",
        "Accept the verified published Linux binary without a source substitute",
        "Retain bounded first-use acceptance evidence",
        "Exercise default decision scan against loopback",
        "Exercise atomic report-output path semantics",
        "Exercise single-run report bundle CLI",
        "Exercise offline report comparison CLI",
        "Exercise offline report bundle verification CLI",
        "Test fixed offline comparison controls without a browser",
        "Exercise credential input handle and buffer contracts",
        "Exercise provider secret-file contracts",
        "Exercise focused core and scanner contracts",
    ),
    "reviews": (
        "Exercise opt-in passive secret-exposure review CLI",
        "Exercise value-free GraphQL privacy composition CLI",
        "Exercise opt-in local JWT policy review CLI",
        "Exercise opt-in JWT target-acceptance review CLI",
        "Exercise opt-in control-reference mapping CLI",
        "Exercise opt-in Cert Spotter CT provider CLI",
        "Exercise opt-in Cert Spotter CT provider capability contract",
        "Exercise opt-in reconnaissance snapshot import CLI",
        "Exercise opt-in reconnaissance snapshot capability contract",
        "Exercise bounded WebSocket review through an owned loopback fixture",
        "Exercise opt-in WebSocket capability contract",
        "Exercise supplied-session WebSocket review through an owned loopback fixture",
        "Exercise supplied-session WebSocket capability contract",
    ),
    "protocols": (
        "Exercise active TLS negotiation through the owned HTTPS profile",
        "Exercise opt-in active TLS negotiation capability contract",
        "Exercise isolated HTTP desynchronization parser-boundary laboratory",
        "Exercise opt-in XML external-entity CLI preflight contracts",
        "Exercise bounded XML external-entity runtime through an owned loopback fixture",
        "Exercise XML external-entity review through the owned HTTPS profile",
        "Exercise opt-in XML external-entity capability contract",
        "Exercise harmless template-evaluation review through a real owned engine",
        "Exercise opt-in template-evaluation capability contract",
    ),
}
GUARD = """      - name: Test native runtime orchestration contracts
        run: python -m unittest discover -s scripts/tests -p test_native_runtime_ci.py"""
# Deliberately additive to the frozen 54-payload oracle; do not rewrite the
# historical snapshot to manufacture agreement with this new native slice.
OPENAPI_PRIVACY = """      - name: Exercise value-free OpenAPI privacy composition and feature-off reader
        shell: bash
        run: |
          set -euo pipefail
          cargo test --release --locked -p termivar-cli --no-default-features --features openapi-review,secret-exposure-review,ssrf-oast-review --test openapi_secret_exposure_cli -- --nocapture
          cargo test --release --locked -p termivar-scanner --lib --no-default-features --features reporting openapi_saved_reader_ -- --nocapture"""
REST_PRIVACY = """      - name: Exercise value-free REST privacy composition and feature-off reader
        shell: bash
        run: |
          set -euo pipefail
          cargo test --release --locked -p termivar-cli --no-default-features --features rest-review,secret-exposure-review,ssrf-oast-review --test rest_secret_exposure_cli -- --nocapture
          cargo test --release --locked -p termivar-scanner --lib --no-default-features --features reporting rest_saved_reader_ -- --nocapture"""
AUTHORIZATION_PRIVACY = """      - name: Exercise value-free resource authorization privacy composition and feature-off reader
        shell: bash
        run: |
          set -euo pipefail
          cargo test --release --locked -p termivar-cli --no-default-features --features authorization-review,secret-exposure-review --test authorization_review_cli privacy_composition:: -- --nocapture
          cargo test --release --locked -p termivar-scanner --lib --no-default-features --features authorization-review,secret-exposure-review authorization_privacy -- --nocapture
          cargo test --release --locked -p termivar-scanner --lib --no-default-features --features reporting authorization_saved_reader_ -- --nocapture"""
MATRIX = "        os: [ubuntu-latest, windows-latest, macos-latest, macos-15-intel]"
OAUTH_CODE = """      - name: Exercise imported OAuth-code session and feature-off reader
        shell: bash
        env:
          TERMIVAR_NATIVE_SOURCE: ${{ github.event.pull_request.head.sha || github.sha }}
        run: |
          set -euo pipefail
          cargo test --release --locked -p termivar-cli --no-default-features --features supplied-session-review,secret-exposure-review --test supplied_session_oauth_code_cli --test capabilities_cli -- --nocapture
          python -c 'import hashlib,json,os,pathlib,platform; e=os.environ; p=pathlib.Path("target/release/termivar"+(".exe" if os.name=="nt" else "")); assert p.is_file() and not p.is_symlink(); n=p.stat().st_size; assert 0<n<=2**27; print(json.dumps(dict(schema="native-oauth-executable/v1",source=e["TERMIVAR_NATIVE_SOURCE"],run_id=e["GITHUB_RUN_ID"],run_attempt=e["GITHUB_RUN_ATTEMPT"],host=platform.system(),arch=platform.machine(),features="supplied-session-review,secret-exposure-review",profile="release",bytes=n,sha256=hashlib.file_digest(p.open("rb"),"sha256").hexdigest(),assurance="self_reported_hash_not_attestation"),sort_keys=True))'
          cargo test --release --locked -p termivar-scanner --lib --no-default-features --features supplied-session-review,reporting web_runtime::supplied_session_runtime::oauth_code::tests:: -- --nocapture
          cargo test --release --locked -p termivar-scanner --lib --no-default-features --features reporting supplied_session_oauth_code_saved_reader_ -- --nocapture"""
BUDGET = "    timeout-minutes: ${{ matrix.os == 'macos-15-intel' && 120 || 90 }}"
CHECKOUT = """      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803 # v6
        with:
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}"""
PYTHON_SETUP = '''      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.12"'''
AGGREGATE = """  platform-runtime-smoke:
    name: Runtime Smoke (${{ matrix.os }})
    needs: [platform-runtime-core, platform-runtime-reviews, platform-runtime-protocols]
    if: ${{ always() }}
    runs-on: ${{ matrix.os }}
""" + BUDGET + """
    permissions:
      contents: read
    strategy:
      fail-fast: false
      matrix:
""" + MATRIX + """
    steps:
""" + CHECKOUT + "\n" + PYTHON_SETUP + """
      - name: Require every native runtime partition
        env:
          TERMIVAR_NATIVE_RUNTIME_NEEDS: ${{ toJSON(needs) }}
        run: python scripts/ci/native_runtime_gate.py"""

# Textual LF snapshot identity; CRLF checkouts normalize before comparison.
BASELINE_TEXT_SHA256 = "25a09154798c8e0045d359b848758fc288b5d5d3c77bca73a7f9934e51d18c29"


def job_records(text: str) -> dict[str, str]:
    text = text.replace("\r\n", "\n")
    if text.count("\njobs:\n") != 1:
        raise AssertionError("one literal jobs mapping required")
    jobs = text.split("\njobs:\n", 1)[1]
    for line in jobs.splitlines():
        if line.startswith("  ") and not line.startswith("   ") and line.strip():
            if not line.startswith("  #") and not re.fullmatch(r"  [a-z][a-z0-9-]*:", line):
                raise AssertionError("unsupported job mapping")
    matches = list(re.finditer(r"^  ([a-z][a-z0-9-]*):\n", jobs, re.MULTILINE))
    result = {}
    for index, match in enumerate(matches):
        name = match.group(1)
        if name in result:
            raise AssertionError("duplicate job")
        end = matches[index + 1].start() if index + 1 < len(matches) else len(jobs)
        result[name] = jobs[match.start():end].rstrip("\n")
    return result


def split_steps(job: str) -> tuple[str, list[str]]:
    marker = "    steps:\n"
    if job.count(marker) != 1:
        raise AssertionError("one steps sequence required")
    header, body = job.split(marker, 1)
    blocks = re.split(r"(?=^      - )", body, flags=re.MULTILINE)
    if blocks[0].strip():
        raise AssertionError("unexpected steps prefix")
    blocks = [block.rstrip("\n") for block in blocks if block.strip()]
    if any(not re.match(r"      - (name|uses): ", block) for block in blocks):
        raise AssertionError("unsupported step shape")
    return header + marker, blocks


def step_name(block: str) -> str:
    prefix = "      - name: "
    if not block.startswith(prefix):
        raise AssertionError("named payload required")
    return block.split("\n", 1)[0][len(prefix):]


def valid_results() -> dict:
    # Literal synthetic CI result, not captured execution or a gate-generated oracle.
    return {
        "platform-runtime-core": {"result": "success", "outputs": {}},
        "platform-runtime-reviews": {"result": "success", "outputs": {}},
        "platform-runtime-protocols": {"result": "success", "outputs": {}},
    }


class NativeRuntimeWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.baseline = BASELINE.read_text(encoding="utf-8")
        _, blocks = split_steps("  platform-runtime-smoke:\n" + cls.baseline.split(
            "  platform-runtime-smoke:\n", 1
        )[1].rstrip("\n"))
        cls.setup = blocks[:4]
        cls.original = {step_name(block): block for block in blocks[4:]}

    def assert_contract(self, text: str):
        jobs = job_records(text)
        self.assertEqual(
            {key for key in jobs if key.startswith("platform-runtime-")},
            {*JOBS, "platform-runtime-smoke"},
        )
        for phase, payloads in PAYLOADS.items():
            identifier = "platform-runtime-" + phase
            header, blocks = split_steps(jobs[identifier])
            expected_header = (
                f"  {identifier}:\n"
                f"    name: Native Runtime {phase.title()} ("
                "${{ matrix.os }})\n"
                "    runs-on: ${{ matrix.os }}\n" + BUDGET + "\n"
                "    permissions:\n      contents: read\n"
                "    strategy:\n      fail-fast: false\n      matrix:\n"
                + MATRIX + "\n    steps:\n"
            )
            self.assertEqual(header, expected_header)
            self.assertEqual(blocks[:4], self.setup)
            expected = [self.original[name] for name in payloads]
            if phase == "core":
                expected.insert(0, GUARD)
                expected.insert(8, OAUTH_CODE)
            if phase == "reviews":
                expected.insert(2, OPENAPI_PRIVACY)
                expected.insert(3, REST_PRIVACY)
                expected.insert(4, AUTHORIZATION_PRIVACY)
            self.assertEqual(blocks[4:], expected)
        self.assertEqual(jobs["platform-runtime-smoke"], AGGREGATE)
        # This also catches duplicate payloads relocated outside the native workers.
        all_names = re.findall(r"^      - name: (.+)$", text.replace("\r\n", "\n"), re.MULTILINE)
        for payload in self.original:
            self.assertEqual(all_names.count(payload), 1)
        self.assertEqual(all_names.count(step_name(OPENAPI_PRIVACY)), 1)
        self.assertEqual(all_names.count(step_name(REST_PRIVACY)), 1)
        self.assertEqual(all_names.count(step_name(AUTHORIZATION_PRIVACY)), 1)
        self.assertEqual(all_names.count(step_name(OAUTH_CODE)), 1)

    def test_oauth_code_extension_cannot_be_omitted_or_weakened(self):
        for changed in (
            "", OAUTH_CODE + "\n" + OAUTH_CODE,
            OAUTH_CODE.replace("        shell: bash\n", ""),
            OAUTH_CODE.replace("set -euo pipefail", "true"),
            OAUTH_CODE.replace("--release --locked", "--locked"),
            OAUTH_CODE.replace("supplied-session-review,secret-exposure-review", "supplied-session-review"),
            OAUTH_CODE.replace("--test supplied_session_oauth_code_cli", "--test supplied_session_cli"),
            OAUTH_CODE.replace(" --test capabilities_cli", ""),
            OAUTH_CODE.replace('          TERMIVAR_NATIVE_SOURCE: ${{ github.event.pull_request.head.sha || github.sha }}\n', ""),
            "\n".join(line for line in OAUTH_CODE.splitlines() if "          python -c " not in line),
            OAUTH_CODE.replace('target/release/termivar', 'target/debug/termivar'),
            OAUTH_CODE.replace("oauth_code::tests::", "nonexistent_filter::"),
            OAUTH_CODE.replace("--features reporting supplied_session_oauth_code_saved_reader_", "--features supplied-session-review supplied_session_oauth_code_saved_reader_"),
            OAUTH_CODE + "\n        if: false",
            OAUTH_CODE + "\n        continue-on-error: true",
        ):
            with self.subTest(mutation=changed), self.assertRaises(AssertionError):
                self.assert_contract(self.workflow.replace(OAUTH_CODE, changed, 1))

    def test_oauth_code_native_identity_record_is_closed_and_uses_original_fixture_bytes(self):
        # Actual Python producer execution over original synthetic file bytes,
        # not an executable/native-capability or source-attestation claim.
        line, = [line for line in OAUTH_CODE.splitlines() if line.startswith("          python -c '")]
        code = line.removeprefix("          python -c '").removesuffix("'")
        original = b"original synthetic native identity fixture\n"
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP") if key in os.environ}
        environment.update(TERMIVAR_NATIVE_SOURCE="a" * 40, GITHUB_RUN_ID="12345", GITHUB_RUN_ATTEMPT="2")
        with tempfile.TemporaryDirectory(prefix="native-oauth-identity-", dir=ROOT) as directory:
            binary = Path(directory) / "target" / "release" / ("termivar.exe" if os.name == "nt" else "termivar")
            binary.parent.mkdir(parents=True)
            binary.write_bytes(original)
            process = subprocess.run([sys.executable, "-c", code], cwd=directory, env=environment,
                                     capture_output=True, timeout=10, check=False)
        self.assertEqual(process.returncode, 0)
        self.assertEqual(process.stderr, b"")
        document = json.loads(process.stdout)
        self.assertEqual(set(document), {"schema", "source", "run_id", "run_attempt", "host", "arch", "features",
                                         "profile", "bytes", "sha256", "assurance"})
        self.assertEqual(document["schema"], "native-oauth-executable/v1")
        self.assertEqual(document["source"], "a" * 40)
        self.assertEqual(document["run_id"], "12345")
        self.assertEqual(document["run_attempt"], "2")
        self.assertEqual(document["features"], "supplied-session-review,secret-exposure-review")
        self.assertEqual(document["profile"], "release")
        self.assertEqual(document["assurance"], "self_reported_hash_not_attestation")
        self.assertEqual(document["bytes"], len(original))
        self.assertEqual(document["sha256"], hashlib.sha256(original).hexdigest())
        self.assertIsInstance(document["host"], str)
        self.assertIsInstance(document["arch"], str)
        self.assertNotIn(directory.encode(), process.stdout)
        self.assertNotIn(original.rstrip(), process.stdout)

    def test_authorization_privacy_extension_cannot_be_omitted_or_weakened(self):
        for changed in (
            "", AUTHORIZATION_PRIVACY + "\n" + AUTHORIZATION_PRIVACY,
            AUTHORIZATION_PRIVACY.replace("        shell: bash\n", ""),
            AUTHORIZATION_PRIVACY.replace("shell: bash", "shell: pwsh"),
            AUTHORIZATION_PRIVACY.replace("set -euo pipefail", "true"),
            AUTHORIZATION_PRIVACY.replace("--release --locked", "--locked"),
            AUTHORIZATION_PRIVACY.replace("authorization-review,secret-exposure-review", "authorization-review"),
            AUTHORIZATION_PRIVACY.replace("privacy_composition::", "nonexistent_filter"),
            AUTHORIZATION_PRIVACY.replace("authorization_privacy --", "nonexistent_filter --"),
            AUTHORIZATION_PRIVACY.replace("--features reporting authorization_saved_reader_", "--features authorization-review authorization_saved_reader_"),
            AUTHORIZATION_PRIVACY + "\n        if: false",
            AUTHORIZATION_PRIVACY + "\n        continue-on-error: true",
        ):
            with self.subTest(mutation=changed):
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(AUTHORIZATION_PRIVACY, changed, 1))

    def test_rest_privacy_extension_cannot_be_omitted_or_weakened(self):
        for changed in (
            "", REST_PRIVACY + "\n" + REST_PRIVACY,
            REST_PRIVACY.replace("        shell: bash\n", ""),
            REST_PRIVACY.replace("shell: bash", "shell: pwsh"),
            REST_PRIVACY.replace("--release --locked", "--locked"),
            REST_PRIVACY.replace(
                "rest-review,secret-exposure-review,ssrf-oast-review", "rest-review"),
            REST_PRIVACY.replace("--test rest_secret_exposure_cli", "--test secret_exposure_cli"),
            REST_PRIVACY.replace("--features reporting rest_saved_reader_", "--features rest-review rest_saved_reader_"),
            REST_PRIVACY + "\n        if: false",
            REST_PRIVACY + "\n        continue-on-error: true",
        ):
            with self.subTest(mutation=changed):
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(REST_PRIVACY, changed, 1))

    def test_openapi_privacy_extension_cannot_be_omitted_or_weakened(self):
        for changed in (
            "", OPENAPI_PRIVACY + "\n" + OPENAPI_PRIVACY,
            OPENAPI_PRIVACY.replace("        shell: bash\n", ""),
            OPENAPI_PRIVACY.replace("shell: bash", "shell: pwsh"),
            OPENAPI_PRIVACY.replace("--release --locked", "--locked"),
            OPENAPI_PRIVACY.replace(
                "openapi-review,secret-exposure-review,ssrf-oast-review", "openapi-review"),
            OPENAPI_PRIVACY.replace("--test openapi_secret_exposure_cli", "--test secret_exposure_cli"),
            OPENAPI_PRIVACY.replace("--features reporting openapi_saved_reader_", "--features openapi-review openapi_saved_reader_"),
            OPENAPI_PRIVACY + "\n        if: false",
            OPENAPI_PRIVACY + "\n        continue-on-error: true",
        ):
            with self.subTest(mutation=changed):
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(OPENAPI_PRIVACY, changed, 1))

    def test_frozen_reviewed_source_is_independent_and_complete(self):
        self.assertEqual(hashlib.sha256(self.baseline.encode("utf-8")).hexdigest(),
                         BASELINE_TEXT_SHA256)
        self.assertEqual(tuple(gate.REQUIRED_JOBS), JOBS)
        expected = [name for names in PAYLOADS.values() for name in names]
        self.assertEqual(len(expected), 54)
        self.assertEqual(len(set(expected)), 54)
        self.assertEqual(set(self.original), set(expected))
        self.assertEqual([len(PAYLOADS[x]) for x in PAYLOADS], [32, 13, 9])

    def test_current_workflow_keeps_all_four_hosts_and_every_original_step(self):
        self.assert_contract(self.workflow)
        self.assert_contract(self.workflow.replace("\n", "\r\n"))

    def test_every_original_payload_omission_or_duplication_is_rejected(self):
        for name, block in self.original.items():
            with self.subTest(name=name, mutation="omission"):
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(block, "", 1))
            with self.subTest(name=name, mutation="duplication"):
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(block, block + "\n" + block, 1))

    def test_worker_and_aggregate_mutations_fail_closed(self):
        for identifier in JOBS:
            block = job_records(self.workflow)[identifier]
            mutations = (
                "", block + "\n" + block,
                block.replace("    runs-on: ${{ matrix.os }}", "    runs-on: ubuntu-latest"),
                block.replace(BUDGET, "    timeout-minutes: 121"),
                block.replace("macos-15-intel]", "]"),
                block.replace("    permissions:", "    if: false\n    permissions:", 1),
                block.replace("    permissions:", "    continue-on-error: true\n    permissions:", 1),
                block.replace("    permissions:", "    env:\n      CARGO_PROFILE_RELEASE_LTO: 'false'\n    permissions:", 1),
                block.replace("persist-credentials: false", "persist-credentials: true", 1),
                block.replace("ref: ${{ github.event.pull_request.head.sha || github.sha }}", "ref: main", 1),
            )
            for index, changed in enumerate(mutations):
                with self.subTest(job=identifier, mutation=index):
                    with self.assertRaises(AssertionError):
                        self.assert_contract(self.workflow.replace(block, changed, 1))
        for before, after in (
            ("    name: Runtime Smoke (", "    name: Runtime Smoke Renamed ("),
            ("    if: ${{ always() }}", "    if: ${{ success() }}"),
            ("platform-runtime-core, platform-runtime-reviews, platform-runtime-protocols]",
             "platform-runtime-core, platform-runtime-reviews]"),
            ("        run: python scripts/ci/native_runtime_gate.py", "        run: echo success"),
            ("TERMIVAR_NATIVE_RUNTIME_NEEDS: ${{ toJSON(needs) }}",
             "TERMIVAR_NATIVE_RUNTIME_NEEDS: '{}'"),
            (GUARD, ""),
        ):
            with self.subTest(aggregate_mutation=before):
                self.assertIn(before, self.workflow)
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(before, after, 1))

    def test_profiles_filters_guards_and_fixed_placement_cannot_drift(self):
        for before, after in (
            ("--release --locked", "--locked"),
            ("--ignored --exact --nocapture", "--exact --nocapture"),
            ("--ignored --exact --nocapture", "--ignored --nocapture"),
            ("features graphql-review,secret-exposure-review", "features secret-exposure-review"),
            ("if: runner.os == 'Windows'", "if: false"),
            ("if: runner.os == 'Linux'", "if: false"),
            ("if: always()", "if: success()"),
            ("run: cargo build --locked -p termivar-cli", "if: false\n        run: cargo build --locked -p termivar-cli"),
        ):
            with self.subTest(before=before):
                self.assertIn(before, self.workflow)
                with self.assertRaises(AssertionError):
                    self.assert_contract(self.workflow.replace(before, after, 1))
        moved = self.original["Exercise bounded XML external-entity runtime through an owned loopback fixture"]
        changed = self.workflow.replace(moved, "", 1).replace(GUARD, GUARD + "\n" + moved, 1)
        with self.assertRaises(AssertionError):
            self.assert_contract(changed)

    def test_actual_old_monolithic_workflow_fails_partition_contract(self):
        old = "name: Tests\n\njobs:\n" + self.baseline.split(
            "  platform-runtime-smoke:\n", 1
        )[0] + "  platform-runtime-smoke:\n" + self.baseline.split(
            "  platform-runtime-smoke:\n", 1
        )[1]
        with self.assertRaises(AssertionError):
            self.assert_contract(old)


class NativeRuntimeGateTests(unittest.TestCase):
    def test_literal_all_success_and_order_independence(self):
        gate.validate_needs(valid_results())
        gate.validate_needs(dict(reversed(list(valid_results().items()))))

    def test_each_non_success_and_missing_matrix_is_rejected(self):
        for job in JOBS:
            for value in ("failure", "skipped", "cancelled", "", "SUCCESS", True, 1, None):
                with self.subTest(job=job, value=value):
                    document = valid_results()
                    document[job]["result"] = value
                    with self.assertRaises(ValueError):
                        gate.validate_needs(document)
            document = valid_results()
            del document[job]
            with self.assertRaises(ValueError):
                gate.validate_needs(document)

    def test_malformed_shapes_and_fabricated_outputs_are_rejected(self):
        documents = [None, [], True, 1, "success", {}, {**valid_results(), "extra": {}}]
        for value in (None, [], "success", True, 1, {}, {"result": "success"},
                      {"result": "success", "outputs": None},
                      {"result": "success", "outputs": []},
                      {"result": "success", "outputs": {"claimed_host": "success"}},
                      {"result": "success", "outputs": {}, "continue-on-error": True}):
            document = valid_results()
            document["platform-runtime-core"] = value
            documents.append(document)
        for document in documents:
            with self.subTest(document_type=type(document).__name__):
                with self.assertRaises(ValueError):
                    gate.validate_needs(document)

    def test_duplicate_keys_constants_and_bounded_input_are_rejected(self):
        valid = json.dumps(valid_results())
        cases = (
            valid.replace('"result": "success"', '"result": "failure", "result": "success"', 1),
            valid[:-1] + ', "platform-runtime-core": {"result":"success","outputs":{}}}',
            "NaN", "Infinity", " " * 16385, "é" * 8193, None, b"{}", 1,
        )
        for raw in cases:
            with self.subTest(input_type=type(raw).__name__):
                with self.assertRaises((ValueError, UnicodeError)):
                    gate.parse_needs(raw)
        # Decoder recursion thresholds vary by Python/platform. The contract is
        # rejection of the malformed dependency shape, not a particular decoder error.
        with self.assertRaises((ValueError, RecursionError)):
            gate.validate_needs(gate.parse_needs("[" * 2000 + "]" * 2000))

    def run_gate(self, raw: str | None, *arguments: str) -> subprocess.CompletedProcess:
        environment = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
                       if key in os.environ}
        if raw is not None:
            environment["TERMIVAR_NATIVE_RUNTIME_NEEDS"] = raw
        return subprocess.run(
            [sys.executable, str(SCRIPT), *arguments], env=environment,
            capture_output=True, timeout=10, check=False,
        )

    def test_real_gate_process_success_and_failure_exits_are_value_safe(self):
        result = self.run_gate(json.dumps(valid_results()))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.replace(b"\r\n", b"\n"),
                         b"native runtime gate: all three native matrices succeeded\n")
        self.assertEqual(result.stderr, b"")
        cases = [None, "not-json-private-canary", "{}", "true", "[" * 2000 + "]" * 2000]
        for job in JOBS:
            for status in ("failure", "skipped", "cancelled"):
                document = valid_results()
                document[job]["result"] = status
                cases.append(json.dumps(document))
        for raw in cases:
            with self.subTest(raw_type=type(raw).__name__):
                result = self.run_gate(raw)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr.replace(b"\r\n", b"\n"),
                                 b"native runtime gate: incomplete or invalid dependencies\n")
                self.assertNotIn(b"private-canary", result.stderr)
        self.assertEqual(self.run_gate(json.dumps(valid_results()), "--ignore").returncode, 1)


if __name__ == "__main__":
    unittest.main()
