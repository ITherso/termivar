"""Original stdlib-only checks for the owned fixture's closed phase diagnostics.

Direct helper tests use explicitly mocked runtime/streams. Actual-script tests
require CPython 3.12 and run the original safe Expat path in a bounded child;
they are not product/CMS execution or a reproduction of the historic timeout.
"""
from __future__ import annotations

import argparse
import base64
import builtins
import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import runpy
import subprocess
import sys
import unittest
from unittest import mock


SCRIPT = (Path(__file__).resolve().parents[2] / "crates/termivar-cli/tests/fixtures/xml_expat_owned_https.py")
SPEC = importlib.util.spec_from_file_location("owned_expat_fixture", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

# Independent literal wire oracle, never assembled from helper constants.
PHASES = (
    b"owned_https_parser_phase stage=started\n",
    b"owned_https_parser_phase stage=input_read\n",
    b"owned_https_parser_phase stage=input_complete\n",
    b"owned_https_parser_phase stage=parse_complete\n",
    b"owned_https_parser_phase stage=result_written\n",
)
RESULT = b'{"external_entity_count":0,"mode":"safe","runtime":"cpython-3.12","schema":"termivar-test.xml-expat-result/v1"}\n'
CANARY = "ORIGINAL_SYNTHETIC_XML_VALUE_MUST_NOT_APPEAR_7D4A2B"
XML = b"<root>" + CANARY.encode() + b"</root>"
CPYTHON_312 = sys.implementation.name == "cpython" and sys.version_info[:2] == (3, 12)


class BinarySink(io.BytesIO):
    def __init__(self, role, events, *, fail_write=False, fail_flush=False, short_write=False):
        super().__init__()
        self.role = role
        self.events = events
        self.fail_write = fail_write
        self.fail_flush = fail_flush
        self.short_write = short_write

    def write(self, value):
        self.events.append((self.role + ".write", value))
        if self.fail_write:
            raise OSError(CANARY)
        if self.short_write:
            return super().write(value[:-1])
        return super().write(value)

    def flush(self):
        self.events.append((self.role + ".flush", None))
        if self.fail_flush:
            raise OSError(CANARY)
        return super().flush()


class BinaryInput(io.BytesIO):
    def __init__(self, value, events):
        super().__init__(value)
        self.events = events

    def read(self, size=-1):
        self.events.append(("stdin.read", size))
        return super().read(size)


class TextFacade:
    """Explicit synthetic standard stream with a binary buffer."""
    def __init__(self, buffer):
        self.buffer = buffer

    def write(self, value):
        self.buffer.write(value.encode("utf-8"))
        return len(value)

    def flush(self):
        self.buffer.flush()


class OwnedExpatPhaseTests(unittest.TestCase):
    def streams(self, stack, *, output_options=None, error_options=None):
        events = []
        output = BinarySink("stdout", events, **(output_options or {}))
        errors = BinarySink("stderr", events, **(error_options or {}))
        stack.enter_context(mock.patch.object(helper.sys, "stdin", TextFacade(BinaryInput(XML, events))))
        stack.enter_context(mock.patch.object(helper.sys, "stdout", TextFacade(output)))
        stack.enter_context(mock.patch.object(helper.sys, "stderr", TextFacade(errors)))
        # Mocked unit context only: actual-process tests do not rewrite runtime.
        stack.enter_context(mock.patch.object(helper.sys, "version_info", (3, 12, 14)))
        stack.enter_context(mock.patch.object(helper, "_arguments", return_value=argparse.Namespace(mode="safe", provider_port=443)))
        return events, output, errors

    def test_module_import_is_silent_and_never_opens_a_network_connection(self):
        output, errors = io.StringIO(), io.StringIO()
        spec = importlib.util.spec_from_file_location("independent_silent_fixture", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), mock.patch("socket.create_connection", side_effect=AssertionError("no network")) as network:
            spec.loader.exec_module(module)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
        network.assert_not_called()

    def test_script_started_marker_precedes_the_first_other_stdlib_import(self):
        events = []
        errors = BinarySink("stderr", events)
        output = BinarySink("stdout", events)
        original_import = builtins.__import__

        def stop_before_argparse(name, *args, **kwargs):
            if name == "argparse":
                self.assertEqual(errors.getvalue(), PHASES[0])
                raise ImportError("synthetic_import_stop")
            return original_import(name, *args, **kwargs)

        with mock.patch.object(sys, "stderr", TextFacade(errors)), mock.patch.object(sys, "stdout", TextFacade(output)), mock.patch("builtins.__import__", side_effect=stop_before_argparse):
            with self.assertRaisesRegex(ImportError, "^synthetic_import_stop$"):
                runpy.run_path(str(SCRIPT), run_name="__main__")
        self.assertEqual(output.getvalue(), b"")
        self.assertEqual(errors.getvalue(), PHASES[0])
        self.assertEqual(events, [("stderr.write", PHASES[0]), ("stderr.flush", None)])

    def test_main_phase_order_surrounds_actual_read_parse_write_and_flush(self):
        with contextlib.ExitStack() as stack:
            events, output, errors = self.streams(stack)
            original_parse = helper._parse

            def actual_parse(*args):
                events.append(("parse.enter", None))
                result = original_parse(*args)
                events.append(("parse.return", None))
                return result

            stack.enter_context(mock.patch.object(helper, "_parse", side_effect=actual_parse))
            self.assertEqual(helper._main(), 0)
        self.assertEqual(output.getvalue(), RESULT)
        # _main itself never emits started; only the script-entry branch does.
        self.assertEqual(errors.getvalue(), b"".join(PHASES[1:]))
        self.assertEqual(events, [
            ("stderr.write", PHASES[1]), ("stderr.flush", None),
            ("stdin.read", 98305),
            ("stderr.write", PHASES[2]), ("stderr.flush", None),
            ("parse.enter", None), ("parse.return", None),
            ("stderr.write", PHASES[3]), ("stderr.flush", None),
            ("stdout.write", RESULT), ("stdout.flush", None),
            ("stderr.write", PHASES[4]), ("stderr.flush", None),
        ])
        self.assertNotIn(CANARY.encode(), output.getvalue() + errors.getvalue())

    def test_runtime_and_arguments_are_validated_before_input_read_marker(self):
        for failure in ("runtime", "arguments"):
            with self.subTest(failure=failure), contextlib.ExitStack() as stack:
                _, output, errors = self.streams(stack)
                read = stack.enter_context(mock.patch.object(helper, "_read_xml"))
                if failure == "runtime":
                    stack.enter_context(mock.patch.object(helper.sys, "version_info", (3, 13)))
                else:
                    stack.enter_context(mock.patch.object(helper, "_arguments", side_effect=helper.OracleError("provider_port")))
                with self.assertRaises(helper.OracleError):
                    helper._main()
                read.assert_not_called()
                self.assertEqual(output.getvalue(), b"")
                self.assertEqual(errors.getvalue(), b"")

    def test_each_failed_phase_retains_only_its_completed_prefix(self):
        for failure, completed in (("read", 1), ("parse", 2), ("result_bound", 3), ("write", 3), ("short_write", 3), ("flush", 3)):
            with self.subTest(failure=failure), contextlib.ExitStack() as stack:
                options = {"fail_write": failure == "write", "short_write": failure == "short_write", "fail_flush": failure == "flush"}
                _, output, errors = self.streams(stack, output_options=options)
                if failure == "read":
                    stack.enter_context(mock.patch.object(helper, "_read_xml", side_effect=OSError(CANARY)))
                elif failure == "parse":
                    stack.enter_context(mock.patch.object(helper, "_parse", side_effect=OSError(CANARY)))
                elif failure == "result_bound":
                    stack.enter_context(mock.patch.object(helper.json, "dumps", return_value=CANARY * 40))
                with self.assertRaises((OSError, helper.OracleError)):
                    helper._main()
                self.assertEqual(errors.getvalue(), b"".join(PHASES[1:1 + completed]))
                self.assertNotIn(PHASES[4], errors.getvalue())
                self.assertNotIn(CANARY.encode(), output.getvalue() + errors.getvalue())
                if failure in {"read", "parse", "result_bound", "write"}:
                    self.assertEqual(output.getvalue(), b"")
                if failure == "flush":
                    self.assertEqual(output.getvalue(), RESULT)

    def test_phase_diagnostic_write_flush_and_short_write_fail_closed(self):
        for option in ("fail_write", "fail_flush", "short_write"):
            with self.subTest(option=option), contextlib.ExitStack() as stack:
                _, output, errors = self.streams(stack, error_options={option: True})
                parse = stack.enter_context(mock.patch.object(helper, "_parse"))
                with self.assertRaises(OSError):
                    helper._main()
                parse.assert_not_called()
                self.assertEqual(output.getvalue(), b"")
                self.assertNotIn(CANARY.encode(), errors.getvalue())

    def test_unknown_phase_never_reflects_the_requested_value(self):
        with contextlib.ExitStack() as stack:
            _, output, errors = self.streams(stack)
            with self.assertRaisesRegex(ValueError, "^phase$"):
                helper._emit_phase(CANARY)
        self.assertEqual(output.getvalue(), b"")
        self.assertEqual(errors.getvalue(), b"")

    def test_safe_expat_path_ignores_external_entity_without_network(self):
        document = b'<!DOCTYPE root [<!ENTITY ignored SYSTEM "https://outside.invalid/original">]><root>&ignored;</root>'
        with mock.patch.object(helper.socket, "create_connection", side_effect=AssertionError("no network")) as network, mock.patch.object(helper.socket.socket, "connect", side_effect=AssertionError("no network")) as connect:
            self.assertEqual(helper._parse(document, "safe", 443), 0)
        network.assert_not_called()
        connect.assert_not_called()

    def test_existing_caps_and_test_root_are_unchanged(self):
        self.assertEqual(helper.MAX_XML_BYTES, 98304)
        self.assertEqual(helper.MAX_PROVIDER_RESPONSE_BYTES, 16384)
        root = base64.b64decode(helper.ROOT_CERTIFICATE_DER_BASE64, validate=True)
        self.assertEqual(hashlib.sha256(root).hexdigest(), "8a838ab89d539252df6bafc16eb489aebb42cbd350b941f3d708fecc7041d409")
        self.assertEqual(helper.PROVIDER_ADDRESS, "::1")
        self.assertEqual(helper.PROVIDER_HOST, "oast-provider.termivar.test")
        self.assertEqual(helper.RESULT_SCHEMA, "termivar-test.xml-expat-result/v1")

    @unittest.skipUnless(CPYTHON_312, "actual-script contract requires CPython 3.12")
    def test_actual_script_success_has_exact_five_lf_lines_and_original_json(self):
        result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--mode", "safe", "--provider-port", "443"], input=XML, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, RESULT)
        self.assertEqual(result.stderr, b"".join(PHASES))
        self.assertNotIn(b"\r", result.stderr)
        self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)

    @unittest.skipUnless(CPYTHON_312, "actual-script contract requires CPython 3.12")
    def test_actual_safe_script_cannot_open_a_network_connection(self):
        guard = """import runpy,socket,sys
def forbidden(*args,**kwargs):
    raise AssertionError('network_forbidden')
socket.create_connection=forbidden
socket.socket.connect=forbidden
script=sys.argv[1]
sys.argv=[script,'--mode','safe','--provider-port','443']
runpy.run_path(script,run_name='__main__')
"""
        document = b'<!DOCTYPE root [<!ENTITY ignored SYSTEM "https://outside.invalid/original">]><root>&ignored;</root>'
        result = subprocess.run([sys.executable, "-I", "-c", guard, str(SCRIPT)], input=document, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, RESULT)
        self.assertEqual(result.stderr, b"".join(PHASES))

    @unittest.skipUnless(CPYTHON_312, "actual-script contract requires CPython 3.12")
    def test_actual_script_error_keeps_prefix_nonzero_exit_and_private_input(self):
        for document, prefix, code in ((b"", PHASES[:2], b"xml_empty"), (b"x" * 98305, PHASES[:2], b"xml_bound"), (b"<root>" + CANARY.encode(), PHASES[:3], b"parser_or_transport")):
            with self.subTest(code=code):
                result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--mode", "safe", "--provider-port", "443"], input=document, capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertTrue(result.stderr.startswith(b"".join(prefix)))
                self.assertEqual(result.stderr[len(b"".join(prefix)):].splitlines(), [b"xml_expat_oracle:" + code])
                self.assertNotIn(CANARY.encode(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
