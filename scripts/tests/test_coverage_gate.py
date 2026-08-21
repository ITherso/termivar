"""Regression tests for the standard-library coverage policy checker."""

from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "coverage_gate.py"
SPEC = importlib.util.spec_from_file_location("coverage_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


def cobertura(classes: list[tuple[str, list[tuple[int, int]]]]) -> str:
    rendered = []
    for filename, lines in classes:
        rendered_lines = "".join(
            f'<line number="{number}" hits="{hits}" />' for number, hits in lines
        )
        rendered.append(
            f'<class filename="{filename}"><lines>{rendered_lines}</lines></class>'
        )
    return "<coverage><packages><package><classes>" + "".join(rendered) + (
        "</classes></package></packages></coverage>"
    )


def valid_record() -> dict:
    commit = "a" * 40
    return {
        "schema": gate.SCHEMA,
        "source": {"commit": commit, "cargo_lock_sha256": "b" * 64},
        "tooling": {
            "rust": gate.RUST_TOOLCHAIN,
            "rust_components": gate.RUST_COMPONENTS,
            "installer_rust": gate.INSTALLER_RUST_TOOLCHAIN,
            "tarpaulin": gate.TARPAULIN_VERSION,
            "engine": gate.COVERAGE_ENGINE,
            "runner_target": gate.RUNNER_TARGET,
            "command": gate.TARPAULIN_COMMAND,
            "timeout_seconds": gate.TIMEOUT_SECONDS,
        },
        "scope": {
            "includes": gate.SCOPE_INCLUDES,
            "excludes": gate.SCOPE_EXCLUDES,
        },
        "coverage": {
            "covered_lines": 3,
            "coverable_lines": 4,
            "line_state_sha256": "d" * 64,
            "files": [
                {
                    "path": "crates/demo/src/lib.rs",
                    "covered_lines": 3,
                    "coverable_lines": 4,
                }
            ],
            "omitted_in_scope_files": list(gate.INITIAL_CALIBRATION_OMISSIONS),
        },
        "cobertura": {"path": "cobertura.xml", "sha256": "c" * 64},
        "provenance": {
            "repository": gate.CANONICAL_REPOSITORY,
            "run_id": "123",
            "run_attempt": "1",
            "artifact_name": gate.DEFAULT_ARTIFACT_NAME,
            "artifact_url": (
                f"https://github.com/{gate.CANONICAL_REPOSITORY}/actions/runs/123"
            ),
        },
        "patch": None,
        "evaluation": {
            "mode": "calibration",
            "status": "passed",
            "baseline_record": None,
            "total": "measured; no accepted numeric floor",
            "patch": "not applicable",
        },
    }


class ScopeTests(unittest.TestCase):
    def test_initial_calibration_omission_inventory_is_exact(self) -> None:
        self.assertEqual(
            gate.INITIAL_CALIBRATION_OMISSIONS,
            [
                "crates/venom-core/src/lib.rs",
                "crates/venom-core/src/models.rs",
                "crates/venom-scanner/src/adaptive/mod.rs",
                "crates/venom-scanner/src/contracts.rs",
                "crates/venom-scanner/src/defense/mod.rs",
                "crates/venom-scanner/src/lib.rs",
                "crates/venom-scanner/src/phases/mod.rs",
                "crates/venom-scanner/src/semantic.rs",
                "crates/venom-scanner/src/web_runtime/api_visibility/tests.rs",
            ],
        )

    def test_scope_is_exact_and_rejects_path_escape(self) -> None:
        self.assertTrue(gate.in_scope("crates/venom-core/src/lib.rs"))
        self.assertTrue(gate.in_scope("xtask/src/architecture/workflows.rs"))
        self.assertFalse(gate.in_scope("crates/venom-core/tests/integration.rs"))
        self.assertFalse(gate.in_scope("examples/src/lib.rs"))
        self.assertFalse(gate.in_scope("crates/demo/src/../../escape.rs"))
        self.assertFalse(gate.in_scope("crates/demo/src/./lib.rs"))
        self.assertFalse(gate.in_scope("crates/demo/src//lib.rs"))
        self.assertFalse(gate.in_scope("/crates/demo/src/lib.rs"))
        self.assertFalse(gate.in_scope("crates\\demo\\src\\lib.rs"))
        self.assertFalse(
            gate.in_scope("crates/venom-scanner/tests/performance_tests.rs")
        )

    def test_workspace_outputs_cannot_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(gate.GateError):
                gate._workspace_path(root, "../summary.json", "summary")
            with self.assertRaises(gate.GateError):
                gate._workspace_path(root, "/tmp/summary.json", "summary")


class InstrumentationExclusionTests(unittest.TestCase):
    def test_comments_literals_lifetimes_and_non_tokens_are_ignored(self) -> None:
        source = r'''
// cfg(not(tarpaulin_include)) and #[coverage(off)] and #[no_coverage]
/* outer tarpaulin /* nested coverage(off) */ no_coverage */
const NORMAL: &str = "cfg(not(tarpaulin)) #[coverage(off)]";
const BYTE: &[u8] = b"tarpaulin_include coverage(off) no_coverage";
const RAW: &str = r###"tarpaulin coverage(off) no_coverage"###;
const BYTE_RAW: &[u8] = br#"tarpaulin"#;
const C_STRING: &CStr = c"tarpaulin coverage(off) no_coverage";
const C_RAW: &CStr = cr##"tarpaulin coverage(off) no_coverage"##;
const QUOTE: char = '"';
const APOSTROPHE: char = '\'';
fn borrow<'a>(value: &'a str) -> &'a str { value }
const TARPAULIN: &str = "upper-case identifier";
let cargo_tarpaulin_label = 1;
let no_coverage = false;
coverage(no_coverage);
'''
        self.assertEqual(gate._instrumentation_exclusions(source), [])

        workspace = SCRIPT.parents[1] / "xtask" / "src" / "architecture" / "workflows.rs"
        self.assertEqual(
            gate._instrumentation_exclusions(workspace.read_text(encoding="utf-8")),
            [],
        )

    def test_cfg_and_coverage_attributes_are_rejected_across_whitespace(self) -> None:
        fixtures = {
            "crate cfg": "#![cfg(not(tarpaulin))]\n",
            "comment-separated cfg": "#[cfg(not(/* intentional gap */ tarpaulin))]\n",
            "cfg attr": "#[cfg_attr(any(unix, r#tarpaulin), allow(dead_code))]\n",
            "tarpaulin include": "#[cfg(not(tarpaulin_include))]\n",
            "raw tarpaulin include": "#[cfg(not(r#tarpaulin_include))]\n",
            "coverage off": "#[coverage /* gap */ ( /* gap */ off )]\n",
            "raw coverage off": "#[r#coverage(r#off)]\n",
            "no coverage": "#[no_coverage]\n",
            "raw no coverage": "#[cfg_attr(test, r#no_coverage)]\n",
            "exact token": "let tarpaulin = false;\n",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name):
                findings = gate._instrumentation_exclusions(source)
                self.assertTrue(findings)
                self.assertEqual(findings[0][0], 1)

    def test_malformed_lexical_constructs_fail_closed(self) -> None:
        fixtures = {
            "normal string": 'const VALUE: &str = "unterminated',
            "raw string": 'const VALUE: &str = r##"unterminated"#;',
            "nested block comment": "/* outer /* inner */",
            "attribute": "#[cfg_attr(test, coverage(off))",
        }
        for name, source in fixtures.items():
            with self.subTest(name=name), self.assertRaises(gate.GateError):
                gate._instrumentation_exclusions(source)

    def test_only_tracked_in_scope_head_blobs_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "coverage@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Coverage Test"],
                cwd=root,
                check=True,
            )
            source = root / "crates" / "demo" / "src"
            tests = root / "crates" / "demo" / "tests"
            source.mkdir(parents=True)
            tests.mkdir(parents=True)
            source_file = source / "lib.rs"
            source_file.write_text("pub fn demo() {}\n", encoding="utf-8")
            (tests / "performance.rs").write_text(
                "#![cfg(not(tarpaulin))]\n", encoding="utf-8"
            )
            subprocess.run(["git", "add", "crates"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "fixture"], cwd=root, check=True
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            tracked = gate._tracked_sources_at(root, head)
            self.assertEqual(tracked, ["crates/demo/src/lib.rs"])
            gate._reject_instrumentation_exclusions(root, head, tracked)

            source_file.write_text(
                "#![cfg(not(/* hidden */ tarpaulin))]\npub fn demo() {}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "crates"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "-q", "-m", "hide production"],
                cwd=root,
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            with self.assertRaisesRegex(
                gate.GateError, r"crates/demo/src/lib\.rs:1.*tarpaulin"
            ):
                gate._reject_instrumentation_exclusions(
                    root, head, gate._tracked_sources_at(root, head)
                )


class CoberturaTests(unittest.TestCase):
    def test_normalized_line_state_digest_is_order_and_hit_count_independent(self) -> None:
        tracked = ["crates/demo/src/lib.rs", "xtask/src/main.rs"]
        first, _ = gate._coverage_measurement(
            {
                "xtask/src/main.rs": {3: 0},
                "crates/demo/src/lib.rs": {2: 0, 1: 7},
            },
            tracked,
        )
        equivalent, _ = gate._coverage_measurement(
            {
                "crates/demo/src/lib.rs": {1: 1, 2: 0},
                "xtask/src/main.rs": {3: 0},
            },
            list(reversed(tracked)),
        )
        swapped, _ = gate._coverage_measurement(
            {
                "crates/demo/src/lib.rs": {1: 0, 2: 1},
                "xtask/src/main.rs": {3: 0},
            },
            tracked,
        )
        different_line_set, _ = gate._coverage_measurement(
            {
                "crates/demo/src/lib.rs": {1: 7, 4: 0},
                "xtask/src/main.rs": {3: 0},
            },
            tracked,
        )
        different_path, _ = gate._coverage_measurement(
            {
                "crates/demo/src/lib.rs": {1: 7, 2: 0},
                "xtask/src/lib.rs": {3: 0},
            },
            ["crates/demo/src/lib.rs", "xtask/src/lib.rs"],
        )

        self.assertEqual(first["line_state_sha256"], equivalent["line_state_sha256"])
        self.assertEqual(
            first["line_state_sha256"],
            "88b2bb736ed4dbc91d2701f66386150bcb37c1f019657a41ce984c44534a06b7",
        )
        self.assertEqual(first["files"], equivalent["files"])
        self.assertNotEqual(first["line_state_sha256"], swapped["line_state_sha256"])
        self.assertEqual(first["files"], swapped["files"])
        self.assertNotEqual(first["line_state_sha256"], different_line_set["line_state_sha256"])
        self.assertNotEqual(first["line_state_sha256"], different_path["line_state_sha256"])

    def test_parser_counts_unique_lines_and_ignores_out_of_scope_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates" / "demo" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("one\ntwo\n", encoding="utf-8")
            report = root / "cobertura.xml"
            report.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>'
                + cobertura(
                    [
                        ("crates/demo/src/lib.rs", [(1, 2), (2, 0)]),
                        ("crates/demo/tests/no.rs", [(1, 9)]),
                    ]
                ),
                encoding="utf-8",
            )
            parsed = gate.parse_cobertura(report.read_bytes(), root)
            self.assertEqual(parsed, {"crates/demo/src/lib.rs": {1: 2, 2: 0}})

    def test_parser_rejects_duplicate_files_lines_and_escaping_paths(self) -> None:
        fixtures = [
            cobertura(
                [
                    ("crates/demo/src/lib.rs", [(1, 1)]),
                    ("crates/demo/src/lib.rs", [(2, 1)]),
                ]
            ),
            cobertura([("crates/demo/src/lib.rs", [(1, 1), (1, 0)])]),
            cobertura([("../crates/demo/src/lib.rs", [(1, 1)])]),
        ]
        for contents in fixtures:
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                report = root / "cobertura.xml"
                report.write_text(contents, encoding="utf-8")
                with self.assertRaises(gate.GateError):
                    gate.parse_cobertura(report.read_bytes(), root)

    def test_parser_rejects_zero_in_scope_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "cobertura.xml"
            report.write_text(cobertura([("tests/example.rs", [(1, 1)])]), encoding="utf-8")
            with self.assertRaises(gate.GateError):
                gate.parse_cobertura(report.read_bytes(), root)

    def test_parser_rejects_dtd_and_entity_declarations(self) -> None:
        declarations = [
            '<!DOCTYPE coverage [<!ENTITY x "unsafe">]><coverage />',
            '<!doctype coverage [<!entity x "unsafe">]><coverage />',
            '<!DoCtYpE coverage [<!EnTiTy x "unsafe">]><coverage />',
        ]
        for contents in declarations:
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                report = root / "cobertura.xml"
                report.write_text(contents, encoding="utf-8")
                with self.assertRaisesRegex(gate.GateError, "DTD and entity"):
                    gate.parse_cobertura(report.read_bytes(), root)

    def test_reader_uses_one_bounded_read_and_rejects_the_extra_byte(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "cobertura.xml"
            opened = mock.MagicMock()
            opened.__enter__.return_value.read.return_value = b"x" * 9
            with mock.patch.object(gate, "MAX_COBERTURA_BYTES", 8), mock.patch.object(
                Path, "open", return_value=opened
            ) as path_open:
                with self.assertRaisesRegex(gate.GateError, "256 MiB"):
                    gate._read_cobertura(report)
                path_open.assert_called_once_with("rb")
                opened.__enter__.return_value.read.assert_called_once_with(9)
                with self.assertRaisesRegex(gate.GateError, "256 MiB"):
                    gate.parse_cobertura(b"x" * 9, Path(directory))

    def test_parser_rejects_utf16_and_utf32_documents_before_xml_parsing(self) -> None:
        source = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            '<!DOCTYPE coverage [<!ENTITY x "unsafe">]><coverage />'
        )
        for encoding in ("utf-16", "utf-16-le", "utf-32", "utf-32-le"):
            with self.subTest(encoding=encoding), self.assertRaisesRegex(
                gate.GateError, "strict UTF-8"
            ):
                gate.parse_cobertura(source.encode(encoding), Path.cwd())

    def test_parser_rejects_non_utf8_xml_declaration(self) -> None:
        contents = b'<?xml version="1.0" encoding="UTF-16"?><coverage />'
        with self.assertRaisesRegex(gate.GateError, "must specify UTF-8"):
            gate.parse_cobertura(contents, Path.cwd())

    def test_parser_rejects_legacy_encoded_bytes_before_element_tree(self) -> None:
        contents = (
            b'<?xml version="1.0" encoding="ISO-8859-1"?>'
            b'<coverage><!-- \xe9 --></coverage>'
        )
        with self.assertRaisesRegex(gate.GateError, "strict UTF-8"):
            gate.parse_cobertura(contents, Path.cwd())

    def test_parser_uses_class_level_lines_not_duplicate_method_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates" / "demo" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("one\n", encoding="utf-8")
            report = root / "cobertura.xml"
            report.write_text(
                "<coverage><packages><package><classes>"
                '<class filename="crates/demo/src/lib.rs">'
                '<methods><method><lines><line number="1" hits="1" /></lines></method></methods>'
                '<lines><line number="1" hits="1" /></lines>'
                "</class></classes></package></packages></coverage>",
                encoding="utf-8",
            )
            self.assertEqual(
                gate.parse_cobertura(report.read_bytes(), root),
                {"crates/demo/src/lib.rs": {1: 1}},
            )

    def test_zero_line_class_is_omitted_instead_of_counting_as_present(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates" / "demo" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("one\n", encoding="utf-8")
            (source / "empty.rs").write_text("// no coverable lines\n", encoding="utf-8")
            report = root / "cobertura.xml"
            report.write_text(
                cobertura(
                    [
                        ("crates/demo/src/lib.rs", [(1, 1)]),
                        ("crates/demo/src/empty.rs", []),
                    ]
                ),
                encoding="utf-8",
            )
            parsed = gate.parse_cobertura(report.read_bytes(), root)
            self.assertEqual(parsed, {"crates/demo/src/lib.rs": {1: 1}})
            _, missing = gate._patch_measurement(
                parsed,
                ["crates/demo/src/empty.rs"],
                {"crates/demo/src/empty.rs": set()},
            )
            self.assertEqual(missing, ["crates/demo/src/empty.rs"])


class DiffTests(unittest.TestCase):
    def test_zero_context_hunks_measure_only_new_side_ranges(self) -> None:
        parsed = gate.parse_unified_diff(
            "diff --git a/crates/demo/src/lib.rs b/crates/demo/src/lib.rs\n"
            "--- a/crates/demo/src/lib.rs\n"
            "+++ b/crates/demo/src/lib.rs\n"
            "@@ -2 +2,2 @@\n"
            "-old\n"
            "+new\n"
            "+more\n"
            "@@ -9,0 +11 @@\n"
            "+last\n"
        )
        self.assertEqual(parsed, {"crates/demo/src/lib.rs": {2, 3, 11}})

    def test_deleted_and_out_of_scope_files_do_not_create_patch_lines(self) -> None:
        parsed = gate.parse_unified_diff(
            "diff --git a/crates/demo/src/deleted.rs b/crates/demo/src/deleted.rs\n"
            "--- a/crates/demo/src/deleted.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n"
            "diff --git a/crates/demo/tests/test.rs b/crates/demo/tests/test.rs\n"
            "--- /dev/null\n+++ b/crates/demo/tests/test.rs\n@@ -0,0 +1 @@\n+test\n"
        )
        self.assertEqual(parsed, {})

    def test_unsafe_path_and_malformed_hunk_fail_closed(self) -> None:
        with self.assertRaises(gate.GateError):
            gate.parse_unified_diff(
                "diff --git a/x b/x\n--- /dev/null\n"
                "+++ b/../crates/demo/src/lib.rs\n@@ -0,0 +1 @@\n+x\n"
            )
        with self.assertRaises(gate.GateError):
            gate.parse_unified_diff(
                "diff --git a/crates/demo/src/lib.rs b/crates/demo/src/lib.rs\n"
                "--- a/crates/demo/src/lib.rs\n+++ b/crates/demo/src/lib.rs\n"
                "@@ malformed @@\n+x\n"
            )

    def test_hunk_content_that_looks_like_new_file_header_cannot_redirect_accounting(self) -> None:
        parsed = gate.parse_unified_diff(
            "diff --git a/crates/demo/src/lib.rs b/crates/demo/src/lib.rs\n"
            "--- a/crates/demo/src/lib.rs\n"
            "+++ b/crates/demo/src/lib.rs\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+++ /dev/null\n"
            "@@ -5 +5 @@\n"
            "-old-again\n"
            "+new-again\n"
        )
        self.assertEqual(parsed, {"crates/demo/src/lib.rs": {1, 5}})


class RatioAndEvaluationTests(unittest.TestCase):
    def test_ratio_comparison_uses_exact_integer_math(self) -> None:
        huge = 10**30
        self.assertTrue(gate.ratio_at_least(2 * huge, 3 * huge, 2, 3))
        self.assertFalse(gate.ratio_at_least(2 * huge - 1, 3 * huge, 2, 3))
        with self.assertRaises(gate.GateError):
            gate.ratio_at_least(0, 0, 1, 2)

    def test_patch_zero_denominator_is_explicitly_not_applicable(self) -> None:
        baseline = ("docs/reports/coverage/aaaaaaa.json", valid_record())
        coverage = copy.deepcopy(valid_record()["coverage"])
        patch = {"covered_lines": 0, "coverable_lines": 0, "files": []}
        violations, evaluation = gate._evaluation_violations(
            coverage, patch, [], baseline, baseline, False
        )
        self.assertEqual(violations, [])
        self.assertEqual(
            evaluation["patch"],
            "not applicable (zero observed coverable changed lines)",
        )

    def test_patch_and_candidate_baseline_must_not_fall_below_floor(self) -> None:
        base = valid_record()
        candidate = copy.deepcopy(base)
        candidate["coverage"]["covered_lines"] = 2
        candidate["coverage"]["files"][0]["covered_lines"] = 2
        coverage = copy.deepcopy(base["coverage"])
        patch = {"covered_lines": 0, "coverable_lines": 2, "files": []}
        violations, _ = gate._evaluation_violations(
            coverage,
            patch,
            [],
            ("docs/reports/coverage/bbbbbbb.json", candidate),
            ("docs/reports/coverage/aaaaaaa.json", base),
            False,
        )
        self.assertTrue(any("candidate accepted baseline lowers" in item for item in violations))
        self.assertTrue(any("patch coverage" in item for item in violations))

    def test_calibration_accepts_an_explicit_changed_omission(self) -> None:
        coverage = copy.deepcopy(valid_record()["coverage"])
        violations, evaluation = gate._evaluation_violations(
            coverage, None, ["crates/venom-core/src/lib.rs"], None, None, True
        )
        self.assertEqual(violations, [])
        self.assertEqual(evaluation["status"], "passed")

    def test_calibration_requires_the_exact_reviewed_bootstrap_omissions(self) -> None:
        fixtures = []
        missing = copy.deepcopy(valid_record()["coverage"])
        missing["omitted_in_scope_files"].pop()
        fixtures.append(missing)
        added = copy.deepcopy(valid_record()["coverage"])
        added["omitted_in_scope_files"] = sorted(
            [*added["omitted_in_scope_files"], "xtask/src/unreviewed.rs"]
        )
        fixtures.append(added)
        for coverage in fixtures:
            with self.subTest(coverage=coverage):
                violations, evaluation = gate._evaluation_violations(
                    coverage, None, [], None, None, True
                )
                self.assertTrue(
                    any("reviewed bootstrap inventory" in item for item in violations)
                )
                self.assertEqual(evaluation["status"], "failed")

    def test_missing_changed_file_must_match_the_current_omission_inventory(self) -> None:
        coverage = copy.deepcopy(valid_record()["coverage"])
        violations, evaluation = gate._evaluation_violations(
            coverage, None, ["xtask/src/not-omitted.rs"], None, None, True
        )
        self.assertTrue(
            any("not in the current omission inventory" in item for item in violations)
        )
        self.assertEqual(evaluation["status"], "failed")

    def test_first_candidate_freezes_its_exact_changed_omission_inventory(self) -> None:
        candidate = valid_record()
        coverage = copy.deepcopy(candidate["coverage"])
        violations, evaluation = gate._evaluation_violations(
            coverage,
            None,
            ["crates/venom-core/src/lib.rs"],
            ("docs/reports/coverage/aaaaaaa.json", candidate),
            None,
            False,
        )
        self.assertEqual(violations, [])
        self.assertEqual(evaluation["status"], "passed")

        incomplete = copy.deepcopy(candidate)
        incomplete["coverage"]["omitted_in_scope_files"].pop()
        violations, evaluation = gate._evaluation_violations(
            copy.deepcopy(incomplete["coverage"]),
            None,
            [],
            ("docs/reports/coverage/aaaaaaa.json", incomplete),
            None,
            False,
        )
        self.assertTrue(any("first accepted baseline" in item for item in violations))
        self.assertEqual(evaluation["status"], "failed")

    def test_evaluation_allows_a_known_omission_after_blob_precheck(self) -> None:
        baseline = valid_record()
        accepted = ("docs/reports/coverage/aaaaaaa.json", baseline)
        patch = {
            "covered_lines": 0,
            "coverable_lines": 0,
            "changed_in_scope_files": ["crates/venom-core/src/lib.rs"],
            "files": [
                {
                    "path": "crates/venom-core/src/lib.rs",
                    "covered_lines": 0,
                    "coverable_lines": 0,
                    "changed_lines": 2,
                }
            ],
        }
        violations, evaluation = gate._evaluation_violations(
            copy.deepcopy(baseline["coverage"]),
            patch,
            ["crates/venom-core/src/lib.rs"],
            accepted,
            accepted,
            False,
        )
        self.assertEqual(violations, [])
        self.assertEqual(evaluation["status"], "passed")
        self.assertEqual(
            evaluation["patch"],
            "not applicable (zero observed coverable changed lines)",
        )

    def test_calibration_is_rejected_after_baseline_acceptance(self) -> None:
        baseline = ("docs/reports/coverage/aaaaaaa.json", valid_record())
        violations, _ = gate._evaluation_violations(
            copy.deepcopy(valid_record()["coverage"]), None, [], baseline, None, True
        )
        self.assertTrue(any("calibration mode is forbidden" in item for item in violations))

    def test_new_omission_cannot_silently_improve_aggregate_ratio(self) -> None:
        baseline = valid_record()
        current = copy.deepcopy(baseline["coverage"])
        current["omitted_in_scope_files"] = sorted(
            [*baseline["coverage"]["omitted_in_scope_files"], "xtask/src/new.rs"]
        )
        violations, _ = gate._evaluation_violations(
            current,
            None,
            ["xtask/src/new.rs"],
            ("docs/reports/coverage/aaaaaaa.json", baseline),
            ("docs/reports/coverage/aaaaaaa.json", baseline),
            False,
        )
        self.assertTrue(any("new in-scope files" in item for item in violations))
        self.assertTrue(
            any("outside the accepted omission inventory" in item for item in violations)
        )

    def test_previously_measured_changed_file_cannot_become_an_omission(self) -> None:
        baseline = valid_record()
        current = copy.deepcopy(baseline["coverage"])
        current["files"][0]["path"] = "xtask/src/replacement.rs"
        current["omitted_in_scope_files"] = sorted(
            [*baseline["coverage"]["omitted_in_scope_files"], "crates/demo/src/lib.rs"]
        )
        accepted = ("docs/reports/coverage/aaaaaaa.json", baseline)
        violations, _ = gate._evaluation_violations(
            current,
            None,
            ["crates/demo/src/lib.rs"],
            accepted,
            accepted,
            False,
        )
        self.assertTrue(any("previously measured" in item for item in violations))

    def test_first_or_replaced_candidate_must_exactly_match_current_measurement(self) -> None:
        candidate = valid_record()
        candidate["coverage"]["covered_lines"] = 2
        candidate["coverage"]["files"][0]["covered_lines"] = 2
        current = copy.deepcopy(valid_record()["coverage"])
        violations, _ = gate._evaluation_violations(
            current,
            None,
            [],
            ("docs/reports/coverage/aaaaaaa.json", candidate),
            None,
            False,
        )
        self.assertTrue(
            any("do not exactly match the current measurement" in item for item in violations)
        )

        violations, _ = gate._evaluation_violations(
            current,
            None,
            [],
            ("docs/reports/coverage/aaaaaaa.json", valid_record()),
            None,
            False,
        )
        self.assertEqual(violations, [])

        different_lines = copy.deepcopy(current)
        different_lines["line_state_sha256"] = "e" * 64
        violations, _ = gate._evaluation_violations(
            different_lines,
            None,
            [],
            ("docs/reports/coverage/aaaaaaa.json", valid_record()),
            None,
            False,
        )
        self.assertTrue(
            any("do not exactly match the current measurement" in item for item in violations)
        )

    def test_replacement_candidate_cannot_bless_a_new_cobertura_omission(self) -> None:
        base = valid_record()
        current = copy.deepcopy(base["coverage"])
        current["files"][0]["path"] = "xtask/src/replacement.rs"
        current["omitted_in_scope_files"] = sorted(
            [*base["coverage"]["omitted_in_scope_files"], "crates/demo/src/lib.rs"]
        )
        candidate = valid_record()
        candidate["coverage"] = copy.deepcopy(current)
        violations, _ = gate._evaluation_violations(
            current,
            None,
            ["crates/demo/src/lib.rs"],
            ("docs/reports/coverage/bbbbbbb.json", candidate),
            ("docs/reports/coverage/aaaaaaa.json", base),
            False,
        )
        self.assertTrue(any("new in-scope files are absent" in item for item in violations))
        self.assertTrue(any("previously measured" in item for item in violations))

    def test_patch_measurement_records_every_changed_file_including_omissions(self) -> None:
        changed_files = ["crates/demo/src/lib.rs", "crates/venom-core/src/lib.rs"]
        patch, missing = gate._patch_measurement(
            {"crates/demo/src/lib.rs": {1: 1, 2: 0}},
            changed_files,
            {
                "crates/demo/src/lib.rs": {1, 3},
                "crates/venom-core/src/lib.rs": {4, 5},
            },
        )
        self.assertEqual(missing, ["crates/venom-core/src/lib.rs"])
        self.assertEqual(patch["changed_in_scope_files"], changed_files)
        self.assertEqual(
            patch["files"],
            [
                {
                    "path": "crates/demo/src/lib.rs",
                    "covered_lines": 1,
                    "coverable_lines": 1,
                    "changed_lines": 2,
                },
                {
                    "path": "crates/venom-core/src/lib.rs",
                    "covered_lines": 0,
                    "coverable_lines": 0,
                    "changed_lines": 2,
                },
            ],
        )
        self.assertEqual((patch["covered_lines"], patch["coverable_lines"]), (1, 1))

        record = valid_record()
        record["patch"] = patch
        record["evaluation"]["patch"] = "measured; no accepted numeric floor"
        gate.validate_baseline(record, "fixture.json")

        incomplete = copy.deepcopy(record)
        incomplete["patch"]["files"].pop()
        with self.assertRaisesRegex(gate.GateError, "exactly equal"):
            gate.validate_baseline(incomplete, "fixture.json")


class BaselineSchemaTests(unittest.TestCase):
    def test_valid_record_has_a_deterministic_markdown_companion(self) -> None:
        record = gate.validate_baseline(valid_record(), "fixture.json")
        first = gate.render_markdown(record)
        second = gate.render_markdown(json.loads(json.dumps(record, sort_keys=True)))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))

    def test_zero_denominator_malformed_counts_and_path_escape_fail(self) -> None:
        fixtures = []
        zero = valid_record()
        zero["coverage"]["covered_lines"] = 0
        zero["coverage"]["coverable_lines"] = 0
        zero["coverage"]["files"][0]["covered_lines"] = 0
        zero["coverage"]["files"][0]["coverable_lines"] = 0
        fixtures.append(zero)
        mismatch = valid_record()
        mismatch["coverage"]["covered_lines"] = 4
        fixtures.append(mismatch)
        invalid_line_state = valid_record()
        invalid_line_state["coverage"]["line_state_sha256"] = "D" * 64
        fixtures.append(invalid_line_state)
        escape = valid_record()
        escape["coverage"]["files"][0]["path"] = "crates/demo/src/../../escape.rs"
        fixtures.append(escape)
        zero_file = valid_record()
        zero_file["coverage"]["files"].append(
            {
                "path": "xtask/src/zero.rs",
                "covered_lines": 0,
                "coverable_lines": 0,
            }
        )
        fixtures.append(zero_file)
        for record in fixtures:
            with self.subTest(record=record), self.assertRaises(gate.GateError):
                gate.validate_baseline(record, "fixture.json")

    def test_tool_scope_and_provenance_are_exact(self) -> None:
        mutations = []
        tool = valid_record()
        tool["tooling"]["tarpaulin"] = "latest"
        mutations.append(tool)
        engine = valid_record()
        engine["tooling"]["engine"] = "ptrace"
        mutations.append(engine)
        missing_engine = valid_record()
        missing_engine["tooling"].pop("engine")
        mutations.append(missing_engine)
        wrong_components = valid_record()
        wrong_components["tooling"]["rust_components"] = []
        mutations.append(wrong_components)
        old_schema = valid_record()
        old_schema["schema"] = "venom.coverage.v1"
        mutations.append(old_schema)
        installer = valid_record()
        installer["tooling"]["installer_rust"] = "stable"
        mutations.append(installer)
        scope = valid_record()
        scope["scope"]["includes"] = ["crates/**"]
        mutations.append(scope)
        provenance = valid_record()
        provenance["provenance"]["artifact_url"] = "https://example.invalid"
        mutations.append(provenance)
        wrong_repository = valid_record()
        wrong_repository["provenance"]["repository"] = "fork/venom"
        wrong_repository["provenance"]["artifact_url"] = (
            "https://github.com/fork/venom/actions/runs/123"
        )
        mutations.append(wrong_repository)
        zero_run = valid_record()
        zero_run["provenance"]["run_id"] = "0"
        zero_run["provenance"]["artifact_url"] = (
            f"https://github.com/{gate.CANONICAL_REPOSITORY}/actions/runs/0"
        )
        mutations.append(zero_run)
        failed = valid_record()
        failed["evaluation"]["status"] = "failed"
        mutations.append(failed)
        incoherent = valid_record()
        incoherent["evaluation"]["total"] = "passed"
        mutations.append(incoherent)
        for record in mutations:
            with self.subTest(record=record), self.assertRaises(gate.GateError):
                gate.validate_baseline(record, "fixture.json")

    def test_unknown_keys_are_rejected_at_every_nested_schema_layer(self) -> None:
        patch_record = valid_record()
        patch_record["patch"] = {
            "covered_lines": 1,
            "coverable_lines": 1,
            "changed_in_scope_files": ["crates/demo/src/lib.rs"],
            "files": [
                {
                    "path": "crates/demo/src/lib.rs",
                    "covered_lines": 1,
                    "coverable_lines": 1,
                    "changed_lines": 1,
                }
            ],
        }
        patch_record["evaluation"]["patch"] = "measured; no accepted numeric floor"
        gate.validate_baseline(patch_record, "fixture.json")

        paths = [
            (),
            ("source",),
            ("tooling",),
            ("scope",),
            ("coverage",),
            ("coverage", "files", 0),
            ("cobertura",),
            ("provenance",),
            ("patch",),
            ("patch", "files", 0),
            ("evaluation",),
        ]
        for path in paths:
            record = copy.deepcopy(patch_record)
            target = record
            for component in path:
                target = target[component]
            target["unexpected"] = True
            with self.subTest(path=path), self.assertRaisesRegex(
                gate.GateError, "invalid key set"
            ):
                gate.validate_baseline(record, "fixture.json")

    def test_patch_inventory_and_line_counts_are_coherent(self) -> None:
        record = valid_record()
        record["patch"] = {
            "covered_lines": 1,
            "coverable_lines": 2,
            "changed_in_scope_files": ["crates/demo/src/lib.rs"],
            "files": [
                {
                    "path": "crates/demo/src/lib.rs",
                    "covered_lines": 1,
                    "coverable_lines": 2,
                    "changed_lines": 2,
                }
            ],
        }
        record["evaluation"]["patch"] = "measured; no accepted numeric floor"
        gate.validate_baseline(record, "fixture.json")

        missing_file = copy.deepcopy(record)
        missing_file["patch"]["covered_lines"] = 0
        missing_file["patch"]["coverable_lines"] = 0
        missing_file["patch"]["files"] = []
        too_many_coverable = copy.deepcopy(record)
        too_many_coverable["patch"]["files"][0]["changed_lines"] = 1
        for mutation in (missing_file, too_many_coverable):
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateError):
                gate.validate_baseline(mutation, "fixture.json")

    def test_policy_paths_are_portable_ascii(self) -> None:
        for path in (
            "crates/demo/src/space name.rs",
            "crates/demo/src/[link](spoof).rs",
            "crates/demo/src/ünicode.rs",
        ):
            with self.subTest(path=path):
                self.assertFalse(gate.in_scope(path))


class CommandIntegrationTests(unittest.TestCase):
    def _git(self, root: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout.strip()

    def test_accepted_omission_content_is_frozen_until_the_path_is_measured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "coverage@example.invalid")
            self._git(root, "config", "user.name", "Coverage Test")
            measured = root / "crates" / "demo" / "src" / "lib.rs"
            measured.parent.mkdir(parents=True)
            measured.write_text("pub fn measured() {}\n", encoding="utf-8")
            for omitted_path in gate.INITIAL_CALIBRATION_OMISSIONS:
                omitted = root.joinpath(*omitted_path.split("/"))
                omitted.parent.mkdir(parents=True, exist_ok=True)
                omitted.write_text("// accepted unobserved source\n", encoding="utf-8")
            self._git(root, "add", "crates")
            self._git(root, "commit", "-q", "-m", "accepted source blobs")
            source_commit = self._git(root, "rev-parse", "HEAD")

            baseline = valid_record()
            baseline["source"]["commit"] = source_commit
            accepted = ("docs/reports/coverage/aaaaaaa.json", baseline)
            coverage = copy.deepcopy(baseline["coverage"])

            tree = self._git(root, "rev-parse", f"{source_commit}^{{tree}}")
            divergent_head = self._git(
                root, "commit-tree", tree, "-m", "divergent identical tree"
            )
            ancestry = subprocess.run(
                ["git", "merge-base", "--is-ancestor", source_commit, divergent_head],
                cwd=root,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(ancestry.returncode, 1)
            self.assertEqual(
                gate._omission_blob_violations(
                    root, divergent_head, coverage, accepted, accepted
                ),
                [],
            )

            truth = root / "docs" / "coverage.md"
            truth.parent.mkdir()
            truth.write_text("candidate evidence\n", encoding="utf-8")
            self._git(root, "add", "docs/coverage.md")
            self._git(root, "commit", "-q", "-m", "docs-only candidate acceptance")
            candidate_head = self._git(root, "rev-parse", "HEAD")
            self.assertEqual(
                gate._omission_blob_violations(
                    root, candidate_head, coverage, accepted, None
                ),
                [],
            )

            target_path = gate.INITIAL_CALIBRATION_OMISSIONS[0]
            target = root.joinpath(*target_path.split("/"))
            target.unlink()
            self._git(root, "add", "-A", "--", target_path)
            self._git(root, "commit", "-q", "-m", "delete omitted source")
            target.write_text("// changed while still unobserved\n", encoding="utf-8")
            self._git(root, "add", target_path)
            self._git(root, "commit", "-q", "-m", "recreate omitted source")
            changed_head = self._git(root, "rev-parse", "HEAD")

            violations = gate._omission_blob_violations(
                root, changed_head, coverage, accepted, accepted
            )
            self.assertTrue(
                any(target_path in item and "remaining unobserved" in item for item in violations)
            )

            replacement = copy.deepcopy(baseline)
            replacement["source"]["commit"] = changed_head
            replacement_baseline = (
                "docs/reports/coverage/bbbbbbb.json",
                replacement,
            )
            self.assertTrue(
                gate._omission_blob_violations(
                    root,
                    changed_head,
                    coverage,
                    replacement_baseline,
                    accepted,
                )
            )

            now_measured = copy.deepcopy(coverage)
            now_measured["omitted_in_scope_files"].remove(target_path)
            now_measured["files"].append(
                {
                    "path": target_path,
                    "covered_lines": 1,
                    "coverable_lines": 1,
                }
            )
            self.assertEqual(
                gate._omission_blob_violations(
                    root, changed_head, now_measured, accepted, accepted
                ),
                [],
            )

            renamed_from_path = gate.INITIAL_CALIBRATION_OMISSIONS[1]
            renamed_from = root.joinpath(*renamed_from_path.split("/"))
            renamed_path = "crates/venom-core/src/renamed_omission.rs"
            renamed_to = root.joinpath(*renamed_path.split("/"))
            renamed_from.rename(renamed_to)
            self._git(root, "add", "-A", "--", renamed_from_path, renamed_path)
            self._git(root, "commit", "-q", "-m", "rename omitted source")
            renamed_head = self._git(root, "rev-parse", "HEAD")
            changed_files, changed_lines = gate._changed_sources(
                root, changed_head, renamed_head
            )
            self.assertEqual(changed_files, [renamed_path])
            patch, missing = gate._patch_measurement({}, changed_files, changed_lines)
            self.assertEqual(missing, [renamed_path])
            self.assertEqual(patch["files"][0]["path"], renamed_path)

            renamed_coverage = copy.deepcopy(coverage)
            renamed_coverage["omitted_in_scope_files"].remove(renamed_from_path)
            renamed_coverage["omitted_in_scope_files"].append(renamed_path)
            renamed_coverage["omitted_in_scope_files"].sort()
            violations, _ = gate._evaluation_violations(
                renamed_coverage,
                patch,
                missing,
                accepted,
                accepted,
                False,
            )
            self.assertTrue(any("new in-scope files" in item for item in violations))

    def test_calibration_writes_both_summaries_and_normal_mode_fails_without_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "coverage@example.invalid")
            self._git(root, "config", "user.name", "Coverage Test")
            source = root / "crates" / "demo" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("pub fn demo() {}\n", encoding="utf-8")
            for omitted_path in gate.INITIAL_CALIBRATION_OMISSIONS:
                omitted = root.joinpath(*omitted_path.split("/"))
                omitted.parent.mkdir(parents=True, exist_ok=True)
                omitted.write_text("// unobserved fixture\n", encoding="utf-8")
            (root / "Cargo.lock").write_text("# fixture\n", encoding="utf-8")
            cargo_config = root / ".cargo" / "config.toml"
            cargo_config.parent.mkdir()
            cargo_config.write_bytes(gate.EXPECTED_CARGO_CONFIG)
            cobertura_bytes = cobertura(
                [("crates/demo/src/lib.rs", [(1, 1)])]
            ).encode("utf-8")
            cobertura_path = root / "cobertura.xml"
            cobertura_path.write_bytes(cobertura_bytes)
            self._git(
                root,
                "add",
                ".cargo/config.toml",
                "Cargo.lock",
                "crates",
            )
            self._git(root, "commit", "-q", "-m", "fixture")

            arguments = [
                "--workspace-root",
                str(root),
                "--calibrate",
                "--repository",
                "owner/repository",
                "--run-id",
                "1",
                "--run-attempt",
                "1",
            ]
            output = io.StringIO()
            errors = io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors), mock.patch.object(
                gate, "_read_cobertura", wraps=gate._read_cobertura
            ) as reader, mock.patch.object(
                gate, "parse_cobertura", wraps=gate.parse_cobertura
            ) as parser, mock.patch.object(
                gate, "_record", wraps=gate._record
            ) as recorder, mock.patch.object(
                gate, "_sha256", wraps=gate._sha256
            ) as sha256, mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("run must not use an unbounded path read"),
            ):
                self.assertEqual(gate.run(arguments), 0)
            reader.assert_called_once_with(cobertura_path)
            parsed_bytes = parser.call_args.args[0]
            recorded_bytes = recorder.call_args.kwargs["cobertura_bytes"]
            self.assertIs(parsed_bytes, recorded_bytes)
            self.assertEqual(parsed_bytes, cobertura_bytes)
            self.assertEqual(
                sum(call.args[0] is parsed_bytes for call in sha256.call_args_list), 1
            )
            self.assertTrue((root / "coverage-summary.json").is_file())
            self.assertTrue((root / "coverage-summary.md").is_file())
            record = json.loads((root / "coverage-summary.json").read_text(encoding="utf-8"))
            self.assertEqual(record["evaluation"]["mode"], "calibration")
            self.assertEqual(
                record["cobertura"]["sha256"], hashlib.sha256(cobertura_bytes).hexdigest()
            )

            normal = [item for item in arguments if item != "--calibrate"]
            with redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(gate.run(normal), 1)

            with self.assertRaises(gate.GateError):
                gate.run([*arguments, "--require-base"])
            with self.assertRaises(gate.GateError):
                gate.run([*arguments, "--base-ref", "0" * 40])

    def test_accepted_baseline_binds_the_recorded_lockfile_to_its_source_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "coverage@example.invalid")
            self._git(root, "config", "user.name", "Coverage Test")
            source = root / "crates" / "demo" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("pub fn demo() {}\n", encoding="utf-8")
            lock_bytes = b"# fixture lock\n"
            (root / "Cargo.lock").write_bytes(lock_bytes)
            self._git(root, "add", "Cargo.lock", "crates/demo/src/lib.rs")
            self._git(root, "commit", "-q", "-m", "measured source")
            source_commit = self._git(root, "rev-parse", "HEAD")

            record = valid_record()
            record["source"]["commit"] = source_commit
            record["source"]["cargo_lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
            record["coverage"]["omitted_in_scope_files"] = []
            evidence = root / "docs" / "reports" / "coverage"
            evidence.mkdir(parents=True)
            target = f"docs/reports/coverage/{source_commit[:7]}.json"
            json_path = root / target
            markdown_path = json_path.with_suffix(".md")
            pointer_path = evidence / "accepted-baseline.txt"
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            markdown_path.write_text(
                gate.render_markdown(record), encoding="utf-8", newline="\n"
            )
            pointer_path.write_text(target + "\n", encoding="utf-8", newline="\n")
            self._git(root, "add", "docs/reports/coverage")
            self._git(root, "commit", "-q", "-m", "accept coverage")
            accepted_commit = self._git(root, "rev-parse", "HEAD")
            loaded = gate.load_baseline(
                root, accepted_commit, gate.DEFAULT_BASELINE_POINTER
            )
            self.assertIsNotNone(loaded)

            record["source"]["cargo_lock_sha256"] = "d" * 64
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            markdown_path.write_text(
                gate.render_markdown(record), encoding="utf-8", newline="\n"
            )
            self._git(root, "add", "docs/reports/coverage")
            self._git(root, "commit", "-q", "-m", "corrupt coverage lock digest")
            corrupted_commit = self._git(root, "rev-parse", "HEAD")
            with self.assertRaisesRegex(gate.GateError, "Cargo.lock digest"):
                gate.load_baseline(
                    root, corrupted_commit, gate.DEFAULT_BASELINE_POINTER
                )

    def test_git_attributes_cannot_turn_changed_rust_into_a_not_applicable_patch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "coverage@example.invalid")
            self._git(root, "config", "user.name", "Coverage Test")
            source = root / "crates" / "demo" / "src"
            source.mkdir(parents=True)
            source_file = source / "lib.rs"
            source_file.write_bytes(b"pub fn demo() {}\n")
            (root / ".gitattributes").write_bytes(b"*.rs -diff\n")
            self._git(root, "add", ".gitattributes", "crates/demo/src/lib.rs")
            self._git(root, "commit", "-q", "-m", "binary-attributed source")
            base = self._git(root, "rev-parse", "HEAD")

            source_file.write_bytes(b"pub fn demo() {}\npub fn added() {}\n")
            self._git(root, "add", "crates/demo/src/lib.rs")
            self._git(root, "commit", "-q", "-m", "change attributed source")
            head = self._git(root, "rev-parse", "HEAD")

            names, line_map = gate._changed_sources(root, base, head)
            self.assertEqual(names, ["crates/demo/src/lib.rs"])
            self.assertEqual(line_map, {"crates/demo/src/lib.rs": {2}})
            patch, missing = gate._patch_measurement(
                {"crates/demo/src/lib.rs": {1: 1, 2: 1}}, names, line_map
            )
            self.assertEqual(missing, [])
            self.assertEqual(patch["coverable_lines"], 1)
            self.assertEqual(patch["covered_lines"], 1)

    def test_candidate_acceptance_freezes_every_non_truth_path_since_measurement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "coverage@example.invalid")
            self._git(root, "config", "user.name", "Coverage Test")
            source = root / "crates" / "demo" / "src"
            workflow_path = root / ".github" / "workflows" / "tests.yml"
            source.mkdir(parents=True)
            workflow_path.parent.mkdir(parents=True)
            source_file = source / "lib.rs"
            source_file.write_text(
                "pub fn decision() -> bool { true }\n", encoding="utf-8"
            )
            (root / "Cargo.lock").write_text("# fixture\n", encoding="utf-8")
            calibration_workflow = (
                b"name: Tests\nsteps:\n"
                + gate._CALIBRATION_STEP_NAME
                + b"\n        run: python3 scripts/coverage_gate.py"
                + gate._CALIBRATION_ARGUMENTS
                + b"\n"
            )
            workflow_path.write_bytes(calibration_workflow)
            self._git(root, "add", ".github", "Cargo.lock", "crates")
            self._git(root, "commit", "-q", "-m", "measured source")
            measured_source = self._git(root, "rev-parse", "HEAD")

            enforcement_workflow = calibration_workflow.replace(
                gate._CALIBRATION_STEP_NAME, gate._ENFORCEMENT_STEP_NAME, 1
            ).replace(gate._CALIBRATION_ARGUMENTS, gate._ENFORCEMENT_ARGUMENTS, 1)
            workflow_path.write_bytes(enforcement_workflow)
            evidence = root / "docs" / "reports" / "coverage"
            evidence.mkdir(parents=True)
            (evidence / "accepted-baseline.txt").write_text(
                "docs/reports/coverage/aaaaaaa.json\n", encoding="utf-8"
            )
            (root / "README.md").write_text("coverage accepted\n", encoding="utf-8")
            (root / "PROJECT_STATUS.md").write_text(
                "# Project status\n\nCoverage evidence accepted.\n",
                encoding="utf-8",
            )
            self._git(
                root,
                "add",
                ".github",
                "README.md",
                "PROJECT_STATUS.md",
                "docs",
            )
            self._git(root, "commit", "-q", "-m", "accept measured evidence")
            acceptance_head = self._git(root, "rev-parse", "HEAD")

            candidate = valid_record()
            candidate["source"]["commit"] = measured_source
            head_baseline = ("docs/reports/coverage/aaaaaaa.json", candidate)
            self.assertEqual(
                gate._candidate_provenance_violations(
                    root, acceptance_head, head_baseline, None
                ),
                [],
            )

            source_file.write_text(
                "pub fn decision() -> bool { false }\n", encoding="utf-8"
            )
            self._git(root, "add", "crates/demo/src/lib.rs")
            self._git(root, "commit", "-q", "-m", "change logic after measurement")
            mutated_head = self._git(root, "rev-parse", "HEAD")
            provenance = gate._candidate_provenance_violations(
                root, mutated_head, head_baseline, None
            )
            self.assertTrue(any("crates/demo/src/lib.rs" in item for item in provenance))
            violations, evaluation = gate._evaluation_violations(
                copy.deepcopy(candidate["coverage"]),
                None,
                [],
                head_baseline,
                None,
                False,
                provenance,
            )
            self.assertTrue(any("dedicated acceptance allowlist" in item for item in violations))
            self.assertEqual(evaluation["status"], "failed")

    def test_head_cargo_configuration_is_exact_and_has_no_legacy_companion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._git(root, "init", "-q")
            self._git(root, "config", "user.email", "coverage@example.invalid")
            self._git(root, "config", "user.name", "Coverage Test")
            cargo = root / ".cargo"
            cargo.mkdir()
            config = cargo / "config.toml"
            config.write_bytes(gate.EXPECTED_CARGO_CONFIG)
            self._git(root, "add", ".cargo/config.toml")
            self._git(root, "commit", "-q", "-m", "reviewed config")
            head = self._git(root, "rev-parse", "HEAD")
            gate._verify_coverage_cargo_config(root, head)

            config.write_text("[build]\nrustflags = ['--cfg', 'hidden']\n", encoding="utf-8")
            self._git(root, "add", ".cargo/config.toml")
            self._git(root, "commit", "-q", "-m", "alter config")
            with self.assertRaisesRegex(gate.GateError, "exact reviewed"):
                gate._verify_coverage_cargo_config(
                    root, self._git(root, "rev-parse", "HEAD")
                )

            config.write_bytes(gate.EXPECTED_CARGO_CONFIG)
            (cargo / "config").write_text("[build]\ntarget = 'other'\n", encoding="utf-8")
            self._git(root, "add", ".cargo")
            self._git(root, "commit", "-q", "-m", "add legacy config")
            with self.assertRaisesRegex(gate.GateError, "legacy"):
                gate._verify_coverage_cargo_config(
                    root, self._git(root, "rev-parse", "HEAD")
                )


if __name__ == "__main__":
    unittest.main()
