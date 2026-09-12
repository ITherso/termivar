"""Independent local-file preparation checks for the synthetic fingerprint catalogue."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPOSITORY_ROOT / "scripts" / "prepare_wordpress_fingerprint_catalog.py"
EXAMPLE = (
    REPOSITORY_ROOT
    / "docs" / "examples" / "wordpress-review" / "asset-fingerprints"
)
SOURCE = EXAMPLE / "catalogue-source.synthetic.json"
CATALOGUE = EXAMPLE / "catalogue.synthetic.json"
SPEC = importlib.util.spec_from_file_location("prepare_wordpress_fingerprint_catalog", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)

EXPECTED = {
    "js_ab": (49, "0a0760b281d010ed4d70610e4f2f460a33846088b373ec10fd47d0d5ccb4bf26"),
    "js_c": (50, "4f770e9b2646e3b0d0b0ac777c7f76ad3893f1477d1a9e00c3cfbfb443b5f4a2"),
    "css_a": (37, "9ae3210e7954adbb2ed976b34b4605495de9a8406634bedd92bc14a3d317fdae"),
    "css_bc": (37, "c8b61302a47ea3208b743c287349570d3580756b3fafc73ac14a5eada9557b90"),
    "common": (32, "e4b20a225f36b6cecb22bd9c1e89b256f33ed39ad9e34bf2044462bba21bf17f"),
}


def strict_json(data: bytes):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(f"duplicate key: {key}")
            result[key] = value
        return result

    return json.loads(data.decode("utf-8", "strict"), object_pairs_hook=no_duplicates)


class FingerprintCataloguePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_checked_in_catalogue_is_exact_fresh_helper_output(self):
        before_source = SOURCE.read_bytes()
        before_assets = {
            path.relative_to(EXAMPLE).as_posix(): path.read_bytes()
            for path in sorted((EXAMPLE / "reference-assets").rglob("*"))
            if path.is_file()
        }
        output = self.root / "catalogue.json"
        with mock.patch.object(Path, "glob", side_effect=AssertionError("no glob")):
            summary = helper.prepare(SOURCE, output)

        self.assertEqual(output.read_bytes(), CATALOGUE.read_bytes())
        self.assertEqual(summary["schema"], helper.CATALOG_SCHEMA)
        self.assertEqual(summary["components"], 1)
        self.assertEqual(summary["releases"], 3)
        self.assertEqual(summary["files"], 9)
        self.assertEqual(summary["reference_bytes"], 355)
        self.assertEqual(SOURCE.read_bytes(), before_source)
        self.assertEqual({
            path.relative_to(EXAMPLE).as_posix(): path.read_bytes()
            for path in sorted((EXAMPLE / "reference-assets").rglob("*"))
            if path.is_file()
        }, before_assets)
        self.assertNotIn("local_file", output.read_text(encoding="utf-8"))

    def test_literal_hash_matrix_and_intersections_are_independent(self):
        rows = {
            "js_ab": EXAMPLE / "reference-assets/release-a/assets/fingerprint.js",
            "js_c": EXAMPLE / "reference-assets/release-c/assets/fingerprint.js",
            "css_a": EXAMPLE / "reference-assets/release-a/assets/fingerprint.css",
            "css_bc": EXAMPLE / "reference-assets/release-b/assets/fingerprint.css",
            "common": EXAMPLE / "reference-assets/release-a/assets/common.css",
        }
        for name, path in rows.items():
            with self.subTest(name=name):
                data = path.read_bytes()
                self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), EXPECTED[name])

        catalogue = strict_json(CATALOGUE.read_bytes())
        releases = catalogue["components"][0]["releases"]
        hashes = {
            release["release_id"]: {
                row["path"]: (row["byte_length"], row["sha256"])
                for row in release["files"]
            }
            for release in releases
        }
        self.assertEqual(
            {release for release, files in hashes.items()
             if files["assets/fingerprint.js"] == EXPECTED["js_ab"]},
            {"release-a", "release-b"},
        )
        self.assertEqual(
            {release for release, files in hashes.items()
             if files["assets/fingerprint.css"] == EXPECTED["css_bc"]},
            {"release-b", "release-c"},
        )
        self.assertEqual(
            {release for release, files in hashes.items()
             if files["assets/fingerprint.js"] == EXPECTED["js_ab"]
             and files["assets/fingerprint.css"] == EXPECTED["css_bc"]},
            {"release-b"},
        )
        self.assertEqual(
            {files["assets/common.css"] for files in hashes.values()},
            {EXPECTED["common"]},
        )

    def test_only_explicit_safe_regular_local_files_are_read(self):
        source = strict_json(SOURCE.read_bytes())
        source["components"][0]["releases"] = source["components"][0]["releases"][:1]
        fixture = self.root / "fixture"
        fixture.mkdir()
        asset_dir = fixture / "assets"
        asset_dir.mkdir()
        explicit = asset_dir / "explicit.js"
        explicit.write_bytes(b"explicit\n")
        (asset_dir / "unlisted.js").write_bytes(b"must not be read\n")
        source["components"][0]["releases"][0]["files"] = [{
            "path": "assets/fingerprint.js",
            "local_file": "assets/explicit.js",
            "representation_profile": helper.REPRESENTATION_PROFILE,
        }]
        source_path = fixture / "source.json"
        source_path.write_text(json.dumps(source), encoding="utf-8")
        catalog, counts = helper.build_catalog(source_path)
        row = catalog["components"][0]["releases"][0]["files"][0]
        self.assertEqual(row["sha256"], hashlib.sha256(b"explicit\n").hexdigest())
        self.assertEqual(counts["files"], 1)

        for bad in (
            "../outside.js",
            "/absolute.js",
            "C:/absolute.js",
            "https://example.invalid/file.js",
            "assets\\explicit.js",
            "assets/%65xplicit.js",
        ):
            with self.subTest(path=bad):
                mutated = copy.deepcopy(source)
                mutated["components"][0]["releases"][0]["files"][0]["local_file"] = bad
                source_path.write_text(json.dumps(mutated), encoding="utf-8")
                with self.assertRaises(helper.PreparationError):
                    helper.build_catalog(source_path)

    def test_duplicates_unknown_fields_limits_and_overwrite_fail_closed(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"x","schema":"y","catalog":{},"components":[]}',
                             encoding="utf-8")
        with self.assertRaisesRegex(helper.PreparationError, "duplicate"):
            helper.build_catalog(duplicate)

        source = strict_json(SOURCE.read_bytes())
        source["unexpected"] = True
        invalid = self.root / "invalid.json"
        invalid.write_text(json.dumps(source), encoding="utf-8")
        with self.assertRaisesRegex(helper.PreparationError, "unknown"):
            helper.build_catalog(invalid)

        with mock.patch.object(helper, "MAX_FILES", 8):
            with self.assertRaisesRegex(helper.PreparationError, "file-count"):
                helper.build_catalog(SOURCE)
        with mock.patch.object(helper, "MAX_TOTAL_ASSET_BYTES", 354):
            with self.assertRaisesRegex(helper.PreparationError, "aggregate"):
                helper.build_catalog(SOURCE)

        source = strict_json(SOURCE.read_bytes())
        source["catalog"]["provenance"]["notices"] = []
        source["components"][0]["releases"] = source["components"][0]["releases"][:1]
        release = source["components"][0]["releases"][0]
        release["source"]["notice_ids"] = []
        release["files"] = [{
            "path": "assets/fingerprint.js",
            "local_file": "explicit.js",
            "representation_profile": helper.REPRESENTATION_PROFILE,
        }]
        (self.root / "explicit.js").write_bytes(b"explicit\n")
        no_notice = self.root / "no-notice.json"
        no_notice.write_text(json.dumps(source), encoding="utf-8")
        catalogue, _ = helper.build_catalog(no_notice)
        self.assertEqual(catalogue["catalog"]["provenance"]["notices"], [])

        output = self.root / "existing.json"
        output.write_bytes(b"preserve")
        with self.assertRaisesRegex(helper.PreparationError, "already exists"):
            helper.prepare(SOURCE, output)
        self.assertEqual(output.read_bytes(), b"preserve")

    def test_cli_is_value_safe_and_never_creates_output_after_invalid_input(self):
        missing = self.root / "PRIVATE-MISSING-SOURCE.json"
        output = self.root / "must-not-exist.json"
        stderr = []
        with mock.patch.object(helper.sys, "stderr") as stream:
            stream.write.side_effect = lambda value: stderr.append(value)
            self.assertEqual(helper.main([
                "--source", str(missing), "--output", str(output)
            ]), 2)
        self.assertFalse(output.exists())
        diagnostic = "".join(stderr)
        self.assertIn("preparation failed", diagnostic)
        self.assertNotIn("PRIVATE-MISSING-SOURCE", diagnostic)


if __name__ == "__main__":
    unittest.main()
