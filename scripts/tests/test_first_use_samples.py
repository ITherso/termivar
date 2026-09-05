"""Pin the genuine checked-in capture, not timing or IDs of future reruns."""

import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import first_use

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "docs/examples/first-use"


class FirstUseSamples(unittest.TestCase):
    def setUp(self):
        self.provenance = json.loads((SAMPLES / "provenance.json").read_bytes())
        self.acquisition = json.loads((SAMPLES / "acquisition.json").read_bytes())

    def test_report_bytes_match_measured_capture_and_acquisition(self):
        for name, receipt in self.acquisition["samples"].items():
            self.assertIn(name, {"assessment.json", "assessment.html", "default.json", "provenance.json"})
            data = (SAMPLES / name).read_bytes()
            self.assertEqual(len(data), receipt["bytes"])
            self.assertEqual(hashlib.sha256(data).hexdigest(), receipt["sha256"])
        runs = self.provenance["invocations"]
        for run in runs:
            if "report" in run:
                self.assertEqual(run["report"]["sha256"], self.acquisition["samples"][run["report"]["path"]]["sha256"])
        self.assertNotEqual(runs[4]["invocation_id"], runs[5]["invocation_id"])
        self.assertEqual(runs[6]["preserved_report_sha256"], runs[4]["report"]["sha256"])
        self.assertEqual(runs[3]["stdout"]["sha256"], self.acquisition["samples"]["default.json"]["sha256"])

    def test_actual_sample_semantics_and_separate_failure_classes(self):
        report = json.loads((SAMPLES / "assessment.json").read_bytes())
        self.assertEqual(report["schema"], "venom-rendered-assessment/v1")
        self.assertEqual((report["status"], report["subject_count"], report["item_count"]), ("complete", 1, 4))
        self.assertEqual(len(report["items"]), 4)
        for item in report["items"]:
            self.assertEqual((item["disposition"], item["claim_basis"], item["severity"]), ("informational", "observation", None))
        default = json.loads((SAMPLES / "default.json").read_bytes())
        self.assertEqual(default["schema_version"], "decision-scan/v1")
        self.assertEqual(default["terminal"]["stop_reason"], "no_eligible_action")
        self.assertEqual(default["usage"]["active_verifications"], 0)
        runs = self.provenance["invocations"]
        self.assertEqual([run["exit_code"] for run in runs], [0, 0, 0, 0, 0, 0, 1, 2, 1])
        self.assertEqual(sum(runs[7]["fixture_requests"].values()), 0)
        self.assertEqual(runs[8]["fixture_requests"]["example"], 3)
        self.assertEqual(self.provenance["status"], "passed")
        self.assertTrue(self.provenance["fixture"]["stopped"])

    def test_release_and_fixture_identity_are_not_a_future_source_build(self):
        self.assertEqual(self.acquisition["release_id"], 382219595)
        self.assertEqual(self.acquisition["peeled_tag_commit"], "2212b2590c6193a18915dcd33ad2bb31e1a9ef7b")
        binary = self.provenance["binary"]
        self.assertEqual(binary["actual_version_output"], "termivar 0.10.0-alpha.1")
        self.assertEqual(binary["declared_source_ref"], "v0.10.0-alpha.1")
        self.assertEqual(binary["declared_build_features"], "release-bundle")
        self.assertEqual(binary["sha256"], self.acquisition["archive_inspection"]["member_sha256"])
        self.assertEqual(self.provenance["host"]["os"], "Windows")
        self.assertEqual(self.provenance["fixture"]["sha256"], first_use.fixture_description()["sha256"])

    def test_public_copy_is_raw_free_without_rewriting_reports(self):
        for name in ("assessment.json", "assessment.html"):
            first_use.validate_sample((SAMPLES / name).read_bytes(), Path("PRIVATE_BINARY_SENTINEL"), html=name.endswith("html"))
        binary = self.provenance["binary"]
        self.assertEqual(binary["path"], "<LOCAL_BINARY>")
        for run in self.provenance["invocations"]:
            self.assertEqual(run["argv"][0], "<LOCAL_BINARY>")
            self.assertFalse(any(arg in {"--authorization-review-policy", "--openapi-review", "--rest-review", "--ssrf-oast-review"} for arg in run["argv"]))
        self.assertEqual(self.provenance["normalization"][0]["fields"], ["binary.path", "invocations[*].argv[0]"])
        for path in SAMPLES.glob("*.json"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?i)(?:[A-Z]:\\|/Users/|/home/|file://)")

    def test_first_use_docs_label_real_output_and_nonfloating_build_choices(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        distribution = (ROOT / "docs/DISTRIBUTION.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs/GETTING_STARTED.md").read_text(encoding="utf-8")
        fragment = '"title":"Permissions-Policy was not observed","disposition":"informational","claim_basis":"observation","severity":null'
        self.assertIn(fragment, (SAMPLES / "assessment.json").read_text(encoding="utf-8"))
        self.assertIn(fragment, readme)
        self.assertIn("releases/tag/v0.10.0-alpha.1", readme)
        reviewed_source = "a29ba40c8cfdc7d0385431ea4d9e374e213ca4e0"
        for text in (readme, distribution, guide):
            self.assertIn(reviewed_source, text)
        for text in (readme, distribution, guide):
            self.assertNotIn("releases/latest", text)
            self.assertNotIn("REPLACE_WITH_SHA", text)
        self.assertIn("--source-ref", guide)
        self.assertIn("--expect-version", guide)


if __name__ == "__main__":
    unittest.main()
