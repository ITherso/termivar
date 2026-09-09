"""Local release-candidate acceptance tests; no public target or real release."""

from __future__ import annotations

import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
REPOSITORY = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
SCRIPT = SCRIPTS / "release_candidate_acceptance.py"
SPEC = importlib.util.spec_from_file_location("release_candidate_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)

PAYLOAD = b"synthetic packaged binary fixture; never executed\n"
TARGET = "x86_64-pc-windows-msvc"
ARCHIVE_NAME = f"termivar-main-{TARGET}.zip"
TEST_VERSION = "0.10.0-alpha.3"

# This is deliberately independent of release_candidate_acceptance.py. If a
# package feature is added without an explicit curated-build classification,
# the release helper and this fixture must not share the same omission.
EXPECTED_RELEASE_MEMBERS = (
    "artifact-adapter",
    "normalization-resilience",
    "graphql-review",
    "openapi-review",
    "rest-review",
    "authorization-review",
    "wordpress-review",
)
EXPECTED_EXCLUDED_FEATURES = (
    "api-adapter",
    "legacy-scanner",
    "proxy-adapter",
    "ssrf-oast-review",
)
EXPECTED_FEATURE_STATES = {
    "api-adapter": "not_compiled",
    "artifact-adapter": "compiled",
    "authorization-review": "compiled",
    "graphql-review": "compiled",
    "legacy-scanner": "not_compiled",
    "normalization-resilience": "compiled",
    "openapi-review": "compiled",
    "proxy-adapter": "not_compiled",
    "release-bundle": "compiled",
    "rest-review": "compiled",
    "ssrf-oast-review": "not_compiled",
    "wordpress-review": "compiled",
}
EXPECTED_WORDPRESS_OPTIONS = (
    "--wordpress-review",
    "--wordpress-context",
    "--wordpress-advisories",
    "--wordpress-plugins-json",
    "--wordpress-themes-json",
    "--wordpress-core-version-file",
    "--wordpress-advisories-format",
    "--wordpress-external-version-profile",
)
EXPECTED_WORDPRESS_PREREQUISITES = (
    "--profile web-review",
    "--wordpress-review",
    "optional --wordpress-context FILE",
    "optional --wordpress-advisories FILE",
    "optional --wordpress-advisories-format termivar|wordfence-v3-production",
    ("optional --wordpress-external-version-profile "
     "numeric-dotted/v1|php-release-subset/v1 (Wordfence Production only)"),
    "optional --wordpress-plugins-json FILE",
    "optional --wordpress-themes-json FILE",
    "optional --wordpress-core-version-file FILE",
)
EXPECTED_WORDPRESS_NOTICE = {
    "id": ("wordfence-notice-sha256:"
           "826c6b2cc3601beebdd82831cb757c64e721434a7e6ea7d5f1511ca041858379"),
    "message": "Original synthetic fixture notice; not a provider notice.",
    "party": "termivar_fixture_author",
    "notice": "Synthetic data created for Termivar package acceptance.",
    "license": "This fictional fixture may be copied with its label intact.",
    "license_url": "https://example.invalid/termivar/package-acceptance/terms",
}
EXPECTED_WORDPRESS_MAPPING_REVISION = "termivar-wordfence-v3-production/v2"
EXPECTED_WORDPRESS_RESOURCE_POLICY = "termivar.wordfence-v3-bounded-capacity/v1"
EXPECTED_WORDPRESS_IDENTITY_POLICY = (
    "termivar.wordfence-v3-exact-plus-ascii-lowercase-candidate/v1"
)
EXPECTED_WORDPRESS_EXPLICIT_POLICY = (
    "termivar.wordfence-v3-explicit-interpretation/v1"
)
EXPECTED_WORDPRESS_SEMANTIC_SHA256 = (
    "4694cd26b7f147fc69b9ff9772c71052a5ebb2717b0f2ac8ae592df4dc3a8363"
)
EXPECTED_WORDPRESS_ACCOUNTED_RETAINED_BYTES = 9_708


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tar_bytes(name: str = "termivar", *, extra: bool = False) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.mode = 0o755
        member.size = len(PAYLOAD)
        archive.addfile(member, io.BytesIO(PAYLOAD))
        if extra:
            other = tarfile.TarInfo("unexpected")
            other.mode = 0o644
            other.size = 1
            archive.addfile(other, io.BytesIO(b"x"))
    return output.getvalue()


def write_bundle(directory: Path, item_count: int = 2,
                 assessment: dict | None = None) -> bytes:
    directory.mkdir()
    if assessment is None:
        items = [{"fixture": index} for index in range(item_count)]
        assessment = {
            "schema": runner.report_bundle_example.ASSESSMENT_SCHEMA,
            "profile": "web-review",
            "status": "complete",
            "subject_count": 1,
            "item_count": item_count,
            "items": items,
        }
    external = assessment.get("wordpress_review", {}).get("external_review")
    if isinstance(external, dict):
        notice = EXPECTED_WORDPRESS_NOTICE
        html = (
            "<!doctype html><html><body><section><h3>Rights notices</h3>"
            f"<code>{notice['party']}</code><code>{notice['message']}</code>"
            f"<code>{notice['notice']}</code><code>{notice['license']}</code>"
            f"<a rel=\"noreferrer noopener\" href=\"{notice['license_url']}\">"
            "License terms</a></section></body></html>"
        ).encode("utf-8")
    else:
        html = b"<!doctype html><html><body>bounded release fixture</body></html>"
    item_count = assessment["item_count"]
    assessment_bytes = json.dumps(assessment, separators=(",", ":")).encode()
    manifest = {
        "schema": runner.report_bundle_example.BUNDLE_SCHEMA,
        "producer": {"product": "Termivar", "version": TEST_VERSION},
        "assessment": {
            "profile": "web-review", "status": "complete",
            "subject_count": 1, "item_count": item_count,
        },
        "files": [
            {
                "name": "assessment.html", "format": "html",
                "media_type": "text/html; charset=utf-8",
                "byte_length": len(html), "sha256": digest(html),
            },
            {
                "name": "assessment.json", "format": "json",
                "media_type": "application/json",
                "byte_length": len(assessment_bytes), "sha256": digest(assessment_bytes),
            },
        ],
    }
    (directory / "assessment.html").write_bytes(html)
    (directory / "assessment.json").write_bytes(assessment_bytes)
    (directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return assessment_bytes


class FakeServer:
    def __init__(self) -> None:
        self.counts = {
            "root": 1, "example": 0, "unknown": 0,
            "unsupported": 0, "invalid": 0,
        }

    def snapshot(self) -> dict:
        return self.counts.copy()


class FakeFixture:
    active = None

    def __init__(self) -> None:
        self.server = FakeServer()
        self.origin = "http://127.0.0.1:48123/"

    def __enter__(self):
        FakeFixture.active = self
        return self

    def __exit__(self, *exc):
        FakeFixture.active = None


def capabilities(*, include_ssrf: bool = False) -> dict:
    states = EXPECTED_FEATURE_STATES.copy()
    if include_ssrf:
        states["ssrf-oast-review"] = "compiled"
    features = [
        {"name": name, "build_state": state}
        for name, state in sorted(states.items())
    ]
    surfaces = [
        {
            "key": "inventory.compiled-cli-capabilities",
            "label": "Compiled CLI capabilities",
            "compile_feature": None,
            "build_state": "compiled",
        },
        {
            "key": "option.ssrf-oast-review",
            "label": "SSRF OAST query review",
            "compile_feature": "ssrf-oast-review",
            "build_state": "compiled" if include_ssrf else "not_compiled",
        },
        {
            "key": "option.wordpress-review",
            "label": "WordPress evidence review",
            "compile_feature": "wordpress-review",
            "build_state": "compiled",
            "group": "optional",
            "kind": "scan_option",
            "maturity": "preview",
            "implementation_status": "implemented",
            "alias": None,
            "prerequisites": list(EXPECTED_WORDPRESS_PREREQUISITES),
            "limitation": (
                "Interprets explicit local declarations, adds no target requests, and "
                "lets the operator explicitly select a comparison rule. Without that "
                "selector the external relation stays indeterminate."
            ),
        },
    ]
    return {
        "schema": runner.CAPABILITIES_SCHEMA,
        "product": "Termivar",
        "package_version": TEST_VERSION,
        "runtime_execution": "not_performed",
        "cli_package_features": features,
        "surfaces": surfaces,
        "build_origin_authenticity": (
            "Self-reported package version and compile features do not establish source "
            "authenticity, an official release origin, or runtime readiness."
        ),
    }


def capabilities_text(document: dict) -> bytes:
    states = "\n".join(
        f"[{surface['build_state']}] {surface['label']}"
        for surface in document["surfaces"]
    )
    return ("Termivar CLI capabilities\n"
            "runtime_execution: not_performed\n" + states + "\n").encode()


class CapabilityCommands:
    def __init__(self, document: dict, text: bytes | None = None) -> None:
        self.document = document
        self.text = capabilities_text(document) if text is None else text

    def run(self, identifier, arguments, *, expected_stderr_empty):
        self.assert_offline_call(identifier, arguments, expected_stderr_empty)
        if arguments == ["capabilities"]:
            return self.text, b""
        return json.dumps(self.document).encode(), b""

    @staticmethod
    def assert_offline_call(identifier, arguments, expected_stderr_empty):
        assert identifier in {"capabilities-text", "capabilities-json"}
        assert arguments in (["capabilities"], ["capabilities", "--format", "json"])
        assert expected_stderr_empty is True


def cargo_feature_contract_violations(features: dict) -> list[str]:
    violations = []
    expected = set(EXPECTED_FEATURE_STATES)
    observed = set(features) - {"default"}
    if observed != expected:
        violations.append("CLI feature inventory requires deliberate classification")
    if features.get("default") != []:
        violations.append("termivar-cli default feature composition changed")
    if tuple(features.get("release-bundle", ())) != EXPECTED_RELEASE_MEMBERS:
        violations.append("release-bundle membership changed")
    return violations


def fake_help(arguments: list[str]) -> bytes:
    if arguments == ["--help"]:
        return (b"Termivar\nCommands:\n  scan  bounded scan\n  artifact  local file\n"
                b"  report  offline reports\n  capabilities  build inventory\n")
    if arguments == ["scan", "--help"]:
        options = (
            "--report-dir", "--progress", "--normalization-resilience",
            "--graphql-review", "--openapi-review", "--rest-review",
            "--authorization-review-policy", *EXPECTED_WORDPRESS_OPTIONS,
        )
        return ("Usage: termivar scan [OPTIONS]\n"
                + "".join(f"  {option}\n" for option in options)).encode()
    if arguments == ["report", "--help"]:
        return b"Commands:\n  compare  compare reports\n  verify  verify bundle\n"
    raise AssertionError(arguments)


VALID_PROGRESS = (
    b"[progress] state=assessment_running elapsed_ms=0 accounted_requests=0 "
    b"accounted_active_verifications=0 subjects_started=0 subjects_processed=0 "
    b"counts=last_observed\n"
    b"[progress] state=composing_report elapsed_ms=10 accounted_requests=3 "
    b"accounted_active_verifications=0 subjects_started=1 subjects_processed=1 "
    b"counts=last_observed\n"
    b"[progress] state=rendering_report elapsed_ms=11 accounted_requests=3 "
    b"accounted_active_verifications=0 subjects_started=1 subjects_processed=1 "
    b"counts=last_observed\n"
    b"[progress] state=publishing_report elapsed_ms=12 accounted_requests=3 "
    b"accounted_active_verifications=0 subjects_started=1 subjects_processed=1 "
    b"counts=last_observed\n"
    b"[progress] state=completed elapsed_ms=13 accounted_requests=3 "
    b"accounted_active_verifications=0 subjects_started=1 subjects_processed=1 "
    b"counts=last_observed\n"
)


def wordpress_assessment(audit: dict | None = None) -> dict:
    items = ([] if audit is None else [{
        "capability_id": "technology.wordpress-surface-observed@1",
        "category": "wordpress-surface",
        "disposition": "informational",
        "claim_basis": "observation",
        "case_reference": None,
        "outcome_reference": None,
        "verification_stage": None,
        "control_evidence_references": [],
        "candidate_evidence_references": [],
    }])
    document = {
        "schema": runner.report_bundle_example.ASSESSMENT_SCHEMA,
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": len(items),
        "items": items,
    }
    if audit is not None:
        document["wordpress_review"] = audit
    return document


def native_wordpress_audit() -> dict:
    expected = {
        "SYNTHETIC-BETA-NUMERIC-0001": (
            "numeric-dotted/v1", "unsupported", "indeterminate_unsupported"),
        "SYNTHETIC-BETA-PHP-SUBSET-0001": (
            "php-release-subset/v1", "within_declared_range",
            "candidate_match_on_declared_facts"),
        "SYNTHETIC-TRAILING-ZERO-NUMERIC-0001": (
            "numeric-dotted/v1", "within_declared_range",
            "candidate_match_on_declared_facts"),
        "SYNTHETIC-TRAILING-ZERO-PHP-SUBSET-0001": (
            "php-release-subset/v1", "outside_declared_ranges",
            "contradicted_by_declared_facts"),
        "SYNTHETIC-VENDOR-LABEL-UNSUPPORTED-0001": (
            "php-release-subset/v1", "unsupported", "indeterminate_unsupported"),
    }
    return {
        "schema": "security.wordpress-review-audit/v3",
        "catalog_schema": "security.wordpress-advisory-catalog/v2",
        "catalog_status": "evaluated",
        "additional_request_count": 0,
        "item_projected": True,
        "advisories": [
            {
                "id": identifier,
                "comparison_profile": profile,
                "version_relation": relation,
                "applicability": applicability,
                "exploit_execution": "not_performed",
                "impact_validation": "not_performed",
            }
            for identifier, (profile, relation, applicability) in expected.items()
        ],
    }


def external_wordpress_audit(feed: Path, profile: str | None) -> dict:
    slugs = (
        "synthetic-policy-within",
        "synthetic-policy-outside",
        "synthetic-vendor-label-plugin",
        "wordpress",
        "SYNTHETIC-POLICY-CANDIDATE",
    )
    if profile is None:
        evaluations = [
            {
                "key": {"source_component": {"slug": slug}},
                "version_relation": "source_comparison_semantics_unresolved",
            }
            for slug in slugs
        ]
        counts = {
            "evaluable_associations": 0,
            "unsupported_associations": 5,
        }
        policy = {"comparison_policy": "wordfence-v3/source-semantics-unresolved/v1"}
    else:
        results = {
            "synthetic-policy-within": (
                "within_supported_range_under_selected_policy",
                "version_match_under_selected_policy"),
            "synthetic-policy-outside": (
                "outside_declared_ranges_under_selected_policy",
                "no_version_match_under_selected_policy"),
            "synthetic-vendor-label-plugin": ("indeterminate", "indeterminate"),
            "wordpress": ("indeterminate", "indeterminate"),
            "SYNTHETIC-POLICY-CANDIDATE": (
                "indeterminate", "indeterminate"),
        }
        evaluations = [
            {
                "key": {"source_component": {"slug": slug}},
                "version_relation": relation,
                "applicability": applicability,
                "identity_mapping": ("ascii_case_fold_candidate"
                                     if slug == "SYNTHETIC-POLICY-CANDIDATE" else "exact"),
                "version_relation_reason": ("identity_mapping_candidate"
                                            if slug == "SYNTHETIC-POLICY-CANDIDATE"
                                            else "fixture_reason"),
                "execution": {
                    "exploit_execution": "not_performed",
                    "impact_validation": "not_performed",
                },
            }
            for slug, (relation, applicability) in results.items()
        ]
        counts = {
            "evaluable_associations": 2,
            "unsupported_associations": 3,
            "within_associations": 1,
            "outside_associations": 1,
            "indeterminate_associations": 3,
            "selected_ranges": 5,
            "evaluated_ranges": 2,
            "containing_ranges": 1,
            "noncontaining_ranges": 1,
            "unsupported_ranges": 1,
            "invalid_ranges": 0,
            "not_evaluated_ranges": 2,
            "partial_range_coverage_associations": 0,
        }
        policy = {
            "comparison_policy": EXPECTED_WORDPRESS_EXPLICIT_POLICY,
            "comparison_profile": profile,
            "policy_selection": "explicit_operator",
            "source_semantics_assurance": "not_established",
        }
    counts.update({
        "parsed_records": 1,
        "software_associations": 6,
        "exact_identity_associations": 4,
        "candidate_identity_associations": 1,
        "ambiguous_identity_associations": 0,
        "unresolved_identity_associations": 1,
        "projected_identity_limitations": 1,
        "unprojected_identity_limitations": 0,
        "selected_associations": 5,
        "excluded_associations": 1,
        "mapped_unselected_associations": 0,
    })
    return {
        "schema": "security.wordpress-review-audit/v6",
        "additional_request_count": 0,
        "item_projected": True,
        "external_review": {
            "source_namespace": "wordfence-intelligence",
            "source_format": "wordfence-v3-production",
            "mapping_revision": EXPECTED_WORDPRESS_MAPPING_REVISION,
            "identity_mapping_policy": EXPECTED_WORDPRESS_IDENTITY_POLICY,
            "identity_source_assurance": "not_established",
            "resource_policy": EXPECTED_WORDPRESS_RESOURCE_POLICY,
            "input": {
                "byte_length": feed.stat().st_size,
                "sha256": digest(feed.read_bytes()),
                "semantic_sha256": EXPECTED_WORDPRESS_SEMANTIC_SHA256,
                "accounted_retained_bytes": EXPECTED_WORDPRESS_ACCOUNTED_RETAINED_BYTES,
            },
            "notices": [EXPECTED_WORDPRESS_NOTICE],
            "counts": counts,
            "evaluations": evaluations,
            "identity_limitations": [{
                "key": {
                    "source_component": {
                        "kind": "plugin",
                        "slug": "https://example.invalid/plugins/opaque_name",
                    },
                },
                "identity_resolution": "canonical_identity_unavailable",
                "version_relation": "not_evaluated",
                "version_relation_reason": "canonical_identity_unavailable",
                "applicability": "indeterminate",
                "execution": {
                    "exploit_execution": "not_performed",
                    "impact_validation": "not_performed",
                },
            }],
            **policy,
        },
    }


class FakeCommands:
    def __init__(self, root: Path, include_ssrf: bool = False,
                 extra_incomplete_request: bool = False,
                 omit_progress_help: bool = False,
                 omitted_wordpress_option: str | None = None,
                 progress_stderr: bytes | None = None) -> None:
        self.root = root
        self.include_ssrf = include_ssrf
        self.extra_incomplete_request = extra_incomplete_request
        self.omit_progress_help = omit_progress_help
        self.omitted_wordpress_option = omitted_wordpress_option
        self.progress_stderr = progress_stderr
        self.arguments: list[list[str]] = []

    def __call__(self, argv, directory, record):
        arguments = argv[1:]
        self.arguments.append(arguments)
        stdout = b""
        stderr = b""
        exit_code = 0
        fixture = FakeFixture.active
        if arguments == ["--version"]:
            stdout = f"termivar {TEST_VERSION}\n".encode()
        elif arguments in (["--help"], ["scan", "--help"], ["report", "--help"]):
            stdout = fake_help(arguments)
            if arguments == ["scan", "--help"] and self.omit_progress_help:
                stdout = stdout.replace(b"  --progress\n", b"")
            if arguments == ["scan", "--help"] and self.omitted_wordpress_option:
                stdout = stdout.replace(
                    f"  {self.omitted_wordpress_option}\n".encode(), b"")
        elif arguments == ["capabilities"]:
            cap = capabilities(include_ssrf=self.include_ssrf)
            stdout = capabilities_text(cap)
        elif arguments == ["capabilities", "--format", "json"]:
            stdout = json.dumps(capabilities(include_ssrf=self.include_ssrf)).encode()
        elif arguments[0] == "scan":
            destination = Path(arguments[arguments.index("--report-dir") + 1])
            target = arguments[1]
            profile = arguments[arguments.index("--profile") + 1]
            if destination.name == "existing-bundle":
                exit_code, stderr = 1, b"report bundle destination already exists\n"
            elif profile == "baseline":
                exit_code, stderr = 2, b"--report-dir requires --profile web-review\n"
            elif destination.name == "assessment-bundle" and destination.exists():
                exit_code, stderr = 1, b"report bundle destination already exists\n"
            elif destination.name == "assessment-bundle":
                assert fixture is not None and target == fixture.origin
                assert "--progress" in arguments
                fixture.server.counts["root"] += 3
                write_bundle(destination)
                progress = (VALID_PROGRESS if self.progress_stderr is None
                            else self.progress_stderr)
                stderr = progress + b"Report bundle completed\n"
            elif destination.name == "incomplete-must-not-exist":
                assert fixture is not None and target.endswith("/example")
                fixture.server.counts["example"] += 3
                if self.extra_incomplete_request:
                    fixture.server.counts["unknown"] += 1
                exit_code = 1
                stdout = json.dumps({
                    "schema_version": "web-assessment/v2",
                    "disposition": "incomplete",
                    "incomplete_reasons": ["assessment_subject_identity_unavailable"],
                }).encode()
            elif destination.name == "wordpress-malformed-must-not-exist":
                exit_code, stderr = 1, b"WordPress advisory input is malformed\n"
            elif destination.name == "wordpress-conflict-must-not-exist":
                exit_code, stderr = 2, b"WordPress input options conflict\n"
            elif destination.name.startswith("wordpress-"):
                assert fixture is not None and target == fixture.origin
                fixture.server.counts["root"] += 5
                fixture.server.request_lines.extend(runner.WORDPRESS_TRACE)
                if destination.name == "wordpress-inactive":
                    assessment = wordpress_assessment()
                elif destination.name == "wordpress-native":
                    assessment = wordpress_assessment(native_wordpress_audit())
                elif destination.name in {
                        "wordpress-external-unresolved", "wordpress-external-numeric"}:
                    feed = Path(arguments[arguments.index("--wordpress-advisories") + 1])
                    selected = ("numeric-dotted/v1"
                                if destination.name.endswith("numeric") else None)
                    assessment = wordpress_assessment(
                        external_wordpress_audit(feed, selected))
                else:
                    raise AssertionError(arguments)
                write_bundle(destination, assessment=assessment)
                stderr = b"Report bundle completed\n"
            else:
                raise AssertionError(arguments)
        elif arguments[:2] == ["report", "verify"]:
            bundle = Path(arguments[arguments.index("--dir") + 1])
            manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
            expected = manifest["files"][0]["sha256"]
            observed = digest((bundle / "assessment.html").read_bytes())
            matched = expected == observed
            exit_code = 0 if matched else 1
            stdout = json.dumps({
                "schema": runner.VERIFICATION_SCHEMA,
                "status": "integrity_match" if matched else "not_verified",
                "reason_codes": [] if matched else ["payload_digest_mismatch"],
            }).encode()
        elif arguments[:2] == ["report", "compare"]:
            before = Path(arguments[arguments.index("--before") + 1])
            after = Path(arguments[arguments.index("--after") + 1])
            if before.name == "before.json":
                groups = {
                    "only_in_after": [{}], "only_in_before": [{}],
                    "changed": [{"changed_fields": ["redacted_summary"]}],
                    "unchanged": [{}],
                }
            elif before.parent.name.startswith("wordpress-"):
                item_count = json.loads(before.read_text(encoding="utf-8"))["item_count"]
                groups = {
                    "only_in_after": [], "only_in_before": [], "changed": [],
                    "unchanged": [{} for _ in range(item_count)],
                }
                same = before == after
                wordpress = {
                    "status": "compared",
                    "methodology": {
                        "status": "unchanged" if same else "changed",
                        "changed_fields": ([] if same else [
                            "comparison_policy", "comparison_profile",
                        ]),
                    },
                    "advisories": {
                        "paired_changed": ([] if same else [{} for _ in range(5)]),
                        "paired_unchanged_count": 6 if same else 1,
                        "only_in_before": [],
                        "only_in_after": [],
                    },
                }
            else:
                item_count = json.loads(before.read_text(encoding="utf-8"))["item_count"]
                groups = {
                    "only_in_after": [], "only_in_before": [], "changed": [],
                    "unchanged": [{} for _ in range(item_count)],
                }
            document = {
                "schema": runner.COMPARISON_SCHEMA,
                "scope_assurance": "operator-declared",
                "before": {"sha256": runner.first_use.digest_file(before)},
                "after": {"sha256": runner.first_use.digest_file(after)},
                **groups,
            }
            if before.parent.name.startswith("wordpress-"):
                document["wordpress_review_comparison"] = wordpress
            stdout = json.dumps(document).encode()
        else:
            raise AssertionError(arguments)
        record["exit_code"] = exit_code
        record["stdout"] = {"bytes": len(stdout), "sha256": digest(stdout)}
        record["stderr"] = {"bytes": len(stderr), "sha256": digest(stderr)}
        return stdout, stderr


class CapabilityInventoryContractTests(unittest.TestCase):
    def validate(self, document: dict, text: bytes | None = None) -> dict:
        return runner._validate_capabilities(
            CapabilityCommands(document, text), TEST_VERSION)

    def assert_rejected(self, document: dict, message: str,
                        text: bytes | None = None) -> None:
        with self.assertRaisesRegex(runner.AcceptanceError, message):
            self.validate(document, text)

    def test_independent_current_inventory_and_wordpress_surface_pass(self):
        document = capabilities()
        rows = document["cli_package_features"]
        self.assertEqual(len(rows), 12)
        self.assertEqual(sum(row["build_state"] == "compiled" for row in rows), 8)
        self.assertEqual(sum(row["build_state"] == "not_compiled" for row in rows), 4)
        result = self.validate(document)
        self.assertEqual(tuple(result["compiled_members"]), EXPECTED_RELEASE_MEMBERS)
        self.assertEqual(tuple(result["excluded_features"]), EXPECTED_EXCLUDED_FEATURES)

    def test_missing_wordpress_and_same_length_wrong_name_fail(self):
        missing = capabilities()
        missing["cli_package_features"] = [
            row for row in missing["cli_package_features"]
            if row["name"] != "wordpress-review"
        ]
        self.assert_rejected(missing, "inventory is incomplete")

        wrong = capabilities()
        next(row for row in wrong["cli_package_features"]
             if row["name"] == "wordpress-review")["name"] = "wordpresx-review"
        self.assert_rejected(wrong, "feature names changed")

    def test_compiled_state_drift_fails_for_selected_and_excluded_features(self):
        cases = [
            ("wordpress-review", "not_compiled"),
            ("api-adapter", "compiled"),
            ("openapi-review", "not_compiled"),
        ]
        for name, state in cases:
            with self.subTest(name=name, state=state):
                document = capabilities()
                next(row for row in document["cli_package_features"]
                     if row["name"] == name)["build_state"] = state
                self.assert_rejected(document, "feature composition")

    def test_malformed_duplicate_and_unknown_feature_rows_fail_closed(self):
        malformed = capabilities()
        malformed["cli_package_features"][0]["build_state"] = "maybe"
        self.assert_rejected(malformed, "invalid or duplicated")

        duplicate = capabilities()
        duplicate["cli_package_features"][-1] = copy.deepcopy(
            duplicate["cli_package_features"][0])
        self.assert_rejected(duplicate, "invalid or duplicated")

        unknown = capabilities()
        unknown["cli_package_features"].append(
            {"name": "future-unclassified-review", "build_state": "not_compiled"})
        self.assert_rejected(unknown, "inventory is incomplete")

    def test_wordpress_surface_state_text_agreement_and_authenticity_are_pinned(self):
        excluded_surface = capabilities()
        next(surface for surface in excluded_surface["surfaces"]
             if surface["key"] == "option.wordpress-review")["build_state"] = "not_compiled"
        self.assert_rejected(excluded_surface, "WordPress surface metadata")

        for field, wrong in [
                ("maturity", "stable"),
                ("implementation_status", "verified"),
                ("kind", "command")]:
            with self.subTest(field=field):
                changed = capabilities()
                next(surface for surface in changed["surfaces"]
                     if surface["key"] == "option.wordpress-review")[field] = wrong
                self.assert_rejected(changed, "WordPress surface metadata")

        implicit = capabilities()
        next(surface for surface in implicit["surfaces"]
             if surface["key"] == "option.wordpress-review")["prerequisites"] = [
                 "--profile web-review"
             ]
        self.assert_rejected(implicit, "explicit opt-in contract")

        document = capabilities()
        text = capabilities_text(document).replace(b"WordPress evidence review", b"other")
        self.assert_rejected(document, "text and JSON views disagree", text)

        overclaim = capabilities()
        overclaim["build_origin_authenticity"] = "authenticated official source"
        self.assert_rejected(overclaim, "overstates build provenance")

    def test_cargo_manifest_features_require_deliberate_classification(self):
        manifest = tomllib.loads(
            (REPOSITORY / "crates/termivar-cli/Cargo.toml").read_text(encoding="utf-8"))
        features = manifest["features"]
        self.assertEqual(cargo_feature_contract_violations(features), [])

        simulated = copy.deepcopy(features)
        simulated["future-unclassified-review"] = []
        self.assertEqual(
            cargo_feature_contract_violations(simulated),
            ["CLI feature inventory requires deliberate classification"],
        )


class ArchiveInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_candidate_archive_helper_reuses_strict_parser_and_extracts_same_bytes(self):
        name = "termivar-main-x86_64-unknown-linux-gnu.tar.gz"
        data = tar_bytes()
        archive = self.root / name
        archive.write_bytes(data)
        output = self.root / "extract"
        result = runner.verify_release_archive.inspect_archive(
            archive, name, "termivar", output)
        self.assertEqual((output / "termivar").read_bytes(), PAYLOAD)
        self.assertEqual(result["archive_sha256"], digest(data))
        self.assertEqual(result["member_sha256"], digest(PAYLOAD))
        self.assertEqual(result["entry_count"], 1)
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_candidate_archive_helper_rejects_extra_member_type_mismatch_and_existing_output(self):
        name = "termivar-main-x86_64-unknown-linux-gnu.tar.gz"
        archive = self.root / name
        archive.write_bytes(tar_bytes(extra=True))
        with self.assertRaises(runner.verify_release_archive.VerificationError):
            runner.verify_release_archive.inspect_archive(archive, name, "termivar")
        archive.write_bytes(tar_bytes())
        with self.assertRaisesRegex(
                runner.verify_release_archive.VerificationError, "inconsistent"):
            runner.verify_release_archive.inspect_archive(archive, name, "termivar.exe")
        output = self.root / "existing"
        output.mkdir()
        marker = output / "marker"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            runner.verify_release_archive.inspect_archive(archive, name, "termivar", output)
        self.assertEqual(marker.read_bytes(), b"preserve")


class CandidateOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.archive = self.root / ARCHIVE_NAME
        self.archive.write_bytes(b"closed synthetic archive fixture")
        self.extract = self.root / "extract"
        self.evidence = self.root / "evidence"
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def inspect(self, archive, expected_archive, expected_member, extract_to=None):
        self.assertEqual(archive, self.archive)
        self.assertEqual(expected_archive, ARCHIVE_NAME)
        self.assertEqual(expected_member, "termivar.exe")
        extract_to.mkdir(mode=0o700)
        binary = extract_to / expected_member
        binary.write_bytes(PAYLOAD)
        return {
            "archive": ARCHIVE_NAME,
            "archive_bytes": self.archive.stat().st_size,
            "archive_sha256": runner.first_use.digest_file(self.archive),
            "entry_count": 1,
            "member": expected_member,
            "member_bytes": len(PAYLOAD),
            "member_sha256": digest(PAYLOAD),
            "extracted": True,
        }

    def execute(self, *, include_ssrf=False, extra_incomplete_request=False,
                omit_progress_help=False, omitted_wordpress_option=None,
                progress_stderr=None, path_suffix=""):
        commands = FakeCommands(
            self.root,
            include_ssrf=include_ssrf,
            extra_incomplete_request=extra_incomplete_request,
            omit_progress_help=omit_progress_help,
            omitted_wordpress_option=omitted_wordpress_option,
            progress_stderr=progress_stderr,
        )
        with mock.patch.object(runner.platform, "system", return_value="Windows"), \
                mock.patch.object(runner.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runner.first_use, "Fixture", FakeFixture), \
                mock.patch.object(runner.first_use, "run_command", side_effect=commands):
            result = runner.run_acceptance(
                self.archive, TARGET, "main", "a" * 40, "123", "1",
                self.root / f"extract{path_suffix}",
                self.root / f"evidence{path_suffix}", TEST_VERSION,
                inspect=self.inspect,
            )
        return result, commands

    def test_full_packaged_acceptance_checks_interfaces_and_application_paths(self):
        result, commands = self.execute()
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["claims"]["native_packaged_binary_executed"])
        self.assertFalse(result["claims"]["candidate_hashes_or_capabilities_authenticate_source"])
        self.assertEqual(
            result["capabilities"]["compiled_members"],
            list(EXPECTED_RELEASE_MEMBERS),
        )
        self.assertEqual(
            result["capabilities"]["excluded_features"],
            list(EXPECTED_EXCLUDED_FEATURES),
        )
        self.assertEqual(result["application"]["bundle_scan_requests"]["root"], 3)
        self.assertEqual(result["application"]["begun_incomplete_requests"], {
            "example": 3, "invalid": 0, "root": 0,
            "unknown": 0, "unsupported": 0,
        })
        self.assertEqual(
            result["application"]["offline_and_preflight_requests"]["capabilities-text"],
            {"example": 0, "invalid": 0, "root": 0, "unknown": 0, "unsupported": 0},
        )
        self.assertEqual(
            result["application"]["offline_and_preflight_requests"]["capabilities-json"],
            {"example": 0, "invalid": 0, "root": 0, "unknown": 0, "unsupported": 0},
        )
        self.assertEqual(result["application"]["synthetic_comparison"]["counts"],
                         runner.SYNTHETIC_COUNTS)
        progress = result["application"]["live_progress"]
        self.assertEqual(progress["channel"], "stderr")
        self.assertEqual(progress["states"][0], "assessment_running")
        self.assertIn("publishing_report", progress["states"])
        self.assertEqual(progress["states"][-1], "completed")
        self.assertEqual(progress["eta_or_finding_claims"], "absent")
        self.assertLessEqual(progress["bytes"], runner.PROGRESS_TOTAL_LIMIT)
        self.assertEqual(result["application"]["verification"], {
            "status": "integrity_match",
            "mismatch_status": "not_verified",
            "mismatch_reason": "payload_digest_mismatch",
        })
        wordpress = result["application"]["wordpress_preview"]
        self.assertEqual(wordpress["inactive"], {
            "wordpress_audit_present": False,
            "wordpress_surface_items": 0,
            "runtime_activation": "not_selected",
        })
        self.assertEqual(wordpress["native_catalogue"]["expected_results"], {
            "within": 2, "outside": 1, "indeterminate": 2,
        })
        self.assertEqual(wordpress["external_absent_profile"]["result_partition"], {
            "within": 0, "outside": 0, "indeterminate": 5,
        })
        self.assertEqual(wordpress["external_explicit_numeric"]["result_partition"], {
            "within": 1, "outside": 1, "indeterminate": 3,
        })
        self.assertEqual(
            wordpress["external_explicit_numeric"]["identity_partition"],
            {
                "exact_identity_associations": 4,
                "candidate_identity_associations": 1,
                "ambiguous_identity_associations": 0,
                "unresolved_identity_associations": 1,
            },
        )
        self.assertTrue(wordpress["offline_commands_after_fixture_shutdown"])
        self.assertTrue(wordpress["inputs_preserved"])
        self.assertEqual(set(wordpress["bundle_verification"].values()),
                         {"integrity_match"})
        self.assertEqual(wordpress["self_comparison"]["advisory_differences"], 0)
        self.assertEqual(
            wordpress["controlled_comparison"]["paired_advisory_differences"], 5)
        self.assertEqual([path.name for path in self.evidence.iterdir()], [runner.EVIDENCE_NAME])
        stored = json.loads((self.evidence / runner.EVIDENCE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(stored, result)
        encoded = json.dumps(result)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn("127.0.0.1", encoded)
        self.assertLessEqual(len(runner._encode_evidence(result)), runner.EVIDENCE_LIMIT)
        self.assertEqual(len(commands.arguments), 27)
        self.assertEqual(runner.first_use.digest_file(self.archive),
                         result["archive"]["archive_sha256"])

    def test_wrong_release_composition_fails_with_bounded_evidence(self):
        result, _ = self.execute(include_ssrf=True)
        self.assertEqual(result["status"], "failed")
        self.assertIn("feature composition", result["failure"])
        self.assertFalse(result["claims"]["native_packaged_binary_executed"])
        self.assertEqual([path.name for path in self.evidence.iterdir()], [runner.EVIDENCE_NAME])
        self.assertLessEqual((self.evidence / runner.EVIDENCE_NAME).stat().st_size,
                             runner.EVIDENCE_LIMIT)

    def test_extra_incomplete_request_category_fails_acceptance(self):
        result, _ = self.execute(extra_incomplete_request=True)
        self.assertEqual(result["status"], "failed")
        self.assertIn("begun-incomplete scan request trace", result["failure"])

    def test_packaged_help_must_expose_opted_in_progress(self):
        result, _ = self.execute(omit_progress_help=True)
        self.assertEqual(result["status"], "failed")
        self.assertIn("scan help omits --progress", result["failure"])

    def test_packaged_help_must_expose_every_bundled_wordpress_option(self):
        for index, option in enumerate((
            "--wordpress-review",
            "--wordpress-context",
            "--wordpress-advisories",
            "--wordpress-advisories-format",
            "--wordpress-external-version-profile",
            "--wordpress-plugins-json",
            "--wordpress-themes-json",
            "--wordpress-core-version-file",
        )):
            with self.subTest(option=option):
                result, _ = self.execute(
                    omitted_wordpress_option=option,
                    path_suffix=f"-wordpress-help-{index}",
                )
                self.assertEqual(result["status"], "failed")
                self.assertIn("omits bundled WordPress option", result["failure"])

    def test_packaged_progress_must_have_bounded_complete_lifecycle(self):
        malformed = (
            b"[progress] state=completed elapsed_ms=1 accounted_requests=3 "
            b"accounted_active_verifications=0 subjects_started=1 subjects_processed=1 "
            b"counts=last_observed\n"
        )
        result, _ = self.execute(progress_stderr=malformed)
        self.assertEqual(result["status"], "failed")
        self.assertIn("progress lifecycle changed", result["failure"])

    def test_packaged_progress_rejects_running_regression_after_composition(self):
        composing = VALID_PROGRESS.index(b"[progress] state=composing_report")
        rendering = VALID_PROGRESS.index(b"[progress] state=rendering_report")
        regressed = (
            VALID_PROGRESS[:rendering]
            + VALID_PROGRESS[:composing]
            + VALID_PROGRESS[rendering:]
        )
        result, _ = self.execute(progress_stderr=regressed)
        self.assertEqual(result["status"], "failed")
        self.assertIn("progress lifecycle changed", result["failure"])

    def test_caller_supplied_version_selects_main_or_matching_tag_identity(self):
        for version, archive_ref in [
                ("0.10.0-alpha.2", "v0.10.0-alpha.2"),
                (TEST_VERSION, "main")]:
            suffix = runner.TARGETS[TARGET]["suffix"]
            archive = self.root / f"termivar-{archive_ref}-{TARGET}{suffix}"
            self.assertEqual(
                runner._candidate_identity(archive, TARGET, archive_ref, version),
                (archive.name, "termivar.exe"),
            )
        mismatched = self.root / f"termivar-v0.10.0-alpha.2-{TARGET}.zip"
        with self.assertRaisesRegex(runner.AcceptanceError, "exact candidate tag"):
            runner._candidate_identity(
                mismatched, TARGET, "v0.10.0-alpha.2", TEST_VERSION)
        for invalid in ("01.2.3", "1.2.3-..", "1.2", "v1.2.3", "1.2.3/other"):
            with self.subTest(invalid=invalid), \
                    self.assertRaisesRegex(runner.AcceptanceError, "valid package version"):
                runner._candidate_identity(self.archive, TARGET, "main", invalid)

    def test_packaged_identity_must_match_caller_supplied_version(self):
        commands = FakeCommands(self.root)
        with mock.patch.object(runner.platform, "system", return_value="Windows"), \
                mock.patch.object(runner.platform, "machine", return_value="AMD64"), \
                mock.patch.object(runner.first_use, "Fixture", FakeFixture), \
                mock.patch.object(runner.first_use, "run_command", side_effect=commands):
            result = runner.run_acceptance(
                self.archive, TARGET, "main", "a" * 40, "123", "1",
                self.root / "extract-alpha2", self.root / "evidence-alpha2",
                "0.10.0-alpha.2", inspect=self.inspect,
            )
        self.assertEqual(result["status"], "failed")
        self.assertIn("caller", result["failure"])

    def test_directory_entry_limits_reject_before_unbounded_materialization(self):
        crowded_parent = self.root / "crowded"
        crowded_parent.mkdir()
        archive = crowded_parent / ARCHIVE_NAME
        archive.write_bytes(b"candidate")
        for index in range(runner.MAX_PARENT_ENTRIES):
            (crowded_parent / f"entry-{index:03}").write_bytes(b"x")
        with self.assertRaisesRegex(runner.AcceptanceError, "bounded entry count"):
            runner._assert_single_candidate_archive(archive)

        crowded_bundle = self.root / "crowded-bundle"
        crowded_bundle.mkdir()
        for index in range(9):
            (crowded_bundle / f"entry-{index:02}").write_bytes(b"x")
        with self.assertRaisesRegex(runner.AcceptanceError, "bounded entry count"):
            runner._snapshot_files(crowded_bundle)

    def test_preflight_rejects_identity_overlap_extra_candidate_and_proxy(self):
        cases = [
            {"source_sha": "A" * 40},
            {"archive_ref": "feature-branch"},
            {"expected_version": "not-a-version"},
            {"run_id": "0"},
            {"extract": self.evidence, "evidence": self.evidence},
        ]
        for index, overrides in enumerate(cases):
            with self.subTest(index=index):
                extract = overrides.get("extract", self.root / f"extract-{index}")
                evidence = overrides.get("evidence", self.root / f"evidence-{index}")
                with mock.patch.object(runner.platform, "system", return_value="Windows"), \
                        mock.patch.object(runner.platform, "machine", return_value="AMD64"):
                    with self.assertRaises(runner.AcceptanceError):
                        runner.run_acceptance(
                            self.archive, TARGET, overrides.get("archive_ref", "main"),
                            overrides.get("source_sha", "a" * 40),
                            overrides.get("run_id", "1"), "1", extract, evidence,
                            overrides.get("expected_version", TEST_VERSION),
                            inspect=self.inspect,
                        )
        other = self.root / "termivar-main-x86_64-unknown-linux-gnu.tar.gz"
        other.write_bytes(b"other")
        with mock.patch.object(runner.platform, "system", return_value="Windows"), \
                mock.patch.object(runner.platform, "machine", return_value="AMD64"):
            with self.assertRaisesRegex(runner.AcceptanceError, "exactly one"):
                runner.run_acceptance(
                    self.archive, TARGET, "main", "a" * 40, "1", "1",
                    self.root / "extract-extra", self.root / "evidence-extra",
                    TEST_VERSION, inspect=self.inspect)
        other.unlink()
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "configured"}, clear=True):
            with self.assertRaisesRegex(runner.AcceptanceError, "proxy"):
                runner.run_acceptance(
                    self.archive, TARGET, "main", "a" * 40, "1", "1",
                    self.root / "extract-proxy", self.root / "evidence-proxy",
                    TEST_VERSION, inspect=self.inspect)

    def test_cli_contract_uses_one_primary_evidence_file_and_failure_exit(self):
        failed = {"schema": runner.SCHEMA, "status": "failed"}
        with mock.patch.object(runner, "run_acceptance", return_value=failed), \
                mock.patch.object(runner.sys, "stdout") as stdout:
            stdout.buffer = io.BytesIO()
            exit_code = runner.main([
                "--archive", str(self.archive), "--target", TARGET,
                "--archive-ref", "main", "--source-sha", "a" * 40,
                "--run-id", "1", "--run-attempt", "1",
                "--extract-to", str(self.extract), "--evidence-dir", str(self.evidence),
                "--expect-version", TEST_VERSION,
            ])
        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(stdout.buffer.getvalue()), failed)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                runner.main(["--unknown"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
