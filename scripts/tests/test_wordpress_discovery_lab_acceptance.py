import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY_ROOT / "scripts" / "wordpress_discovery_lab_acceptance.py"
SPEC = importlib.util.spec_from_file_location("wordpress_discovery_lab_acceptance", MODULE_PATH)
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)


BASE_FINGERPRINT = "sha256:" + "1" * 64
DISCOVERY_FINGERPRINT = "sha256:" + "2" * 64
BASE_CAPABILITY = "technology.wordpress-surface-observed@1"
DISCOVERY_CAPABILITY = "technology.wordpress-metadata-source-response-observed@1"
APPLICATION_REFERENCE = "sha256:" + "a" * 64
REST_REFERENCE = "sha256:" + "b" * 64
THEME_REFERENCE = "sha256:" + "c" * 64
PLUGIN_REFERENCE = "sha256:" + "d" * 64
DISCOVERY_METHOD = {
    "schema": "security.wordpress-discovery-audit/v2",
    "capability_id": "technology.wordpress-metadata-discovery@1",
    "policy_id": "termivar.wordpress-deployment-aware-metadata-discovery/v1",
    "selected": True,
    "method": "get",
    "credential_mode": "anonymous",
    "layout_roles": [
        {"role": "core", "basis": "none"},
        {"role": "themes", "basis": "none"},
        {"role": "plugins", "basis": "none"},
        {"role": "rest_index", "basis": "structured_advertisement"},
    ],
}
BEFORE_METHOD = {"schema": "security.wordpress-review-audit/v1"}
AFTER_METHOD = {
    "schema": "security.wordpress-review-audit/v7",
    "review_basis_schema": "security.wordpress-review-audit/v1",
    "wordpress_discovery": DISCOVERY_METHOD,
}
BEFORE_COVERAGE = {
    "catalog_status": "catalogue_not_supplied",
    "signal_count": 1,
    "evidence_reference_count": 1,
    "item_projected": True,
    "component_count": 1,
    "advisory_count": 0,
}
AFTER_COVERAGE = {
    **BEFORE_COVERAGE,
    "additional_request_count": 1,
    "wordpress_discovery": {
        "seed_count": 1,
        "candidate_count": 1,
        "candidate_limit_reached": False,
        "omitted_candidate_count": 0,
        "attempted_request_count": 1,
        "completed_response_count": 1,
        "committed_response_count": 1,
        "response_bytes": 16,
        "source_count": 1,
        "source_outcomes": [{
            "kind": "rest_index",
            "parent_depth": 0,
            "outcome": "observed",
            "request_attempted": True,
            "response_bytes": 16,
            "evidence_reference_count": 1,
            "association": "structured_advertisement",
            "resource_reference": "sha256:" + "e" * 64,
            "role_reference": REST_REFERENCE,
        }],
        "layout_roles": [
            {"role": "core", "status": "unresolved", "candidate_count": 0},
            {"role": "themes", "status": "unresolved", "candidate_count": 0},
            {"role": "plugins", "status": "unresolved", "candidate_count": 0},
            {"role": "rest_index", "status": "exact", "candidate_count": 1},
        ],
        "skipped_foreign_origin_count": 0,
        "skipped_sibling_application_count": 0,
        "conflicting_association_count": 0,
    },
}
DISCOVERY_CONTENT = {"rest_indexes": [{
    "kind": "rest_index",
    "namespaces": ["wp/v2"],
    "association": "structured_advertisement",
    "resource_reference": "sha256:" + "e" * 64,
    "role_reference": REST_REFERENCE,
}]}


def synthetic_assessment_item(fingerprint, capability_id, title):
    return {
        "schema": "venom-assessment-item/v1",
        "capability_id": capability_id,
        "subject_reference": "subject-0000",
        "title": title,
        "disposition": "informational",
        "claim_basis": "observation",
        "severity": None,
        "confidence_ppm": 550_000,
        "fingerprint": fingerprint,
        "evidence_count": 1,
        "redacted_summary": "Synthetic acceptance observation.",
        "category": "synthetic-acceptance",
        "cwe": None,
        "remediation": {
            "id": "synthetic.remediation@1",
            "summary": "Review the synthetic acceptance observation.",
        },
        "evidence_references": ["evidence-0000"],
        "control_evidence_references": [],
        "candidate_evidence_references": [],
        "case_reference": None,
        "outcome_reference": None,
        "verification_stage": None,
    }


def synthetic_discovery_item(capability_id=DISCOVERY_CAPABILITY):
    item = synthetic_assessment_item(
        DISCOVERY_FINGERPRINT,
        capability_id,
        "WordPress metadata-source response outcome observed",
    )
    item.update({
        "category": "wordpress-metadata-source-response",
        "redacted_summary": (
            "Bounded response evidence from selected public WordPress metadata "
            "sources was collected; usable metadata, installation authenticity, "
            "vulnerable-code reachability, and advisory impact were not established."
        ),
        "remediation": {
            "id": "wordpress-metadata-review",
            "summary": (
                "Confirm the installation inventory and source-qualified metadata "
                "before making a security or remediation decision."
            ),
        },
        "evidence_references": ["evidence-0001"],
    })
    return item


def synthetic_assessment(items, *, item_count=None, optional_audits=None):
    document = {
        "schema": "venom-rendered-assessment/v1",
        "source_schema": "venom-assessment-run/v1",
        "run_schema": "venom-run/v1",
        "profile_schema": "venom.scan-profile/v1",
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": len(items) if item_count is None else item_count,
        "items": items,
    }
    document.update(copy.deepcopy(optional_audits or {}))
    return document


def synthetic_projection(title):
    return {
        "title": title,
        "category": "synthetic-acceptance",
        "disposition": "informational",
        "claim_basis": "observation",
        "severity": None,
        "cwe": None,
        "confidence_ppm": 550_000,
        "redacted_summary": "Synthetic acceptance observation.",
        "remediation": {
            "id": "synthetic.remediation@1",
            "summary": "Review the synthetic acceptance observation.",
        },
        "evidence": {
            "evidence_count": 1,
            "evidence_reference_count": 1,
            "control_reference_count": 0,
            "candidate_reference_count": 0,
            "case_present": False,
            "outcome_present": False,
            "verification_stage": None,
        },
    }


def projection_from_item(item):
    return {
        "title": item["title"],
        "category": item["category"],
        "disposition": item["disposition"],
        "claim_basis": item["claim_basis"],
        "severity": item["severity"],
        "cwe": item["cwe"],
        "confidence_ppm": item["confidence_ppm"],
        "redacted_summary": item["redacted_summary"],
        "remediation": copy.deepcopy(item["remediation"]),
        "evidence": {
            "evidence_count": item["evidence_count"],
            "evidence_reference_count": len(item["evidence_references"]),
            "control_reference_count": len(item["control_evidence_references"]),
            "candidate_reference_count": len(item["candidate_evidence_references"]),
            "case_present": item["case_reference"] is not None,
            "outcome_present": item["outcome_reference"] is not None,
            "verification_stage": item["verification_stage"],
        },
    }


def comparison_item(
    fingerprint,
    capability_id,
    *,
    before,
    after,
    changed_fields,
):
    return {
        "fingerprint": fingerprint,
        "capability_id": capability_id,
        "before": before,
        "after": after,
        "changed_fields": changed_fields,
    }


def source_metadata(raw, item_count):
    document = json.loads(raw)
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "schema": "venom-rendered-assessment/v1",
        "source_schema": "venom-assessment-run/v1",
        "run_schema": "venom-run/v1",
        "profile_schema": "venom.scan-profile/v1",
        "profile": "web-review",
        "status": "complete",
        "subject_count": 1,
        "item_count": item_count,
        "optional_audits": {
            field: document[field]
            for field in runner.OPTIONAL_AUDIT_FIELDS
            if field in document
        },
    }


def wordpress_comparison(*, discovery, controlled):
    def facet(status, changed_fields, before, after):
        return {
            "status": status,
            "changed_fields": changed_fields,
            "before": copy.deepcopy(before),
            "after": copy.deepcopy(after),
            "note": "Synthetic acceptance facet.",
        }

    empty_entities = {
        "paired_unchanged_count": 0 if controlled else 1,
        "paired_changed": [],
        "only_in_before": [],
        "only_in_after": [],
    }
    if controlled:
        method_before, method_after = BEFORE_METHOD, AFTER_METHOD
        coverage_before, coverage_after = BEFORE_COVERAGE, AFTER_COVERAGE
        method_fields = ["review_basis_schema", "schema", "wordpress_discovery"]
        coverage_fields = ["additional_request_count", "wordpress_discovery"]
    elif discovery:
        method_before = method_after = AFTER_METHOD
        coverage_before = coverage_after = AFTER_COVERAGE
        method_fields = []
        coverage_fields = []
    else:
        method_before = method_after = BEFORE_METHOD
        coverage_before = coverage_after = BEFORE_COVERAGE
        method_fields = []
        coverage_fields = []
    comparison = {
        "schema": (
            "termivar-wordpress-review-comparison/v2"
            if discovery else "termivar-wordpress-review-comparison/v1"
        ),
        "status": "not_compared" if controlled else "compared",
        "scope_assurance": "operator-declared",
        "coverage": facet(
            "changed" if controlled else "not_established",
            coverage_fields,
            coverage_before,
            coverage_after,
        ),
        "methodology": facet(
            "changed" if controlled else "unchanged",
            method_fields,
            method_before,
            method_after,
        ),
        "provenance": facet("unchanged", [], {}, {}),
        "components": copy.deepcopy(empty_entities),
        "advisories": {
            "paired_unchanged_count": 0,
            "paired_changed": [],
            "only_in_before": [],
            "only_in_after": [],
        },
        "interpretation_limits": [],
    }
    if controlled:
        comparison["reason"] = "application_scope_unknown"
    if discovery:
        comparison["discovery_source_content"] = (
            facet("not_comparable", ["audit_presence"], None, DISCOVERY_CONTENT)
            if controlled else
            facet("unchanged", [], DISCOVERY_CONTENT, DISCOVERY_CONTENT)
        )
    return comparison


def comparison_document(before_raw, before_count, after_raw, after_count, *, groups):
    return {
        "schema": "termivar-report-comparison/v1",
        "scope_assurance": "operator-declared",
        "coverage_equivalence": "not-established",
        "source_authenticity": "not-established-by-parsing",
        "interpretation_limits": [],
        "before": source_metadata(before_raw, before_count),
        "after": source_metadata(after_raw, after_count),
        **groups,
    }


class OfflineProcessRunner:
    def __init__(self, responses, expected_arguments, *, after_run=None):
        self.responses = responses
        self.expected_arguments = expected_arguments
        self.after_run = after_run
        self.calls = []

    def run(self, arguments, *, label, **_kwargs):
        argv = [str(argument) for argument in arguments]
        self.calls.append((label, argv))
        if label not in self.responses:
            raise AssertionError(f"unexpected synthetic command: {label}: {argv!r}")
        if argv != self.expected_arguments[label]:
            raise AssertionError(
                f"unexpected arguments for {label}: {argv!r}"
            )
        if self.after_run is not None:
            self.after_run(label)
        return runner.CommandResult(
            json.dumps(self.responses[label], separators=(",", ":")).encode("utf-8"),
            b"",
            0,
        )


def write_synthetic_bundle(root, name, items, *, item_count=None, optional_audits=None):
    bundle = root / name
    bundle.mkdir()
    raw = json.dumps(
        synthetic_assessment(
            items, item_count=item_count, optional_audits=optional_audits
        ),
        separators=(",", ":"),
    ).encode("utf-8")
    html = b"<!doctype html><title>Synthetic Termivar assessment</title>"
    (bundle / "assessment.json").write_bytes(raw)
    (bundle / "assessment.html").write_bytes(html)
    manifest = {
        "schema": "termivar-report-bundle/v1",
        "producer": {"product": "Termivar", "version": "0.10.0-alpha.3"},
        "assessment": {
            "profile": "web-review",
            "status": "complete",
            "subject_count": 1,
            "item_count": len(items) if item_count is None else item_count,
        },
        "files": [
            {
                "name": "assessment.html",
                "format": "html",
                "media_type": "text/html; charset=utf-8",
                "byte_length": len(html),
                "sha256": hashlib.sha256(html).hexdigest(),
            },
            {
                "name": "assessment.json",
                "format": "json",
                "media_type": "application/json",
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            },
        ],
    }
    (bundle / "manifest.json").write_bytes(
        json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    )
    return bundle, raw


def self_comparison(raw, items):
    unchanged = []
    for item in items:
        projection = projection_from_item(item)
        unchanged.append(comparison_item(
            item["fingerprint"],
            item["capability_id"],
            before=projection,
            after=copy.deepcopy(projection),
            changed_fields=[],
        ))
    result = comparison_document(
        raw,
        len(items),
        raw,
        len(items),
        groups={
            "only_in_after": [],
            "only_in_before": [],
            "changed": [],
            "unchanged": unchanged,
        },
    )
    assessment = json.loads(raw)
    if "wordpress_review" in assessment:
        discovery = "wordpress_discovery" in assessment
        result["wordpress_review_comparison"] = wordpress_comparison(
            discovery=discovery,
            controlled=False,
        )
    return result


def expected_offline_arguments(scenarios):
    binary = "synthetic-termivar"
    expected = {}
    for name, scenario in scenarios.items():
        bundle = Path(scenario["_bundle"])
        expected[f"offline verification {name}"] = [
            binary, "report", "verify", "--dir", str(bundle), "--format", "json",
        ]
        expected[f"offline self comparison {name}"] = [
            binary, "report", "compare", "--before", str(bundle / "assessment.json"),
            "--after", str(bundle / "assessment.json"), "--same-scope", "--format", "json",
        ]
    before = Path(scenarios["pretty-review-only"]["_bundle"])
    after = Path(scenarios["pretty-discovery"]["_bundle"])
    expected["offline collection-policy comparison"] = [
        binary, "report", "compare", "--before", str(before / "assessment.json"),
        "--after", str(after / "assessment.json"), "--same-scope", "--format", "json",
    ]
    if {"custom-no-layout-discovery", "custom-layout-discovery"} <= scenarios.keys():
        before = Path(scenarios["custom-no-layout-discovery"]["_bundle"])
        after = Path(scenarios["custom-layout-discovery"]["_bundle"])
        expected["offline custom layout comparison"] = [
            binary, "report", "compare", "--before", str(before / "assessment.json"),
            "--after", str(after / "assessment.json"), "--same-scope", "--format", "json",
        ]
    if {"blog-pretty-discovery", "custom-layout-discovery"} <= scenarios.keys():
        before = Path(scenarios["blog-pretty-discovery"]["_bundle"])
        after = Path(scenarios["custom-layout-discovery"]["_bundle"])
        expected["offline application-scope mismatch comparison"] = [
            binary, "report", "compare", "--before", str(before / "assessment.json"),
            "--after", str(after / "assessment.json"), "--same-scope", "--format", "json",
        ]
    return expected


def offline_process_runner(responses, scenarios, *, after_run=None):
    return OfflineProcessRunner(
        responses,
        expected_offline_arguments(scenarios),
        after_run=after_run,
    )


def offline_fixture(root, *, discovery_capability=DISCOVERY_CAPABILITY):
    base_item = synthetic_assessment_item(
        BASE_FINGERPRINT, BASE_CAPABILITY, "WordPress surface hints observed"
    )
    base_item.update({
        "category": "technology-observation",
        "redacted_summary": (
            "The root response contained bounded structured WordPress hints; "
            "installation authenticity and advisory impact were not established."
        ),
        "remediation": {
            "id": "wordpress-inventory-review",
            "summary": (
                "Review supplied WordPress context and advisory applicability "
                "independently."
            ),
        },
    })
    after_base_item = copy.deepcopy(base_item)
    after_base_item["title"] = "WordPress surface hints observed after policy change"
    discovery_item = synthetic_discovery_item(discovery_capability)
    core_component = {
        "identity": {"kind": "core", "slug": "wordpress"},
        "evidence_class": "observed_hint",
        "identity_sources": ["generator_metadata"],
        "confidence_classes": ["public_declaration"],
        "versions": [{
            "value": "6.9.4",
            "source": "generator_metadata",
            "confidence": "public_declaration",
        }],
        "activation": None,
    }
    before_audits = {
        "wordpress_review": {
            "schema": "security.wordpress-review-audit/v1",
            "capability_id": BASE_CAPABILITY,
            "catalog_status": "catalogue_not_supplied",
            "signal_count": 1,
            "evidence_reference_count": 1,
            "additional_request_count": 0,
            "item_projected": True,
            "component_count": 1,
            "advisory_count": 0,
            "components": [copy.deepcopy(core_component)],
            "advisories": [],
        },
    }
    after_audits = {
        "wordpress_review": {
            "schema": "security.wordpress-review-audit/v7",
            "review_basis_schema": "security.wordpress-review-audit/v1",
            "capability_id": BASE_CAPABILITY,
            "catalog_status": "catalogue_not_supplied",
            "signal_count": 1,
            "evidence_reference_count": 1,
            "additional_request_count": 1,
            "item_projected": True,
            "component_count": 1,
            "advisory_count": 0,
            "components": [copy.deepcopy(core_component)],
            "advisories": [],
        },
        "wordpress_discovery": {
            "schema": "security.wordpress-discovery-audit/v2",
            "capability_id": "technology.wordpress-metadata-discovery@1",
            "policy_id": "termivar.wordpress-deployment-aware-metadata-discovery/v1",
            "selected": True,
            "method": "get",
            "credential_mode": "anonymous",
            "seed_count": 1,
            "candidate_count": 1,
            "candidate_limit_reached": False,
            "omitted_candidate_count": 0,
            "attempted_request_count": 1,
            "completed_response_count": 1,
            "committed_response_count": 1,
            "response_bytes": 16,
            "source_count": 1,
            "layout": {
                "application_reference": APPLICATION_REFERENCE,
                "roles": [
                    {"role": "core", "status": "unresolved", "basis": "none",
                     "candidate_count": 0},
                    {"role": "themes", "status": "unresolved", "basis": "none",
                     "candidate_count": 0},
                    {"role": "plugins", "status": "unresolved", "basis": "none",
                     "candidate_count": 0},
                    {"role": "rest_index", "status": "exact",
                     "basis": "structured_advertisement", "reference": REST_REFERENCE,
                     "candidate_count": 1},
                ],
                "skipped_foreign_origin_count": 0,
                "skipped_sibling_application_count": 0,
                "conflicting_association_count": 0,
            },
            "sources": [{
                "kind": "rest_index",
                "association": "structured_advertisement",
                "resource_reference": "sha256:" + "e" * 64,
                "role_reference": REST_REFERENCE,
                "parent_depth": 0,
                "outcome": "observed",
                "request_attempted": True,
                "response_bytes": 16,
                "evidence_reference_count": 1,
                "evidence_references": ["evidence-0001"],
                "namespaces": ["wp/v2"],
            }],
        },
    }
    before_bundle, before_raw = write_synthetic_bundle(
        root, "pretty-review-only", [base_item], optional_audits=before_audits
    )
    after_bundle, after_raw = write_synthetic_bundle(
        root, "pretty-discovery", [after_base_item, discovery_item],
        optional_audits=after_audits,
    )
    controlled = comparison_document(
        before_raw,
        1,
        after_raw,
        2,
        groups={
            "only_in_after": [comparison_item(
                DISCOVERY_FINGERPRINT,
                discovery_capability,
                before=None,
                after=projection_from_item(discovery_item),
                changed_fields=[],
            )],
            "only_in_before": [],
            "changed": [comparison_item(
                BASE_FINGERPRINT,
                BASE_CAPABILITY,
                before=projection_from_item(base_item),
                after=projection_from_item(after_base_item),
                changed_fields=["title"],
            )],
            "unchanged": [],
        },
    )
    controlled["wordpress_review_comparison"] = wordpress_comparison(
        discovery=True,
        controlled=True,
    )
    responses = {
        "offline verification pretty-review-only": {
            "schema": "termivar-report-verification/v1",
            "status": "integrity_match",
        },
        "offline self comparison pretty-review-only": self_comparison(
            before_raw, [base_item]
        ),
        "offline verification pretty-discovery": {
            "schema": "termivar-report-verification/v1",
            "status": "integrity_match",
        },
        "offline self comparison pretty-discovery": self_comparison(
            after_raw, [after_base_item, discovery_item]
        ),
        "offline collection-policy comparison": controlled,
    }
    scenarios = {
        "pretty-review-only": {
            "bundle": runner._report_identity(before_bundle),
            "_bundle": str(before_bundle),
        },
        "pretty-discovery": {
            "bundle": runner._report_identity(after_bundle),
            "_bundle": str(after_bundle),
        },
    }
    return scenarios, responses, (before_raw, after_raw)


def layout_offline_fixture(root):
    scenarios, responses, originals = offline_fixture(root)
    items = [
        synthetic_assessment_item(
            BASE_FINGERPRINT, BASE_CAPABILITY, "WordPress surface hints observed"
        ),
        synthetic_discovery_item(),
    ]

    def audit(application_reference, declared):
        return {
            "wordpress_review": {
                "schema": "security.wordpress-review-audit/v7",
                "review_basis_schema": "security.wordpress-review-audit/v1",
            },
            "wordpress_discovery": {
                "schema": "security.wordpress-discovery-audit/v2",
                "layout": {
                    "application_reference": application_reference,
                    "declaration": declared,
                },
            },
        }

    raw_by_name = {}
    for name, application_reference, declared in (
        ("custom-no-layout-discovery", APPLICATION_REFERENCE, None),
        ("custom-layout-discovery", APPLICATION_REFERENCE, {"sha256": "f" * 64}),
        ("blog-pretty-discovery", "sha256:" + "9" * 64, None),
    ):
        bundle, raw = write_synthetic_bundle(
            root, name, copy.deepcopy(items),
            optional_audits=audit(application_reference, declared),
        )
        scenarios[name] = {
            "bundle": runner._report_identity(bundle),
            "_bundle": str(bundle),
            "layout_application_reference": application_reference,
        }
        raw_by_name[name] = raw
        responses[f"offline verification {name}"] = {
            "schema": "termivar-report-verification/v1",
            "status": "integrity_match",
        }
        responses[f"offline self comparison {name}"] = self_comparison(raw, items)

    def unchanged_groups():
        rows = []
        for item in items:
            projection = projection_from_item(item)
            rows.append(comparison_item(
                item["fingerprint"], item["capability_id"], before=projection,
                after=copy.deepcopy(projection), changed_fields=[],
            ))
        return {
            "only_in_after": [], "only_in_before": [], "changed": [],
            "unchanged": rows,
        }

    custom = comparison_document(
        raw_by_name["custom-no-layout-discovery"], 2,
        raw_by_name["custom-layout-discovery"], 2,
        groups=unchanged_groups(),
    )
    custom_wordpress = wordpress_comparison(discovery=True, controlled=False)
    for facet_name in ("methodology", "coverage"):
        facet = custom_wordpress[facet_name]
        facet.update({
            "status": "changed",
            "before": {"layout": "unresolved"},
            "after": {"layout": "operator_declaration"},
            "changed_fields": ["layout"],
        })
    custom["wordpress_review_comparison"] = custom_wordpress
    responses["offline custom layout comparison"] = custom

    mismatch = comparison_document(
        raw_by_name["blog-pretty-discovery"], 2,
        raw_by_name["custom-layout-discovery"], 2,
        groups=unchanged_groups(),
    )
    mismatch_wordpress = wordpress_comparison(discovery=True, controlled=False)
    mismatch_wordpress.update({
        "status": "not_compared",
        "reason": "application_scope_mismatch",
    })
    mismatch_wordpress["components"] = {
        "paired_unchanged_count": 0, "paired_changed": [],
        "only_in_before": [], "only_in_after": [],
    }
    mismatch_wordpress["advisories"] = copy.deepcopy(
        mismatch_wordpress["components"]
    )
    mismatch["wordpress_review_comparison"] = mismatch_wordpress
    responses["offline application-scope mismatch comparison"] = mismatch
    return scenarios, responses, originals


class WordPressDiscoveryLabAcceptanceTests(unittest.TestCase):
    def test_discovery_capability_uses_the_real_prerequisites_wire_field(self):
        document = {
            "schema": "termivar-cli-capabilities/v1",
            "surfaces": [{
                "key": "option.wordpress-discovery",
                "build_state": "compiled",
                "compile_feature": "wordpress-review",
                "implementation_status": "implemented",
                "prerequisites": [
                    "--profile web-review",
                    "--wordpress-review",
                    "--wordpress-discovery",
                    "optional --wordpress-layout FILE",
                ],
            }]
        }

        runner._validate_discovery_capability(document)

        wrong_field = copy.deepcopy(document)
        prerequisites = wrong_field["surfaces"][0].pop("prerequisites")
        wrong_field["surfaces"][0]["required_inputs"] = prerequisites
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "capabilities do not report compiled WordPress discovery",
        ):
            runner._validate_discovery_capability(wrong_field)

    def test_discovery_capability_rejects_missing_duplicate_or_uncompiled_rows(self):
        valid_row = {
            "key": "option.wordpress-discovery",
            "build_state": "compiled",
            "compile_feature": "wordpress-review",
            "implementation_status": "implemented",
            "prerequisites": [
                "--profile web-review",
                "--wordpress-review",
                "--wordpress-discovery",
                "optional --wordpress-layout FILE",
            ],
        }
        cases = (
            (
                {"schema": "termivar-cli-capabilities/v1"},
                "capabilities surfaces must be an array",
            ),
            (
                {"schema": "other", "surfaces": []},
                "capabilities schema is unsupported",
            ),
            (
                {"schema": "termivar-cli-capabilities/v1", "surfaces": []},
                "exactly one WordPress discovery surface",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [valid_row, copy.deepcopy(valid_row)],
                },
                "exactly one WordPress discovery surface",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{**valid_row, "build_state": "not_compiled"}],
                },
                "compiled WordPress discovery",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{**valid_row, "prerequisites": None}],
                },
                "compiled WordPress discovery",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{**valid_row, "prerequisites": []}],
                },
                "compiled WordPress discovery",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{
                        **valid_row,
                        "prerequisites": valid_row["prerequisites"][:-1],
                    }],
                },
                "compiled WordPress discovery",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{
                        **valid_row,
                        "prerequisites": valid_row["prerequisites"]
                        + ["optional --wordpress-layout FILE"],
                    }],
                },
                "compiled WordPress discovery",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{**valid_row, "compile_feature": "other"}],
                },
                "compiled WordPress discovery",
            ),
            (
                {
                    "schema": "termivar-cli-capabilities/v1",
                    "surfaces": [{
                        **valid_row,
                        "implementation_status": "planned",
                    }],
                },
                "compiled WordPress discovery",
            ),
        )
        for document, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(runner.AcceptanceError, message):
                    runner._validate_discovery_capability(document)

    def test_nonroot_trace_baseline_is_ordinary_typed_incomplete_web_review(self):
        process = mock.Mock()
        diagnostic = {
            "schema_version": "web-assessment/v2",
            "disposition": "incomplete",
            "incomplete_reasons": ["synthetic non-root subject"],
            "assessment": {
                "report": {
                    "assessment_items": {"projection_status": "unavailable"}
                }
            },
        }
        process.run.return_value = runner.CommandResult(
            json.dumps(diagnostic, separators=(",", ":")).encode("utf-8"),
            b"progress\n",
            1,
            0.125,
            {"status": "not_measured", "reason": "synthetic"},
        )

        measured = runner._run_nonroot_trace_baseline(
            process,
            Path("synthetic-termivar"),
            "http://127.0.0.1:8080/blog/",
            label="synthetic non-root baseline",
        )

        process.run.assert_called_once_with(
            [
                Path("synthetic-termivar"),
                "scan",
                "http://127.0.0.1:8080/blog/",
                "--profile",
                "web-review",
                "--format",
                "json",
                "--progress",
            ],
            expected=1,
            label="synthetic non-root baseline",
            timeout=300,
            measure_peak_memory=True,
        )
        self.assertEqual(measured["exit_code"], 1)
        self.assertTrue(measured["typed_incomplete"])
        self.assertEqual(measured["diagnostic_schema"], "web-assessment/v2")
        self.assertEqual(measured["incomplete_reason_count"], 1)
        self.assertEqual(measured["elapsed_milliseconds"], 125.0)

    def test_nonroot_trace_baseline_rejects_other_exit_one_diagnostics(self):
        valid = {
            "schema_version": "web-assessment/v2",
            "disposition": "incomplete",
            "incomplete_reasons": ["synthetic non-root subject"],
            "assessment": {
                "report": {
                    "assessment_items": {"projection_status": "unavailable"}
                }
            },
        }
        malformed = [
            {**valid, "schema_version": "web-assessment/v1"},
            {**valid, "disposition": "failed"},
            {**valid, "incomplete_reasons": []},
            {**valid, "incomplete_reasons": "synthetic"},
            {**valid, "assessment": {}},
            {
                **valid,
                "assessment": {
                    "report": {
                        "assessment_items": {
                            "projection_status": "available",
                            "items": [],
                        }
                    }
                },
            },
        ]
        for diagnostic in malformed:
            with self.subTest(diagnostic=diagnostic):
                process = mock.Mock()
                process.run.return_value = runner.CommandResult(
                    json.dumps(diagnostic, separators=(",", ":")).encode("utf-8"),
                    b"progress\n",
                    1,
                )
                with self.assertRaises(runner.AcceptanceError):
                    runner._run_nonroot_trace_baseline(
                        process,
                        Path("synthetic-termivar"),
                        "http://127.0.0.1:8080/blog/",
                        label="synthetic non-root baseline",
                    )

        process = mock.Mock()
        process.run.return_value = runner.CommandResult(
            json.dumps(valid, separators=(",", ":")).encode("utf-8"),
            b"progress\n",
            0,
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "typed incompleteness"):
            runner._run_nonroot_trace_baseline(
                process,
                Path("synthetic-termivar"),
                "http://127.0.0.1:8080/blog/",
                label="synthetic non-root baseline",
            )

    def test_run_scan_passes_layout_only_with_explicit_discovery(self):
        class ScanProcessRunner:
            def __init__(self, expected, bundle):
                self.expected = expected
                self.bundle = bundle
                self.calls = []

            def run(self, arguments, *, label, **kwargs):
                argv = [str(argument) for argument in arguments]
                self.calls.append((label, argv, kwargs))
                if argv != self.expected:
                    raise AssertionError(f"unexpected synthetic scan arguments: {argv!r}")
                write_synthetic_bundle(
                    self.bundle.parent, self.bundle.name,
                    [synthetic_assessment_item(
                        BASE_FINGERPRINT, BASE_CAPABILITY,
                        "Synthetic layout-aware observation",
                    )],
                )
                return runner.CommandResult(
                    b"", b"synthetic progress\n", 0, 0.125,
                    {"status": "not_measured", "reason": "synthetic"},
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            layout = root / "layout.json"
            layout_bytes = b'{"schema":"security.wordpress-layout/v1"}\n'
            layout.write_bytes(layout_bytes)
            binary = Path("synthetic-termivar")
            target = "http://127.0.0.1:8080/blog/"
            expected = [
                str(binary), "scan", target, "--profile", "web-review", "--progress",
                "--report-dir", str(bundle), "--wordpress-review",
                "--wordpress-discovery", "--wordpress-layout", str(layout),
            ]
            fake = ScanProcessRunner(expected, bundle)
            document, _, stdout, stderr, metrics = runner._run_scan(
                fake, binary, target, bundle, wordpress_review=True,
                discovery=True, layout_path=layout, label="synthetic layout scan",
            )
            self.assertEqual(document["status"], "complete")
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"synthetic progress\n")
            self.assertEqual(metrics["elapsed_milliseconds"], 125.0)
            self.assertEqual(layout.read_bytes(), layout_bytes)
            self.assertEqual(len(fake.calls), 1)

    def test_real_lab_rejects_non_linux_host_before_docker_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            with mock.patch.object(runner.platform, "system", return_value="Windows"):
                with mock.patch.object(runner.shutil, "which") as which:
                    with self.assertRaisesRegex(
                        runner.AcceptanceError, "native Linux Docker engine"
                    ):
                        lab.start()
                    which.assert_not_called()

    def test_fixture_inventory_and_digest_pins_are_closed(self):
        result = runner.validate_fixture()
        self.assertEqual(result["file_count"], 14)
        self.assertRegex(result["fixture_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["ground_truth_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(set(result["image_references"]), set(runner.IMAGE_REFERENCES))
        for reference in result["image_references"]:
            self.assertRegex(reference, r"^[a-z]+@sha256:[0-9a-f]{64}$")

    def test_validate_only_executes_without_docker(self):
        completed = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--validate-only"],
            cwd=REPOSITORY_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        document = json.loads(completed.stdout)
        self.assertEqual(document["schema"], runner.TASK_SCHEMA)
        self.assertEqual(document["status"], "validated")

    def test_process_runner_reports_fresh_command_elapsed_and_honest_peak_metric(self):
        result = runner.ProcessRunner().run(
            [sys.executable, "-c", "pass"],
            label="process metric self-test",
            measure_peak_memory=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertGreaterEqual(result.elapsed_seconds, 0.0)
        if runner.platform.system() == "Linux" and Path("/usr/bin/time").is_file():
            self.assertEqual(result.peak_memory["status"], "measured")
            self.assertEqual(result.peak_memory["unit"], "KiB")
            self.assertGreater(result.peak_memory["value"], 0)
        else:
            self.assertEqual(result.peak_memory["status"], "not_measured")

    def test_source_contains_no_broad_or_privileged_docker_operation(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in (
            "--privileged",
            "--network=host",
            "/var/run/docker.sock",
            "docker system prune",
            "docker image prune",
            "docker volume prune",
            "docker network prune",
            "remove_dir_all",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('"--internal"', source)
        self.assertNotIn('"--publish"', source)
        self.assertIn('super().__init__(("127.0.0.1", 0)', source)
        self.assertIn('"build", "--network=none", "--pull=false"', source)
        self.assertIn('"--env-file", str(self.wordpress_env)', source)
        self.assertEqual(source.count('"run", "--pull=never"'), 3)
        self.assertNotIn('"--user", "0:0"', source)
        dockerfile = (runner.FIXTURE_ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("Listen 8080", dockerfile)
        self.assertIn("<VirtualHost *:8080>", dockerfile)
        self.assertTrue(dockerfile.rstrip().endswith("USER www-data"))
        for forbidden_import in (
            "import urllib",
            "from urllib",
            "import requests",
            "from requests",
        ):
            self.assertNotIn(forbidden_import, source)
        for forbidden_executable in ('"curl"', '"wget"'):
            self.assertNotIn(forbidden_executable, source)

    def test_loopback_relay_forwards_only_to_its_fixed_upstream(self):
        class ResponseHandler(socketserver.BaseRequestHandler):
            def handle(self):
                request = self.request.recv(4096)
                self.server.requests.append(request)
                self.request.sendall(
                    b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )

        upstream = socketserver.TCPServer(("127.0.0.1", 0), ResponseHandler)
        upstream.requests = []
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        relay = runner.LoopbackTcpRelay("127.0.0.1", upstream.server_address[1])
        relay_port = relay.start()
        try:
            with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
                client.sendall(b"GET /fixed HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                response = bytearray()
                while payload := client.recv(4096):
                    response.extend(payload)
            self.assertIn(b"200 OK", response)
            self.assertIn(b"GET /fixed HTTP/1.0", upstream.requests[0])
        finally:
            relay.stop()
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())

    def test_loopback_relay_stop_closes_an_active_handler(self):
        connected = threading.Event()
        release = threading.Event()

        class HoldingHandler(socketserver.BaseRequestHandler):
            def handle(self):
                connected.set()
                self.request.recv(1)
                release.wait(timeout=2)

        class ThreadedUpstream(socketserver.ThreadingTCPServer):
            daemon_threads = True

        upstream = ThreadedUpstream(("127.0.0.1", 0), HoldingHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        relay = runner.LoopbackTcpRelay("127.0.0.1", upstream.server_address[1])
        relay_port = relay.start()
        client = socket.create_connection(("127.0.0.1", relay_port), timeout=2)
        client.sendall(b"x")
        self.assertTrue(connected.wait(timeout=2))
        started = runner.time.monotonic()
        relay.stop()
        self.assertLess(runner.time.monotonic() - started, 2)
        client.close()
        release.set()
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())

    def test_loopback_relay_can_close_before_start(self):
        relay = runner.LoopbackTcpRelay("127.0.0.1", 1)
        relay.stop()

    def test_loopback_relay_reports_post_startup_upstream_failure(self):
        relay = runner.LoopbackTcpRelay("127.0.0.1", 0)
        relay_port = relay.start()
        relay.acknowledge_startup()
        with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
            self.assertEqual(client.recv(1), b"")
        deadline = runner.time.monotonic() + 2
        while (relay._server.transport_failures() == 0
               and runner.time.monotonic() < deadline):
            runner.time.sleep(0.01)
        with self.assertRaisesRegex(runner.AcceptanceError, "transport failure"):
            relay.assert_healthy()
        relay.stop()

    def test_loopback_relay_reports_byte_limit_plus_one_and_still_stops(self):
        received = threading.Event()

        class DrainHandler(socketserver.BaseRequestHandler):
            def handle(self):
                received.set()
                while self.request.recv(4096):
                    pass

        upstream = socketserver.TCPServer(("127.0.0.1", 0), DrainHandler)
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        old_limit = runner.MAX_RELAY_CONNECTION_BYTES
        runner.MAX_RELAY_CONNECTION_BYTES = 8
        relay = runner.LoopbackTcpRelay("127.0.0.1", upstream.server_address[1])
        relay_port = relay.start()
        relay.acknowledge_startup()
        try:
            with socket.create_connection(("127.0.0.1", relay_port), timeout=2) as client:
                client.sendall(b"123456789")
                client.shutdown(socket.SHUT_WR)
                while client.recv(4096):
                    pass
            self.assertTrue(received.wait(timeout=2))
            deadline = runner.time.monotonic() + 2
            while (relay._server.limit_failures() == 0
                   and runner.time.monotonic() < deadline):
                runner.time.sleep(0.01)
            with self.assertRaisesRegex(runner.AcceptanceError, "connection or byte bound"):
                relay.assert_healthy()
        finally:
            relay.stop()
            runner.MAX_RELAY_CONNECTION_BYTES = old_limit
            upstream.shutdown()
            upstream.server_close()
            upstream_thread.join(timeout=2)
        self.assertFalse(upstream_thread.is_alive())

    def test_html_execution_boundary_is_exact_and_bounded(self):
        html = (
            "<h3>Execution boundary</h3>"
            "<dl class=\"meta\">"
            "<dt>Exploit execution</dt><dd><code>not_performed</code></dd>"
            "<dt>Impact validation</dt><dd><code>not_performed</code></dd>"
            "</dl>"
        ).encode()
        runner._validate_wordpress_execution_boundary(html)

        duplicated = html.replace(
            b"</dl>",
            b"<dt>Exploit execution</dt><dd><code>not_performed</code></dd></dl>",
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "omits or duplicates"):
            runner._validate_wordpress_execution_boundary(duplicated)
        with self.assertRaisesRegex(runner.AcceptanceError, "report bound"):
            runner._validate_wordpress_execution_boundary(b"")

    def test_internal_container_address_rejects_network_or_address_drift(self):
        network_name = "termivar-wp-net-0123456789ab"
        network_id = "a" * 64
        network = {
            "Name": network_name,
            "Id": network_id,
            "Internal": True,
            "IPAM": {"Config": [{"Subnet": "172.30.0.0/16"}]},
        }
        attachments = {
            network_name: {"NetworkID": network_id, "IPAddress": "172.30.0.7"}
        }
        self.assertEqual(
            runner._internal_container_address(network_name, network, attachments),
            "172.30.0.7",
        )
        mutations = []
        not_internal = copy.deepcopy(network)
        not_internal["Internal"] = False
        mutations.append((not_internal, attachments))
        public_subnet = copy.deepcopy(network)
        public_subnet["IPAM"]["Config"][0]["Subnet"] = "8.8.8.0/24"
        mutations.append((public_subnet, attachments))
        wrong_identity = copy.deepcopy(attachments)
        wrong_identity[network_name]["NetworkID"] = "b" * 64
        mutations.append((network, wrong_identity))
        public_address = copy.deepcopy(attachments)
        public_address[network_name]["IPAddress"] = "8.8.8.8"
        mutations.append((network, public_address))
        extra_network = copy.deepcopy(attachments)
        extra_network["foreign"] = {"NetworkID": "c" * 64, "IPAddress": "172.31.0.2"}
        mutations.append((network, extra_network))
        for network_case, attachment_case in mutations:
            with self.subTest(network=network_case, attachments=attachment_case):
                with self.assertRaises(runner.AcceptanceError):
                    runner._internal_container_address(
                        network_name, network_case, attachment_case
                    )

    def test_plain_permalink_oracle_tracks_current_core_index_form(self):
        self.assertEqual(
            runner.EXPECTED_DISCOVERY_PATHS["plain"][0],
            "/index.php?rest_route=/",
        )
        self.assertNotIn("/?rest_route=/", runner.EXPECTED_DISCOVERY_PATHS["plain"])
        self.assertEqual(runner.EXPECTED_DISCOVERY_PATHS["pretty"][0], "/wp-json/")

    def test_layout_request_oracles_are_literal_and_keep_sibling_separate(self):
        self.assertEqual(
            runner._framed_reference(
                "wordpress-selected-application", "http://127.0.0.1:8080/blog/"
            ),
            "sha256:ac4295a28e5a25143dde1e7b215669b8182253e67a75eaae5cd126f0369fb715",
        )
        self.assertEqual(runner.EXPECTED_DISCOVERY_PATHS["blog-pretty"], (
            "/blog/wp-json/",
            "/blog/wp-content/themes/termivar-child/style.css",
            "/blog/wp-content/themes/termivar-parent/style.css",
            "/blog/wp-content/plugins/termivar-metadata-lab/readme.txt",
        ))
        self.assertEqual(runner.EXPECTED_DISCOVERY_PATHS["blog-plain"][0],
                         "/blog/index.php?rest_route=/")
        self.assertEqual(runner.EXPECTED_DISCOVERY_PATHS["cms"][1],
                         "/cms/wp-content/themes/termivar-child/style.css")
        self.assertEqual(runner.EXPECTED_DISCOVERY_PATHS["custom"][1:], (
            "/site-content/themes/termivar-child/style.css",
            "/site-content/themes/termivar-parent/style.css",
            "/modules/termivar-metadata-lab/readme.txt",
        ))
        self.assertNotIn(
            "/shop/wp-content/themes/termivar-child/style.css",
            runner.EXPECTED_DISCOVERY_PATHS["blog-pretty"],
        )

    def test_deployment_audit_oracle_binds_application_roles_and_resources(self):
        document = self.discovery_document()
        application = "http://127.0.0.1:8080/blog/"
        oracle = runner.DiscoveryOracle(
            application_url=application,
            request_paths=runner.EXPECTED_DISCOVERY_PATHS["blog-pretty"],
            core_base_url=application,
            themes_base_url=application + "wp-content/themes/",
            plugins_base_url=application + "wp-content/plugins/",
            rest_base_url=application,
            skipped_sibling_application_count=1,
        )
        layout = document["wordpress_discovery"]["layout"]
        layout["application_reference"] = runner._framed_reference(
            "wordpress-selected-application", application
        )
        for role, base, basis in (
            ("core", oracle.core_base_url, "conventional_asset"),
            ("themes", oracle.themes_base_url, "conventional_asset"),
            ("plugins", oracle.plugins_base_url, "conventional_asset"),
            ("rest_index", oracle.rest_base_url, "structured_advertisement"),
        ):
            row = next(item for item in layout["roles"] if item["role"] == role)
            row.update({
                "status": "exact", "basis": basis,
                "reference": runner._framed_reference("wordpress-discovery-role", base),
                "candidate_count": 1,
            })
        layout["skipped_sibling_application_count"] = 1
        origin = "http://127.0.0.1:8080"
        for source, path, base in zip(
            document["wordpress_discovery"]["sources"],
            oracle.request_paths,
            (oracle.rest_base_url, oracle.themes_base_url,
             oracle.themes_base_url, oracle.plugins_base_url),
            strict=True,
        ):
            source["resource_reference"] = runner._framed_reference(
                "wordpress-discovery-resource", origin + path
            )
            source["role_reference"] = runner._framed_reference(
                "wordpress-discovery-role", base
            )
        self.assertEqual(
            runner._validate_discovery_document(
                document, generator_visible=True, oracle=oracle
            ),
            "security.wordpress-discovery-audit/v2",
        )

        mismatched = copy.deepcopy(document)
        mismatched["wordpress_discovery"]["sources"][1]["resource_reference"] = (
            "sha256:" + "f" * 64
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "opaque reference differs"):
            runner._validate_discovery_document(
                mismatched, generator_visible=True, oracle=oracle
            )

        unexpected_audit_field = copy.deepcopy(document)
        unexpected_audit_field["wordpress_discovery"]["unexpected"] = True
        with self.assertRaisesRegex(runner.AcceptanceError, "unexpected top-level shape"):
            runner._validate_discovery_document(
                unexpected_audit_field, generator_visible=True, oracle=oracle
            )

        unexpected_source_field = copy.deepcopy(document)
        unexpected_source_field["wordpress_discovery"]["sources"][0]["unexpected"] = True
        with self.assertRaisesRegex(runner.AcceptanceError, "source row has an unexpected shape"):
            runner._validate_discovery_document(
                unexpected_source_field, generator_visible=True, oracle=oracle
            )

    def test_exact_four_request_delta_preserves_base_and_extra_order(self):
        review = [("GET", "/", 200, ()), ("HEAD", "/", 200, ())]
        expected = [
            ("GET", path, 200, ()) for path in runner.EXPECTED_DISCOVERY_PATHS["pretty"]
        ]
        runner._assert_request_delta(
            review,
            [review[0], expected[0], expected[1], review[1], expected[2], expected[3]],
            "pretty",
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "reordered"):
            runner._assert_request_delta(review, [*reversed(review), *expected], "pretty")
        with self.assertRaisesRegex(runner.AcceptanceError, "ordered four-request oracle"):
            runner._assert_request_delta(review, [*review, *reversed(expected)], "pretty")
        with self.assertRaisesRegex(runner.AcceptanceError, "ordered four-request oracle"):
            runner._assert_request_delta(
                review,
                [*review, *expected, ("GET", "/wp-json/wp/v2/users", 200, ())],
                "pretty",
            )
        forbidden = list(expected)
        forbidden[0] = (*forbidden[0][:3], ("authorization",))
        with self.assertRaisesRegex(runner.AcceptanceError, "ordered four-request oracle"):
            runner._assert_request_delta(review, [*review, *forbidden], "pretty")

    def test_apache_request_parser_ignores_non_access_log_output(self):
        line = (
            '172.19.0.1 - - [10/Sep/2026:00:00:00 +0000] '
            '"GET /wp-json/ HTTP/1.1" 200 123 '
            'tmv_auth=- tmv_cookie=- tmv_proxy_auth=-'
        )
        match = runner.REQUEST_RE.search(line)
        self.assertIsNotNone(match)
        self.assertEqual((match["method"], match["target"], match["status"]),
                         ("GET", "/wp-json/", "200"))
        self.assertEqual(
            (match["authorization"], match["cookie"], match["proxy_authorization"]),
            ("-", "-", "-"),
        )
        self.assertIsNone(runner.REQUEST_RE.search("Apache configured -- resuming normal operations"))

    @staticmethod
    def discovery_document():
        return {
            "item_count": 1,
            "items": [{
                "capability_id": "technology.wordpress-metadata-source-response-observed@1",
                "title": "WordPress metadata-source response outcome observed",
                "category": "wordpress-metadata-source-response",
                "disposition": "informational",
                "claim_basis": "observation",
                "severity": None,
                "cwe": None,
                "confidence_ppm": 550_000,
                "evidence_count": 4,
                "evidence_references": [
                    "evidence-0001", "evidence-0002", "evidence-0003", "evidence-0004",
                ],
                "control_evidence_references": [],
                "candidate_evidence_references": [],
                "case_reference": None,
                "outcome_reference": None,
                "verification_stage": None,
                "redacted_summary": "Bounded response evidence from selected public WordPress metadata sources was collected; usable metadata, installation authenticity, vulnerable-code reachability, and advisory impact were not established.",
                "remediation": {
                    "id": "wordpress-metadata-review",
                    "summary": "Confirm the installation inventory and source-qualified metadata before making a security or remediation decision.",
                },
            }],
            "wordpress_review": {
                "schema": "security.wordpress-review-audit/v7",
                "review_basis_schema": "security.wordpress-review-audit/v1",
                "additional_request_count": 4,
                "components": [
                    {
                        "identity": {"kind": "core", "slug": "wordpress"},
                        "identity_sources": [
                            "generator_metadata", "same_origin_asset_path"
                        ],
                        "versions": [
                            {
                                "value": "7.1",
                                "source": "generator_metadata",
                                "confidence": "public_declaration",
                            }
                        ],
                    },
                    {
                        "identity": {"kind": "theme", "slug": "termivar-child"},
                        "identity_sources": [
                            "same_origin_asset_path", "theme_stylesheet_declaration"
                        ],
                        "versions": [{
                            "value": "1.4.0",
                            "source": "theme_stylesheet_declaration",
                            "confidence": "public_declaration",
                        }],
                    },
                    {
                        "identity": {"kind": "theme", "slug": "termivar-parent"},
                        "identity_sources": ["theme_stylesheet_declaration"],
                        "versions": [{
                            "value": "3.2.1",
                            "source": "theme_stylesheet_declaration",
                            "confidence": "public_declaration",
                        }],
                    },
                    {
                        "identity": {"kind": "plugin", "slug": "termivar-metadata-lab"},
                        "identity_sources": ["same_origin_asset_path"],
                        "versions": [],
                    },
                ],
            },
            "wordpress_discovery": {
                "schema": "security.wordpress-discovery-audit/v2",
                "capability_id": "technology.wordpress-metadata-discovery@1",
                "policy_id": "termivar.wordpress-deployment-aware-metadata-discovery/v1",
                "selected": True,
                "method": "get",
                "credential_mode": "anonymous",
                "seed_count": 3,
                "candidate_count": 4,
                "candidate_limit_reached": False,
                "omitted_candidate_count": 0,
                "attempted_request_count": 4,
                "completed_response_count": 4,
                "committed_response_count": 4,
                "response_bytes": 1024,
                "source_count": 4,
                "layout": {
                    "application_reference": APPLICATION_REFERENCE,
                    "roles": [
                        {"role": "core", "status": "exact",
                         "basis": "conventional_asset", "reference": REST_REFERENCE,
                         "candidate_count": 1},
                        {"role": "themes", "status": "exact",
                         "basis": "conventional_asset", "reference": THEME_REFERENCE,
                         "candidate_count": 1},
                        {"role": "plugins", "status": "exact",
                         "basis": "conventional_asset", "reference": PLUGIN_REFERENCE,
                         "candidate_count": 1},
                        {"role": "rest_index", "status": "exact",
                         "basis": "structured_advertisement", "reference": REST_REFERENCE,
                         "candidate_count": 1},
                    ],
                    "skipped_foreign_origin_count": 0,
                    "skipped_sibling_application_count": 0,
                    "conflicting_association_count": 0,
                },
                "sources": [
                    {
                        "kind": "rest_index",
                        "association": "structured_advertisement",
                        "resource_reference": "sha256:" + "4" * 64,
                        "role_reference": REST_REFERENCE,
                        "parent_depth": 0,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0001"],
                        "namespaces": ["wp/v2", "termivar-lab/v1"],
                    },
                    {
                        "kind": "theme_stylesheet",
                        "association": "observed_conventional",
                        "resource_reference": "sha256:" + "5" * 64,
                        "role_reference": THEME_REFERENCE,
                        "component": {"kind": "theme", "slug": "termivar-child"},
                        "parent_depth": 0,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0002"],
                        "theme": {
                            "name": "Termivar Metadata Child",
                            "version": "1.4.0",
                            "template": "termivar-parent",
                        },
                    },
                    {
                        "kind": "theme_stylesheet",
                        "association": "same_theme_base_parent",
                        "resource_reference": "sha256:" + "6" * 64,
                        "role_reference": THEME_REFERENCE,
                        "component": {"kind": "theme", "slug": "termivar-parent"},
                        "parent_depth": 1,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0003"],
                        "theme": {
                            "name": "Termivar Metadata Parent",
                            "version": "3.2.1",
                        },
                    },
                    {
                        "kind": "plugin_readme",
                        "association": "observed_conventional",
                        "resource_reference": "sha256:" + "7" * 64,
                        "role_reference": PLUGIN_REFERENCE,
                        "component": {"kind": "plugin", "slug": "termivar-metadata-lab"},
                        "parent_depth": 0,
                        "outcome": "observed",
                        "request_attempted": True,
                        "response_bytes": 256,
                        "evidence_reference_count": 1,
                        "evidence_references": ["evidence-0004"],
                        "plugin": {
                            "name": "Termivar Metadata Lab",
                            "stable_tag": "9.9.9",
                        },
                    },
                ],
            },
        }

    def test_comparison_groups_require_the_actual_four_array_schema(self):
        document = {
            "schema": "termivar-report-comparison/v1",
            "only_in_after": [],
            "only_in_before": [],
            "changed": [],
            "unchanged": [{"synthetic": True}],
        }
        groups = runner._comparison_group_arrays(document, "synthetic comparison")
        self.assertEqual(
            {name: len(items) for name, items in groups.items()},
            {
                "only_in_after": 0,
                "only_in_before": 0,
                "changed": 0,
                "unchanged": 1,
            },
        )
        self.assertNotIn("counts", document)

        for invalid in ([], None, "comparison", 1, True):
            with self.subTest(root=invalid):
                with self.assertRaisesRegex(runner.AcceptanceError, "root is not an object"):
                    runner._comparison_group_arrays(invalid, "synthetic comparison")
        wrong_schema = copy.deepcopy(document)
        wrong_schema["schema"] = "termivar-report-comparison/v2"
        with self.assertRaisesRegex(runner.AcceptanceError, "unsupported comparison schema"):
            runner._comparison_group_arrays(wrong_schema, "synthetic comparison")

        for missing in runner.COMPARISON_GROUPS:
            malformed = copy.deepcopy(document)
            del malformed[missing]
            malformed["counts"] = {name: 0 for name in runner.COMPARISON_GROUPS}
            with self.subTest(missing=missing):
                with self.assertRaisesRegex(runner.AcceptanceError, f"omits comparison group {missing}"):
                    runner._comparison_group_arrays(malformed, "synthetic comparison")

        for group in runner.COMPARISON_GROUPS:
            for invalid in (None, "items", {}, 1, True):
                malformed = copy.deepcopy(document)
                malformed[group] = invalid
                malformed["counts"] = {name: 999 for name in runner.COMPARISON_GROUPS}
                with self.subTest(group=group, value=invalid):
                    with self.assertRaisesRegex(runner.AcceptanceError, "is not an array"):
                        runner._comparison_group_arrays(malformed, "synthetic comparison")

        contradictory_counts = copy.deepcopy(document)
        contradictory_counts["counts"] = {
            "only_in_after": 99,
            "only_in_before": 99,
            "changed": 99,
            "unchanged": 0,
        }
        groups = runner._comparison_group_arrays(
            contradictory_counts, "synthetic comparison"
        )
        self.assertEqual([len(groups[name]) for name in runner.COMPARISON_GROUPS], [0, 0, 0, 1])

    def test_offline_acceptance_uses_derived_counts_in_both_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, original_bytes = offline_fixture(Path(temporary))
            fake = offline_process_runner(responses, scenarios)
            result = runner._run_offline_acceptance(
                fake, Path("synthetic-termivar"), scenarios
            )

            self.assertEqual(result["bundles"]["pretty-review-only"], {
                "bundle_unchanged": True,
                "verification_status": "integrity_match",
                "self_compare_counts": {
                    "only_in_after": 0,
                    "only_in_before": 0,
                    "changed": 0,
                    "unchanged": 1,
                },
            })
            self.assertEqual(result["bundles"]["pretty-discovery"], {
                "bundle_unchanged": True,
                "verification_status": "integrity_match",
                "self_compare_counts": {
                    "only_in_after": 0,
                    "only_in_before": 0,
                    "changed": 0,
                    "unchanged": 2,
                },
            })
            self.assertEqual(result["review_only_to_discovery"], {
                "status": "not_compared",
                "reason": "application_scope_unknown",
                "methodology": "changed",
                "coverage": "changed",
                "item_counts": {
                    "only_in_after": 1,
                    "only_in_before": 0,
                    "changed": 1,
                    "unchanged": 0,
                },
            })
            labels = [
                "offline verification pretty-review-only",
                "offline self comparison pretty-review-only",
                "offline verification pretty-discovery",
                "offline self comparison pretty-discovery",
                "offline collection-policy comparison",
            ]
            self.assertEqual(
                fake.calls,
                [(label, fake.expected_arguments[label]) for label in labels],
            )
            self.assertEqual(
                (Path(scenarios["pretty-review-only"]["_bundle"])
                 / "assessment.json").read_bytes(),
                original_bytes[0],
            )
            self.assertEqual(
                (Path(scenarios["pretty-discovery"]["_bundle"])
                 / "assessment.json").read_bytes(),
                original_bytes[1],
            )

    def test_offline_acceptance_exercises_layout_and_application_scope_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = layout_offline_fixture(Path(temporary))
            fake = offline_process_runner(responses, scenarios)
            result = runner._run_offline_acceptance(
                fake, Path("synthetic-termivar"), scenarios
            )

            self.assertEqual(result["custom_no_layout_to_declared_layout"], {
                "status": "compared",
                "methodology": "changed",
                "coverage": "changed",
                "item_counts": {
                    "only_in_after": 0, "only_in_before": 0,
                    "changed": 0, "unchanged": 2,
                },
            })
            self.assertEqual(result["application_scope_mismatch"], {
                "status": "not_compared",
                "reason": "application_scope_mismatch",
                "item_counts": {
                    "only_in_after": 0, "only_in_before": 0,
                    "changed": 0, "unchanged": 2,
                },
            })
            self.assertEqual(
                [label for label, _ in fake.calls[-2:]],
                [
                    "offline custom layout comparison",
                    "offline application-scope mismatch comparison",
                ],
            )

    def test_offline_layout_acceptance_rejects_false_scope_and_methodology(self):
        def same_application_identity(scenarios, _responses):
            scenarios["blog-pretty-discovery"]["layout_application_reference"] = (
                APPLICATION_REFERENCE
            )

        def paired_mismatch_entities(_scenarios, responses):
            comparison = responses["offline application-scope mismatch comparison"]
            comparison["wordpress_review_comparison"]["components"][
                "paired_unchanged_count"
            ] = 1

        def unchanged_custom_methodology(_scenarios, responses):
            facet = responses["offline custom layout comparison"][
                "wordpress_review_comparison"
            ]["methodology"]
            facet.update({
                "status": "unchanged", "after": copy.deepcopy(facet["before"]),
                "changed_fields": [],
            })

        mutations = (
            (same_application_identity, "different applications unexpectedly share"),
            (paired_mismatch_entities, "unexpectedly paired WordPress components"),
            (unchanged_custom_methodology, "methodology is not changed"),
        )
        for mutate, message in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = layout_offline_fixture(Path(temporary))
                    mutate(scenarios, responses)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"), scenarios,
                        )

    def test_offline_acceptance_rejects_self_partition_mutations(self):
        def empty_self(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"] = []

        def changed_self(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"] = []
            comparison["changed"] = [comparison_item(
                BASE_FINGERPRINT,
                BASE_CAPABILITY,
                before=synthetic_projection("before"),
                after=synthetic_projection("after"),
                changed_fields=["title"],
            )]

        def one_sided_self(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            item = comparison["unchanged"].pop()
            item["before"] = None
            comparison["only_in_after"] = [item]

        def duplicate_identity(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"].append(copy.deepcopy(comparison["unchanged"][0]))

        def substituted_identity(responses):
            comparison = responses["offline self comparison pretty-review-only"]
            comparison["unchanged"][0]["fingerprint"] = "sha256:" + "3" * 64

        mutations = (
            (empty_self, "paired identities"),
            (changed_self, "invalid group shape"),
            (one_sided_self, "only_in_after identities"),
            (duplicate_identity, "repeats a fingerprint"),
            (substituted_identity, "invalid group shape"),
        )
        for mutate, message in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    mutate(responses)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_offline_acceptance_rejects_invalid_source_inventory_counts(self):
        for invalid_count, message in ((True, "invalid item_count"), (2, "does not match")):
            with self.subTest(item_count=invalid_count):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    bundle = Path(scenarios["pretty-review-only"]["_bundle"])
                    document = json.loads((bundle / "assessment.json").read_bytes())
                    document["item_count"] = invalid_count
                    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
                    (bundle / "assessment.json").write_bytes(raw)
                    scenarios["pretty-review-only"]["bundle"] = (
                        runner._report_identity(bundle)
                    )
                    comparison = responses["offline self comparison pretty-review-only"]
                    comparison["before"] = source_metadata(raw, invalid_count)
                    comparison["after"] = source_metadata(raw, invalid_count)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_offline_acceptance_rejects_controlled_partition_and_wordpress_drift(self):
        def invalid_root(responses):
            responses["offline collection-policy comparison"] = []

        def missing_wordpress(responses):
            del responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]

        def unchanged_methodology(responses):
            responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]["methodology"]["status"] = "unchanged"

        def unchanged_coverage(responses):
            responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]["coverage"]["status"] = "unchanged"

        def false_methodology_change(responses):
            facet = responses["offline collection-policy comparison"][
                "wordpress_review_comparison"
            ]["methodology"]
            facet["after"] = copy.deepcopy(facet["before"])

        def false_item_change(responses):
            comparison = responses["offline collection-policy comparison"]
            comparison["changed"][0]["changed_fields"] = []

        def omitted_source_audits(responses):
            responses["offline collection-policy comparison"]["before"][
                "optional_audits"
            ] = {}

        def missing_discovery_identity(responses):
            comparison = responses["offline collection-policy comparison"]
            comparison["only_in_after"][0]["capability_id"] = "synthetic.other@1"

        def duplicate_controlled_identity(responses):
            comparison = responses["offline collection-policy comparison"]
            comparison["changed"].append(
                copy.deepcopy(comparison["changed"][0])
            )

        mutations = (
            (invalid_root, "root is not an object"),
            (missing_wordpress, "omitted WordPress"),
            (unchanged_methodology, "methodology is not changed"),
            (unchanged_coverage, "coverage is not changed"),
            (false_methodology_change, "inconsistent changed fields"),
            (false_item_change, "invalid group shape"),
            (omitted_source_audits, "optional audit metadata"),
            (missing_discovery_identity, "only_in_after identities"),
            (duplicate_controlled_identity, "repeats a fingerprint"),
        )
        for mutate, message in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    mutate(responses)
                    with self.assertRaisesRegex(runner.AcceptanceError, message):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = offline_fixture(
                Path(temporary), discovery_capability="synthetic.other@1"
            )
            with self.assertRaisesRegex(runner.AcceptanceError, "one-sided discovery"):
                runner._run_offline_acceptance(
                    offline_process_runner(responses, scenarios),
                    Path("synthetic-termivar"),
                    scenarios,
                )

    def test_offline_acceptance_rejects_failed_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = offline_fixture(Path(temporary))
            responses["offline verification pretty-review-only"]["status"] = "not_verified"
            with self.assertRaisesRegex(runner.AcceptanceError, "verification rejected"):
                runner._run_offline_acceptance(
                    offline_process_runner(responses, scenarios),
                    Path("synthetic-termivar"),
                    scenarios,
                )

    def test_offline_acceptance_rejects_invalid_verification_schema_and_root(self):
        for replacement in (
            {"schema": "termivar-report-verification/v2", "status": "integrity_match"},
            [],
        ):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    responses["offline verification pretty-review-only"] = replacement
                    with self.assertRaisesRegex(
                        runner.AcceptanceError, "unsupported schema"
                    ):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_offline_acceptance_rejects_bundle_content_changes(self):
        for filename in ("assessment.html", "assessment.json", "manifest.json"):
            with self.subTest(filename=filename):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = offline_fixture(Path(temporary))
                    bundle = Path(scenarios["pretty-review-only"]["_bundle"])

                    def mutate_after_verify(label, *, path=bundle / filename):
                        if label == "offline verification pretty-review-only":
                            path.write_bytes(path.read_bytes() + b"x")

                    with self.assertRaisesRegex(
                        runner.AcceptanceError, "modified report bundle"
                    ):
                        runner._run_offline_acceptance(
                            offline_process_runner(
                                responses, scenarios, after_run=mutate_after_verify
                            ),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_audit_oracle_keeps_stable_tag_out_of_installed_versions(self):
        document = self.discovery_document()
        self.assertEqual(
            runner._validate_discovery_document(document, generator_visible=True),
            "security.wordpress-discovery-audit/v2",
        )
        promoted = copy.deepcopy(document)
        promoted["wordpress_review"]["components"][3]["versions"] = [{"value": "9.9.9"}]
        with self.assertRaisesRegex(runner.AcceptanceError, "promoted"):
            runner._validate_discovery_document(promoted, generator_visible=True)

        missing_theme_version = copy.deepcopy(document)
        missing_theme_version["wordpress_review"]["components"][1]["versions"] = []
        with self.assertRaisesRegex(runner.AcceptanceError, "source-qualified"):
            runner._validate_discovery_document(missing_theme_version, generator_visible=True)

        mismatched = copy.deepcopy(document)
        mismatched["wordpress_review"]["additional_request_count"] = 3
        with self.assertRaisesRegex(runner.AcceptanceError, "request accounting"):
            runner._validate_discovery_document(mismatched, generator_visible=True)

    def test_suppressed_generator_must_not_supply_core_version(self):
        document = self.discovery_document()
        document["wordpress_review"]["components"][0]["versions"] = []
        document["wordpress_review"]["components"][0]["identity_sources"] = [
            "same_origin_asset_path"
        ]
        runner._validate_discovery_document(document, generator_visible=False)
        quality = runner._discovery_quality_metrics(document, generator_visible=False)
        self.assertEqual(quality["observable_identity_recall"], {
            "matched": 4,
            "denominator": 4,
            "missed": 0,
        })
        self.assertEqual(quality["expected_abstentions"]["correct"], 3)
        self.assertEqual(quality["expected_abstentions"]["denominator"], 3)
        with self.assertRaisesRegex(runner.AcceptanceError, "suppressed generator"):
            runner._validate_discovery_document(self.discovery_document(), generator_visible=False)

    def test_quality_oracle_has_independent_denominators_and_rejects_false_matches(self):
        document = self.discovery_document()
        quality = runner._discovery_quality_metrics(document, generator_visible=True)
        self.assertEqual(quality["observable_identity_recall"], {
            "matched": 4,
            "denominator": 4,
            "missed": 0,
        })
        self.assertEqual(quality["false_identity_matches"], {
            "count": 0,
            "observed_denominator": 4,
        })
        self.assertEqual(
            quality["version_accuracy_by_source_class"]["generator_metadata"],
            {"correct": 1, "denominator": 1, "not_observable": 0},
        )
        self.assertEqual(
            quality["version_accuracy_by_source_class"]["theme_stylesheet_declaration"],
            {"correct": 2, "denominator": 2},
        )
        self.assertEqual(quality["expected_abstentions"]["correct"], 2)
        self.assertEqual(quality["expected_abstentions"]["denominator"], 2)

        extra = copy.deepcopy(document)
        extra["wordpress_review"]["components"].append({
            "identity": {"kind": "plugin", "slug": "unexpected-plugin"},
            "identity_sources": ["same_origin_asset_path"],
            "versions": [],
        })
        with self.assertRaisesRegex(runner.AcceptanceError, "identity oracle"):
            runner._discovery_quality_metrics(extra, generator_visible=True)

        wrong_source = copy.deepcopy(document)
        wrong_source["wordpress_review"]["components"][0]["versions"][0]["source"] = (
            "same_origin_asset_path"
        )
        with self.assertRaisesRegex(runner.AcceptanceError, "version/source oracle"):
            runner._discovery_quality_metrics(wrong_source, generator_visible=True)

    def test_duplicate_ground_truth_key_is_rejected(self):
        with self.assertRaisesRegex(runner.AcceptanceError, "duplicate object key"):
            runner.parse_json(b'{"schema":"one","schema":"two"}', "fixture")

    def test_evidence_output_is_bounded_and_no_overwrite(self):
        evidence = {
            "schema": runner.TASK_SCHEMA,
            "status": "failed",
            "source_ref": "0" * 40,
            "failure": "synthetic test failure",
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            runner.write_evidence(destination, evidence)
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {
                    "wordpress-discovery-lab-acceptance.json",
                    "wordpress-discovery-lab-acceptance.md",
                },
            )
            with self.assertRaises(FileExistsError):
                runner.write_evidence(destination, evidence)

    def test_cleanup_failure_retains_exact_task_owned_resume_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(runner.ProcessRunner(), Path(temporary))
            abandoned = runner._safe_name("wp-cli", "a" * 12)
            lab._wp_cli_containers.add(abandoned)
            lab._created.add("network")

            def failed_cleanup(*_args, **_kwargs):
                return runner.CommandResult(b"", b"bounded failure", 1)

            lab.docker = failed_cleanup
            with self.assertRaisesRegex(
                runner.AcceptanceError,
                f"{abandoned}.*{lab.network}",
            ):
                lab.shutdown()
            self.assertEqual(lab._wp_cli_containers, {abandoned})
            self.assertEqual(lab._created, {"network"})

    def test_wp_cleanup_does_not_forget_a_container_that_still_exists(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(runner.ProcessRunner(), Path(temporary))
            observed_name = None

            def persistent_container(*arguments, **_kwargs):
                nonlocal observed_name
                if arguments[0] == "run":
                    observed_name = arguments[arguments.index("--name") + 1]
                    return runner.CommandResult(b"ok", b"", 0)
                if arguments[:2] == ("rm", "--force"):
                    return runner.CommandResult(b"", b"bounded failure", 1)
                if arguments[:3] == ("container", "ls", "--all"):
                    return runner.CommandResult(f"{observed_name}\n".encode(), b"", 0)
                self.fail(f"unexpected Docker command: {arguments!r}")

            lab.docker = persistent_container
            with self.assertRaisesRegex(
                runner.AcceptanceError,
                "WP-CLI cleanup remains unconfirmed",
            ):
                lab.wp("core", "version", label="synthetic WP-CLI command")
            self.assertEqual(lab._wp_cli_containers, {observed_name})


if __name__ == "__main__":
    unittest.main()
