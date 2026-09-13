import copy
import hashlib
import importlib.util
import io
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
REJECTED_BLOG_APPLICATION_URL = "https://lab.example/blog/"
REJECTED_BLOG_ENTRY_REFERENCE = (
    "sha256:ab0026874320ce507442f08c7e0f9b2885258bbb15ac144bbc58963ee844dfa3"
)
SYNTHETIC_FINGERPRINT_COMPARISON_LIMITS = [
    "Compared SHA-256 values and byte lengths describe complete admitted response bytes, not whole-package verification.",
    "Catalogue candidates are conditional on a finite operator-supplied reference set and are not installed-version evidence.",
    "Identical bytes can occur in unlisted releases, copied assets, caches, or custom builds.",
    "A one-sided or failed resource observation does not establish component installation, removal, or remediation.",
    "Source labels and digests identify supplied data; they do not authenticate its publisher or completeness.",
]
SYNTHETIC_SESSION_CAPABILITY = {
    "key": "option.supplied-session-review",
    "build_state": "compiled",
    "compile_feature": "supplied-session-review",
    "implementation_status": "implemented",
    "prerequisites": [
        "--profile web-review",
        "--session-policy FILE",
        "V1: one of --session-auth-env, --session-auth-file, or --session-auth-stdin",
        "V2: --session-cookie-file FILE",
        "optional --wordpress-supplied-session when also compiled with wordpress-review",
        "HTTPS, except numeric-loopback HTTP fixtures; Secure cookies still require HTTPS",
    ],
    "limitation": (
        "complete health-qualified session-resource HTML may nominate public WordPress "
        "metadata; the credential is not sent to metadata or fingerprint requests; "
        "authenticated-page fingerprint acquisition is not selected"
    ),
}
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


def rewrite_synthetic_assessment(bundle, document):
    """Rewrite one task-owned fixture and keep its literal bundle manifest coherent."""
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    assessment_path = bundle / "assessment.json"
    assessment_path.write_bytes(raw)
    manifest_path = bundle / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    assessment_row = next(
        row for row in manifest["files"] if row["name"] == "assessment.json"
    )
    assessment_row["byte_length"] = len(raw)
    assessment_row["sha256"] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_bytes(
        json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    )
    return raw


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


def fingerprint_entity_changes(*, paired_unchanged_count, paired_changed=None):
    """Literal comparison wire shape; independent of the acceptance helper."""
    return {
        "paired_unchanged_count": paired_unchanged_count,
        "paired_changed": copy.deepcopy(paired_changed or []),
        "only_in_before": [],
        "only_in_after": [],
    }


def fingerprint_methodology_projection(audit):
    return {
        field: copy.deepcopy(audit[field])
        for field in (
            "schema",
            "capability_id",
            "policy_id",
            "selected",
            "representation_profile",
            "finite_reference_scope",
            "same_release_assumption",
            "installed_version_assurance",
            "source_authenticity",
        )
    }


def fingerprint_coverage_projection(audit):
    return {
        field: copy.deepcopy(audit[field])
        for field in (
            "candidate_count",
            "selected_resource_count",
            "omitted_resource_count",
            "attempted_request_count",
            "reused_response_count",
            "fetched_response_count",
            "response_bytes",
            "stop",
            "resource_count",
            "component_count",
        )
    }


def fingerprint_resource_projection(resource):
    return {
        "resource_bytes": {
            "observation": copy.deepcopy(resource.get("observation"))
        },
        "acquisition": {
            field: copy.deepcopy(resource[field])
            for field in (
                "acquisition",
                "outcome",
                "observed_variant_count",
                "request_attempted",
                "interpreted_response_bytes",
                "response_bytes",
            )
        },
        "source_binding": {
            field: copy.deepcopy(resource[field])
            for field in ("resource_reference", "source_page_references")
        },
    }


def fingerprint_component_projection(component):
    return {
        "candidate_set": {
            field: copy.deepcopy(component[field])
            for field in (
                "state",
                "compatible_release_ids",
                "undetermined_release_ids",
                "inconsistent_release_ids",
            )
        },
        "reference_matrix": {
            field: copy.deepcopy(component[field])
            for field in (
                "catalogue_component_listed",
                "listed_matrix_complete",
                "releases",
            )
        },
        "resource_coverage": {
            field: copy.deepcopy(component[field])
            for field in (
                "candidate_resource_count",
                "selected_resource_count",
                "completely_interpreted_resource_count",
                "omitted_resource_count",
                "informative_resource_count",
                "resource_count",
                "resources",
            )
        },
    }


def fingerprint_comparison_facet(
    status="unchanged", *, before=None, after=None, changed_fields=()
):
    return {
        "status": status,
        "changed_fields": list(changed_fields),
        "before": copy.deepcopy(before),
        "after": copy.deepcopy(after),
        "note": "Synthetic acceptance facet.",
    }


def attach_fingerprint_self_comparison(
    comparison, *, audit, resource_count, component_count
):
    if (
        audit["resource_count"] != resource_count
        or audit["component_count"] != component_count
    ):
        raise AssertionError("synthetic source counts differ from the literal oracle")
    wordpress = comparison["wordpress_review_comparison"]
    wordpress["schema"] = "termivar-wordpress-review-comparison/v3"
    wordpress["asset_fingerprints"] = {
        "status": "compared",
        "methodology": fingerprint_comparison_facet(
            before=fingerprint_methodology_projection(audit),
            after=fingerprint_methodology_projection(audit),
        ),
        "catalogue": fingerprint_comparison_facet(
            before=audit["catalogue"], after=audit["catalogue"]
        ),
        "coverage": fingerprint_comparison_facet(
            before=fingerprint_coverage_projection(audit),
            after=fingerprint_coverage_projection(audit),
        ),
        "resources": fingerprint_entity_changes(
            paired_unchanged_count=resource_count
        ),
        "components": fingerprint_entity_changes(
            paired_unchanged_count=component_count
        ),
        "interpretation_limits": copy.deepcopy(
            SYNTHETIC_FINGERPRINT_COMPARISON_LIMITS
        ),
    }
    return comparison


def synthetic_fingerprint_audit(*, variant):
    """Reviewed literal v1 wire fixture; it does not call the product matcher."""
    if variant not in {
        "release-a", "release-b", "mixed-artifacts", "missing-reference", "empty"
    }:
        raise AssertionError(f"unknown synthetic fingerprint variant: {variant}")

    namespace = "termivar.synthetic.wordpress-asset-fingerprints"
    component = {
        "kind": runner.FINGERPRINT_COMPONENT[0],
        "slug": runner.FINGERPRINT_COMPONENT[1],
    }
    missing_reference = variant == "missing-reference"
    catalogue = {
        "schema": "security.wordpress-asset-fingerprint-catalog/v1",
        "id": "synthetic-fingerprint-catalogue",
        "revision": "r2" if missing_reference else "r1",
        "source_namespace": namespace,
        "byte_length": 2048,
        "sha256": ("9" if missing_reference else "1") * 64,
        "semantic_sha256": ("c" if missing_reference else "2") * 64,
        "retained_bytes": 4096,
        "component_count": 1,
        "release_count": 3,
        "file_count": 5 if missing_reference else 6,
        "provenance": {
            "reference": "https://example.test/fingerprint-catalogue",
            "revision": "fixture-r2" if missing_reference else "fixture-r1",
            "notices": [{
                "id": "fixture-notice",
                "party": "Termivar synthetic fixture authors",
                "notice": "Original harmless fixture bytes.",
                "license": "Synthetic test data permission.",
                "license_reference": (
                    "https://example.test/fingerprint-catalogue/license"
                ),
            }],
        },
    }
    audit = {
        "schema": "security.wordpress-asset-fingerprint-audit/v1",
        "capability_id": "technology.wordpress-asset-fingerprint-candidate@1",
        "policy_id": "termivar.wordpress-observed-asset-fingerprint/v1",
        "selected": True,
        "representation_profile": "identity-content-bytes/v1",
        "finite_reference_scope": "listed_releases_only",
        "same_release_assumption": (
            "considered_paths_share_one_listed_release_artifact_set"
        ),
        "installed_version_assurance": (
            "not_established_by_asset_fingerprints"
        ),
        "source_authenticity": "not_established",
        "catalogue": catalogue,
        "candidate_count": 0 if variant == "empty" else 2,
        "selected_resource_count": 0 if variant == "empty" else 2,
        "omitted_resource_count": 0,
        "attempted_request_count": 0,
        "reused_response_count": 0 if variant == "empty" else 2,
        "fetched_response_count": 0,
        "response_bytes": 0,
        "stop": "complete",
        "resource_count": 0 if variant == "empty" else 2,
        "resources": [],
        "component_count": 0 if variant == "empty" else 1,
        "components": [],
    }
    if variant == "empty":
        return audit

    release_b_hashes = {
        "assets/fingerprint.js": "a" * 64,
        "assets/fingerprint.css": "b" * 64,
    }
    release_a_hashes = {
        "assets/fingerprint.js": release_b_hashes["assets/fingerprint.js"],
        "assets/fingerprint.css": "c" * 64,
    }
    mixed_hashes = {
        "assets/fingerprint.js": "d" * 64,
        "assets/fingerprint.css": "e" * 64,
    }
    observation_hashes = (
        mixed_hashes
        if variant == "mixed-artifacts"
        else release_a_hashes
        if variant == "release-a"
        else release_b_hashes
    )
    resource_specs = (
        ("assets/fingerprint.js", 49, "3", "evidence-0002"),
        ("assets/fingerprint.css", 37, "5", "evidence-0003"),
    )
    audit["resources"] = [
        {
            "component": copy.deepcopy(component),
            "relative_path": path,
            "resource_reference": "sha256:" + reference_character * 64,
            "source_page_references": ["sha256:" + "4" * 64],
            "observed_variant_count": 1,
            "acquisition": "reused",
            "outcome": "observed",
            "request_attempted": False,
            "interpreted_response_bytes": byte_length,
            "response_bytes": 0,
            "evidence_reference_count": 1,
            "evidence_references": [evidence_reference],
            "observation": {
                "byte_length": byte_length,
                "sha256": observation_hashes[path],
            },
        }
        for path, byte_length, reference_character, evidence_reference in resource_specs
    ]

    if variant == "release-a":
        relations = {
            "assets/fingerprint.js": ("match", "match", "mismatch"),
            "assets/fingerprint.css": ("match", "mismatch", "mismatch"),
        }
        release_states = ("compatible", "inconsistent", "inconsistent")
        aggregate = {
            "state": "single_catalogue_candidate",
            "compatible_release_ids": ["release-a"],
            "undetermined_release_ids": [],
            "inconsistent_release_ids": ["release-b", "release-c"],
            "informative_resource_count": 2,
            "listed_matrix_complete": True,
        }
    elif variant == "mixed-artifacts":
        relations = {
            "assets/fingerprint.js": ("match", "mismatch", "mismatch"),
            "assets/fingerprint.css": ("mismatch", "mismatch", "match"),
        }
        release_states = ("inconsistent", "inconsistent", "inconsistent")
        aggregate = {
            "state": "no_consistent_catalogue_release",
            "compatible_release_ids": [],
            "undetermined_release_ids": [],
            "inconsistent_release_ids": ["release-a", "release-b", "release-c"],
            "informative_resource_count": 2,
            "listed_matrix_complete": True,
        }
    elif missing_reference:
        relations = {
            "assets/fingerprint.js": ("match", "match", "mismatch"),
            "assets/fingerprint.css": ("unknown", "match", "match"),
        }
        release_states = ("undetermined", "compatible", "inconsistent")
        aggregate = {
            "state": "provisional_candidates",
            "compatible_release_ids": ["release-b"],
            "undetermined_release_ids": ["release-a"],
            "inconsistent_release_ids": ["release-c"],
            "informative_resource_count": 1,
            "listed_matrix_complete": False,
        }
    else:
        relations = {
            "assets/fingerprint.js": ("match", "match", "mismatch"),
            "assets/fingerprint.css": ("mismatch", "match", "match"),
        }
        release_states = ("inconsistent", "compatible", "inconsistent")
        aggregate = {
            "state": "single_catalogue_candidate",
            "compatible_release_ids": ["release-b"],
            "undetermined_release_ids": [],
            "inconsistent_release_ids": ["release-a", "release-c"],
            "informative_resource_count": 2,
            "listed_matrix_complete": True,
        }

    release_ids = ("release-a", "release-b", "release-c")
    matrix = []
    for path in ("assets/fingerprint.js", "assets/fingerprint.css"):
        rows = []
        for release_id, relation in zip(release_ids, relations[path]):
            row = {"release_id": release_id, "relation": relation}
            if relation == "unknown":
                row["unknown_reason"] = "missing_reference"
            rows.append(row)
        matrix.append({
            "relative_path": path,
            "distinct_observation_count": 1,
            "informative": (
                path == "assets/fingerprint.js" or variant != "missing-reference"
            ),
            "release_relation_count": 3,
            "release_relations": rows,
        })
    releases = []
    for release_id, version, build_variant, state in zip(
        release_ids,
        ("1.0", "2.0", "3.0"),
        (None, "standard", None),
        release_states,
    ):
        releases.append({
            "release_id": release_id,
            "version": version,
            "build_variant": build_variant,
            "state": state,
            "source": {
                "reference": f"https://example.test/releases/{release_id[-1]}",
                "revision": f"source-{release_id[-1]}",
                "notice_ids": ["fixture-notice"],
            },
        })
    audit["components"] = [{
        "identity": copy.deepcopy(component),
        "catalogue_component_listed": True,
        **aggregate,
        "candidate_resource_count": 2,
        "selected_resource_count": 2,
        "completely_interpreted_resource_count": 2,
        "omitted_resource_count": 0,
        "resource_count": 2,
        "resources": matrix,
        "release_count": 3,
        "releases": releases,
    }]
    return audit


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
    if {"session-root-healthy", "session-root-loss-after-resource"} <= scenarios.keys():
        before = Path(scenarios["session-root-healthy"]["_bundle"])
        after = Path(scenarios["session-root-loss-after-resource"]["_bundle"])
        expected["offline supplied-session health-loss comparison"] = [
            binary, "report", "compare", "--before", str(before / "assessment.json"),
            "--after", str(after / "assessment.json"), "--same-scope", "--format", "json",
        ]
    if {"session-root-healthy", "session-root-bob-healthy"} <= scenarios.keys():
        before = Path(scenarios["session-root-healthy"]["_bundle"])
        after = Path(scenarios["session-root-bob-healthy"]["_bundle"])
        expected["offline supplied-session principal-context comparison"] = [
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
    fingerprint_names = {
        "fingerprint-release-a",
        "fingerprint-release-b",
        "fingerprint-mixed-artifacts",
        "fingerprint-missing-reference",
    }
    if fingerprint_names <= scenarios.keys():
        release_a = Path(scenarios["fingerprint-release-a"]["_bundle"])
        release_b = Path(scenarios["fingerprint-release-b"]["_bundle"])
        missing = Path(scenarios["fingerprint-missing-reference"]["_bundle"])
        expected["offline fingerprint byte comparison"] = [
            binary, "report", "compare", "--before",
            str(release_b / "assessment.json"), "--after",
            str(release_a / "assessment.json"), "--same-scope", "--format", "json",
        ]
        expected["offline fingerprint catalogue comparison"] = [
            binary, "report", "compare", "--before",
            str(release_b / "assessment.json"), "--after",
            str(missing / "assessment.json"), "--same-scope", "--format", "json",
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


def fingerprint_controlled_comparison(
    before_raw,
    after_raw,
    items,
    *,
    catalogue_status,
    changed_resource_paths,
    unchanged_resource_count,
    component_dimensions,
):
    before_audit = json.loads(before_raw)["wordpress_asset_fingerprints"]
    after_audit = json.loads(after_raw)["wordpress_asset_fingerprints"]
    result = comparison_document(
        before_raw,
        len(items),
        after_raw,
        len(items),
        groups={
            "only_in_after": [],
            "only_in_before": [],
            "changed": [],
            "unchanged": [
                comparison_item(
                    item["fingerprint"],
                    item["capability_id"],
                    before=projection_from_item(item),
                    after=copy.deepcopy(projection_from_item(item)),
                    changed_fields=[],
                )
                for item in items
            ],
        },
    )
    wordpress = wordpress_comparison(discovery=True, controlled=False)
    wordpress["schema"] = "termivar-wordpress-review-comparison/v3"
    namespace = "termivar.synthetic.wordpress-asset-fingerprints"
    component = {
        "kind": runner.FINGERPRINT_COMPONENT[0],
        "slug": runner.FINGERPRINT_COMPONENT[1],
    }
    before_resources = {
        resource["relative_path"]: resource for resource in before_audit["resources"]
    }
    after_resources = {
        resource["relative_path"]: resource for resource in after_audit["resources"]
    }
    resource_changes = [
        {
            "key": {
                "source_namespace": namespace,
                "component": copy.deepcopy(component),
                "relative_path": path,
            },
            "changed_dimensions": ["resource_bytes"],
            "before": fingerprint_resource_projection(before_resources[path]),
            "after": fingerprint_resource_projection(after_resources[path]),
        }
        for path in changed_resource_paths
    ]
    before_component = before_audit["components"][0]
    after_component = after_audit["components"][0]
    component_change = {
        "key": {
            "source_namespace": namespace,
            "component": copy.deepcopy(component),
        },
        "changed_dimensions": list(component_dimensions),
        "before": fingerprint_component_projection(before_component),
        "after": fingerprint_component_projection(after_component),
    }
    methodology_before = fingerprint_methodology_projection(before_audit)
    methodology_after = fingerprint_methodology_projection(after_audit)
    coverage_before = fingerprint_coverage_projection(before_audit)
    coverage_after = fingerprint_coverage_projection(after_audit)
    catalogue_changed_fields = (
        ("file_count", "provenance", "revision", "semantic_sha256", "sha256")
        if catalogue_status == "changed" else ()
    )
    wordpress["asset_fingerprints"] = {
        "status": "compared",
        "methodology": fingerprint_comparison_facet(
            before=methodology_before, after=methodology_after
        ),
        "catalogue": fingerprint_comparison_facet(
            catalogue_status,
            before=before_audit["catalogue"],
            after=after_audit["catalogue"],
            changed_fields=catalogue_changed_fields,
        ),
        "coverage": fingerprint_comparison_facet(
            before=coverage_before, after=coverage_after
        ),
        "resources": fingerprint_entity_changes(
            paired_unchanged_count=unchanged_resource_count,
            paired_changed=resource_changes,
        ),
        "components": fingerprint_entity_changes(
            paired_unchanged_count=0,
            paired_changed=[component_change],
        ),
        "interpretation_limits": copy.deepcopy(
            SYNTHETIC_FINGERPRINT_COMPARISON_LIMITS
        ),
    }
    result["wordpress_review_comparison"] = wordpress
    return result


def fingerprint_offline_fixture(root):
    """Synthetic full-path oracle with both positive and selected-empty audits."""
    scenarios, responses, originals = offline_fixture(root)
    surface_item = synthetic_assessment_item(
        BASE_FINGERPRINT, BASE_CAPABILITY, "WordPress surface hints observed"
    )
    discovery_item = synthetic_discovery_item()
    discovery_item["evidence_count"] = 3
    discovery_item["evidence_references"] = [
        "evidence-0001", "evidence-0002", "evidence-0003"
    ]
    items = [surface_item, discovery_item]
    source_template = json.loads(originals[1])
    review_template = source_template["wordpress_review"]
    review_template["schema"] = "security.wordpress-review-audit/v8"
    discovery_template = source_template["wordpress_discovery"]
    discovery_template["schema"] = "security.wordpress-discovery-audit/v3"
    discovery_template["policy_id"] = (
        "termivar.wordpress-page-scoped-metadata-discovery/v1"
    )
    entry_reference = "sha256:" + "4" * 64
    discovery_template["page_collection"] = {
        "mode": "observed",
        "entry_page_reference": entry_reference,
        "candidate_count": 0,
        "selected_count": 0,
        "omitted_candidate_count": 0,
        "reused_response_count": 0,
        "fetched_response_count": 0,
        "not_observed_count": 0,
        "rejected_response_count": 0,
        "accepted_association_count": 0,
        "rejected_association_count": 0,
        "attempted_request_count": 0,
        "completed_response_count": 0,
        "committed_response_count": 0,
        "interpreted_response_bytes": 0,
        "response_bytes": 0,
        "pages": [],
    }
    for source in discovery_template["sources"]:
        source["source_page_references"] = [entry_reference]
    names_and_variants = (
        ("fingerprint-release-a", "release-a"),
        ("fingerprint-release-b", "release-b"),
        ("fingerprint-mixed-artifacts", "mixed-artifacts"),
        ("fingerprint-missing-reference", "missing-reference"),
        ("blog-fingerprint-sibling-rejected", "empty"),
    )
    raw_by_name = {}
    for name, variant in names_and_variants:
        audit = synthetic_fingerprint_audit(variant=variant)
        scenario_items = copy.deepcopy(items)
        if variant == "empty":
            scenario_items[1]["evidence_count"] = 1
            scenario_items[1]["evidence_references"] = ["evidence-0001"]
        optional_audits = {
            "wordpress_review": copy.deepcopy(review_template),
            "wordpress_discovery": copy.deepcopy(discovery_template),
            "wordpress_asset_fingerprints": audit,
        }
        bundle, raw = write_synthetic_bundle(
            root,
            name,
            scenario_items,
            optional_audits=optional_audits,
        )
        resource_count = audit["resource_count"]
        component_count = audit["component_count"]
        scenarios[name] = {
            "bundle": runner._report_identity(bundle),
            "_bundle": str(bundle),
            "fingerprints": {
                "resource_count": resource_count,
                "component_count": component_count,
            },
        }
        raw_by_name[name] = raw
        responses[f"offline verification {name}"] = {
            "schema": "termivar-report-verification/v1",
            "status": "integrity_match",
        }
        responses[f"offline self comparison {name}"] = (
            attach_fingerprint_self_comparison(
                self_comparison(raw, scenario_items),
                audit=audit,
                resource_count=resource_count,
                component_count=component_count,
            )
        )

    responses["offline fingerprint byte comparison"] = (
        fingerprint_controlled_comparison(
            raw_by_name["fingerprint-release-b"],
            raw_by_name["fingerprint-release-a"],
            items,
            catalogue_status="unchanged",
            changed_resource_paths=("assets/fingerprint.css",),
            unchanged_resource_count=1,
            component_dimensions=(
                "candidate_set",
                "reference_matrix",
                "resource_coverage",
            ),
        )
    )
    responses["offline fingerprint catalogue comparison"] = (
        fingerprint_controlled_comparison(
            raw_by_name["fingerprint-release-b"],
            raw_by_name["fingerprint-missing-reference"],
            items,
            catalogue_status="changed",
            changed_resource_paths=(),
            unchanged_resource_count=2,
            component_dimensions=(
                "candidate_set",
                "reference_matrix",
                "resource_coverage",
            ),
        )
    )
    return scenarios, responses, originals


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


def synthetic_supplied_session_audit(
    *, outcome="complete", principal_alias="termivar-lab-alice",
    policy_declares_expiry=True,
):
    """Literal S01 v2 audit fixture; independent of the lab validator."""
    if outcome not in {"complete", "startup_unhealthy", "session_lost"}:
        raise AssertionError(f"unsupported synthetic session outcome: {outcome}")
    checkpoint_specs = (
        [("startup", 0, "unhealthy", "not_matched", "7", 17)]
        if outcome == "startup_unhealthy" else
        [
            ("startup", 0, "healthy", "matched", "7", 17),
            (
                "terminal", 1,
                "unhealthy" if outcome == "session_lost" else "healthy",
                "not_matched" if outcome == "session_lost" else "matched",
                "8", 19,
            ),
        ]
    )
    checkpoints = [
        {
            "sequence": sequence,
            "phase": phase,
            "after_subject_count": after_subject_count,
            "evidence_reference": (
                "supplied-session-checkpoint-evidence-sha256:" + character * 64
            ),
            "outcome": checkpoint_outcome,
            "status": 200,
            "body_state": "complete",
            "predicate": predicate,
            "response_bytes": byte_length,
        }
        for sequence, (
            phase, after_subject_count, checkpoint_outcome, predicate,
            character, byte_length,
        ) in enumerate(checkpoint_specs)
    ]
    committed = outcome == "complete"
    dispatched = outcome != "startup_unhealthy"
    resource_bytes = 23 if dispatched else 0
    resource = {
        "sequence": 0,
        "resource_reference": "supplied-session-resource-sha256:" + "5" * 64,
        "evidence_reference": (
            "supplied-session-resource-evidence-sha256:"
            + ("9" if principal_alias == "termivar-lab-bob" else "6") * 64
            if dispatched else None
        ),
        "outcome": (
            "committed" if committed
            else "health_unqualified" if dispatched
            else "not_dispatched"
        ),
        "status": 200 if dispatched else None,
        "response_bytes": resource_bytes,
        "epoch": 1,
    }
    return {
        "schema": "security.supplied-session-audit/v2",
        "capability_id": "session.supplied-context-assessment@1",
        "policy_reference": "supplied-session-policy-sha256:" + "1" * 64,
        "application_reference": "supplied-session-application-sha256:" + "2" * 64,
        "principal_reference": "supplied-session-principal-0001",
        "principal_alias": principal_alias,
        "principal_assurance": "operator_declared",
        "credential_mechanism": "cookie_jar",
        "cookie_policy": {
            "declared_count": 1,
            "host_only_count": 1,
            "domain_count": 0,
            "secure_count": 0,
            "http_only_count": 1,
            "session_count": int(not policy_declares_expiry),
            "persistent_count": int(policy_declares_expiry),
            "same_site_missing_count": 1,
            "same_site_strict_count": 0,
            "same_site_lax_count": 0,
            "same_site_none_count": 0,
            "update_policy": "stop_on_selected_cookie",
            "browser_semantics": "attributes_preserved_not_browser_csrf_emulation",
        },
        "cookie_lifecycle": {
            "initial_epoch": 1,
            "final_epoch": 1,
            "selected_update_response_count": 0,
            "unselected_update_response_count": 0,
            "update_classification_failure_count": 0,
            "updates_applied": 0,
        },
        "health_oracle": {
            "kind": "json_boolean_true",
            "field_reference": "supplied-session-health-field-sha256:" + "4" * 64,
        },
        "outcome": outcome,
        "coverage": "complete" if committed else "none",
        "checkpoints": checkpoints,
        "resources": [resource],
        "selected_resource_count": 1,
        "dispatched_resource_count": int(dispatched),
        "committed_resource_count": int(committed),
        "dispatched_request_count": len(checkpoints) + int(dispatched),
        "response_bytes": sum(row["response_bytes"] for row in checkpoints)
        + resource_bytes,
        "response_byte_limit": 196_608,
        "response_byte_limit_exceeded": False,
        "refresh_performed": False,
        "anonymous_fallback_performed": False,
        "continuous_authentication_established": False,
        "exploit_execution": "not_performed",
        "impact_validation": "not_performed",
    }


def attach_supplied_session_comparison(
    comparison, *, before_audit, after_audit, context_status,
    health_status, accounting_status, status, reason,
):
    """Attach the literal comparison wire shape without calling production code."""
    def facet(facet_status):
        return {
            "status": facet_status,
            "changed_fields": [],
            "before": {},
            "after": {},
            "note": "Synthetic supplied-session comparison fixture.",
        }

    comparison["supplied_session_comparison"] = {
        "schema": "termivar-supplied-session-comparison/v1",
        "status": status,
        "reason": reason,
        "scope_assurance": "operator_declared",
        "context": facet(context_status),
        "health_and_coverage": facet(health_status),
        "accounting": facet(accounting_status),
        "interpretation_limits": [],
    }
    comparison["supplied_session_comparison"]["context"]["before"] = {
        "principal_alias": before_audit["principal_alias"]
    }
    comparison["supplied_session_comparison"]["context"]["after"] = {
        "principal_alias": after_audit["principal_alias"]
    }
    comparison["supplied_session_comparison"]["context"]["changed_fields"] = (
        []
        if before_audit["principal_alias"] == after_audit["principal_alias"]
        else ["principal_alias"]
    )
    return comparison


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
                    "optional --wordpress-page-scope observed",
                    "optional --wordpress-layout FILE",
                    "optional --wordpress-fingerprints FILE",
                    "optional --wordpress-supplied-session when also compiled with supplied-session-review",
                ],
            }, copy.deepcopy(SYNTHETIC_SESSION_CAPABILITY)]
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
                "optional --wordpress-page-scope observed",
                "optional --wordpress-layout FILE",
                "optional --wordpress-fingerprints FILE",
                "optional --wordpress-supplied-session when also compiled with supplied-session-review",
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
                        + ["optional --wordpress-fingerprints FILE"],
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

    def test_wp_cli_rewrite_config_is_exact_and_used_by_nonroot_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            calls = []

            def fake_docker(*arguments, **kwargs):
                calls.append((arguments, kwargs))
                return runner.CommandResult(b"ok", b"", 0)

            lab.docker = fake_docker
            lab._install_wp_cli_rewrite_config()
            config_arguments, config_kwargs = calls.pop(0)
            self.assertEqual(config_arguments[:4], (
                "exec", "--interactive", lab.wordpress, "sh"
            ))
            self.assertEqual(
                config_kwargs["input_bytes"],
                b"apache_modules:\n  - mod_rewrite\n",
            )
            self.assertIn(runner.WP_CLI_CONFIG_PATH, config_arguments[-1])

            lab.wp("rewrite", "flush", "--hard", label="synthetic hard flush")
            run_arguments = calls[0][0]
            self.assertNotIn("--interactive", run_arguments)
            self.assertIn("--volumes-from", run_arguments)
            self.assertIn("33:33", run_arguments)
            self.assertIn(
                f"WP_CLI_CONFIG_PATH={runner.WP_CLI_CONFIG_PATH}",
                run_arguments,
            )
            self.assertNotIn("--mount", run_arguments)

            calls.clear()
            lab.wp(
                "eval-file", "/dev/stdin", label="synthetic stdin WP-CLI",
                input_bytes=b"<?php echo 'ok';\n",
            )
            self.assertIn("--interactive", calls[0][0])

    def test_pretty_rewrite_ground_truth_uses_each_effective_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            commands = []

            def fake_docker(*arguments, **_kwargs):
                commands.append(arguments[-1])
                return runner.CommandResult(b"", b"", 0)

            lab.docker = fake_docker
            for path in (
                "/var/www/html", "/var/www/html/blog", "/var/www/html/cms"
            ):
                lab._assert_pretty_rewrite_file(path)
            self.assertIn("RewriteBase /", commands[0])
            self.assertIn("RewriteRule . /index.php [L]", commands[0])
            self.assertIn("RewriteBase /blog/", commands[1])
            self.assertIn("RewriteRule . /blog/index.php [L]", commands[1])
            self.assertIn("/var/www/html/.htaccess", commands[2])
            self.assertIn("RewriteRule . /index.php [L]", commands[2])
            with self.assertRaisesRegex(
                runner.AcceptanceError, "unknown pretty-permalink fixture path"
            ):
                lab._assert_pretty_rewrite_file("/var/www/html/other")

    def test_blog_copy_excludes_the_wp_cli_control_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            lab.origin = "http://127.0.0.1:8080/"
            docker_calls = []
            lab.docker = lambda *arguments, **_kwargs: (
                docker_calls.append(arguments)
                or runner.CommandResult(b"", b"", 0)
            )
            lab.wp = lambda *_arguments, **_kwargs: runner.CommandResult(b"", b"", 0)
            lab.configure_at = lambda *_arguments, **_kwargs: None

            self.assertEqual(
                lab.prepare_blog_application(), "http://127.0.0.1:8080/blog/"
            )
            copy_command = docker_calls[0][-1]
            self.assertIn(
                f"! -name {Path(runner.WP_CLI_CONFIG_PATH).name}",
                copy_command,
            )

    def test_fingerprint_variant_selection_uses_only_closed_task_owned_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            lab.wordpress = "task-wordpress"
            docker_calls = []
            wp_calls = []
            lab.docker = lambda *arguments, **_kwargs: (
                docker_calls.append(arguments)
                or runner.CommandResult(b"", b"", 0)
            )
            lab.wp = lambda *arguments, **_kwargs: (
                wp_calls.append(arguments)
                or runner.CommandResult(b"", b"", 0)
            )

            selected = lab.configure_fingerprint_assets(
                variant="mixed",
                mode="one",
                path="/var/www/html/cms",
                plugin_directory="/var/www/html/modules",
            )

            copy_command = docker_calls[0][-1]
            self.assertIn("reference/release-c/assets/fingerprint.js", copy_command)
            self.assertIn("reference/release-a/assets/fingerprint.css", copy_command)
            self.assertNotIn("..", copy_command)
            self.assertEqual(
                wp_calls[0],
                (
                    "--path=/var/www/html/cms", "option", "update",
                    "termivar_fingerprint_lab_mode", "one",
                ),
            )
            self.assertEqual(set(selected["observed_assets"]), {"assets/fingerprint.js"})
            self.assertEqual(selected["installed_plugin_version"], "4.0.0")
            for invalid in ("newest", "../release-a"):
                with self.assertRaisesRegex(
                    runner.AcceptanceError, "unknown fingerprint fixture variant"
                ):
                    lab.configure_fingerprint_assets(variant=invalid, mode="two")

    def test_missing_reference_catalogue_is_a_single_independent_mutation(self):
        original = runner.FINGERPRINT_CATALOGUE_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "missing.json"
            identity = runner._write_missing_reference_catalogue(
                runner.FINGERPRINT_CATALOGUE_PATH, target
            )
            document = json.loads(target.read_bytes())
            release_a = next(
                release for release in document["components"][0]["releases"]
                if release["release_id"] == "release-a"
            )
            self.assertNotIn(
                "assets/fingerprint.css",
                {row["path"] for row in release_a["files"]},
            )
            self.assertEqual(len(release_a["files"]), 2)
            self.assertEqual(identity["byte_length"], target.stat().st_size)
            self.assertEqual(identity["sha256"], runner.sha256_file(target))
        self.assertEqual(runner.FINGERPRINT_CATALOGUE_PATH.read_bytes(), original)

    def test_fingerprint_delta_preserves_existing_trace_and_exact_observed_paths(self):
        baseline = [
            ("GET", "/", 200, ()),
            ("GET", "/contact/", 200, ()),
            ("GET", "/gallery/", 200, ()),
            (
                "HEAD",
                "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.css",
                200,
                (),
            ),
            (
                "GET",
                "/wp-content/plugins/termivar-fingerprint-lab/readme.txt",
                200,
                (),
            ),
        ]
        fingerprint = baseline + [
            (
                "GET",
                "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.css?ver=cache-42",
                200,
                (),
            ),
            (
                "GET",
                "/wp-content/plugins/termivar-fingerprint-lab/assets/fingerprint.js?ver=cache-42",
                200,
                (),
            ),
        ]
        runner._assert_fingerprint_request_delta(
            baseline,
            fingerprint,
            plugin_base_path="/wp-content/plugins/termivar-fingerprint-lab/",
            relative_paths=("assets/fingerprint.js", "assets/fingerprint.css"),
        )
        with self.assertRaisesRegex(
            runner.AcceptanceError, "exact observed-resource oracle"
        ):
            runner._assert_fingerprint_request_delta(
                baseline,
                fingerprint + [("GET", "/unseen.css", 200, ())],
                plugin_base_path="/wp-content/plugins/termivar-fingerprint-lab/",
                relative_paths=("assets/fingerprint.js", "assets/fingerprint.css"),
            )

    def test_fingerprint_delta_requires_matching_option_off_asset_shape(self):
        base = "/wp-content/plugins/termivar-fingerprint-lab/"
        shared = [
            ("GET", "/", 200, ()),
            ("GET", "/contact/", 200, ()),
            ("GET", "/gallery/", 200, ()),
            ("GET", f"{base}readme.txt", 200, ()),
        ]
        two_file_baseline = shared[:-1] + [
            ("HEAD", f"{base}assets/fingerprint.css", 200, ()),
            shared[-1],
        ]
        one_file_baseline = list(shared)
        one_file_fingerprint = one_file_baseline + [
            ("GET", f"{base}assets/fingerprint.js?ver=cache-42", 200, ()),
        ]
        common_file_baseline = shared[:-1] + [
            ("HEAD", f"{base}assets/common.css", 200, ()),
            shared[-1],
        ]
        common_file_fingerprint = common_file_baseline + [
            ("GET", f"{base}assets/common.css?ver=cache-42", 200, ()),
        ]

        runner._assert_fingerprint_request_delta(
            one_file_baseline,
            one_file_fingerprint,
            plugin_base_path=base,
            relative_paths=("assets/fingerprint.js",),
        )
        runner._assert_fingerprint_request_delta(
            common_file_baseline,
            common_file_fingerprint,
            plugin_base_path=base,
            relative_paths=("assets/common.css",),
        )
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "changed, removed, or reordered",
        ) as raised:
            runner._assert_fingerprint_request_delta(
                two_file_baseline,
                one_file_fingerprint,
                plugin_base_path=base,
                relative_paths=("assets/fingerprint.js",),
            )
        self.assertEqual(
            raised.exception.diagnostic["actual"]["matched_baseline_request_count"],
            3,
        )
        self.assertEqual(
            raised.exception.diagnostic["expected"]["baseline_request_count"],
            len(two_file_baseline),
        )

    def test_option_off_fingerprint_trace_retains_head_without_body_get(self):
        base = "/wp-content/plugins/termivar-fingerprint-lab/"
        expected_head = (
            "HEAD",
            f"{base}assets/fingerprint.css",
            200,
            (),
        )
        trace = [
            ("GET", "/", 200, ()),
            ("GET", "/contact/", 200, ()),
            expected_head,
        ]
        paths = ("assets/fingerprint.js", "assets/fingerprint.css")
        runner._assert_fingerprint_option_off_trace(
            trace,
            plugin_base_path=base,
            relative_paths=paths,
        )
        with self.assertRaisesRegex(
            runner.AcceptanceError, "without acquiring fingerprint asset bodies"
        ):
            runner._assert_fingerprint_option_off_trace(
                trace
                + [("GET", f"{base}assets/fingerprint.js?ver=cache-42", 200, ())],
                plugin_base_path=base,
                relative_paths=paths,
            )
        with self.assertRaisesRegex(
            runner.AcceptanceError, "without acquiring fingerprint asset bodies"
        ):
            runner._assert_fingerprint_option_off_trace(
                trace + [("GET", f"{base}assets/unseen.css", 200, ())],
                plugin_base_path=base,
                relative_paths=paths,
            )
        with self.assertRaisesRegex(
            runner.AcceptanceError, "preserve the ordinary stylesheet HEAD"
        ):
            runner._assert_fingerprint_option_off_trace(
                trace[:-1],
                plugin_base_path=base,
                relative_paths=paths,
            )

    def test_fingerprint_accounting_diagnostic_distinguishes_values_and_types(self):
        document = {
            "wordpress_asset_fingerprints": {
                "candidate_count": 0,
                "attempted_request_count": True,
                "reused_response_count": "0",
                "resources": {"body": "https://private.invalid/secret"},
                "stop": None,
                "components": [{
                    "state": "single_catalogue_candidate",
                    "compatible_release_ids": ["release-b"],
                    "undetermined_release_ids": [],
                    "inconsistent_release_ids": ["release-a", "release-c"],
                    "query": "token=private",
                }],
            },
            "wordpress_discovery": {
                "page_collection": {"committed_response_count": 0}
            },
            "wordpress_review": {},
        }
        diagnostic = runner._bounded_fingerprint_accounting_diagnostic(
            document,
            asset_count=2,
            expected_state="single_catalogue_candidate",
            compatible=["release-b"],
            undetermined=[],
            inconsistent=["release-a", "release-c"],
        )
        actual = diagnostic["actual"]["fingerprint"]
        self.assertEqual(actual["candidate_count"], {"status": "present", "value": 0})
        self.assertEqual(actual["selected_resource_count"], {"status": "missing"})
        self.assertEqual(
            actual["attempted_request_count"],
            {"status": "wrong_type", "json_type": "boolean"},
        )
        self.assertEqual(
            actual["reused_response_count"],
            {"status": "wrong_type", "json_type": "string"},
        )
        self.assertEqual(
            actual["resources_length"],
            {"status": "wrong_type", "json_type": "object"},
        )
        encoded = json.dumps(diagnostic, sort_keys=True)
        self.assertLess(len(encoded.encode("utf-8")), 8 * 1024)
        self.assertNotIn("private.invalid", encoded)
        self.assertNotIn("token=private", encoded)

    def _fingerprint_accounting_mismatch_document(self):
        catalogue = runner.FINGERPRINT_CATALOGUE_PATH
        return {
            "wordpress_asset_fingerprints": {
                "schema": "security.wordpress-asset-fingerprint-audit/v1",
                "capability_id": "technology.wordpress-asset-fingerprint-candidate@1",
                "policy_id": "termivar.wordpress-observed-asset-fingerprint/v1",
                "selected": True,
                "representation_profile": "identity-content-bytes/v1",
                "finite_reference_scope": "listed_releases_only",
                "same_release_assumption": (
                    "considered_paths_share_one_listed_release_artifact_set"
                ),
                "installed_version_assurance": (
                    "not_established_by_asset_fingerprints"
                ),
                "source_authenticity": "not_established",
                "catalogue": {
                    "schema": "security.wordpress-asset-fingerprint-catalog/v1",
                    "byte_length": catalogue.stat().st_size,
                    "sha256": runner.sha256_file(catalogue),
                    "semantic_sha256": "a" * 64,
                    "component_count": 1,
                    "release_count": 3,
                },
                "candidate_count": 0,
                "selected_resource_count": 0,
                "omitted_resource_count": 0,
                "attempted_request_count": 0,
                "reused_response_count": 0,
                "fetched_response_count": 0,
                "stop": "complete",
                "resource_count": 0,
                "resources": [],
                "components": [],
            },
            "wordpress_discovery": {},
            "wordpress_review": {},
        }

    def _rejected_blog_fingerprint_document(self):
        document = copy.deepcopy(self.discovery_document())
        audit = self._fingerprint_accounting_mismatch_document()[
            "wordpress_asset_fingerprints"
        ]
        audit["catalogue"].update({
            "id": "termivar-wordpress-asset-matrix",
            "revision": "v1",
            "source_namespace": "termivar.synthetic.wordpress-asset-fingerprints",
            "file_count": 9,
        })
        audit.update({
            "response_bytes": 0,
            "component_count": 0,
        })
        document["wordpress_asset_fingerprints"] = audit

        review = document["wordpress_review"]
        review["schema"] = "security.wordpress-review-audit/v8"
        review["review_basis_schema"] = "security.wordpress-review-audit/v1"
        review["additional_request_count"] = 4

        discovery = document["wordpress_discovery"]
        discovery["schema"] = "security.wordpress-discovery-audit/v3"
        discovery["policy_id"] = (
            "termivar.wordpress-page-scoped-metadata-discovery/v1"
        )
        discovery["seed_count"] = 3
        discovery["layout"]["skipped_sibling_application_count"] = 1
        discovery["page_collection"] = {
            "mode": "observed",
            "entry_page_reference": REJECTED_BLOG_ENTRY_REFERENCE,
            "candidate_count": 2,
            "selected_count": 2,
            "omitted_candidate_count": 0,
            "reused_response_count": 2,
            "fetched_response_count": 0,
            "not_observed_count": 0,
            "rejected_response_count": 2,
            "accepted_association_count": 0,
            "rejected_association_count": 2,
            "attempted_request_count": 0,
            "completed_response_count": 2,
            "committed_response_count": 2,
            "interpreted_response_bytes": 768,
            "response_bytes": 0,
            "pages": [
                {
                    "page_reference": "sha256:" + "9" * 64,
                    "acquisition": "reused",
                    "association": "rejected",
                    "outcome": "incompatible_application",
                    "request_attempted": False,
                    "interpreted_response_bytes": 384,
                    "response_bytes": 0,
                    "evidence_reference_count": 1,
                    "evidence_references": ["evidence-0005"],
                },
                {
                    "page_reference": "sha256:" + "e" * 64,
                    "acquisition": "reused",
                    "association": "rejected",
                    "outcome": "incompatible_application",
                    "request_attempted": False,
                    "interpreted_response_bytes": 384,
                    "response_bytes": 0,
                    "evidence_reference_count": 1,
                    "evidence_references": ["evidence-0006"],
                },
            ],
        }
        for source in discovery["sources"]:
            source["source_page_references"] = [REJECTED_BLOG_ENTRY_REFERENCE]
        item = document["items"][0]
        item["evidence_count"] = 6
        item["evidence_references"] = [
            "evidence-0001",
            "evidence-0002",
            "evidence-0003",
            "evidence-0004",
            "evidence-0005",
            "evidence-0006",
        ]
        return document

    def _accepted_root_observed_document(self):
        document = self._rejected_blog_fingerprint_document()
        document.pop("wordpress_asset_fingerprints")
        review = document["wordpress_review"]
        review["schema"] = "security.wordpress-review-audit/v7"
        review["additional_request_count"] = 5
        review["components"].insert(3, {
            "identity": {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            },
            "identity_sources": ["same_origin_asset_path"],
            "versions": [],
        })

        discovery = document["wordpress_discovery"]
        discovery["seed_count"] = 4
        for field in (
            "candidate_count",
            "attempted_request_count",
            "completed_response_count",
            "committed_response_count",
            "source_count",
        ):
            discovery[field] = 5
        discovery["response_bytes"] = 1280
        discovery["layout"]["skipped_sibling_application_count"] = 0
        page_collection = discovery["page_collection"]
        page_collection.update({
            "rejected_response_count": 0,
            "accepted_association_count": 2,
            "rejected_association_count": 0,
        })
        page_references = [
            page["page_reference"] for page in page_collection["pages"]
        ]
        for index, page in enumerate(page_collection["pages"], start=6):
            page.update({
                "association": "accepted",
                "outcome": "accepted",
                "evidence_references": [f"evidence-{index:04d}"],
            })
        fingerprint_source = copy.deepcopy(discovery["sources"][3])
        fingerprint_source.update({
            "component": {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            },
            "evidence_references": ["evidence-0004"],
            "source_page_references": page_references,
            "plugin": {
                "name": "Termivar Fingerprint Lab",
                "stable_tag": "9.9.9",
            },
        })
        discovery["sources"].insert(3, fingerprint_source)
        discovery["sources"][4]["evidence_references"] = ["evidence-0005"]
        item = document["items"][0]
        item["evidence_count"] = 7
        item["evidence_references"] = [
            f"evidence-{index:04d}" for index in range(1, 8)
        ]
        return document

    def _accepted_custom_fingerprint_document(self):
        document = self._accepted_root_observed_document()
        review = document["wordpress_review"]
        review["schema"] = "security.wordpress-review-audit/v8"
        review["additional_request_count"] = 7

        discovery = document["wordpress_discovery"]
        fingerprint_source = next(
            source
            for source in discovery["sources"]
            if source.get("component")
            == {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            }
        )
        fingerprint_source["association"] = "explicit_operator"
        page_references = [
            page["page_reference"]
            for page in discovery["page_collection"]["pages"]
        ]

        audit = synthetic_fingerprint_audit(variant="release-b")
        audit["catalogue"].update({
            "byte_length": runner.FINGERPRINT_CATALOGUE_PATH.stat().st_size,
            "sha256": runner.sha256_file(runner.FINGERPRINT_CATALOGUE_PATH),
        })
        audit.update({
            "attempted_request_count": 2,
            "reused_response_count": 0,
            "fetched_response_count": 2,
            "response_bytes": sum(
                resource["observation"]["byte_length"]
                for resource in audit["resources"]
            ),
        })
        for resource in audit["resources"]:
            resource.update({
                "source_page_references": list(page_references),
                "acquisition": "fetched",
                "request_attempted": True,
                "response_bytes": resource["observation"]["byte_length"],
            })
        document["wordpress_asset_fingerprints"] = audit
        return document

    def test_rejected_blog_pages_preserve_empty_selected_fingerprint_audit(self):
        self.assertEqual(
            runner._framed_reference(
                "wordpress-discovery-page", REJECTED_BLOG_APPLICATION_URL
            ),
            REJECTED_BLOG_ENTRY_REFERENCE,
        )
        document = self._rejected_blog_fingerprint_document()
        summary = runner._validate_rejected_page_fingerprint_document(
            document,
            catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
            expected_discovery_request_count=4,
            expected_application_url=REJECTED_BLOG_APPLICATION_URL,
        )
        self.assertEqual(summary["state"], "no_eligible_resources_from_rejected_pages")
        self.assertEqual(summary["candidate_count"], 0)
        self.assertEqual(summary["attempted_request_count"], 0)

        option_off = copy.deepcopy(document)
        option_off.pop("wordpress_asset_fingerprints")
        option_off["wordpress_review"]["schema"] = (
            "security.wordpress-review-audit/v7"
        )
        self.assertEqual(
            runner._validate_observed_page_baseline(
                option_off,
                expected_discovery_request_count=4,
                expected_page_association="rejected",
            ),
            "security.wordpress-discovery-audit/v3",
        )

    def test_rejected_blog_sources_require_exact_entry_only_provenance(self):
        def validate(document):
            runner._validate_rejected_page_fingerprint_document(
                document,
                catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                expected_discovery_request_count=4,
                expected_application_url=REJECTED_BLOG_APPLICATION_URL,
            )

        provenance_mutations = []
        for value in ([], None, "entry", {}, 1, True):
            document = self._rejected_blog_fingerprint_document()
            document["wordpress_discovery"]["sources"][0][
                "source_page_references"
            ] = value
            provenance_mutations.append(document)
        missing = self._rejected_blog_fingerprint_document()
        del missing["wordpress_discovery"]["sources"][0]["source_page_references"]
        provenance_mutations.append(missing)

        rejected_reference = self._rejected_blog_fingerprint_document()
        rejected = rejected_reference["wordpress_discovery"]["page_collection"][
            "pages"
        ][0]["page_reference"]
        rejected_reference["wordpress_discovery"]["sources"][0][
            "source_page_references"
        ] = [rejected]
        provenance_mutations.append(rejected_reference)

        mixed = self._rejected_blog_fingerprint_document()
        mixed["wordpress_discovery"]["sources"][0]["source_page_references"] = [
            REJECTED_BLOG_ENTRY_REFERENCE,
            rejected,
        ]
        provenance_mutations.append(mixed)

        duplicate = self._rejected_blog_fingerprint_document()
        duplicate["wordpress_discovery"]["sources"][0][
            "source_page_references"
        ] = [REJECTED_BLOG_ENTRY_REFERENCE, REJECTED_BLOG_ENTRY_REFERENCE]
        provenance_mutations.append(duplicate)

        substituted = self._rejected_blog_fingerprint_document()
        substitute_reference = "sha256:" + "f" * 64
        substituted["wordpress_discovery"]["page_collection"][
            "entry_page_reference"
        ] = substitute_reference
        for source in substituted["wordpress_discovery"]["sources"]:
            source["source_page_references"] = [substitute_reference]
        provenance_mutations.append(substituted)

        entry_as_page = self._rejected_blog_fingerprint_document()
        entry_as_page["wordpress_discovery"]["page_collection"]["pages"][0][
            "page_reference"
        ] = REJECTED_BLOG_ENTRY_REFERENCE
        provenance_mutations.append(entry_as_page)

        for index, document in enumerate(provenance_mutations):
            with self.subTest(provenance_mutation=index):
                with self.assertRaises(runner.AcceptanceError):
                    validate(document)

    def test_rejected_blog_sources_require_literal_unique_identity_order(self):
        def validate(document):
            runner._validate_rejected_page_fingerprint_document(
                document,
                catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                expected_discovery_request_count=4,
                expected_application_url=REJECTED_BLOG_APPLICATION_URL,
            )

        mutations = []
        missing = self._rejected_blog_fingerprint_document()
        missing["wordpress_discovery"]["sources"].pop()
        mutations.append(missing)

        extra = self._rejected_blog_fingerprint_document()
        extra["wordpress_discovery"]["sources"].append(
            copy.deepcopy(extra["wordpress_discovery"]["sources"][0])
        )
        mutations.append(extra)

        duplicated = self._rejected_blog_fingerprint_document()
        duplicated["wordpress_discovery"]["sources"][1] = copy.deepcopy(
            duplicated["wordpress_discovery"]["sources"][0]
        )
        mutations.append(duplicated)

        malformed = self._rejected_blog_fingerprint_document()
        malformed["wordpress_discovery"]["sources"][0] = []
        mutations.append(malformed)

        reordered = self._rejected_blog_fingerprint_document()
        reordered["wordpress_discovery"]["sources"][1:3] = reversed(
            reordered["wordpress_discovery"]["sources"][1:3]
        )
        mutations.append(reordered)

        rest_component = self._rejected_blog_fingerprint_document()
        rest_component["wordpress_discovery"]["sources"][0]["component"] = {
            "kind": "core",
            "slug": "wordpress",
        }
        mutations.append(rest_component)

        substituted_slug = self._rejected_blog_fingerprint_document()
        substituted_slug["wordpress_discovery"]["sources"][3]["component"][
            "slug"
        ] = "substituted-plugin"
        mutations.append(substituted_slug)

        for index, document in enumerate(mutations):
            with self.subTest(identity_mutation=index):
                with self.assertRaises(runner.AcceptanceError):
                    validate(document)

    def test_rejected_blog_provenance_diagnostics_preserve_safe_type_and_membership(self):
        cases = []
        missing = self._rejected_blog_fingerprint_document()
        del missing["wordpress_discovery"]["sources"][0]["source_page_references"]
        cases.append((missing, '"status": "missing"'))

        wrong_type = self._rejected_blog_fingerprint_document()
        wrong_type["wordpress_discovery"]["sources"][0][
            "source_page_references"
        ] = "https://private.invalid/asset.js?token=secret"
        cases.append((wrong_type, '"json_type": "string"'))

        substituted = self._rejected_blog_fingerprint_document()
        substitute_reference = "sha256:" + "f" * 64
        substituted["wordpress_discovery"]["page_collection"][
            "entry_page_reference"
        ] = substitute_reference
        for source in substituted["wordpress_discovery"]["sources"]:
            source["source_page_references"] = [substitute_reference]
        cases.append((substituted, '"matches_application": false'))

        for document, marker in cases:
            with self.subTest(marker=marker):
                with self.assertRaises(runner.AcceptanceError) as raised:
                    runner._validate_rejected_page_fingerprint_document(
                        document,
                        catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                        expected_discovery_request_count=4,
                        expected_application_url=REJECTED_BLOG_APPLICATION_URL,
                    )
                encoded = json.dumps(raised.exception.diagnostic, sort_keys=True)
                self.assertLess(len(encoded.encode("utf-8")), 8 * 1024)
                self.assertIn(marker, encoded)
                self.assertNotIn("private.invalid", encoded)
                self.assertNotIn("token=secret", encoded)
                self.assertNotIn(REJECTED_BLOG_APPLICATION_URL, encoded)

    def test_accepted_root_pages_retain_deduplicated_fingerprint_readme(self):
        document = self._accepted_root_observed_document()
        self.assertEqual(
            runner._validate_observed_page_baseline(document),
            "security.wordpress-discovery-audit/v3",
        )

        reordered = copy.deepcopy(document)
        sources = reordered["wordpress_discovery"]["sources"]
        sources[3], sources[4] = sources[4], sources[3]
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "source identities changed",
        ):
            runner._validate_observed_page_baseline(reordered)

    def test_observed_page_baseline_requires_independent_role_binding_basis(self):
        document = self._accepted_root_observed_document()
        fingerprint_source = next(
            source
            for source in document["wordpress_discovery"]["sources"]
            if source.get("component")
            == {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            }
        )
        self.assertEqual(fingerprint_source["association"], "observed_conventional")

        custom_document = copy.deepcopy(document)
        custom_source = next(
            source
            for source in custom_document["wordpress_discovery"]["sources"]
            if source.get("component")
            == {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            }
        )
        custom_source["association"] = "explicit_operator"
        self.assertEqual(
            runner._validate_observed_page_baseline(
                custom_document,
                expected_component_association="explicit_operator",
            ),
            "security.wordpress-discovery-audit/v3",
        )

        for wrong_association in (
            "observed_conventional",
            "same_theme_base_parent",
            None,
            True,
        ):
            with self.subTest(wrong_association=wrong_association):
                mutated = copy.deepcopy(custom_document)
                mutated_source = next(
                    source
                    for source in mutated["wordpress_discovery"]["sources"]
                    if source.get("component")
                    == {
                        "kind": runner.FINGERPRINT_COMPONENT[0],
                        "slug": runner.FINGERPRINT_COMPONENT[1],
                    }
                )
                mutated_source["association"] = wrong_association
                with self.assertRaisesRegex(
                    runner.AcceptanceError,
                    "conditional plugin binding",
                ):
                    runner._validate_observed_page_baseline(
                        mutated,
                        expected_component_association="explicit_operator",
                    )

    def test_fingerprint_document_requires_declared_custom_role_binding_basis(self):
        document = self._accepted_custom_fingerprint_document()
        resources = document["wordpress_asset_fingerprints"]["resources"]
        asset_oracle = {
            resource["relative_path"]: copy.deepcopy(resource["observation"])
            for resource in resources
        }
        summary = runner._validate_fingerprint_document(
            document,
            catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
            asset_oracle=asset_oracle,
            expected_state="single_catalogue_candidate",
            compatible=["release-b"],
            undetermined=[],
            inconsistent=["release-a", "release-c"],
            expected_component_association="explicit_operator",
        )
        self.assertEqual(summary["state"], "single_catalogue_candidate")

        mutated = copy.deepcopy(document)
        fingerprint_source = next(
            source
            for source in mutated["wordpress_discovery"]["sources"]
            if source.get("component")
            == {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            }
        )
        fingerprint_source["association"] = "observed_conventional"
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "plugin metadata",
        ):
            runner._validate_fingerprint_document(
                mutated,
                catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                asset_oracle=asset_oracle,
                expected_state="single_catalogue_candidate",
                compatible=["release-b"],
                undetermined=[],
                inconsistent=["release-a", "release-c"],
                expected_component_association="explicit_operator",
            )

    def test_rejected_blog_fingerprint_oracle_rejects_false_authority(self):
        mutations = []

        boolean_count = self._rejected_blog_fingerprint_document()
        boolean_count["wordpress_asset_fingerprints"]["candidate_count"] = False
        mutations.append(boolean_count)

        nonempty_resource = self._rejected_blog_fingerprint_document()
        nonempty_resource["wordpress_asset_fingerprints"]["resources"] = [
            {"private_url": "https://private.invalid/asset.js"}
        ]
        mutations.append(nonempty_resource)

        accepted_page = self._rejected_blog_fingerprint_document()
        accepted_page["wordpress_discovery"]["page_collection"].update({
            "rejected_response_count": 1,
            "accepted_association_count": 1,
            "rejected_association_count": 1,
        })
        accepted_page["wordpress_discovery"]["page_collection"]["pages"][0].update({
            "association": "accepted",
            "outcome": "accepted",
        })
        mutations.append(accepted_page)

        duplicate_page_reference = self._rejected_blog_fingerprint_document()
        pages = duplicate_page_reference["wordpress_discovery"]["page_collection"][
            "pages"
        ]
        pages[1]["page_reference"] = pages[0]["page_reference"]
        mutations.append(duplicate_page_reference)

        duplicate_evidence_reference = self._rejected_blog_fingerprint_document()
        pages = duplicate_evidence_reference["wordpress_discovery"]["page_collection"][
            "pages"
        ]
        pages[1]["evidence_references"] = pages[0]["evidence_references"]
        mutations.append(duplicate_evidence_reference)

        fingerprint_readme = self._rejected_blog_fingerprint_document()
        fingerprint_readme["wordpress_discovery"]["sources"][3]["component"] = {
            "kind": runner.FINGERPRINT_COMPONENT[0],
            "slug": runner.FINGERPRINT_COMPONENT[1],
        }
        mutations.append(fingerprint_readme)

        fingerprint_component = self._rejected_blog_fingerprint_document()
        fingerprint_component["wordpress_review"]["components"][3]["identity"] = {
            "kind": runner.FINGERPRINT_COMPONENT[0],
            "slug": runner.FINGERPRINT_COMPONENT[1],
        }
        mutations.append(fingerprint_component)

        wrong_additional_count = self._rejected_blog_fingerprint_document()
        wrong_additional_count["wordpress_review"]["additional_request_count"] = 5
        mutations.append(wrong_additional_count)

        for index, mutated in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(runner.AcceptanceError):
                    runner._validate_rejected_page_fingerprint_document(
                        mutated,
                        catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                        expected_discovery_request_count=4,
                        expected_application_url=REJECTED_BLOG_APPLICATION_URL,
                    )

    def test_rejected_blog_fingerprint_failure_diagnostic_is_bounded(self):
        document = self._rejected_blog_fingerprint_document()
        document["wordpress_asset_fingerprints"]["candidate_count"] = 1
        document["wordpress_asset_fingerprints"]["private"] = {
            "url": "https://private.invalid/asset.js?token=secret"
        }
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "unexpectedly authorized fingerprint work",
        ) as raised:
            runner._validate_rejected_page_fingerprint_document(
                document,
                catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                expected_discovery_request_count=4,
                expected_application_url=REJECTED_BLOG_APPLICATION_URL,
            )
        encoded = json.dumps(raised.exception.diagnostic, sort_keys=True)
        self.assertLess(len(encoded.encode("utf-8")), 8 * 1024)
        self.assertIn('"candidate_count": {"status": "present", "value": 1}', encoded)
        self.assertNotIn("private.invalid", encoded)
        self.assertNotIn("token=secret", encoded)

    def test_fingerprint_accounting_mismatch_retains_bounded_diagnostic(self):
        document = self._fingerprint_accounting_mismatch_document()
        oracle = {
            "assets/fingerprint.js": {"byte_length": 1, "sha256": "1" * 64},
            "assets/fingerprint.css": {"byte_length": 1, "sha256": "2" * 64},
        }
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "fingerprint acquisition accounting differs",
        ) as raised:
            runner._validate_fingerprint_document(
                document,
                catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                asset_oracle=oracle,
                expected_state="single_catalogue_candidate",
                compatible=["release-b"],
                undetermined=[],
                inconsistent=["release-a", "release-c"],
            )
        diagnostic = raised.exception.diagnostic
        self.assertEqual(diagnostic["expected"]["fingerprint"]["candidate_count"], 2)
        self.assertEqual(
            diagnostic["actual"]["fingerprint"]["candidate_count"],
            {"status": "present", "value": 0},
        )

    def test_diagnostic_capture_failure_preserves_original_acceptance_error(self):
        document = self._fingerprint_accounting_mismatch_document()
        oracle = {
            "assets/fingerprint.js": {"byte_length": 1, "sha256": "1" * 64},
            "assets/fingerprint.css": {"byte_length": 1, "sha256": "2" * 64},
        }
        with mock.patch.object(
            runner,
            "_bounded_fingerprint_accounting_diagnostic",
            side_effect=RuntimeError("diagnostic failed"),
        ):
            with self.assertRaisesRegex(
                runner.AcceptanceError,
                "fingerprint acquisition accounting differs",
            ) as raised:
                runner._validate_fingerprint_document(
                    document,
                    catalogue_path=runner.FINGERPRINT_CATALOGUE_PATH,
                    asset_oracle=oracle,
                    expected_state="single_catalogue_candidate",
                    compatible=["release-b"],
                    undetermined=[],
                    inconsistent=["release-a", "release-c"],
                )
        self.assertEqual(
            raised.exception.diagnostic,
            {"status": "unavailable", "reason": "diagnostic_capture_failed"},
        )

    def test_failure_evidence_retains_safe_diagnostic_identity(self):
        source_ref = "1" * 40
        failure_context = {
            "scenario": "fingerprint-release-b",
            "source_ref": source_ref,
            "binary": {
                "version": "termivar 0.10.0-alpha.3",
                "byte_length": 123,
                "sha256": "2" * 64,
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            with mock.patch.object(
                runner,
                "execute_acceptance",
                side_effect=runner.AcceptanceError(
                    "fingerprint acquisition accounting differs",
                    failure_context,
                ),
            ):
                exit_code = runner.main([
                    "--binary",
                    str(MODULE_PATH),
                    "--output-dir",
                    str(destination),
                    "--source-ref",
                    source_ref,
                    "--expect-version",
                    "0.10.0-alpha.3",
                ])
            self.assertEqual(exit_code, 1)
            evidence = json.loads(
                (destination / "wordpress-discovery-lab-acceptance.json").read_bytes()
            )
            self.assertEqual(evidence["failure_context"], failure_context)
            self.assertNotIn("path", evidence["failure_context"]["binary"])

    def test_evidence_write_failure_does_not_conceal_acceptance_failure(self):
        source_ref = "1" * 40
        with mock.patch.object(
            runner,
            "execute_acceptance",
            side_effect=runner.AcceptanceError("original fingerprint mismatch"),
        ), mock.patch.object(
            runner,
            "write_evidence",
            side_effect=OSError("C:/private/export/report.json"),
        ), mock.patch.object(runner.sys, "stderr", new_callable=io.StringIO) as stderr:
            exit_code = runner.main([
                "--binary",
                str(MODULE_PATH),
                "--output-dir",
                str(Path.cwd() / "unused-evidence"),
                "--source-ref",
                source_ref,
                "--expect-version",
                "0.10.0-alpha.3",
            ])
        self.assertEqual(exit_code, 1)
        self.assertIn("original fingerprint mismatch", stderr.getvalue())
        self.assertIn("evidence_write_error=OSError", stderr.getvalue())
        self.assertNotIn("private/export", stderr.getvalue())

    def test_fixture_inventory_and_digest_pins_are_closed(self):
        result = runner.validate_fixture()
        self.assertEqual(result["file_count"], 28)
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

    def test_process_runner_measures_an_expected_nonzero_exit_without_status_noise(self):
        result = runner.ProcessRunner().run(
            [sys.executable, "-c", "raise SystemExit(7)"],
            expected=7,
            label="expected nonzero process metric self-test",
            measure_peak_memory=True,
        )
        self.assertEqual(result.returncode, 7)
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
        self.assertEqual(source.count('"--pull=never"'), 3)
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

    def test_sparse_custom_layout_oracle_accepts_no_plugin_component(self):
        document = self.discovery_document()
        application = "http://127.0.0.1:8080/"
        core = application + "cms/"
        oracle = runner.DiscoveryOracle(
            application_url=application,
            request_paths=runner.EXPECTED_DISCOVERY_PATHS["custom-no-layout"],
            core_base_url=core,
            themes_base_url=None,
            plugins_base_url=None,
            rest_base_url=application,
        )
        review = document["wordpress_review"]
        review["additional_request_count"] = 1
        review["components"] = review["components"][:1]
        discovery = document["wordpress_discovery"]
        for field in (
            "seed_count",
            "candidate_count",
            "attempted_request_count",
            "completed_response_count",
            "committed_response_count",
            "source_count",
        ):
            discovery[field] = 1
        discovery["response_bytes"] = 256
        discovery["sources"] = discovery["sources"][:1]
        discovery["layout"] = {
            "application_reference": runner._framed_reference(
                "wordpress-selected-application", application
            ),
            "roles": [
                {
                    "role": "core",
                    "status": "exact",
                    "basis": "conventional_asset",
                    "reference": runner._framed_reference(
                        "wordpress-discovery-role", core
                    ),
                    "candidate_count": 1,
                },
                {
                    "role": "themes",
                    "status": "unresolved",
                    "basis": "none",
                    "candidate_count": 0,
                },
                {
                    "role": "plugins",
                    "status": "unresolved",
                    "basis": "none",
                    "candidate_count": 0,
                },
                {
                    "role": "rest_index",
                    "status": "exact",
                    "basis": "structured_advertisement",
                    "reference": runner._framed_reference(
                        "wordpress-discovery-role", application
                    ),
                    "candidate_count": 1,
                },
            ],
            "skipped_foreign_origin_count": 0,
            "skipped_sibling_application_count": 0,
            "conflicting_association_count": 0,
        }
        source = discovery["sources"][0]
        source["resource_reference"] = runner._framed_reference(
            "wordpress-discovery-resource", application.rstrip("/") + "/wp-json/"
        )
        source["role_reference"] = runner._framed_reference(
            "wordpress-discovery-role", application
        )
        item = document["items"][0]
        item["evidence_count"] = 1
        item["evidence_references"] = ["evidence-0001"]

        self.assertEqual(
            runner._validate_discovery_document(
                document, generator_visible=True, oracle=oracle
            ),
            "security.wordpress-discovery-audit/v2",
        )

    def test_discovery_evidence_linkage_is_order_independent_but_exact(self):
        document = self.discovery_document()
        item_references = document["items"][0]["evidence_references"]
        item_references.reverse()
        self.assertEqual(
            runner._validate_discovery_document(document, generator_visible=True),
            "security.wordpress-discovery-audit/v2",
        )

        for replacement in (
            ["evidence-0001", "evidence-0002", "evidence-0003", "evidence-9999"],
            ["evidence-0001", "evidence-0002", "evidence-0003", "evidence-0003"],
        ):
            malformed = self.discovery_document()
            malformed["items"][0]["evidence_references"] = replacement
            with self.subTest(replacement=replacement):
                with self.assertRaisesRegex(
                    runner.AcceptanceError,
                    "discovery source-to-evidence linkage differs",
                ):
                    runner._validate_discovery_document(
                        malformed, generator_visible=True
                    )

    def test_discovery_source_shape_accepts_closed_sparse_metadata_rows(self):
        common = {
            "association": "invalid_advertisement",
            "resource_reference": "sha256:" + "4" * 64,
            "parent_depth": 0,
            "outcome": "invalid_advertisement",
            "request_attempted": False,
            "response_bytes": 0,
            "evidence_reference_count": 0,
            "evidence_references": [],
        }
        rest = {"kind": "rest_index", **common}
        runner._validate_discovery_source_shape(rest)

        runner._validate_discovery_source_shape({
            "kind": "rest_index",
            "association": "structured_advertisement",
            "resource_reference": "sha256:" + "7" * 64,
            "role_reference": REST_REFERENCE,
            "parent_depth": 0,
            "outcome": "no_metadata",
            "request_attempted": True,
            "response_bytes": 16,
            "evidence_reference_count": 1,
            "evidence_references": ["evidence-0001"],
        })

        for kind, component in (
            ("theme_stylesheet", {"kind": "theme", "slug": "termivar-child"}),
            ("plugin_readme", {"kind": "plugin", "slug": "termivar-plugin"}),
        ):
            with self.subTest(kind=kind):
                runner._validate_discovery_source_shape({
                    "kind": kind,
                    "association": "observed_conventional",
                    "resource_reference": "sha256:" + "5" * 64,
                    "role_reference": "sha256:" + "6" * 64,
                    "component": component,
                    "parent_depth": 0,
                    "outcome": "no_metadata",
                    "request_attempted": True,
                    "response_bytes": 16,
                    "evidence_reference_count": 1,
                    "evidence_references": ["evidence-0001"],
                })

        observed = copy.deepcopy(self.discovery_document()["wordpress_discovery"]["sources"])
        for source in observed:
            runner._validate_discovery_source_shape(source)

    def test_discovery_source_diagnostics_are_bounded_and_value_safe(self):
        sources = [
            {"kind": "rest_index", "outcome": "not_found"},
            {"kind": ["private-value"], "outcome": {"secret": True}},
        ]
        sources.extend(
            {"kind": "private-value", "outcome": "secret-value"}
            for _ in range(11)
        )
        summary = runner._bounded_discovery_source_outcomes({
            "wordpress_discovery": {"sources": sources}
        })
        self.assertTrue(summary.startswith("rest_index:not_found,invalid:invalid"))
        self.assertTrue(summary.endswith(",truncated"))
        self.assertNotIn("private-value", summary)
        self.assertNotIn("secret-value", summary)
        self.assertEqual(
            runner._bounded_discovery_source_outcomes({
                "wordpress_discovery": ["not-an-object"]
            }),
            "unavailable",
        )

    def test_sparse_source_shape_cannot_satisfy_the_real_cms_oracle(self):
        document = copy.deepcopy(self.discovery_document())
        source = document["wordpress_discovery"]["sources"][1]
        source["outcome"] = "no_metadata"
        source.pop("theme")

        runner._validate_discovery_source_shape(source)
        with self.assertRaisesRegex(
            runner.AcceptanceError,
            "source outcome, evidence, or byte accounting differs",
        ):
            runner._validate_discovery_document(
                document,
                generator_visible=True,
            )

    def test_discovery_source_shape_rejects_missing_cross_kind_and_extra_fields(self):
        sources = self.discovery_document()["wordpress_discovery"]["sources"]
        cases = []

        unknown_kind = copy.deepcopy(sources[0])
        unknown_kind["kind"] = "unknown"
        cases.append(unknown_kind)

        missing_required = copy.deepcopy(sources[1])
        missing_required.pop("component")
        cases.append(missing_required)

        rest_component = copy.deepcopy(sources[0])
        rest_component["component"] = {"kind": "core", "slug": "wordpress"}
        cases.append(rest_component)

        theme_plugin_metadata = copy.deepcopy(sources[1])
        theme_plugin_metadata["plugin"] = {"name": "wrong metadata class"}
        cases.append(theme_plugin_metadata)

        plugin_namespaces = copy.deepcopy(sources[3])
        plugin_namespaces["namespaces"] = ["wp/v2"]
        cases.append(plugin_namespaces)

        invalid_metadata_type = copy.deepcopy(sources[0])
        invalid_metadata_type["namespaces"] = {"wp/v2": True}
        cases.append(invalid_metadata_type)

        missing_observed_metadata = copy.deepcopy(sources[1])
        missing_observed_metadata.pop("theme")
        cases.append(missing_observed_metadata)

        empty_observed_metadata = copy.deepcopy(sources[1])
        empty_observed_metadata["theme"] = {}
        cases.append(empty_observed_metadata)

        empty_observed_namespaces = copy.deepcopy(sources[0])
        empty_observed_namespaces["namespaces"] = []
        cases.append(empty_observed_namespaces)

        unexpected_inner_metadata = copy.deepcopy(sources[1])
        unexpected_inner_metadata["theme"]["unexpected"] = "value"
        cases.append(unexpected_inner_metadata)

        metadata_on_non_observed = copy.deepcopy(sources[1])
        metadata_on_non_observed["outcome"] = "no_metadata"
        cases.append(metadata_on_non_observed)

        missing_role_binding = copy.deepcopy(sources[1])
        missing_role_binding.pop("role_reference")
        cases.append(missing_role_binding)

        role_on_invalid_advertisement = {
            "kind": "rest_index",
            "association": "invalid_advertisement",
            "resource_reference": "sha256:" + "4" * 64,
            "role_reference": REST_REFERENCE,
            "parent_depth": 0,
            "outcome": "invalid_advertisement",
            "request_attempted": False,
            "response_bytes": 0,
            "evidence_reference_count": 0,
            "evidence_references": [],
        }
        cases.append(role_on_invalid_advertisement)

        unexpected = copy.deepcopy(sources[0])
        unexpected["unexpected"] = True
        cases.append(unexpected)

        for index, source in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaisesRegex(
                    runner.AcceptanceError, "source row has an unexpected shape"
                ):
                    runner._validate_discovery_source_shape(source)

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
                "component_count": 4,
                "advisory_count": 0,
                "advisories": [],
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

    def test_offline_acceptance_self_compares_positive_and_selected_empty_fingerprints(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = fingerprint_offline_fixture(Path(temporary))
            fake = offline_process_runner(responses, scenarios)
            result = runner._run_offline_acceptance(
                fake, Path("synthetic-termivar"), scenarios
            )

            self.assertEqual(
                result["bundles"]["fingerprint-release-b"][
                    "fingerprint_entity_counts"
                ],
                {"resources": 2, "components": 1},
            )
            self.assertEqual(
                result["bundles"]["blog-fingerprint-sibling-rejected"][
                    "fingerprint_entity_counts"
                ],
                {"resources": 0, "components": 0},
            )
            self.assertEqual(
                result["fingerprint_bytes_changed"],
                {
                    "item_counts": {
                        "only_in_after": 0,
                        "only_in_before": 0,
                        "changed": 0,
                        "unchanged": 2,
                    },
                    "catalogue": "unchanged",
                    "changed_resources": 1,
                    "unchanged_resources": 1,
                    "component_changed_dimensions": [
                        "candidate_set",
                        "reference_matrix",
                        "resource_coverage",
                    ],
                },
            )
            labels = [label for label, _ in fake.calls]
            self.assertLess(
                labels.index(
                    "offline self comparison blog-fingerprint-sibling-rejected"
                ),
                labels.index("offline collection-policy comparison"),
            )
            self.assertEqual(
                labels[-2:],
                [
                    "offline fingerprint byte comparison",
                    "offline fingerprint catalogue comparison",
                ],
            )

    def test_controlled_byte_pair_is_equal_length_and_mixed_pair_is_not(self):
        release_a = runner.FINGERPRINT_REFERENCE_ORACLE["release-a"]
        release_b = runner.FINGERPRINT_REFERENCE_ORACLE["release-b"]
        release_c = runner.FINGERPRINT_REFERENCE_ORACLE["release-c"]

        self.assertEqual(
            release_a["assets/fingerprint.js"],
            release_b["assets/fingerprint.js"],
        )
        self.assertEqual(
            release_a["assets/fingerprint.css"][0],
            release_b["assets/fingerprint.css"][0],
        )
        self.assertNotEqual(
            release_a["assets/fingerprint.css"][1],
            release_b["assets/fingerprint.css"][1],
        )
        self.assertEqual(
            sum(release_a[path][0] for path in (
                "assets/fingerprint.js", "assets/fingerprint.css"
            )),
            86,
        )
        self.assertEqual(
            sum(release_b[path][0] for path in (
                "assets/fingerprint.js", "assets/fingerprint.css"
            )),
            86,
        )
        self.assertEqual(
            release_c["assets/fingerprint.js"][0]
            + release_a["assets/fingerprint.css"][0],
            87,
        )

    def test_literal_fingerprint_audits_are_source_consistent_v1_shapes(self):
        expected_top_level = {
            "schema", "capability_id", "policy_id", "selected",
            "representation_profile", "finite_reference_scope",
            "same_release_assumption", "installed_version_assurance",
            "source_authenticity", "catalogue", "candidate_count",
            "selected_resource_count", "omitted_resource_count",
            "attempted_request_count", "reused_response_count",
            "fetched_response_count", "response_bytes", "stop",
            "resource_count", "resources", "component_count", "components",
        }
        expected_catalogue = {
            "schema", "id", "revision", "source_namespace", "byte_length",
            "sha256", "semantic_sha256", "retained_bytes", "component_count",
            "release_count", "file_count", "provenance",
        }
        expected = {
            "release-a": {
                "counts": (2, 1),
                "file_count": 6,
                "state": "single_catalogue_candidate",
                "release_states": (
                    "compatible", "inconsistent", "inconsistent"
                ),
                "relations": (
                    ("match", "match", "mismatch"),
                    ("match", "mismatch", "mismatch"),
                ),
            },
            "release-b": {
                "counts": (2, 1),
                "file_count": 6,
                "state": "single_catalogue_candidate",
                "release_states": (
                    "inconsistent", "compatible", "inconsistent"
                ),
                "relations": (
                    ("match", "match", "mismatch"),
                    ("mismatch", "match", "match"),
                ),
            },
            "mixed-artifacts": {
                "counts": (2, 1),
                "file_count": 6,
                "state": "no_consistent_catalogue_release",
                "release_states": (
                    "inconsistent", "inconsistent", "inconsistent"
                ),
                "relations": (
                    ("match", "mismatch", "mismatch"),
                    ("mismatch", "mismatch", "match"),
                ),
            },
            "missing-reference": {
                "counts": (2, 1),
                "file_count": 5,
                "state": "provisional_candidates",
                "release_states": (
                    "undetermined", "compatible", "inconsistent"
                ),
                "relations": (
                    ("match", "match", "mismatch"),
                    ("unknown", "match", "match"),
                ),
            },
            "empty": {
                "counts": (0, 0),
                "file_count": 6,
                "state": None,
                "release_states": (),
                "relations": (),
            },
        }
        for variant, oracle in expected.items():
            with self.subTest(variant=variant):
                audit = synthetic_fingerprint_audit(variant=variant)
                self.assertEqual(set(audit), expected_top_level)
                self.assertEqual(set(audit["catalogue"]), expected_catalogue)
                resource_count, component_count = oracle["counts"]
                self.assertEqual(
                    (audit["resource_count"], len(audit["resources"])),
                    (resource_count, resource_count),
                )
                self.assertEqual(
                    (audit["component_count"], len(audit["components"])),
                    (component_count, component_count),
                )
                self.assertEqual(audit["catalogue"]["file_count"], oracle["file_count"])
                if component_count == 0:
                    self.assertEqual(audit["candidate_count"], 0)
                    self.assertEqual(audit["catalogue"]["component_count"], 1)
                    continue
                component = audit["components"][0]
                self.assertEqual(component["state"], oracle["state"])
                self.assertEqual(
                    tuple(row["state"] for row in component["releases"]),
                    oracle["release_states"],
                )
                self.assertEqual(
                    tuple(
                        tuple(row["relation"] for row in resource["release_relations"])
                        for resource in component["resources"]
                    ),
                    oracle["relations"],
                )
                self.assertEqual(
                    {
                        (resource["component"]["kind"],
                         resource["component"]["slug"])
                        for resource in audit["resources"]
                    },
                    {runner.FINGERPRINT_COMPONENT},
                )

    def test_offline_fingerprint_self_compare_rejects_malformed_entity_partitions(self):
        def mutate_missing_group(responses):
            del responses[
                "offline self comparison blog-fingerprint-sibling-rejected"
            ]["wordpress_review_comparison"]["asset_fingerprints"]["components"][
                "only_in_after"
            ]

        def mutate_wrong_group_type(responses):
            responses[
                "offline self comparison blog-fingerprint-sibling-rejected"
            ]["wordpress_review_comparison"]["asset_fingerprints"]["resources"][
                "paired_changed"
            ] = None

        def mutate_boolean_count(responses):
            responses[
                "offline self comparison blog-fingerprint-sibling-rejected"
            ]["wordpress_review_comparison"]["asset_fingerprints"]["components"][
                "paired_unchanged_count"
            ] = False

        def mutate_empty_as_one(responses):
            responses[
                "offline self comparison blog-fingerprint-sibling-rejected"
            ]["wordpress_review_comparison"]["asset_fingerprints"]["components"][
                "paired_unchanged_count"
            ] = 1

        def mutate_positive_as_zero(responses):
            responses["offline self comparison fingerprint-release-b"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["components"]["paired_unchanged_count"] = 0

        def mutate_duplicate_changed_identity(responses):
            resources = responses["offline self comparison fingerprint-release-b"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["resources"]
            key = {
                "source_namespace": "termivar.synthetic.wordpress-asset-fingerprints",
                "component": {
                    "kind": runner.FINGERPRINT_COMPONENT[0],
                    "slug": runner.FINGERPRINT_COMPONENT[1],
                },
                "relative_path": "assets/fingerprint.js",
            }
            change = {
                "key": key,
                "changed_dimensions": ["resource_bytes"],
                "before": {},
                "after": {},
            }
            resources["paired_unchanged_count"] = 0
            resources["paired_changed"] = [change, copy.deepcopy(change)]

        def mutate_interpretation_limits(responses):
            responses["offline self comparison fingerprint-release-b"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["interpretation_limits"] = []

        mutations = (
            mutate_missing_group,
            mutate_wrong_group_type,
            mutate_boolean_count,
            mutate_empty_as_one,
            mutate_positive_as_zero,
            mutate_duplicate_changed_identity,
            mutate_interpretation_limits,
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = fingerprint_offline_fixture(
                        Path(temporary)
                    )
                    mutate(responses)
                    with self.assertRaises(runner.AcceptanceError):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_fingerprint_one_sided_interpretations_are_directional(self):
        key = {
            "source_namespace": "termivar.synthetic.wordpress-asset-fingerprints",
            "component": {
                "kind": runner.FINGERPRINT_COMPONENT[0],
                "slug": runner.FINGERPRINT_COMPONENT[1],
            },
        }
        encoded = json.dumps(key, sort_keys=True, separators=(",", ":"))
        cases = (
            (
                "only_in_before",
                {encoded},
                set(),
                "present_only_in_the_supplied_before_audit_not_verified_remediation",
            ),
            (
                "only_in_after",
                set(),
                {encoded},
                "present_only_in_the_supplied_after_audit_not_verified_newness",
            ),
        )
        for group, before_keys, after_keys, interpretation in cases:
            with self.subTest(group=group):
                document = fingerprint_entity_changes(paired_unchanged_count=0)
                document[group] = [{
                    "key": copy.deepcopy(key),
                    "content": {"candidate_set": {"state": "undetermined"}},
                    "interpretation": interpretation,
                }]
                parsed = runner._fingerprint_comparison_entity_groups(
                    document,
                    entity="components",
                    before_count=len(before_keys),
                    after_count=len(after_keys),
                    before_keys=before_keys,
                    after_keys=after_keys,
                    label="synthetic directional fingerprint comparison",
                )
                self.assertEqual(len(parsed[group]), 1)
                swapped = copy.deepcopy(document)
                swapped[group][0]["interpretation"] = (
                    "present_only_in_the_supplied_after_audit_not_verified_newness"
                    if group == "only_in_before" else
                    "present_only_in_the_supplied_before_audit_not_verified_remediation"
                )
                with self.assertRaisesRegex(
                    runner.AcceptanceError, "invalid one-sided content"
                ):
                    runner._fingerprint_comparison_entity_groups(
                        swapped,
                        entity="components",
                        before_count=len(before_keys),
                        after_count=len(after_keys),
                        before_keys=before_keys,
                        after_keys=after_keys,
                        label="synthetic directional fingerprint comparison",
                    )

    def test_offline_fingerprint_self_compare_rejects_source_audit_drift(self):
        def rewrite_source(scenarios, responses, mutate):
            name = "fingerprint-release-b"
            bundle = Path(scenarios[name]["_bundle"])
            document = json.loads((bundle / "assessment.json").read_bytes())
            mutate(document["wordpress_asset_fingerprints"], scenarios[name], responses)
            raw = rewrite_synthetic_assessment(bundle, document)
            scenarios[name]["bundle"] = runner._report_identity(bundle)
            comparison = responses[f"offline self comparison {name}"]
            comparison["before"] = source_metadata(raw, document["item_count"])
            comparison["after"] = source_metadata(raw, document["item_count"])

        def boolean_source_count(audit, _scenario, _responses):
            audit["resource_count"] = True

        def source_count_array_mismatch(audit, _scenario, _responses):
            audit["resource_count"] = 1

        def duplicate_resource(audit, _scenario, _responses):
            audit["resources"][1] = copy.deepcopy(audit["resources"][0])

        def duplicate_component(audit, scenario, responses):
            audit["components"].append(copy.deepcopy(audit["components"][0]))
            audit["component_count"] = 2
            scenario["fingerprints"]["component_count"] = 2
            responses["offline self comparison fingerprint-release-b"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["components"]["paired_unchanged_count"] = 2

        mutations = (
            boolean_source_count,
            source_count_array_mismatch,
            duplicate_resource,
            duplicate_component,
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = fingerprint_offline_fixture(
                        Path(temporary)
                    )
                    rewrite_source(scenarios, responses, mutate)
                    with self.assertRaises(runner.AcceptanceError):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = fingerprint_offline_fixture(Path(temporary))
            name = "fingerprint-release-b"
            bundle = Path(scenarios[name]["_bundle"])
            document = json.loads((bundle / "assessment.json").read_bytes())
            del document["wordpress_asset_fingerprints"]
            raw = rewrite_synthetic_assessment(bundle, document)
            scenarios[name]["bundle"] = runner._report_identity(bundle)
            comparison = responses[f"offline self comparison {name}"]
            comparison["before"] = source_metadata(raw, document["item_count"])
            comparison["after"] = source_metadata(raw, document["item_count"])
            with self.assertRaises(runner.AcceptanceError):
                runner._run_offline_acceptance(
                    offline_process_runner(responses, scenarios),
                    Path("synthetic-termivar"),
                    scenarios,
                )

    def test_offline_fingerprint_controlled_comparisons_require_closed_partitions(self):
        def missing_one_sided(responses):
            del responses["offline fingerprint byte comparison"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["resources"]["only_in_after"]

        def wrong_one_sided_type(responses):
            responses["offline fingerprint catalogue comparison"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["components"]["only_in_before"] = False

        def boolean_paired_count(responses):
            responses["offline fingerprint byte comparison"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["resources"]["paired_unchanged_count"] = False

        def substituted_resource_identity(responses):
            responses["offline fingerprint byte comparison"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["resources"]["paired_changed"][0]["key"][
                "relative_path"
            ] = "assets/substituted.js"

        def substituted_component_identity(responses):
            responses["offline fingerprint catalogue comparison"][
                "wordpress_review_comparison"
            ]["asset_fingerprints"]["components"]["paired_changed"][0]["key"][
                "component"
            ]["slug"] = "substituted-component"

        for mutate in (
            missing_one_sided,
            wrong_one_sided_type,
            boolean_paired_count,
            substituted_resource_identity,
            substituted_component_identity,
        ):
            with self.subTest(mutation=mutate.__name__):
                with tempfile.TemporaryDirectory() as temporary:
                    scenarios, responses, _ = fingerprint_offline_fixture(
                        Path(temporary)
                    )
                    mutate(responses)
                    with self.assertRaises(runner.AcceptanceError):
                        runner._run_offline_acceptance(
                            offline_process_runner(responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_offline_fingerprint_comparison_failure_retains_bounded_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            scenarios, responses, _ = fingerprint_offline_fixture(Path(temporary))
            comparison = responses["offline fingerprint byte comparison"]
            comparison["wordpress_review_comparison"]["asset_fingerprints"][
                "coverage"
            ]["status"] = "changed"

            with self.assertRaises(runner.AcceptanceError) as raised:
                runner._run_offline_acceptance(
                    offline_process_runner(responses, scenarios),
                    Path("synthetic-termivar"),
                    scenarios,
                )

            diagnostic = raised.exception.diagnostic
            self.assertEqual(
                diagnostic,
                {
                    "status": "fingerprint_comparison_contract_mismatch",
                    "label": "offline fingerprint byte comparison",
                    "catalogue_status": "unchanged",
                    "coverage_status": "changed",
                    "resource_paired_unchanged": 1,
                    "resource_changed_dimensions": [["resource_bytes"]],
                    "resource_only_in_before_count": 0,
                    "resource_only_in_after_count": 0,
                    "component_paired_unchanged": 0,
                    "component_changed_dimensions": [[
                        "candidate_set",
                        "reference_matrix",
                        "resource_coverage",
                    ]],
                    "component_only_in_before_count": 0,
                    "component_only_in_after_count": 0,
                },
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


class SuppliedSessionWordPressLabAcceptanceTests(unittest.TestCase):
    @staticmethod
    def session_input(root, *, credential_alias="termivar-lab-alice"):
        cookie_value = (
            f"{credential_alias}|4102444800|" + "T" * 43 + "|" + "b" * 64
        ).encode("ascii")
        return runner.LabSessionInput(
            policy_path=Path(root) / "session-policy.toml",
            cookie_path=Path(root) / "session-cookie.tsv",
            cookie_value=cookie_value,
            principal_alias="termivar-lab-alice",
            health_path="/termivar-session-health/",
            resource_path="/termivar-session-member/",
            application_path="/",
            policy_identity={"byte_length": 1, "sha256": "0" * 64},
            cookie_byte_length=len(cookie_value),
            policy_declares_expiry=True,
            credential_principal_alias=credential_alias,
            server_expired=False,
            lose_after_resource=False,
        )

    @classmethod
    def session_wordpress_document(
        cls, root, *, outcome="complete", integration=True, fingerprints=False,
        credential_alias="termivar-lab-alice",
    ):
        origin = "http://127.0.0.1:8080/"
        oracle = runner.DiscoveryOracle(
            application_url=origin,
            request_paths=runner.EXPECTED_DISCOVERY_PATHS["pretty"],
            core_base_url=origin,
            themes_base_url=origin + "wp-content/themes/",
            plugins_base_url=origin + "wp-content/plugins/",
            rest_base_url=origin,
        )
        session_input = cls.session_input(root, credential_alias=credential_alias)
        audit = synthetic_supplied_session_audit(
            outcome=outcome, principal_alias=credential_alias
        )
        audit["application_reference"] = runner._supplied_session_literal_reference(
            b"security.supplied-session-application.reference.v1\0",
            origin,
            "supplied-session-application-sha256",
        )
        audit["health_oracle"]["field_reference"] = (
            runner._supplied_session_literal_reference(
                b"security.supplied-session-health-field.reference.v1\0",
                "authenticated",
                "supplied-session-health-field-sha256",
            )
        )
        audit["resources"][0]["resource_reference"] = (
            runner._supplied_session_literal_reference(
                b"security.supplied-session-resource.reference.v1\0",
                origin.rstrip("/") + session_input.resource_path,
                "supplied-session-resource-sha256",
            )
        )
        resource_bytes = (
            len(runner._expected_session_private_body(
                oracle.plugins_base_url, session_input.credential_principal_alias
            ))
            if outcome != "startup_unhealthy" else 0
        )
        audit["resources"][0]["response_bytes"] = resource_bytes
        audit["response_bytes"] = (
            sum(row["response_bytes"] for row in audit["checkpoints"])
            + resource_bytes
        )
        document = WordPressDiscoveryLabAcceptanceTests.discovery_document()
        document["supplied_session"] = audit
        document["wordpress_review"].update({
            "capability_id": BASE_CAPABILITY,
            "catalog_status": "catalogue_not_supplied",
            "signal_count": 1,
            "evidence_reference_count": 1,
            "item_projected": True,
        })
        layout = document["wordpress_discovery"]["layout"]
        layout["application_reference"] = runner._framed_reference(
            "wordpress-selected-application", oracle.application_url
        )
        role_urls = {
            "core": oracle.core_base_url,
            "themes": oracle.themes_base_url,
            "plugins": oracle.plugins_base_url,
            "rest_index": oracle.rest_base_url,
        }
        for role in layout["roles"]:
            role["reference"] = runner._framed_reference(
                "wordpress-discovery-role", role_urls[role["role"]]
            )
        for source, request_path in zip(
            document["wordpress_discovery"]["sources"],
            oracle.request_paths,
            strict=True,
        ):
            source["role_reference"] = runner._framed_reference(
                "wordpress-discovery-role",
                role_urls[
                    "rest_index" if source["kind"] == "rest_index"
                    else "themes" if source["kind"] == "theme_stylesheet"
                    else "plugins"
                ],
            )
            source["resource_reference"] = runner._framed_reference(
                "wordpress-discovery-resource",
                origin.rstrip("/") + request_path,
            )
        if not integration:
            return document, session_input, oracle

        committed = outcome == "complete"
        discovery = document["wordpress_discovery"]
        discovery["schema"] = "security.wordpress-discovery-audit/v4"
        discovery["policy_id"] = (
            "termivar.wordpress-supplied-session-metadata-discovery/v1"
        )
        discovery["seed_count"] = 4 if committed else 3
        discovery["candidate_count"] = 5 if committed else 4
        discovery["attempted_request_count"] = 5 if committed else 4
        discovery["completed_response_count"] = 5 if committed else 4
        discovery["committed_response_count"] = 5 if committed else 4
        discovery["source_count"] = 5 if committed else 4
        for source in discovery["sources"]:
            source["source_supplied_session_page_references"] = []
        resource_url = origin.rstrip("/") + session_input.resource_path
        page_reference = runner._framed_supplied_session_page_reference(
            audit, resource_url
        )
        resource = audit["resources"][0]
        evidence_reference = resource["evidence_reference"]
        interpreted_bytes = resource["response_bytes"] if committed else 0
        discovery["supplied_session_pages"] = {
            "mode": "committed_supplied_session_resources",
            "policy_reference": audit["policy_reference"],
            "application_reference": audit["application_reference"],
            "principal_reference": audit["principal_reference"],
            "credential_mechanism": "cookie_jar",
            "session_epoch": 1,
            "selected_count": 1,
            "committed_count": int(committed),
            "accepted_association_count": int(committed),
            "rejected_association_count": 0,
            "not_established_association_count": int(not committed),
            "not_evaluated_count": int(not committed),
            "interpreted_response_bytes": interpreted_bytes,
            "pages": [{
                "page_reference": page_reference,
                "resource_reference": resource["resource_reference"],
                "resource_evidence_reference": evidence_reference if committed else None,
                "acquisition": "reused_supplied_session_response",
                "association": "accepted" if committed else "not_established",
                "outcome": "accepted" if committed else "not_evaluated",
                "fingerprint_evaluation": "not_selected_in_v1",
                "interpreted_response_bytes": interpreted_bytes,
                "evidence_reference_count": int(committed),
                "evidence_references": [evidence_reference] if committed else [],
            }],
        }
        if committed:
            plugin_role = runner._framed_reference(
                "wordpress-discovery-role", oracle.plugins_base_url
            )
            discovery["sources"].append({
                "kind": "plugin_readme",
                "association": "observed_conventional",
                "resource_reference": "sha256:" + "8" * 64,
                "role_reference": plugin_role,
                "component": {
                    "kind": runner.FINGERPRINT_COMPONENT[0],
                    "slug": runner.FINGERPRINT_COMPONENT[1],
                },
                "parent_depth": 0,
                "outcome": "observed",
                "request_attempted": True,
                "response_bytes": 256,
                "evidence_reference_count": 1,
                "evidence_references": ["evidence-0005"],
                "source_supplied_session_page_references": [page_reference],
                "plugin": {
                    "name": "Termivar Fingerprint Lab",
                    "stable_tag": "9.9.9",
                },
            })
            document["wordpress_review"]["components"].append({
                "identity": {
                    "kind": runner.FINGERPRINT_COMPONENT[0],
                    "slug": runner.FINGERPRINT_COMPONENT[1],
                },
                "identity_sources": ["same_origin_asset_path"],
                "versions": [],
            })
        document["wordpress_review"]["component_count"] = 5 if committed else 4
        document["wordpress_review"]["additional_request_count"] = 5 if committed else 4
        if fingerprints:
            document["wordpress_review"]["schema"] = (
                "security.wordpress-review-audit/v8"
            )
            fingerprint_audit = synthetic_fingerprint_audit(variant="empty")
            fingerprint_audit["catalogue"].update({
                "id": "termivar-wordpress-asset-matrix",
                "revision": "v1",
                "source_namespace": "termivar.synthetic.wordpress-asset-fingerprints",
                "byte_length": runner.FINGERPRINT_CATALOGUE_PATH.stat().st_size,
                "sha256": runner.sha256_file(runner.FINGERPRINT_CATALOGUE_PATH),
                "component_count": 1,
                "release_count": 3,
                "file_count": 9,
            })
            document["wordpress_asset_fingerprints"] = fingerprint_audit
        return document, session_input, oracle

    def validate_wordpress_document(
        self, document, session_input, oracle, *, outcome, integration, fingerprints
    ):
        return runner._validate_supplied_session_wordpress_document(
            document,
            session_input=session_input,
            root_origin="http://127.0.0.1:8080/",
            oracle=oracle,
            expected_session_outcome=outcome,
            integration_selected=integration,
            expected_component_association="observed_conventional",
            fingerprints_path=(
                runner.FINGERPRINT_CATALOGUE_PATH if fingerprints else None
            ),
        )

    def test_session_wordpress_v4_accepts_option_off_complete_loss_and_empty_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            cases = (
                ("complete", False, False, "security.wordpress-discovery-audit/v2"),
                ("complete", True, False, "security.wordpress-discovery-audit/v4"),
                ("session_lost", True, False, "security.wordpress-discovery-audit/v4"),
                ("complete", True, True, "security.wordpress-discovery-audit/v4"),
            )
            for outcome, integration, fingerprints, expected_schema in cases:
                with self.subTest(
                    outcome=outcome, integration=integration, fingerprints=fingerprints
                ):
                    document, session_input, oracle = self.session_wordpress_document(
                        temporary,
                        outcome=outcome,
                        integration=integration,
                        fingerprints=fingerprints,
                    )
                    schema, summary, fingerprint = self.validate_wordpress_document(
                        document,
                        session_input,
                        oracle,
                        outcome=outcome,
                        integration=integration,
                        fingerprints=fingerprints,
                    )
                    self.assertEqual(schema, expected_schema)
                    self.assertEqual(
                        summary["committed_resource_count"], int(outcome == "complete")
                    )
                    self.assertEqual(fingerprint is not None, fingerprints)
                    if fingerprints:
                        self.assertEqual(fingerprint["resource_count"], 0)
                        self.assertEqual(fingerprint["component_count"], 0)

    def test_session_wordpress_v4_rejects_malformed_counts_provenance_and_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            document, session_input, oracle = self.session_wordpress_document(temporary)
            pages = document["wordpress_discovery"]["supplied_session_pages"]
            page_reference = pages["pages"][0]["page_reference"]
            evidence_reference = pages["pages"][0]["resource_evidence_reference"]
            mutations = []
            alice_body = runner._expected_session_private_body(
                oracle.plugins_base_url, "termivar-lab-alice"
            )
            bob_body = runner._expected_session_private_body(
                oracle.plugins_base_url, "termivar-lab-bob"
            )
            self.assertNotEqual(alice_body, bob_body)
            self.assertNotEqual(len(alice_body), len(bob_body))

            changed = copy.deepcopy(document)
            changed["supplied_session"]["resources"][0]["response_bytes"] = len(
                bob_body
            )
            mutations.append(changed)

            changed = copy.deepcopy(document)
            changed["wordpress_discovery"]["unexpected_count"] = 0
            mutations.append(changed)

            for container_path, field in (
                (("wordpress_discovery", "supplied_session_pages"), "selected_count"),
                (("wordpress_discovery", "supplied_session_pages", "pages", 0), "evidence_reference_count"),
                (("wordpress_review",), "additional_request_count"),
                (("wordpress_review",), "component_count"),
                (("wordpress_review",), "advisory_count"),
            ):
                changed = copy.deepcopy(document)
                cursor = changed
                for key in container_path:
                    cursor = cursor[key]
                cursor[field] = True
                mutations.append(changed)

            changed = copy.deepcopy(document)
            changed["wordpress_discovery"]["supplied_session_pages"]["pages"][0][
                "evidence_references"
            ] = [evidence_reference, evidence_reference]
            mutations.append(changed)
            changed = copy.deepcopy(document)
            changed["wordpress_discovery"]["sources"][0][
                "source_supplied_session_page_references"
            ] = [page_reference]
            mutations.append(changed)
            changed = copy.deepcopy(document)
            changed["wordpress_discovery"]["sources"][0][
                "source_page_references"
            ] = []
            mutations.append(changed)
            changed = copy.deepcopy(document)
            changed["wordpress_discovery"]["sources"].pop()
            mutations.append(changed)
            for field in ("component_count", "advisory_count"):
                changed = copy.deepcopy(document)
                changed["wordpress_review"][field] = 999
                mutations.append(changed)
            for audit_path, replacement in (
                (("application_reference",), "supplied-session-application-sha256:" + "a" * 64),
                (("health_oracle", "field_reference"), "supplied-session-health-field-sha256:" + "b" * 64),
                (("resources", 0, "resource_reference"), "supplied-session-resource-sha256:" + "c" * 64),
            ):
                changed = copy.deepcopy(document)
                cursor = changed["supplied_session"]
                for key in audit_path[:-1]:
                    cursor = cursor[key]
                cursor[audit_path[-1]] = replacement
                mutations.append(changed)

            for index, changed in enumerate(mutations):
                with self.subTest(mutation=index):
                    with self.assertRaises(runner.AcceptanceError):
                        self.validate_wordpress_document(
                            changed,
                            session_input,
                            oracle,
                            outcome="complete",
                            integration=True,
                            fingerprints=False,
                        )

            option_off, session_input, oracle = self.session_wordpress_document(
                temporary, integration=False
            )
            option_off["wordpress_discovery"]["supplied_session_pages"] = {}
            with self.assertRaises(runner.AcceptanceError):
                self.validate_wordpress_document(
                    option_off,
                    session_input,
                    oracle,
                    outcome="complete",
                    integration=False,
                    fingerprints=False,
                )
            for path, value in (
                (("wordpress_discovery", "omitted_candidate_count"), False),
                (("wordpress_discovery", "layout", "skipped_foreign_origin_count"), False),
                (("wordpress_discovery", "sources", 0, "evidence_reference_count"), True),
                (("wordpress_discovery", "sources", 0, "response_bytes"), True),
            ):
                option_off, session_input, oracle = self.session_wordpress_document(
                    temporary, integration=False
                )
                cursor = option_off
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = value
                with self.subTest(option_off_bool_path=path):
                    with self.assertRaises(runner.AcceptanceError):
                        self.validate_wordpress_document(
                            option_off,
                            session_input,
                            oracle,
                            outcome="complete",
                            integration=False,
                            fingerprints=False,
                        )
            option_off, session_input, oracle = self.session_wordpress_document(
                temporary, integration=False
            )
            option_off["supplied_session"]["application_reference"] = (
                "supplied-session-application-sha256:" + "d" * 64
            )
            with self.assertRaises(runner.AcceptanceError):
                self.validate_wordpress_document(
                    option_off,
                    session_input,
                    oracle,
                    outcome="complete",
                    integration=False,
                    fingerprints=False,
                )

    def test_supplied_session_audit_accepts_three_outcomes_and_rejects_bool_counts(self):
        for outcome, declares_expiry in (
            ("complete", True),
            ("session_lost", True),
            ("startup_unhealthy", False),
        ):
            with self.subTest(outcome=outcome):
                document = {
                    "supplied_session": synthetic_supplied_session_audit(
                        outcome=outcome,
                        policy_declares_expiry=declares_expiry,
                    )
                }
                audit, committed = runner._validate_supplied_session_audit(
                    document,
                    expected_outcome=outcome,
                    expected_principal_alias="termivar-lab-alice",
                    policy_declares_expiry=declares_expiry,
                )
                self.assertEqual(committed, outcome == "complete")
                self.assertEqual(audit["outcome"], outcome)

        mutations = (
            ("selected_resource_count",),
            ("dispatched_request_count",),
            ("response_byte_limit",),
            ("cookie_policy", "declared_count"),
            ("cookie_lifecycle", "initial_epoch"),
            ("checkpoints", 0, "sequence"),
            ("checkpoints", 0, "status"),
            ("resources", 0, "epoch"),
            ("resources", 0, "status"),
        )
        for path in mutations:
            with self.subTest(path=path):
                audit = synthetic_supplied_session_audit()
                cursor = audit
                for key in path[:-1]:
                    cursor = cursor[key]
                cursor[path[-1]] = True
                with self.assertRaises(runner.AcceptanceError):
                    runner._validate_supplied_session_audit(
                        {"supplied_session": audit},
                        expected_outcome="complete",
                        expected_principal_alias="termivar-lab-alice",
                        policy_declares_expiry=True,
                    )

        changed = synthetic_supplied_session_audit()
        changed["checkpoints"][1]["predicate"] = "not_matched"
        with self.assertRaisesRegex(runner.AcceptanceError, "checkpoint"):
            runner._validate_supplied_session_audit(
                {"supplied_session": changed},
                expected_outcome="complete",
                expected_principal_alias="termivar-lab-alice",
                policy_declares_expiry=True,
            )

    def test_supplied_session_trace_is_exact_and_private_assets_are_never_requested(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = self.session_input(temporary)
            metadata = ["/wp-json/", "/wp-content/plugins/example/readme.txt"]
            trace = [
                ("GET", "/", 200, ()),
                ("GET", session.health_path, 200, ("cookie",)),
                ("GET", session.resource_path, 200, ("cookie",)),
                ("GET", session.health_path, 200, ("cookie",)),
                ("GET", metadata[0], 200, ()),
                ("GET", metadata[1], 200, ()),
            ]
            conditional_readme = "/wp-content/plugins/private/readme.txt"
            counts = runner._assert_supplied_session_trace(
                trace,
                session=session,
                expected_session_paths=[
                    session.health_path, session.resource_path, session.health_path,
                ],
                expected_metadata_paths=metadata,
                known_metadata_paths=(*metadata, conditional_readme),
                forbidden_anonymous_paths=(
                    "/wp-content/plugins/private/assets/fingerprint.js?ver=private-page",
                    "/wp-content/plugins/private/assets/fingerprint.css?ver=private-page",
                ),
            )
            self.assertEqual(counts["credentialed_request_count"], 3)
            summary = runner._compact_session_trace_evidence(
                trace, session, metadata_paths=metadata
            )
            self.assertEqual(summary["full_request_count"], 6)
            self.assertEqual(summary["retained_request_count"], 5)
            self.assertEqual(summary["omitted_anonymous_general_request_count"], 1)
            self.assertRegex(summary["full_trace_sha256"], r"^[0-9a-f]{64}$")

            mutations = (
                trace + [("GET", session.health_path, 200, ())],
                trace + [("HEAD", "/wp-content/plugins/private/assets/fingerprint.js?ver=private-page", 200, ())],
                trace + [("GET", "/wp-content/plugins/private/assets/fingerprint.css", 200, ())],
                trace + [("HEAD", metadata[0], 200, ())],
                trace + [("GET", metadata[0], 500, ())],
                trace + [("GET", metadata[0], 200, ())],
                trace + [("GET", conditional_readme, 200, ())],
                [
                    row if row[1] != metadata[0]
                    else (row[0], row[1], row[2], ("cookie",))
                    for row in trace
                ],
            )
            for mutated in mutations:
                with self.subTest(mutated=mutated[-1]):
                    with self.assertRaises(runner.AcceptanceError):
                        runner._assert_supplied_session_trace(
                            mutated,
                            session=session,
                            expected_session_paths=[
                                session.health_path,
                                session.resource_path,
                                session.health_path,
                            ],
                            expected_metadata_paths=metadata,
                            known_metadata_paths=(*metadata, conditional_readme),
                            forbidden_anonymous_paths=(
                                "/wp-content/plugins/private/assets/fingerprint.js?ver=private-page",
                                "/wp-content/plugins/private/assets/fingerprint.css?ver=private-page",
                            ),
                        )

    def test_sensitive_process_failures_withhold_cookie_and_child_output(self):
        secret = b"alice|4102444800|" + b"T" * 43 + b"|" + b"b" * 64
        completed = subprocess.CompletedProcess(
            ["synthetic"], 7, stdout=b"", stderr=b"failure:" + secret
        )
        with mock.patch.object(runner.subprocess, "run", return_value=completed):
            with self.assertRaises(runner.AcceptanceError) as raised:
                runner.ProcessRunner().run_sensitive(
                    ["synthetic"],
                    sensitive_values=(secret,),
                    label="synthetic sensitive command",
                )
        rendered = str(raised.exception).encode("utf-8")
        self.assertNotIn(secret, rendered)
        self.assertEqual(
            raised.exception.diagnostic,
            {"status": "sensitive_output_rejected"},
        )

        raw_log = subprocess.CompletedProcess(
            ["docker", "logs"], 0,
            stdout=b"unparsed php warning leaked=" + secret + b"\n",
            stderr=b"",
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            runner.subprocess, "run", return_value=raw_log
        ):
            lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            with self.assertRaises(runner.AcceptanceError) as log_error:
                lab.request_log(sensitive_values=(secret,))
        self.assertNotIn(secret, str(log_error.exception).encode("utf-8"))

    def test_session_trace_preserves_the_existing_anonymous_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            session = self.session_input(temporary)
            baseline = [
                ("GET", "/", 200, ()),
                ("GET", "/wp-json/", 200, ()),
                ("GET", "/wp-content/plugins/base/readme.txt", 200, ()),
            ]
            conditional = "/wp-content/plugins/private/readme.txt"
            option_off = [
                baseline[0],
                ("GET", session.health_path, 200, ("cookie",)),
                ("GET", session.resource_path, 200, ("cookie",)),
                ("GET", session.health_path, 200, ("cookie",)),
                *baseline[1:],
            ]
            healthy = [*option_off, ("GET", conditional, 200, ())]
            runner._assert_session_preserves_anonymous_trace(
                baseline,
                option_off,
                session=session,
                conditional_metadata_path=None,
            )
            runner._assert_session_preserves_anonymous_trace(
                baseline,
                healthy,
                session=session,
                conditional_metadata_path=conditional,
            )
            for changed, conditional_path in (
                (option_off[:-1], None),
                (healthy + [("GET", "/unexpected/", 200, ())], conditional),
            ):
                with self.assertRaises(runner.AcceptanceError):
                    runner._assert_session_preserves_anonymous_trace(
                        baseline,
                        changed,
                        session=session,
                        conditional_metadata_path=conditional_path,
                    )

    def test_real_wordpress_cookie_shape_private_inputs_and_cleanup(self):
        expiration = 4_102_444_800
        cookie = (
            "termivar-lab-alice|4102444800|" + "T" * 43 + "|" + "b" * 64
        )
        encoded = (
            f"{expiration}\twordpress_logged_in_{'a' * 32}\t{cookie}"
        ).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            lab = runner.DockerWordPressLab(runner.ProcessRunner(), Path(temporary))
            lab.wp = mock.Mock(side_effect=[
                runner.CommandResult(b"", b"", 0),
                runner.CommandResult(encoded, b"", 0),
            ])
            credential = lab.configure_supplied_session(
                path="/var/www/html",
                application_path="/",
                credential_login="termivar-lab-alice",
                expiration_unix_seconds=expiration,
            )
            self.assertEqual(credential.principal_alias, "termivar-lab-alice")
            self.assertFalse(credential.server_expired)
            self.assertRegex(
                credential.cookie_name, r"^wordpress_logged_in_[0-9a-f]{32}$"
            )
            self.assertNotIn(cookie, repr(credential))
            cookie_program = lab.wp.call_args_list[1].kwargs["input_bytes"]
            self.assertIn(b"WP_Session_Tokens::get_instance", cookie_program)
            self.assertIn(b"wp_generate_auth_cookie", cookie_program)

            session = runner._write_supplied_session_inputs(
                Path(temporary),
                name="session-root-healthy",
                origin="http://127.0.0.1:8080/",
                credential=credential,
            )
            policy = session.policy_path.read_text(encoding="utf-8")
            self.assertIn('same_site = "missing"', policy)
            self.assertIn(f"expires_unix_seconds = {expiration}", policy)
            self.assertNotIn(cookie, policy)
            self.assertEqual(
                session.cookie_path.read_bytes(),
                b"wordpress-lab-session\t" + cookie.encode("ascii") + b"\r\n",
            )
            self.assertEqual(session.credential_principal_alias, "termivar-lab-alice")
            runner._remove_supplied_session_inputs(session)
            self.assertFalse(session.policy_path.exists())
            self.assertFalse(session.cookie_path.exists())

            malformed_lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            malformed_lab.wp = mock.Mock(side_effect=[
                runner.CommandResult(b"", b"", 0),
                runner.CommandResult(
                    encoded.replace(b"wordpress_logged_in_", b"wordpress_logged_in_X"),
                    b"", 0,
                ),
            ])
            with self.assertRaisesRegex(runner.AcceptanceError, "cookie output"):
                malformed_lab.configure_supplied_session(
                    path="/var/www/html",
                    application_path="/",
                    credential_login="termivar-lab-alice",
                    expiration_unix_seconds=expiration,
                )

            non_ascii_lab = runner.DockerWordPressLab(
                runner.ProcessRunner(), Path(temporary)
            )
            non_ascii_lab.wp = mock.Mock(side_effect=[
                runner.CommandResult(b"", b"", 0),
                runner.CommandResult(b"\xff", b"", 0),
            ])
            with self.assertRaisesRegex(runner.AcceptanceError, "cookie output"):
                non_ascii_lab.configure_supplied_session(
                    path="/var/www/html",
                    application_path="/",
                    credential_login="termivar-lab-alice",
                    expiration_unix_seconds=expiration,
                )

    def test_fixed_expiry_makes_healthy_and_loss_policy_inputs_comparable(self):
        expiration = 4_102_444_800
        base = dict(
            principal_alias="termivar-lab-alice",
            cookie_name="wordpress_logged_in_" + "a" * 32,
            application_path="/",
            expires_unix_seconds=expiration,
            server_expired=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            healthy = runner._write_supplied_session_inputs(
                Path(temporary),
                name="session-root-healthy",
                origin="http://127.0.0.1:8080/",
                credential=runner.LabSessionCredential(
                    cookie_value=(
                        "termivar-lab-alice|4102444800|" + "T" * 43 + "|" + "b" * 64
                    ),
                    lose_after_resource=False,
                    **base,
                ),
            )
            loss = runner._write_supplied_session_inputs(
                Path(temporary),
                name="session-root-loss-after-resource",
                origin="http://127.0.0.1:8080/",
                credential=runner.LabSessionCredential(
                    cookie_value=(
                        "termivar-lab-alice|4102444800|" + "U" * 43 + "|" + "c" * 64
                    ),
                    lose_after_resource=True,
                    **base,
                ),
            )
            self.assertEqual(healthy.policy_identity, loss.policy_identity)
            self.assertNotEqual(healthy.cookie_value, loss.cookie_value)
            runner._remove_supplied_session_inputs(healthy)
            runner._remove_supplied_session_inputs(loss)

    def test_private_input_io_failures_do_not_expose_paths(self):
        expiration = 4_102_444_800
        credential = runner.LabSessionCredential(
            principal_alias="termivar-lab-alice",
            cookie_name="wordpress_logged_in_" + "a" * 32,
            cookie_value=(
                "termivar-lab-alice|4102444800|" + "T" * 43 + "|" + "b" * 64
            ),
            application_path="/",
            expires_unix_seconds=expiration,
            server_expired=False,
            lose_after_resource=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            session = runner._write_supplied_session_inputs(
                Path(temporary),
                name="session-root-healthy",
                origin="http://127.0.0.1:8080/",
                credential=credential,
            )
            private_paths = (
                str(session.policy_path).encode(), str(session.cookie_path).encode()
            )
            path_type = type(session.policy_path)
            with mock.patch.object(
                path_type,
                "read_bytes",
                side_effect=OSError(str(session.policy_path)),
            ):
                with self.assertRaises(runner.AcceptanceError) as read_error:
                    runner._run_scan(
                        mock.Mock(),
                        Path("synthetic-termivar"),
                        "http://127.0.0.1:8080/",
                        Path(temporary) / "unused-bundle",
                        wordpress_review=True,
                        discovery=True,
                        supplied_session=session,
                        wordpress_supplied_session=True,
                        label="synthetic private input failure",
                    )
            for private_path in private_paths:
                self.assertNotIn(private_path, str(read_error.exception).encode())

            with mock.patch.object(
                path_type,
                "unlink",
                side_effect=OSError(str(session.cookie_path)),
            ):
                with self.assertRaises(runner.AcceptanceError) as unlink_error:
                    runner._remove_supplied_session_inputs(session)
            for private_path in private_paths:
                self.assertNotIn(private_path, str(unlink_error.exception).encode())
            session.cookie_path.unlink(missing_ok=True)
            session.policy_path.unlink(missing_ok=True)

    def test_run_scan_uses_sensitive_process_path_and_keeps_private_inputs_out(self):
        expiration = 4_102_444_800
        cookie_value = (
            "termivar-lab-alice|4102444800|" + "T" * 43 + "|" + "b" * 64
        )
        credential = runner.LabSessionCredential(
            principal_alias="termivar-lab-alice",
            cookie_name="wordpress_logged_in_" + "a" * 32,
            cookie_value=cookie_value,
            application_path="/",
            expires_unix_seconds=expiration,
            server_expired=False,
            lose_after_resource=False,
        )

        class SensitiveOnlyRunner:
            def __init__(self):
                self.call = None

            def run(self, *_args, **_kwargs):
                raise AssertionError("session scan used the ordinary process path")

            def run_sensitive(self, arguments, *, sensitive_values, **kwargs):
                self.call = (list(arguments), tuple(sensitive_values), dict(kwargs))
                bundle = Path(arguments[arguments.index("--report-dir") + 1])
                write_synthetic_bundle(
                    bundle.parent,
                    bundle.name,
                    [synthetic_assessment_item(
                        BASE_FINGERPRINT,
                        BASE_CAPABILITY,
                        "Synthetic session process observation",
                    )],
                )
                return runner.CommandResult(
                    b"", b"", 0, 0.01,
                    {"status": "not_measured", "reason": "synthetic"},
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            session = runner._write_supplied_session_inputs(
                root,
                name="session-root-healthy",
                origin="http://127.0.0.1:8080/",
                credential=credential,
            )
            process = SensitiveOnlyRunner()
            bundle = root / "bundle"
            document, identity, _, _, _ = runner._run_scan(
                process,
                Path("synthetic-termivar"),
                "http://127.0.0.1:8080/",
                bundle,
                wordpress_review=True,
                discovery=True,
                supplied_session=session,
                wordpress_supplied_session=True,
                label="synthetic supplied-session scan",
            )
            arguments, sensitive, kwargs = process.call
            self.assertIn("--wordpress-supplied-session", arguments)
            self.assertIn("--session-policy", arguments)
            self.assertIn("--session-cookie-file", arguments)
            self.assertEqual(kwargs["label"], "synthetic supplied-session scan")
            self.assertIn(cookie_value.encode("ascii"), sensitive)
            self.assertIn(b"T" * 43, sensitive)
            self.assertIn(b"b" * 64, sensitive)
            self.assertIn(runner.SESSION_PRIVATE_BODY_CANARY, sensitive)
            self.assertIn(str(session.policy_path).encode(), sensitive)
            self.assertIn(str(session.cookie_path).encode(), sensitive)
            self.assertEqual(document["schema"], "venom-rendered-assessment/v1")
            self.assertEqual(identity, runner._report_identity(bundle))
            runner._remove_supplied_session_inputs(session)

    def test_selected_empty_fingerprint_audit_is_typed_and_rejects_bool(self):
        audit = synthetic_fingerprint_audit(variant="empty")
        catalogue = audit["catalogue"]
        catalogue.update({
            "id": "termivar-wordpress-asset-matrix",
            "revision": "v1",
            "source_namespace": "termivar.synthetic.wordpress-asset-fingerprints",
            "byte_length": runner.FINGERPRINT_CATALOGUE_PATH.stat().st_size,
            "sha256": runner.sha256_file(runner.FINGERPRINT_CATALOGUE_PATH),
            "component_count": 1,
            "release_count": 3,
            "file_count": 9,
        })
        document = {"wordpress_asset_fingerprints": audit}
        summary = runner._validate_selected_empty_fingerprint_audit(
            document, runner.FINGERPRINT_CATALOGUE_PATH
        )
        self.assertEqual(summary["component_count"], 0)
        for field in (
            "candidate_count", "selected_resource_count", "attempted_request_count",
            "resource_count", "component_count",
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(document)
                mutated["wordpress_asset_fingerprints"][field] = False
                with self.assertRaises(runner.AcceptanceError):
                    runner._validate_selected_empty_fingerprint_audit(
                        mutated, runner.FINGERPRINT_CATALOGUE_PATH
                    )

    def test_offline_acceptance_executes_session_self_health_and_principal_compares(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scenarios, responses, _ = offline_fixture(root)
            surface_item = synthetic_assessment_item(
                "sha256:" + "9" * 64,
                "session.synthetic-health-observation@1",
                "Synthetic supplied-session health observation",
            )
            discovery_complete = synthetic_discovery_item()
            discovery_complete["evidence_count"] = 5
            discovery_complete["evidence_references"] = [
                f"evidence-{index:04d}" for index in range(1, 6)
            ]
            discovery_lost = copy.deepcopy(discovery_complete)
            discovery_lost["evidence_count"] = 4
            discovery_lost["evidence_references"] = [
                f"evidence-{index:04d}" for index in range(1, 5)
            ]
            audits = {
                "session-root-option-off": synthetic_supplied_session_audit(),
                "session-root-healthy": synthetic_supplied_session_audit(),
                "session-root-loss-after-resource": synthetic_supplied_session_audit(
                    outcome="session_lost"
                ),
                "session-root-bob-healthy": synthetic_supplied_session_audit(
                    principal_alias="termivar-lab-bob"
                ),
            }
            raw_documents = {}
            scenario_items = {}
            for name, audit in audits.items():
                integration_selected = name != "session-root-option-off"
                items = [
                    copy.deepcopy(surface_item),
                    copy.deepcopy(
                        discovery_complete
                        if integration_selected and audit["outcome"] == "complete"
                        else discovery_lost
                    ),
                ]
                wordpress_document, _, _ = self.session_wordpress_document(
                    root,
                    outcome=audit["outcome"],
                    integration=integration_selected,
                    fingerprints=False,
                    credential_alias=audit["principal_alias"],
                )
                audit = wordpress_document["supplied_session"]
                audits[name] = audit
                bundle, raw = write_synthetic_bundle(
                    root,
                    name,
                    items,
                    optional_audits={
                        "supplied_session": audit,
                        "wordpress_review": wordpress_document["wordpress_review"],
                        "wordpress_discovery": wordpress_document[
                            "wordpress_discovery"
                        ],
                    },
                )
                raw_documents[name] = raw
                scenario_items[name] = items
                scenarios[name] = {
                    "bundle": runner._report_identity(bundle),
                    "_bundle": str(bundle),
                    "supplied_session": {
                        "outcome": audit["outcome"],
                        "wordpress_integration": (
                            "selected" if integration_selected else "not_selected"
                        ),
                    },
                }
                responses[f"offline verification {name}"] = {
                    "schema": "termivar-report-verification/v1",
                    "status": "integrity_match",
                }
                self_compare = self_comparison(raw, items)
                attach_supplied_session_comparison(
                    self_compare,
                    before_audit=audit,
                    after_audit=audit,
                    context_status="same_declared_context",
                    health_status="unchanged",
                    accounting_status="unchanged",
                    status="compared_within_same_declared_context",
                    reason=None,
                )
                wordpress_self = wordpress_comparison(
                    discovery=True, controlled=False
                )
                wordpress_self["schema"] = (
                    "termivar-wordpress-review-comparison/v4"
                    if integration_selected
                    else "termivar-wordpress-review-comparison/v2"
                )
                source_inventory = runner._read_assessment_inventory(
                    bundle / "assessment.json",
                    f"synthetic supplied-session self source {name}",
                )
                for facet_name, facet_status, projector in (
                    (
                        "methodology", "unchanged",
                        runner._project_wordpress_methodology,
                    ),
                    (
                        "coverage", "not_established",
                        runner._project_wordpress_coverage,
                    ),
                    (
                        "provenance", "unchanged",
                        runner._project_wordpress_provenance,
                    ),
                    (
                        "discovery_source_content", "unchanged",
                        runner._project_wordpress_discovery_source_content,
                    ),
                ):
                    projection = projector(
                        source_inventory,
                        f"synthetic supplied-session self {facet_name} {name}",
                    )
                    wordpress_self[facet_name] = {
                        "status": facet_status,
                        "changed_fields": [],
                        "before": projection,
                        "after": copy.deepcopy(projection),
                        "note": "Synthetic acceptance facet.",
                    }
                wordpress_self["components"]["paired_unchanged_count"] = len(
                    wordpress_document["wordpress_review"]["components"]
                )
                self_compare["wordpress_review_comparison"] = wordpress_self
                responses[f"offline self comparison {name}"] = self_compare

            healthy_raw = raw_documents["session-root-healthy"]
            loss_raw = raw_documents["session-root-loss-after-resource"]
            unchanged_projection = projection_from_item(surface_item)
            changed_before_projection = projection_from_item(discovery_complete)
            changed_after_projection = projection_from_item(discovery_lost)
            health_loss = comparison_document(
                healthy_raw, 2, loss_raw, 2,
                groups={
                    "only_in_after": [],
                    "only_in_before": [],
                    "changed": [comparison_item(
                        discovery_complete["fingerprint"],
                        discovery_complete["capability_id"],
                        before=changed_before_projection,
                        after=changed_after_projection,
                        changed_fields=["evidence"],
                    )],
                    "unchanged": [comparison_item(
                        surface_item["fingerprint"], surface_item["capability_id"],
                        before=unchanged_projection,
                        after=copy.deepcopy(unchanged_projection),
                        changed_fields=[],
                    )],
                },
            )
            attach_supplied_session_comparison(
                health_loss,
                before_audit=audits["session-root-healthy"],
                after_audit=audits["session-root-loss-after-resource"],
                context_status="same_declared_context",
                health_status="changed",
                accounting_status="changed",
                status="compared_within_same_declared_context",
                reason=None,
            )
            health_wordpress = wordpress_comparison(discovery=True, controlled=False)
            health_wordpress["schema"] = "termivar-wordpress-review-comparison/v4"
            healthy_inventory = runner._read_assessment_inventory(
                Path(scenarios["session-root-healthy"]["_bundle"])
                / "assessment.json",
                "synthetic healthy WordPress coverage source",
            )
            loss_inventory = runner._read_assessment_inventory(
                Path(scenarios["session-root-loss-after-resource"]["_bundle"])
                / "assessment.json",
                "synthetic lost WordPress coverage source",
            )
            before_coverage = runner._project_wordpress_coverage(
                healthy_inventory, "synthetic healthy WordPress coverage source"
            )
            after_coverage = runner._project_wordpress_coverage(
                loss_inventory, "synthetic lost WordPress coverage source"
            )
            health_wordpress["coverage"].update({
                "status": "changed",
                "changed_fields": sorted(
                    field
                    for field in before_coverage.keys() | after_coverage.keys()
                    if before_coverage.get(field) != after_coverage.get(field)
                ),
                "before": before_coverage,
                "after": after_coverage,
            })
            for facet_name, projector in (
                ("methodology", runner._project_wordpress_methodology),
                ("provenance", runner._project_wordpress_provenance),
            ):
                before_facet = projector(
                    healthy_inventory,
                    f"synthetic healthy WordPress {facet_name} source",
                )
                after_facet = projector(
                    loss_inventory,
                    f"synthetic lost WordPress {facet_name} source",
                )
                health_wordpress[facet_name] = {
                    "status": "unchanged",
                    "changed_fields": [],
                    "before": before_facet,
                    "after": after_facet,
                    "note": "Synthetic acceptance facet.",
                }
            def expected_source_content(source_document):
                rest_source = next(
                    source for source in source_document["wordpress_discovery"]["sources"]
                    if source["kind"] == "rest_index"
                )
                rest_projection = {
                    field: copy.deepcopy(rest_source[field])
                    for field in (
                        "kind", "namespaces", "association", "resource_reference",
                        "role_reference", "source_supplied_session_page_references",
                    )
                    if field in rest_source
                }
                rest_projection["namespaces"] = sorted(rest_projection["namespaces"])
                page = source_document["wordpress_discovery"][
                    "supplied_session_pages"
                ]["pages"][0]
                return {
                    "rest_indexes": [rest_projection],
                    "supplied_session_pages": [{
                        field: copy.deepcopy(page[field])
                        for field in (
                            "page_reference", "resource_reference",
                            "resource_evidence_reference", "acquisition",
                            "association", "outcome", "interpreted_response_bytes",
                            "fingerprint_evaluation",
                        )
                    }],
                }

            before_source_content = expected_source_content(json.loads(healthy_raw))
            after_source_content = expected_source_content(json.loads(loss_raw))
            health_wordpress["discovery_source_content"] = {
                "status": "changed",
                "changed_fields": ["supplied_session_pages"],
                "before": before_source_content,
                "after": after_source_content,
                "note": "Synthetic acceptance facet.",
            }
            health_wordpress["components"] = {
                "paired_unchanged_count": 4,
                "paired_changed": [],
                "only_in_before": [{
                    "key": {
                        "kind": runner.FINGERPRINT_COMPONENT[0],
                        "slug": runner.FINGERPRINT_COMPONENT[1],
                    },
                    "content": {"component_evidence": "synthetic"},
                    "interpretation": (
                        "present_only_in_the_supplied_before_audit_not_verified_remediation"
                    ),
                }],
                "only_in_after": [],
            }
            health_loss["wordpress_review_comparison"] = health_wordpress
            responses["offline supplied-session health-loss comparison"] = health_loss

            bob_raw = raw_documents["session-root-bob-healthy"]
            bob_items = scenario_items["session-root-bob-healthy"]
            healthy_items = scenario_items["session-root-healthy"]
            before_inventory = runner._read_assessment_inventory(
                Path(scenarios["session-root-healthy"]["_bundle"])
                / "assessment.json",
                "synthetic cross-principal before source",
            )
            after_inventory = runner._read_assessment_inventory(
                Path(scenarios["session-root-bob-healthy"]["_bundle"])
                / "assessment.json",
                "synthetic cross-principal after source",
            )
            principal_change = comparison_document(
                healthy_raw, len(healthy_items), bob_raw, len(bob_items),
                groups={
                    "only_in_after": [
                        comparison_item(
                            item["fingerprint"], item["capability_id"],
                            before=None,
                            after=projection_from_item(item),
                            changed_fields=[],
                        )
                        for item in bob_items
                    ],
                    "only_in_before": [
                        comparison_item(
                            item["fingerprint"], item["capability_id"],
                            before=projection_from_item(item),
                            after=None,
                            changed_fields=[],
                        )
                        for item in healthy_items
                    ],
                    "changed": [],
                    "unchanged": [],
                },
            )
            attach_supplied_session_comparison(
                principal_change,
                before_audit=audits["session-root-healthy"],
                after_audit=audits["session-root-bob-healthy"],
                context_status="operator_declared_principal_changed",
                health_status="not_comparable",
                accounting_status="not_comparable",
                status="not_compared",
                reason="operator_declared_principal_changed",
            )
            principal_wordpress = wordpress_comparison(discovery=True, controlled=False)
            principal_facet_sources = {
                "methodology": runner._project_wordpress_methodology,
                "coverage": runner._project_wordpress_coverage,
                "provenance": runner._project_wordpress_provenance,
                "discovery_source_content": (
                    runner._project_wordpress_discovery_source_content
                ),
            }
            for facet_name, projector in principal_facet_sources.items():
                before_facet = projector(
                    before_inventory, f"synthetic cross-principal before {facet_name}"
                )
                after_facet = projector(
                    after_inventory, f"synthetic cross-principal after {facet_name}"
                )
                facet_status = (
                    "not_established"
                    if facet_name == "coverage" and before_facet == after_facet
                    else "unchanged" if before_facet == after_facet
                    else "changed"
                )
                principal_wordpress[facet_name] = {
                    "status": facet_status,
                    "changed_fields": sorted(
                        field
                        for field in before_facet.keys() | after_facet.keys()
                        if before_facet.get(field) != after_facet.get(field)
                    ),
                    "before": before_facet,
                    "after": after_facet,
                    "note": "Synthetic acceptance facet.",
                }
            principal_wordpress.update({
                "schema": "termivar-wordpress-review-comparison/v4",
                "status": "not_compared",
                "reason": "supplied_session_context_mismatch",
                "components": {
                    "paired_unchanged_count": 0,
                    "paired_changed": [],
                    "only_in_before": [],
                    "only_in_after": [],
                },
                "advisories": {
                    "paired_unchanged_count": 0,
                    "paired_changed": [],
                    "only_in_before": [],
                    "only_in_after": [],
                },
            })
            principal_change["wordpress_review_comparison"] = principal_wordpress
            responses[
                "offline supplied-session principal-context comparison"
            ] = principal_change
            counts, _ = runner._validate_comparison_partition(
                principal_change,
                before_inventory,
                after_inventory,
                "synthetic cross-principal partition",
                context_blocks_item_pairing=True,
            )
            self.assertEqual(counts["only_in_before"], 2)
            self.assertEqual(counts["only_in_after"], 2)
            duplicated = copy.deepcopy(principal_change)
            duplicated["only_in_before"].append(
                copy.deepcopy(duplicated["only_in_before"][0])
            )
            with self.assertRaisesRegex(runner.AcceptanceError, "within comparison group"):
                runner._validate_comparison_partition(
                    duplicated,
                    before_inventory,
                    after_inventory,
                    "synthetic duplicate cross-principal partition",
                    context_blocks_item_pairing=True,
                )
            substituted = copy.deepcopy(principal_change)
            substituted["only_in_after"][0]["fingerprint"] = "sha256:" + "e" * 64
            with self.assertRaises(runner.AcceptanceError):
                runner._validate_comparison_partition(
                    substituted,
                    before_inventory,
                    after_inventory,
                    "synthetic substituted cross-principal partition",
                    context_blocks_item_pairing=True,
                )

            process = offline_process_runner(responses, scenarios)
            result = runner._run_offline_acceptance(
                process, Path("synthetic-termivar"), scenarios
            )
            self.assertEqual(
                result["supplied_session_healthy_to_loss"]["health_and_coverage"],
                "changed",
            )
            self.assertEqual(
                result["supplied_session_healthy_to_loss"]
                ["wordpress_provenance"],
                "unchanged",
            )
            self.assertEqual(
                result["supplied_session_healthy_to_loss"]
                ["wordpress_discovery_source_content"],
                "changed",
            )
            self.assertEqual(
                result["supplied_session_healthy_to_loss"]["item_counts"],
                {
                    "only_in_after": 0,
                    "only_in_before": 0,
                    "changed": 1,
                    "unchanged": 1,
                },
            )
            self.assertEqual(
                result["supplied_session_alice_to_bob"]["reason"],
                "operator_declared_principal_changed",
            )
            self.assertEqual(
                result["supplied_session_alice_to_bob"]["item_counts"],
                {
                    "only_in_after": 2,
                    "only_in_before": 2,
                    "changed": 0,
                    "unchanged": 0,
                },
            )
            self.assertIn(
                "offline supplied-session health-loss comparison",
                [label for label, _ in process.calls],
            )
            self.assertIn(
                "offline supplied-session principal-context comparison",
                [label for label, _ in process.calls],
            )

            invalid_self_responses = copy.deepcopy(responses)
            invalid_self_facet = invalid_self_responses[
                "offline self comparison session-root-healthy"
            ]["wordpress_review_comparison"]["methodology"]
            invalid_self_facet.update({
                "changed_fields": [],
                "before": {"equal_but_not_source_derived": True},
                "after": {"equal_but_not_source_derived": True},
            })
            with self.assertRaises(runner.AcceptanceError):
                runner._run_offline_acceptance(
                    offline_process_runner(invalid_self_responses, scenarios),
                    Path("synthetic-termivar"),
                    scenarios,
                )

            def move_health_change_to_unchanged(response):
                changed_item = response["changed"].pop()
                changed_item["changed_fields"] = []
                response["unchanged"].append(changed_item)

            def move_health_change_to_one_sided(response):
                changed_item = response["changed"].pop()
                changed_item["after"] = None
                changed_item["changed_fields"] = []
                response["only_in_before"].append(changed_item)

            for label, mutate in (
                (
                    "missing health-loss WordPress comparison",
                    lambda response: response.pop("wordpress_review_comparison"),
                ),
                (
                    "paired cross-principal WordPress component",
                    lambda response: response["wordpress_review_comparison"][
                        "components"
                    ].update({"paired_unchanged_count": 1}),
                ),
                (
                    "boolean cross-principal WordPress advisory count",
                    lambda response: response["wordpress_review_comparison"][
                        "advisories"
                    ].update({"paired_unchanged_count": False}),
                ),
                (
                    "cross-principal WordPress methodology projection",
                    lambda response: response["wordpress_review_comparison"][
                        "methodology"
                    ]["before"]["wordpress_discovery"].update({
                        "policy_id": "synthetic.invalid-policy",
                    }),
                ),
                (
                    "cross-principal WordPress canonical layout order",
                    lambda response: response["wordpress_review_comparison"][
                        "methodology"
                    ]["before"]["wordpress_discovery"]["layout_roles"].reverse(),
                ),
                (
                    "cross-principal WordPress coverage status",
                    lambda response: response["wordpress_review_comparison"][
                        "coverage"
                    ].update({"status": "unchanged"}),
                ),
                (
                    "cross-principal WordPress provenance projection",
                    lambda response: response["wordpress_review_comparison"][
                        "provenance"
                    ]["after"]["wordpress_supplied_session"].update({
                        "session_epoch": 2,
                    }),
                ),
                (
                    "cross-principal WordPress source-content status",
                    lambda response: response["wordpress_review_comparison"][
                        "discovery_source_content"
                    ].update({"status": "unchanged", "changed_fields": []}),
                ),
                (
                    "one-sided health-loss WordPress advisory",
                    lambda response: response["wordpress_review_comparison"][
                        "advisories"
                    ]["only_in_before"].append({"synthetic": True}),
                ),
                (
                    "unchanged health-loss WordPress source content",
                    lambda response: response["wordpress_review_comparison"][
                        "discovery_source_content"
                    ].update({"status": "unchanged", "changed_fields": []}),
                ),
                (
                    "wrong health-loss WordPress source projection",
                    lambda response: response["wordpress_review_comparison"][
                        "discovery_source_content"
                    ]["after"]["supplied_session_pages"][0].update(
                        {"association": "accepted"}
                    ),
                ),
                (
                    "wrong health-loss WordPress coverage fields",
                    lambda response: response["wordpress_review_comparison"][
                        "coverage"
                    ].update({"changed_fields": ["wordpress_discovery"]}),
                ),
                (
                    "changed health-loss WordPress provenance",
                    lambda response: response["wordpress_review_comparison"][
                        "provenance"
                    ].update({
                        "status": "changed",
                        "changed_fields": ["supplied_session_context"],
                    }),
                ),
                (
                    "wrong equal-bogus health-loss methodology projection",
                    lambda response: response["wordpress_review_comparison"][
                        "methodology"
                    ].update({
                        "status": "unchanged",
                        "changed_fields": [],
                        "before": {"equal_but_not_source_derived": True},
                        "after": {"equal_but_not_source_derived": True},
                    }),
                ),
                (
                    "wrong health-loss outer unchanged partition",
                    move_health_change_to_unchanged,
                ),
                (
                    "wrong health-loss outer capability",
                    lambda response: response["changed"][0].update({
                        "capability_id": BASE_CAPABILITY,
                    }),
                ),
                (
                    "wrong health-loss outer changed fields",
                    lambda response: response["changed"][0].update({
                        "changed_fields": ["title"],
                    }),
                ),
                (
                    "one-sided health-loss outer discovery item",
                    move_health_change_to_one_sided,
                ),
            ):
                with self.subTest(label=label):
                    invalid_responses = copy.deepcopy(responses)
                    target = (
                        "offline supplied-session health-loss comparison"
                        if label.startswith((
                            "missing", "one-sided", "unchanged", "wrong", "changed"
                        )) else
                        "offline supplied-session principal-context comparison"
                    )
                    mutate(invalid_responses[target])
                    with self.assertRaises(runner.AcceptanceError):
                        runner._run_offline_acceptance(
                            offline_process_runner(invalid_responses, scenarios),
                            Path("synthetic-termivar"),
                            scenarios,
                        )

    def test_scenario_registry_and_static_session_fixture_contract_are_exact(self):
        expected_registry = (
            "ordinary-web-review", "pretty-review-only", "pretty-discovery",
            "suppressed-review-only", "suppressed-discovery", "plain-review-only",
            "plain-discovery", "session-root-option-off", "session-root-healthy",
            "session-root-fingerprint-selected-empty", "session-root-wrong-principal",
            "session-root-loss-after-resource", "session-root-bob-healthy",
            "session-root-expired-startup", "fingerprint-observed-option-off",
            "fingerprint-one-file-observed-option-off",
            "fingerprint-common-file-observed-option-off", "fingerprint-release-b",
            "fingerprint-release-a", "fingerprint-release-c", "fingerprint-one-file",
            "fingerprint-common-file", "fingerprint-mixed-artifacts",
            "fingerprint-missing-reference", "blog-pretty-discovery",
            "session-blog-healthy", "blog-fingerprint-observed-option-off",
            "blog-fingerprint-sibling-rejected", "blog-plain-discovery",
            "cms-review-only", "cms-discovery", "custom-review-only",
            "custom-no-layout-discovery", "custom-layout-discovery",
            "custom-fingerprint-observed-option-off", "custom-fingerprint-release-b",
            "session-custom-fingerprint-selected-empty",
        )
        self.assertEqual(runner.EXPECTED_SCENARIOS, expected_registry)
        self.assertEqual(len(runner.EXPECTED_SCENARIOS), 37)
        self.assertEqual(len(set(runner.EXPECTED_SCENARIOS)), 37)
        self.assertEqual(len(runner.SESSION_SCENARIOS), 9)
        self.assertTrue(set(runner.SESSION_SCENARIOS) <= set(runner.EXPECTED_SCENARIOS))
        fixture = runner.validate_fixture()
        self.assertEqual(fixture["file_count"], 28)
        workflow = (REPOSITORY_ROOT / ".github/workflows/tests.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "--features wordpress-review,supplied-session-review", workflow
        )
        php = (
            runner.FIXTURE_ROOT / "plugins/termivar-fingerprint-lab/termivar-fingerprint-lab.php"
        ).read_text(encoding="utf-8")
        for literal in (
            "is_user_logged_in()",
            "termivar-session-health",
            "termivar-session-member",
            runner.SESSION_PRIVATE_BODY_CANARY.decode("ascii"),
            runner.SESSION_PRIVATE_BODY_MARKERS["termivar-lab-alice"].decode("ascii"),
            runner.SESSION_PRIVATE_BODY_MARKERS["termivar-lab-bob"].decode("ascii"),
        ):
            self.assertIn(literal, php)

    def test_compact_evidence_serialization_preserves_the_fixed_boundary(self):
        # Indentation alone would breach the historical 256-KiB ceiling for this
        # synthetic 37-scenario-shaped record; the compact writer retains it.
        evidence = {
            "schema": runner.TASK_SCHEMA,
            "status": "passed",
            "scenarios": {
                f"scenario-{index:02d}": {
                    "requests": [
                        {"sequence": sequence, "method": "GET", "status": 200}
                        for sequence in range(90)
                    ]
                }
                for index in range(37)
            },
        }
        pretty = (
            json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        compact = (
            json.dumps(
                evidence,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ) + "\n"
        ).encode("utf-8")
        self.assertGreater(len(pretty), runner.MAX_EVIDENCE_OUTPUT)
        self.assertLessEqual(len(compact), runner.MAX_EVIDENCE_OUTPUT)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            with mock.patch.object(
                runner, "render_markdown", return_value="# Synthetic bounded evidence\n"
            ):
                runner.write_evidence(destination, evidence)
            self.assertEqual(
                (destination / "wordpress-discovery-lab-acceptance.json").read_bytes(),
                compact,
            )


if __name__ == "__main__":
    unittest.main()
