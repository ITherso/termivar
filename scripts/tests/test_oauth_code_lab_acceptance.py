"""Synthetic controller/consumer regressions, not captured Keycloak output."""

import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.parse


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("oauth_code_lab_acceptance", ROOT / "scripts/oauth_code_lab_acceptance.py")
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)

NAMES = ("option-off", "valid-a", "replayed-code", "wrong-verifier", "wrong-b-health", "valid-b-context")
ROLES = {
    "option-off": (), "valid-a": ("health", "resource-one", "health", "resource-two", "health"),
    "replayed-code": (), "wrong-verifier": (), "wrong-b-health": ("health",),
    "valid-b-context": ("health", "resource-one", "health", "resource-two", "health"),
}


def literal_image_inspection(profile="legacy"):
    """Original literal engine-shape fixtures, not captured Docker output."""
    row = {
        "Id": "sha256:b55801be6ce15109868bd056dc18d62d47106bfaad7ffbd1a5d804192ec98257",
        "RepoDigests": ["quay.io/keycloak/keycloak@sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc"],
        "Architecture": "amd64", "Os": "linux", "Config": {"User": "1000"},
    }
    if profile == "containerd":
        row["Id"] = "sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc"
        row["Descriptor"] = {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc",
            "size": 1056,
        }
    elif profile != "legacy":
        raise AssertionError("unknown synthetic image-inspection profile")
    return [row]


def synthetic_audit(name="valid-a"):
    """Literal reviewed V5 subset consumed by the helper, not a product export."""
    if name == "option-off":
        return None
    successful = name in ("valid-a", "wrong-b-health", "valid-b-context")
    resources = 2 if name in ("valid-a", "valid-b-context") else 0
    phases = ["startup", "subject_boundary", "terminal"] if resources else (["startup"] if successful else [])
    return {
        "schema": "security.supplied-session-audit/v5",
        "principal_alias": "canary-b" if name == "valid-b-context" else "canary-a",
        "credential_acquisition": "imported_oauth_code_pkce",
        "outcome": "startup_unhealthy" if name == "wrong-b-health" else (
            "complete" if successful else "oauth_code_exchange_unavailable"),
        "dispatched_request_count": 6 if resources else (2 if successful else 1),
        "selected_resource_count": 2, "dispatched_resource_count": resources, "committed_resource_count": resources,
        "checkpoints": [{"sequence": index, "phase": phase, "after_subject_count": index,
                         "evidence_reference": "supplied-session-checkpoint-evidence-sha256:" + str(index + 5) * 64,
                         "outcome": "unhealthy" if name == "wrong-b-health" else "healthy", "status": 200,
                         "body_state": "complete", "predicate": "not_matched" if name == "wrong-b-health" else "matched",
                         "response_bytes": 20} for index, phase in enumerate(phases)],
        "resources": [{"sequence": index, "resource_reference": "supplied-session-resource-sha256:" + str(index + 3) * 64,
                       "evidence_reference": "supplied-session-resource-evidence-sha256:" + str(index + 3) * 64 if resources else None,
                       "outcome": "committed" if resources else "not_dispatched", "status": 200 if resources else None,
                       "response_bytes": 20 if resources else 0, "epoch": 1} for index in range(2)],
        "refresh_performed": False, "anonymous_fallback_performed": False,
        "continuous_authentication_established": False, "exploit_execution": "not_performed",
        "impact_validation": "not_performed", "response_bytes": 612 if resources else (532 if successful else 64),
        "response_byte_limit_exceeded": False,
        "oauth_code": {
            "profile": "external-public-code-s256-bearer/v1",
            "transport_profile": "owned-numeric-loopback-http/v1",
            "idp_reference": "oauth-code-policy-sha256:" + "1" * 64,
            "transaction_context_assurance": "operator_declared_external_transaction",
            "pkce_assurance": "imported_s256_context_not_remote_enforcement",
            "token_interpretation": "opaque_bearer_not_oidc_identity",
            "authorization_initiated": False, "browser_callback_received": False,
            "state_nonce_verified": False, "oidc_identity_validation_performed": False,
            "token_signature_validation_performed": False,
            "request_attempt_count": 1, "request_admitted_count": 1,
            "response_completed_count": 1, "credential_commit_count": 1 if successful else 0,
            "verifier_in_admitted_request": True, "status": 200 if successful else 400,
            "body_state": "complete", "response_bytes": 512 if successful else 64,
            "configured_token_response_byte_limit": 8192,
            "token_response_validated": successful,
            "response_scope_matched": True if successful else None,
            "declared_token_lifetime_seconds": 180 if successful else None,
            "refresh_token_returned": False if successful else None,
            "evidence_reference": "supplied-session-oauth-code-evidence-sha256:" + "2" * 64 if successful else None,
            "outcome": "credential_committed" if successful else "response_rejected",
        },
    }


def synthetic_trace(name):
    ordinary = [{"phase": name, "role": "ordinary", "method": "GET", "credential_present": False,
                 "accepted": False, "entry_path": True} for _ in range(3)]
    session = [{"phase": name, "role": role, "method": "GET", "credential_present": True,
                "accepted": name != "wrong-b-health", "entry_path": False, "response_bytes": 20} for role in ROLES[name]]
    idp = [] if name == "option-off" else [{"phase": name, "role": "token-exchange", "method": "POST",
                 "request_bytes": 200, "status": 400 if name in ("replayed-code", "wrong-verifier") else 200,
                 "response_bytes": 64 if name in ("replayed-code", "wrong-verifier") else 512,
                 "error_class": "invalid_grant" if name in ("replayed-code", "wrong-verifier") else None}]
    return ordinary + session, idp


def synthetic_item(name):
    return {"capability_id": "session.supplied-context-observed@1", "fingerprint": "sha256:" + hashlib.sha256(name.encode()).hexdigest()}


def synthetic_source(name):
    result = {"schema": "venom-rendered-assessment/v1", "item_count": 1, "items": [synthetic_item(name)]}
    if name != "option-off":
        result["supplied_session"] = synthetic_audit(name)
    return result


def synthetic_self_comparison(source):
    result = {"schema": "termivar-report-comparison/v1", "only_in_after": [], "only_in_before": [],
              "changed": [], "unchanged": copy.deepcopy(source["items"])}
    if "supplied_session" in source:
        result["supplied_session_comparison"] = {
            "schema": "termivar-supplied-session-comparison/v1", "status": "compared_within_same_declared_context",
            "context": {"status": "same_declared_context"},
            "health_and_coverage": {"status": "unchanged"}, "accounting": {"status": "unchanged"}}
    return result


class FakeLab:
    instances = []

    def __init__(self, runner, relay, realm):
        self.runner, self.relay, self.realm = runner, relay, realm
        self.closed = False
        self.prepared = False
        self.__class__.instances.append(self)

    def prepare(self):
        self.prepared = True

    def cleanup(self):
        self.closed = True
        return {"status": "complete", "failures": [], "container_removed": True, "network_removed": True}


class FakeRunner:
    """Bounded canned process responses exercise execute and run_offline themselves.

    These are synthetic, not native executable or provider acceptance.
    """

    def __init__(self, mutation=None, publish_failures=True):
        self.private = lab.PrivateValues()
        self.records = []
        self.sources = {}
        self.mutation = mutation
        self.publish_failures = publish_failures
        self.scanner_arguments = []

    def run(self, args, *, label, **kwargs):
        self.records.append({"id": label, "exit_code": 0, "elapsed_seconds": 0.01})
        if label == "candidate-version":
            return lab.Result(b"termivar 0.10.0-alpha.3\n", b"", 0, 0.01)
        if label.endswith("-scan"):
            name = label[:-5]
            self.scanner_arguments.append(list(args))
            fixture = FakeLab.instances[-1]
            if not fixture.prepared or fixture.closed:
                raise AssertionError("scan did not use active synthetic provider")
            target = TargetCapture.instances[-1]
            rows, idp = synthetic_trace(name)
            target.trace.extend(rows)
            fixture.relay.trace.extend(idp)
            source = synthetic_source(name)
            if self.mutation is not None:
                self.mutation(name, source)
            path = Path(args[args.index("--report-dir") + 1])
            self.sources[path] = source
            if self.publish_failures or name in ("option-off", "valid-a", "valid-b-context"):
                path.mkdir()
                (path / "assessment.json").write_text(json.dumps(source), encoding="utf-8")
                (path / "assessment.html").write_text("<main>synthetic report</main>", encoding="utf-8")
                (path / "manifest.json").write_text('{"synthetic":true}', encoding="utf-8")
                return lab.Result(b"{}", b"", 0, 0.01)
            output = {"schema_version": "web-assessment/v2", "disposition": "incomplete",
                      "assessment": {"report": {"supplied_session_audit": source["supplied_session"]}}}
            self.records[-1]["exit_code"] = 1
            return lab.Result(json.dumps(output).encode(), b"", 1, 0.01)
        if not FakeLab.instances[-1].closed or not TargetCapture.instances[-1].stopped:
            raise AssertionError("offline execution preceded genuine synthetic fixture shutdown")
        if label.endswith("-verify"):
            value = {"status": "integrity_match"}
        elif label.endswith("-self-compare"):
            path = Path(args[args.index("--before") + 1]).parent
            value = synthetic_self_comparison(self.sources[path])
        elif label == "a-to-b-context-compare":
            before = self.sources[Path(args[args.index("--before") + 1]).parent]
            after = self.sources[Path(args[args.index("--after") + 1]).parent]
            value = {"schema": "termivar-report-comparison/v1", "only_in_after": after["items"],
                     "only_in_before": before["items"], "changed": [], "unchanged": [],
                     "supplied_session_comparison": {"status": "not_compared", "context": {"status": "session_policy_changed"},
                         "health_and_coverage": {"status": "not_comparable"}, "accounting": {"status": "not_comparable"}}}
        else:
            raise AssertionError("unexpected process path " + label)
        return lab.Result(json.dumps(value).encode(), b"", 0, 0.01)


class TargetCapture(lab.TargetApplication):
    instances = []

    def __init__(self, *args):
        super().__init__(*args)
        self.stopped = False
        self.__class__.instances.append(self)

    def stop(self):
        super().stop()
        self.stopped = True


def synthetic_grant(origin, redirect, username, controller_secret, private):
    verifier = "v" * 64
    return lab.Grant("synthetic-code-" + username + "-" + "c" * 16, verifier, lab.challenge(verifier),
                     origin + "/realms/termivar-owned-code", redirect, int(lab.time.time()))


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        FakeLab.instances.clear()
        TargetCapture.instances.clear()

    def execute_fake(self, runner=None, output=None):
        runner = runner or FakeRunner()
        parent = tempfile.TemporaryDirectory(prefix="test-owned-oauth-", dir=ROOT)
        self.addCleanup(parent.cleanup)
        root = Path(parent.name)
        binary = root / "synthetic-termivar"
        binary.write_bytes(b"synthetic candidate, not executable output")
        output = output or root / "safe-evidence"
        patches = (mock.patch.object(lab, "KeycloakLab", FakeLab),
                   mock.patch.object(lab, "TargetApplication", TargetCapture),
                   mock.patch.object(lab, "obtain_code", side_effect=synthetic_grant))
        with patches[0], patches[1], patches[2]:
            result = lab.execute(binary, output, "a" * 40, "0.10.0-alpha.3", runner)
        return result, runner, output

    def test_static_contract_is_explicitly_not_provider_execution(self):
        document = lab.validate_fixture()
        self.assertEqual(document["scenario_registry"], list(NAMES))
        self.assertEqual(document["execution_class"], "static_only")
        self.assertEqual(document["cms_or_idp_execution"], "not_performed")
        self.assertEqual(document["image_linux_amd64"], "sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc")

    def test_policy_uses_absolute_scope_and_explicit_fixture_transport(self):
        import tomllib
        value = tomllib.loads(lab.policy_source("http://127.0.0.1:1234/realms/termivar-owned-code",
                                               "http://127.0.0.1:5678/callback", "canary-a").decode())
        self.assertEqual(value["health_path"], "/app/health")
        self.assertEqual(value["health_json_field"], "canary_a")
        self.assertEqual(value["resources"], ["/app/private/one", "/app/private/two"])
        self.assertEqual(value["max_session_requests"], 6)
        self.assertEqual(value["oauth_code"]["transport_profile"], "owned-numeric-loopback-http/v1")
        self.assertEqual(value["oauth_code"]["scopes"], ["canary-read"])

    def test_owned_policy_child_cap_is_independently_8192_not_32768(self):
        import tomllib
        value = tomllib.loads(lab.policy_source("http://127.0.0.1:1234/realms/termivar-owned-code",
                                               "http://127.0.0.1:5678/callback", "canary-a").decode())
        self.assertEqual(value["max_response_body_bytes"], 8192)
        self.assertEqual(value["oauth_code"]["max_token_response_bytes"], 8192)
        self.assertLessEqual(value["oauth_code"]["max_token_response_bytes"], value["max_response_body_bytes"])

    def test_owned_matrix_requires_zero_exit_and_all_six_emitted_bundles(self):
        with self.assertRaisesRegex(lab.LabError, "scan_exit_contract|expected_completed_bundle"):
            self.execute_fake(FakeRunner(publish_failures=False))

    def test_static_owned_policy_oracle_rejects_32768_child_and_bool_caps(self):
        # Literal independent policy fragment; no product policy parser/matcher
        # supplies either this input or the expected 8192 ceiling.
        source = b'''schema = "security.supplied-session-policy/v5"
max_response_body_bytes = 8192
[oauth_code]
max_token_response_bytes = 8192
'''
        lab.validate_fixture_policy(source)
        for bad in (source.replace(b"max_token_response_bytes = 8192", b"max_token_response_bytes = 32768"),
                    source.replace(b"max_token_response_bytes = 8192", b"max_token_response_bytes = true"),
                    source.replace(b"max_response_body_bytes = 8192", b"max_response_body_bytes = true")):
            with self.subTest(source=bad), self.assertRaisesRegex(lab.LabError, "fixture_policy_body_caps"):
                lab.validate_fixture_policy(bad)

    def test_original_realm_keeps_three_client_authorities_separate(self):
        document = lab.realm_document("synthetic-resource-secret", "synthetic-controller-secret", "http://127.0.0.1:1234/callback")
        clients = {client["clientId"]: client for client in document["clients"]}
        self.assertEqual(set(clients), {"termivar-owned-public", "termivar-owned-resource", "termivar-owned-controller"})
        self.assertFalse(clients["termivar-owned-resource"]["serviceAccountsEnabled"])
        self.assertTrue(clients["termivar-owned-controller"]["serviceAccountsEnabled"])
        self.assertEqual(clients["termivar-owned-public"]["attributes"], {"pkce.code.challenge.method": "S256"})
        self.assertTrue(all(not row["directAccessGrantsEnabled"] for row in clients.values()))
        self.assertEqual(document["users"][-1]["clientRoles"], {"realm-management": ["impersonation"]})
        self.assertEqual([user["credentials"] for user in document["users"][:2]], [[], []])

    def test_complete_execute_loop_and_every_offline_path(self):
        document, runner, output = self.execute_fake()
        self.assertEqual(document["status"], "passed")
        self.assertEqual(tuple(document["scenarios"]), NAMES)
        self.assertEqual(set(document["offline"]["bundles"]), set(NAMES))
        self.assertEqual(len([row for row in runner.records if row["id"].endswith("-verify")]), 6)
        self.assertEqual(len([row for row in runner.records if row["id"].endswith("-self-compare")]), 6)
        self.assertEqual(runner.records[-1]["id"], "a-to-b-context-compare")
        self.assertTrue(document["offline"]["fixtures_stopped_before_execution"])
        self.assertTrue(document["cleanup"]["idp"]["container_removed"])
        self.assertEqual(document["interactive_login_qualification"], "not_performed")
        self.assertEqual(document["scenarios"]["valid-a"]["diagnostic"]["actual"]["session_requests"], 6)
        self.assertEqual(document["scenarios"]["wrong-b-health"]["diagnostic"]["actual"]["resource_count"], 0)
        payload = (output / "oauth-code-lab-acceptance.json").read_bytes()
        self.assertNotIn(b"http://", payload)
        self.assertNotIn(str(output.parent).encode(), payload)
        self.assertNotIn(b"synthetic-code-", payload)
        for args in runner.scanner_arguments:
            self.assertEqual(args[1], "scan")
            if "--session-policy" in args:
                self.assertIn("--session-oauth-code-file", args)
                self.assertNotIn("--session-authorization-file", args)

    def test_nonpublished_started_failure_not_relabelled_success(self):
        runner = FakeRunner(publish_failures=False)
        with tempfile.TemporaryDirectory(prefix="test-owned-oauth-", dir=ROOT) as directory:
            output = Path(directory) / "evidence"
            with self.assertRaisesRegex(lab.LabError, "scan_exit_contract"):
                self.execute_fake(runner, output)
            document = json.loads((output / "oauth-code-lab-acceptance.json").read_bytes())
            self.assertEqual(document["status"], "failed")
            self.assertEqual(document["failure"]["diagnostic"],
                             {"scenario": "replayed-code", "expected_exit": 0, "actual_exit": 1})
            self.assertEqual(document["offline"]["status"], "not_run")
            self.assertFalse(any(row["id"].endswith("-verify") for row in runner.records))

    def test_accounting_failure_keeps_bounded_diagnostic_and_cleanup(self):
        def mutation(name, source):
            if name == "valid-a":
                source["supplied_session"]["oauth_code"]["credential_commit_count"] = 0

        with tempfile.TemporaryDirectory(prefix="test-owned-oauth-", dir=ROOT) as directory:
            output = Path(directory) / "evidence"
            with self.assertRaisesRegex(lab.LabError, "oauth_accounting"):
                self.execute_fake(FakeRunner(mutation), output)
            value = json.loads((output / "oauth-code-lab-acceptance.json").read_bytes())
            self.assertEqual(value["failure"]["code"], "oauth_accounting")
            self.assertEqual(value["failure"]["diagnostic"]["scenario"], "valid-a")
            self.assertEqual(value["failure"]["diagnostic"]["actual"]["oauth_code"]["credential_commit_count"], 0)
            self.assertEqual(value["cleanup"]["idp"]["status"], "complete")
            self.assertEqual(value["offline"]["status"], "not_run")

    def test_original_failure_survives_cleanup_and_diagnostic_write_failure(self):
        def mutation(name, source):
            if name == "valid-a":
                source["supplied_session"]["oauth_code"]["credential_commit_count"] = 0

        original_write = lab.private_write

        def failed_evidence(path, data):
            if path.name == "oauth-code-lab-acceptance.json":
                raise OSError("synthetic private path must not be shown")
            return original_write(path, data)

        with mock.patch.object(lab, "private_write", side_effect=failed_evidence), \
             mock.patch.object(FakeLab, "cleanup", return_value={"status": "failed", "failures": ["synthetic_cleanup"]}):
            with self.assertRaisesRegex(lab.LabError, "oauth_accounting") as raised:
                self.execute_fake(FakeRunner(mutation))
        self.assertNotIn("private path", str(raised.exception))

    def test_each_named_scenario_independent_trace_and_audit_oracles(self):
        baseline = [{"method": "GET", "role": "ordinary", "entry_path": True} for _ in range(3)]
        for name in NAMES:
            with self.subTest(name=name):
                target, idp = synthetic_trace(name)
                result = lab.validate_case(name, synthetic_audit(name), target, idp, baseline)
                self.assertEqual(result["status"], "passed")

    def test_missing_wrong_type_and_bool_counts_never_become_zero(self):
        for key in ("request_attempt_count", "request_admitted_count", "response_completed_count", "credential_commit_count"):
            for value in (None, True, "1", [], {}, 0):
                with self.subTest(key=key, value=value):
                    audit = synthetic_audit()
                    audit["oauth_code"][key] = value
                    target, idp = synthetic_trace("valid-a")
                    with self.assertRaisesRegex(lab.LabError, "oauth_accounting"):
                        lab.validate_case("valid-a", audit, target, idp, None)
        audit = synthetic_audit()
        del audit["dispatched_request_count"]
        target, idp = synthetic_trace("valid-a")
        with self.assertRaises(lab.LabError) as raised:
            lab.validate_case("valid-a", audit, target, idp, None)
        self.assertEqual(raised.exception.diagnostic["actual"]["session_requests"], {"state": "missing"})

    def test_required_claims_and_types_are_not_weakened(self):
        mutations = {
            "authorization_initiated": True, "browser_callback_received": True,
            "state_nonce_verified": True, "oidc_identity_validation_performed": True,
            "token_signature_validation_performed": True, "token_interpretation": "verified_identity",
            "pkce_assurance": "remote_enforcement_proven", "transport_profile": "verified-https/v1",
            "profile": "other", "transaction_context_assurance": None,
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                audit = synthetic_audit()
                audit["oauth_code"][key] = value
                target, idp = synthetic_trace("valid-a")
                with self.assertRaisesRegex(lab.LabError, "oauth_claim_boundaries"):
                    lab.validate_case("valid-a", audit, target, idp, None)

    def test_no_hidden_second_token_request_or_wrong_verifier_local_shortcut(self):
        for name in ("valid-a", "wrong-verifier", "replayed-code"):
            target, idp = synthetic_trace(name)
            with self.subTest(name=name, mutation="duplicate"):
                with self.assertRaisesRegex(lab.LabError, "token_post_count"):
                    lab.validate_case(name, synthetic_audit(name), target, idp * 2, None)
            with self.subTest(name=name, mutation="missing"):
                with self.assertRaisesRegex(lab.LabError, "token_post_count"):
                    lab.validate_case(name, synthetic_audit(name), target, [], None)
        target, idp = synthetic_trace("wrong-verifier")
        idp[0]["error_class"] = None
        with self.assertRaisesRegex(lab.LabError, "real_provider_refusal"):
            lab.validate_case("wrong-verifier", synthetic_audit("wrong-verifier"), target, idp, None)

    def test_wrong_principal_health_cannot_authorize_resource(self):
        target, idp = synthetic_trace("wrong-b-health")
        target.append({"role": "resource-one", "method": "GET", "credential_present": True, "accepted": False})
        with self.assertRaisesRegex(lab.LabError, "session_trace"):
            lab.validate_case("wrong-b-health", synthetic_audit("wrong-b-health"), target, idp, None)

    def test_source_entities_and_byte_counts_cannot_hide_missing_or_duplicate_work(self):
        def missing_resources(audit):
            del audit["resources"]

        def duplicate_resource(audit):
            audit["resources"][1]["resource_reference"] = audit["resources"][0]["resource_reference"]

        def missing_checkpoint(audit):
            audit["checkpoints"].pop()

        def wrong_phase(audit):
            audit["checkpoints"][1]["phase"] = "terminal"

        def wrong_total(audit):
            audit["response_bytes"] += 1

        def bool_total(audit):
            audit["response_bytes"] = True

        def incomplete_resource(audit):
            audit["resources"][0]["outcome"] = "not_dispatched"

        for mutate in (missing_resources, duplicate_resource, missing_checkpoint, wrong_phase,
                       wrong_total, bool_total, incomplete_resource):
            with self.subTest(mutation=mutate.__name__):
                audit = synthetic_audit()
                mutate(audit)
                target, idp = synthetic_trace("valid-a")
                with self.assertRaises(lab.LabError):
                    lab.validate_case("valid-a", audit, target, idp, None)

    def test_audit_bytes_must_match_independent_target_and_provider_trace(self):
        for role in ("target", "idp"):
            target, idp = synthetic_trace("valid-a")
            if role == "target":
                target[-1]["response_bytes"] += 1
            else:
                idp[0]["response_bytes"] += 1
            with self.subTest(role=role), self.assertRaises(lab.LabError):
                lab.validate_case("valid-a", synthetic_audit(), target, idp, None)

    def test_real_introspection_is_not_status_or_token_shape(self):
        document = {"active": True, "username": "canary-a", "aud": ["termivar-owned-resource"],
                    "scope": "canary-read", "client_id": "termivar-owned-public"}
        self.assertTrue(lab.introspection_allows(document, "canary-a"))
        for key, value in {"active": False, "username": "canary-b", "aud": ["other"],
                           "scope": "canary-read offline_access", "client_id": "other"}.items():
            changed = {**document, key: value}
            self.assertFalse(lab.introspection_allows(changed, "canary-a"), key)
        self.assertFalse(lab.introspection_allows(document, "canary-b"))

    def test_four_groups_no_counts_missing_wrong_type_and_duplicate_identity(self):
        source = synthetic_source("valid-a")
        comparison = synthetic_self_comparison(source)
        self.assertNotIn("counts", comparison)
        self.assertEqual(lab._self_compare(comparison, source),
                         {"only_in_after": 0, "only_in_before": 0, "changed": 0, "unchanged": 1})
        for group in ("only_in_after", "only_in_before", "changed", "unchanged"):
            for value in (None, False, 0, {}, ""):
                mutated = copy.deepcopy(comparison)
                mutated[group] = value
                mutated["counts"] = {"unchanged": 1}
                with self.subTest(group=group, value=value), self.assertRaisesRegex(lab.LabError, "comparison_groups"):
                    lab._self_compare(mutated, source)
            mutated = copy.deepcopy(comparison)
            del mutated[group]
            with self.assertRaisesRegex(lab.LabError, "comparison_groups"):
                lab._self_compare(mutated, source)
        mutated = copy.deepcopy(comparison)
        mutated["unchanged"][0]["fingerprint"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(lab.LabError, "self_compare_identity"):
            lab._self_compare(mutated, source)
        for count in (True, -1, 0, "1"):
            changed = {**source, "item_count": count}
            with self.assertRaisesRegex(lab.LabError, "source_item_count"):
                lab._self_compare(comparison, changed)

    def test_empty_selected_session_audit_still_self_compared(self):
        source = {"schema": "venom-rendered-assessment/v1", "item_count": 0, "items": [],
                  "supplied_session": synthetic_audit("wrong-b-health")}
        value = synthetic_self_comparison(source)
        self.assertEqual(lab._self_compare(value, source)["unchanged"], 0)
        value["supplied_session_comparison"]["status"] = "not_compared"
        with self.assertRaisesRegex(lab.LabError, "self_compare_session"):
            lab._self_compare(value, source)

    def test_strict_json_rejects_duplicates_utf8_constants_and_bounds(self):
        for data in (b'{"a":1,"a":2}', b'{"a":{"b":1,"b":2}}', b'NaN', b'"\xff"'):
            with self.subTest(data=data), self.assertRaises(lab.LabError):
                lab.strict_json(data)
        with self.assertRaisesRegex(lab.LabError, "json_size"):
            lab.strict_json(b"{}", 1)

    def test_grant_literal_keys_preserved_and_rfc_known_answer(self):
        value = lab.Grant("literal-synthetic-code", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "http://127.0.0.1:1234/realms/termivar-owned-code",
                          "http://127.0.0.1:5678/callback", 42)
        rows = dict(line.split("\t", 1) for line in value.tsv().decode().splitlines())
        self.assertEqual(set(rows), {"authorization_code", "code_verifier", "code_challenge", "issuer", "client_id",
                                    "redirect_uri", "scope", "received_unix_seconds"})
        self.assertEqual(rows["code_verifier"], "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        self.assertNotIn(value.code, repr(value))

    def test_form_parser_does_not_run_scripts_or_accept_duplicates(self):
        parser = lab.FormParser(b'<form method="post" action="/callback"><input name="code" value="x&amp;y"></form><script>ignored()</script>')
        self.assertEqual(parser.forms[0]["inputs"], {"code": "x&y"})
        for source in (b'<form><input name="code"><input name="code"></form>',
                       b'<form action="a" action="b"></form>', b'<form><form></form></form>'):
            with self.assertRaises(lab.LabError):
                lab.FormParser(source)

    def test_private_canary_raw_and_public_digest_are_refused(self):
        values = lab.PrivateValues()
        secret = b"synthetic-secret-canary-not-operational"
        values.add(secret)
        for data in (b"prefix " + secret, hashlib.sha256(secret).hexdigest().encode()):
            with self.assertRaises(lab.LabError):
                values.check(data)
        values.check(b"redacted observation only")

    def test_validate_only_never_constructs_or_starts_provider(self):
        with mock.patch.object(lab, "KeycloakLab", side_effect=AssertionError("no provider")), \
             mock.patch.object(lab, "Runner", side_effect=AssertionError("no process")), mock.patch("sys.stdout", new=io.StringIO()) as output:
            self.assertEqual(lab.main(["--validate-only"]), 0)
            self.assertEqual(json.loads(output.getvalue())["execution_class"], "static_only")


class ControllerTests(unittest.TestCase):
    def test_normal_prepare_satisfies_independent_local_logger_compression_constraint(self):
        # Synthetic daemon oracle from public Moby local/config.go, not CI logs:
        # compression defaults true and cannot accompany one retained file.
        owner = self._exercise_docker_prepare_and_cleanup(literal_image_inspection("containerd"),
                                                         enforce_logger_constraint=True)
        self.assertEqual(owner.image_inspection["status"], "validated")

    def test_daemon_lexical_vector_has_literal_whole_words_and_cpu_templates(self):
        owner = "termivar-oauth-0123456789abcdef"
        inspected = [{"Config": {"Labels": {"termivar.oauth.owner": owner}}}]
        guard = lab.PrivateValues()
        body = b"NanoCPUs can not be set, as your kernel does not support CPU CFS scheduler or the cgroup is not mounted"
        result = lab.daemon_start_lexical_signals(b"", b"Error response from daemon: " + body + b"\n",
                    capture_complete=True, inspected=inspected, owner=owner, private=guard)
        self.assertEqual(result["state"], "eligible")
        self.assertEqual(result["templates"], {"cpu_cfs_unavailable": True, "cpu_range_unavailable": False})
        self.assertEqual(result["unknown_token_count"], 0)
        for word in ("nanocpus", "cpu", "cfs", "scheduler", "cgroup", "mounted", "not", "support"):
            self.assertIs(result["presence"][word], True)
        for word in ("tmpfs", "logging", "uid", "network"):
            self.assertIs(result["presence"][word], False)
        body = b"range of CPUs is from 0.01 to 4.00, as there are only 4 CPUs available"
        trailer = b"\nError: failed to start containers: " + owner.encode() + b"-idp\n"
        result = lab.daemon_start_lexical_signals(b"", b"Error response from daemon: " + body + trailer,
                    capture_complete=True, inspected=inspected, owner=owner, private=guard)
        self.assertEqual(result["templates"], {"cpu_cfs_unavailable": False, "cpu_range_unavailable": True})
        self.assertEqual(result["unknown_token_count"], 3)
        self.assertTrue(all(type(value) is bool for value in result["presence"].values()))
        self.assertNotIn("4.00", json.dumps(result))
        self.assertNotIn(owner, json.dumps(result))

    def test_daemon_lexical_vector_refuses_foreign_or_unassured_inputs(self):
        owner = "termivar-oauth-0123456789abcdef"
        inspected = [{"Config": {"Labels": {"termivar.oauth.owner": owner}}}]
        baseline = {"stdout": b"", "stderr": b"Error response from daemon: invalid tmpfs mount\n", "capture_complete": True,
                    "inspected": inspected, "owner": owner, "private": lab.PrivateValues()}
        mutations = (
            {"stdout": b"foreign stdout"}, {"capture_complete": False}, {"private": None},
            {"owner": "termivar-oauth-fedcba9876543210"}, {"inspected": None},
            {"stderr": b"prefix Error response from daemon: invalid tmpfs\n"},
            {"stderr": b"Error response from daemonish: invalid tmpfs\n"},
            {"stderr": baseline["stderr"] + b"foreign unrelated line\n"},
            {"stderr": baseline["stderr"] + b"Error: failed to start containers: other-idp\n"},
            {"stderr": baseline["stderr"] + b"\n"},
            {"stderr": b"Error response from daemon: tmpfs \xff\n"},
            {"stderr": b"Error response from daemon: tmpfs\tvalue\n"},
            {"stderr": b"Error response from daemon: " + b"x" * (128 * 1024)},
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                result = lab.daemon_start_lexical_signals(**{**baseline, **mutation})
                self.assertEqual(result["state"], "not_eligible")
                self.assertNotIn("presence", result)
                self.assertNotIn("unknown_token_count", result)

    def test_daemon_lexical_vector_never_splits_secret_like_atoms_or_known_private_material(self):
        owner = "termivar-oauth-0123456789abcdef"
        inspected = [{"Config": {"Labels": {"termivar.oauth.owner": owner}}}]
        guard = lab.PrivateValues()
        compounds = b'prefix-tmpfs tmpfs-suffix prefix_tmpfs tmpfs_suffix tmpfs123 123tmpfs /tmpfs/file https://tmpfs.invalid mount=private token:tmpfs "tmpfs" [tmpfs]'
        result = lab.daemon_start_lexical_signals(b"", b"Error response from daemon: " + compounds,
                    capture_complete=True, inspected=inspected, owner=owner, private=guard)
        self.assertEqual(result["state"], "eligible")
        self.assertEqual(result["unknown_token_count"], 12)
        self.assertFalse(any(result["presence"].values()))
        self.assertNotIn("prefix-tmpfs", json.dumps(result))
        self.assertNotIn("https://", json.dumps(result))
        secret = b"synthetic-private-mount-value-never-export"
        guard.add(secret)
        for private_bytes in (secret, hashlib.sha256(secret).hexdigest().encode()):
            refused = lab.daemon_start_lexical_signals(b"", b"Error response from daemon: invalid tmpfs " + private_bytes,
                        capture_complete=True, inspected=inspected, owner=owner, private=guard)
            self.assertEqual(refused, {"state": "not_eligible", "reason": "private_registry_check_failed"})
            self.assertNotIn(private_bytes, json.dumps(refused).encode())
        with mock.patch.object(guard, "check", side_effect=OSError("synthetic-private-guard-error")):
            refused = lab.daemon_start_lexical_signals(b"", b"Error response from daemon: invalid tmpfs",
                        capture_complete=True, inspected=inspected, owner=owner, private=guard)
        self.assertEqual(refused["reason"], "private_registry_check_failed")
        self.assertNotIn("synthetic-private", json.dumps(refused))

    def test_daemon_cpu_template_prefix_suffix_or_value_mismatch_never_match(self):
        owner = "termivar-oauth-0123456789abcdef"
        inspected = [{"Config": {"Labels": {"termivar.oauth.owner": owner}}}]
        body = b"NanoCPUs can not be set, as your kernel does not support CPU CFS scheduler or the cgroup is not mounted"
        for message in (b"private-" + body, body + b"-private", b"range of CPUs is from 0.01 to 4.00, as there are only 3 CPUs available"):
            result = lab.daemon_start_lexical_signals(b"", b"Error response from daemon: " + message,
                        capture_complete=True, inspected=inspected, owner=owner, private=lab.PrivateValues())
            self.assertEqual(result["templates"], {"cpu_cfs_unavailable": False, "cpu_range_unavailable": False})

    def test_normal_prepare_records_daemon_vector_without_adding_work_or_hiding_failure(self):
        _, failure = self._exercise_docker_prepare_and_cleanup(
            literal_image_inspection("containerd"), startup_exit=1, startup_after_inspection=True,
            inspection_state={"Status": "created", "Running": False, "ExitCode": 0, "OOMKilled": False, "Error": ""},
            startup_output=b"Error response from daemon: invalid tmpfs mount reading size\n")
        self.assertEqual(failure.code, "idp_startup_failure")
        result = failure.diagnostic["docker_daemon_lexical"]
        self.assertEqual(result["state"], "eligible")
        self.assertEqual(result["unknown_token_count"], 0)
        for word in ("invalid", "tmpfs", "mount", "reading", "size"):
            self.assertIs(result["presence"][word], True)
        self.assertIs(result["presence"]["cpu"], False)
        self.assertEqual(result["interpretation"], "lexical_signals_not_established_cause")

    def test_last_owned_state_is_typed_stale_and_never_exports_inspection_secrets(self):
        owner = "termivar-oauth-0123456789abcdef"
        sentinel = "synthetic-private-state-error-and-environment-value"
        row = {"Config": {"Labels": {"termivar.oauth.owner": owner}, "Env": [sentinel]},
               "State": {"Status": "running", "Running": True, "ExitCode": 0, "OOMKilled": False,
                         "Error": "https://invalid.example/" + sentinel}, "Name": sentinel}
        result = lab.last_owned_container_state([row], owner)
        self.assertEqual(result["observation_scope"], "last_inspected_before_client_exit_not_atomic_final_state")
        self.assertEqual(result["ownership"], "validated")
        self.assertEqual(result["fields"], {
            "Status": {"state": "known", "value": "running"}, "Running": {"state": "known", "value": True},
            "ExitCode": {"state": "known", "value": 0}, "OOMKilled": {"state": "known", "value": False},
            "Error": {"field_present": True, "type": "string", "nonempty": True},
        })
        for payload in (json.dumps(result), json.dumps(lab.last_owned_container_state([row], "termivar-oauth-fedcba9876543210"))):
            self.assertNotIn(sentinel, payload)
            self.assertNotIn("https://", payload)
            self.assertNotIn(owner, payload)
            self.assertNotIn(hashlib.sha256(sentinel.encode()).hexdigest(), payload)
        for value in (None, {}, [], [None], [row, row]):
            self.assertEqual(lab.last_owned_container_state(value, owner)["ownership"], "not_established")
        for path, invalid in (("Status", "synthetic-private-unknown-status"), ("Running", 1), ("ExitCode", True),
                              ("ExitCode", -1), ("ExitCode", 10 ** 100), ("OOMKilled", "true"), ("Error", {"private": sentinel})):
            mutation = copy.deepcopy(row)
            mutation["State"][path] = invalid
            reduced = lab.last_owned_container_state([mutation], owner)
            field = reduced["fields"][path]
            self.assertEqual(field["state"] if path != "Error" else field["type"]["state"], "unknown")
            self.assertNotIn(sentinel, json.dumps(reduced))
        missing = copy.deepcopy(row)
        missing["State"] = {}
        self.assertEqual(lab.last_owned_container_state([missing], owner)["fields"]["ExitCode"], {"state": "missing"})
        del missing["Config"]["Labels"]["termivar.oauth.owner"]
        self.assertEqual(lab.last_owned_container_state([missing], owner)["ownership"], "not_established")

    def test_reviewed_source_layer_prefixes_emit_only_closed_marker_names(self):
        cases = (
            (b"Error response from daemon: synthetic details", "docker_daemon_error_prefix"),
            (b"Error attaching: synthetic details", "docker_attach_error_prefix"),
            (b"OCI runtime create failed: synthetic details", "oci_runtime_error_prefix"),
            (b"owned-bootstrap: line 3: synthetic details", "owned_bootstrap_shell_error_prefix"),
            (b"owned-bootstrap: -c: line 3: synthetic details", "owned_bootstrap_shell_error_prefix"),
            (b"Error: Could not create the Java Virtual Machine.", "jvm_launcher_error_prefix"),
            (b"ERROR: Failed to run 'start-dev' command.", "keycloak_startup_error_prefix"),
            (b"ERROR: Failed to run 'import' command.", "keycloak_import_error_prefix"),
        )
        sentinel = b"synthetic-provider-private-prefix-value"
        for message, expected in cases:
            with self.subTest(expected=expected):
                child = mock.Mock()
                child.finish.return_value = lab.Result(b"", message + b" " + sentinel, 1, 0)
                result = lab.startup_failure_diagnostic(child, 1)
                self.assertEqual(result["source_layer_markers"], [expected])
                self.assertEqual(result["marker_interpretation"], "closed_text_signals_not_established_cause")
                self.assertEqual(result["bootstrap_subphase"], "unknown")
                self.assertNotIn(sentinel, json.dumps(result).encode())
                self.assertNotIn(hashlib.sha256(message).hexdigest().encode(), json.dumps(result).encode())
        for message in (b"documentation mentions Error response from daemon: in a sentence", b"not-owned-bootstrap: line 3: no marker", b"ERROR: Failed to run 'unreviewed' command."):
            child = mock.Mock()
            child.finish.return_value = lab.Result(message, b"", 1, 0)
            self.assertEqual(lab.startup_failure_diagnostic(child, 1)["source_layer_markers"], ["unknown"])
        for message, expected in ((b"No space left on device", "storage_exhaustion_marker"),
                                  (b"the input device is not a TTY", "stdin_attach_template_marker")):
            child = mock.Mock()
            child.finish.return_value = lab.Result(b"", message, 1, 0)
            self.assertEqual(lab.startup_failure_diagnostic(child, 1)["failure_classes"], [expected])

    def test_finished_exit_and_overflow_preserve_poll_history_without_guessing(self):
        child = mock.Mock()
        child.finish.return_value = lab.Result(b"", b"", 127, 0)
        result = lab.startup_failure_diagnostic(child, None, overflow=True)
        self.assertIsNone(result["attached_child_exit_code"])
        self.assertEqual(result["finished_child_exit_code"], 127)
        self.assertEqual(result["exit_class"], "unknown")
        self.assertIs(result["overflow_flag"], True)
        result = lab.startup_failure_diagnostic(child, 1, overflow=False)
        self.assertEqual(result["attached_child_exit_code"], 1)
        self.assertEqual(result["finished_child_exit_code"], 127)
        child.finish.return_value = lab.Result(b"", b"", True, 0)
        self.assertIsNone(lab.startup_failure_diagnostic(child, None, overflow="true")["finished_child_exit_code"])
        self.assertIsNone(lab.startup_failure_diagnostic(child, None, overflow="true")["overflow_flag"])

    def test_normal_prepare_reuses_owned_last_inspection_without_another_request(self):
        sentinel = "synthetic-private-state-error-must-not-export"
        _, failure = self._exercise_docker_prepare_and_cleanup(
            literal_image_inspection("containerd"), startup_exit=1, startup_after_inspection=True,
            inspection_state={"Status": "running", "Running": True, "ExitCode": 0, "OOMKilled": False, "Error": sentinel},
            startup_output=b"owned-bootstrap: line 3: " + sentinel.encode())
        diagnostic = failure.diagnostic
        self.assertEqual(failure.code, "idp_startup_failure")
        self.assertEqual(diagnostic["attached_child_exit_code"], 1)
        self.assertEqual(diagnostic["finished_child_exit_code"], 1)
        self.assertIs(diagnostic["overflow_flag"], False)
        self.assertEqual(diagnostic["last_owned_container_inspection"]["fields"]["ExitCode"], {"state": "known", "value": 0})
        self.assertEqual(diagnostic["last_owned_container_inspection"]["ownership"], "validated")
        self.assertEqual(diagnostic["source_layer_markers"], ["owned_bootstrap_shell_error_prefix"])
        self.assertNotIn(sentinel, json.dumps(diagnostic))
        with mock.patch.object(lab, "last_owned_container_state", side_effect=OSError(sentinel)):
            _, failed_diagnostic = self._exercise_docker_prepare_and_cleanup(literal_image_inspection(), startup_exit=1)
        self.assertEqual(failed_diagnostic.code, "idp_startup_failure")
        self.assertIn("last_inspection_unavailable", failed_diagnostic.diagnostic["diagnostic_errors"])
        self.assertNotIn(sentinel, json.dumps(failed_diagnostic.diagnostic))

    def test_startup_diagnostics_use_only_closed_literal_markers_and_actual_exit_classes(self):
        cases = (
            (b"/bin/bash: command: Permission denied\n", 126, "permission_denied_marker"),
            (b"/tmp/original.so: failed to map segment from shared object\n", 126, "temporary_native_mapping_marker"),
            (b"cannot create file: Read-only file system\n", 1, "read_only_filesystem_marker"),
            (b"Unrecognized VM option 'original-test'\n", 1, "java_options_rejected_marker"),
            (b"Unknown option: '--original-test'\n", 2, "unsupported_cli_marker"),
            (b"Failed to import realm\n", 1, "realm_schema_import_marker"),
            (b"java.lang.OutOfMemoryError: original synthetic test\n", 137, "out_of_memory_marker"),
        )
        sentinel = b"synthetic-provider-private-value-must-never-export"
        private = lab.PrivateValues()
        private.add(sentinel)
        for message, status, expected in cases:
            with self.subTest(expected=expected):
                child = mock.Mock()
                child.finish.return_value = lab.Result(b"", sentinel + b"\n" + message, status, 0)
                result = lab.startup_failure_diagnostic(child, status, private)
                self.assertEqual(result["failure_classes"], [expected])
                self.assertEqual(result["attached_child_exit_code"], status)
                self.assertEqual(result["exit_class"], "exit_" + str(status) if status in (126, 127, 137) else "other_exit")
                self.assertEqual(result["bootstrap_subphase"], "unknown")
                self.assertEqual(result["capture_state"], "complete")
                child.finish.assert_called_once_with(2)
                payload = json.dumps(result).encode()
                self.assertNotIn(sentinel, payload)
                self.assertNotIn(hashlib.sha256(sentinel).hexdigest().encode(), payload)
                self.assertNotIn(hashlib.sha256(message).hexdigest().encode(), payload)

    def test_unknown_and_prefix_limited_startup_output_never_becomes_a_cause(self):
        for message in (b"", b"Permission denial is a synthetic near miss", b"https://invalid.example/private?token=synthetic-secret", b"x" * (128 * 1024) + b"Permission denied"):
            with self.subTest(bytes=len(message)):
                child = mock.Mock()
                child.finish.return_value = lab.Result(message, b"", 137, 0)
                result = lab.startup_failure_diagnostic(child, 137)
                self.assertEqual(result["failure_classes"], ["unknown"])
                self.assertEqual(result["exit_class"], "exit_137")
                self.assertEqual(result["classification_bytes"], min(len(message), 128 * 1024))
                self.assertEqual(result["stdout_captured_bytes"], len(message))
                self.assertNotIn(b"https://", json.dumps(result).encode())
                self.assertNotIn(hashlib.sha256(message).hexdigest().encode(), json.dumps(result).encode())

    def test_startup_finish_buffer_and_privacy_failures_remain_reduced_unknowns(self):
        sentinel = "synthetic-private-exception-should-not-export"
        child = mock.Mock(buffers=[bytearray(b"Permission denied\n"), bytearray()])
        child.finish.side_effect = lab.LabError(sentinel)
        result = lab.startup_failure_diagnostic(child, 127)
        self.assertEqual(result["capture_state"], "partial")
        self.assertEqual(result["failure_classes"], ["permission_denied_marker"])
        self.assertEqual(result["diagnostic_errors"], ["finish_or_output_unavailable"])

        class Unreadable:
            def finish(self, timeout):
                raise OSError(sentinel)

            @property
            def buffers(self):
                raise OSError(sentinel)

        unknown = lab.startup_failure_diagnostic(Unreadable(), 127)
        self.assertEqual(unknown["failure_classes"], ["unknown"])
        self.assertEqual(unknown["attached_child_exit_code"], 127)
        self.assertEqual(unknown["diagnostic_errors"], ["finish_or_output_unavailable", "buffer_read_unavailable"])
        guard = mock.Mock()
        guard.check.side_effect = RuntimeError(sentinel)
        refused = lab.startup_failure_diagnostic(child, 127, guard)
        self.assertEqual(refused["failure_classes"], ["unknown"])
        self.assertEqual(refused["diagnostic_errors"], ["reduced_diagnostic_privacy_check_failed"])
        self.assertNotIn(sentinel, json.dumps([result, unknown, refused]))
        for status in (None, True, "127", 10 ** 100, -999):
            self.assertIsNone(lab.startup_failure_diagnostic(Unreadable(), status)["attached_child_exit_code"])

    def test_diagnostic_exception_cannot_replace_normal_prepare_startup_failure(self):
        with mock.patch.object(lab, "startup_failure_diagnostic", side_effect=RuntimeError("synthetic-private-diagnostic-exception")):
            _, failure = self._exercise_docker_prepare_and_cleanup(literal_image_inspection("containerd"), startup_exit=126)
        self.assertEqual(failure.code, "idp_startup_failure")
        self.assertEqual(failure.diagnostic["diagnostic_errors"], ["startup_diagnostic_unavailable"])
        self.assertNotIn("synthetic-private", json.dumps(failure.diagnostic))

    def test_startup_failure_survives_evidence_write_and_cleanup_errors(self):
        child = mock.Mock(buffers=[bytearray(), bytearray()])
        child.finish.side_effect = OSError("synthetic-private-provider-error")
        diagnostic = lab.startup_failure_diagnostic(child, 127)
        original = lab.private_write

        def failed_write(path, data):
            if path.name == "oauth-code-lab-acceptance.json":
                raise OSError("synthetic-private-evidence-error")
            return original(path, data)

        with mock.patch.object(FakeLab, "prepare", side_effect=lab.LabError("idp_startup_failure", diagnostic)), \
             mock.patch.object(FakeLab, "cleanup", side_effect=OSError("synthetic-private-cleanup-error")), \
             mock.patch.object(lab, "private_write", side_effect=failed_write), \
             self.assertRaisesRegex(lab.LabError, "^idp_startup_failure$") as raised:
            AcceptanceTests.execute_fake(self)
        self.assertEqual(raised.exception.diagnostic["attached_child_exit_code"], 127)
        self.assertNotIn("synthetic-private", json.dumps(raised.exception.diagnostic))

    def test_actual_docker_prepare_and_cleanup_call_paths_with_bounded_fakes(self):
        owner = self._exercise_docker_prepare_and_cleanup(literal_image_inspection())
        self.assertEqual(owner.image_inspection["status"], "validated")
        self.assertEqual(owner.image_inspection["profile"], "legacy_config_id")
        self.assertIsNone(owner.image_inspection["manifest_descriptor"])

    def test_containerd_manifest_image_id_reaches_same_prepare_and_cleanup_path(self):
        owner = self._exercise_docker_prepare_and_cleanup(literal_image_inspection("containerd"))
        self.assertEqual(owner.image_inspection["status"], "validated")
        self.assertEqual(owner.image_inspection["profile"], "containerd_manifest_descriptor")
        self.assertEqual(owner.image_inspection["manifest_descriptor"], {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc",
            "size": 1056,
        })

    def test_exited_attached_child_retains_startup_exit_before_owned_cleanup(self):
        _, failure = self._exercise_docker_prepare_and_cleanup(
            literal_image_inspection("containerd"), startup_exit=127,
            startup_output=b"/bin/bash: /opt/keycloak/bin/kc.sh: No such file or directory\n")
        self.assertEqual(failure.code, "idp_startup_failure")
        self.assertEqual(failure.diagnostic["attached_child_exit_code"], 127)
        self.assertEqual(failure.diagnostic["exit_class"], "exit_127")
        self.assertEqual(failure.diagnostic["phase"], "attached_provider_before_readiness")

    def test_two_literal_image_profiles_keep_same_pins_platform_and_nonroot_users(self):
        for fixture, expected in (("legacy", "legacy_config_id"), ("containerd", "containerd_manifest_descriptor")):
            for user in ("1000", "1000:0"):
                with self.subTest(fixture=fixture, user=user):
                    document = literal_image_inspection(fixture)
                    document[0]["Config"]["User"] = user
                    result = lab.validate_image_inspection(document)
                    self.assertEqual(result["profile"], expected)
                    self.assertEqual(result["platform"], "linux/amd64")
                    self.assertEqual(result["user"], user)
                    self.assertEqual(result["expected_config_digest"], "sha256:b55801be6ce15109868bd056dc18d62d47106bfaad7ffbd1a5d804192ec98257")

    def test_image_inspection_rejects_missing_wrong_or_contradictory_identity_fields(self):
        cases = [("root-" + str(index), value) for index, value in enumerate((None, {}, True, 0, [], [None], [{}], literal_image_inspection() * 2))]
        for fixture in ("legacy", "containerd"):
            for key in ("Id", "RepoDigests", "Architecture", "Os", "Config"):
                document = literal_image_inspection(fixture)
                del document[0][key]
                cases.append((fixture + "-missing-" + key, document))
            for key, values in {
                "Id": (None, False, 0, {}, [], "sha256:" + "0" * 64, "sha256:" + "A" * 64),
                "RepoDigests": (None, False, {}, "pinned", [], [False], ["unreviewed"],
                                literal_image_inspection()[0]["RepoDigests"] * 2,
                                ["quay.io/other/keycloak@sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc"]),
                "Architecture": (None, False, 1, [], "arm64", "AMD64"),
                "Os": (None, False, {}, "windows", "Linux"),
                "Config": (None, False, [], "1000", {}, {"User": False}, {"User": 1000}, {"User": "0"}, {"User": "root"}, {"User": "1000:1"}),
            }.items():
                for index, value in enumerate(values):
                    document = literal_image_inspection(fixture)
                    document[0][key] = value
                    cases.append((fixture + "-wrong-" + key + "-" + str(index), document))
        for key, values in {
            "mediaType": (None, False, {}, "application/vnd.oci.image.index.v1+json"),
            "digest": (None, True, [], "sha256:b55801be6ce15109868bd056dc18d62d47106bfaad7ffbd1a5d804192ec98257"),
            "size": (None, True, "1056", 1056.0, -1, 1055, 1057, 10 ** 100),
        }.items():
            missing = literal_image_inspection("containerd")
            del missing[0]["Descriptor"][key]
            cases.append(("descriptor-missing-" + key, missing))
            for index, value in enumerate(values):
                document = literal_image_inspection("containerd")
                document[0]["Descriptor"][key] = value
                cases.append(("descriptor-wrong-" + key + "-" + str(index), document))
        for value in (None, False, [], "manifest", {}):
            document = literal_image_inspection("containerd")
            document[0]["Descriptor"] = value
            cases.append(("descriptor-container-type-" + type(value).__name__, document))
        missing = literal_image_inspection("containerd")
        del missing[0]["Descriptor"]
        cases.append(("containerd-missing-descriptor", missing))
        for value in (None, literal_image_inspection("containerd")[0]["Descriptor"]):
            document = literal_image_inspection()
            document[0]["Descriptor"] = value
            cases.append(("legacy-unreviewed-descriptor-" + type(value).__name__, document))
        extra = literal_image_inspection("containerd")
        extra[0]["Descriptor"]["platform"] = {"os": "linux", "architecture": "arm64"}
        cases.append(("unreviewed-descriptor-platform", extra))
        for name, document in cases:
            with self.subTest(name=name), self.assertRaises(lab.LabError) as raised:
                lab.validate_image_inspection(document)
            self.assertIn(raised.exception.code, ("idp_image_config_identity", "idp_image_user"))
            self.assertLess(len(json.dumps(raised.exception.diagnostic).encode()), 4096)
            self.assertIn("actual", raised.exception.diagnostic)
            self.assertIn("expected", raised.exception.diagnostic)

    def test_image_failure_diagnostic_is_reduced_and_survives_execute_cleanup(self):
        document = literal_image_inspection("containerd")
        document[0]["Descriptor"]["size"] = True
        document[0]["Config"]["Env"] = ["UNRELATED_PRIVATE=synthetic-inspect-secret-must-not-export"]
        with tempfile.TemporaryDirectory(prefix="test-owned-image-", dir=ROOT) as directory:
            output = Path(directory) / "evidence"
            with mock.patch.object(FakeLab, "prepare", side_effect=lambda: lab.validate_image_inspection(document)), \
                 self.assertRaisesRegex(lab.LabError, "idp_image_config_identity"):
                AcceptanceTests.execute_fake(self, output=output)
            payload = (output / "oauth-code-lab-acceptance.json").read_bytes()
            evidence = json.loads(payload)
            self.assertEqual(evidence["failure"]["code"], "idp_image_config_identity")
            self.assertIs(evidence["failure"]["diagnostic"]["actual"]["descriptor_size"], True)
            self.assertEqual(evidence["failure"]["diagnostic"]["actual"]["profile"], "containerd_manifest_descriptor")
            self.assertEqual(evidence["scenarios"], {})
            self.assertEqual(evidence["offline"], {"status": "not_run"})
            self.assertEqual(evidence["cleanup"]["idp"]["status"], "complete")
            self.assertTrue(evidence["cleanup"]["private_work_removed"])
            self.assertNotIn(b"synthetic-inspect-secret", payload)
            self.assertNotIn(b"Config.Env", payload)

    def test_validated_image_profile_is_retained_by_complete_execute_evidence(self):
        def prepare(owner):
            owner.image_inspection = lab.validate_image_inspection(literal_image_inspection("containerd"))
            owner.prepared = True

        with mock.patch.object(FakeLab, "prepare", prepare):
            document, _, output = AcceptanceTests.execute_fake(self)
        self.assertEqual(document["status"], "passed")
        self.assertEqual(document["image_inspection"]["profile"], "containerd_manifest_descriptor")
        self.assertEqual(document["image_inspection"]["manifest_descriptor"]["size"], 1056)
        saved = json.loads((output / "oauth-code-lab-acceptance.json").read_bytes())
        self.assertEqual(saved["image_inspection"], document["image_inspection"])

    def test_prepare_rejects_oversized_inspection_before_creating_any_owned_resource(self):
        labels = []
        document = literal_image_inspection()
        document[0]["Config"]["Env"] = ["x" * (128 * 1024)]

        class Runner:
            def run(self, args, *, label, **kwargs):
                labels.append(label)
                value = b"default\n" if label == "docker-local-context" else (
                    json.dumps(document).encode() if label == "inspect-idp-image" else b"pulled")
                return lab.Result(value, b"", 0, 0.01)

        owner = lab.KeycloakLab(Runner(), mock.Mock(origin="http://127.0.0.1:1234"), {})
        with mock.patch.object(lab.sys, "platform", "linux"), \
             mock.patch.dict(lab.os.environ, {"DOCKER_HOST": ""}), \
             self.assertRaisesRegex(lab.LabError, "json_size"):
            owner.prepare()
        self.assertEqual(labels, ["docker-local-context", "prepare-pinned-idp", "inspect-idp-image"])
        self.assertFalse(owner.network_created)
        self.assertFalse(owner.container_created)
        self.assertIsNone(owner.image_inspection)

    def _exercise_docker_prepare_and_cleanup(self, image_document, startup_exit=None, startup_output=b"",
                                            startup_after_inspection=False, inspection_state=None,
                                            enforce_logger_constraint=False):
        private = lab.PrivateValues()
        resource_secret = "synthetic-resource-secret-never-in-argv"
        controller_secret = "synthetic-controller-secret-never-in-argv"
        realm = lab.realm_document(resource_secret, controller_secret, "http://127.0.0.1:5678/callback")
        relay = mock.Mock(origin="http://127.0.0.1:1234", errors=[], trace=[])
        calls = []
        attachments = []
        owner = None
        created = []
        daemon_logging_conflict = False

        class Process:
            def __init__(self):
                self.polls = 0

            def poll(self):
                self.polls += 1
                if daemon_logging_conflict:
                    return 1
                if startup_after_inspection and self.polls == 1:
                    return None
                return startup_exit

        class Attachment:
            def __init__(self, args, payload):
                nonlocal daemon_logging_conflict
                attachments.append((args, payload))
                self.process = Process()
                self.overflow = mock.Mock(is_set=lambda: False)
                if enforce_logger_constraint:
                    values = created[0]
                    driver = values[values.index("--log-driver") + 1]
                    options = dict(values[index + 1].split("=", 1) for index, value in enumerate(values) if value == "--log-opt")
                    daemon_logging_conflict = (driver == "local" and int(options.get("max-file", "5")) <= 1
                                               and options.get("compress", "true") == "true")

            def finish(self, timeout):
                if daemon_logging_conflict:
                    return lab.Result(b"", b"Error response from daemon: synthetic local logger constraint refusal\n", 1, 0)
                return lab.Result(b"", startup_output, startup_exit or 0, 0)

        class Runner:
            def __init__(self):
                self.private = private

            def run(self, args, *, label, **kwargs):
                calls.append((args, label))
                if label == "create-owned-idp":
                    created.append(args)
                if label == "docker-local-context":
                    value = b"default\n"
                elif label == "inspect-idp-image":
                    value = json.dumps(image_document).encode()
                elif label in ("inspect-owned-idp", "cleanup-owned-identity"):
                    value = json.dumps([{
                        "Config": {"User": "1000:0", "Labels": {"termivar.oauth.owner": owner.owner}},
                        "HostConfig": {"Privileged": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
                                       "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
                                       "NetworkMode": owner.network, "Binds": None, "Memory": 1073741824, "PidsLimit": 256,
                                       "Tmpfs": {"/tmp": "size=67108864,uid=1000", "/opt/keycloak/data": "size=201326592,uid=1000"},
                                       "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]}},
                         "Mounts": [], "NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "2345"}]}},
                         "State": inspection_state,
                    }]).encode()
                elif label in ("inspect-owned-network", "cleanup-owned-network-identity"):
                    value = json.dumps([{"Internal": True, "Driver": "bridge", "Labels": {"termivar.oauth.owner": owner.owner}}]).encode()
                else:
                    value = b"owned-success"
                return lab.Result(value, b"", 0, 0.01)

        owner = lab.KeycloakLab(Runner(), relay, realm)
        metadata = {"issuer": "http://127.0.0.1:1234/realms/termivar-owned-code",
                    "token_endpoint": "http://127.0.0.1:1234/realms/termivar-owned-code/protocol/openid-connect/token"}
        with mock.patch.object(lab.sys, "platform", "linux"), mock.patch.dict(lab.os.environ, {"DOCKER_HOST": ""}), \
             mock.patch.object(lab, "CapturedChild", Attachment), \
              mock.patch.object(lab, "request_bytes", return_value=(503 if startup_after_inspection else 200, [], json.dumps(metadata).encode())) as requests, \
              mock.patch.object(lab.time, "sleep"):
            if startup_exit is None:
                owner.prepare()
            else:
                with self.assertRaises(lab.LabError) as raised:
                    owner.prepare()
            outcome = owner.cleanup()
        self.assertEqual(outcome["status"], "complete")
        labels = [label for _, label in calls]
        if startup_exit is not None:
            self.assertEqual(labels.count("inspect-owned-idp"), int(startup_after_inspection))
            self.assertEqual(requests.call_count, int(startup_after_inspection))
            self.assertNotIn("inspect-owned-network", labels)
            self.assertEqual(labels[-5:], ["cleanup-owned-identity", "stop-owned-idp", "remove-owned-idp",
                                          "cleanup-owned-network-identity", "remove-owned-network"])
            return owner, raised.exception
        self.assertEqual(labels, ["docker-local-context", "prepare-pinned-idp", "inspect-idp-image", "create-owned-network",
                                  "create-owned-idp", "inspect-owned-idp", "inspect-owned-network", "cleanup-owned-identity",
                                  "stop-owned-idp", "remove-owned-idp", "cleanup-owned-network-identity", "remove-owned-network"])
        args = next(args for args, label in calls if label == "create-owned-idp")
        self.assertEqual(args[args.index("--log-driver") + 1], "local")
        options = [args[index + 1] for index, value in enumerate(args) if value == "--log-opt"]
        self.assertEqual(options, ["max-size=1m", "max-file=1", "compress=false"])
        for required in ("--pull=never", "--interactive", "1000:0", "ALL", "no-new-privileges=true", "127.0.0.1::8080"):
            self.assertIn(required, args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--volume", args)
        self.assertNotIn(resource_secret, " ".join(args))
        self.assertNotIn(controller_secret, " ".join(args))
        self.assertEqual(json.loads(attachments[0][1]), realm)
        self.assertEqual(attachments[0][0], ["docker", "start", "--attach", "--interactive", owner.container])
        return owner

    def test_actual_obtain_code_call_path_uses_query_free_admin_sso_and_form_post(self):
        observed = []
        private = lab.PrivateValues()
        token = "synthetic-controller-access-token-" + "x" * 32

        # A real stdlib CookieJar must apply outgoing Secure-cookie rules.
        # This original cookie is synthetic, not captured provider output.
        cookie = lab.http.cookiejar.Cookie(
            version=0, name="KEYCLOAK_IDENTITY", value="synthetic-private-sso-cookie-" + "c" * 32,
            port=None, port_specified=False, domain="127.0.0.1", domain_specified=False,
            domain_initial_dot=False, path="/realms/termivar-owned-code/", path_specified=True,
            secure=True, expires=None, discard=True, comment=None, comment_url=None,
            rest={"HttpOnly": None}, rfc2109=False,
        )

        class Response:
            status = 200
            headers = {}

            def __init__(self, body):
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self, maximum):
                return self.body[:maximum]

        class Opener:
            def __init__(self, jar):
                self.jar = jar

            def open(self, request, timeout):
                self.jar.add_cookie_header(request)
                values = dict(urllib.parse.parse_qsl(request.data.decode()))
                observed.append((request.full_url, values, dict(request.header_items())))
                if len(observed) == 1:
                    return Response(json.dumps({"access_token": token}).encode())
                if len(observed) == 2:
                    self.jar.set_cookie(cookie)
                    return Response(b'{"sameRealm":false,"redirect":"http://127.0.0.1:1234/account"}')
                self_outer.assertTrue(request.get_header("Cookie") == "KEYCLOAK_IDENTITY=" + cookie.value,
                                      "controller did not return the exact synthetic SSO cookie")
                self_outer.assertTrue(next(iter(self.jar)).secure)
                return Response(('<form method="post" action="http://127.0.0.1:5678/callback">'
                                 '<input name="state" value="' + values["state"] + '">'
                                 '<input name="code" value="synthetic-actual-provider-code"></form>').encode())

        self_outer = self
        def build_opener(*handlers):
            jar = next(handler.cookiejar for handler in handlers
                       if isinstance(handler, lab.urllib.request.HTTPCookieProcessor))
            return Opener(jar)

        with mock.patch.object(lab.urllib.request, "build_opener", side_effect=build_opener):
            grant = lab.obtain_code("http://127.0.0.1:1234", "http://127.0.0.1:5678/callback", "canary-a",
                                    "synthetic-controller-secret", private)
        self.assertEqual(grant.code, "synthetic-actual-provider-code")
        self.assertEqual(len(observed), 3)
        self.assertTrue(all("?" not in url and "#" not in url for url, _, _ in observed))
        self.assertEqual(observed[0][1]["grant_type"], "client_credentials")
        self.assertEqual(observed[1][0], "http://127.0.0.1:1234/admin/realms/termivar-owned-code/users/00000000-0000-4000-8000-000000000001/impersonation")
        self.assertEqual(observed[2][1]["response_mode"], "form_post")
        self.assertEqual(observed[2][1]["code_challenge_method"], "S256")
        self.assertEqual(observed[2][1]["prompt"], "none")
        self.assertFalse(any(values.get("grant_type") == "password" for _, values, _ in observed))

    def test_real_cookie_jar_loopback_exception_is_explicit_and_exactly_scoped(self):
        origin = "http://127.0.0.1:1234"
        auth = origin + "/realms/termivar-owned-code/protocol/openid-connect/auth"
        def cookie(**updates):
            fields = dict(version=0, name="KEYCLOAK_IDENTITY", value="synthetic-controller-cookie",
                          port=None, port_specified=False, domain="127.0.0.1", domain_specified=False,
                          domain_initial_dot=False, path="/realms/termivar-owned-code/", path_specified=True,
                          secure=True, expires=None, discard=True, comment=None, comment_url=None,
                          rest={"HttpOnly": None}, rfc2109=False)
            fields.update(updates)
            return lab.http.cookiejar.Cookie(**fields)
        def outgoing(policy, url, value=None):
            jar = lab.http.cookiejar.CookieJar(policy=policy)
            original_cookie = cookie() if value is None else value
            jar.set_cookie(original_cookie)
            request = lab.urllib.request.Request(url, data=b"original=fixture", method="POST")
            jar.add_cookie_header(request)
            self.assertTrue(original_cookie.secure, "fixture must not strip Secure")
            return request.get_header("Cookie")
        self.assertIsNone(outgoing(lab.http.cookiejar.DefaultCookiePolicy(), auth))
        self.assertIsNone(outgoing(lab.ControllerCookiePolicy(origin), auth))
        selected = lab.ControllerCookiePolicy(origin, owned_loopback_http=True)
        self.assertTrue(outgoing(selected, auth) == "KEYCLOAK_IDENTITY=synthetic-controller-cookie")
        for refused in (auth.replace(":1234", ":1235"), auth.replace("127.0.0.1", "localhost"),
                        auth.replace("127.0.0.1", "127.0.0.2"), auth.replace("http:", "https:"),
                        origin + "/realms/termivar-owned-code/protocol/openid-connect/token",
                        origin + "/admin/realms/termivar-owned-code/", auth + "/", auth + "?x=1",
                        auth + "#fragment"):
            with self.subTest(scope="refused_owned_cookie_destination"):
                self.assertIsNone(outgoing(selected, refused))
        self.assertIsNone(outgoing(selected, auth, cookie(expires=1)))
        self.assertIsNone(outgoing(selected, auth, cookie(path="/different/")))
        self.assertIsNone(outgoing(selected, auth, cookie(domain="other.invalid")))
        self.assertIsNone(outgoing(selected, auth, cookie(name="UNRELATED_COOKIE")))
        for bad_origin in ("http://localhost:1234", "http://127.0.0.2:1234", "https://127.0.0.1:1234",
                           "http://127.0.0.1:1234/other/", "http://127.0.0.1:1234/?secret=1"):
            with self.subTest(scope="refused_controller_origin"), self.assertRaises(lab.LabError):
                lab.ControllerCookiePolicy(bad_origin, owned_loopback_http=True)

    def test_isolation_mutations_fail_closed(self):
        owner, network = "termivar-oauth-synthetic", "termivar-oauth-synthetic-net"
        container = {"Config": {"User": "1000:0", "Labels": {"termivar.oauth.owner": owner}},
                     "HostConfig": {"Privileged": False, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
                                    "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
                                    "NetworkMode": network, "Binds": None, "Memory": 1073741824, "PidsLimit": 256,
                                    "Tmpfs": {"/tmp": "size=67108864,uid=1000", "/opt/keycloak/data": "size=201326592,uid=1000"},
                                    "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]}}, "Mounts": []}
        net = {"Internal": True, "Driver": "bridge", "Labels": {"termivar.oauth.owner": owner}}
        lab.validate_isolation(container, net, owner, network)
        for section, key, value in (("HostConfig", "Privileged", True), ("HostConfig", "CapDrop", []),
                                     ("HostConfig", "Binds", ["/host:/container"]), ("Config", "User", "0"),
                                     ("HostConfig", "Tmpfs", {}), ("HostConfig", "NetworkMode", "host")):
            changed = copy.deepcopy(container)
            changed[section][key] = value
            with self.subTest(key=key), self.assertRaises(lab.LabError):
                lab.validate_isolation(changed, net, owner, network)
        changed = copy.deepcopy(container)
        changed["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostIp"] = "0.0.0.0"
        with self.assertRaises(lab.LabError):
            lab.validate_isolation(changed, net, owner, network)
        with self.assertRaises(lab.LabError):
            lab.validate_isolation(container, {**net, "Internal": False}, owner, network)
        logging = {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}}
        invalid_logs = [None, False, [], "local", {}, {"Type": "local"}, {"Config": logging["Config"]},
                        {"Type": "json-file", "Config": logging["Config"]},
                        {"Type": False, "Config": logging["Config"]},
                        {"Type": "local", "Config": None}, {"Type": "local", "Config": []}]
        for key, values in (("compress", (None, False, True, "true", "False", 0)),
                            ("max-size", (None, "2m", 1000000)), ("max-file", (None, "2", 1))):
            missing = copy.deepcopy(logging)
            del missing["Config"][key]
            invalid_logs.append(missing)
            for value in values:
                changed = copy.deepcopy(logging)
                changed["Config"][key] = value
                invalid_logs.append(changed)
        extra = copy.deepcopy(logging)
        extra["Config"]["unreviewed-option"] = "value"
        invalid_logs.append(extra)
        for index, value in enumerate(invalid_logs):
            changed = copy.deepcopy(container)
            changed["HostConfig"]["LogConfig"] = value
            with self.subTest(log_case=index), self.assertRaisesRegex(lab.LabError, "isolation_log_config"):
                lab.validate_isolation(changed, net, owner, network)
        changed = copy.deepcopy(container)
        del changed["HostConfig"]["LogConfig"]
        with self.assertRaisesRegex(lab.LabError, "isolation_log_config"):
            lab.validate_isolation(changed, net, owner, network)


if __name__ == "__main__":
    unittest.main()
